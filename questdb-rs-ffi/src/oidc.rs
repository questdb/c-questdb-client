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

//! C ABI for the OIDC device authorization flow.
//!
//! The ABI owns opaque `Arc<OidcDeviceAuth>` handles so one authentication
//! state can safely feed sender, reader, and pooled connections. All input
//! pointers are validated before allocation or Rust string construction: the
//! enclosing FFI crate ships with `panic = "abort"`.

use std::cell::RefCell;
use std::path::PathBuf;
use std::ptr;
use std::slice;
use std::str;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use libc::{c_char, c_void, size_t};
use questdb::oidc::{
    DeviceCodeChallenge, DiagnosticHandler, FileTokenStore, OidcDeviceAuth, OidcError,
    OidcErrorKind, Renderer, sanitize_display_text,
};
use questdb::{Error, ErrorCode, TokenProviderIsolation};
use zeroize::Zeroizing;

use crate::{line_sender_error, line_sender_opts, questdb_error, set_err_out_from_error};

/// Hard cap for every caller-provided OIDC string. Real endpoint URLs, scopes,
/// and filesystem paths are tiny; the cap prevents an attacker-controlled C
/// length from becoming an abort-on-OOM allocation in this `panic = "abort"`
/// crate.
const MAX_OIDC_INPUT_BYTES: usize = 1024 * 1024;

/// Cap for the success event's identity (a best-effort, unverified name/email
/// from the token claims) before it is copied into an event a terminal or
/// notebook renderer displays. A hostile IdP claim is otherwise bounded only by
/// the multi-MB token response; 256 chars is well above any real identity.
const MAX_IDENTITY_DISPLAY_CHARS: usize = 256;

#[derive(Clone)]
enum BuilderSource {
    Explicit,
    QuestDb(String),
}

#[derive(Clone)]
enum FileStoreConfig {
    None,
    Directory(PathBuf),
    DefaultLocation,
}

#[derive(Clone)]
struct OidcBuilderConfig {
    source: BuilderSource,
    client_id: Option<String>,
    scope: Option<String>,
    audience: Option<String>,
    groups_in_token: Option<bool>,
    issuer: Option<String>,
    token_endpoint: Option<String>,
    device_authorization_endpoint: Option<String>,
    allow_insecure_transport: bool,
    ca_bundle: Option<PathBuf>,
    open_browser: Option<bool>,
    interactive: Option<bool>,
    default_interval: Option<u64>,
    timeout_ms: Option<u64>,
    renderer: Option<Arc<CEventTarget>>,
    diagnostic: Option<Arc<CDiagnosticTarget>>,
    file_store: FileStoreConfig,
}

impl OidcBuilderConfig {
    fn new(source: BuilderSource) -> Self {
        Self {
            source,
            client_id: None,
            scope: None,
            audience: None,
            groups_in_token: None,
            issuer: None,
            token_endpoint: None,
            device_authorization_endpoint: None,
            allow_insecure_transport: false,
            ca_bundle: None,
            open_browser: None,
            interactive: None,
            default_interval: None,
            timeout_ms: None,
            renderer: None,
            diagnostic: None,
            file_store: FileStoreConfig::None,
        }
    }

    #[allow(clippy::type_complexity)]
    fn build(
        &self,
    ) -> Result<
        (
            OidcDeviceAuth,
            Option<Arc<CEventHandler>>,
            Option<CDiagnosticSink>,
        ),
        Error,
    > {
        let mut builder = match &self.source {
            BuilderSource::Explicit => OidcDeviceAuth::builder(),
            BuilderSource::QuestDb(url) => OidcDeviceAuth::from_questdb(url.clone()),
        };
        if let Some(value) = &self.client_id {
            builder = builder.client_id(value.clone());
        }
        if let Some(value) = &self.scope {
            builder = builder.scope(value.clone());
        }
        if let Some(value) = &self.audience {
            builder = builder.audience(value.clone());
        }
        if let Some(value) = self.groups_in_token {
            builder = builder.groups_in_token(value);
        }
        if let Some(value) = &self.issuer {
            builder = builder.issuer(value.clone());
        }
        if let Some(value) = &self.token_endpoint {
            builder = builder.token_endpoint(value.clone());
        }
        if let Some(value) = &self.device_authorization_endpoint {
            builder = builder.device_authorization_endpoint(value.clone());
        }
        builder = builder.allow_insecure_transport(self.allow_insecure_transport);
        if let Some(value) = &self.ca_bundle {
            builder = builder.ca_bundle(value.clone());
        }
        if let Some(value) = self.open_browser {
            builder = builder.open_browser(value);
        }
        if let Some(value) = self.interactive {
            builder = builder.interactive(value);
        }
        if let Some(value) = self.default_interval {
            builder = builder.default_interval(value);
        }
        if let Some(value) = self.timeout_ms {
            builder = builder.timeout(Duration::from_millis(value));
        }
        // The callback target and its caller-owned `user_data` are shared by
        // every auth built from a reusable builder, but callback activity and
        // cancellation belong to one auth state. Sharing the whole handler
        // made a callback on sibling A look like B's own callback to close().
        let event_handler = self
            .renderer
            .as_ref()
            .map(|target| Arc::new(CEventHandler::new(Arc::clone(target))));
        if let Some(renderer) = &event_handler {
            builder = builder.renderer(CEventRenderer(Arc::clone(renderer)));
        }
        // The sink's per-auth state is retained alongside the auth so the
        // binding can detach delivery when its callback stops being callable.
        let diagnostic_sink = self.diagnostic.as_ref().map(|target| CDiagnosticSink {
            target: Arc::clone(target),
            state: Arc::new(CDiagnosticState::default()),
        });
        if let Some(sink) = &diagnostic_sink {
            builder = builder.diagnostic_handler(sink.clone());
        }
        match &self.file_store {
            FileStoreConfig::None => {}
            FileStoreConfig::Directory(directory) => {
                builder = builder.token_store(FileTokenStore::at(directory.clone()));
            }
            FileStoreConfig::DefaultLocation => {
                // Already a `ConfigError` carrying a full diagnostic; re-word
                // it only to name the FFI-level operation that failed.
                let store = FileTokenStore::at_default_location().map_err(|err| {
                    Error::new(
                        err.code(),
                        format!(
                            "Could not resolve the default OIDC token-store directory: {}",
                            err.msg()
                        ),
                    )
                })?;
                builder = builder.token_store(store);
            }
        }
        let auth = builder.build().map_err(Error::from)?;
        Ok((auth, event_handler, diagnostic_sink))
    }
}

/// Reusable OIDC builder. Its Rust builder is reconstructed from this cloneable
/// configuration for each build, so a failed build does not consume the C
/// handle and one configuration can build multiple independent auth states.
pub struct questdb_oidc_builder {
    config: OidcBuilderConfig,
}

/// Thread-safe OIDC authentication state. Transport attachment clones the Arc;
/// freeing this C handle does not invalidate already-configured clients.
pub struct questdb_oidc_auth {
    shared: SharedOidcAuth,
}

/// The Rust auth state plus the C callback identity installed on it.
///
/// Transport providers retain this complete value so a token request made
/// indirectly by a sender, reader, or pool observes the same callback
/// reentrancy guard as the direct C auth functions.
#[derive(Clone)]
pub(crate) struct SharedOidcAuth {
    inner: Arc<OidcDeviceAuth>,
    event_handler: Option<Arc<CEventHandler>>,
    diagnostic: Option<CDiagnosticSink>,
    /// One isolated-acquisition cell shared by every QWP attachment that uses
    /// this auth. Without this, attaching the same provider to N transports
    /// creates N abandoned workers when the synchronous callback blocks and
    /// can consume the process-wide worker budget by itself.
    token_provider_isolation: TokenProviderIsolation,
}

impl SharedOidcAuth {
    fn callback_is_active(&self) -> bool {
        self.event_handler
            .as_deref()
            .is_some_and(CEventHandler::target_is_active)
            || self
                .diagnostic
                .as_ref()
                .is_some_and(CDiagnosticSink::target_is_active)
    }

    /// This thread is the one inside the callback: it already holds the
    /// acquisition lock, so any operation needing it would deadlock on itself.
    ///
    /// `cancel_sign_in` and `close` are absent from the list on purpose: both
    /// are safe here. A renderer's ordinary "cancel" affordance should use the
    /// attempt-scoped former; close remains the permanent lifecycle operation.
    fn reentry_error() -> Error {
        Error::new(
            ErrorCode::InvalidApiCall,
            "OIDC authentication cannot be re-entered from its event or persistence \
             diagnostic callback; return from the callback before calling sign_in, token, \
             clear, or an attached transport. cancel_sign_in and close are exempt and may \
             be called here."
                .to_string(),
        )
    }

    /// Another thread is inside the callback, so the acquisition lock is held
    /// and this caller would block behind a prompt that may be waiting on a
    /// human. Distinct from re-entry: this caller did nothing wrong.
    fn callback_busy_error() -> Error {
        Error::new(
            ErrorCode::InvalidApiCall,
            "OIDC authentication is busy: an event or persistence diagnostic callback for \
             this provider is running on another thread and no valid cached token is \
             available. Acquire a token before starting an interactive sign-in, or retry \
             once the callback completes."
                .to_string(),
        )
    }

    /// `callback_busy_error` for the `token()` acquisition path, which needs a
    /// RETRYABLE class.
    ///
    /// `sign_in` and `clear` are direct user calls, so `InvalidApiCall` is
    /// right for them and is what `oidc.h` documents. `token()` is different:
    /// it is what an attached sender, reader or pool calls on a background
    /// reconnect, and its result runs through `classify_provider_error`, whose
    /// `InvalidApiCall` carve-out is terminal. A reconnect that merely landed
    /// inside a renderer's paint -- a window that is live on every
    /// `on_prompt` / `on_waiting` of a first sign-in, because there is no
    /// cached token to serve -- therefore stopped reconnecting permanently and
    /// terminalized a store-and-forward publication store with accepted frames
    /// still queued. The condition clears as soon as the callback returns.
    fn token_busy_error() -> Error {
        // Carries the structured `InteractionRequired` payload rather than
        // being a bare `Error::new`. This error reaches a caller through the
        // transport's provider-error path, where `questdb_error_oidc_get_view`
        // -- and every binding that picks an exception type from it -- decides
        // whether an OIDC failure caused the flush to fail. Without a payload
        // the predicate answered false, so `oidc.h`'s own promise that "a
        // token-provider failure surfacing as a retryable
        // `line_sender_error_socket_error` ... answer[s] true here" did not
        // hold, and the Python binding reported a plain `QuestDBError` for a
        // condition its documentation types as `OidcInteractionRequired`.
        // The retryable `SocketError` classification is unchanged.
        OidcError::retryable_interaction_required(
            "OIDC authentication is busy: an event or persistence diagnostic callback for \
             this provider is running on another thread and no valid cached token is \
             available. The token will be requested again on the next attempt; acquire a \
             token before starting an interactive sign-in to avoid the wait.",
        )
    }

    /// `reentry_error` for the `token()` acquisition path, which must not be
    /// TERMINAL even though the caller did violate the contract.
    ///
    /// The message stays that of `reentry_error` -- the caller genuinely did
    /// re-enter from its own callback and needs to be told so -- but the
    /// `InvalidApiCall` class does not: `classify_provider_error` re-carries it
    /// as a terminal `ConfigError`, which stops an attached transport's
    /// reconnect loop permanently and terminalizes a store-and-forward
    /// publication store with accepted frames still queued. That is a
    /// disproportionate, unrecoverable penalty for a mistake that ends as soon
    /// as the callback returns, and it is the same mistake `token_busy_error`
    /// already refuses to terminalize when it is made from another thread.
    ///
    /// Unlike `token_busy_error` this is NOT marked as an acquisition-busy
    /// wait: the caller blocked on the lock IS the callback, so re-resolving
    /// inside a retry budget can never succeed and must fail fast.
    fn token_reentry_error() -> Error {
        OidcError::reentrant_interaction_required(
            "OIDC authentication cannot be re-entered from its event or persistence \
             diagnostic callback; return from the callback before calling sign_in, token, \
             clear, or an attached transport. cancel_sign_in and close are exempt and may \
             be called here."
                .to_string(),
        )
    }

    /// Reject an operation that would take the acquisition lock while a
    /// callback holds it.
    ///
    /// The guard is keyed on each callback target's shared flag rather than
    /// only this auth's state, and deliberately so: a callback may dispatch to
    /// a worker and *wait* for it, or a reusable-builder sibling may hold its
    /// acquisition lock while waiting for the same serialized callback target.
    /// A blocking acquisition in either case deadlocks. Thread-local target
    /// identity supplies only the more precise re-entry versus busy message.
    fn in_own_callback(&self) -> bool {
        in_event_callback_of_on_this_thread(self.event_handler.as_ref())
            || self
                .diagnostic
                .as_ref()
                .is_some_and(CDiagnosticSink::in_callback_on_this_thread)
    }

    fn callback_reentry_error(&self) -> Option<Error> {
        self.callback_is_active().then(|| {
            if self.in_own_callback() {
                Self::reentry_error()
            } else {
                Self::callback_busy_error()
            }
        })
    }

    fn reject_callback_reentry(&self) -> Result<(), Error> {
        match self.callback_reentry_error() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Acquire the per-auth sign-in gate without waiting through a callback
    /// that the queued caller may be joined from. The callback and gate belong
    /// to the same sign-in, so once this lock becomes available that callback
    /// has returned; the second check closes the try-lock admission window.
    fn lock_sign_in_gate<'a>(
        &self,
        handler: &'a CEventHandler,
    ) -> Result<std::sync::MutexGuard<'a, ()>, Error> {
        loop {
            self.reject_callback_reentry()?;
            match handler.sign_in_gate.try_lock() {
                Ok(guard) => {
                    self.reject_callback_reentry()?;
                    return Ok(guard);
                }
                Err(std::sync::TryLockError::Poisoned(error)) => {
                    let guard = error.into_inner();
                    self.reject_callback_reentry()?;
                    return Ok(guard);
                }
                Err(std::sync::TryLockError::WouldBlock) => {
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        }
    }

    fn sign_in(&self) -> Result<(), Error> {
        self.reject_callback_reentry()?;
        // Mirror native's per-auth sign-in serialization at the callback layer.
        // This makes the handler generation below identify the invocation that
        // can actually render; a queued second caller cannot overwrite it.
        let _sign_in_gate = match self.event_handler.as_deref() {
            Some(handler) => Some(self.lock_sign_in_gate(handler)?),
            None => None,
        };
        let generation = self
            .event_handler
            .as_ref()
            .map(|handler| handler.begin_sign_in_serialized());
        // A callback can become active after the entry check while this call is
        // waiting for the core acquisition mutex. Re-check from that wait loop
        // so a callback which joins this thread cannot deadlock on itself.
        let abort_wait = || self.callback_reentry_error();
        let result = self.inner.sign_in_with_acquire_abort(&abort_wait);
        if let (Some(handler), Some(generation)) = (&self.event_handler, generation) {
            handler.finish_sign_in_serialized(generation);
        }
        result
    }

    fn cancel_sign_in(&self) -> Result<(), Error> {
        if let Some(handler) = &self.event_handler {
            handler.cancel_sign_in_serialized(|| self.inner.cancel_sign_in());
        } else {
            self.inner.cancel_sign_in();
        }
        Ok(())
    }

    pub(crate) fn token_provider_isolation(&self) -> TokenProviderIsolation {
        self.token_provider_isolation.clone()
    }

    pub(crate) fn token(&self) -> Result<String, Error> {
        // Serve a valid cached token even while a callback runs -- on any
        // thread, including the callback's own. That path consults only the
        // token cache, never the acquisition lock, so it cannot block behind
        // the callback and cannot deadlock, and the header states this
        // normatively: "`token` DOES succeed from a valid cache: that path
        // consults no lock the callback holds."
        //
        // The cache lookup has to come before the thread test, not after. On
        // the callback's own thread the old order returned the re-entry error
        // without ever looking, so a renderer reacting to SUCCESS -- which
        // fires *after* the token is committed -- was refused a token that was
        // sitting in the cache, as was any sender, reader or pool it flushed
        // from there. Only an acquisition, which would block, is still refused.
        if self.callback_is_active() {
            if let Some(cached) = self.inner.cached_token() {
                return cached.map_err(Into::into);
            }
            return Err(if self.in_own_callback() {
                Self::token_reentry_error()
            } else {
                Self::token_busy_error()
            });
        }
        // OidcDeviceAuth::token is deliberately non-interactive. Every attached
        // transport shares this path, so flush/connect/reconnect can refresh
        // silently but can never start a device-flow prompt.
        self.inner.token().map_err(Into::into)
    }

    /// `clear` behind an interactive sign-in on another thread.
    ///
    /// The core already refuses this rather than wait out a device flow (up to
    /// the whole device-code lifetime, with no escape short of `close`). It is
    /// raised here first only to keep the C class uniform: the same sign-in
    /// rejects `clear` with `InvalidApiCall` while its renderer is painting
    /// (`callback_busy_error`), and a caller must not see a different code
    /// depending on whether the flow was mid-paint or between polls.
    fn clear_behind_sign_in_error() -> Error {
        Error::new(
            ErrorCode::InvalidApiCall,
            "OIDC authentication is busy: an interactive sign-in is in progress on another \
             thread, and clear would wait for up to the device code's lifetime. Nothing \
             was cleared. Cancel the sign-in with cancel_sign_in, or retry clear once it \
             completes."
                .to_string(),
        )
    }

    fn clear(&self) -> Result<(), Error> {
        self.reject_callback_reentry()?;
        // Close the admission race just as sign_in does: clear may already be
        // waiting for the core acquisition mutex when a renderer or diagnostic
        // callback becomes active and joins this thread.
        let abort_wait = || {
            self.callback_reentry_error().or_else(|| {
                self.inner
                    .interactive_sign_in_in_progress()
                    .then(Self::clear_behind_sign_in_error)
            })
        };
        self.inner.try_clear_with_acquire_abort(&abort_wait)
    }

    fn close(&self) -> Result<(), Error> {
        // Publish the close BEFORE waking anything. The wakes below release
        // work that is parked mid-operation -- a sibling sign-in queued behind
        // this auth's callback target resumes at its post-persistence
        // `ensure_open()` -- and a wake issued first has no ordering against
        // the publication, so that sibling could race past the check, complete,
        // and cache a fresh credential into a provider the caller had already
        // closed (after this call's own `discard_credentials` had run). Closing
        // is documented as terminal and monotonic, so the flag a wake releases
        // work against must already be set. `signal_close` takes only its own
        // wait mutex -- never the acquisition lock or a callback gate -- so it
        // cannot deadlock ahead of the wakes, including on a callback stack.
        self.inner.signal_close();
        // Wake a callback for this auth that is queued behind a sibling built
        // from the same reusable builder. Without this, the sibling can hold
        // its acquisition lock while waiting for the shared callback gate, and
        // a callback that closes and joins that sibling waits forever.
        if let Some(handler) = &self.event_handler {
            handler.close();
        }
        if let Some(sink) = &self.diagnostic {
            // A persistence warning is emitted synchronously while token
            // acquisition still owns the provider's acquisition mutex. If the
            // callback calls close(), waiting for that mutex on this same stack
            // self-deadlocks. Publish suppression, then skip the native drain
            // whenever THIS auth's diagnostic callback is active. Activity is
            // per auth, so an unrelated sibling callback cannot weaken close.
            sink.detach_nowait();
        }
        // A callback may delegate close to a worker and join that worker. The
        // worker is not in callback TLS, but draining there still deadlocks:
        // sign-in or persistence owns the acquisition lock until the callback
        // returns. There is no way to distinguish a joined delegate from an
        // unrelated closer, so close is non-draining whenever THIS auth's event
        // or diagnostic callback is active on any thread. The per-auth flags
        // are essential: a sibling sharing the same target must still drain its
        // own unrelated work.
        let callback_active = self
            .event_handler
            .as_deref()
            .is_some_and(CEventHandler::is_active)
            || self
                .diagnostic
                .as_ref()
                .is_some_and(|sink| sink.state.active.load(Ordering::Acquire));
        if callback_active {
            // The drain is skipped, but credential teardown is not: it takes
            // only the tokens lock, so it is safe inside the critical section.
            self.inner.discard_credentials();
        } else {
            self.inner.close();
        }
        Ok(())
    }
}

/// Owned token copy. `Zeroizing` overwrites its allocation when released.
pub struct questdb_oidc_token {
    value: Zeroizing<String>,
}

/// Device-flow renderer event kind.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum questdb_oidc_event_kind {
    QUESTDB_OIDC_EVENT_PROMPT = 0,
    QUESTDB_OIDC_EVENT_WAITING = 1,
    QUESTDB_OIDC_EVENT_SUCCESS = 2,
    QUESTDB_OIDC_EVENT_FAILURE = 3,
}

/// Borrowed event view. Every string is valid only for the callback duration.
#[repr(C)]
pub struct questdb_oidc_event {
    pub struct_size: size_t,
    pub kind: questdb_oidc_event_kind,
    pub user_code: *const c_char,
    pub user_code_len: size_t,
    pub verification_uri: *const c_char,
    pub verification_uri_len: size_t,
    pub verification_uri_complete: *const c_char,
    pub verification_uri_complete_len: size_t,
    pub identity: *const c_char,
    pub identity_len: size_t,
    pub message: *const c_char,
    pub message_len: size_t,
    pub seconds_left: f64,
    pub expires_in_seconds: f64,
    pub browser_target: *const c_char,
    pub browser_target_len: size_t,
    pub interval_seconds: u64,
}

pub type questdb_oidc_event_cb =
    Option<unsafe extern "C" fn(user_data: *mut c_void, event: *const questdb_oidc_event)>;
/// Releases callback state after its final owner is dropped. It may run on any
/// thread and must return normally without unwinding or performing a non-local
/// jump (for example, C `longjmp`) across the Rust FFI frame.
pub type questdb_oidc_user_data_release_cb = Option<unsafe extern "C" fn(user_data: *mut c_void)>;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum questdb_oidc_diagnostic_kind {
    QUESTDB_OIDC_DIAGNOSTIC_PERSISTENCE_WARNING = 0,
}

#[repr(C)]
pub struct questdb_oidc_diagnostic {
    pub struct_size: size_t,
    pub kind: questdb_oidc_diagnostic_kind,
    pub message: *const c_char,
    pub message_len: size_t,
}

pub type questdb_oidc_diagnostic_cb = Option<
    unsafe extern "C" fn(user_data: *mut c_void, diagnostic: *const questdb_oidc_diagnostic),
>;

struct CDiagnosticTarget {
    callback: unsafe extern "C" fn(*mut c_void, *const questdb_oidc_diagnostic),
    user_data: usize,
    release: questdb_oidc_user_data_release_cb,
    /// Logical callback ownership. The mutex protects admission but is not held
    /// across foreign code, so detach can cancel a sibling queued behind the
    /// active callback instead of deadlocking with its acquisition lock.
    callback_gate: std::sync::Mutex<CallbackGateState>,
    callback_ready: std::sync::Condvar,
    /// Whether any auth sharing this target is executing its callback. This is
    /// separate from the per-auth state used by close: acquisition-taking
    /// operations must also reject the sibling AB/BA case where one auth holds
    /// its acquisition lock while waiting for this serialized target.
    active: AtomicBool,
}

/// Per-auth diagnostic delivery state.
///
/// Separate from [`CDiagnosticTarget`], which is shared by every auth built
/// from one reusable builder: detaching one auth's diagnostics must not silence
/// its siblings, but it must still serialize against a callback in flight, and
/// the target's gate is what provides that.
#[derive(Default)]
struct CDiagnosticState {
    detached: AtomicBool,
    /// True only while this auth's callback body is executing. The target gate
    /// serializes all siblings, while this per-auth bit lets close distinguish
    /// its own reentrant diagnostic from an unrelated sibling's callback.
    active: AtomicBool,
    /// Test-only synchronization for the sibling-close regression: unlike a
    /// sleep, this proves the sibling reached the cancellable gate wait.
    #[cfg(test)]
    waiting_for_target: AtomicBool,
}

std::thread_local! {
    /// The C diagnostic targets this thread is currently inside, innermost last.
    ///
    /// Recorded by target identity rather than merely counted: this thread can
    /// be inside target A's callback while an auth belonging to target B is
    /// detached, because the callback runs binding code that can destroy an
    /// unrelated handle. A bare depth counter would skip B's drain on the
    /// strength of holding A's gate, and B may genuinely have a callback
    /// running on another thread.
    static IN_DIAGNOSTIC_CALLBACK: RefCell<Vec<*const CDiagnosticTarget>> =
        const { RefCell::new(Vec::new()) };
}

/// How many times a bounded [`CDiagnosticSink`] detach retries the gate before
/// giving up on the drain. Bounded because the caller cannot safely wait --
/// it holds either another target's gate or a caller-runtime lock the callback
/// may need -- so waiting indefinitely is the inversion itself; a callback
/// mid-flight on another thread normally releases within a few yields.
const DETACH_BOUNDED_DRAIN_ROUNDS: usize = 64;

/// Marks this thread as being inside `target`'s callback for as long as it
/// lives. Mirrors [`ActiveEventHandler`]'s stack discipline.
struct InDiagnosticCallback(*const CDiagnosticTarget);

struct ActiveDiagnosticState<'a> {
    state: &'a CDiagnosticState,
    target: &'a CDiagnosticTarget,
}

impl<'a> ActiveDiagnosticState<'a> {
    fn enter(state: &'a CDiagnosticState, target: &'a CDiagnosticTarget) -> Option<Self> {
        let mut gate = target
            .callback_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while gate.held && !state.detached.load(Ordering::Acquire) {
            #[cfg(test)]
            state.waiting_for_target.store(true, Ordering::Release);
            gate = target
                .callback_ready
                .wait(gate)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        #[cfg(test)]
        state.waiting_for_target.store(false, Ordering::Release);
        if state.detached.load(Ordering::Acquire) {
            return None;
        }
        gate.held = true;
        let state_was_active = state.active.swap(true, Ordering::AcqRel);
        let target_was_active = target.active.swap(true, Ordering::AcqRel);
        debug_assert!(!state_was_active, "one auth cannot overlap its diagnostics");
        debug_assert!(
            !target_was_active,
            "one serialized target cannot overlap its diagnostics"
        );
        drop(gate);
        Some(Self { state, target })
    }
}

impl Drop for ActiveDiagnosticState<'_> {
    fn drop(&mut self) {
        let state_was_active = self.state.active.swap(false, Ordering::AcqRel);
        let target_was_active = self.target.active.swap(false, Ordering::AcqRel);
        debug_assert!(
            state_was_active && target_was_active,
            "active diagnostic guard must be balanced"
        );
        let mut gate = self
            .target
            .callback_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        debug_assert!(gate.held, "diagnostic callback gate must be held");
        gate.held = false;
        self.target.callback_ready.notify_all();
    }
}

impl InDiagnosticCallback {
    fn enter(target: &Arc<CDiagnosticTarget>) -> Self {
        let target = Arc::as_ptr(target);
        IN_DIAGNOSTIC_CALLBACK.with(|stack| stack.borrow_mut().push(target));
        Self(target)
    }
}

impl Drop for InDiagnosticCallback {
    fn drop(&mut self) {
        IN_DIAGNOSTIC_CALLBACK.with(|stack| {
            let mut stack = stack.borrow_mut();
            let popped = stack.pop();
            debug_assert_eq!(popped, Some(self.0));
        });
    }
}

impl Drop for CDiagnosticTarget {
    fn drop(&mut self) {
        if let Some(release) = self.release {
            unsafe { release(self.user_data as *mut c_void) };
        }
    }
}

#[derive(Clone)]
struct CDiagnosticSink {
    target: Arc<CDiagnosticTarget>,
    state: Arc<CDiagnosticState>,
}

impl CDiagnosticSink {
    fn target_is_active(&self) -> bool {
        self.target.active.load(Ordering::Acquire)
    }

    fn in_callback_on_this_thread(&self) -> bool {
        let target = Arc::as_ptr(&self.target);
        IN_DIAGNOSTIC_CALLBACK.with(|stack| stack.borrow().contains(&target))
    }

    /// Stop delivering this auth's diagnostics, waiting out a callback already
    /// running.
    ///
    /// Taking the gate is what makes this a handshake rather than a flag flip:
    /// on return, no invocation is in progress and no later one can start. A
    /// binding whose callback enters a managed runtime needs exactly that
    /// before it stops being able to service one -- publishing the flag alone
    /// would leave a callback that had already passed the check running into a
    /// runtime that is going away.
    ///
    /// Reached from inside this thread's own callback it degrades to that flag
    /// flip, which is not a weakening: the gate serializes every invocation of
    /// this target, so if this thread holds it then the only invocation in
    /// flight is the caller's own frame, and it is about to return. Taking the
    /// gate again would deadlock a caller on itself -- reachable without any
    /// user writing such a call, because a binding's callback can run a
    /// collection that destroys a handle.
    ///
    /// Reached from inside a DIFFERENT target's callback, the drain becomes
    /// best-effort and bounded. That case is an AB/BA inversion, not
    /// self-deadlock: this thread holds the other target's gate, so blocking
    /// here while a thread inside this target's callback reaches for that one
    /// parks both permanently, and `panic = "abort"` means neither guard is
    /// ever unwound. Two providers each with a token store are enough to
    /// construct it.
    ///
    /// Waiting is therefore only safe when the calling thread holds nothing
    /// the callback might acquire. Releasing the binding's global runtime lock
    /// is NOT sufficient evidence of that: the callback runs binding code that
    /// can take finer-grained locks -- Python's `logging` handler lock is the
    /// worked example -- and a thread reaching a finalizer may already own
    /// one. Callers that cannot establish it must use
    /// [`detach_nowait`](Self::detach_nowait).
    ///
    /// Suppression is exact on every path, because the flag is published
    /// before any waiting; only the "no callback is still running" half is
    /// downgraded when the drain must be bounded.
    fn detach(&self) {
        self.detach_inner(true);
    }

    /// As [`detach`](Self::detach), but never waits for a callback already
    /// running: it publishes the suppression and drains only best-effort.
    ///
    /// For a caller that cannot prove it holds no lock the callback needs.
    /// Waiting is only safe when nothing the callback might acquire is held by
    /// the waiting thread, and a binding's finalizer cannot establish that: it
    /// runs wherever a collection happened to fire. The Python client reaches
    /// this from `_OidcNativeHandle.__dealloc__`, which a garbage collection
    /// can run inside a `logging` handler's `emit` -- so the thread owns that
    /// handler's lock, which is exactly what the diagnostic callback acquires
    /// when it logs. Blocking there deadlocks the two permanently, and
    /// releasing the GIL does not help, because the GIL is not the lock in
    /// contention.
    fn detach_nowait(&self) {
        self.detach_inner(false);
    }

    fn detach_inner(&self, may_block: bool) {
        let target: *const CDiagnosticTarget = Arc::as_ptr(&self.target);
        let reentrant = IN_DIAGNOSTIC_CALLBACK.with(|stack| stack.borrow().contains(&target));
        // Holding either callback kind can form the same AB/BA inversion: an
        // event callback may reclaim a diagnostic target while its diagnostic
        // callback reclaims the event target, and vice versa.
        let nested = in_any_oidc_callback_on_this_thread();
        {
            // Serialize suppression with callback admission and wake this
            // auth if it is queued behind a sibling callback. Without the wake,
            // close(B) from A's shared callback can wait on B's acquisition
            // lock while B waits for A to release this target.
            let _gate = self
                .target
                .callback_gate
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.state.detached.store(true, Ordering::Release);
            self.target.callback_ready.notify_all();
        }
        if reentrant {
            return;
        }
        if nested || !may_block {
            for _ in 0..DETACH_BOUNDED_DRAIN_ROUNDS {
                let gate = self
                    .target
                    .callback_gate
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if !self.state.active.load(Ordering::Acquire) {
                    return;
                }
                drop(gate);
                std::thread::yield_now();
            }
            return;
        }
        // Wait for THIS auth's callback only. The gate serializes every auth
        // built from one builder, so waiting on `gate.held` also waited out a
        // sibling's callback -- unbounded, and a deadlock when that sibling's
        // callback waits for the detaching thread -- although detaching one
        // auth is documented not to affect its siblings. `state.active` is set
        // under the gate on entry and cleared before the gate is released and
        // `callback_ready` notified, so this predicate cannot miss a wakeup.
        let mut gate = self
            .target
            .callback_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while self.state.active.load(Ordering::Acquire) {
            gate = self
                .target
                .callback_ready
                .wait(gate)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }
}

impl DiagnosticHandler for CDiagnosticSink {
    fn on_persistence_warning(&self, message: &str) {
        if self.state.detached.load(Ordering::Acquire) {
            return;
        }
        let display = sanitize_display_text(message);
        let (message, message_len) = str_or_null(Some(&display));
        let diagnostic = questdb_oidc_diagnostic {
            struct_size: std::mem::size_of::<questdb_oidc_diagnostic>(),
            kind: questdb_oidc_diagnostic_kind::QUESTDB_OIDC_DIAGNOSTIC_PERSISTENCE_WARNING,
            message,
            message_len,
        };
        let Some(_active) = ActiveDiagnosticState::enter(&self.state, &self.target) else {
            return;
        };
        let _in_callback = InDiagnosticCallback::enter(&self.target);
        unsafe { (self.target.callback)(self.target.user_data as *mut c_void, &diagnostic) };
    }
}

struct CEventTarget {
    callback: unsafe extern "C" fn(*mut c_void, *const questdb_oidc_event),
    user_data: usize,
    /// May be absent only for a null, stateless `user_data` registration.
    release: questdb_oidc_user_data_release_cb,
    /// Auths built from one reusable builder share caller-owned callback state,
    /// so entry must remain serialized across those siblings.
    callback_gate: std::sync::Mutex<CallbackGateState>,
    callback_ready: std::sync::Condvar,
    /// Whether any sibling is currently inside the shared callback target.
    active: AtomicBool,
}

#[derive(Default)]
struct CallbackGateState {
    held: bool,
}

/// Per-auth callback state. The target is shared by reusable-builder siblings;
/// activity and cancellation are deliberately not.
struct CEventHandler {
    target: Arc<CEventTarget>,
    active: AtomicBool,
    /// Permanent callback cancellation, paired with provider close.
    closed: AtomicBool,
    /// Serializes C-facing sign-in invocations so one active generation maps
    /// exactly to native's serialized interactive flow.
    sign_in_gate: std::sync::Mutex<()>,
    /// Serializes begin/finish with cancellation's core attempt selection.
    /// Never held while sign-in itself runs or while user code is invoked.
    sign_in_generation_gate: std::sync::Mutex<()>,
    next_sign_in_generation: AtomicU64,
    active_sign_in_generation: AtomicU64,
    cancelled_sign_in_generation: AtomicU64,
}

std::thread_local! {
    /// The C event handlers this thread is currently inside, innermost last.
    ///
    /// Target activity is deliberately shared across threads — it backs the
    /// re-entry rejection, which must fire for any caller while a callback runs.
    /// This stack supplies only the more precise diagnostic: whether this
    /// thread itself re-entered the auth or merely encountered a busy callback.
    ///
    /// Handlers are recorded by per-auth identity, not merely counted. Auths
    /// built from one reusable builder share a target but not their activity or
    /// cancellation state, so A's callback is never mistaken for B's.
    ///
    /// A stack rather than a single slot because two different handlers can
    /// nest: a renderer for A may drive B synchronously. Each entry must stay
    /// visible while it is held, or the outer one would be forgotten.
    static IN_EVENT_CALLBACK: RefCell<Vec<*const CEventHandler>> =
        const { RefCell::new(Vec::new()) };
}

/// Whether this thread is executing inside `handler`'s own callback — the only
/// situation in which its acquisition lock is already held by this thread.
///
/// Borrows are short and never span a call into user code, so the `RefCell`
/// cannot be re-entered.
fn in_event_callback_of_on_this_thread(handler: Option<&Arc<CEventHandler>>) -> bool {
    let Some(handler) = handler else {
        return false;
    };
    let target: *const CEventHandler = Arc::as_ptr(handler);
    IN_EVENT_CALLBACK.with(|stack| stack.borrow().contains(&target))
}

/// Whether this thread currently owns any OIDC callback gate, regardless of
/// callback kind. A detach reached from either stack must never perform an
/// unbounded drain of the other kind: cross-kind callbacks can reclaim each
/// other's handles and otherwise form the same AB/BA deadlock as two event or
/// two diagnostic targets.
fn in_any_oidc_callback_on_this_thread() -> bool {
    IN_EVENT_CALLBACK.with(|stack| !stack.borrow().is_empty())
        || IN_DIAGNOSTIC_CALLBACK.with(|stack| !stack.borrow().is_empty())
}

struct ActiveEventHandler<'a> {
    handler: &'a CEventHandler,
}

impl<'a> ActiveEventHandler<'a> {
    fn enter(handler: &'a CEventHandler) -> Option<Self> {
        let mut gate = handler
            .target
            .callback_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while gate.held && !handler.callbacks_cancelled() {
            gate = handler
                .target
                .callback_ready
                .wait(gate)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        if handler.callbacks_cancelled() {
            return None;
        }
        gate.held = true;
        let was_active = handler.active.swap(true, Ordering::AcqRel);
        debug_assert!(!was_active, "one auth cannot overlap its callbacks");
        let target_was_active = handler.target.active.swap(true, Ordering::AcqRel);
        debug_assert!(
            !target_was_active,
            "callback gate must serialize shared target entry"
        );
        drop(gate);
        IN_EVENT_CALLBACK.with(|stack| stack.borrow_mut().push(handler as *const _));
        Some(Self { handler })
    }
}

impl Drop for ActiveEventHandler<'_> {
    fn drop(&mut self) {
        IN_EVENT_CALLBACK.with(|stack| {
            let mut stack = stack.borrow_mut();
            let popped = stack.pop();
            debug_assert_eq!(
                popped,
                Some(self.handler as *const _),
                "callback handler stack must unwind in order"
            );
        });
        let was_active = self.handler.active.swap(false, Ordering::AcqRel);
        debug_assert!(was_active, "active callback guard must be balanced");
        let target_was_active = self.handler.target.active.swap(false, Ordering::AcqRel);
        debug_assert!(target_was_active, "target callback guard must be balanced");
        let mut gate = self
            .handler
            .target
            .callback_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        debug_assert!(gate.held, "callback gate must be held during callback");
        gate.held = false;
        self.handler.target.callback_ready.notify_all();
    }
}

impl CEventHandler {
    fn new(target: Arc<CEventTarget>) -> Self {
        Self {
            target,
            active: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            sign_in_gate: std::sync::Mutex::new(()),
            sign_in_generation_gate: std::sync::Mutex::new(()),
            next_sign_in_generation: AtomicU64::new(1),
            active_sign_in_generation: AtomicU64::new(0),
            cancelled_sign_in_generation: AtomicU64::new(0),
        }
    }

    fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    fn target_is_active(&self) -> bool {
        self.target.active.load(Ordering::Acquire)
    }

    fn callbacks_cancelled(&self) -> bool {
        if self.closed.load(Ordering::Acquire) {
            return true;
        }
        let active = self.active_sign_in_generation.load(Ordering::Acquire);
        active != 0 && self.cancelled_sign_in_generation.load(Ordering::Acquire) == active
    }

    fn begin_sign_in(&self) -> u64 {
        let generation = self.next_sign_in_generation.fetch_add(1, Ordering::AcqRel);
        debug_assert_ne!(generation, 0, "sign-in generation wrapped");
        let previous = self
            .active_sign_in_generation
            .swap(generation, Ordering::AcqRel);
        debug_assert_eq!(previous, 0, "sign-in gate must serialize generations");
        generation
    }

    fn begin_sign_in_serialized(&self) -> u64 {
        let _state = self
            .sign_in_generation_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.begin_sign_in()
    }

    fn finish_sign_in(&self, generation: u64) {
        let _ = self.active_sign_in_generation.compare_exchange(
            generation,
            0,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        self.clear_sign_in_cancel(generation);
    }

    fn finish_sign_in_serialized(&self, generation: u64) {
        let _state = self
            .sign_in_generation_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.finish_sign_in(generation);
    }

    /// Keep renderer-generation transitions fixed while the core chooses and
    /// signals its active attempt. Without this gate, attempt A can finish and
    /// B can publish between the native cancellation and the callback-layer
    /// store, causing A's cancellation to mute B.
    fn cancel_sign_in_serialized(&self, cancel_core: impl FnOnce() -> bool) {
        let _state = self
            .sign_in_generation_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let generation = self.cancel_sign_in();
        let cancelled = cancel_core();
        debug_assert!(
            !cancelled || generation.is_some(),
            "an interactive flow must have a renderer generation"
        );
        if !cancelled && let Some(generation) = generation {
            // Native found no active device flow. Undo only our own
            // speculative publication; a later generation is untouched.
            self.clear_sign_in_cancel(generation);
        }
    }

    /// Cancel the currently active renderer generation, if any, and return its
    /// identity so a speculative publication can be rolled back precisely.
    fn cancel_sign_in(&self) -> Option<u64> {
        // Serialize the cancellation predicate with callback admission so an
        // attempt cancellation cannot miss a waiter between its predicate
        // check and wait.
        let _gate = self
            .target
            .callback_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let generation = self.active_sign_in_generation.load(Ordering::Acquire);
        if generation == 0 {
            return None;
        }
        self.cancelled_sign_in_generation
            .store(generation, Ordering::Release);
        self.target.callback_ready.notify_all();
        Some(generation)
    }

    fn clear_sign_in_cancel(&self, generation: u64) {
        let _ = self.cancelled_sign_in_generation.compare_exchange(
            generation,
            0,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    fn close(&self) {
        // Serialize the cancellation predicate with callback admission so
        // close cannot miss a waiter between its predicate check and wait.
        let _gate = self
            .target
            .callback_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.closed.store(true, Ordering::Release);
        self.target.callback_ready.notify_all();
    }

    /// Permanently suppress this auth's renderer and, when safe, wait for an
    /// invocation already in flight. This does not close the provider: a
    /// managed runtime may need transports to keep refreshing tokens after it
    /// can no longer service presentation callbacks.
    fn detach(&self) {
        self.detach_inner(true);
    }

    /// As [`detach`](Self::detach), but never waits for a callback already
    /// running: it publishes suppression and drains only best-effort.
    fn detach_nowait(&self) {
        self.detach_inner(false);
    }

    fn detach_inner(&self, may_block: bool) {
        let target: *const CEventHandler = self;
        let reentrant = IN_EVENT_CALLBACK.with(|stack| stack.borrow().contains(&target));
        let nested = in_any_oidc_callback_on_this_thread();
        {
            // Serialize suppression with callback admission. Once this store
            // completes, no callback that has not already entered can start.
            let _gate = self
                .target
                .callback_gate
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.closed.store(true, Ordering::Release);
            self.target.callback_ready.notify_all();
        }
        if reentrant {
            return;
        }
        if nested || !may_block {
            // Do not create an AB/BA inversion between two renderer targets,
            // or turn a finalizer/shutdown hook into an unbounded wait on user
            // code. Suppression is exact; only the drain is best-effort here.
            for _ in 0..DETACH_BOUNDED_DRAIN_ROUNDS {
                let gate = self
                    .target
                    .callback_gate
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if !self.is_active() {
                    return;
                }
                drop(gate);
                std::thread::yield_now();
            }
            return;
        }
        // Wait for THIS auth's callback only, not a sibling's sharing the
        // target: see `CDiagnosticSink::detach_inner`. `active` is set under
        // the gate on entry and cleared before the gate is released and
        // `callback_ready` notified, so this predicate cannot miss a wakeup.
        let mut gate = self
            .target
            .callback_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while self.is_active() {
            gate = self
                .target
                .callback_ready
                .wait(gate)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }
}

impl Drop for CEventTarget {
    fn drop(&mut self) {
        if let Some(release) = self.release {
            // SAFETY: registration transfers ownership of `user_data` and
            // requires `release` to return normally across this FFI boundary.
            unsafe { release(self.user_data as *mut c_void) };
        }
    }
}

#[derive(Clone)]
struct CEventRenderer(Arc<CEventHandler>);

impl CEventRenderer {
    fn invoke(&self, event: &questdb_oidc_event) {
        let Some(_active) = ActiveEventHandler::enter(&self.0) else {
            return;
        };
        let target = &self.0.target;
        unsafe { (target.callback)(target.user_data as *mut c_void, event) };
    }
}

impl Renderer for CEventRenderer {
    fn on_prompt(&self, challenge: &DeviceCodeChallenge) {
        // Never expose the raw IdP response through a presentation callback.
        // Display fields are inert single-line ASCII; the independently vetted
        // browser target is the only URL consumers may make clickable or open.
        let display_user_code = challenge.display_user_code();
        let display_verification_uri = challenge.display_verification_uri();
        let display_verification_uri_complete = challenge.display_verification_uri_complete();
        let browser_target_value = challenge.browser_target();
        let (user_code, user_code_len) = str_or_null(Some(&display_user_code));
        let (verification_uri, verification_uri_len) = str_or_null(Some(&display_verification_uri));
        let (verification_uri_complete, verification_uri_complete_len) =
            str_or_null(display_verification_uri_complete.as_deref());
        let (browser_target, browser_target_len) = str_or_null(browser_target_value.as_deref());
        self.invoke(&questdb_oidc_event {
            struct_size: std::mem::size_of::<questdb_oidc_event>(),
            kind: questdb_oidc_event_kind::QUESTDB_OIDC_EVENT_PROMPT,
            user_code,
            user_code_len,
            verification_uri,
            verification_uri_len,
            verification_uri_complete,
            verification_uri_complete_len,
            identity: ptr::null(),
            identity_len: 0,
            message: ptr::null(),
            message_len: 0,
            seconds_left: 0.0,
            expires_in_seconds: challenge.expires_in_seconds() as f64,
            browser_target,
            browser_target_len,
            interval_seconds: challenge.interval_seconds(),
        });
    }

    fn on_waiting(&self, seconds_left: f64) {
        let mut event = empty_event(questdb_oidc_event_kind::QUESTDB_OIDC_EVENT_WAITING);
        event.seconds_left = seconds_left;
        self.invoke(&event);
    }

    fn on_success(&self, identity: Option<&str>, expires_in_secs: f64) {
        let mut event = empty_event(questdb_oidc_event_kind::QUESTDB_OIDC_EVENT_SUCCESS);
        // Cap before sanitizing so a hostile multi-MB identity claim is never
        // copied in full into the event; take() only walks the bounded prefix.
        let display_identity = identity.map(|id| {
            let bounded: String = id.chars().take(MAX_IDENTITY_DISPLAY_CHARS).collect();
            sanitize_display_text(&bounded)
        });
        (event.identity, event.identity_len) = str_or_null(display_identity.as_deref());
        event.expires_in_seconds = expires_in_secs;
        self.invoke(&event);
    }

    fn on_failure(&self, message: &str) {
        let mut event = empty_event(questdb_oidc_event_kind::QUESTDB_OIDC_EVENT_FAILURE);
        let display_message = sanitize_display_text(message);
        (event.message, event.message_len) = str_or_null(Some(&display_message));
        self.invoke(&event);
    }
}

fn empty_event(kind: questdb_oidc_event_kind) -> questdb_oidc_event {
    questdb_oidc_event {
        struct_size: std::mem::size_of::<questdb_oidc_event>(),
        kind,
        user_code: ptr::null(),
        user_code_len: 0,
        verification_uri: ptr::null(),
        verification_uri_len: 0,
        verification_uri_complete: ptr::null(),
        verification_uri_complete_len: 0,
        identity: ptr::null(),
        identity_len: 0,
        message: ptr::null(),
        message_len: 0,
        seconds_left: 0.0,
        expires_in_seconds: 0.0,
        browser_target: ptr::null(),
        browser_target_len: 0,
        interval_seconds: 0,
    }
}

/// Return a borrowed pointer-plus-length span. Non-NULL data is not
/// NUL-terminated and callers must use the returned length.
fn str_or_null(value: Option<&str>) -> (*const c_char, size_t) {
    value.map_or((ptr::null(), 0), |value| {
        (value.as_ptr() as *const c_char, value.len())
    })
}

unsafe fn set_input_error(
    err_out: *mut *mut questdb_error,
    code: ErrorCode,
    message: impl Into<String>,
) {
    unsafe { set_err_out_from_error(err_out, Error::new(code, message.into())) };
}

unsafe fn input_str<'a>(
    input: *const c_char,
    input_len: size_t,
    label: &str,
    err_out: *mut *mut questdb_error,
) -> Option<&'a str> {
    if input.is_null() && input_len != 0 {
        unsafe {
            set_input_error(
                err_out,
                ErrorCode::InvalidApiCall,
                format!("{label} pointer is NULL with non-zero length"),
            )
        };
        return None;
    }
    if input_len > MAX_OIDC_INPUT_BYTES {
        unsafe {
            set_input_error(
                err_out,
                ErrorCode::InvalidApiCall,
                format!(
                    "{label} length {input_len} exceeds the OIDC input cap of {MAX_OIDC_INPUT_BYTES} bytes"
                ),
            )
        };
        return None;
    }
    let bytes = if input_len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(input as *const u8, input_len) }
    };
    match str::from_utf8(bytes) {
        Ok(value) => Some(value),
        Err(_) => {
            unsafe {
                set_input_error(
                    err_out,
                    ErrorCode::InvalidUtf8,
                    format!("{label} is not valid UTF-8"),
                )
            };
            None
        }
    }
}

unsafe fn builder_mut<'a>(
    builder: *mut questdb_oidc_builder,
    err_out: *mut *mut questdb_error,
) -> Option<&'a mut questdb_oidc_builder> {
    if builder.is_null() {
        unsafe {
            set_input_error(
                err_out,
                ErrorCode::InvalidApiCall,
                "OIDC builder pointer is NULL",
            )
        };
        None
    } else {
        Some(unsafe { &mut *builder })
    }
}

pub(crate) unsafe fn clone_auth(
    auth: *const questdb_oidc_auth,
    err_out: *mut *mut questdb_error,
) -> Option<SharedOidcAuth> {
    if auth.is_null() {
        unsafe {
            set_input_error(
                err_out,
                ErrorCode::InvalidApiCall,
                "OIDC auth pointer is NULL",
            )
        };
        None
    } else {
        Some(unsafe { (*auth).shared.clone() })
    }
}

/// Create an explicit OIDC builder. The caller must set client id, token
/// endpoint, and device-authorization endpoint before building.
#[unsafe(no_mangle)]
pub extern "C" fn questdb_oidc_builder_new() -> *mut questdb_oidc_builder {
    Box::into_raw(Box::new(questdb_oidc_builder {
        config: OidcBuilderConfig::new(BuilderSource::Explicit),
    }))
}

/// Create a builder that discovers OIDC configuration from QuestDB `/settings`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_builder_from_questdb(
    url: *const c_char,
    url_len: size_t,
    err_out: *mut *mut questdb_error,
) -> *mut questdb_oidc_builder {
    let Some(url) = (unsafe { input_str(url, url_len, "QuestDB URL", err_out) }) else {
        return ptr::null_mut();
    };
    Box::into_raw(Box::new(questdb_oidc_builder {
        config: OidcBuilderConfig::new(BuilderSource::QuestDb(url.to_owned())),
    }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_builder_free(builder: *mut questdb_oidc_builder) {
    if !builder.is_null() {
        unsafe { drop(Box::from_raw(builder)) };
    }
}

macro_rules! string_setter {
    ($name:ident, $field:ident, $label:literal) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name(
            builder: *mut questdb_oidc_builder,
            value: *const c_char,
            value_len: size_t,
            err_out: *mut *mut questdb_error,
        ) -> bool {
            let Some(builder) = (unsafe { builder_mut(builder, err_out) }) else {
                return false;
            };
            let Some(value) = (unsafe { input_str(value, value_len, $label, err_out) }) else {
                return false;
            };
            builder.config.$field = Some(value.to_owned());
            true
        }
    };
}

string_setter!(questdb_oidc_builder_client_id, client_id, "OIDC client id");
string_setter!(questdb_oidc_builder_scope, scope, "OIDC scope");
string_setter!(questdb_oidc_builder_audience, audience, "OIDC audience");
string_setter!(questdb_oidc_builder_issuer, issuer, "OIDC issuer");
string_setter!(
    questdb_oidc_builder_token_endpoint,
    token_endpoint,
    "OIDC token endpoint"
);
string_setter!(
    questdb_oidc_builder_device_authorization_endpoint,
    device_authorization_endpoint,
    "OIDC device-authorization endpoint"
);

#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_builder_groups_in_token(
    builder: *mut questdb_oidc_builder,
    enabled: bool,
    err_out: *mut *mut questdb_error,
) -> bool {
    let Some(builder) = (unsafe { builder_mut(builder, err_out) }) else {
        return false;
    };
    builder.config.groups_in_token = Some(enabled);
    true
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_builder_allow_insecure_transport(
    builder: *mut questdb_oidc_builder,
    enabled: bool,
    err_out: *mut *mut questdb_error,
) -> bool {
    let Some(builder) = (unsafe { builder_mut(builder, err_out) }) else {
        return false;
    };
    builder.config.allow_insecure_transport = enabled;
    true
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_builder_open_browser(
    builder: *mut questdb_oidc_builder,
    enabled: bool,
    err_out: *mut *mut questdb_error,
) -> bool {
    let Some(builder) = (unsafe { builder_mut(builder, err_out) }) else {
        return false;
    };
    builder.config.open_browser = Some(enabled);
    true
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_builder_interactive(
    builder: *mut questdb_oidc_builder,
    enabled: bool,
    err_out: *mut *mut questdb_error,
) -> bool {
    let Some(builder) = (unsafe { builder_mut(builder, err_out) }) else {
        return false;
    };
    builder.config.interactive = Some(enabled);
    true
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_builder_default_interval_seconds(
    builder: *mut questdb_oidc_builder,
    seconds: u64,
    err_out: *mut *mut questdb_error,
) -> bool {
    let Some(builder) = (unsafe { builder_mut(builder, err_out) }) else {
        return false;
    };
    builder.config.default_interval = Some(seconds);
    true
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_builder_timeout_ms(
    builder: *mut questdb_oidc_builder,
    timeout_ms: u64,
    err_out: *mut *mut questdb_error,
) -> bool {
    let Some(builder) = (unsafe { builder_mut(builder, err_out) }) else {
        return false;
    };
    builder.config.timeout_ms = Some(timeout_ms);
    true
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_builder_ca_bundle(
    builder: *mut questdb_oidc_builder,
    path: *const c_char,
    path_len: size_t,
    err_out: *mut *mut questdb_error,
) -> bool {
    let Some(builder) = (unsafe { builder_mut(builder, err_out) }) else {
        return false;
    };
    let Some(path) = (unsafe { input_str(path, path_len, "OIDC CA-bundle path", err_out) }) else {
        return false;
    };
    if let Err(err) = reject_unexpanded_home(path, "OIDC CA-bundle path") {
        unsafe { set_err_out_from_error(err_out, err) };
        return false;
    }
    builder.config.ca_bundle = Some(PathBuf::from(path));
    true
}

/// Explicitly enable plaintext token persistence in `directory`.
///
/// Access, ID, and long-lived refresh tokens are stored as unencrypted JSON.
/// Unix uses owner-only file/directory modes; other platforms depend on the
/// directory's default ACL. Without this opt-in, credentials remain in memory.
///
/// `directory` is used verbatim: no runtime expands `~`, so a `~/...` value is
/// rejected here rather than silently creating a directory literally named `~`
/// under the working directory and leaving a long-lived refresh token in it.
/// A relative path is accepted but follows the process working directory, so
/// prefer an absolute one.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_builder_file_token_store(
    builder: *mut questdb_oidc_builder,
    directory: *const c_char,
    directory_len: size_t,
    err_out: *mut *mut questdb_error,
) -> bool {
    let Some(builder) = (unsafe { builder_mut(builder, err_out) }) else {
        return false;
    };
    let Some(directory) = (unsafe {
        input_str(
            directory,
            directory_len,
            "OIDC token-store directory",
            err_out,
        )
    }) else {
        return false;
    };
    if let Err(err) = reject_unexpanded_home(directory, "OIDC token-store directory") {
        unsafe { set_err_out_from_error(err_out, err) };
        return false;
    }
    builder.config.file_store = FileStoreConfig::Directory(PathBuf::from(directory));
    true
}

/// Refuse a public path argument whose leading `~` nothing will expand.
///
/// A shell expands `~`, these APIs do not. For a token-store directory the
/// unchecked spelling creates a directory literally named `~` under the
/// working directory and can leave a plaintext refresh token there; for a CA
/// bundle it produces a misleading file-open failure. Fail at the builder
/// boundary and make callers pass the path they actually intend.
fn reject_unexpanded_home(path: &str, label: &str) -> questdb::Result<()> {
    if path == "~" || path.starts_with("~/") || path.starts_with("~\\") {
        return Err(Error::new(
            ErrorCode::ConfigError,
            format!(
                "the {label} {path:?} starts with `~`, which shells expand but this \
                 client does not. Pass an already-expanded absolute path."
            ),
        ));
    }
    Ok(())
}

/// Explicitly enable plaintext token persistence at the configured default
/// location. Access, ID, and long-lived refresh tokens are stored as
/// unencrypted JSON; see the public C header for the platform security contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_builder_default_file_token_store(
    builder: *mut questdb_oidc_builder,
    err_out: *mut *mut questdb_error,
) -> bool {
    let Some(builder) = (unsafe { builder_mut(builder, err_out) }) else {
        return false;
    };
    builder.config.file_store = FileStoreConfig::DefaultLocation;
    true
}

/// Install a renderer callback. Non-null `user_data` requires a non-null
/// `release`; on success ownership transfers to the builder and is released
/// exactly once after the builder and every auth object/transport built from it
/// have dropped their last reference. On failure ownership remains with the
/// caller. Null `user_data` with no release is a stateless callback. The callback
/// may run on any token-acquisition thread, is serialized with its sibling
/// invocations, and must not unwind. Auth reentry from the callback is rejected
/// before reaching the core acquisition mutex. Final `release` has no
/// thread-affinity guarantee and must return normally without unwinding or
/// performing a non-local jump across the Rust FFI frame.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_builder_event_handler(
    builder: *mut questdb_oidc_builder,
    callback: questdb_oidc_event_cb,
    user_data: *mut c_void,
    release: questdb_oidc_user_data_release_cb,
    err_out: *mut *mut questdb_error,
) -> bool {
    let previous = {
        let Some(builder) = (unsafe { builder_mut(builder, err_out) }) else {
            return false;
        };
        let Some(callback) = callback else {
            unsafe {
                set_input_error(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    "OIDC event callback is NULL",
                )
            };
            return false;
        };
        if !user_data.is_null() && release.is_none() {
            unsafe {
                set_input_error(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    "OIDC event user_data is non-NULL but its release callback is NULL",
                )
            };
            return false;
        }
        let replacement = Arc::new(CEventTarget {
            callback,
            user_data: user_data as usize,
            release,
            callback_gate: std::sync::Mutex::new(CallbackGateState::default()),
            callback_ready: std::sync::Condvar::new(),
            active: AtomicBool::new(false),
        });
        builder.config.renderer.replace(replacement)
    };
    // Dropping the previous target calls foreign code. Its mutable builder
    // borrow is now out of scope, so a release callback may safely re-enter this
    // setter on the same builder.
    drop(previous);
    true
}

/// Install a persistence diagnostic callback. It may run on a token-provider
/// or transport thread, is serialized, must return promptly, and must not
/// unwind or re-enter the auth/transport operation that emitted it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_builder_diagnostic_handler(
    builder: *mut questdb_oidc_builder,
    callback: questdb_oidc_diagnostic_cb,
    user_data: *mut c_void,
    release: questdb_oidc_user_data_release_cb,
    err_out: *mut *mut questdb_error,
) -> bool {
    let previous = {
        let Some(builder) = (unsafe { builder_mut(builder, err_out) }) else {
            return false;
        };
        let Some(callback) = callback else {
            unsafe {
                set_input_error(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    "OIDC diagnostic callback is NULL",
                )
            };
            return false;
        };
        if !user_data.is_null() && release.is_none() {
            unsafe {
                set_input_error(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    "OIDC diagnostic user_data is non-NULL but its release callback is NULL",
                )
            };
            return false;
        }
        let replacement = Arc::new(CDiagnosticTarget {
            callback,
            user_data: user_data as usize,
            release,
            callback_gate: std::sync::Mutex::new(CallbackGateState::default()),
            callback_ready: std::sync::Condvar::new(),
            active: AtomicBool::new(false),
        });
        builder.config.diagnostic.replace(replacement)
    };
    drop(previous);
    true
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_builder_build(
    builder: *const questdb_oidc_builder,
    err_out: *mut *mut questdb_error,
) -> *mut questdb_oidc_auth {
    if builder.is_null() {
        unsafe {
            set_input_error(
                err_out,
                ErrorCode::InvalidApiCall,
                "OIDC builder pointer is NULL",
            )
        };
        return ptr::null_mut();
    }
    let config = unsafe { &(*builder).config };
    match config.build() {
        Ok((auth, event_handler, diagnostic)) => Box::into_raw(Box::new(questdb_oidc_auth {
            shared: SharedOidcAuth {
                inner: Arc::new(auth),
                event_handler,
                diagnostic,
                token_provider_isolation: TokenProviderIsolation::default(),
            },
        })),
        Err(err) => {
            unsafe { set_err_out_from_error(err_out, err) };
            ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_auth_clone(
    auth: *const questdb_oidc_auth,
    err_out: *mut *mut questdb_error,
) -> *mut questdb_oidc_auth {
    let Some(shared) = (unsafe { clone_auth(auth, err_out) }) else {
        return ptr::null_mut();
    };
    Box::into_raw(Box::new(questdb_oidc_auth { shared }))
}

/// Permanently stop delivering this auth's renderer events without closing it.
///
/// Returns once no event callback is running for it and no later one can start.
/// Idempotent and NULL-tolerant. From inside this auth's callback it publishes
/// suppression and returns without waiting for its own frame. From inside a
/// different auth's event callback the drain is bounded to avoid a cross-target
/// AB/BA deadlock; suppression remains exact.
///
/// Other auths built from the same reusable builder keep delivering events.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_auth_detach_events(auth: *const questdb_oidc_auth) {
    if auth.is_null() {
        return;
    }
    if let Some(handler) = unsafe { &(*auth).shared.event_handler } {
        handler.detach();
    }
}

/// As [`questdb_oidc_auth_detach_events`], but never waits for a renderer
/// callback that is already running.
///
/// Later events are suppressed exactly as with the waiting form; only the "no
/// callback is still running on return" guarantee is given up. Use this from a
/// finalizer, garbage-collection hook, interpreter shutdown hook, or any other
/// context that must not wait for arbitrary user callback code.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_auth_detach_events_nowait(auth: *const questdb_oidc_auth) {
    if auth.is_null() {
        return;
    }
    if let Some(handler) = unsafe { &(*auth).shared.event_handler } {
        handler.detach_nowait();
    }
}

/// Permanently stop delivering this auth's persistence diagnostics.
///
/// Returns once no diagnostic callback is running for it and no later one can
/// start. Idempotent, NULL-tolerant, and safe to call from any thread.
///
/// From inside the diagnostic callback it degrades to publishing the flag: the
/// only invocation it could drain is the caller's own frame. Later diagnostics
/// are still suppressed.
///
/// This exists for a binding whose callback enters a managed runtime it is
/// about to lose -- a garbage-collected handle being reclaimed, or an
/// interpreter beginning to shut down -- while a background token-provider or
/// transport thread may still hold a clone of this auth and reach a token-store
/// write. Closing an auth also ends its diagnostics, because a closed auth
/// performs no further store writes; this is the operation for the case where
/// the owner is going away without being able to wait for that.
///
/// Other auths built from the same builder keep delivering.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_auth_detach_diagnostics(auth: *const questdb_oidc_auth) {
    if auth.is_null() {
        return;
    }
    if let Some(sink) = unsafe { &(*auth).shared.diagnostic } {
        sink.detach();
    }
}

/// As [`questdb_oidc_auth_detach_diagnostics`], but never waits for a callback
/// that is already running.
///
/// Later diagnostics are suppressed exactly as with the waiting form; only the
/// "no callback is still running on return" guarantee is given up. Use this
/// from a finalizer, garbage-collection hook, or any context that cannot prove
/// the calling thread holds no lock the diagnostic callback might acquire --
/// the waiting form deadlocks against such a lock, and dropping the binding's
/// global runtime lock does not prevent it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_auth_detach_diagnostics_nowait(
    auth: *const questdb_oidc_auth,
) {
    if auth.is_null() {
        return;
    }
    if let Some(sink) = unsafe { &(*auth).shared.diagnostic } {
        sink.detach_nowait();
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_auth_free(auth: *mut questdb_oidc_auth) {
    if !auth.is_null() {
        unsafe { drop(Box::from_raw(auth)) };
    }
}

/// Cancel only the currently running interactive device flow.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_auth_cancel_sign_in(
    auth: *const questdb_oidc_auth,
    err_out: *mut *mut questdb_error,
) -> bool {
    let Some(auth) = (unsafe { clone_auth(auth, err_out) }) else {
        return false;
    };
    match auth.cancel_sign_in() {
        Ok(()) => true,
        Err(err) => {
            unsafe { set_err_out_from_error(err_out, err) };
            false
        }
    }
}

/// Permanently close this shared auth state and cancel interruptible waits.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_auth_close(
    auth: *const questdb_oidc_auth,
    err_out: *mut *mut questdb_error,
) -> bool {
    let Some(auth) = (unsafe { clone_auth(auth, err_out) }) else {
        return false;
    };
    match auth.close() {
        Ok(()) => true,
        Err(err) => {
            unsafe { set_err_out_from_error(err_out, err) };
            false
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_auth_sign_in(
    auth: *const questdb_oidc_auth,
    err_out: *mut *mut questdb_error,
) -> bool {
    let Some(auth) = (unsafe { clone_auth(auth, err_out) }) else {
        return false;
    };
    match auth.sign_in() {
        Ok(()) => true,
        Err(err) => {
            unsafe { set_err_out_from_error(err_out, err) };
            false
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_auth_token(
    auth: *const questdb_oidc_auth,
    err_out: *mut *mut questdb_error,
) -> *mut questdb_oidc_token {
    let Some(auth) = (unsafe { clone_auth(auth, err_out) }) else {
        return ptr::null_mut();
    };
    match auth.token() {
        Ok(value) => Box::into_raw(Box::new(questdb_oidc_token {
            value: Zeroizing::new(value),
        })),
        Err(err) => {
            unsafe { set_err_out_from_error(err_out, err) };
            ptr::null_mut()
        }
    }
}

/// Clear in-memory credentials and delete any persisted local entry.
///
/// Memory is cleared even if deletion fails. Such a failure is returned because
/// a new auth object or process may still load the persisted credential. This
/// does not revoke tokens at the identity provider.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_auth_clear(
    auth: *const questdb_oidc_auth,
    err_out: *mut *mut questdb_error,
) -> bool {
    let Some(auth) = (unsafe { clone_auth(auth, err_out) }) else {
        return false;
    };
    match auth.clear() {
        Ok(()) => true,
        Err(err) => {
            unsafe { set_err_out_from_error(err_out, err) };
            false
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_token_data(
    token: *const questdb_oidc_token,
) -> *const c_char {
    if token.is_null() {
        return ptr::null();
    }
    unsafe { (*token).value.as_ptr() as *const c_char }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_token_len(token: *const questdb_oidc_token) -> size_t {
    if token.is_null() {
        return 0;
    }
    let token = unsafe { &*token };
    token.value.len()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_token_free(token: *mut questdb_oidc_token) {
    if !token.is_null() {
        unsafe { drop(Box::from_raw(token)) };
    }
}

/// Resolved OIDC configuration. Strings borrow from the auth handle.
#[repr(C)]
pub struct questdb_oidc_config_view {
    pub struct_size: size_t,
    pub groups_in_token: bool,
    pub client_id: *const c_char,
    pub client_id_len: size_t,
    pub token_endpoint: *const c_char,
    pub token_endpoint_len: size_t,
    pub device_authorization_endpoint: *const c_char,
    pub device_authorization_endpoint_len: size_t,
    pub scope: *const c_char,
    pub scope_len: size_t,
    pub audience: *const c_char,
    pub audience_len: size_t,
    pub issuer: *const c_char,
    pub issuer_len: size_t,
}

// Pin the initial output layouts independently of future appended fields.
// Both v1 structs deliberately end in a naturally aligned integer so adding a
// field cannot hide inside trailing padding without increasing struct_size.
const QUESTDB_OIDC_CONFIG_VIEW_V1_SIZE: usize =
    std::mem::offset_of!(questdb_oidc_config_view, issuer_len) + std::mem::size_of::<size_t>();

unsafe fn versioned_output_capacity<T>(out: *mut T, minimum_size: usize) -> Option<usize> {
    if out.is_null() {
        return None;
    }
    let capacity = unsafe { out.cast::<size_t>().read() };
    if capacity < minimum_size {
        // The pointer contract requires storage for at least struct_size even
        // when its value is invalid, so report the required v1 capacity there.
        unsafe { out.cast::<size_t>().write(minimum_size) };
        return None;
    }
    Some(capacity)
}

unsafe fn write_versioned_output<T>(out: *mut T, capacity: usize, value: &T) {
    unsafe {
        std::ptr::copy_nonoverlapping(
            (value as *const T).cast::<u8>(),
            out.cast::<u8>(),
            capacity.min(std::mem::size_of::<T>()),
        )
    };
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_oidc_auth_get_config(
    auth: *const questdb_oidc_auth,
    out: *mut questdb_oidc_config_view,
) -> bool {
    if auth.is_null() {
        return false;
    }
    let Some(capacity) =
        (unsafe { versioned_output_capacity(out, QUESTDB_OIDC_CONFIG_VIEW_V1_SIZE) })
    else {
        return false;
    };
    let config = unsafe { (*auth).shared.inner.config() };
    let (client_id, client_id_len) = str_or_null(Some(&config.client_id));
    let (token_endpoint, token_endpoint_len) = str_or_null(Some(&config.token_endpoint));
    let (device_authorization_endpoint, device_authorization_endpoint_len) =
        str_or_null(Some(&config.device_authorization_endpoint));
    let (scope, scope_len) = str_or_null(Some(&config.scope));
    let (audience, audience_len) = str_or_null(config.audience.as_deref());
    let (issuer, issuer_len) = str_or_null(config.issuer.as_deref());
    let written_size = capacity.min(std::mem::size_of::<questdb_oidc_config_view>());
    let mut value = unsafe { std::mem::zeroed::<questdb_oidc_config_view>() };
    value.struct_size = written_size;
    value.groups_in_token = config.groups_in_token;
    value.client_id = client_id;
    value.client_id_len = client_id_len;
    value.token_endpoint = token_endpoint;
    value.token_endpoint_len = token_endpoint_len;
    value.device_authorization_endpoint = device_authorization_endpoint;
    value.device_authorization_endpoint_len = device_authorization_endpoint_len;
    value.scope = scope;
    value.scope_len = scope_len;
    value.audience = audience;
    value.audience_len = audience_len;
    value.issuer = issuer;
    value.issuer_len = issuer_len;
    unsafe { write_versioned_output(out, capacity, &value) };
    true
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum questdb_oidc_error_kind {
    QUESTDB_OIDC_ERROR_CONFIG = 0,
    QUESTDB_OIDC_ERROR_NETWORK = 1,
    QUESTDB_OIDC_ERROR_DEVICE_FLOW = 2,
    QUESTDB_OIDC_ERROR_TIMEOUT = 3,
    QUESTDB_OIDC_ERROR_INTERACTION_REQUIRED = 4,
    QUESTDB_OIDC_ERROR_CANCELLED = 5,
    QUESTDB_OIDC_ERROR_UNKNOWN = 255,
}

#[repr(C)]
pub struct questdb_oidc_error_view {
    pub struct_size: size_t,
    pub kind: questdb_oidc_error_kind,
    pub idp_error: *const c_char,
    pub idp_error_len: size_t,
    pub idp_error_description: *const c_char,
    pub idp_error_description_len: size_t,
    pub has_status: bool,
    pub status: u16,
    pub has_retry_after: bool,
    pub retry_after_seconds: u64,
    /// True when InteractionRequired means a peer temporarily owns the
    /// acquisition/callback path rather than that human sign-in is needed.
    pub acquisition_busy: bool,
}

const QUESTDB_OIDC_ERROR_VIEW_V1_SIZE: usize =
    std::mem::offset_of!(questdb_oidc_error_view, retry_after_seconds) + std::mem::size_of::<u64>();

fn error_kind(kind: OidcErrorKind) -> questdb_oidc_error_kind {
    match kind {
        OidcErrorKind::Config => questdb_oidc_error_kind::QUESTDB_OIDC_ERROR_CONFIG,
        OidcErrorKind::Network => questdb_oidc_error_kind::QUESTDB_OIDC_ERROR_NETWORK,
        OidcErrorKind::DeviceFlow => questdb_oidc_error_kind::QUESTDB_OIDC_ERROR_DEVICE_FLOW,
        OidcErrorKind::Timeout => questdb_oidc_error_kind::QUESTDB_OIDC_ERROR_TIMEOUT,
        OidcErrorKind::InteractionRequired => {
            questdb_oidc_error_kind::QUESTDB_OIDC_ERROR_INTERACTION_REQUIRED
        }
        OidcErrorKind::Cancelled => questdb_oidc_error_kind::QUESTDB_OIDC_ERROR_CANCELLED,
        _ => questdb_oidc_error_kind::QUESTDB_OIDC_ERROR_UNKNOWN,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_error_oidc_get_view(
    error: *const questdb_error,
    out: *mut questdb_oidc_error_view,
) -> bool {
    if error.is_null() {
        return false;
    }
    let Some(capacity) =
        (unsafe { versioned_output_capacity(out, QUESTDB_OIDC_ERROR_VIEW_V1_SIZE) })
    else {
        return false;
    };
    let Some(oidc) = (unsafe { (*error).error.oidc_error() }) else {
        return false;
    };
    let (idp_error, idp_error_len) = str_or_null(oidc.idp_error());
    let (idp_error_description, idp_error_description_len) =
        str_or_null(oidc.idp_error_description());
    let status = oidc.status();
    let retry_after = oidc.retry_after_secs();
    let written_size = capacity.min(std::mem::size_of::<questdb_oidc_error_view>());
    let mut value = unsafe { std::mem::zeroed::<questdb_oidc_error_view>() };
    value.struct_size = written_size;
    value.kind = error_kind(oidc.kind());
    value.idp_error = idp_error;
    value.idp_error_len = idp_error_len;
    value.idp_error_description = idp_error_description;
    value.idp_error_description_len = idp_error_description_len;
    value.has_status = status.is_some();
    value.status = status.unwrap_or(0);
    value.has_retry_after = retry_after.is_some();
    value.retry_after_seconds = retry_after.unwrap_or(0);
    value.acquisition_busy = oidc.acquisition_busy();
    unsafe { write_versioned_output(out, capacity, &value) };
    true
}

/// Attach this OIDC state as a rotating, non-prompting provider to an HTTP(S)
/// or QWP/WebSocket sender builder. Explicit sign-in must happen before a
/// transport needs a token that cannot be loaded or silently refreshed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_opts_oidc_auth(
    opts: *mut line_sender_opts,
    auth: *const questdb_oidc_auth,
    err_out: *mut *mut line_sender_error,
) -> bool {
    if opts.is_null() {
        unsafe {
            set_input_error(
                err_out,
                ErrorCode::InvalidApiCall,
                "line_sender_opts_oidc_auth requires non-NULL opts",
            )
        };
        return false;
    }
    let Some(auth) = (unsafe { clone_auth(auth, err_out) }) else {
        return false;
    };
    let current = unsafe { (*opts).0.clone() };
    let isolation = auth.token_provider_isolation();
    match current.bearer_token_provider_with_isolation(move || auth.token(), isolation) {
        Ok(updated) => {
            unsafe { (*opts).0 = updated };
            true
        }
        Err(err) => {
            unsafe { set_err_out_from_error(err_out, err) };
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use questdb::oidc::{PersistedToken, TokenStore, TokenStoreKey, TokenStoreResult};
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

    #[test]
    fn oidc_paths_reject_an_unexpanded_home_prefix() {
        // A shell expands `~`; no runtime here does. For a token store this can
        // leave a plaintext refresh token under an accidental working-directory
        // path; for a CA bundle it produces a misleading file-open failure.
        // Apply one spelling rule to both public path-taking builder methods.
        for label in ["OIDC token-store directory", "OIDC CA-bundle path"] {
            for bad in ["~", "~/tokens", "~/.questdb/oidc-tokens"] {
                assert!(
                    reject_unexpanded_home(bad, label).is_err(),
                    "{label}: {bad:?} must be rejected"
                );
            }
            // An already-expanded path, a relative one, and a name that merely
            // contains a tilde all stay acceptable.
            for ok in ["/home/u/.questdb/oidc-tokens", "tokens", "./t", "a~b"] {
                assert!(
                    reject_unexpanded_home(ok, label).is_ok(),
                    "{label}: {ok:?} must be accepted"
                );
            }
        }
    }

    unsafe extern "C" fn record_diagnostic(
        user_data: *mut c_void,
        diagnostic: *const questdb_oidc_diagnostic,
    ) {
        let messages = unsafe { &*(user_data as *const Mutex<Vec<String>>) };
        let diagnostic = unsafe { &*diagnostic };
        let message = unsafe {
            std::str::from_utf8_unchecked(std::slice::from_raw_parts(
                diagnostic.message.cast::<u8>(),
                diagnostic.message_len,
            ))
        };
        messages.lock().unwrap().push(message.to_string());
    }

    #[test]
    fn persistence_diagnostic_is_bounded_sanitized_and_separate_from_renderer() {
        let messages = Mutex::new(Vec::<String>::new());
        let target = Arc::new(CDiagnosticTarget {
            callback: record_diagnostic,
            user_data: (&messages as *const Mutex<Vec<String>>) as usize,
            release: None,
            callback_gate: Mutex::new(CallbackGateState::default()),
            callback_ready: std::sync::Condvar::new(),
            active: AtomicBool::new(false),
        });
        let sink = CDiagnosticSink {
            target,
            state: Arc::new(CDiagnosticState::default()),
        };
        sink.on_persistence_warning("save failed\n\x1b[31m");
        let messages = messages.lock().unwrap();
        assert_eq!(messages.len(), 1);
        assert!(!messages[0].contains('\n'));
        assert!(!messages[0].contains('\x1b'));
    }

    #[test]
    fn detaching_diagnostics_stops_delivery_without_silencing_siblings() {
        // A binding detaches when its callback stops being callable -- a
        // collected handle, or an interpreter shutting down -- while a
        // detached token-provider worker may still hold a clone of the auth
        // and reach a store write. After detach, that write must not reach the
        // callback. The per-auth state keeps a sibling built from the same
        // reusable builder (which shares the caller-owned `user_data`)
        // delivering.
        let messages = Mutex::new(Vec::<String>::new());
        let target = Arc::new(CDiagnosticTarget {
            callback: record_diagnostic,
            user_data: (&messages as *const Mutex<Vec<String>>) as usize,
            release: None,
            callback_gate: Mutex::new(CallbackGateState::default()),
            callback_ready: std::sync::Condvar::new(),
            active: AtomicBool::new(false),
        });
        let detached = CDiagnosticSink {
            target: Arc::clone(&target),
            state: Arc::new(CDiagnosticState::default()),
        };
        let sibling = CDiagnosticSink {
            target,
            state: Arc::new(CDiagnosticState::default()),
        };

        detached.on_persistence_warning("before detach");
        detached.detach();
        detached.on_persistence_warning("after detach");
        // Idempotent, and a clone of the same auth's sink is equally detached.
        detached.detach();
        detached.clone().on_persistence_warning("via clone");
        sibling.on_persistence_warning("sibling still delivering");

        let messages = messages.lock().unwrap();
        assert_eq!(
            *messages,
            vec![
                "before detach".to_string(),
                "sibling still delivering".to_string()
            ]
        );
    }

    #[test]
    fn detaching_diagnostics_from_inside_the_callback_does_not_deadlock() {
        // A binding reaches this without anyone writing such a call: the
        // callback enters a managed runtime, and a collection there destroys a
        // handle, whose teardown detaches. Detach must recognize its own
        // logical callback ownership rather than waiting for that invocation to
        // return -- which cannot happen until detach itself returns.
        static SINK: Mutex<Option<CDiagnosticSink>> = Mutex::new(None);
        static DETACH_RETURNED: AtomicUsize = AtomicUsize::new(0);

        unsafe extern "C" fn detach_from_within(
            _user_data: *mut c_void,
            _diagnostic: *const questdb_oidc_diagnostic,
        ) {
            let sink = SINK.lock().unwrap().clone().expect("sink installed");
            sink.detach();
            DETACH_RETURNED.fetch_add(1, Ordering::SeqCst);
        }

        let sink = CDiagnosticSink {
            target: Arc::new(CDiagnosticTarget {
                callback: detach_from_within,
                user_data: 0,
                release: None,
                callback_gate: Mutex::new(CallbackGateState::default()),
                callback_ready: std::sync::Condvar::new(),
                active: AtomicBool::new(false),
            }),
            state: Arc::new(CDiagnosticState::default()),
        };
        *SINK.lock().unwrap() = Some(sink.clone());

        // Emit off-thread so a regression fails the test instead of hanging
        // the whole run: a deadlock here is unkillable from inside the test.
        let (tx, rx) = std::sync::mpsc::channel();
        let emitter = std::thread::spawn({
            let sink = sink.clone();
            move || {
                sink.on_persistence_warning("reentrant");
                let _ = tx.send(());
            }
        });
        rx.recv_timeout(std::time::Duration::from_secs(5))
            .expect("detach from inside the callback must not deadlock");
        emitter.join().unwrap();

        assert_eq!(DETACH_RETURNED.load(Ordering::SeqCst), 1);
        // The flag was still published, so later diagnostics stay suppressed.
        sink.on_persistence_warning("after");
        assert_eq!(DETACH_RETURNED.load(Ordering::SeqCst), 1);
        // The gate is free: an unrelated detach still completes.
        sink.detach();
        *SINK.lock().unwrap() = None;
    }

    #[test]
    fn cross_target_detach_from_inside_a_callback_cannot_deadlock() {
        // Two providers, two independent logical gates. Each thread is inside
        // its own target's callback and detaches the OTHER one -- which is what
        // a binding does when the callback's managed code reclaims an unrelated
        // handle. Draining the foreign callback here is an AB/BA inversion that
        // parks both threads permanently.
        static A_ENTERED: AtomicUsize = AtomicUsize::new(0);
        static B_ENTERED: AtomicUsize = AtomicUsize::new(0);
        static SINK_A: Mutex<Option<CDiagnosticSink>> = Mutex::new(None);
        static SINK_B: Mutex<Option<CDiagnosticSink>> = Mutex::new(None);

        // Inside A's callback: wait until B is provably inside its own
        // callback, then detach B. Pre-fix this blocks on B's gate forever.
        unsafe extern "C" fn a_callback(
            _user_data: *mut c_void,
            _diagnostic: *const questdb_oidc_diagnostic,
        ) {
            A_ENTERED.fetch_add(1, Ordering::SeqCst);
            while B_ENTERED.load(Ordering::SeqCst) == 0 {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            let sink = SINK_B.lock().unwrap().clone().expect("B installed");
            sink.detach();
        }
        unsafe extern "C" fn b_callback(
            _user_data: *mut c_void,
            _diagnostic: *const questdb_oidc_diagnostic,
        ) {
            B_ENTERED.fetch_add(1, Ordering::SeqCst);
            while A_ENTERED.load(Ordering::SeqCst) == 0 {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            let sink = SINK_A.lock().unwrap().clone().expect("A installed");
            sink.detach();
        }

        fn sink_with(
            callback: unsafe extern "C" fn(*mut c_void, *const questdb_oidc_diagnostic),
        ) -> CDiagnosticSink {
            CDiagnosticSink {
                target: Arc::new(CDiagnosticTarget {
                    callback,
                    user_data: 0,
                    release: None,
                    callback_gate: Mutex::new(CallbackGateState::default()),
                    callback_ready: std::sync::Condvar::new(),
                    active: AtomicBool::new(false),
                }),
                state: Arc::new(CDiagnosticState::default()),
            }
        }
        let a = sink_with(a_callback);
        let b = sink_with(b_callback);
        *SINK_A.lock().unwrap() = Some(a.clone());
        *SINK_B.lock().unwrap() = Some(b.clone());

        let (tx, rx) = std::sync::mpsc::channel();
        let ta = std::thread::spawn({
            let a = a.clone();
            let tx = tx.clone();
            move || {
                a.on_persistence_warning("a");
                let _ = tx.send(());
            }
        });
        let tb = std::thread::spawn({
            let b = b.clone();
            move || {
                b.on_persistence_warning("b");
                let _ = tx.send(());
            }
        });
        for _ in 0..2 {
            rx.recv_timeout(std::time::Duration::from_secs(10))
                .expect("cross-target detach must not deadlock");
        }
        ta.join().unwrap();
        tb.join().unwrap();

        // Both were entered exactly once, and suppression still took effect
        // even though the drain was downgraded to best-effort.
        assert_eq!(A_ENTERED.load(Ordering::SeqCst), 1);
        assert_eq!(B_ENTERED.load(Ordering::SeqCst), 1);
        a.on_persistence_warning("a again");
        b.on_persistence_warning("b again");
        assert_eq!(A_ENTERED.load(Ordering::SeqCst), 1);
        assert_eq!(B_ENTERED.load(Ordering::SeqCst), 1);
        *SINK_A.lock().unwrap() = None;
        *SINK_B.lock().unwrap() = None;
    }

    #[test]
    fn event_and_diagnostic_detach_each_other_without_deadlock() {
        // Cross-kind variant of the AB/BA regression above. Each callback owns
        // one logical target gate and reclaims the other kind of callback
        // target. Looking only at the same-kind TLS stack makes both detach
        // calls perform an unbounded drain and park forever.
        static EVENT_ENTERED: AtomicUsize = AtomicUsize::new(0);
        static DIAGNOSTIC_ENTERED: AtomicUsize = AtomicUsize::new(0);
        static EVENT_HANDLER: Mutex<Option<Arc<CEventHandler>>> = Mutex::new(None);
        static DIAGNOSTIC_SINK: Mutex<Option<CDiagnosticSink>> = Mutex::new(None);

        unsafe extern "C" fn event_callback(
            _user_data: *mut c_void,
            _event: *const questdb_oidc_event,
        ) {
            EVENT_ENTERED.store(1, Ordering::SeqCst);
            while DIAGNOSTIC_ENTERED.load(Ordering::SeqCst) == 0 {
                std::thread::yield_now();
            }
            DIAGNOSTIC_SINK
                .lock()
                .unwrap()
                .as_ref()
                .expect("diagnostic sink installed")
                .detach();
        }

        unsafe extern "C" fn diagnostic_callback(
            _user_data: *mut c_void,
            _diagnostic: *const questdb_oidc_diagnostic,
        ) {
            DIAGNOSTIC_ENTERED.store(1, Ordering::SeqCst);
            while EVENT_ENTERED.load(Ordering::SeqCst) == 0 {
                std::thread::yield_now();
            }
            EVENT_HANDLER
                .lock()
                .unwrap()
                .as_ref()
                .expect("event handler installed")
                .detach();
        }

        EVENT_ENTERED.store(0, Ordering::SeqCst);
        DIAGNOSTIC_ENTERED.store(0, Ordering::SeqCst);
        let handler = Arc::new(CEventHandler::new(Arc::new(CEventTarget {
            callback: event_callback,
            user_data: 0,
            release: None,
            callback_gate: Mutex::new(CallbackGateState::default()),
            callback_ready: std::sync::Condvar::new(),
            active: AtomicBool::new(false),
        })));
        let sink = CDiagnosticSink {
            target: Arc::new(CDiagnosticTarget {
                callback: diagnostic_callback,
                user_data: 0,
                release: None,
                callback_gate: Mutex::new(CallbackGateState::default()),
                callback_ready: std::sync::Condvar::new(),
                active: AtomicBool::new(false),
            }),
            state: Arc::new(CDiagnosticState::default()),
        };
        *EVENT_HANDLER.lock().unwrap() = Some(Arc::clone(&handler));
        *DIAGNOSTIC_SINK.lock().unwrap() = Some(sink.clone());

        let (tx, rx) = std::sync::mpsc::channel();
        let event_thread = std::thread::spawn({
            let renderer = CEventRenderer(Arc::clone(&handler));
            let tx = tx.clone();
            move || {
                renderer.invoke(&empty_event(
                    questdb_oidc_event_kind::QUESTDB_OIDC_EVENT_WAITING,
                ));
                let _ = tx.send(());
            }
        });
        let diagnostic_thread = std::thread::spawn({
            let sink = sink.clone();
            move || {
                sink.on_persistence_warning("cross-kind");
                let _ = tx.send(());
            }
        });
        for _ in 0..2 {
            rx.recv_timeout(std::time::Duration::from_secs(10))
                .expect("cross-kind detach must not deadlock");
        }
        event_thread.join().unwrap();
        diagnostic_thread.join().unwrap();

        // Both detach publications remain exact even though their drains were
        // downgraded to bounded best-effort.
        CEventRenderer(Arc::clone(&handler)).invoke(&empty_event(
            questdb_oidc_event_kind::QUESTDB_OIDC_EVENT_WAITING,
        ));
        sink.on_persistence_warning("after");
        assert_eq!(EVENT_ENTERED.load(Ordering::SeqCst), 1);
        assert_eq!(DIAGNOSTIC_ENTERED.load(Ordering::SeqCst), 1);
        *EVENT_HANDLER.lock().unwrap() = None;
        *DIAGNOSTIC_SINK.lock().unwrap() = None;
    }

    #[test]
    fn nowait_detach_returns_while_a_callback_holds_the_gate() {
        // A finalizer reaches detach wherever a collection fired, so it can
        // already hold a lock the callback needs -- in the Python client, a
        // `logging` handler lock taken by the very `emit` the collection ran
        // inside, which the callback then tries to take when it logs. Waiting
        // for callback completion there parks both threads forever, and
        // releasing the GIL does not help because the GIL is not the lock in
        // contention. So this form must return while a callback is active.
        static NW_ENTERED: AtomicUsize = AtomicUsize::new(0);
        static NW_RELEASE: AtomicUsize = AtomicUsize::new(0);
        static NW_DELIVERED: AtomicUsize = AtomicUsize::new(0);

        unsafe extern "C" fn holding_diagnostic(
            _user_data: *mut c_void,
            _diagnostic: *const questdb_oidc_diagnostic,
        ) {
            NW_DELIVERED.fetch_add(1, Ordering::SeqCst);
            NW_ENTERED.fetch_add(1, Ordering::SeqCst);
            while NW_RELEASE.load(Ordering::SeqCst) == 0 {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }

        let sink = CDiagnosticSink {
            target: Arc::new(CDiagnosticTarget {
                callback: holding_diagnostic,
                user_data: 0,
                release: None,
                callback_gate: Mutex::new(CallbackGateState::default()),
                callback_ready: std::sync::Condvar::new(),
                active: AtomicBool::new(false),
            }),
            state: Arc::new(CDiagnosticState::default()),
        };

        // Park a callback inside the logical gate on another thread.
        let emitter = std::thread::spawn({
            let sink = sink.clone();
            move || sink.on_persistence_warning("in flight")
        });
        while NW_ENTERED.load(Ordering::SeqCst) == 0 {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }

        // The callback stays active until this test releases it. The waiting
        // form blocks here; this one must not. Run it off-thread so a regression
        // fails this test instead of hanging the entire run.
        let (tx, rx) = std::sync::mpsc::channel();
        let detacher = std::thread::spawn({
            let sink = sink.clone();
            move || {
                sink.detach_nowait();
                let _ = tx.send(());
            }
        });
        let outcome = rx.recv_timeout(std::time::Duration::from_secs(5));

        // Release before asserting, so even a failure lets both threads exit
        // and the harness report the failure rather than wedge.
        NW_RELEASE.store(1, Ordering::SeqCst);
        outcome.expect("nowait detach must not wait for the gate");
        detacher.join().unwrap();
        emitter.join().unwrap();

        // Suppression is still exact for everything after it.
        assert_eq!(NW_DELIVERED.load(Ordering::SeqCst), 1);
        sink.on_persistence_warning("after detach");
        assert_eq!(NW_DELIVERED.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn detaching_diagnostics_waits_for_a_callback_in_flight() {
        // Detach is a handshake, not a flag flip: it must not return while a
        // callback is still running, or a binding would tear down the runtime
        // that callback is inside.
        static ENTERED: AtomicUsize = AtomicUsize::new(0);
        static RELEASE: AtomicUsize = AtomicUsize::new(0);
        static RETURNED: AtomicUsize = AtomicUsize::new(0);

        unsafe extern "C" fn blocking_diagnostic(
            _user_data: *mut c_void,
            _diagnostic: *const questdb_oidc_diagnostic,
        ) {
            ENTERED.fetch_add(1, Ordering::SeqCst);
            while RELEASE.load(Ordering::SeqCst) == 0 {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            RETURNED.fetch_add(1, Ordering::SeqCst);
        }

        let sink = CDiagnosticSink {
            target: Arc::new(CDiagnosticTarget {
                callback: blocking_diagnostic,
                user_data: 0,
                release: None,
                callback_gate: Mutex::new(CallbackGateState::default()),
                callback_ready: std::sync::Condvar::new(),
                active: AtomicBool::new(false),
            }),
            state: Arc::new(CDiagnosticState::default()),
        };

        let emitter = std::thread::spawn({
            let sink = sink.clone();
            move || sink.on_persistence_warning("in flight")
        });
        while ENTERED.load(Ordering::SeqCst) == 0 {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }

        let detacher = std::thread::spawn(move || {
            sink.detach();
            // The callback must have returned before detach did.
            assert_eq!(RETURNED.load(Ordering::SeqCst), 1);
        });
        // Give detach a chance to return early if it were going to.
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert_eq!(RETURNED.load(Ordering::SeqCst), 0, "callback still running");
        RELEASE.store(1, Ordering::SeqCst);

        emitter.join().unwrap();
        detacher.join().unwrap();
    }

    #[test]
    fn token_busy_error_carries_a_structured_oidc_cause() {
        // The busy error reaches a caller through the transport's
        // provider-error path, where `questdb_error_oidc_get_view` decides
        // whether a binding reports a typed OIDC failure. A bare `Error::new`
        // answered false there, so Python raised a plain `QuestDBError` for a
        // condition `docs/auth.rst` types as `OidcInteractionRequired`.
        let err = SharedOidcAuth::token_busy_error();

        // The retryable classification is load-bearing and must not change:
        // `oidc.h` documents this window as `questdb_error_socket_error`, and a
        // terminal class strands a store-and-forward queue behind a prompt.
        assert_eq!(err.code(), ErrorCode::SocketError);
        assert_eq!(
            err.oidc_error().map(questdb::oidc::OidcError::kind),
            Some(OidcErrorKind::InteractionRequired),
            "the busy error must carry an OIDC cause the C view can surface"
        );

        // And the C predicate the header promises actually answers true.
        let boxed = Box::into_raw(Box::new(questdb_error {
            error: err,
            qwp_ws_error: None,
        }));
        let mut view = questdb_oidc_error_view {
            struct_size: std::mem::size_of::<questdb_oidc_error_view>(),
            ..unsafe { std::mem::zeroed() }
        };
        let seen = unsafe { questdb_error_oidc_get_view(boxed, &mut view) };
        assert!(seen, "questdb_error_oidc_get_view must report the cause");
        assert_eq!(
            view.kind,
            questdb_oidc_error_kind::QUESTDB_OIDC_ERROR_INTERACTION_REQUIRED
        );
        assert!(
            view.acquisition_busy,
            "the C view must preserve the transient contention discriminator"
        );
        unsafe { drop(Box::from_raw(boxed)) };
    }

    #[test]
    fn error_kind_maps_every_variant_away_from_unknown() {
        // The binding's `else -> base OidcError` (UNKNOWN=255) branch is reachable
        // only if a native error carries a kind outside 0..=5. Every real
        // OidcErrorKind must map to a specific FFI kind, keeping that branch
        // defensive / forward-compat only; a new unmapped variant here would
        // silently degrade the Python typed error to a base OidcError.
        let cases = [
            (
                OidcErrorKind::Config,
                questdb_oidc_error_kind::QUESTDB_OIDC_ERROR_CONFIG,
            ),
            (
                OidcErrorKind::Network,
                questdb_oidc_error_kind::QUESTDB_OIDC_ERROR_NETWORK,
            ),
            (
                OidcErrorKind::DeviceFlow,
                questdb_oidc_error_kind::QUESTDB_OIDC_ERROR_DEVICE_FLOW,
            ),
            (
                OidcErrorKind::Timeout,
                questdb_oidc_error_kind::QUESTDB_OIDC_ERROR_TIMEOUT,
            ),
            (
                OidcErrorKind::InteractionRequired,
                questdb_oidc_error_kind::QUESTDB_OIDC_ERROR_INTERACTION_REQUIRED,
            ),
            (
                OidcErrorKind::Cancelled,
                questdb_oidc_error_kind::QUESTDB_OIDC_ERROR_CANCELLED,
            ),
        ];
        for (kind, expected) in cases {
            assert_eq!(
                error_kind(kind) as u32,
                expected as u32,
                "{kind:?} mapped to the wrong FFI kind"
            );
            assert_ne!(
                error_kind(kind) as u32,
                questdb_oidc_error_kind::QUESTDB_OIDC_ERROR_UNKNOWN as u32,
                "{kind:?} degraded to UNKNOWN"
            );
        }
    }

    // Frozen copies of the first published output prefixes. They deliberately
    // remain unchanged when fields are appended to the public Rust structs.
    #[repr(C)]
    struct OidcConfigViewV1 {
        struct_size: size_t,
        groups_in_token: bool,
        client_id: *const c_char,
        client_id_len: size_t,
        token_endpoint: *const c_char,
        token_endpoint_len: size_t,
        device_authorization_endpoint: *const c_char,
        device_authorization_endpoint_len: size_t,
        scope: *const c_char,
        scope_len: size_t,
        audience: *const c_char,
        audience_len: size_t,
        issuer: *const c_char,
        issuer_len: size_t,
    }

    #[repr(C)]
    struct GuardedOidcConfigViewV1 {
        view: OidcConfigViewV1,
        canary: [u8; 16],
    }

    #[repr(C)]
    struct OidcErrorViewV1 {
        struct_size: size_t,
        kind: questdb_oidc_error_kind,
        idp_error: *const c_char,
        idp_error_len: size_t,
        idp_error_description: *const c_char,
        idp_error_description_len: size_t,
        has_status: bool,
        status: u16,
        has_retry_after: bool,
        retry_after_seconds: u64,
    }

    #[repr(C)]
    struct GuardedOidcErrorViewV1 {
        view: OidcErrorViewV1,
        canary: [u8; 16],
    }

    unsafe fn set_string(
        setter: unsafe extern "C" fn(
            *mut questdb_oidc_builder,
            *const c_char,
            size_t,
            *mut *mut questdb_error,
        ) -> bool,
        builder: *mut questdb_oidc_builder,
        value: &str,
    ) {
        let mut error = ptr::null_mut();
        assert!(unsafe {
            setter(
                builder,
                value.as_ptr() as *const c_char,
                value.len(),
                &mut error,
            )
        });
        assert!(error.is_null());
    }

    unsafe fn explicit_builder() -> *mut questdb_oidc_builder {
        let builder = questdb_oidc_builder_new();
        unsafe {
            set_string(questdb_oidc_builder_client_id, builder, "questdb-c");
            set_string(questdb_oidc_builder_scope, builder, "openid profile");
            set_string(
                questdb_oidc_builder_token_endpoint,
                builder,
                "https://idp.example/token",
            );
            set_string(
                questdb_oidc_builder_device_authorization_endpoint,
                builder,
                "https://idp.example/device",
            );
        }
        builder
    }

    fn event_target(
        callback: unsafe extern "C" fn(*mut c_void, *const questdb_oidc_event),
        user_data: usize,
        release: questdb_oidc_user_data_release_cb,
    ) -> Arc<CEventTarget> {
        Arc::new(CEventTarget {
            callback,
            user_data,
            release,
            callback_gate: std::sync::Mutex::new(CallbackGateState::default()),
            callback_ready: std::sync::Condvar::new(),
            active: AtomicBool::new(false),
        })
    }

    fn event_handler(
        callback: unsafe extern "C" fn(*mut c_void, *const questdb_oidc_event),
        user_data: usize,
        release: questdb_oidc_user_data_release_cb,
    ) -> Arc<CEventHandler> {
        Arc::new(CEventHandler::new(event_target(
            callback, user_data, release,
        )))
    }

    unsafe fn auth_with_event_handler(
        callback: unsafe extern "C" fn(*mut c_void, *const questdb_oidc_event),
    ) -> (*mut questdb_oidc_auth, Arc<CEventHandler>) {
        let builder = unsafe { explicit_builder() };
        let mut error = ptr::null_mut();
        assert!(unsafe {
            questdb_oidc_builder_event_handler(
                builder,
                Some(callback),
                ptr::null_mut(),
                None,
                &mut error,
            )
        });
        assert!(error.is_null());
        let auth = unsafe { questdb_oidc_builder_build(builder, &mut error) };
        assert!(!auth.is_null());
        assert!(error.is_null());
        let handler = Arc::clone(unsafe { (*auth).shared.event_handler.as_ref().unwrap() });
        unsafe { questdb_oidc_builder_free(builder) };
        (auth, handler)
    }

    #[test]
    fn detaching_events_suppresses_only_that_auth() {
        unsafe extern "C" fn count_event(
            user_data: *mut c_void,
            _event: *const questdb_oidc_event,
        ) {
            let calls = unsafe { &*(user_data as *const AtomicUsize) };
            calls.fetch_add(1, Ordering::SeqCst);
        }

        let calls = AtomicUsize::new(0);
        let target = event_target(count_event, (&calls as *const AtomicUsize) as usize, None);
        let detached = Arc::new(CEventHandler::new(Arc::clone(&target)));
        let sibling = Arc::new(CEventHandler::new(target));
        let detached_renderer = CEventRenderer(Arc::clone(&detached));
        let sibling_renderer = CEventRenderer(sibling);
        let event = empty_event(questdb_oidc_event_kind::QUESTDB_OIDC_EVENT_WAITING);

        detached_renderer.invoke(&event);
        detached.detach();
        detached_renderer.invoke(&event);
        sibling_renderer.invoke(&event);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn detach_events_ffi_waits_for_an_inflight_callback() {
        static ENTERED: AtomicUsize = AtomicUsize::new(0);
        static RELEASE: AtomicUsize = AtomicUsize::new(0);
        static RETURNED: AtomicUsize = AtomicUsize::new(0);

        unsafe extern "C" fn blocking_event(
            _user_data: *mut c_void,
            _event: *const questdb_oidc_event,
        ) {
            ENTERED.store(1, Ordering::SeqCst);
            while RELEASE.load(Ordering::SeqCst) == 0 {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            RETURNED.store(1, Ordering::SeqCst);
        }

        ENTERED.store(0, Ordering::SeqCst);
        RELEASE.store(0, Ordering::SeqCst);
        RETURNED.store(0, Ordering::SeqCst);
        let (auth, handler) = unsafe { auth_with_event_handler(blocking_event) };
        let renderer = CEventRenderer(Arc::clone(&handler));
        let emitter = std::thread::spawn(move || {
            renderer.invoke(&empty_event(
                questdb_oidc_event_kind::QUESTDB_OIDC_EVENT_WAITING,
            ));
        });
        while ENTERED.load(Ordering::SeqCst) == 0 {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let auth_addr = auth as usize;
        let detacher = std::thread::spawn(move || {
            unsafe { questdb_oidc_auth_detach_events(auth_addr as *const questdb_oidc_auth) };
            let _ = tx.send(RETURNED.load(Ordering::SeqCst));
        });
        // First prove that the detacher has actually run and published
        // suppression. Without this synchronization, an empty result channel
        // could mean only that the detacher had not been scheduled yet, so a
        // mutation to the nowait implementation could still pass by chance.
        while !handler.closed.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
        assert!(
            matches!(rx.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty)),
            "detach returned while the event callback was still active"
        );
        RELEASE.store(1, Ordering::SeqCst);
        assert_eq!(
            rx.recv_timeout(std::time::Duration::from_secs(5))
                .expect("event detach did not drain after callback return"),
            1
        );
        emitter.join().unwrap();
        detacher.join().unwrap();
        unsafe { questdb_oidc_auth_free(auth) };
    }

    #[test]
    fn detach_events_does_not_wait_for_a_sibling_callback() {
        // Auths built from one reusable builder share the serializing callback
        // target. Detaching A must wait for A's callback only: waiting out B's
        // blocked the caller indefinitely, and deadlocked it when B's callback
        // waited for the detaching thread.
        static ENTERED: AtomicUsize = AtomicUsize::new(0);
        static RELEASE: AtomicUsize = AtomicUsize::new(0);

        unsafe extern "C" fn blocking_event(
            _user_data: *mut c_void,
            _event: *const questdb_oidc_event,
        ) {
            ENTERED.store(1, Ordering::SeqCst);
            while RELEASE.load(Ordering::SeqCst) == 0 {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }

        ENTERED.store(0, Ordering::SeqCst);
        RELEASE.store(0, Ordering::SeqCst);
        let builder = unsafe { explicit_builder() };
        let mut error = ptr::null_mut();
        assert!(unsafe {
            questdb_oidc_builder_event_handler(
                builder,
                Some(blocking_event),
                ptr::null_mut(),
                None,
                &mut error,
            )
        });
        let a = unsafe { questdb_oidc_builder_build(builder, &mut error) };
        let b = unsafe { questdb_oidc_builder_build(builder, &mut error) };
        assert!(!a.is_null() && !b.is_null());
        let a_handler = Arc::clone(unsafe { (*a).shared.event_handler.as_ref().unwrap() });
        let b_handler = Arc::clone(unsafe { (*b).shared.event_handler.as_ref().unwrap() });
        assert!(Arc::ptr_eq(&a_handler.target, &b_handler.target));

        let renderer = CEventRenderer(Arc::clone(&b_handler));
        let emitter = std::thread::spawn(move || {
            renderer.invoke(&empty_event(
                questdb_oidc_event_kind::QUESTDB_OIDC_EVENT_WAITING,
            ));
        });
        while ENTERED.load(Ordering::SeqCst) == 0 {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let a_addr = a as usize;
        let detacher = std::thread::spawn(move || {
            unsafe { questdb_oidc_auth_detach_events(a_addr as *const questdb_oidc_auth) };
            let _ = tx.send(());
        });
        let outcome = rx.recv_timeout(std::time::Duration::from_secs(5));
        // Release before asserting so a regression reports instead of hanging.
        RELEASE.store(1, Ordering::SeqCst);
        outcome.expect("detaching A waited for sibling B's callback");
        assert!(a_handler.closed.load(Ordering::Acquire));
        assert!(!b_handler.closed.load(Ordering::Acquire));
        emitter.join().unwrap();
        detacher.join().unwrap();
        unsafe {
            questdb_oidc_auth_free(a);
            questdb_oidc_auth_free(b);
            questdb_oidc_builder_free(builder);
        }
    }

    #[test]
    fn detach_diagnostics_does_not_wait_for_a_sibling_callback() {
        static ENTERED: AtomicUsize = AtomicUsize::new(0);
        static RELEASE: AtomicUsize = AtomicUsize::new(0);

        unsafe extern "C" fn blocking_diagnostic(
            _user_data: *mut c_void,
            _diagnostic: *const questdb_oidc_diagnostic,
        ) {
            ENTERED.store(1, Ordering::SeqCst);
            while RELEASE.load(Ordering::SeqCst) == 0 {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }

        ENTERED.store(0, Ordering::SeqCst);
        RELEASE.store(0, Ordering::SeqCst);
        let builder = unsafe { explicit_builder() };
        let mut error = ptr::null_mut();
        assert!(unsafe {
            questdb_oidc_builder_diagnostic_handler(
                builder,
                Some(blocking_diagnostic),
                ptr::null_mut(),
                None,
                &mut error,
            )
        });
        let a = unsafe { questdb_oidc_builder_build(builder, &mut error) };
        let b = unsafe { questdb_oidc_builder_build(builder, &mut error) };
        assert!(!a.is_null() && !b.is_null());
        let a_sink = unsafe { (*a).shared.diagnostic.clone().unwrap() };
        let b_sink = unsafe { (*b).shared.diagnostic.clone().unwrap() };
        assert!(Arc::ptr_eq(&a_sink.target, &b_sink.target));

        let emitter = std::thread::spawn(move || {
            b_sink.on_persistence_warning("sibling save failed");
        });
        while ENTERED.load(Ordering::SeqCst) == 0 {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let a_addr = a as usize;
        let detacher = std::thread::spawn(move || {
            unsafe { questdb_oidc_auth_detach_diagnostics(a_addr as *const questdb_oidc_auth) };
            let _ = tx.send(());
        });
        let outcome = rx.recv_timeout(std::time::Duration::from_secs(5));
        RELEASE.store(1, Ordering::SeqCst);
        outcome.expect("detaching A's diagnostics waited for sibling B's callback");
        assert!(a_sink.state.detached.load(Ordering::Acquire));
        emitter.join().unwrap();
        detacher.join().unwrap();
        unsafe {
            questdb_oidc_auth_free(a);
            questdb_oidc_auth_free(b);
            questdb_oidc_builder_free(builder);
        }
    }

    #[test]
    fn detach_events_nowait_ffi_returns_while_callback_is_parked_and_suppresses_later_events() {
        static CALLS: AtomicUsize = AtomicUsize::new(0);
        static ENTERED: AtomicUsize = AtomicUsize::new(0);
        static RELEASE: AtomicUsize = AtomicUsize::new(0);
        static RETURNED: AtomicUsize = AtomicUsize::new(0);

        unsafe extern "C" fn blocking_first_event(
            _user_data: *mut c_void,
            _event: *const questdb_oidc_event,
        ) {
            let call = CALLS.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                ENTERED.store(1, Ordering::SeqCst);
                while RELEASE.load(Ordering::SeqCst) == 0 {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                RETURNED.store(1, Ordering::SeqCst);
            }
        }

        CALLS.store(0, Ordering::SeqCst);
        ENTERED.store(0, Ordering::SeqCst);
        RELEASE.store(0, Ordering::SeqCst);
        RETURNED.store(0, Ordering::SeqCst);
        let (auth, handler) = unsafe { auth_with_event_handler(blocking_first_event) };
        let emitter_renderer = CEventRenderer(Arc::clone(&handler));
        let later_renderer = CEventRenderer(handler);
        let emitter = std::thread::spawn(move || {
            emitter_renderer.invoke(&empty_event(
                questdb_oidc_event_kind::QUESTDB_OIDC_EVENT_WAITING,
            ));
        });
        while ENTERED.load(Ordering::SeqCst) == 0 {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }

        let (tx, rx) = std::sync::mpsc::channel();
        let auth_addr = auth as usize;
        let detacher = std::thread::spawn(move || {
            unsafe {
                questdb_oidc_auth_detach_events_nowait(auth_addr as *const questdb_oidc_auth)
            };
            let _ = tx.send(RETURNED.load(Ordering::SeqCst));
        });
        let observed = rx.recv_timeout(std::time::Duration::from_secs(1));
        if observed.is_err() {
            RELEASE.store(1, Ordering::SeqCst);
            emitter.join().unwrap();
            detacher.join().unwrap();
            unsafe { questdb_oidc_auth_free(auth) };
            panic!("nowait event detach waited for the parked callback");
        }
        assert_eq!(observed.unwrap(), 0, "callback returned before detach");

        RELEASE.store(1, Ordering::SeqCst);
        emitter.join().unwrap();
        detacher.join().unwrap();
        later_renderer.invoke(&empty_event(
            questdb_oidc_event_kind::QUESTDB_OIDC_EVENT_WAITING,
        ));
        assert_eq!(CALLS.load(Ordering::SeqCst), 1, "later event was delivered");
        unsafe { questdb_oidc_auth_free(auth) };
    }

    #[test]
    fn default_file_token_store_entry_point_selects_the_default_location() {
        unsafe {
            let builder = explicit_builder();
            let mut error = ptr::null_mut();
            assert!(questdb_oidc_builder_default_file_token_store(
                builder, &mut error,
            ));
            assert!(error.is_null());
            assert!(matches!(
                (*builder).config.file_store,
                FileStoreConfig::DefaultLocation
            ));
            questdb_oidc_builder_free(builder);
        }
    }

    #[test]
    fn null_token_is_an_empty_null_span() {
        let token = ptr::null();
        assert!(unsafe { questdb_oidc_token_data(token) }.is_null());
        assert_eq!(unsafe { questdb_oidc_token_len(token) }, 0);
    }

    #[test]
    fn null_pointer_arguments_are_rejected_not_dereferenced() {
        // This crate is `panic = "abort"`, so these NULL guards are the only thing
        // between a NULL handle (a caller bug or a use-after-free) and a
        // host-process abort. Each entry point must return its failure sentinel
        // (and set err_out where it has one) rather than dereferencing NULL.
        use crate::questdb_error_free;

        // Free functions treat NULL as a harmless no-op: reaching the end of the
        // test without aborting is the assertion.
        unsafe {
            questdb_oidc_builder_free(ptr::null_mut());
            questdb_oidc_auth_detach_events(ptr::null());
            questdb_oidc_auth_detach_events_nowait(ptr::null());
            questdb_oidc_auth_detach_diagnostics(ptr::null());
            questdb_oidc_auth_detach_diagnostics_nowait(ptr::null());
            questdb_oidc_auth_free(ptr::null_mut());
            questdb_oidc_token_free(ptr::null_mut());
        }

        // Entry points that report via err_out: NULL handle -> sentinel + error.
        unsafe {
            let mut error = ptr::null_mut();
            assert!(questdb_oidc_builder_build(ptr::null(), &mut error).is_null());
            assert!(!error.is_null());
            questdb_error_free(error);

            let mut error = ptr::null_mut();
            assert!(questdb_oidc_auth_clone(ptr::null(), &mut error).is_null());
            assert!(!error.is_null());
            questdb_error_free(error);

            let mut error = ptr::null_mut();
            assert!(!questdb_oidc_auth_sign_in(ptr::null(), &mut error));
            assert!(!error.is_null());
            questdb_error_free(error);

            error = ptr::null_mut();
            assert!(!questdb_oidc_auth_cancel_sign_in(ptr::null(), &mut error));
            assert!(!error.is_null());
            questdb_error_free(error);

            error = ptr::null_mut();
            assert!(!questdb_oidc_auth_close(ptr::null(), &mut error));
            assert!(!error.is_null());
            questdb_error_free(error);

            let mut error = ptr::null_mut();
            assert!(questdb_oidc_auth_token(ptr::null(), &mut error).is_null());
            assert!(!error.is_null());
            questdb_error_free(error);

            let mut error = ptr::null_mut();
            assert!(!questdb_oidc_auth_clear(ptr::null(), &mut error));
            assert!(!error.is_null());
            questdb_error_free(error);

            // A string setter with a NULL builder.
            let mut error = ptr::null_mut();
            let value = "x";
            assert!(!questdb_oidc_builder_client_id(
                ptr::null_mut(),
                value.as_ptr() as *const c_char,
                value.len(),
                &mut error,
            ));
            assert!(!error.is_null());
            questdb_error_free(error);

            // A NULL string pointer with a non-zero length.
            let mut error = ptr::null_mut();
            assert!(questdb_oidc_builder_from_questdb(ptr::null(), 5, &mut error).is_null());
            assert!(!error.is_null());
            questdb_error_free(error);

            // Callback registration with a NULL builder.
            let mut error = ptr::null_mut();
            assert!(!questdb_oidc_builder_event_handler(
                ptr::null_mut(),
                None,
                ptr::null_mut(),
                None,
                &mut error,
            ));
            assert!(!error.is_null());
            questdb_error_free(error);
        }

        // Out-param queries (no err_out): a NULL handle returns false, and the
        // handle is checked before the output pointer is touched.
        unsafe {
            let mut config = std::mem::zeroed::<questdb_oidc_config_view>();
            config.struct_size = std::mem::size_of::<questdb_oidc_config_view>();
            assert!(!questdb_oidc_auth_get_config(ptr::null(), &mut config));

            let mut view = std::mem::zeroed::<questdb_oidc_error_view>();
            view.struct_size = std::mem::size_of::<questdb_oidc_error_view>();
            assert!(!questdb_error_oidc_get_view(ptr::null(), &mut view));
        }
    }

    #[test]
    fn close_is_shared_idempotent_and_reports_cancelled_use() {
        unsafe {
            let builder = explicit_builder();
            let mut error = ptr::null_mut();
            let auth = questdb_oidc_builder_build(builder, &mut error);
            assert!(!auth.is_null());
            assert!(error.is_null());
            let clone = questdb_oidc_auth_clone(auth, &mut error);
            assert!(!clone.is_null());

            // Attempt-scoped cancellation while idle is a successful no-op,
            // not a permanent close shared by the clone.
            assert!(questdb_oidc_auth_cancel_sign_in(auth, &mut error));
            assert!(error.is_null());
            let token = questdb_oidc_auth_token(clone, &mut error);
            assert!(token.is_null());
            assert!(!error.is_null());
            let mut idle_view = std::mem::zeroed::<questdb_oidc_error_view>();
            idle_view.struct_size = std::mem::size_of_val(&idle_view);
            assert!(questdb_error_oidc_get_view(error, &mut idle_view));
            assert_eq!(
                idle_view.kind,
                questdb_oidc_error_kind::QUESTDB_OIDC_ERROR_INTERACTION_REQUIRED
            );
            crate::questdb_error_free(error);
            error = ptr::null_mut();

            assert!(questdb_oidc_auth_close(auth, &mut error));
            assert!(error.is_null());
            // A second handle shares the permanent closed signal.
            let token = questdb_oidc_auth_token(clone, &mut error);
            assert!(token.is_null());
            assert!(!error.is_null());
            let mut view = std::mem::zeroed::<questdb_oidc_error_view>();
            view.struct_size = std::mem::size_of_val(&view);
            assert!(questdb_error_oidc_get_view(error, &mut view));
            assert_eq!(
                view.kind,
                questdb_oidc_error_kind::QUESTDB_OIDC_ERROR_CANCELLED
            );
            crate::questdb_error_free(error);
            error = ptr::null_mut();

            assert!(questdb_oidc_auth_close(clone, &mut error));
            assert!(error.is_null());
            questdb_oidc_auth_free(clone);
            questdb_oidc_auth_free(auth);
            questdb_oidc_builder_free(builder);
        }
    }

    unsafe extern "C" fn ignore_event(_user_data: *mut c_void, _event: *const questdb_oidc_event) {}

    unsafe extern "C" fn ignore_diagnostic(
        _user_data: *mut c_void,
        _diagnostic: *const questdb_oidc_diagnostic,
    ) {
    }

    struct FailingClearStore;

    impl TokenStore for FailingClearStore {
        fn load(&self, _key: &TokenStoreKey) -> TokenStoreResult<Option<PersistedToken>> {
            Ok(None)
        }

        fn save(&self, _key: &TokenStoreKey, _token: &PersistedToken) -> TokenStoreResult<()> {
            Ok(())
        }

        fn clear(&self, _key: &TokenStoreKey) -> TokenStoreResult<()> {
            Err(Box::new(std::io::Error::other(
                "injected persisted clear failure",
            )))
        }

        fn in_lock(
            &self,
            _key: &TokenStoreKey,
            action: &mut dyn FnMut() -> TokenStoreResult<()>,
        ) -> TokenStoreResult<()> {
            action()
        }
    }

    struct FailingSaveStore;

    impl TokenStore for FailingSaveStore {
        fn load(&self, _key: &TokenStoreKey) -> TokenStoreResult<Option<PersistedToken>> {
            Ok(None)
        }

        fn save(&self, _key: &TokenStoreKey, _token: &PersistedToken) -> TokenStoreResult<()> {
            Err(Box::new(std::io::Error::other(
                "injected persisted save failure",
            )))
        }

        fn clear(&self, _key: &TokenStoreKey) -> TokenStoreResult<()> {
            Ok(())
        }

        fn in_lock(
            &self,
            _key: &TokenStoreKey,
            action: &mut dyn FnMut() -> TokenStoreResult<()>,
        ) -> TokenStoreResult<()> {
            action()
        }
    }

    struct CoordinatedFailingSaveStore {
        entered: Arc<AtomicBool>,
        release: Arc<AtomicBool>,
    }

    impl TokenStore for CoordinatedFailingSaveStore {
        fn load(&self, _key: &TokenStoreKey) -> TokenStoreResult<Option<PersistedToken>> {
            Ok(None)
        }

        fn save(&self, _key: &TokenStoreKey, _token: &PersistedToken) -> TokenStoreResult<()> {
            self.entered.store(true, Ordering::Release);
            while !self.release.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
            Err(Box::new(std::io::Error::other(
                "injected coordinated save failure",
            )))
        }

        fn clear(&self, _key: &TokenStoreKey) -> TokenStoreResult<()> {
            Ok(())
        }

        fn in_lock(
            &self,
            _key: &TokenStoreKey,
            action: &mut dyn FnMut() -> TokenStoreResult<()>,
        ) -> TokenStoreResult<()> {
            action()
        }
    }

    #[derive(Default)]
    struct DiagnosticCloseState {
        auth: Mutex<Option<SharedOidcAuth>>,
        close_returned: AtomicUsize,
    }

    unsafe extern "C" fn close_from_diagnostic(
        user_data: *mut c_void,
        _diagnostic: *const questdb_oidc_diagnostic,
    ) {
        let state = unsafe { &*(user_data as *const Arc<DiagnosticCloseState>) };
        let auth = state.auth.lock().unwrap().clone().expect("auth installed");
        auth.close().expect("close from diagnostic");
        state.close_returned.store(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn release_diagnostic_close_state(user_data: *mut c_void) {
        unsafe { drop(Box::from_raw(user_data as *mut Arc<DiagnosticCloseState>)) };
    }

    #[derive(Default)]
    struct DiagnosticClearState {
        auth: Mutex<Option<SharedOidcAuth>>,
        clear_result: Mutex<Option<Result<(), (ErrorCode, String)>>>,
    }

    unsafe extern "C" fn clear_from_diagnostic(
        user_data: *mut c_void,
        _diagnostic: *const questdb_oidc_diagnostic,
    ) {
        let state = unsafe { &*(user_data as *const Arc<DiagnosticClearState>) };
        let auth = state.auth.lock().unwrap().clone().expect("auth installed");
        let result = auth
            .clear()
            .map_err(|err| (err.code(), err.msg().to_string()));
        *state.clear_result.lock().unwrap() = Some(result);
    }

    unsafe extern "C" fn release_diagnostic_clear_state(user_data: *mut c_void) {
        unsafe { drop(Box::from_raw(user_data as *mut Arc<DiagnosticClearState>)) };
    }

    struct DiagnosticSiblingCloseState {
        auth: Mutex<Option<SharedOidcAuth>>,
        queued_state: Arc<CDiagnosticState>,
        release_save: Arc<AtomicBool>,
        close_result: Mutex<Option<Result<(), String>>>,
        callback_started: AtomicBool,
    }

    unsafe extern "C" fn close_queued_sibling_from_diagnostic(
        user_data: *mut c_void,
        _diagnostic: *const questdb_oidc_diagnostic,
    ) {
        let state = unsafe { &*(user_data as *const Arc<DiagnosticSiblingCloseState>) };
        if state.callback_started.swap(true, Ordering::SeqCst) {
            return;
        }
        let auth = state.auth.lock().unwrap().clone().expect("auth installed");
        state.release_save.store(true, Ordering::Release);

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !state
            .queued_state
            .waiting_for_target
            .load(Ordering::Acquire)
        {
            if std::time::Instant::now() >= deadline {
                *state.close_result.lock().unwrap() =
                    Some(Err("sibling never reached the diagnostic gate".to_string()));
                return;
            }
            std::thread::yield_now();
        }
        *state.close_result.lock().unwrap() = Some(
            auth.close()
                .map_err(|err| format!("sibling close failed: {err}")),
        );
    }

    unsafe extern "C" fn release_diagnostic_sibling_close_state(user_data: *mut c_void) {
        unsafe {
            drop(Box::from_raw(
                user_data as *mut Arc<DiagnosticSiblingCloseState>,
            ))
        };
    }

    unsafe extern "C" fn release_counter(user_data: *mut c_void) {
        let counter = unsafe { Box::from_raw(user_data as *mut Arc<AtomicUsize>) };
        counter.fetch_add(1, Ordering::SeqCst);
    }

    struct ReentrantReleaseState {
        builder: *mut questdb_oidc_builder,
        releases: Arc<AtomicUsize>,
        nested_releases: Arc<AtomicUsize>,
        reentry_succeeded: Arc<AtomicBool>,
    }

    unsafe extern "C" fn release_and_replace_handler(user_data: *mut c_void) {
        let state = unsafe { Box::from_raw(user_data as *mut ReentrantReleaseState) };
        state.releases.fetch_add(1, Ordering::SeqCst);

        let nested_data =
            Box::into_raw(Box::new(Arc::clone(&state.nested_releases))) as *mut c_void;
        let mut error = ptr::null_mut();
        let installed = unsafe {
            questdb_oidc_builder_event_handler(
                state.builder,
                Some(ignore_event),
                nested_data,
                Some(release_counter),
                &mut error,
            )
        };
        state.reentry_succeeded.store(installed, Ordering::SeqCst);
        if !installed {
            // Registration failure leaves ownership with the caller.
            drop(unsafe { Box::from_raw(nested_data as *mut Arc<AtomicUsize>) });
        }
        if !error.is_null() {
            unsafe { crate::questdb_error_free(error) };
        }
    }

    #[derive(Default)]
    struct EventLog {
        kinds: Vec<questdb_oidc_event_kind>,
        user_code: String,
        verification_uri: String,
        verification_uri_complete: String,
        browser_target: String,
        prompt_expires_in_seconds: f64,
        prompt_interval_seconds: u64,
        identity: String,
        message: String,
    }

    unsafe fn copy_event_text(value: *const c_char, value_len: size_t) -> String {
        if value.is_null() || value_len == 0 {
            return String::new();
        }
        String::from_utf8_lossy(unsafe { slice::from_raw_parts(value as *const u8, value_len) })
            .into_owned()
    }

    unsafe extern "C" fn record_event(user_data: *mut c_void, event: *const questdb_oidc_event) {
        let events = unsafe { &*(user_data as *const Arc<Mutex<EventLog>>) };
        let event = unsafe { &*event };
        let mut events = events.lock().unwrap();
        events.kinds.push(event.kind);
        match event.kind {
            questdb_oidc_event_kind::QUESTDB_OIDC_EVENT_PROMPT => {
                events.user_code = unsafe { copy_event_text(event.user_code, event.user_code_len) };
                events.verification_uri =
                    unsafe { copy_event_text(event.verification_uri, event.verification_uri_len) };
                events.verification_uri_complete = unsafe {
                    copy_event_text(
                        event.verification_uri_complete,
                        event.verification_uri_complete_len,
                    )
                };
                events.browser_target =
                    unsafe { copy_event_text(event.browser_target, event.browser_target_len) };
                events.prompt_expires_in_seconds = event.expires_in_seconds;
                events.prompt_interval_seconds = event.interval_seconds;
            }
            questdb_oidc_event_kind::QUESTDB_OIDC_EVENT_SUCCESS => {
                events.identity = unsafe { copy_event_text(event.identity, event.identity_len) };
            }
            questdb_oidc_event_kind::QUESTDB_OIDC_EVENT_FAILURE => {
                events.message = unsafe { copy_event_text(event.message, event.message_len) };
            }
            questdb_oidc_event_kind::QUESTDB_OIDC_EVENT_WAITING => {}
        }
    }

    unsafe extern "C" fn release_events(user_data: *mut c_void) {
        unsafe { drop(Box::from_raw(user_data as *mut Arc<Mutex<EventLog>>)) };
    }

    #[derive(Default)]
    struct SerializedCallbackState {
        active: AtomicUsize,
        overlaps: AtomicUsize,
        calls: AtomicUsize,
    }

    unsafe extern "C" fn record_serialized_callback(
        user_data: *mut c_void,
        _event: *const questdb_oidc_event,
    ) {
        let state = unsafe { &*(user_data as *const Arc<SerializedCallbackState>) };
        if state.active.fetch_add(1, Ordering::SeqCst) != 0 {
            state.overlaps.fetch_add(1, Ordering::SeqCst);
        }
        // Widen the overlap window so this reliably catches a missing callback
        // gate even under a heavily loaded test runner.
        std::thread::sleep(Duration::from_millis(2));
        state.calls.fetch_add(1, Ordering::SeqCst);
        state.active.fetch_sub(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn release_serialized_callback(user_data: *mut c_void) {
        unsafe {
            drop(Box::from_raw(
                user_data as *mut Arc<SerializedCallbackState>,
            ))
        };
    }

    #[derive(Default)]
    struct ReentrantCallState {
        auth: AtomicPtr<questdb_oidc_auth>,
        /// Refused as re-entry: this thread is the one inside the callback.
        rejected: AtomicUsize,
        /// Refused as busy: a callback holds the lock on ANOTHER thread, so
        /// this caller would block behind it. It did not re-enter anything and
        /// must not be told that it did. `sign_in` / `clear` are direct user
        /// calls and keep the `InvalidApiCall` the header documents.
        busy: AtomicUsize,
        /// As `busy`, but from `token()`, which must be RETRYABLE: it is what a
        /// sender/reader/pool calls on a background reconnect, and a terminal
        /// class there stops the reconnect permanently over a condition that
        /// clears when the callback returns.
        busy_retryable: AtomicUsize,
        /// As `rejected`, but from `token()`, which must also be RETRYABLE.
        /// The caller did re-enter and is told so, but terminalizing an
        /// attached transport's publication store over a mistake that ends
        /// when the callback returns is a penalty it can never recover from.
        rejected_retryable: AtomicUsize,
        unexpected: AtomicUsize,
        closed_ok: AtomicUsize,
    }

    unsafe fn record_reentrant_result(
        state: &ReentrantCallState,
        succeeded: bool,
        error: *mut questdb_error,
    ) {
        let code = (!succeeded && !error.is_null())
            .then(|| unsafe { crate::questdb_error_get_code(error) } as i32);
        let is_invalid_api_call =
            code == Some(crate::line_sender_error_code::line_sender_error_invalid_api_call as i32);
        let is_socket_error =
            code == Some(crate::line_sender_error_code::line_sender_error_socket_error as i32);
        let guard_message = (is_invalid_api_call || is_socket_error).then(|| {
            let mut len = 0;
            let message = unsafe { crate::questdb_error_msg(error, &mut len) };
            let message = unsafe { slice::from_raw_parts(message as *const u8, len) };
            String::from_utf8_lossy(message).into_owned()
        });
        match guard_message.as_deref() {
            Some(message) if message.contains("cannot be re-entered") && is_invalid_api_call => {
                state.rejected.fetch_add(1, Ordering::SeqCst);
            }
            Some(message) if message.contains("cannot be re-entered") && is_socket_error => {
                state.rejected_retryable.fetch_add(1, Ordering::SeqCst);
            }
            Some(message) if message.contains("is busy") && is_invalid_api_call => {
                state.busy.fetch_add(1, Ordering::SeqCst);
            }
            Some(message) if message.contains("is busy") && is_socket_error => {
                state.busy_retryable.fetch_add(1, Ordering::SeqCst);
            }
            _ => {
                state.unexpected.fetch_add(1, Ordering::SeqCst);
            }
        }
        unsafe { crate::questdb_error_free(error) };
    }

    unsafe fn perform_reentrant_auth_calls(state: &ReentrantCallState) {
        let auth = state.auth.load(Ordering::SeqCst);

        let mut error = ptr::null_mut();
        let signed_in = unsafe { questdb_oidc_auth_sign_in(auth, &mut error) };
        unsafe { record_reentrant_result(state, signed_in, error) };

        error = ptr::null_mut();
        let token = unsafe { questdb_oidc_auth_token(auth, &mut error) };
        unsafe { record_reentrant_result(state, !token.is_null(), error) };
        unsafe { questdb_oidc_token_free(token) };

        error = ptr::null_mut();
        let cleared = unsafe { questdb_oidc_auth_clear(auth, &mut error) };
        unsafe { record_reentrant_result(state, cleared, error) };

        // close is deliberately NOT guarded. It publishes the close signal and
        // skips the drain whenever this auth's callback is active, including a
        // worker the callback delegates to and joins.
        error = ptr::null_mut();
        let closed = unsafe { questdb_oidc_auth_close(auth, &mut error) };
        if closed && error.is_null() {
            state.closed_ok.fetch_add(1, Ordering::SeqCst);
        } else {
            state.unexpected.fetch_add(1, Ordering::SeqCst);
        }
        unsafe { crate::questdb_error_free(error) };
    }

    unsafe extern "C" fn attempt_reentrant_auth_calls(
        user_data: *mut c_void,
        _event: *const questdb_oidc_event,
    ) {
        let state = unsafe { &*(user_data as *const Arc<ReentrantCallState>) };
        unsafe { perform_reentrant_auth_calls(state) };
    }

    unsafe extern "C" fn attempt_cross_thread_reentrant_auth_calls(
        user_data: *mut c_void,
        _event: *const questdb_oidc_event,
    ) {
        let state = unsafe { &*(user_data as *const Arc<ReentrantCallState>) };
        let state = Arc::clone(state);
        std::thread::spawn(move || unsafe { perform_reentrant_auth_calls(&state) })
            .join()
            .unwrap();
    }

    unsafe extern "C" fn release_reentrant_state(user_data: *mut c_void) {
        unsafe { drop(Box::from_raw(user_data as *mut Arc<ReentrantCallState>)) };
    }

    /// What a renderer callback saw when it asked for the cached token.
    #[derive(Default)]
    struct CallbackTokenState {
        auth: AtomicPtr<questdb_oidc_auth>,
        /// Token bytes returned to the callback, per SUCCESS event.
        served: Mutex<Vec<String>>,
        /// The callback asked and was refused.
        refused: AtomicUsize,
    }

    unsafe extern "C" fn take_token_on_success(
        user_data: *mut c_void,
        event: *const questdb_oidc_event,
    ) {
        let state = unsafe { &*(user_data as *const Arc<CallbackTokenState>) };
        if unsafe { (*event).kind } != questdb_oidc_event_kind::QUESTDB_OIDC_EVENT_SUCCESS {
            return;
        }
        let auth = state.auth.load(Ordering::SeqCst);
        if auth.is_null() {
            return;
        }
        let mut error = ptr::null_mut();
        let token = unsafe { questdb_oidc_auth_token(auth, &mut error) };
        if token.is_null() {
            state.refused.fetch_add(1, Ordering::SeqCst);
            if !error.is_null() {
                unsafe { crate::questdb_error_free(error) };
            }
            return;
        }
        let data = unsafe { questdb_oidc_token_data(token) };
        let len = unsafe { questdb_oidc_token_len(token) };
        let bytes = unsafe { slice::from_raw_parts(data as *const u8, len) };
        state
            .served
            .lock()
            .unwrap()
            .push(String::from_utf8_lossy(bytes).into_owned());
        unsafe { questdb_oidc_token_free(token) };
    }

    unsafe extern "C" fn release_callback_token_state(user_data: *mut c_void) {
        unsafe { drop(Box::from_raw(user_data as *mut Arc<CallbackTokenState>)) };
    }

    fn write_json_response(mut stream: TcpStream, body: &str) {
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        let mut chunk = [0u8; 1024];
        let headers_end = loop {
            let read = stream.read(&mut chunk).unwrap();
            if read == 0 {
                return;
            }
            request.extend_from_slice(&chunk[..read]);
            if let Some(position) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                break position + 4;
            }
        };
        let headers = String::from_utf8_lossy(&request[..headers_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.trim()
                    .eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())?
            })
            .unwrap_or(0);
        while request.len() < headers_end + content_length {
            let read = stream.read(&mut chunk).unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);
        }
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(response.as_bytes()).unwrap();
    }

    #[test]
    fn builder_is_reusable_and_config_view_borrows_from_auth() {
        unsafe {
            let builder = explicit_builder();
            let mut error = ptr::null_mut();
            let first = questdb_oidc_builder_build(builder, &mut error);
            assert!(!first.is_null());
            assert!(error.is_null());
            let second = questdb_oidc_builder_build(builder, &mut error);
            assert!(!second.is_null());
            assert!(error.is_null());

            assert_eq!(
                std::mem::size_of::<OidcConfigViewV1>(),
                QUESTDB_OIDC_CONFIG_VIEW_V1_SIZE
            );
            let mut guarded = std::mem::zeroed::<GuardedOidcConfigViewV1>();
            guarded.canary = [0xA5; 16];
            guarded.view.struct_size = std::mem::size_of::<OidcConfigViewV1>();
            assert!(questdb_oidc_auth_get_config(
                first,
                (&mut guarded.view as *mut OidcConfigViewV1).cast::<questdb_oidc_config_view>(),
            ));
            let view = &guarded.view;
            assert_eq!(view.struct_size, QUESTDB_OIDC_CONFIG_VIEW_V1_SIZE);
            assert_eq!(
                slice::from_raw_parts(view.client_id as *const u8, view.client_id_len),
                b"questdb-c"
            );
            assert_eq!(
                slice::from_raw_parts(view.scope as *const u8, view.scope_len),
                b"openid profile"
            );
            assert_eq!(guarded.canary, [0xA5; 16]);

            let mut undersized = std::mem::size_of::<size_t>();
            assert!(!questdb_oidc_auth_get_config(
                first,
                (&mut undersized as *mut size_t).cast::<questdb_oidc_config_view>(),
            ));
            assert_eq!(undersized, QUESTDB_OIDC_CONFIG_VIEW_V1_SIZE);

            questdb_oidc_builder_free(builder);
            questdb_oidc_auth_free(first);
            questdb_oidc_auth_free(second);
        }
    }

    #[test]
    fn config_failures_retain_structured_oidc_details() {
        unsafe {
            let builder = questdb_oidc_builder_new();
            let mut error = ptr::null_mut();
            assert!(questdb_oidc_builder_build(builder, &mut error).is_null());
            assert!(!error.is_null());
            assert_eq!(
                std::mem::size_of::<OidcErrorViewV1>(),
                QUESTDB_OIDC_ERROR_VIEW_V1_SIZE
            );
            let mut guarded = std::mem::zeroed::<GuardedOidcErrorViewV1>();
            guarded.canary = [0x5A; 16];
            guarded.view.struct_size = std::mem::size_of::<OidcErrorViewV1>();
            assert!(questdb_error_oidc_get_view(
                error,
                (&mut guarded.view as *mut OidcErrorViewV1).cast::<questdb_oidc_error_view>(),
            ));
            let view = &guarded.view;
            assert_eq!(view.struct_size, QUESTDB_OIDC_ERROR_VIEW_V1_SIZE);
            assert_eq!(
                view.kind,
                questdb_oidc_error_kind::QUESTDB_OIDC_ERROR_CONFIG
            );
            assert_eq!(guarded.canary, [0x5A; 16]);

            let mut undersized = std::mem::size_of::<size_t>();
            assert!(!questdb_error_oidc_get_view(
                error,
                (&mut undersized as *mut size_t).cast::<questdb_oidc_error_view>(),
            ));
            assert_eq!(undersized, QUESTDB_OIDC_ERROR_VIEW_V1_SIZE);
            crate::questdb_error_free(error);
            questdb_oidc_builder_free(builder);
        }
    }

    #[test]
    fn attached_reader_failure_retains_structured_oidc_details() {
        unsafe {
            let builder = explicit_builder();
            let mut error = ptr::null_mut();
            assert!(questdb_oidc_builder_interactive(builder, true, &mut error));
            let auth = questdb_oidc_builder_build(builder, &mut error);
            assert!(!auth.is_null());
            assert!(error.is_null());

            // Provider acquisition happens before DNS/TCP, so a closed address
            // is enough: the structured OIDC error must surface without a dial.
            let conf = "ws::addr=127.0.0.1:1;failover=off;";
            let config = crate::line_sender_utf8 {
                len: conf.len(),
                buf: conf.as_ptr() as *const c_char,
            };
            let reader = crate::egress::qwp_reader_from_conf_with_oidc(config, &*auth, &mut error);
            assert!(reader.is_null());
            assert!(!error.is_null());

            let mut view = std::mem::zeroed::<questdb_oidc_error_view>();
            view.struct_size = std::mem::size_of_val(&view);
            assert!(questdb_error_oidc_get_view(error, &mut view));
            assert_eq!(
                view.kind,
                questdb_oidc_error_kind::QUESTDB_OIDC_ERROR_INTERACTION_REQUIRED
            );

            crate::questdb_error_free(error);
            questdb_oidc_auth_free(auth);
            questdb_oidc_builder_free(builder);
        }
    }

    #[test]
    fn renderer_user_data_lives_until_builder_and_auth_are_released() {
        unsafe {
            let releases = Arc::new(AtomicUsize::new(0));
            let user_data = Box::into_raw(Box::new(Arc::clone(&releases))) as *mut c_void;
            let builder = explicit_builder();
            let mut error = ptr::null_mut();
            assert!(questdb_oidc_builder_event_handler(
                builder,
                Some(ignore_event),
                user_data,
                Some(release_counter),
                &mut error,
            ));
            let auth = questdb_oidc_builder_build(builder, &mut error);
            assert!(!auth.is_null());
            questdb_oidc_builder_free(builder);
            assert_eq!(releases.load(Ordering::SeqCst), 0);
            questdb_oidc_auth_free(auth);
            assert_eq!(releases.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn event_handler_requires_release_for_non_null_user_data() {
        unsafe {
            let releases = Arc::new(AtomicUsize::new(0));
            let builder = explicit_builder();
            let mut error = ptr::null_mut();

            // Stateless callbacks remain supported (and are used by the C
            // example): there is no owned state to release.
            assert!(questdb_oidc_builder_event_handler(
                builder,
                Some(ignore_event),
                ptr::null_mut(),
                None,
                &mut error,
            ));
            assert!(error.is_null());

            // Install an owned handler so the rejected replacement also proves
            // that a failed registration does not disturb existing ownership.
            let owned = Box::into_raw(Box::new(Arc::clone(&releases))) as *mut c_void;
            assert!(questdb_oidc_builder_event_handler(
                builder,
                Some(ignore_event),
                owned,
                Some(release_counter),
                &mut error,
            ));
            assert_eq!(releases.load(Ordering::SeqCst), 0);

            let rejected = Box::into_raw(Box::new(17_u8)) as *mut c_void;
            assert!(!questdb_oidc_builder_event_handler(
                builder,
                Some(ignore_event),
                rejected,
                None,
                &mut error,
            ));
            assert!(!error.is_null());
            assert_eq!(
                crate::questdb_error_get_code(error) as i32,
                crate::line_sender_error_code::line_sender_error_invalid_api_call as i32
            );
            crate::questdb_error_free(error);

            // Registration failed, so ownership of `rejected` stayed here.
            drop(Box::from_raw(rejected as *mut u8));
            assert_eq!(releases.load(Ordering::SeqCst), 0);
            questdb_oidc_builder_free(builder);
            assert_eq!(
                releases.load(Ordering::SeqCst),
                1,
                "the previously installed state remains owned and is released once"
            );
        }
    }

    #[test]
    fn diagnostic_handler_validates_and_releases_every_transferred_state_once() {
        unsafe {
            let releases = Arc::new(AtomicUsize::new(0));
            let builder = explicit_builder();
            let mut error = ptr::null_mut();

            // Stateless handlers are valid.
            assert!(questdb_oidc_builder_diagnostic_handler(
                builder,
                Some(ignore_diagnostic),
                ptr::null_mut(),
                None,
                &mut error,
            ));
            assert!(error.is_null());

            let first = Box::into_raw(Box::new(Arc::clone(&releases))) as *mut c_void;
            assert!(questdb_oidc_builder_diagnostic_handler(
                builder,
                Some(ignore_diagnostic),
                first,
                Some(release_counter),
                &mut error,
            ));

            // Non-NULL state without a release callback is rejected without
            // disturbing or taking ownership of the installed handler.
            let rejected = Box::into_raw(Box::new(17_u8)) as *mut c_void;
            assert!(!questdb_oidc_builder_diagnostic_handler(
                builder,
                Some(ignore_diagnostic),
                rejected,
                None,
                &mut error,
            ));
            assert!(!error.is_null());
            crate::questdb_error_free(error);
            error = ptr::null_mut();
            drop(Box::from_raw(rejected as *mut u8));
            assert_eq!(releases.load(Ordering::SeqCst), 0);

            // Replacement releases the previous transferred state once; the
            // final installed state is released once with the builder.
            let second = Box::into_raw(Box::new(Arc::clone(&releases))) as *mut c_void;
            assert!(questdb_oidc_builder_diagnostic_handler(
                builder,
                Some(ignore_diagnostic),
                second,
                Some(release_counter),
                &mut error,
            ));
            assert!(error.is_null());
            assert_eq!(releases.load(Ordering::SeqCst), 1);
            questdb_oidc_builder_free(builder);
            assert_eq!(releases.load(Ordering::SeqCst), 2);
        }
    }

    #[test]
    fn replacing_event_handlers_releases_every_transferred_state_once() {
        unsafe {
            let releases = Arc::new(AtomicUsize::new(0));
            let builder = explicit_builder();
            let mut error = ptr::null_mut();

            for replaced in 0..3 {
                let user_data = Box::into_raw(Box::new(Arc::clone(&releases))) as *mut c_void;
                assert!(questdb_oidc_builder_event_handler(
                    builder,
                    Some(ignore_event),
                    user_data,
                    Some(release_counter),
                    &mut error,
                ));
                assert!(error.is_null());
                assert_eq!(releases.load(Ordering::SeqCst), replaced);
            }

            questdb_oidc_builder_free(builder);
            assert_eq!(releases.load(Ordering::SeqCst), 3);
        }
    }

    /// Pins the ownership-ordering exception documented on
    /// `questdb_oidc_builder_event_handler` in `include/questdb/oidc.h`: a
    /// `release` callback that re-registers supersedes the registration this
    /// call is still installing, so that `user_data` is released before the
    /// call returns `true`. Each `release` still runs exactly once.
    #[test]
    fn replacing_handler_allows_release_callback_reentry() {
        unsafe {
            let old_releases = Arc::new(AtomicUsize::new(0));
            let outer_releases = Arc::new(AtomicUsize::new(0));
            let nested_releases = Arc::new(AtomicUsize::new(0));
            let reentry_succeeded = Arc::new(AtomicBool::new(false));
            let builder = explicit_builder();
            let mut error = ptr::null_mut();

            let old_data = Box::into_raw(Box::new(ReentrantReleaseState {
                builder,
                releases: Arc::clone(&old_releases),
                nested_releases: Arc::clone(&nested_releases),
                reentry_succeeded: Arc::clone(&reentry_succeeded),
            })) as *mut c_void;
            assert!(questdb_oidc_builder_event_handler(
                builder,
                Some(ignore_event),
                old_data,
                Some(release_and_replace_handler),
                &mut error,
            ));

            let outer_data = Box::into_raw(Box::new(Arc::clone(&outer_releases))) as *mut c_void;
            assert!(questdb_oidc_builder_event_handler(
                builder,
                Some(ignore_event),
                outer_data,
                Some(release_counter),
                &mut error,
            ));
            assert!(error.is_null());
            assert!(reentry_succeeded.load(Ordering::SeqCst));
            assert_eq!(old_releases.load(Ordering::SeqCst), 1);
            // The old target's release callback replaced the just-installed
            // outer target; it too was released after its setter borrow ended.
            assert_eq!(outer_releases.load(Ordering::SeqCst), 1);
            assert_eq!(nested_releases.load(Ordering::SeqCst), 0);

            questdb_oidc_builder_free(builder);
            assert_eq!(nested_releases.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn callbacks_shared_by_renderer_clones_are_serialized() {
        const THREADS: usize = 8;
        const CALLS_PER_THREAD: usize = 4;

        let state = Arc::new(SerializedCallbackState::default());
        let user_data = Box::into_raw(Box::new(Arc::clone(&state))) as *mut c_void;
        let handler = event_handler(
            record_serialized_callback,
            user_data as usize,
            Some(release_serialized_callback),
        );
        let start = Arc::new(std::sync::Barrier::new(THREADS + 1));
        let threads: Vec<_> = (0..THREADS)
            .map(|_| {
                let renderer = CEventRenderer(Arc::clone(&handler));
                let start = Arc::clone(&start);
                std::thread::spawn(move || {
                    start.wait();
                    for _ in 0..CALLS_PER_THREAD {
                        renderer.on_waiting(30.0);
                    }
                })
            })
            .collect();
        start.wait();
        for thread in threads {
            thread.join().unwrap();
        }

        assert_eq!(
            state.calls.load(Ordering::SeqCst),
            THREADS * CALLS_PER_THREAD
        );
        assert_eq!(state.active.load(Ordering::SeqCst), 0);
        assert_eq!(state.overlaps.load(Ordering::SeqCst), 0);
        drop(handler);
    }

    #[test]
    fn auth_operations_from_its_event_callback_are_rejected() {
        unsafe {
            let builder = explicit_builder();
            let mut error = ptr::null_mut();
            assert!(questdb_oidc_builder_interactive(builder, false, &mut error));
            let state = Arc::new(ReentrantCallState::default());
            let user_data = Box::into_raw(Box::new(Arc::clone(&state))) as *mut c_void;
            assert!(questdb_oidc_builder_event_handler(
                builder,
                Some(attempt_reentrant_auth_calls),
                user_data,
                Some(release_reentrant_state),
                &mut error,
            ));
            let auth = questdb_oidc_builder_build(builder, &mut error);
            assert!(!auth.is_null());
            assert!(error.is_null());
            let handler = Arc::clone((*auth).shared.event_handler.as_ref().unwrap());
            state.auth.store(auth, Ordering::SeqCst);

            // Enter through the same renderer used by the auth. sign_in,
            // token and clear must fail before attempting to acquire the core
            // mutex; close must still work.
            CEventRenderer(handler).on_waiting(30.0);

            // sign_in and clear are direct user calls and keep the terminal
            // `InvalidApiCall` the header documents; token() is what an
            // attached transport calls, so it reports the same re-entry
            // message under a retryable class instead.
            assert_eq!(state.rejected.load(Ordering::SeqCst), 2);
            assert_eq!(state.rejected_retryable.load(Ordering::SeqCst), 1);
            assert_eq!(state.closed_ok.load(Ordering::SeqCst), 1);
            assert_eq!(state.unexpected.load(Ordering::SeqCst), 0);
            questdb_oidc_auth_free(auth);
            questdb_oidc_builder_free(builder);
        }
    }

    #[test]
    fn callback_thread_scope_is_per_thread_not_process_wide() {
        // The shared active flag drives busy rejection and callback-safe close,
        // but the re-entry diagnostic remains scoped to the callback thread.
        unsafe {
            let builder = explicit_builder();
            let mut error = ptr::null_mut();
            assert!(questdb_oidc_builder_interactive(builder, false, &mut error));
            let observed_other_thread = Arc::new(AtomicBool::new(true));
            let observed_callback_thread = Arc::new(AtomicBool::new(false));
            let probe_other = Arc::clone(&observed_other_thread);
            let probe_self = Arc::clone(&observed_callback_thread);

            let handler = event_handler(ignore_event, 0, None);
            assert!(!in_event_callback_of_on_this_thread(Some(&handler)));
            let probe_handler = Arc::clone(&handler);
            {
                let _entered = ActiveEventHandler::enter(&handler);
                // On the callback's own thread the scope is active...
                probe_self.store(
                    in_event_callback_of_on_this_thread(Some(&handler)),
                    Ordering::SeqCst,
                );
                // ...while any other thread must NOT see itself as inside it,
                // even though the shared `active` flag is set for both.
                assert!(handler.is_active());
                let other = std::thread::spawn(move || {
                    probe_other.store(
                        in_event_callback_of_on_this_thread(Some(&probe_handler)),
                        Ordering::SeqCst,
                    );
                });
                other.join().unwrap();
            }

            assert!(
                observed_callback_thread.load(Ordering::SeqCst),
                "the callback's own thread must be identified as re-entry"
            );
            assert!(
                !observed_other_thread.load(Ordering::SeqCst),
                "an unrelated thread must be diagnosed as busy, not re-entry"
            );
            assert!(!handler.is_active());
            assert!(!in_event_callback_of_on_this_thread(Some(&handler)));
            questdb_oidc_builder_free(builder);
        }
    }

    #[test]
    fn callback_thread_scope_is_keyed_per_handler() {
        // The scope answers "is this thread inside *this handler's* callback",
        // not "inside any callback". A bare depth counter gave the wrong
        // re-entry diagnostic for B while A's callback was running. Close now
        // uses the per-auth shared activity flag instead, because a callback can
        // delegate close to another thread and join it.
        let make = || event_handler(ignore_event, 0, None);
        let a = make();
        let b = make();
        {
            let _in_a = ActiveEventHandler::enter(&a);
            assert!(
                in_event_callback_of_on_this_thread(Some(&a)),
                "inside A's callback"
            );
            assert!(
                !in_event_callback_of_on_this_thread(Some(&b)),
                "B holds no lock on this thread, so its drain must not be skipped"
            );
            // Nesting keeps both visible: an inner handler must not hide the
            // outer one, whose lock this thread still holds.
            {
                let _in_b = ActiveEventHandler::enter(&b);
                assert!(in_event_callback_of_on_this_thread(Some(&a)));
                assert!(in_event_callback_of_on_this_thread(Some(&b)));
            }
            assert!(in_event_callback_of_on_this_thread(Some(&a)));
            assert!(!in_event_callback_of_on_this_thread(Some(&b)));
        }
        assert!(!in_event_callback_of_on_this_thread(Some(&a)));
        assert!(!in_event_callback_of_on_this_thread(Some(&b)));
        // A handler-less auth is never inside its own callback.
        assert!(!in_event_callback_of_on_this_thread(None));
    }

    #[test]
    fn attempt_cancelled_callback_handler_is_reusable() {
        let target = event_target(ignore_event, 0, None);
        let a = Arc::new(CEventHandler::new(Arc::clone(&target)));
        let b = Arc::new(CEventHandler::new(target));
        let in_a = ActiveEventHandler::enter(&a).expect("A callback enters");
        let b_generation = b.begin_sign_in();

        // B waits behind the target shared with A. Attempt cancellation must
        // wake it without permanently disabling B's callback state.
        let started = Arc::new(std::sync::Barrier::new(2));
        let waiter_started = Arc::clone(&started);
        let waiting_b = Arc::clone(&b);
        let waiter = std::thread::spawn(move || {
            waiter_started.wait();
            ActiveEventHandler::enter(&waiting_b).is_none()
        });
        started.wait();
        assert_eq!(b.cancel_sign_in(), Some(b_generation));
        assert!(
            waiter.join().unwrap(),
            "attempt-cancelled sibling entered callback"
        );
        drop(in_a);

        b.finish_sign_in(b_generation);
        assert!(
            ActiveEventHandler::enter(&b).is_some(),
            "a later sign-in must be allowed to render"
        );
    }

    #[test]
    fn late_attempt_cancellation_cannot_mute_the_next_renderer() {
        let handler = Arc::new(CEventHandler::new(event_target(ignore_event, 0, None)));
        let first = handler.begin_sign_in();
        handler.finish_sign_in(first);

        // Models cancel_sign_in observing native completion before it can
        // publish at the callback layer. There is no active generation to
        // mark, so the publication is rejected rather than latching a bool.
        assert_eq!(handler.cancel_sign_in(), None);

        let second = handler.begin_sign_in();
        assert!(
            ActiveEventHandler::enter(&handler).is_some(),
            "a late cancellation from the previous attempt muted this renderer"
        );
        handler.finish_sign_in(second);
    }

    #[test]
    fn cancellation_selection_blocks_the_next_renderer_generation() {
        let handler = Arc::new(CEventHandler::new(event_target(ignore_event, 0, None)));
        let first = handler.begin_sign_in_serialized();

        let (core_entered_tx, core_entered_rx) = std::sync::mpsc::channel();
        let (release_core_tx, release_core_rx) = std::sync::mpsc::channel();
        let cancelling_handler = Arc::clone(&handler);
        let cancelling = std::thread::spawn(move || {
            cancelling_handler.cancel_sign_in_serialized(|| {
                core_entered_tx.send(()).unwrap();
                release_core_rx.recv().unwrap();
                true
            });
        });
        core_entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("cancellation never selected the first attempt");

        let (transition_started_tx, transition_started_rx) = std::sync::mpsc::channel();
        let (second_tx, second_rx) = std::sync::mpsc::channel();
        let transitioning_handler = Arc::clone(&handler);
        let transition = std::thread::spawn(move || {
            transition_started_tx.send(()).unwrap();
            transitioning_handler.finish_sign_in_serialized(first);
            second_tx
                .send(transitioning_handler.begin_sign_in_serialized())
                .unwrap();
        });
        transition_started_rx.recv().unwrap();
        assert!(
            second_rx.recv_timeout(Duration::from_millis(50)).is_err(),
            "the next renderer generation advanced while cancellation was selecting its attempt"
        );

        release_core_tx.send(()).unwrap();
        cancelling.join().unwrap();
        let second = second_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the next generation did not start after cancellation completed");
        transition.join().unwrap();
        assert!(
            ActiveEventHandler::enter(&handler).is_some(),
            "cancelling the first attempt muted the next renderer"
        );
        handler.finish_sign_in_serialized(second);
    }

    #[test]
    fn reusable_builder_siblings_have_distinct_cancellable_callback_state() {
        let target = event_target(ignore_event, 0, None);
        let a = Arc::new(CEventHandler::new(Arc::clone(&target)));
        let b = Arc::new(CEventHandler::new(target));
        let in_a = ActiveEventHandler::enter(&a).expect("A callback enters");

        assert!(a.is_active());
        assert!(
            !b.is_active(),
            "A's callback must not mark sibling B active"
        );
        assert!(a.target_is_active(), "the shared target remains busy");
        assert!(in_event_callback_of_on_this_thread(Some(&a)));
        assert!(!in_event_callback_of_on_this_thread(Some(&b)));

        // B is now queued behind A's shared callback gate. Closing B marks
        // only B closed and wakes that waiter; it must not enter caller state
        // after close or wait for A to return.
        let started = Arc::new(std::sync::Barrier::new(2));
        let waiter_started = Arc::clone(&started);
        let waiting_b = Arc::clone(&b);
        let waiter = std::thread::spawn(move || {
            waiter_started.wait();
            ActiveEventHandler::enter(&waiting_b).is_none()
        });
        started.wait();
        b.close();
        assert!(waiter.join().unwrap(), "closed sibling entered callback");
        assert!(a.is_active(), "cancelling B must not cancel A");
        drop(in_a);
    }

    #[test]
    fn auth_operations_from_another_thread_during_event_callback_are_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (device, _) = listener.accept().unwrap();
            write_json_response(
                device,
                r#"{"device_code":"DEV-CODE","user_code":"ABCD-1234","verification_uri":"https://idp.example.com/activate","expires_in":600,"interval":5}"#,
            );
        });

        unsafe {
            let builder = questdb_oidc_builder_new();
            set_string(questdb_oidc_builder_client_id, builder, "questdb-c");
            set_string(questdb_oidc_builder_scope, builder, "openid");
            set_string(
                questdb_oidc_builder_device_authorization_endpoint,
                builder,
                &format!("http://{address}/device"),
            );
            set_string(
                questdb_oidc_builder_token_endpoint,
                builder,
                &format!("http://{address}/token"),
            );
            let mut error = ptr::null_mut();
            assert!(questdb_oidc_builder_interactive(builder, true, &mut error));
            assert!(questdb_oidc_builder_open_browser(
                builder, false, &mut error
            ));
            let state = Arc::new(ReentrantCallState::default());
            let user_data = Box::into_raw(Box::new(Arc::clone(&state))) as *mut c_void;
            assert!(questdb_oidc_builder_event_handler(
                builder,
                Some(attempt_cross_thread_reentrant_auth_calls),
                user_data,
                Some(release_reentrant_state),
                &mut error,
            ));
            let auth = questdb_oidc_builder_build(builder, &mut error);
            assert!(!auth.is_null());
            assert!(error.is_null());
            state.auth.store(auth, Ordering::SeqCst);

            // Enter through a real sign-in so the acquisition lock is held.
            // The callback joins a worker that calls close: draining on that
            // worker would wait for the callback itself and deadlock.
            assert!(!questdb_oidc_auth_sign_in(auth, &mut error));
            assert!(!error.is_null());
            crate::questdb_error_free(error);

            // sign_in, token and clear are refused -- the callback JOINS this worker, so a blocking
            // acquisition here would deadlock exactly as one on the callback's
            // own thread would. But the diagnostic is now thread-scoped: this
            // thread never entered a callback and must not be told it
            // re-entered one.
            // sign_in and clear keep the documented terminal InvalidApiCall;
            // token's refusal is retryable so a background reconnect that
            // merely landed inside a renderer's paint is not terminalized.
            assert_eq!(state.busy.load(Ordering::SeqCst), 2);
            assert_eq!(state.busy_retryable.load(Ordering::SeqCst), 1);
            assert_eq!(
                state.rejected.load(Ordering::SeqCst)
                    + state.rejected_retryable.load(Ordering::SeqCst),
                0,
                "a thread that never entered a callback was accused of re-entry"
            );
            assert_eq!(state.closed_ok.load(Ordering::SeqCst), 1);
            assert_eq!(state.unexpected.load(Ordering::SeqCst), 0);
            questdb_oidc_auth_free(auth);
            questdb_oidc_builder_free(builder);
        }
        server.join().unwrap();
    }

    #[test]
    fn a_callback_is_served_the_cached_token() {
        // Regression: `SharedOidcAuth::token` checked the callback-active flag
        // BEFORE the cache, so a renderer reacting to SUCCESS -- which fires
        // after the token is committed -- was refused a token sitting in the
        // cache, as was any sender, reader or pool it flushed from there. Only
        // an acquisition, which would block, may be refused.
        //
        // The existing re-entrancy tests cannot catch this: their provider has
        // an empty cache, so they only ever exercise the `Err` fallback.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (device, _) = listener.accept().unwrap();
            write_json_response(
                device,
                r#"{"device_code":"DEV-CODE","user_code":"ABCD-1234","verification_uri":"https://idp.example.com/activate","expires_in":600,"interval":5}"#,
            );
            let (token, _) = listener.accept().unwrap();
            write_json_response(
                token,
                r#"{"access_token":"cached-access-token","token_type":"Bearer","expires_in":300}"#,
            );
        });

        unsafe {
            let builder = questdb_oidc_builder_new();
            set_string(questdb_oidc_builder_client_id, builder, "questdb-c");
            set_string(questdb_oidc_builder_scope, builder, "openid");
            set_string(
                questdb_oidc_builder_device_authorization_endpoint,
                builder,
                &format!("http://{address}/device"),
            );
            set_string(
                questdb_oidc_builder_token_endpoint,
                builder,
                &format!("http://{address}/token"),
            );
            let mut error = ptr::null_mut();
            assert!(questdb_oidc_builder_interactive(builder, true, &mut error));
            assert!(questdb_oidc_builder_open_browser(
                builder, false, &mut error
            ));
            let state = Arc::new(CallbackTokenState::default());
            let user_data = Box::into_raw(Box::new(Arc::clone(&state))) as *mut c_void;
            assert!(questdb_oidc_builder_event_handler(
                builder,
                Some(take_token_on_success),
                user_data,
                Some(release_callback_token_state),
                &mut error,
            ));
            let auth = questdb_oidc_builder_build(builder, &mut error);
            assert!(!auth.is_null());
            // The callback can only reach the auth once it exists.
            state.auth.store(auth, Ordering::SeqCst);

            assert!(questdb_oidc_auth_sign_in(auth, &mut error));

            assert_eq!(
                state.refused.load(Ordering::SeqCst),
                0,
                "the SUCCESS callback was refused a token already in the cache"
            );
            let served = state.served.lock().unwrap().clone();
            assert_eq!(
                served,
                vec!["cached-access-token".to_string()],
                "the callback did not receive the committed token"
            );

            questdb_oidc_auth_free(auth);
            questdb_oidc_builder_free(builder);
        }
        server.join().unwrap();
    }

    #[test]
    fn device_flow_returns_owned_token_and_renderer_events() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (device, _) = listener.accept().unwrap();
            write_json_response(
                device,
                r#"{"device_code":"DEV-CODE","user_code":"AB\u001b[31m\u202e\u0430","verification_uri":"https://exa\u0430mple.com/\nactivate","verification_uri_complete":"https://idp.example.com/activate?code=ABCD\n","expires_in":600,"interval":5}"#,
            );
            let (token, _) = listener.accept().unwrap();
            write_json_response(
                token,
                r#"{"access_token":"ffi-access-token","token_type":"Bearer","expires_in":300}"#,
            );
        });

        unsafe {
            let builder = questdb_oidc_builder_new();
            set_string(questdb_oidc_builder_client_id, builder, "questdb-c");
            set_string(questdb_oidc_builder_scope, builder, "openid");
            set_string(
                questdb_oidc_builder_device_authorization_endpoint,
                builder,
                &format!("http://{address}/device"),
            );
            set_string(
                questdb_oidc_builder_token_endpoint,
                builder,
                &format!("http://{address}/token"),
            );
            let mut error = ptr::null_mut();
            assert!(questdb_oidc_builder_interactive(builder, true, &mut error));
            assert!(questdb_oidc_builder_open_browser(
                builder, false, &mut error
            ));
            let events = Arc::new(Mutex::new(EventLog::default()));
            let user_data = Box::into_raw(Box::new(Arc::clone(&events))) as *mut c_void;
            assert!(questdb_oidc_builder_event_handler(
                builder,
                Some(record_event),
                user_data,
                Some(release_events),
                &mut error,
            ));
            let auth = questdb_oidc_builder_build(builder, &mut error);
            assert!(!auth.is_null());

            // Token retrieval is safe for transport callbacks even when the
            // auth permits interaction: it reports InteractionRequired without
            // touching the device endpoint. Only sign_in starts the mock server
            // sequence below.
            let token = questdb_oidc_auth_token(auth, &mut error);
            assert!(token.is_null());
            assert!(!error.is_null());
            let mut view = std::mem::zeroed::<questdb_oidc_error_view>();
            view.struct_size = std::mem::size_of_val(&view);
            assert!(questdb_error_oidc_get_view(error, &mut view));
            assert_eq!(
                view.kind,
                questdb_oidc_error_kind::QUESTDB_OIDC_ERROR_INTERACTION_REQUIRED
            );
            crate::questdb_error_free(error);
            error = ptr::null_mut();

            assert!(questdb_oidc_auth_sign_in(auth, &mut error));
            assert!(error.is_null());
            let token = questdb_oidc_auth_token(auth, &mut error);
            assert!(!token.is_null());
            assert!(error.is_null());
            assert_eq!(
                slice::from_raw_parts(
                    questdb_oidc_token_data(token) as *const u8,
                    questdb_oidc_token_len(token),
                ),
                b"ffi-access-token"
            );
            let events = events.lock().unwrap();
            assert_eq!(
                events.kinds,
                vec![
                    questdb_oidc_event_kind::QUESTDB_OIDC_EVENT_PROMPT,
                    questdb_oidc_event_kind::QUESTDB_OIDC_EVENT_SUCCESS,
                ]
            );
            assert_eq!(events.user_code, "AB[31m\\u{0430}");
            assert_eq!(
                events.verification_uri,
                "https://exa\\u{0430}mple.com/activate"
            );
            assert_eq!(
                events.verification_uri_complete,
                "https://idp.example.com/activate?code=ABCD"
            );
            // The verification_uri host is a non-ASCII confusable, so it is not
            // a vettable browser target; the different-host complete is refused
            // rather than silently offered for open/QR, and no target is
            // emitted (empty string in the recording).
            assert_eq!(events.browser_target, "");
            assert_eq!(events.prompt_expires_in_seconds, 600.0);
            assert_eq!(events.prompt_interval_seconds, 5);
            drop(events);
            questdb_oidc_token_free(token);
            questdb_oidc_auth_free(auth);
            questdb_oidc_builder_free(builder);
        }
        server.join().unwrap();
    }

    #[test]
    fn close_from_persistence_diagnostic_does_not_self_deadlock() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (device, _) = listener.accept().unwrap();
            write_json_response(
                device,
                r#"{"device_code":"DEV-CODE","user_code":"ABCD-1234","verification_uri":"https://idp.example.com/activate","expires_in":600,"interval":1}"#,
            );
            let (token, _) = listener.accept().unwrap();
            write_json_response(
                token,
                r#"{"access_token":"short-lived","refresh_token":"refresh-secret","token_type":"Bearer","expires_in":300}"#,
            );
        });

        let state = Arc::new(DiagnosticCloseState::default());
        let user_data = Box::into_raw(Box::new(Arc::clone(&state))) as *mut c_void;
        let sink = CDiagnosticSink {
            target: Arc::new(CDiagnosticTarget {
                callback: close_from_diagnostic,
                user_data: user_data as usize,
                release: Some(release_diagnostic_close_state),
                callback_gate: Mutex::new(CallbackGateState::default()),
                callback_ready: std::sync::Condvar::new(),
                active: AtomicBool::new(false),
            }),
            state: Arc::new(CDiagnosticState::default()),
        };
        let inner = OidcDeviceAuth::builder()
            .client_id("questdb-c")
            .scope("openid")
            .token_endpoint(format!("http://{address}/token"))
            .device_authorization_endpoint(format!("http://{address}/device"))
            .allow_insecure_transport(true)
            .interactive(true)
            .open_browser(false)
            .token_store(FailingSaveStore)
            .diagnostic_handler(sink.clone())
            .build()
            .unwrap();
        let auth = SharedOidcAuth {
            inner: Arc::new(inner),
            event_handler: None,
            diagnostic: Some(sink),
            token_provider_isolation: TokenProviderIsolation::default(),
        };
        *state.auth.lock().unwrap() = Some(auth.clone());

        let (tx, rx) = std::sync::mpsc::channel();
        let signer = std::thread::spawn({
            let auth = auth.clone();
            move || {
                let result = auth.sign_in();
                let _ = tx.send(result);
            }
        });
        let result = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("diagnostic close waited for its own acquisition stack");
        if let Err(err) = result {
            assert_eq!(
                err.oidc_error().map(OidcError::kind),
                Some(OidcErrorKind::Cancelled),
                "close may cancel sign-in, but must not substitute another error: {err}"
            );
        }
        assert_eq!(state.close_returned.load(Ordering::SeqCst), 1);
        assert_eq!(
            auth.token().unwrap_err().oidc_error().map(OidcError::kind),
            Some(OidcErrorKind::Cancelled),
        );
        signer.join().unwrap();
        *state.auth.lock().unwrap() = None; // break target -> state -> auth cycle
        drop(auth);
        server.join().unwrap();
    }

    #[test]
    fn clear_from_persistence_diagnostic_is_rejected_without_deadlock() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (device, _) = listener.accept().unwrap();
            write_json_response(
                device,
                r#"{"device_code":"DEV-CODE","user_code":"ABCD-1234","verification_uri":"https://idp.example.com/activate","expires_in":600,"interval":1}"#,
            );
            let (token, _) = listener.accept().unwrap();
            write_json_response(
                token,
                r#"{"access_token":"short-lived","refresh_token":"refresh-secret","token_type":"Bearer","expires_in":300}"#,
            );
        });

        let state = Arc::new(DiagnosticClearState::default());
        let user_data = Box::into_raw(Box::new(Arc::clone(&state))) as *mut c_void;
        let sink = CDiagnosticSink {
            target: Arc::new(CDiagnosticTarget {
                callback: clear_from_diagnostic,
                user_data: user_data as usize,
                release: Some(release_diagnostic_clear_state),
                callback_gate: Mutex::new(CallbackGateState::default()),
                callback_ready: std::sync::Condvar::new(),
                active: AtomicBool::new(false),
            }),
            state: Arc::new(CDiagnosticState::default()),
        };
        let inner = OidcDeviceAuth::builder()
            .client_id("questdb-c")
            .scope("openid")
            .token_endpoint(format!("http://{address}/token"))
            .device_authorization_endpoint(format!("http://{address}/device"))
            .allow_insecure_transport(true)
            .interactive(true)
            .open_browser(false)
            .token_store(FailingSaveStore)
            .diagnostic_handler(sink.clone())
            .build()
            .unwrap();
        let auth = SharedOidcAuth {
            inner: Arc::new(inner),
            event_handler: None,
            diagnostic: Some(sink),
            token_provider_isolation: TokenProviderIsolation::default(),
        };
        *state.auth.lock().unwrap() = Some(auth.clone());

        let (tx, rx) = std::sync::mpsc::channel();
        let signer = std::thread::spawn({
            let auth = auth.clone();
            move || {
                let result = auth.sign_in();
                let _ = tx.send(result);
            }
        });
        rx.recv_timeout(std::time::Duration::from_secs(10))
            .expect("diagnostic clear waited for its own acquisition stack")
            .expect("failed persistence is best-effort after sign-in");
        let result = state
            .clear_result
            .lock()
            .unwrap()
            .take()
            .expect("diagnostic did not call clear");
        let (code, message) = result.expect_err("diagnostic clear unexpectedly succeeded");
        assert_eq!(code, ErrorCode::InvalidApiCall);
        assert!(
            message.contains("persistence diagnostic callback"),
            "unexpected re-entry diagnostic: {message}"
        );

        signer.join().unwrap();
        *state.auth.lock().unwrap() = None; // break target -> state -> auth cycle
        drop(auth);
        server.join().unwrap();
    }

    #[test]
    fn clear_on_sibling_sharing_persistence_target_is_rejected() {
        let state = Arc::new(DiagnosticClearState::default());
        let user_data = Box::into_raw(Box::new(Arc::clone(&state))) as *mut c_void;
        let target = Arc::new(CDiagnosticTarget {
            callback: clear_from_diagnostic,
            user_data: user_data as usize,
            release: Some(release_diagnostic_clear_state),
            callback_gate: Mutex::new(CallbackGateState::default()),
            callback_ready: std::sync::Condvar::new(),
            active: AtomicBool::new(false),
        });
        let emitting = CDiagnosticSink {
            target: Arc::clone(&target),
            state: Arc::new(CDiagnosticState::default()),
        };
        let sibling = CDiagnosticSink {
            target,
            state: Arc::new(CDiagnosticState::default()),
        };
        let inner = OidcDeviceAuth::builder()
            .client_id("questdb-c")
            .scope("openid")
            .token_endpoint("https://idp.example/token")
            .device_authorization_endpoint("https://idp.example/device")
            .diagnostic_handler(sibling.clone())
            .build()
            .unwrap();
        let auth = SharedOidcAuth {
            inner: Arc::new(inner),
            event_handler: None,
            diagnostic: Some(sibling),
            token_provider_isolation: TokenProviderIsolation::default(),
        };
        *state.auth.lock().unwrap() = Some(auth.clone());

        let (tx, rx) = std::sync::mpsc::channel();
        let emitter = std::thread::spawn(move || {
            emitting.on_persistence_warning("shared-target warning");
            let _ = tx.send(());
        });
        rx.recv_timeout(std::time::Duration::from_secs(5))
            .expect("sibling clear waited on the shared diagnostic target");
        emitter.join().unwrap();

        let result = state
            .clear_result
            .lock()
            .unwrap()
            .take()
            .expect("diagnostic did not call sibling clear");
        let (code, message) = result.expect_err("sibling clear unexpectedly succeeded");
        assert_eq!(code, ErrorCode::InvalidApiCall);
        assert!(
            message.contains("persistence diagnostic callback"),
            "unexpected shared-target diagnostic: {message}"
        );

        *state.auth.lock().unwrap() = None; // break target -> state -> auth cycle
        drop(auth);
    }

    #[test]
    fn close_wakes_a_sibling_queued_for_the_shared_persistence_target() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (device, _) = listener.accept().unwrap();
            write_json_response(
                device,
                r#"{"device_code":"DEV-CODE","user_code":"ABCD-1234","verification_uri":"https://idp.example.com/activate","expires_in":600,"interval":1}"#,
            );
            let (token, _) = listener.accept().unwrap();
            write_json_response(
                token,
                r#"{"access_token":"short-lived","refresh_token":"refresh-secret","token_type":"Bearer","expires_in":300}"#,
            );
        });

        let queued_state = Arc::new(CDiagnosticState::default());
        let save_entered = Arc::new(AtomicBool::new(false));
        let release_save = Arc::new(AtomicBool::new(false));
        let state = Arc::new(DiagnosticSiblingCloseState {
            auth: Mutex::new(None),
            queued_state: Arc::clone(&queued_state),
            release_save: Arc::clone(&release_save),
            close_result: Mutex::new(None),
            callback_started: AtomicBool::new(false),
        });
        let user_data = Box::into_raw(Box::new(Arc::clone(&state))) as *mut c_void;
        let target = Arc::new(CDiagnosticTarget {
            callback: close_queued_sibling_from_diagnostic,
            user_data: user_data as usize,
            release: Some(release_diagnostic_sibling_close_state),
            callback_gate: Mutex::new(CallbackGateState::default()),
            callback_ready: std::sync::Condvar::new(),
            active: AtomicBool::new(false),
        });
        let emitting = CDiagnosticSink {
            target: Arc::clone(&target),
            state: Arc::new(CDiagnosticState::default()),
        };
        let queued = CDiagnosticSink {
            target,
            state: queued_state,
        };
        let inner = OidcDeviceAuth::builder()
            .client_id("questdb-c")
            .scope("openid")
            .token_endpoint(format!("http://{address}/token"))
            .device_authorization_endpoint(format!("http://{address}/device"))
            .allow_insecure_transport(true)
            .interactive(true)
            .open_browser(false)
            .token_store(CoordinatedFailingSaveStore {
                entered: Arc::clone(&save_entered),
                release: release_save,
            })
            .diagnostic_handler(queued.clone())
            .build()
            .unwrap();
        let auth = SharedOidcAuth {
            inner: Arc::new(inner),
            event_handler: None,
            diagnostic: Some(queued),
            token_provider_isolation: TokenProviderIsolation::default(),
        };
        *state.auth.lock().unwrap() = Some(auth.clone());

        // Put the sibling inside token acquisition before the first callback
        // takes the shared target. It will leave `save` only after that callback
        // is active, then queue its own persistence warning behind the target.
        let sibling_auth = auth.clone();
        let sibling = std::thread::spawn(move || {
            sibling_auth
                .sign_in()
                .map_err(|err| (err.code(), err.msg().to_string()))
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !save_entered.load(Ordering::Acquire) {
            assert!(
                std::time::Instant::now() < deadline,
                "sibling did not reach its coordinated store save"
            );
            std::thread::yield_now();
        }

        let (tx, rx) = std::sync::mpsc::channel();
        let emitter = std::thread::spawn(move || {
            emitting.on_persistence_warning("first sibling owns the target");
            let _ = tx.send(());
        });
        rx.recv_timeout(std::time::Duration::from_secs(10))
            .expect("close waited for a sibling queued on its diagnostic target");
        emitter.join().unwrap();
        state
            .close_result
            .lock()
            .unwrap()
            .take()
            .expect("callback did not call sibling close")
            .expect("sibling close did not complete");
        sibling
            .join()
            .expect("sibling sign-in panicked")
            .expect_err("close should cancel the sibling sign-in");

        *state.auth.lock().unwrap() = None; // break target -> state -> auth cycle
        drop(auth);
        server.join().unwrap();
    }

    #[test]
    fn clear_propagates_persisted_deletion_failure() {
        let inner = OidcDeviceAuth::builder()
            .client_id("questdb-c")
            .scope("openid")
            .token_endpoint("https://idp.example/token")
            .device_authorization_endpoint("https://idp.example/device")
            .token_store(FailingClearStore)
            .build()
            .unwrap();
        let auth = Box::into_raw(Box::new(questdb_oidc_auth {
            shared: SharedOidcAuth {
                inner: Arc::new(inner),
                event_handler: None,
                diagnostic: None,
                token_provider_isolation: TokenProviderIsolation::default(),
            },
        }));

        unsafe {
            let mut error = ptr::null_mut();
            assert!(!questdb_oidc_auth_clear(auth, &mut error));
            assert!(!error.is_null());
            let mut view = std::mem::zeroed::<questdb_oidc_error_view>();
            view.struct_size = std::mem::size_of_val(&view);
            assert!(questdb_error_oidc_get_view(error, &mut view));
            assert_eq!(
                view.kind,
                questdb_oidc_error_kind::QUESTDB_OIDC_ERROR_NETWORK
            );
            let mut message_len = 0;
            let message = crate::questdb_error_msg(error, &mut message_len);
            let message = slice::from_raw_parts(message as *const u8, message_len);
            assert!(String::from_utf8_lossy(message).contains("injected persisted clear failure"));
            crate::questdb_error_free(error);
            questdb_oidc_auth_free(auth);
        }
    }

    #[test]
    fn renderer_sanitizes_identity_and_failure_message() {
        let events = Arc::new(Mutex::new(EventLog::default()));
        let user_data = Box::into_raw(Box::new(Arc::clone(&events))) as *mut c_void;
        let renderer = CEventRenderer(event_handler(
            record_event,
            user_data as usize,
            Some(release_events),
        ));

        renderer.on_success(Some("alice\x1b[31m\u{202e}"), 300.0);
        renderer.on_failure("failed\n\u{200b}try again");
        drop(renderer);

        let events = events.lock().unwrap();
        assert_eq!(
            events.kinds,
            vec![
                questdb_oidc_event_kind::QUESTDB_OIDC_EVENT_SUCCESS,
                questdb_oidc_event_kind::QUESTDB_OIDC_EVENT_FAILURE,
            ]
        );
        assert_eq!(events.identity, "alice[31m");
        assert_eq!(events.message, "failedtry again");
    }

    #[test]
    fn sender_attachment_keeps_shared_auth_state_alive() {
        unsafe {
            let builder = explicit_builder();
            let mut error = ptr::null_mut();
            let auth = questdb_oidc_builder_build(builder, &mut error);
            assert!(!auth.is_null());
            let host = crate::line_sender_utf8 {
                len: "localhost".len(),
                buf: c"localhost".as_ptr(),
            };
            let opts = crate::line_sender_opts_new(
                crate::line_sender_protocol::line_sender_protocol_https,
                host,
                9000,
            );
            assert!(!opts.is_null());
            assert!(line_sender_opts_oidc_auth(opts, auth, &mut error));
            assert!(error.is_null());

            questdb_oidc_auth_free(auth);
            crate::line_sender_opts_free(opts);
            questdb_oidc_builder_free(builder);
        }
    }

    #[test]
    fn lazy_pool_retains_auth_without_running_device_flow() {
        unsafe {
            let builder = explicit_builder();
            let mut error = ptr::null_mut();
            let auth = questdb_oidc_builder_build(builder, &mut error);
            assert!(!auth.is_null());

            let mut options = crate::column_sender::questdb_db_connect_options::default();
            let options_size = std::mem::size_of_val(&options);
            crate::column_sender::questdb_db_connect_options_init(&mut options, options_size);
            options.oidc_auth = auth;
            let conf = "ws::addr=127.0.0.1:1;lazy_connect=true;";
            let db = crate::column_sender::questdb_db_connect_ex(
                conf.as_ptr() as *const c_char,
                conf.len(),
                &options,
                &mut error,
            );
            assert!(!db.is_null());
            assert!(error.is_null());

            questdb_oidc_auth_free(auth);
            crate::column_sender::questdb_db_close(db);
            questdb_oidc_builder_free(builder);
        }
    }
}

/// Guards the hand-maintained C headers against drift from the Rust
/// `#[repr(C)]` definitions they mirror.
///
/// The OIDC surface, and `questdb_db_connect_options` alongside it, had no such
/// guard. C has no name mangling, so appending or reordering a field on one
/// side links cleanly and corrupts memory at the call site instead of failing
/// the build. The existing `c_header_line_sender_enum_matches_rust` covers only
/// `line_sender.h`; this extends the same `include_str!` approach to the rest.
///
/// Each check pins both sides: the exhaustive destructuring fails to compile if
/// a Rust field is added, renamed or removed, and the literal list is then
/// compared against the header's own field order.
#[cfg(test)]
mod header_abi {
    use super::*;

    const OIDC_H: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../include/questdb/oidc.h"
    ));
    const CLIENT_H: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../include/questdb/client.h"
    ));

    /// The field identifiers of a C `typedef struct NAME { ... }`, in order.
    fn c_struct_fields(header: &str, name: &str) -> Vec<String> {
        let decl = format!("typedef struct {name}");
        let start = header
            .find(&decl)
            .unwrap_or_else(|| panic!("`{decl}` not found in the header"));
        let body_start = start
            + header[start..]
                .find('{')
                .unwrap_or_else(|| panic!("no body for `{name}`"))
            + 1;
        let body_end = body_start
            + header[body_start..]
                .find('}')
                .unwrap_or_else(|| panic!("unterminated body for `{name}`"));
        header[body_start..body_end]
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                if line.starts_with("//") || line.starts_with('*') {
                    return None;
                }
                let decl = line.strip_suffix(';')?;
                let ident = decl
                    .rsplit(|c: char| c.is_whitespace() || c == '*')
                    .next()?;
                (!ident.is_empty()).then(|| ident.to_string())
            })
            .collect()
    }

    /// The `NAME = <discriminant>` entries of a C enum, in order.
    fn c_enum_variants(header: &str, name: &str) -> Vec<(String, i64)> {
        let decl = format!("typedef enum {name}");
        let start = header
            .find(&decl)
            .unwrap_or_else(|| panic!("`{decl}` not found in the header"));
        let body_start = start + header[start..].find('{').unwrap() + 1;
        let body_end = body_start + header[body_start..].find('}').unwrap();
        header[body_start..body_end]
            .lines()
            .filter_map(|line| {
                let line = line.trim().strip_suffix(',')?;
                let (name, value) = line.split_once('=')?;
                Some((name.trim().to_string(), value.trim().parse::<i64>().ok()?))
            })
            .collect()
    }

    #[test]
    fn oidc_input_cap_matches_the_public_header() {
        let needle =
            format!("#define QUESTDB_OIDC_MAX_INPUT_BYTES ((size_t){MAX_OIDC_INPUT_BYTES})");
        assert!(
            OIDC_H.contains(&needle),
            "public C OIDC input cap drifted from Rust's {MAX_OIDC_INPUT_BYTES}-byte cap; \
             expected `{needle}`"
        );
    }

    #[test]
    fn oidc_event_struct_matches_the_header() {
        #[allow(dead_code)]
        fn exhaustive(event: &questdb_oidc_event) {
            let questdb_oidc_event {
                struct_size: _,
                kind: _,
                user_code: _,
                user_code_len: _,
                verification_uri: _,
                verification_uri_len: _,
                verification_uri_complete: _,
                verification_uri_complete_len: _,
                identity: _,
                identity_len: _,
                message: _,
                message_len: _,
                seconds_left: _,
                expires_in_seconds: _,
                browser_target: _,
                browser_target_len: _,
                interval_seconds: _,
            } = event;
        }
        assert_eq!(
            c_struct_fields(OIDC_H, "questdb_oidc_event"),
            [
                "struct_size",
                "kind",
                "user_code",
                "user_code_len",
                "verification_uri",
                "verification_uri_len",
                "verification_uri_complete",
                "verification_uri_complete_len",
                "identity",
                "identity_len",
                "message",
                "message_len",
                "seconds_left",
                "expires_in_seconds",
                "browser_target",
                "browser_target_len",
                "interval_seconds",
            ]
        );
    }

    #[test]
    fn oidc_diagnostic_struct_matches_the_header() {
        #[allow(dead_code)]
        fn exhaustive(diagnostic: &questdb_oidc_diagnostic) {
            let questdb_oidc_diagnostic {
                struct_size: _,
                kind: _,
                message: _,
                message_len: _,
            } = diagnostic;
        }
        assert_eq!(
            c_struct_fields(OIDC_H, "questdb_oidc_diagnostic"),
            ["struct_size", "kind", "message", "message_len"]
        );
    }

    #[test]
    fn oidc_config_view_struct_matches_the_header() {
        #[allow(dead_code)]
        fn exhaustive(view: &questdb_oidc_config_view) {
            let questdb_oidc_config_view {
                struct_size: _,
                groups_in_token: _,
                client_id: _,
                client_id_len: _,
                token_endpoint: _,
                token_endpoint_len: _,
                device_authorization_endpoint: _,
                device_authorization_endpoint_len: _,
                scope: _,
                scope_len: _,
                audience: _,
                audience_len: _,
                issuer: _,
                issuer_len: _,
            } = view;
        }
        assert_eq!(
            c_struct_fields(OIDC_H, "questdb_oidc_config_view"),
            [
                "struct_size",
                "groups_in_token",
                "client_id",
                "client_id_len",
                "token_endpoint",
                "token_endpoint_len",
                "device_authorization_endpoint",
                "device_authorization_endpoint_len",
                "scope",
                "scope_len",
                "audience",
                "audience_len",
                "issuer",
                "issuer_len",
            ]
        );
    }

    #[test]
    fn oidc_error_view_struct_matches_the_header() {
        #[allow(dead_code)]
        fn exhaustive(view: &questdb_oidc_error_view) {
            let questdb_oidc_error_view {
                struct_size: _,
                kind: _,
                idp_error: _,
                idp_error_len: _,
                idp_error_description: _,
                idp_error_description_len: _,
                has_status: _,
                status: _,
                has_retry_after: _,
                retry_after_seconds: _,
                acquisition_busy: _,
            } = view;
        }
        assert_eq!(
            c_struct_fields(OIDC_H, "questdb_oidc_error_view"),
            [
                "struct_size",
                "kind",
                "idp_error",
                "idp_error_len",
                "idp_error_description",
                "idp_error_description_len",
                "has_status",
                "status",
                "has_retry_after",
                "retry_after_seconds",
                "acquisition_busy",
            ]
        );
    }

    #[test]
    fn db_connect_options_struct_matches_the_header() {
        #[allow(dead_code)]
        fn exhaustive(options: &crate::column_sender::questdb_db_connect_options) {
            let crate::column_sender::questdb_db_connect_options {
                struct_size: _,
                oidc_auth: _,
                event_callback: _,
                event_user_data: _,
                event_inbox_capacity: _,
                rejection_callback: _,
                rejection_user_data: _,
                rejection_inbox_capacity: _,
            } = options;
        }
        assert_eq!(
            c_struct_fields(CLIENT_H, "questdb_db_connect_options"),
            [
                "struct_size",
                "oidc_auth",
                "event_callback",
                "event_user_data",
                "event_inbox_capacity",
                "rejection_callback",
                "rejection_user_data",
                "rejection_inbox_capacity",
            ]
        );
    }

    #[test]
    fn oidc_enums_match_the_header() {
        // Discriminants, not just names: QUESTDB_OIDC_ERROR_UNKNOWN is 255, not
        // the 6 it would get by position, and the binding compares against the
        // named constants.
        assert_eq!(
            c_enum_variants(OIDC_H, "questdb_oidc_event_kind"),
            [
                ("QUESTDB_OIDC_EVENT_PROMPT".to_string(), 0),
                ("QUESTDB_OIDC_EVENT_WAITING".to_string(), 1),
                ("QUESTDB_OIDC_EVENT_SUCCESS".to_string(), 2),
                ("QUESTDB_OIDC_EVENT_FAILURE".to_string(), 3),
            ]
        );
        assert_eq!(questdb_oidc_event_kind::QUESTDB_OIDC_EVENT_PROMPT as i64, 0);
        assert_eq!(
            c_enum_variants(OIDC_H, "questdb_oidc_diagnostic_kind"),
            [("QUESTDB_OIDC_DIAGNOSTIC_PERSISTENCE_WARNING".to_string(), 0)]
        );
        assert_eq!(
            questdb_oidc_diagnostic_kind::QUESTDB_OIDC_DIAGNOSTIC_PERSISTENCE_WARNING as i64,
            0
        );
        assert_eq!(
            questdb_oidc_event_kind::QUESTDB_OIDC_EVENT_FAILURE as i64,
            3
        );

        assert_eq!(
            c_enum_variants(OIDC_H, "questdb_oidc_error_kind"),
            [
                ("QUESTDB_OIDC_ERROR_CONFIG".to_string(), 0),
                ("QUESTDB_OIDC_ERROR_NETWORK".to_string(), 1),
                ("QUESTDB_OIDC_ERROR_DEVICE_FLOW".to_string(), 2),
                ("QUESTDB_OIDC_ERROR_TIMEOUT".to_string(), 3),
                ("QUESTDB_OIDC_ERROR_INTERACTION_REQUIRED".to_string(), 4),
                ("QUESTDB_OIDC_ERROR_CANCELLED".to_string(), 5),
                ("QUESTDB_OIDC_ERROR_UNKNOWN".to_string(), 255),
            ]
        );
        assert_eq!(
            questdb_oidc_error_kind::QUESTDB_OIDC_ERROR_UNKNOWN as i64,
            255
        );
        assert_eq!(
            questdb_oidc_error_kind::QUESTDB_OIDC_ERROR_CANCELLED as i64,
            5
        );
    }
}
