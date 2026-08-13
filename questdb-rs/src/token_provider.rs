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

//! A caller-supplied source of a fresh Bearer token, pulled on each (re)connect,
//! for the QWP/WebSocket ingress sender and the egress reader (the ILP/HTTP
//! sender has its own per-request provider in `ingress::sender::http`).
//!
//! Wire [`OidcDeviceAuth::token`](crate::oidc::OidcDeviceAuth::token) here so a
//! long-lived client keeps working as the OIDC token silently rotates.

use std::sync::Arc;
#[cfg(feature = "_sender-qwp-ws")]
use std::sync::mpsc::{self, RecvTimeoutError};
#[cfg(feature = "_sender-qwp-ws")]
use std::time::Duration;

#[cfg(feature = "_sender-qwp-ws")]
const ISOLATED_PROVIDER_POLL: Duration = Duration::from_millis(5);

/// The boxed provider closure. Returns a fresh token (the raw token, *not* the
/// `Bearer` header) or an error that fails the connection attempt.
pub(crate) type TokenProviderFn = Arc<dyn Fn() -> crate::Result<String> + Send + Sync>;

/// A cloneable, thread-safe token provider whose [`Debug`] never renders the
/// closure (or any captured token).
#[derive(Clone)]
pub(crate) struct TokenProvider(pub(crate) TokenProviderFn);

impl TokenProvider {
    /// Wrap a caller closure, mapping its error into the crate error type.
    pub(crate) fn new<F, E>(provider: F) -> Self
    where
        F: Fn() -> std::result::Result<String, E> + Send + Sync + 'static,
        E: Into<crate::Error>,
    {
        TokenProvider(Arc::new(move || provider().map_err(Into::into)))
    }

    /// Pull the raw token without transport classification. Used when one
    /// provider instance is shared across independently configured sender and
    /// reader connection factories; each transport applies its own validation
    /// and retry classification when it formats the Bearer header.
    pub(crate) fn provide(&self) -> crate::Result<String> {
        (self.0)()
    }

    /// Pull a token and format it as a validated `Authorization: Bearer` value.
    ///
    /// A control / non-ASCII byte (a decoded CR/LF is a header-injection vector)
    /// or a blank value is rejected — the token never reaches the wire. Mirrors
    /// the ILP/HTTP `HttpAuth::resolve` gate and the device flow's `safe_token`.
    ///
    /// Provider acquisition and validation failures are retryable: the callback
    /// can return a different token on its next invocation, and a QWP
    /// store-and-forward sender must not abandon accepted frames because one
    /// refresh attempt failed. Server authentication rejections remain separate
    /// terminal `AuthError`s because they occur after this method succeeds.
    pub(crate) fn bearer_header(&self) -> crate::Result<String> {
        let provided = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.provide()))
            .map_err(|_| {
                crate::error::fmt!(
                    SocketError,
                    "The token provider panicked while acquiring a Bearer token; \
                     it will be polled again on the next connection attempt."
                )
            })?;
        let token = provided.map_err(classify_provider_error)?;
        if !crate::is_printable_ascii_token(&token) {
            return Err(crate::error::fmt!(
                SocketError,
                "The token provider returned an empty token or one containing a \
                 non-printable-ASCII character; refusing to send it as a Bearer header. \
                 The provider will be polled again on the next connection attempt."
            ));
        }
        Ok(format!("Bearer {token}"))
    }

    /// Run acquisition on an isolated thread while the caller waits
    /// cancellation-aware for its result.
    ///
    /// A synchronous caller-supplied closure cannot be forcibly cancelled.
    /// Once `cancelled` becomes true this method abandons the result receiver;
    /// the provider invocation may finish later, but it retains only this
    /// provider clone rather than the transport runner or its durable queue.
    #[cfg(feature = "_sender-qwp-ws")]
    pub(crate) fn bearer_header_isolated_until(
        &self,
        cancelled: impl Fn() -> bool,
    ) -> crate::Result<String> {
        if cancelled() {
            return Err(provider_shutdown_error());
        }

        let provider = self.clone();
        let (result_tx, result_rx) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("questdb-token-provider".to_string())
            .spawn(move || {
                let _ = result_tx.send(provider.bearer_header());
            })
            .map_err(|err| {
                crate::error::fmt!(
                    SocketError,
                    "Could not start the isolated token-provider worker: {err}"
                )
            })?;

        loop {
            match result_rx.recv_timeout(ISOLATED_PROVIDER_POLL) {
                Ok(result) => return result,
                Err(RecvTimeoutError::Timeout) if cancelled() => {
                    return Err(provider_shutdown_error());
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(crate::error::fmt!(
                        SocketError,
                        "The isolated token-provider worker stopped without returning a token"
                    ));
                }
            }
        }
    }
}

#[cfg(feature = "_sender-qwp-ws")]
fn provider_shutdown_error() -> crate::Error {
    crate::error::fmt!(
        SocketError,
        "Token-provider acquisition was abandoned because the transport is shutting down"
    )
}

/// Classify a token-provider acquisition error separately from a server
/// authentication rejection. The provider is caller-controlled and may recover
/// on its next invocation, so every such failure is retryable. This is especially
/// important for QWP store-and-forward: a provider failure must retain and keep
/// draining already-accepted frames rather than terminalizing the publication
/// store. An actual server rejection is produced later by the handshake path as
/// a terminal [`AuthError`](crate::ErrorCode::AuthError).
fn classify_provider_error(e: crate::Error) -> crate::Error {
    if e.code() == crate::ErrorCode::SocketError {
        e
    } else {
        let msg = format!("Token provider failed: {}", e.msg());
        e.reclassified(crate::ErrorCode::SocketError, msg)
    }
}

impl std::fmt::Debug for TokenProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TokenProvider { .. }")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_header_formats_and_validates() {
        let ok = TokenProvider::new(|| Ok::<_, crate::Error>("tok-123".to_string()));
        assert_eq!(ok.bearer_header().unwrap(), "Bearer tok-123");

        // Blank / all-whitespace is rejected.
        let blank = TokenProvider::new(|| Ok::<_, crate::Error>("   ".to_string()));
        assert!(blank.bearer_header().is_err());

        // A CR/LF (header-injection vector) is rejected.
        let injected = TokenProvider::new(|| Ok::<_, crate::Error>("bad\r\ntoken".to_string()));
        assert!(injected.bearer_header().is_err());

        // A provider error propagates.
        let failing =
            TokenProvider::new(|| Err::<String, _>(crate::error::fmt!(AuthError, "no token")));
        assert!(failing.bearer_header().is_err());
    }

    #[test]
    fn provider_failures_are_retryable_across_connection_attempts() {
        use crate::ErrorCode;
        // A SocketError is preserved, including its original diagnostic.
        let transient = TokenProvider::new(|| {
            Err::<String, _>(crate::Error::new(ErrorCode::SocketError, "network blip"))
        });
        let err = transient.bearer_header().unwrap_err();
        assert_eq!(err.code(), ErrorCode::SocketError);
        assert_eq!(err.msg(), "network blip");

        // Even a non-socket provider error is acquisition-local: a later callback
        // invocation can recover, so transports must not confuse it with a server
        // authentication rejection and terminalize queued data.
        let acquisition = TokenProvider::new(|| {
            Err::<String, _>(crate::Error::new(ErrorCode::ConfigError, "bad config"))
        });
        assert_eq!(
            acquisition.bearer_header().unwrap_err().code(),
            ErrorCode::SocketError
        );

        // Validation is also provider-local and is retried: the next invocation
        // may return a rotated, valid token.
        let blank = TokenProvider::new(|| Ok::<_, crate::Error>("   ".to_string()));
        assert_eq!(
            blank.bearer_header().unwrap_err().code(),
            ErrorCode::SocketError
        );
    }

    #[cfg(feature = "_oidc")]
    #[test]
    fn retry_classification_preserves_oidc_detail() {
        let provider = TokenProvider::new(|| {
            Err::<String, _>(crate::oidc::OidcError::interaction_required("sign in"))
        });

        let err = provider.bearer_header().unwrap_err();
        assert_eq!(err.code(), crate::ErrorCode::SocketError);
        assert_eq!(
            err.oidc_error().map(crate::oidc::OidcError::kind),
            Some(crate::oidc::OidcErrorKind::InteractionRequired)
        );
    }

    #[test]
    fn provider_panic_is_retryable_and_provider_is_polled_again() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let calls = Arc::new(AtomicUsize::new(0));
        let provider = TokenProvider::new({
            let calls = Arc::clone(&calls);
            move || {
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    panic!("synthetic provider panic");
                }
                Ok::<_, crate::Error>("recovered-token".to_string())
            }
        });

        let err = provider.bearer_header().unwrap_err();
        assert_eq!(err.code(), crate::ErrorCode::SocketError);
        assert!(err.msg().contains("token provider panicked"));
        assert_eq!(provider.bearer_header().unwrap(), "Bearer recovered-token");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    /// Coverage for `bearer_header_isolated_until` — the QWP/WebSocket path that
    /// runs an uncancellable synchronous provider closure on a throwaway thread so
    /// a slow or blocking closure can never wedge sender shutdown. Only its
    /// success path was previously exercised (via the connect handshake tests);
    /// the cancellation branches — the whole reason the method exists — were not.
    #[cfg(feature = "_sender-qwp-ws")]
    mod isolated {
        use super::super::TokenProvider;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::{Arc, Condvar, Mutex};

        /// A one-shot manual-reset event usable from a `Fn + Send + Sync` provider.
        #[derive(Default)]
        struct Gate {
            set: Mutex<bool>,
            cv: Condvar,
        }
        impl Gate {
            fn signal(&self) {
                *self.set.lock().unwrap() = true;
                self.cv.notify_all();
            }
            fn wait(&self) {
                let mut set = self.set.lock().unwrap();
                while !*set {
                    set = self.cv.wait(set).unwrap();
                }
            }
        }

        #[test]
        fn returns_the_token_on_fast_success() {
            let provider = TokenProvider::new(|| Ok::<_, crate::Error>("tok-iso".to_string()));
            assert_eq!(
                provider.bearer_header_isolated_until(|| false).unwrap(),
                "Bearer tok-iso"
            );
        }

        #[test]
        fn cancelled_up_front_returns_shutdown_error_without_invoking_provider() {
            let calls = Arc::new(AtomicUsize::new(0));
            let provider = TokenProvider::new({
                let calls = Arc::clone(&calls);
                move || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, crate::Error>("unused".to_string())
                }
            });

            let err = provider.bearer_header_isolated_until(|| true).unwrap_err();
            assert_eq!(err.code(), crate::ErrorCode::SocketError);
            assert!(err.msg().contains("shutting down"), "{}", err.msg());
            // Cancellation short-circuits before any worker thread is spawned.
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }

        #[test]
        fn cancel_while_a_blocked_provider_runs_returns_promptly() {
            // The provider blocks indefinitely; once cancellation is observed the
            // call must return the shutdown error without waiting for it — the whole
            // reason acquisition runs on an isolated thread. A regression that
            // failed to observe cancellation in the poll loop would never return;
            // the bounded `recv_timeout` below turns that wedge into a clear failure
            // instead of a hang.
            let started = Arc::new(Gate::default());
            let release = Arc::new(Gate::default());
            let provider = TokenProvider::new({
                let started = Arc::clone(&started);
                let release = Arc::clone(&release);
                move || {
                    started.signal();
                    release.wait();
                    Ok::<_, crate::Error>("late-token".to_string())
                }
            });

            let cancelled = Arc::new(AtomicBool::new(false));
            let (done_tx, done_rx) = std::sync::mpsc::channel();
            let call = std::thread::spawn({
                let cancelled = Arc::clone(&cancelled);
                move || {
                    let result = provider
                        .bearer_header_isolated_until(move || cancelled.load(Ordering::SeqCst));
                    let _ = done_tx.send(result);
                }
            });

            // Only cancel once the worker is provably inside the blocked provider,
            // so this exercises the poll-loop cancellation branch, not the entry
            // guard.
            started.wait();
            cancelled.store(true, Ordering::SeqCst);

            let result = done_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("cancellation must abandon the blocked provider promptly, not hang");
            let err = result.unwrap_err();
            assert_eq!(err.code(), crate::ErrorCode::SocketError);
            assert!(err.msg().contains("shutting down"), "{}", err.msg());

            // Release the abandoned worker so it exits cleanly; its send to the
            // now-dropped receiver is ignored (no panic, no leak).
            release.signal();
            call.join().unwrap();
        }
    }
}
