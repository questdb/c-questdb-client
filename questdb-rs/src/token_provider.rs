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
        let token = (self.0)().map_err(classify_provider_error)?;
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
        crate::error::fmt!(SocketError, "Token provider failed: {}", e.msg())
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
}
