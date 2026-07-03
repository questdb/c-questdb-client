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

//! Errors raised by the [`oidc`](crate::oidc) module.

use crate::oidc::render::strip_control;
use crate::{Error, ErrorCode};
use std::fmt::{Display, Formatter};

/// A specialized [`Result`](std::result::Result) type for OIDC operations.
pub type Result<T> = std::result::Result<T, OidcError>;

/// The category of an [`OidcError`], mirroring the reference clients' typed
/// exception hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OidcErrorKind {
    /// The OIDC configuration could not be resolved or is inconsistent (e.g.
    /// QuestDB does not advertise OIDC, the IdP device-authorization endpoint
    /// cannot be discovered, or a required argument is missing).
    Config,

    /// A network-level failure while talking to QuestDB or the IdP. The refresh
    /// token (if any) is still valid, so the caller may retry later.
    Network,

    /// The OAuth 2.0 device authorization grant failed; the IdP
    /// `error`/`error_description` are preserved when available.
    DeviceFlow,

    /// The user did not authorize the device in time (the code expired).
    Timeout,

    /// Interactive sign-in is required, but the process is not interactive
    /// (e.g. no TTY, a CI job). Use a QuestDB service-account REST token or the
    /// OAuth 2.0 client-credentials grant there instead.
    InteractionRequired,
}

/// An error raised while acquiring or refreshing an OIDC token.
///
/// Converts into the crate-wide [`Error`](crate::Error) (via `From`), mapping
/// [`Config`](OidcErrorKind::Config) to [`ConfigError`](ErrorCode::ConfigError),
/// [`Network`](OidcErrorKind::Network) to [`SocketError`](ErrorCode::SocketError),
/// and the remaining kinds to [`AuthError`](ErrorCode::AuthError) — so it flows
/// straight into a [`SenderBuilder`](crate::ingress::SenderBuilder) token
/// provider's `Result`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcError {
    kind: OidcErrorKind,
    message: String,
    /// The raw `error` field from an untrusted IdP response (control-stripped).
    error: Option<String>,
    /// The raw `error_description` from an untrusted IdP response (control-stripped).
    error_description: Option<String>,
    /// The HTTP status behind a non-JSON response, when applicable.
    status: Option<u16>,
    /// A parsed `Retry-After` (delta-seconds) off a 429/503 response, when present.
    retry_after: Option<u64>,
}

impl OidcError {
    fn new(kind: OidcErrorKind, message: impl Into<String>) -> Self {
        // Strip terminal / bidi / zero-width control characters from every
        // message before it can reach a display sink. Error messages routinely
        // interpolate untrusted IdP fields (error_description, response bodies,
        // verification URIs), and an uncaught error printed to a terminal is a
        // sink the renderer's own sanitization never sees. Doing it here (not at
        // each construction site) means no site can forget.
        OidcError {
            kind,
            message: strip_control(&message.into()),
            error: None,
            error_description: None,
            status: None,
            retry_after: None,
        }
    }

    pub(crate) fn config(message: impl Into<String>) -> Self {
        Self::new(OidcErrorKind::Config, message)
    }

    pub(crate) fn network(message: impl Into<String>) -> Self {
        Self::new(OidcErrorKind::Network, message)
    }

    pub(crate) fn device_flow(message: impl Into<String>) -> Self {
        Self::new(OidcErrorKind::DeviceFlow, message)
    }

    pub(crate) fn timeout(message: impl Into<String>) -> Self {
        Self::new(OidcErrorKind::Timeout, message)
    }

    pub(crate) fn interaction_required(message: impl Into<String>) -> Self {
        Self::new(OidcErrorKind::InteractionRequired, message)
    }

    /// Attach the untrusted IdP `error` / `error_description` fields (each
    /// control-stripped, same rationale as the message).
    pub(crate) fn with_idp_error(
        mut self,
        error: Option<&str>,
        error_description: Option<&str>,
    ) -> Self {
        self.error = error.map(strip_control);
        self.error_description = error_description.map(strip_control);
        self
    }

    pub(crate) fn with_status(mut self, status: Option<u16>) -> Self {
        self.status = status;
        self
    }

    pub(crate) fn with_retry_after(mut self, retry_after: Option<u64>) -> Self {
        self.retry_after = retry_after;
        self
    }

    /// The category of this error.
    pub fn kind(&self) -> OidcErrorKind {
        self.kind
    }

    /// The human-readable message (control-stripped).
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The untrusted IdP `error` field, when the response carried one.
    pub fn idp_error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// The untrusted IdP `error_description` field, when the response carried one.
    pub fn idp_error_description(&self) -> Option<&str> {
        self.error_description.as_deref()
    }

    /// The HTTP status behind a non-JSON response, when applicable.
    pub fn status(&self) -> Option<u16> {
        self.status
    }

    /// A parsed `Retry-After` (delta-seconds), when present.
    pub(crate) fn retry_after_secs(&self) -> Option<u64> {
        self.retry_after
    }
}

impl Display for OidcError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)?;
        // Surface the structured IdP fields for a device-flow error so a
        // top-level `{}` print (or a converted crate::Error) carries them.
        if let Some(desc) = &self.error_description {
            if !desc.is_empty() && !self.message.contains(desc.as_str()) {
                write!(f, " [{desc}]")?;
            }
        } else if let Some(err) = &self.error
            && !err.is_empty()
            && !self.message.contains(err.as_str())
        {
            write!(f, " [{err}]")?;
        }
        Ok(())
    }
}

impl std::error::Error for OidcError {}

impl From<OidcError> for Error {
    fn from(err: OidcError) -> Error {
        let code = match err.kind {
            OidcErrorKind::Config => ErrorCode::ConfigError,
            OidcErrorKind::Network => ErrorCode::SocketError,
            OidcErrorKind::DeviceFlow
            | OidcErrorKind::Timeout
            | OidcErrorKind::InteractionRequired => ErrorCode::AuthError,
        };
        Error::new(code, err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_maps_to_error_code() {
        let cases = [
            (OidcError::config("x"), ErrorCode::ConfigError),
            (OidcError::network("x"), ErrorCode::SocketError),
            (OidcError::device_flow("x"), ErrorCode::AuthError),
            (OidcError::timeout("x"), ErrorCode::AuthError),
            (OidcError::interaction_required("x"), ErrorCode::AuthError),
        ];
        for (oidc_err, expected) in cases {
            let err: Error = oidc_err.into();
            assert_eq!(err.code(), expected);
        }
    }

    #[test]
    fn message_is_control_stripped() {
        let err = OidcError::device_flow("bad\x1b[31mred\nnewline");
        assert!(!err.message().contains('\x1b'));
        assert!(!err.message().contains('\n'));
    }

    #[test]
    fn idp_error_description_appended_once() {
        let err = OidcError::device_flow("Device flow failed")
            .with_idp_error(Some("access_denied"), Some("user said no"));
        let shown = err.to_string();
        assert!(shown.contains("Device flow failed"));
        assert!(shown.contains("user said no"));
    }

    #[test]
    fn idp_fields_control_stripped() {
        let err = OidcError::device_flow("failed").with_idp_error(Some("a\x1bb"), Some("c\x07d"));
        assert_eq!(err.idp_error(), Some("ab"));
        assert_eq!(err.idp_error_description(), Some("cd"));
    }
}
