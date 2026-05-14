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
use std::convert::Infallible;
use std::fmt::{Display, Formatter};

macro_rules! fmt {
    ($code:ident, $($arg:tt)*) => {
        crate::error::Error::new(
            crate::error::ErrorCode::$code,
            format!($($arg)*))
    }
}

/// Category of error.
///
/// Accessible via Error's [`code`](Error::code) method.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ErrorCode {
    /// The host, port, or interface was incorrect.
    CouldNotResolveAddr,

    /// Called methods in the wrong order. E.g. `symbol` after `column`.
    InvalidApiCall,

    /// A network error connecting or flushing data out.
    SocketError,

    /// The string or symbol field is not encoded in valid UTF-8.
    ///
    /// *This error is reserved for the
    /// [C and C++ API](https://github.com/questdb/c-questdb-client/).*
    InvalidUtf8,

    /// The table name or column name contains bad characters.
    InvalidName,

    /// The supplied timestamp is invalid.
    InvalidTimestamp,

    /// Error during the authentication process.
    AuthError,

    /// Error during TLS handshake.
    TlsError,

    /// The server does not support ILP-over-HTTP.
    HttpNotSupported,

    /// Error sent back from the server during flush.
    ServerFlushError,

    /// Bad configuration.
    ConfigError,

    /// There was an error serializing an array.
    ArrayError,

    /// Validate protocol version error.
    ProtocolVersionError,

    /// The supplied decimal is invalid.
    InvalidDecimal,

    /// QWP/WebSocket server rejection or terminal protocol violation.
    ServerRejection,
}

/// An error that occurred when using QuestDB client library.
#[derive(Debug, PartialEq, Clone)]
pub struct Error {
    code: ErrorCode,
    msg: String,
    #[cfg(feature = "_sender-qwp-ws")]
    qwp_ws_rejection: Option<Box<crate::ingress::QwpWsSenderError>>,
    #[cfg(feature = "_sender-qwp-ws")]
    qwp_ws_role_reject: Option<crate::ingress::QwpWsRoleReject>,
}

impl Error {
    /// Create an error with the given code and message.
    pub fn new<S: Into<String>>(code: ErrorCode, msg: S) -> Error {
        Error {
            code,
            msg: msg.into(),
            #[cfg(feature = "_sender-qwp-ws")]
            qwp_ws_rejection: None,
            #[cfg(feature = "_sender-qwp-ws")]
            qwp_ws_role_reject: None,
        }
    }

    /// Attach a structured QWP/WebSocket rejection to this error.
    #[cfg(feature = "_sender-qwp-ws")]
    pub fn with_qwp_ws_rejection(mut self, rejection: crate::ingress::QwpWsSenderError) -> Self {
        self.qwp_ws_rejection = Some(Box::new(rejection));
        self
    }

    #[cfg(feature = "_sender-qwp-ws")]
    #[allow(dead_code)]
    pub(crate) fn with_qwp_ws_role_reject(
        mut self,
        role_reject: crate::ingress::QwpWsRoleReject,
    ) -> Self {
        self.qwp_ws_role_reject = Some(role_reject);
        self
    }

    #[cfg(feature = "sync-sender-http")]
    pub(crate) fn from_ureq_error(err: ureq::Error, url: &str) -> Error {
        match err {
            ureq::Error::StatusCode(code) => {
                if code == 404 {
                    fmt!(
                        HttpNotSupported,
                        "Could not flush buffer: HTTP endpoint does not support ILP."
                    )
                } else if [401, 403].contains(&code) {
                    fmt!(
                        AuthError,
                        "Could not flush buffer: HTTP endpoint authentication error [code: {}]",
                        code
                    )
                } else {
                    fmt!(SocketError, "Could not flush buffer: {}: {}", url, err)
                }
            }
            e => {
                fmt!(SocketError, "Could not flush buffer: {}: {}", url, e)
            }
        }
    }

    /// Get the error code (category) of this error.
    pub fn code(&self) -> ErrorCode {
        self.code
    }

    /// Get the string message of this error.
    pub fn msg(&self) -> &str {
        &self.msg
    }

    /// Return the structured QWP/WebSocket rejection that made this error
    /// terminal, if one is available.
    #[cfg(feature = "_sender-qwp-ws")]
    pub fn qwp_ws_rejection(&self) -> Option<&crate::ingress::QwpWsSenderError> {
        self.qwp_ws_rejection.as_deref()
    }

    #[cfg(feature = "_sender-qwp-ws")]
    pub(crate) fn qwp_ws_role_reject(&self) -> Option<&crate::ingress::QwpWsRoleReject> {
        self.qwp_ws_role_reject.as_ref()
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.msg)
    }
}

impl std::error::Error for Error {}

impl From<Infallible> for Error {
    fn from(_: Infallible) -> Self {
        unreachable!()
    }
}

/// A specialized `Result` type for the crate's [`Error`] type.
pub type Result<T> = std::result::Result<T, Error>;

pub(crate) use fmt;
