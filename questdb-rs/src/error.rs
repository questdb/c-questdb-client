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
#[non_exhaustive]
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

    /// `ColumnSender::flush_arrow_batch_*` was passed a column whose Arrow /
    /// QuestDB kind cannot be persisted to a QuestDB table (e.g.
    /// `ARRAY(LONG, N-D)` is query-result-only on the egress side and has
    /// no QWP wire tag for ingress). Only emitted on the `arrow` feature.
    ArrowUnsupportedColumnKind,

    /// `ColumnSender::flush_arrow_batch_*` was passed a `RecordBatch` that
    /// failed client-side structural validation (column count vs schema,
    /// name encoding, ARROW C Data Interface invariants on a freshly
    /// imported array, etc.). Only emitted on the `arrow` feature.
    ArrowIngest,

    /// A reconnectable failure on the column-major sender's flush/sync path
    /// (transport error, EOF, or a closed connection). The operation has not
    /// committed; the caller should obtain a fresh connection from the pool
    /// (which rotates to a live endpoint) and re-drive from its source. Distinct
    /// from terminal failures (auth / protocol / schema / server rejection),
    /// which must not be retried.
    FailoverRetry,

    /// Every reachable endpoint completed its handshake but none advertised
    /// a role matching the configured `target=` filter (e.g. `target=primary`
    /// against an all-replica address list, or a 421 + `X-QuestDB-Role:
    /// REPLICA` upgrade reject). Distinct from `SocketError` ("all endpoints
    /// unreachable") so callers can tell "no primary elected yet" from
    /// "everything is down".
    RoleMismatch,
}

/// An error that occurred when using QuestDB client library.
#[derive(Debug, PartialEq, Clone)]
pub struct Error {
    code: ErrorCode,
    msg: String,
    in_doubt: bool,
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
            in_doubt: false,
            #[cfg(feature = "_sender-qwp-ws")]
            qwp_ws_rejection: None,
            #[cfg(feature = "_sender-qwp-ws")]
            qwp_ws_role_reject: None,
        }
    }

    /// Mark this error as *delivery-unknown* ("in doubt"): the current input's
    /// bytes may already have reached the server even though the operation
    /// reported failure (e.g. a socket write that failed mid-frame, or a
    /// post-publish ACK wait that failed). Surfaced to callers via
    /// [`Error::in_doubt`]. See `ColumnSender::flush` and the `FlushFailure`
    /// delivery classification.
    #[must_use]
    pub(crate) fn with_in_doubt(mut self, in_doubt: bool) -> Self {
        self.in_doubt = in_doubt;
        self
    }

    /// `true` when the operation that produced this error is *delivery-unknown*
    /// ("in doubt"): the current input may already have reached the server, so
    /// blindly replaying it on a fresh connection can duplicate rows.
    ///
    /// This is independent of the [`code`](Error::code): a delivery-unknown
    /// failure typically reports [`ErrorCode::FailoverRetry`] (the connection
    /// can be replaced), yet `FailoverRetry` alone does **not** mean the input
    /// is safe to retry. Use `in_doubt() == false` together with a retryable
    /// code to decide whether re-sending the same input is safe; when
    /// `in_doubt()` is `true`, only replay if table-level dedup/upsert keys
    /// make duplicates harmless.
    #[must_use]
    pub fn in_doubt(&self) -> bool {
        self.in_doubt
    }

    /// Attach a structured QWP/WebSocket rejection to this error.
    #[cfg(feature = "_sender-qwp-ws")]
    pub fn with_qwp_ws_rejection(mut self, rejection: crate::ingress::QwpWsSenderError) -> Self {
        self.qwp_ws_rejection = Some(Box::new(rejection));
        self
    }

    #[cfg(feature = "_sender-qwp-ws")]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_are_not_in_doubt_by_default() {
        let err = Error::new(ErrorCode::SocketError, "boom");
        assert!(!err.in_doubt());
    }

    #[test]
    fn with_in_doubt_sets_and_preserves_code_and_msg() {
        let err =
            Error::new(ErrorCode::FailoverRetry, "mid-frame write failed").with_in_doubt(true);
        assert!(err.in_doubt());
        assert_eq!(err.code(), ErrorCode::FailoverRetry);
        assert_eq!(err.msg(), "mid-frame write failed");
        // The flag is a flat boolean, not a one-way latch.
        assert!(!err.with_in_doubt(false).in_doubt());
    }
}
