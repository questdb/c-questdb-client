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

//! Egress error type. Distinct from the ingress [`crate::Error`] so that
//! callers handling read failures aren't forced to match against
//! sender-only variants and vice versa.

use std::fmt::{Display, Formatter};

/// Egress error category.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// Bad URL, host, or interface in the connect string.
    CouldNotResolveAddr,

    /// Bad configuration string or builder argument.
    ConfigError,

    /// Methods called in the wrong order (e.g. `execute()` while a cursor is live).
    InvalidApiCall,

    /// Network-level failure (connect, read, write, close).
    SocketError,

    /// TLS handshake failure.
    TlsError,

    /// HTTP-upgrade or WebSocket handshake failure.
    HandshakeError,

    /// Authentication or authorization failure.
    AuthError,

    /// Server returned an unsupported QWP version, encoding, or capability.
    UnsupportedServer,

    /// All endpoints connected, but none advertised a role matching the
    /// configured `target` filter (e.g. `target=replica` against a
    /// single-node OSS server that emits `STANDALONE`).
    RoleMismatch,

    /// Wire-format violation: bad magic, truncated frame, unknown discriminant,
    /// invalid varint, schema/symbol-dict reference miss, etc.
    ProtocolError,

    /// String or symbol field was not valid UTF-8.
    InvalidUtf8,

    /// Bind parameter index, count, or value rejected client-side
    /// (before the QUERY_REQUEST hits the wire).
    InvalidBind,

    /// Invalid timestamp value.
    InvalidTimestamp,

    /// Invalid decimal value.
    InvalidDecimal,

    /// Server-reported QWP `SCHEMA_MISMATCH` (status `0x03`).
    ServerSchemaMismatch,

    /// Server-reported QWP `PARSE_ERROR` (status `0x05`).
    ServerParseError,

    /// Server-reported QWP `INTERNAL_ERROR` (status `0x06`).
    ServerInternalError,

    /// Server-reported QWP `SECURITY_ERROR` (status `0x08`).
    ServerSecurityError,

    /// Client-side limit hit (e.g. an array row exceeds the configured
    /// per-row element cap).
    LimitExceeded,

    /// Server-reported QWP `LIMIT_EXCEEDED` (status `0x0B`).
    ServerLimitExceeded,

    /// Query was cancelled (locally or via server `CANCELLED` status `0x0A`).
    Cancelled,
}

/// Egress error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    code: ErrorCode,
    msg: String,
}

impl Error {
    pub fn new<S: Into<String>>(code: ErrorCode, msg: S) -> Error {
        Error {
            code,
            msg: msg.into(),
        }
    }

    pub fn code(&self) -> ErrorCode {
        self.code
    }

    pub fn msg(&self) -> &str {
        &self.msg
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.msg)
    }
}

impl std::error::Error for Error {}

/// `Result` alias scoped to the egress error type.
pub type Result<T> = std::result::Result<T, Error>;

/// Internal `format!`-style constructor mirroring the ingress `fmt!` macro.
macro_rules! fmt {
    ($code:ident, $($arg:tt)*) => {
        $crate::egress::error::Error::new(
            $crate::egress::error::ErrorCode::$code,
            format!($($arg)*))
    }
}

pub(crate) use fmt;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fmt_macro_builds_error() {
        let err = fmt!(ProtocolError, "bad code 0x{:02X}", 0xAB);
        assert_eq!(err.code(), ErrorCode::ProtocolError);
        assert_eq!(err.msg(), "bad code 0xAB");
    }

    #[test]
    fn display_matches_msg() {
        let err = Error::new(ErrorCode::SocketError, "boom");
        assert_eq!(format!("{}", err), "boom");
    }
}
