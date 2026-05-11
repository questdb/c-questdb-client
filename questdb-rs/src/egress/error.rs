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
///
/// `#[non_exhaustive]` so new diagnostic categories can be added without
/// breaking exhaustive matches in downstream code.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
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

/// Upgrade-time topology rejection carried alongside an `Error`.
///
/// Populated when the server rejects the WebSocket upgrade with HTTP `421`
/// plus an `X-QuestDB-Role` header (per failover.md §5), or when a v2
/// `SERVER_INFO` advertises a role that does not match the configured
/// `target=` filter. The host-health tracker (when present) reads this to
/// decide whether the host is in `TransientReject` (`PRIMARY_CATCHUP`) or
/// `TopologyReject` (every other role byte) and to update zone tier from
/// the optional `X-QuestDB-Zone` / `SERVER_INFO.zone_id`.
///
/// `role_byte` is the raw `SERVER_INFO.role` byte from wire-egress.md §11.8
/// (`0x00`=STANDALONE, `0x01`=PRIMARY, `0x02`=REPLICA, `0x03`=PRIMARY_CATCHUP);
/// unrecognised values are carried through verbatim so a future role
/// addition is observable to operators even on an older client build.
/// `role_name` is the ASCII token actually seen on the wire (uppercased for
/// the four named roles; the literal header value when the byte is unknown);
/// it is kept so diagnostics surface what the server *said*, not what the
/// client decided to call it. `zone` is `Some` only when the server
/// advertised one (via `SERVER_INFO.zone_id` gated on `CAP_ZONE`, or the
/// `X-QuestDB-Zone` upgrade header).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpgradeReject {
    pub role_byte: u8,
    pub role_name: String,
    pub zone: Option<String>,
}

impl UpgradeReject {
    pub fn new(role_byte: u8, role_name: impl Into<String>, zone: Option<String>) -> Self {
        Self {
            role_byte,
            role_name: role_name.into(),
            zone,
        }
    }

    /// True when the server-advertised role is `PRIMARY_CATCHUP` —
    /// a transient state (promotion in flight) that the tracker should
    /// classify as recoverable. Every other role byte is topological
    /// (won't recover without operator intervention or topology change).
    /// Per failover.md §6: any non-empty `X-QuestDB-Role` value other
    /// than `PRIMARY_CATCHUP` is conservatively treated as topological,
    /// including unrecognised tokens.
    pub fn is_transient(&self) -> bool {
        self.role_byte == 0x03 || self.role_name.eq_ignore_ascii_case("PRIMARY_CATCHUP")
    }
}

/// Egress error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    code: ErrorCode,
    msg: String,
    /// Set only for upgrade-time role rejections (HTTP `421 +
    /// X-QuestDB-Role`) and target-filter mismatches against
    /// `SERVER_INFO`. `None` for every other error.
    upgrade_reject: Option<UpgradeReject>,
}

impl Error {
    pub fn new<S: Into<String>>(code: ErrorCode, msg: S) -> Error {
        Error {
            code,
            msg: msg.into(),
            upgrade_reject: None,
        }
    }

    /// Builder: attach `UpgradeReject` to a freshly-constructed error.
    /// Used by the upgrade-reject and target-mismatch sites so the
    /// host-health tracker can later read the role + zone without
    /// re-parsing the HTTP response.
    pub fn with_upgrade_reject(mut self, reject: UpgradeReject) -> Error {
        self.upgrade_reject = Some(reject);
        self
    }

    pub fn code(&self) -> ErrorCode {
        self.code
    }

    pub fn msg(&self) -> &str {
        &self.msg
    }

    /// Server-advertised role + zone carried alongside this error. `Some`
    /// when the error originated from an HTTP `421 + X-QuestDB-Role`
    /// upgrade reject or a `SERVER_INFO` role / `target=` filter mismatch;
    /// `None` for all other failure paths.
    pub fn upgrade_reject(&self) -> Option<&UpgradeReject> {
        self.upgrade_reject.as_ref()
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

    #[test]
    fn upgrade_reject_round_trips() {
        let r = UpgradeReject::new(0x03, "PRIMARY_CATCHUP", Some("eu-west-1a".into()));
        let err = Error::new(ErrorCode::RoleMismatch, "rejected").with_upgrade_reject(r.clone());
        assert_eq!(err.code(), ErrorCode::RoleMismatch);
        assert_eq!(err.upgrade_reject(), Some(&r));
        assert!(r.is_transient());
    }

    #[test]
    fn upgrade_reject_default_is_none() {
        let err = Error::new(ErrorCode::SocketError, "x");
        assert!(err.upgrade_reject().is_none());
    }

    #[test]
    fn upgrade_reject_topological_for_non_catchup_roles() {
        // STANDALONE / PRIMARY / REPLICA / unknown all classify as
        // topological (won't recover without topology change). The header
        // parser matches PRIMARY_CATCHUP case-insensitively per spec §5.
        for (byte, name) in [
            (0x00, "STANDALONE"),
            (0x01, "PRIMARY"),
            (0x02, "REPLICA"),
            (0x99, "FUTURE_ROLE"),
        ] {
            let r = UpgradeReject::new(byte, name, None);
            assert!(!r.is_transient(), "role {} should be topological", name);
        }
    }

    #[test]
    fn upgrade_reject_is_transient_case_insensitive() {
        let r = UpgradeReject::new(0x99, "primary_catchup", None);
        assert!(r.is_transient(), "case-insensitive match per spec §5");
    }
}
