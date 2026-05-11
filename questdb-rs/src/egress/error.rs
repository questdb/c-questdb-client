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

use crate::egress::server_event::ServerInfo;

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
    /// (before the QUERY_REQUEST hits the wire). Covers timestamp /
    /// decimal / geohash range failures alongside everything else
    /// caught at bind time — the egress path has no separate
    /// `InvalidTimestamp` / `InvalidDecimal` because every reachable
    /// client-side validation flows through bind encoding.
    InvalidBind,

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

    /// Mid-query failover was eligible but at least one batch had already
    /// been delivered to the caller, and the cursor's
    /// [`on_failover_reset`](crate::egress::ReaderQuery::on_failover_reset)
    /// callback was not installed.
    ///
    /// Failover replays `QUERY_REQUEST` from `batch_seq=0` on the new
    /// endpoint, which means any rows the caller already consumed would
    /// be re-delivered. Without the callback, the caller has no signal
    /// that this happened and would silently merge duplicates into its
    /// result set. Rather than do that, the cursor terminates with this
    /// error: the caller must either install `on_failover_reset` (and
    /// discard partial state on each invocation) or run the query
    /// again from scratch.
    ///
    /// Surfaced only mid-query — initial connect failover (before any
    /// batch is yielded) does not raise this and behaves transparently.
    FailoverWouldDuplicate,
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
///
/// `#[non_exhaustive]` so future fields (a structured replay-hint, a
/// retry-after value, a cluster-ID tag — anything the failover.md spec
/// might extend `421` reject headers with) can be added without
/// breaking downstream struct-literal construction or exhaustive
/// destructuring. Use [`UpgradeReject::new`] to construct from
/// external code.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
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
///
/// The payload lives behind a `Box` so `Result<T, Error>` stays
/// pointer-sized on the happy path. The `ServerInfo` + diagnostic
/// strings push the inner struct over the 128-byte threshold that
/// `clippy::result_large_err` (rightly) complains about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(Box<ErrorInner>);

#[derive(Debug, Clone, PartialEq, Eq)]
struct ErrorInner {
    code: ErrorCode,
    msg: String,
    /// Set only for upgrade-time role rejections (HTTP `421 +
    /// X-QuestDB-Role`) and target-filter mismatches against
    /// `SERVER_INFO`. `None` for every other error.
    upgrade_reject: Option<UpgradeReject>,
    /// Set only when the rejection came from a v2 `SERVER_INFO`
    /// target-filter mismatch — the full server-advertised identity
    /// (`epoch`, `cluster_id`, `node_id`, `capabilities`, `server_wall_ns`)
    /// alongside the role/zone already on `upgrade_reject`. Spec
    /// (wire-egress.md §11.9.3) calls this out so operators can tell
    /// `target=` filter exhaustion apart from "all endpoints unreachable"
    /// and identify the cluster/node that last refused.
    ///
    /// `None` for every other error path, including the v1-pinned
    /// `RoleMismatch` (no `SERVER_INFO` to attach) and the `421 +
    /// X-QuestDB-Role` upgrade reject (only headers; no full `SERVER_INFO`).
    server_info: Option<ServerInfo>,
}

impl Error {
    /// Construct an [`Error`] from a category and a human-readable
    /// message. `upgrade_reject` and `server_info` are `None` —
    /// attach them with [`Error::with_upgrade_reject`] /
    /// [`Error::with_server_info`] if available. The message is taken
    /// verbatim; format it with `format!` at the call site.
    pub fn new<S: Into<String>>(code: ErrorCode, msg: S) -> Error {
        Error(Box::new(ErrorInner {
            code,
            msg: msg.into(),
            upgrade_reject: None,
            server_info: None,
        }))
    }

    /// Builder: attach `UpgradeReject` to a freshly-constructed error.
    /// Used by the upgrade-reject and target-mismatch sites so the
    /// host-health tracker can later read the role + zone without
    /// re-parsing the HTTP response.
    pub fn with_upgrade_reject(mut self, reject: UpgradeReject) -> Error {
        self.0.upgrade_reject = Some(reject);
        self
    }

    /// Builder: attach the full last-observed `ServerInfo` to a
    /// `RoleMismatch` produced from the v2 `SERVER_INFO`-target-mismatch
    /// path. Lets diagnostics name the cluster/node that refused, on top
    /// of the role/zone already on `upgrade_reject`.
    pub fn with_server_info(mut self, info: ServerInfo) -> Error {
        self.0.server_info = Some(info);
        self
    }

    /// Diagnostic category for this error. Stable across releases —
    /// new variants may be added (`ErrorCode` is `#[non_exhaustive]`),
    /// but existing ones aren't renamed or repurposed.
    pub fn code(&self) -> ErrorCode {
        self.0.code
    }

    /// Human-readable diagnostic message. Format and contents are
    /// **not** part of the stable API — pattern-matching on the
    /// string is unsupported; use [`Error::code`] for programmatic
    /// classification.
    pub fn msg(&self) -> &str {
        &self.0.msg
    }

    /// Server-advertised role + zone carried alongside this error. `Some`
    /// when the error originated from an HTTP `421 + X-QuestDB-Role`
    /// upgrade reject or a `SERVER_INFO` role / `target=` filter mismatch;
    /// `None` for all other failure paths.
    pub fn upgrade_reject(&self) -> Option<&UpgradeReject> {
        self.0.upgrade_reject.as_ref()
    }

    /// Full last-observed `SERVER_INFO` carried alongside this error.
    /// `Some` only when the rejection came from the v2
    /// `SERVER_INFO`-target-mismatch path; `None` everywhere else,
    /// including v1-pinned `RoleMismatch` and the `421 + X-QuestDB-Role`
    /// upgrade reject. Lets callers distinguish "no endpoint matched
    /// `target=`" (this is `Some`) from "all endpoints unreachable"
    /// (this is `None`).
    pub fn server_info(&self) -> Option<&ServerInfo> {
        self.0.server_info.as_ref()
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0.msg)
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
    fn server_info_round_trips_and_default_is_none() {
        use crate::egress::server_event::{ServerInfo, ServerRole};
        let err_plain = Error::new(ErrorCode::SocketError, "x");
        assert!(err_plain.server_info().is_none());

        let info = ServerInfo {
            role: ServerRole::Replica,
            epoch: 7,
            capabilities: 0,
            server_wall_ns: 1_700_000_000_000_000_000,
            cluster_id: "c-1".into(),
            node_id: "n-2".into(),
            zone_id: Some("eu-west-1a".into()),
        };
        let err = Error::new(ErrorCode::RoleMismatch, "no match").with_server_info(info.clone());
        assert_eq!(err.server_info(), Some(&info));
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
