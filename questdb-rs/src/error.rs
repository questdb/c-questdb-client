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
/// This is the single, unified error category for the whole client: it spans
/// both ingestion (writing into QuestDB) and queries (reading out). Not every
/// variant can arise from every operation — the ingest path never emits the
/// reader-only wire/cursor categories, and a query never emits the
/// sender-only encode categories — but a caller handling errors from a
/// `QuestDb` pool, which spans both directions, sees one category enum.
///
/// Accessible via Error's [`code`](Error::code) method.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorCode {
    /// The host, port, or interface was incorrect.
    CouldNotResolveAddr,

    /// Called methods in the wrong order. E.g. `symbol` after `column`.
    InvalidApiCall,

    /// A network error connecting or flushing data out.
    SocketError,

    /// The TCP connect (dial) to the server exceeded the configured
    /// `connect_timeout`. Distinct from [`SocketError`](Self::SocketError)
    /// so a caller can tell a timed-out dial apart from a refused / reset
    /// connection. Currently produced only by the QWP/WebSocket transport.
    ConnectTimeout,

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

    // --- Query / reader (egress) categories -----------------------------
    // The categories below are emitted by the query path. They never arise
    // from ingestion, but live in the same enum so a `QuestDb` handle (which
    // spans both directions) speaks a single error vocabulary.
    /// HTTP-upgrade or WebSocket handshake failure.
    HandshakeError,

    /// Server returned an unsupported QWP version, encoding, or capability.
    UnsupportedServer,

    /// Wire-format violation: bad magic, truncated frame, unknown discriminant,
    /// invalid varint, symbol-dict reference miss, etc.
    ProtocolError,

    /// Bind parameter index, count, or value rejected client-side
    /// (before the QUERY_REQUEST hits the wire). On the query path this
    /// covers timestamp / decimal / geohash range failures alongside
    /// everything else caught at bind time.
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
    /// been delivered to the caller, and the cursor's `on_failover_reset`
    /// callback was not installed. Failover would replay the query from the
    /// start on the new endpoint, re-delivering already-consumed rows, so the
    /// cursor terminates with this error instead of silently duplicating.
    /// The caller must install `on_failover_reset` (and discard partial state
    /// on each invocation) or re-run the query from scratch.
    FailoverWouldDuplicate,

    /// Streaming Arrow adapter saw a mid-stream schema change: a later
    /// `RESULT_BATCH` decoded into an Arrow schema that differs from the
    /// snapshot captured at adapter construction. The adapter is poisoned;
    /// the underlying cursor remains usable and the caller may re-wrap it
    /// with a fresh `as_arrow_reader()` call. Only emitted on the `arrow`
    /// feature.
    SchemaDrift,

    /// `Cursor::as_arrow_reader()` was called on a stream that terminated
    /// before any `RESULT_BATCH` was decoded — there is no schema to
    /// snapshot. Recoverable: treat as a "no rows" result, or re-execute.
    /// Only emitted on the `arrow` feature.
    NoSchema,

    /// Arrow C Data Interface export failed (e.g. arrow-rs rejected an
    /// internal invariant on the produced `ArrayData`). Indicates a crate
    /// bug; not user-recoverable. Only emitted on the `arrow` feature.
    ArrowExport,

    /// An irreducible QWP/WebSocket unit (the table schema plus a single
    /// row block) exceeds the negotiated per-batch cap
    /// (`min(max_buf_size, server X-QWP-Max-Batch-Size)`). The column sender
    /// splits oversize chunks into smaller frames automatically, so this only
    /// surfaces when splitting cannot make a frame fit. Distinct from
    /// [`InvalidApiCall`](Self::InvalidApiCall) so callers can recognise it
    /// without matching on the error message text.
    BatchTooLarge,
}

/// An error that occurred when using the QuestDB client library.
///
/// The payload lives behind a `Box` so `Result<T, Error>` stays pointer-sized
/// on the happy path: the optional query-side `ServerInfo` and the diagnostic
/// strings would otherwise push the struct past the `clippy::result_large_err`
/// threshold.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Error(Box<ErrorInner>);

#[derive(Debug, PartialEq, Eq, Clone)]
struct ErrorInner {
    code: ErrorCode,
    msg: String,
    in_doubt: bool,
    /// Structured QWP/WebSocket sender rejection diagnostic.
    /// Sender-only.
    #[cfg(feature = "_sender-qwp-ws")]
    qwp_ws_rejection: Option<Box<crate::ingress::QwpWsSenderError>>,
    /// `421 + X-QuestDB-Role` topology reject seen on the QWP/WebSocket
    /// *sender* upgrade. Sender-only; kept distinct from the query-side
    /// [`UpgradeReject`](crate::egress::server_event::UpgradeReject), which
    /// carries the richer `SERVER_INFO` role byte.
    #[cfg(feature = "_sender-qwp-ws")]
    qwp_ws_role_reject: Option<crate::ingress::QwpWsRoleReject>,
    /// Server-advertised role + zone from a query-side `421 + X-QuestDB-Role`
    /// upgrade reject or `SERVER_INFO` target-filter mismatch. Query-only.
    #[cfg(feature = "_egress")]
    upgrade_reject: Option<crate::egress::server_event::UpgradeReject>,
    /// Full last-observed `SERVER_INFO` from a query-side target-filter
    /// mismatch. Query-only.
    #[cfg(feature = "_egress")]
    server_info: Option<crate::egress::server_event::ServerInfo>,
}

impl Error {
    /// Create an error with the given code and message.
    pub fn new<S: Into<String>>(code: ErrorCode, msg: S) -> Error {
        Error(Box::new(ErrorInner {
            code,
            msg: msg.into(),
            in_doubt: false,
            #[cfg(feature = "_sender-qwp-ws")]
            qwp_ws_rejection: None,
            #[cfg(feature = "_sender-qwp-ws")]
            qwp_ws_role_reject: None,
            #[cfg(feature = "_egress")]
            upgrade_reject: None,
            #[cfg(feature = "_egress")]
            server_info: None,
        }))
    }

    /// Mark this error as *delivery-unknown* ("in doubt"): the current input's
    /// bytes may already have reached the server even though the operation
    /// reported failure (e.g. a socket write that failed mid-frame, or a
    /// post-publish ACK wait that failed). Surfaced to callers via
    /// [`Error::in_doubt`]. See `ColumnSender::flush` and the `FlushFailure`
    /// delivery classification.
    #[must_use]
    pub(crate) fn with_in_doubt(mut self, in_doubt: bool) -> Self {
        self.0.in_doubt = in_doubt;
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
        self.0.in_doubt
    }

    /// Attach a structured QWP/WebSocket rejection to this error.
    #[cfg(feature = "_sender-qwp-ws")]
    pub fn with_qwp_ws_rejection(mut self, rejection: crate::ingress::QwpWsSenderError) -> Self {
        self.0.qwp_ws_rejection = Some(Box::new(rejection));
        self
    }

    #[cfg(feature = "_sender-qwp-ws")]
    pub(crate) fn with_qwp_ws_role_reject(
        mut self,
        role_reject: crate::ingress::QwpWsRoleReject,
    ) -> Self {
        self.0.qwp_ws_role_reject = Some(role_reject);
        self
    }

    /// Builder: attach a query-side [`UpgradeReject`](crate::egress::server_event::UpgradeReject)
    /// (HTTP `421 + X-QuestDB-Role` or `SERVER_INFO` target mismatch) so the
    /// host-health tracker can read the role + zone without re-parsing.
    #[cfg(feature = "_egress")]
    pub fn with_upgrade_reject(
        mut self,
        reject: crate::egress::server_event::UpgradeReject,
    ) -> Self {
        self.0.upgrade_reject = Some(reject);
        self
    }

    /// Builder: attach the full last-observed `SERVER_INFO` to a
    /// `RoleMismatch` produced from the `SERVER_INFO` target-mismatch path.
    #[cfg(feature = "_egress")]
    pub fn with_server_info(mut self, info: crate::egress::server_event::ServerInfo) -> Self {
        self.0.server_info = Some(info);
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
        self.0.code
    }

    /// Get the string message of this error.
    pub fn msg(&self) -> &str {
        &self.0.msg
    }

    /// Return the structured QWP/WebSocket rejection that made this error
    /// terminal, if one is available.
    #[cfg(feature = "_sender-qwp-ws")]
    pub fn qwp_ws_rejection(&self) -> Option<&crate::ingress::QwpWsSenderError> {
        self.0.qwp_ws_rejection.as_deref()
    }

    #[cfg(feature = "_sender-qwp-ws")]
    pub(crate) fn qwp_ws_role_reject(&self) -> Option<&crate::ingress::QwpWsRoleReject> {
        self.0.qwp_ws_role_reject.as_ref()
    }

    /// Server-advertised role + zone carried alongside a query-side error.
    /// `Some` when the error originated from an HTTP `421 + X-QuestDB-Role`
    /// upgrade reject or a `SERVER_INFO` role / `target=` filter mismatch;
    /// `None` for all other failure paths.
    #[cfg(feature = "_egress")]
    pub fn upgrade_reject(&self) -> Option<&crate::egress::server_event::UpgradeReject> {
        self.0.upgrade_reject.as_ref()
    }

    /// Full last-observed `SERVER_INFO` carried alongside this error. `Some`
    /// only when the rejection came from the `SERVER_INFO` target-mismatch
    /// path; `None` everywhere else. Lets callers distinguish "no endpoint
    /// matched `target=`" (this is `Some`) from "all endpoints unreachable"
    /// (this is `None`).
    #[cfg(feature = "_egress")]
    pub fn server_info(&self) -> Option<&crate::egress::server_event::ServerInfo> {
        self.0.server_info.as_ref()
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0.msg)
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

    #[test]
    fn display_matches_msg() {
        let err = Error::new(ErrorCode::ProtocolError, "boom");
        assert_eq!(format!("{}", err), "boom");
    }

    #[test]
    fn fmt_macro_builds_error() {
        let err = fmt!(ProtocolError, "bad code 0x{:02X}", 0xAB);
        assert_eq!(err.code(), ErrorCode::ProtocolError);
        assert_eq!(err.msg(), "bad code 0xAB");
    }

    #[cfg(feature = "_egress")]
    #[test]
    fn server_info_and_upgrade_reject_round_trip() {
        use crate::egress::server_event::{ServerInfo, ServerRole, UpgradeReject};
        let err_plain = Error::new(ErrorCode::SocketError, "x");
        assert!(err_plain.server_info().is_none());
        assert!(err_plain.upgrade_reject().is_none());

        let info = ServerInfo {
            role: ServerRole::Replica,
            epoch: 7,
            capabilities: 0,
            server_wall_ns: 1_700_000_000_000_000_000,
            cluster_id: "c-1".into(),
            node_id: "n-2".into(),
            zone_id: Some("eu-west-1a".into()),
        };
        let reject = UpgradeReject::new(0x02, "REPLICA", Some("eu-west-1a".into()));
        let err = Error::new(ErrorCode::RoleMismatch, "no match")
            .with_server_info(info.clone())
            .with_upgrade_reject(reject.clone());
        assert_eq!(err.server_info(), Some(&info));
        assert_eq!(err.upgrade_reject(), Some(&reject));
    }

    #[test]
    fn error_code_is_exhaustively_known() {
        // Compile-time tripwire. This match is WILDCARD-FREE, which the
        // *defining* crate is allowed to write over its own `#[non_exhaustive]`
        // enum (the attribute only forces a `_` arm in downstream crates).
        // Adding a new `ErrorCode` variant breaks THIS compile — a forcing
        // reminder to also map it in the FFI `impl From<ErrorCode> for
        // line_sender_error_code` (questdb-rs-ffi/src/lib.rs) and the C/C++
        // headers, none of which the compiler can check cross-crate.
        fn _exhaustive(code: ErrorCode) {
            match code {
                ErrorCode::CouldNotResolveAddr => {}
                ErrorCode::InvalidApiCall => {}
                ErrorCode::SocketError => {}
                ErrorCode::ConnectTimeout => {}
                ErrorCode::InvalidUtf8 => {}
                ErrorCode::InvalidName => {}
                ErrorCode::InvalidTimestamp => {}
                ErrorCode::AuthError => {}
                ErrorCode::TlsError => {}
                ErrorCode::HttpNotSupported => {}
                ErrorCode::ServerFlushError => {}
                ErrorCode::ConfigError => {}
                ErrorCode::ArrayError => {}
                ErrorCode::ProtocolVersionError => {}
                ErrorCode::InvalidDecimal => {}
                ErrorCode::ServerRejection => {}
                ErrorCode::ArrowUnsupportedColumnKind => {}
                ErrorCode::ArrowIngest => {}
                ErrorCode::FailoverRetry => {}
                ErrorCode::RoleMismatch => {}
                ErrorCode::HandshakeError => {}
                ErrorCode::UnsupportedServer => {}
                ErrorCode::ProtocolError => {}
                ErrorCode::InvalidBind => {}
                ErrorCode::ServerSchemaMismatch => {}
                ErrorCode::ServerParseError => {}
                ErrorCode::ServerInternalError => {}
                ErrorCode::ServerSecurityError => {}
                ErrorCode::LimitExceeded => {}
                ErrorCode::ServerLimitExceeded => {}
                ErrorCode::Cancelled => {}
                ErrorCode::FailoverWouldDuplicate => {}
                ErrorCode::SchemaDrift => {}
                ErrorCode::NoSchema => {}
                ErrorCode::ArrowExport => {}
                ErrorCode::BatchTooLarge => {}
            }
        }
        let _ = _exhaustive;
    }
}
