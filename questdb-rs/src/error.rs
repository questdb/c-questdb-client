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

    /// A network error connecting or flushing data out. **Transient** — obtain a
    /// fresh connection (or let the pool rotate) and retry.
    ///
    /// The terminal, resend-required failure of the QWP/WebSocket
    /// store-and-forward persisted symbol dictionary is a *distinct* code,
    /// [`StoreResendRequired`](Self::StoreResendRequired), so a caller can tell it
    /// apart from a retryable socket drop **by code**, without matching on the
    /// error message text.
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

    /// An Arrow column cannot be written to QuestDB because its type is not
    /// supported for ingestion. Only emitted on the `arrow` feature.
    ArrowUnsupportedColumnKind,

    /// Arrow data is invalid or conflicts with its metadata or overrides. For
    /// example, a UUID claim requires 16-byte values and a LONG256 claim
    /// requires 32-byte values. Only emitted on the `arrow` feature.
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
    /// (`min(max_buf_size, server X-QWP-Max-Batch-Size)`). Chunk publication
    /// splits oversize inputs into smaller frames automatically, so this only
    /// surfaces when splitting cannot make a frame fit. Distinct from
    /// [`InvalidApiCall`](Self::InvalidApiCall) so callers can recognise it
    /// without matching on the error message text.
    BatchTooLarge,

    /// The QWP/WebSocket store-and-forward persisted symbol dictionary is
    /// unrecoverable, so the queued frames that reference it cannot be replayed:
    /// a host/power crash tore the `.symbol-dict` side-file relative to the
    /// queued frames, or it could not be written ahead of them. Retrying the
    /// connection will not help — the affected rows must be **re-ingested from
    /// their source**.
    ///
    /// Terminal, and **distinct from [`SocketError`](Self::SocketError)** (a
    /// transient, retryable socket drop) so a caller can tell "resend from
    /// source" apart from "reconnect and retry" **by code**, without matching on
    /// the error message text. The sender's own reconnect/failover loops treat it
    /// as terminal (they stop) rather than retrying it to their deadline.
    StoreResendRequired,

    /// The QWP/WebSocket connection-scoped symbol dictionary is full: interning
    /// another distinct symbol would push it past its entry-count cap
    /// (2,000,000, matching the server's ingress ceiling) or its cumulative
    /// UTF-8 heap cap (256 MiB). The dictionary accumulates every distinct
    /// symbol referenced across every column, chunk, and row-buffer flush on
    /// one connection, and is only reset by discarding that connection.
    ///
    /// The failing frame is rejected before any byte reaches the wire and the
    /// buffer is rolled back, so *that flush* loses nothing and already-interned
    /// symbols keep flushing — but retrying a *new* symbol on the same sender can
    /// never succeed. A full dictionary therefore **retires the connection on
    /// return**: a pooled sender is dropped rather than recycled (so the next
    /// borrow gets a fresh, empty-dictionary connection, not the same full one),
    /// and the frames flushed *earlier* on it are drained / committed best-effort
    /// on the way out. So the simplest recovery is to return or drop the sender as
    /// usual and continue on a fresh borrow. If those earlier frames must not be
    /// lost, drain or commit them *and check* first, as below.
    ///
    /// - **Pooled row sender** (`QuestDb::borrow_sender`): a full dictionary marks
    ///   the connection for retirement, so a plain drop (which *is* the pool
    ///   return) drains the queue best-effort within `close_flush_timeout` and
    ///   drops the connection instead of recycling it — the next borrow gets a
    ///   fresh one. (Nothing extra to call: an explicit `drop_on_return()` does the
    ///   same and is redundant here.) `wait()` first if the queued frames must not
    ///   be lost. With `sf_dir` configured they persist in the slot, but so does
    ///   the dictionary, and the next borrower re-seeds from that slot's side-file
    ///   at the same size unless the slot drained first — so `wait()` there too, so
    ///   the slot drains and the next borrower starts clean.
    /// - **Pooled direct column sender**
    ///   (`QuestDb::borrow_direct_column_sender`): a full dictionary marks the
    ///   connection **spent** — retired on return, but its transport is healthy and
    ///   still drainable — so a plain drop commits the deferred tail best-effort
    ///   *and* retires the connection. Its `flush` is *deferred* (nothing is
    ///   committed until [`commit`](crate::db::BorrowedDirectColumnSender::commit)
    ///   or `flush_and_wait`), so for a *checked* guarantee call `commit(..)` (or
    ///   `flush_and_wait(..)` on the final chunk) and confirm it succeeded before
    ///   the drop — `commit` still goes through on a spent connection. Do **not**
    ///   reach for `drop_on_return()` on a full dictionary: it hard-latches the
    ///   connection, which makes the drop **skip** the best-effort commit and
    ///   discard the tail. `reborrow_from_pool()` likewise discards the in-flight
    ///   tail (its failover contract), so `commit`/`wait()` before it if that tail
    ///   matters.
    /// - **Standalone** (`Sender`): call
    ///   [`close_drain`](crate::ingress::Sender::close_drain) and check it
    ///   succeeded, then drop and reconnect. Unlike the pooled guards above, a
    ///   plain drop drains **nothing** here — `SyncProtocolHandler`'s `Drop`
    ///   shuts down the ILP-over-TCP socket and has no QWP/WebSocket arm at all,
    ///   so every published-but-unacked frame is discarded with no wait. This is
    ///   the most lossy of the three flavours on a bare drop, not the least.
    ///   `close_drain` is bounded by `close_flush_timeout`.
    /// - **C ABI**: a plain `questdb_db_return_sender` /
    ///   `questdb_db_return_direct_sender` now retires (does not recycle) a
    ///   full-dictionary connection and drains / commits its pending frames
    ///   best-effort — call `qwp_sender_wait` / `qwp_direct_sender_commit` first
    ///   for a checked guarantee. `questdb_db_drop_direct_sender` force-drops and
    ///   **skips** the direct sender's tail commit, so on a full dictionary prefer
    ///   the plain return unless you mean to discard the tail.
    ///
    /// **One exception to "that flush loses nothing", and it matters for
    /// resends.** A chunk too large for a
    /// single frame is split, and each half is published on its own;
    /// store-and-forward is at-least-once, so an earlier half can already be
    /// durably queued when a later half hits the cap. Nothing is lost then
    /// either, but the operation is no longer known-not-delivered:
    /// [`not_delivered`](Error::not_delivered) is false. Do not resend that
    /// chunk — its committed prefix would be duplicated. Consult
    /// [`in_doubt`](Error::in_doubt) separately before replaying a larger
    /// source from an earlier checkpoint.
    ///
    /// Distinct from [`InvalidApiCall`](Self::InvalidApiCall) — a caller
    /// mistake with no recovery — so callers can recognise a full dictionary
    /// **by code** and take that specific action, without matching on the error
    /// message text.
    SymbolDictFull,
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
    /// The specific input passed to the operation that produced this error was
    /// provably not transmitted. Orthogonal to `in_doubt`, which describes
    /// replay from the caller's earlier checkpoint.
    not_delivered: bool,
    /// Structured QWP/WebSocket sender rejection diagnostic.
    /// Sender-only.
    #[cfg(feature = "_sender-qwp-ws")]
    qwp_ws_rejection: Option<Box<crate::ingress::QwpWsSenderError>>,
    /// `421 + X-QuestDB-Role` topology reject seen on the QWP/WebSocket
    /// *sender* upgrade. Sender-only; kept distinct from the query-side
    /// [`UpgradeReject`](crate::egress::UpgradeReject), which
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
            not_delivered: false,
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

    /// Mark this error as unsafe for blind replay ("in doubt"): either the
    /// current input may have reached the server, or an earlier direct-sender
    /// publication may have committed since the caller's last successful ACK
    /// boundary. Surfaced to callers via [`Error::in_doubt`]. See
    /// `PooledSenderCore::flush` and the `FlushFailure` delivery
    /// classification.
    #[must_use]
    #[cfg(feature = "sync-sender-qwp-ws")]
    pub(crate) fn with_in_doubt(mut self, in_doubt: bool) -> Self {
        self.0.in_doubt = in_doubt;
        self
    }

    /// `true` when replaying from the caller's previous successful ACK boundary
    /// is unsafe ("in doubt"). The current input may already have reached the
    /// server, or an earlier direct-sender publication may have committed even
    /// when the current input was provably not transmitted.
    ///
    /// This is independent of the [`code`](Error::code): a delivery-unknown
    /// failure typically reports [`ErrorCode::FailoverRetry`] (the connection
    /// can be replaced), yet `FailoverRetry` alone does **not** make any replay
    /// safe. Use this flag to decide whether replaying from the earlier source
    /// boundary is safe, and use [`not_delivered`](Self::not_delivered) to
    /// decide whether the specific current input may be retried independently.
    /// Low-level APIs can report both flags as `true` when only an earlier
    /// publication caused the source-level ambiguity.
    #[must_use]
    pub fn in_doubt(&self) -> bool {
        self.0.in_doubt
    }

    /// Mark the specific input associated with this error as provably not
    /// transmitted. This metadata is set by QWP column-sender flush paths when
    /// they retain the caller's current chunk or can return its Arrow array.
    #[must_use]
    #[cfg(feature = "sync-sender-qwp-ws")]
    pub(crate) fn with_not_delivered(mut self, not_delivered: bool) -> Self {
        self.0.not_delivered = not_delivered;
        self
    }

    /// `true` only when the specific input passed to the failed operation was
    /// provably not transmitted and may be retried independently.
    ///
    /// This is intentionally independent of [`in_doubt`](Self::in_doubt).
    /// Both may be `true`: the current input is safe to retry, while replaying
    /// a larger source from an earlier checkpoint would duplicate a prefix
    /// committed by a previous direct-sender publication. A `false` result is
    /// conservative and does not by itself say whether an API-specific input
    /// remains available for retry.
    #[must_use]
    pub fn not_delivered(&self) -> bool {
        self.0.not_delivered
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

    /// Builder: attach a query-side [`UpgradeReject`](crate::egress::UpgradeReject)
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
    fn errors_have_no_delivery_guarantee_by_default() {
        let err = Error::new(ErrorCode::SocketError, "boom");
        assert!(!err.in_doubt());
        assert!(!err.not_delivered());
    }

    #[test]
    #[cfg(feature = "sync-sender-qwp-ws")]
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
    #[cfg(feature = "sync-sender-qwp-ws")]
    fn current_input_delivery_is_independent_of_checkpoint_replay() {
        let err = Error::new(ErrorCode::FailoverRetry, "earlier prefix committed")
            .with_not_delivered(true)
            .with_in_doubt(true);
        assert!(err.not_delivered());
        assert!(err.in_doubt());
        assert_eq!(err.code(), ErrorCode::FailoverRetry);
        assert_eq!(err.msg(), "earlier prefix committed");
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
                ErrorCode::StoreResendRequired => {}
                ErrorCode::SymbolDictFull => {}
            }
        }
        let _ = _exhaustive;
    }
}
