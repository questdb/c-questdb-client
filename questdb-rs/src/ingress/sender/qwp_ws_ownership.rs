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

//! QWP/WebSocket progress ownership.

use std::fmt;
use std::sync::Arc;

/// Controls whether a QWP/WebSocket [`crate::ingress::Sender`] starts its
/// background progress runner or requires the caller to drive progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QwpWsProgress {
    /// Start a background runner that sends frames, receives ACKs, reconnects,
    /// and replays as needed. This is the default and matches Java's sender.
    Background,
    /// Do not start a background runner. The caller must call
    /// [`crate::ingress::Sender::drive_once`] or
    /// [`crate::ingress::Sender::await_acked_fsn`] to advance WebSocket progress.
    Manual,
}

/// Structured server-side error observed by a QWP/WebSocket sender.
///
/// This mirrors Java's `SenderError` shape, but Rust exposes it through
/// polling on [`crate::ingress::Sender`] instead of a callback dispatcher.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QwpWsSenderError {
    /// Server-distinguishable error category.
    pub category: QwpWsErrorCategory,
    /// Policy the client applied after observing the error.
    pub applied_policy: QwpWsErrorPolicy,
    /// Raw QWP status byte. `None` for WebSocket protocol violations, which do
    /// not carry a QWP status byte.
    pub status: Option<u8>,
    /// Human-readable message provided by the server or derived from the
    /// WebSocket close reason.
    pub message: Option<String>,
    /// Server's per-frame QWP message sequence. `None` for WebSocket protocol
    /// violations, which do not carry a QWP message sequence.
    pub message_sequence: Option<u64>,
    /// Inclusive lower bound of the affected frame sequence number span.
    pub from_fsn: u64,
    /// Inclusive upper bound of the affected frame sequence number span.
    pub to_fsn: u64,
}

/// Producer-thread callback invoked for structured QWP/WebSocket server
/// diagnostics.
///
/// The callback runs synchronously from sender API calls such as
/// [`crate::ingress::Sender::flush`]. It must not call back into the same
/// sender.
#[derive(Clone)]
pub struct QwpWsErrorHandler {
    handler: Arc<dyn Fn(&QwpWsSenderError) + Send + Sync>,
}

impl QwpWsErrorHandler {
    /// Create a handler from a closure.
    pub fn new<F>(handler: F) -> Self
    where
        F: Fn(&QwpWsSenderError) + Send + Sync + 'static,
    {
        Self {
            handler: Arc::new(handler),
        }
    }

    pub(crate) fn log_default() -> Self {
        Self::new(default_qwp_ws_error_handler)
    }

    pub(crate) fn handle(&self, error: &QwpWsSenderError) {
        (self.handler)(error);
    }
}

impl fmt::Debug for QwpWsErrorHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("QwpWsErrorHandler { .. }")
    }
}

fn default_qwp_ws_error_handler(error: &QwpWsSenderError) {
    let status = error
        .status
        .map(|status| format!("0x{status:02x}"))
        .unwrap_or_else(|| "none".to_string());
    let sequence = error
        .message_sequence
        .map(|sequence| sequence.to_string())
        .unwrap_or_else(|| "none".to_string());
    let message = error.message.as_deref().unwrap_or("");
    if error.applied_policy == QwpWsErrorPolicy::Halt {
        log::error!(
            target: "questdb::ingress",
            "QWP/WebSocket server rejected batch [category={:?}, policy={:?}, status={}, fsn=[{},{}], seq={}, msg={}]",
            error.category,
            error.applied_policy,
            status,
            error.from_fsn,
            error.to_fsn,
            sequence,
            message
        );
    } else {
        log::warn!(
            target: "questdb::ingress",
            "QWP/WebSocket server rejected batch [category={:?}, policy={:?}, status={}, fsn=[{},{}], seq={}, msg={}]",
            error.category,
            error.applied_policy,
            status,
            error.from_fsn,
            error.to_fsn,
            sequence,
            message
        );
    }
}

/// Lifetime totals reported by a QWP/WebSocket [`crate::ingress::Sender`].
///
/// Mirrors the `getTotal*` counters on Java's `QwpWebSocketSender` so the
/// QuestDB Enterprise e2e harness (questdb-ent/e2e) can compare the same
/// signal across language bindings. All counts are cumulative from the
/// moment the sender was constructed: they never reset, and they survive
/// reconnects.
#[non_exhaustive]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct QwpWsTotals {
    /// Frames handed to the transport for writing, regardless of whether the
    /// server has acknowledged them.
    pub frames_sent: u64,
    /// Server responses interpreted as ACKs: ordinary OK, DurableOk, and
    /// stand-alone DurableAck position notifications.
    pub acks: u64,
    /// Reconnect attempts initiated, including ones that returned
    /// immediately because the retry budget was exhausted.
    pub reconnect_attempts: u64,
    /// Reconnect cycles that completed successfully and resumed publication.
    pub reconnects_succeeded: u64,
    /// Server-sent Reject responses (any policy: terminal, drop-and-continue,
    /// durable, presend).
    pub server_errors: u64,
}

/// Server-distinguishable QWP/WebSocket error category.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QwpWsErrorCategory {
    /// Server-side schema mismatch, such as a missing column, type clash, or
    /// NOT NULL violation.
    SchemaMismatch,
    /// Malformed QWP payload.
    ParseError,
    /// Server-side internal failure.
    InternalError,
    /// Authentication or authorization failure.
    SecurityError,
    /// Non-critical server write failure.
    WriteError,
    /// Terminal WebSocket close code that indicates replaying the same bytes
    /// would fail again.
    ProtocolViolation,
    /// Unknown QWP status byte.
    Unknown,
}

/// Policy applied by the sender after observing a QWP/WebSocket server error.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QwpWsErrorPolicy {
    /// Drop the affected batch from the sender's perspective and continue
    /// draining subsequent batches.
    DropAndContinue,
    /// Latch the error as terminal. The sender must be closed and rebuilt.
    Halt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QwpWsRoleReject {
    pub(crate) role: String,
    pub(crate) zone: Option<String>,
}

impl QwpWsRoleReject {
    pub(crate) fn new(role: &str, zone: Option<&str>) -> Self {
        Self {
            role: role.to_string(),
            zone: zone.map(str::to_string),
        }
    }

    pub(crate) fn is_transient(&self) -> bool {
        self.role.eq_ignore_ascii_case("PRIMARY_CATCHUP")
    }
}
