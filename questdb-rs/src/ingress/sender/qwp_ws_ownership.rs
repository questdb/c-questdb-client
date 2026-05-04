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
