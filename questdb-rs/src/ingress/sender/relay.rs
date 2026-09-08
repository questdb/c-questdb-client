/*******************************************************************************
 *     ___                  _   ____  ____
 *    / _ \ _   _  ___  ___| |_|  _ \| __ )
 *   | | | | | | |/ _ \/ __| __| | | |  _ \
 *   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
 *    \__\_\\__,_|\___||___/\__|____/|____/
 *
 *  Copyright (c) 2014-2019 Appsicle
 *  Copyright (c) 2019-2026 QuestDB
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

// Same cfg pruning as `sender.rs`: with only `sync-sender-qwp-ws` enabled the
// handler enum has just the two `*Ws` variants and the `_ =>` fallbacks below
// become unreachable.
#![cfg_attr(
    not(any(
        feature = "sync-sender-tcp",
        feature = "sync-sender-http",
        feature = "sync-sender-qwp-udp"
    )),
    allow(unreachable_patterns)
)]

use crate::error::{self, Result};
use crate::ingress::sender::{
    SyncProtocolHandler, effective_qwp_ws_max_buf_size, publish_qwp_ws_payload_background,
    publish_qwp_ws_payload_manual, qwp_ws_check_error_background, qwp_ws_check_error_manual,
};
use crate::ingress::{
    AckLevel, QwpWsSenderError, QwpWsTotals, Sender, SenderBuilder, is_self_contained,
};
use std::fmt::{Debug, Formatter};
use std::time::Duration;

/// A QWP/WebSocket connection that relays pre-encoded self-contained frames
/// verbatim.
///
/// Build one with [`SenderBuilder::build_relay`] or [`RelaySender::from_conf`].
/// The frames are produced elsewhere — typically by
/// [`Buffer::encode_self_contained`](crate::ingress::Buffer::encode_self_contained)
/// in another process — and shipped by [`flush_encoded`](Self::flush_encoded)
/// without being re-encoded.
///
/// This is a distinct type from [`Sender`] rather than a mode switch: a
/// self-contained frame carries its own base-0 symbol dictionary, whereas typed
/// rows resolve symbols against the connection's delta dictionary, so one
/// connection cannot carry both. A `RelaySender` therefore has no `new_buffer`
/// or row `flush` methods, and a [`Sender`] has no `flush_encoded`. A process
/// that needs both opens one of each.
///
/// Relay runs over the default in-memory Store-and-Forward queue only; `sf_dir`
/// is rejected at build time. Everything else — background or manual progress,
/// reconnect and replay, [`wait`](Self::wait), the FSN watermarks, error
/// polling and the error handler — behaves exactly as on [`Sender`].
pub struct RelaySender {
    inner: Sender,
}

impl Debug for RelaySender {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        f.debug_tuple("RelaySender").field(&self.inner).finish()
    }
}

impl RelaySender {
    /// Wrap a sender whose handler was built with `QwpWsConfig::relay` set.
    /// Only [`SenderBuilder::build_relay`] constructs one, so the handler is
    /// always a QWP/WebSocket handler with the driver already in relay mode.
    pub(crate) fn new(inner: Sender) -> Self {
        Self { inner }
    }

    /// Create a `RelaySender` from a configuration string.
    ///
    /// The format is the same as for [`Sender::from_conf`] and the protocol
    /// must be `ws` or `wss`; see [`SenderBuilder::build_relay`] for the
    /// relay-specific constraints.
    pub fn from_conf<T: AsRef<str>>(conf: T) -> Result<Self> {
        SenderBuilder::from_conf(conf)?.build_relay()
    }

    /// Publish a pre-encoded self-contained QWP/WebSocket frame verbatim.
    ///
    /// The frame must have been produced by
    /// [`Buffer::encode_self_contained`](crate::ingress::Buffer::encode_self_contained)
    /// (or satisfy the same QWP v1 header contract). Only the fixed header and
    /// dictionary base are inspected; tenant table and column data remain
    /// opaque. Validation happens before publication or socket I/O.
    ///
    /// This has the same local-publication semantics as [`Sender::flush`]: it
    /// returns the frame's sequence number once the frame is accepted by the
    /// local replay queue, before the server necessarily ACKs it. The FSN is
    /// not optional: a self-contained frame is never empty, so every
    /// successful call publishes exactly one frame. Keep it to correlate this
    /// frame with [`Self::acked_fsn`] or with the `from_fsn..=to_fsn` span of a
    /// [`QwpWsSenderError`], or call [`Self::wait`] with [`AckLevel::Ok`] to
    /// block for server acceptance.
    ///
    /// A frame is shipped as exactly one WebSocket message and is never split,
    /// so it must fit the smallest of `max_buf_size`, the server's advertised
    /// batch cap, and the per-frame capacity of the replay queue
    /// (`sf_max_segment_bytes` less the segment headers, ~4 MiB by default).
    /// Larger frames are rejected with
    /// [`ErrorCode::InvalidApiCall`](crate::ErrorCode::InvalidApiCall) before
    /// publication.
    pub fn flush_encoded(&mut self, frame: &[u8]) -> Result<u64> {
        if !is_self_contained(frame) {
            return Err(error::fmt!(
                InvalidApiCall,
                "flush_encoded requires a self-contained QWP/WebSocket frame produced by Buffer::encode_self_contained()."
            ));
        }

        // Drain before returning the check error too: a relay-only caller never
        // reaches `wait`/`drive_once`/`close_drain`, so this is the sole point
        // at which its error handler can be notified.
        match &self.inner.handler {
            SyncProtocolHandler::SyncQwpWs(state) => {
                if let Err(err) = qwp_ws_check_error_background(state) {
                    let _ = self.inner.drain_qwp_ws_error_notifications();
                    return Err(err);
                }
            }
            SyncProtocolHandler::ManualQwpWs(state) => {
                if let Err(err) = qwp_ws_check_error_manual(state) {
                    let _ = self.inner.drain_qwp_ws_error_notifications();
                    return Err(err);
                }
            }
            _ => unreachable!("RelaySender is built only over a QWP/WebSocket handler"),
        }
        self.inner.drain_qwp_ws_error_notifications()?;

        // Two caps bind a relay frame: the negotiated message size
        // (`max_buf_size` narrowed by the server's advertised batch cap) and
        // the replay queue's per-frame payload capacity. The queue enforces
        // the latter itself, but only after this call has promised to validate
        // before publication, and with an internal error rather than one that
        // names the knob. A self-contained frame cannot be split, so check the
        // tighter of the two here.
        let (negotiated, queue_cap) = match &self.inner.handler {
            SyncProtocolHandler::SyncQwpWs(state) => (
                effective_qwp_ws_max_buf_size(
                    self.inner.max_buf_size,
                    &state.server_max_batch_size,
                ),
                state.sfa_frame_payload_cap,
            ),
            SyncProtocolHandler::ManualQwpWs(state) => (
                effective_qwp_ws_max_buf_size(
                    self.inner.max_buf_size,
                    &state.server_max_batch_size,
                ),
                state.sfa_frame_payload_cap,
            ),
            _ => unreachable!("RelaySender is built only over a QWP/WebSocket handler"),
        };
        let max = negotiated.min(queue_cap);
        if frame.len() > max {
            let bound_by = if queue_cap < negotiated {
                "the replay queue's per-frame capacity (sf_max_segment_bytes less segment headers)"
            } else {
                "max_buf_size or the server's advertised batch cap"
            };
            return Err(error::fmt!(
                InvalidApiCall,
                "flush_encoded: self-contained frame of {} bytes exceeds the {}-byte limit set by {}; a relay frame is shipped as one message and cannot be split.",
                frame.len(),
                max,
                bound_by
            ));
        }

        let result = match &mut self.inner.handler {
            SyncProtocolHandler::SyncQwpWs(state) => {
                publish_qwp_ws_payload_background(state, frame, max)
            }
            SyncProtocolHandler::ManualQwpWs(state) => {
                publish_qwp_ws_payload_manual(state, frame, max)
            }
            _ => unreachable!("RelaySender is built only over a QWP/WebSocket handler"),
        };
        if let Err(err) = &result
            && matches!(err.code(), crate::ErrorCode::SocketError)
        {
            self.inner.connected = false;
        }
        result
    }

    /// Return the highest frame sequence number published locally by this
    /// sender, or `None` if no frame has been published. See
    /// [`Sender::published_fsn`].
    pub fn published_fsn(&self) -> Result<Option<u64>> {
        self.inner.published_fsn()
    }

    /// Return the highest frame sequence number completed by server ACK or
    /// server-side reject-and-continue, or `None` if no frame has completed.
    /// See [`Sender::acked_fsn`].
    pub fn acked_fsn(&self) -> Result<Option<u64>> {
        self.inner.acked_fsn()
    }

    /// Wait until every frame published so far reaches `ack_level`, or until
    /// the wait makes no progress for `timeout`. See [`Sender::wait`].
    pub fn wait(&mut self, ack_level: AckLevel, timeout: Duration) -> Result<()> {
        self.inner.wait(ack_level, timeout)
    }

    /// Poll the next structured QWP/WebSocket server error observed by this
    /// sender. See [`Sender::poll_qwp_ws_error`].
    pub fn poll_qwp_ws_error(&mut self) -> Result<Option<QwpWsSenderError>> {
        self.inner.poll_qwp_ws_error()
    }

    /// Return the structured diagnostic that halted this sender, if any,
    /// without consuming it. See [`Sender::qwp_ws_terminal_error`].
    #[doc(hidden)]
    pub fn qwp_ws_terminal_error(&self) -> Result<Option<QwpWsSenderError>> {
        self.inner.qwp_ws_terminal_error()
    }

    /// Return how many structured diagnostics were dropped because the
    /// sender's bounded diagnostic log was full. See
    /// [`Sender::qwp_ws_errors_dropped`].
    pub fn qwp_ws_errors_dropped(&self) -> Result<u64> {
        self.inner.qwp_ws_errors_dropped()
    }

    /// Snapshot the sender's lifetime totals. See [`Sender::qwp_ws_totals`].
    pub fn qwp_ws_totals(&self) -> Result<QwpWsTotals> {
        self.inner.qwp_ws_totals()
    }

    /// Drive one progress step when the sender was built with
    /// [`QwpWsProgress::Manual`](crate::ingress::QwpWsProgress::Manual). See
    /// [`Sender::drive_once`].
    pub fn drive_once(&mut self) -> Result<bool> {
        self.inner.drive_once()
    }

    /// Stop accepting new publications and wait for all already published
    /// frames to complete. See [`Sender::close_drain`].
    pub fn close_drain(&mut self) -> Result<()> {
        self.inner.close_drain()
    }

    /// Tell whether the sender is no longer usable and must be dropped. See
    /// [`Sender::must_close`].
    #[must_use]
    pub fn must_close(&self) -> bool {
        self.inner.must_close()
    }

    /// Total connection events discarded by the listener inbox's drop-oldest
    /// policy. `0` when no listener is registered.
    pub fn connection_events_dropped(&self) -> u64 {
        self.inner.connection_events_dropped()
    }

    /// Total connection events delivered to the listener. `0` when no
    /// listener is registered.
    pub fn connection_events_delivered(&self) -> u64 {
        self.inner.connection_events_delivered()
    }
}
