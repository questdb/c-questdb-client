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

#![allow(dead_code)]

//! QWP/WebSocket send-core mechanics over an explicit transport abstraction.
//!
//! The publication store owns queue and receipt state. `QwpWsSendCore` owns
//! transport plus connection-local progress state and exposes the progress
//! primitives used by both manual and background schedulers.

use std::collections::{HashMap, VecDeque};
#[cfg(feature = "sync-sender-qwp-ws")]
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

#[cfg(feature = "sync-sender-qwp-ws")]
use rand::Rng;

use crate::error;
#[cfg(feature = "sync-sender-qwp-ws")]
use crate::ingress::conf::{QwpWsConfig, QwpWsEndpoint};
#[cfg(feature = "sync-sender-qwp-ws")]
use crate::ingress::tls::TlsSettings;
use crate::{Error, ErrorCode};

#[cfg(feature = "sync-sender-qwp-ws")]
use super::qwp_ws::{
    QwpWsConnectRoundSuccess, QwpWsHostHealthTracker, WsFrameRead, WsFrameReader, WsStream,
    connect_qwp_ws_endpoint_round, qwp_ws_configured_endpoints, write_binary_frame,
    write_ping_frame,
};
use super::qwp_ws_codec::{self as codec, PipelinedResponse};
use super::qwp_ws_ownership::{QwpWsErrorCategory, QwpWsErrorPolicy, QwpWsSenderError};
use super::qwp_ws_queue::{
    OutboundFrame, OutboundFrameView, QueueError, QwpReceipt, QwpReceiptStatus, SentFrame,
};
use super::qwp_ws_sfa_catchup::{
    CatchUpEntryTooLarge, CatchUpStreamError, SentDictMirror, frame_delta_start,
};
#[cfg(test)]
use super::qwp_ws_sfa_queue::SfaMemoryQueueOptions;
use super::qwp_ws_sfa_queue::{
    SfaCleanupFailure, SfaFrameQueue, SfaProducer, SfaProgressView, SfaSendCursor,
    SfaStorageFinish, SfaStorageResult, SfaStorageStep,
};
#[cfg(feature = "sync-sender-qwp-ws")]
use crate::ws::frame::OPCODE_BINARY;

pub(crate) const DEFAULT_EVENT_CAPACITY: usize = 1024;
pub(crate) const DEFAULT_MAX_FRAME_REJECTIONS: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReconnectPolicy {
    max_duration: Duration,
    initial_backoff: Duration,
    max_backoff: Duration,
}

impl ReconnectPolicy {
    pub(crate) fn bounded(
        max_duration: Duration,
        initial_backoff: Duration,
        max_backoff: Duration,
    ) -> Self {
        Self {
            max_duration,
            initial_backoff,
            max_backoff,
        }
    }

    fn no_backoff(max_duration: Duration) -> Self {
        Self {
            max_duration,
            initial_backoff: Duration::ZERO,
            max_backoff: Duration::ZERO,
        }
    }

    pub(crate) fn max_duration(&self) -> Duration {
        self.max_duration
    }

    pub(crate) fn initial_backoff(&self) -> Duration {
        self.initial_backoff
    }

    pub(crate) fn max_backoff(&self) -> Duration {
        self.max_backoff
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct PoisonFrameTracker {
    fsn: Option<u64>,
    completed_fsn: Option<u64>,
    rejection_count: usize,
    first_strike_at: Option<Instant>,
}

impl PoisonFrameTracker {
    fn clear(&mut self) {
        *self = Self::default();
    }

    fn record_failure(
        &mut self,
        fsn: u64,
        completed_fsn: Option<u64>,
        limit: usize,
        min_escalation_window: Duration,
        now: Instant,
    ) -> bool {
        if self.fsn == Some(fsn) && self.completed_fsn == completed_fsn {
            self.rejection_count = self.rejection_count.saturating_add(1);
        } else {
            self.fsn = Some(fsn);
            self.completed_fsn = completed_fsn;
            self.rejection_count = 1;
            self.first_strike_at = Some(now);
        }
        if self.rejection_count < limit {
            return false;
        }
        min_escalation_window.is_zero()
            || self.first_strike_at.is_some_and(|first_strike_at| {
                now.saturating_duration_since(first_strike_at) >= min_escalation_window
            })
    }

    fn strikes(&self) -> usize {
        self.rejection_count
    }
}

#[cfg(test)]
#[derive(Debug)]
pub(crate) struct QwpWsCoreTestHarness<Q, T> {
    store: QwpWsPublicationStore<Q>,
    send_core: QwpWsSendCore<T>,
}

// Connection-local send-loop state shared by the manual and background
// schedulers. It owns transport and cursor state, but never owns publication
// state.
#[derive(Debug)]
pub(crate) struct QwpWsSendCore<T> {
    transport: T,
    send_cursor: SendCursor,
    /// I/O-thread-local mirror of every symbol dictionary entry sent on this
    /// connection, used to re-register the whole dictionary via catch-up frame(s)
    /// on reconnect. Inert (disabled) unless the store enables delta mode via
    /// [`Self::enable_delta_dict`]; disabled keeps every frame self-sufficient.
    dict_mirror: SentDictMirror,
    /// Set on a successful reconnect when delta mode is active: the next send
    /// iteration emits the full-dictionary catch-up frame(s) before replaying the
    /// queued delta frames, so the fresh server can resolve them. Cleared once
    /// emitted.
    catch_up_pending: bool,
    durable_ack: Option<DurableAckTracker>,
    reconnect_policy: ReconnectPolicy,
    pending_reconnect: Option<QwpWsReconnectState>,
    poison_tracker: PoisonFrameTracker,
    max_frame_rejections: usize,
    poison_min_escalation_window: Duration,
    sends_on_connection: u64,
}

#[derive(Debug)]
pub(crate) enum QwpWsSendProgress {
    Outcome(DriveOutcome),
    TransportFailure(TransportFailure),
}

#[derive(Debug)]
pub(crate) enum QwpWsHotSendProgress {
    NoResponse {
        frame: SentFrame,
    },
    Response {
        frame: SentFrame,
        response: TransportResponse,
    },
    TransportFailure {
        frame: SentFrame,
        failure: TransportFailure,
    },
}

#[derive(Debug)]
pub(crate) struct QwpWsHotResponseProgress {
    pub(crate) outcome: DriveOutcome,
    pub(crate) events: Vec<DriverEvent>,
    pub(crate) ok_fsn: Option<u64>,
}

impl QwpWsHotResponseProgress {
    fn idle() -> Self {
        Self {
            outcome: DriveOutcome::Idle,
            events: Vec::new(),
            ok_fsn: None,
        }
    }

    fn from_optional_event(outcome: DriveOutcome, event: Option<DriverEvent>) -> Self {
        let events = event.into_iter().collect();
        Self {
            outcome,
            events,
            ok_fsn: None,
        }
    }

    fn with_ok_fsn(mut self, fsn: u64) -> Self {
        self.ok_fsn = Some(fsn);
        self
    }
}

#[derive(Debug)]
pub(crate) enum QwpWsTransportFailureAction {
    Reconnect {
        reason: ReconnectReason,
        initial_error: Error,
        pace: Duration,
    },
    Terminal(Error),
}

#[derive(Debug)]
pub(crate) enum QwpWsReconnectStep {
    Reconnected { reason: ReconnectReason },
    RetryAfter { sleep_for: Duration },
    Terminal(Error),
}

#[derive(Debug)]
pub(crate) struct QwpWsReconnectState {
    policy: ReconnectPolicy,
    context: &'static str,
    reason: ReconnectReason,
    started: Instant,
    deadline: Option<Instant>,
    backoff: Duration,
    pace_first_attempt: Option<Duration>,
    last_error: Error,
    attempts: usize,
}

impl QwpWsReconnectState {
    fn new(
        policy: ReconnectPolicy,
        context: &'static str,
        reason: ReconnectReason,
        initial_error: Error,
    ) -> Self {
        let started = Instant::now();
        Self {
            policy,
            context,
            reason,
            started,
            deadline: started.checked_add(policy.max_duration),
            backoff: policy.initial_backoff,
            pace_first_attempt: None,
            last_error: initial_error,
            attempts: 0,
        }
    }

    pub(crate) fn with_pace(mut self, pace: Duration) -> Self {
        if !pace.is_zero() {
            self.deadline = self
                .deadline
                .and_then(|deadline| deadline.checked_add(pace));
            self.pace_first_attempt = Some(pace);
        }
        self
    }

    pub(crate) fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    pub(crate) fn initial_backoff(&self) -> Duration {
        self.policy.initial_backoff
    }

    fn deadline_expired(&self) -> bool {
        reconnect_deadline_expired(self.deadline)
    }

    pub(crate) fn retry_budget_exhausted_error(&self) -> Error {
        retry_budget_exhausted_error(
            self.context,
            self.attempts,
            self.started,
            Some(self.last_error.clone()),
        )
    }

    pub(crate) fn next_after_retryable_terminal(&self, err: Error) -> Self {
        Self::new(self.policy, self.context, self.reason, err)
    }

    pub(crate) fn take_first_attempt_pace(&mut self) -> Option<Duration> {
        self.pace_first_attempt.take()
    }

    fn record_retryable_error(&mut self, err: Error) -> Duration {
        let role_reject = is_qwp_ws_role_reject_error(&err);
        self.last_error = err;
        let sleep_for =
            reconnect_sleep_duration(role_reject, self.policy.initial_backoff, self.backoff);
        self.backoff = if role_reject {
            self.policy.initial_backoff
        } else {
            double_duration(self.backoff).min(self.policy.max_backoff)
        };
        sleep_for
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PublicationState {
    Open,
    Closing,
    Terminal,
}

#[derive(Debug, Clone)]
pub(crate) struct PublicationLifecycle {
    state: Arc<AtomicU8>,
}

const PUBLICATION_OPEN: u8 = 0;
const PUBLICATION_CLOSING: u8 = 1;
const PUBLICATION_TERMINAL: u8 = 2;

impl PublicationState {
    fn from_raw(state: u8) -> Self {
        match state {
            PUBLICATION_OPEN => Self::Open,
            PUBLICATION_CLOSING => Self::Closing,
            PUBLICATION_TERMINAL => Self::Terminal,
            _ => Self::Terminal,
        }
    }
}

impl PublicationLifecycle {
    fn new() -> Self {
        Self {
            state: Arc::new(AtomicU8::new(PUBLICATION_OPEN)),
        }
    }

    pub(crate) fn load(&self) -> PublicationState {
        PublicationState::from_raw(self.state.load(Ordering::Acquire))
    }

    pub(crate) fn begin_close(&self) {
        let _ = self.state.compare_exchange(
            PUBLICATION_OPEN,
            PUBLICATION_CLOSING,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    pub(crate) fn terminalize(&self) -> PublicationState {
        PublicationState::from_raw(self.state.swap(PUBLICATION_TERMINAL, Ordering::AcqRel))
    }

    pub(crate) fn is_terminal(&self) -> bool {
        self.load() == PublicationState::Terminal
    }
}

/// Lifetime counters mirroring the Java QwpWebSocketSender's total-* getters.
/// Bumped at the same event sites the Java sidecar reports on so the QWP/WS
/// e2e harness (questdb-enterprise/questdb-ent/e2e) can observe identical
/// signals across language bindings.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct QwpWsCounters {
    pub total_frames_sent: u64,
    pub total_acks: u64,
    pub total_reconnect_attempts: u64,
    pub total_reconnects_succeeded: u64,
    pub total_server_errors: u64,
}

impl From<QwpWsCounters> for super::qwp_ws_ownership::QwpWsTotals {
    fn from(counters: QwpWsCounters) -> Self {
        Self {
            frames_sent: counters.total_frames_sent,
            acks: counters.total_acks,
            reconnect_attempts: counters.total_reconnect_attempts,
            reconnects_succeeded: counters.total_reconnects_succeeded,
            server_errors: counters.total_server_errors,
        }
    }
}

#[derive(Debug)]
pub(crate) struct QwpWsPublicationStore<Q = SfaFrameQueue> {
    queue: Q,
    events: DriverEventRing,
    lifecycle: PublicationLifecycle,
    terminal_error: Option<Error>,
    terminal_sender_error: Option<QwpWsSenderError>,
    last_server_error: Option<QwpServerError>,
    rejected_frames: VecDeque<QwpRejectedFrame>,
    sender_errors: SenderErrorLog,
    counters: QwpWsCounters,
}

impl<Q: PublicationLog> QwpWsPublicationStore<Q> {
    pub(crate) fn new(queue: Q, event_capacity: usize) -> Self {
        Self {
            queue,
            events: DriverEventRing::new(event_capacity),
            lifecycle: PublicationLifecycle::new(),
            terminal_error: None,
            terminal_sender_error: None,
            last_server_error: None,
            rejected_frames: VecDeque::new(),
            sender_errors: SenderErrorLog::new(event_capacity),
            counters: QwpWsCounters::default(),
        }
    }

    pub(crate) fn counters(&self) -> QwpWsCounters {
        self.counters
    }

    pub(crate) fn record_reconnect_attempt(&mut self) {
        self.counters.total_reconnect_attempts += 1;
    }

    pub(crate) fn lifecycle(&self) -> PublicationLifecycle {
        self.lifecycle.clone()
    }

    pub(crate) fn max_in_flight(&self) -> usize {
        self.queue.max_in_flight()
    }

    pub(crate) fn try_submit(&mut self, payload: &[u8]) -> Result<QwpReceipt, DriverError> {
        match self.lifecycle.load() {
            PublicationState::Open => {}
            PublicationState::Closing => return Err(DriverError::Closing),
            PublicationState::Terminal => return Err(DriverError::Terminal),
        }
        let receipt = self.queue.try_publish(payload)?;
        self.push_event(DriverEvent::Published { fsn: receipt.fsn });
        Ok(receipt)
    }

    pub(crate) fn take_producer(&mut self) -> Option<SfaProducer> {
        self.queue.take_producer()
    }

    pub(crate) fn progress_view(&self) -> SfaProgressView {
        self.queue.progress_view()
    }

    pub(crate) fn record_sent_frame(
        &mut self,
        send_cursor: &mut SendCursor,
        frame: SentFrame,
    ) -> Result<(), DriverError> {
        send_cursor.commit_sent(frame)?;
        self.record_sent_event(frame);
        Ok(())
    }

    pub(crate) fn record_sent_event(&mut self, frame: SentFrame) {
        self.counters.total_frames_sent += 1;
        self.push_event(DriverEvent::Sent {
            fsn: frame.fsn,
            wire_seq: frame.wire_seq,
        });
    }

    pub(crate) fn record_completed_through_event(&mut self, fsn: u64, wire_seq: u64) {
        self.queue.persist_completed_fsn(fsn);
        self.push_event(DriverEvent::CompletedThrough { fsn, wire_seq });
    }

    pub(crate) fn record_driver_event(&mut self, event: DriverEvent) {
        self.push_event(event);
    }

    pub(crate) fn mark_terminal(&mut self, error: Option<Error>) {
        if self.lifecycle.terminalize() != PublicationState::Terminal {
            self.terminal_error = error;
            self.push_event(DriverEvent::Terminal);
        }
    }

    pub(crate) fn is_terminal(&self) -> bool {
        self.lifecycle.is_terminal()
    }

    fn receipt_status(
        &self,
        send_cursor: &SendCursor,
        durable_ack: Option<&DurableAckTracker>,
        receipt: QwpReceipt,
    ) -> QwpReceiptStatus {
        let status = self.queue.receipt_status(receipt);
        if self.is_terminal() && status.is_pending() {
            return QwpReceiptStatus::Terminal { fsn: receipt.fsn };
        }
        if matches!(status, QwpReceiptStatus::Published { .. })
            && let Some(wire_seq) = send_cursor.wire_seq_for_fsn(receipt.fsn)
        {
            return QwpReceiptStatus::Sent {
                fsn: receipt.fsn,
                wire_seq,
            };
        }
        if matches!(status, QwpReceiptStatus::Published { .. })
            && let Some(wire_seq) =
                durable_ack.and_then(|tracker| tracker.pending_wire_seq_for_fsn(receipt.fsn))
        {
            return QwpReceiptStatus::Sent {
                fsn: receipt.fsn,
                wire_seq,
            };
        }
        status
    }

    pub(crate) fn take_storage_maintenance_step(
        &mut self,
    ) -> Result<Option<SfaStorageStep>, DriverError> {
        self.queue
            .take_storage_maintenance_step(self.lifecycle.load() == PublicationState::Open)
    }

    pub(crate) fn finish_storage_maintenance(
        &mut self,
        result: SfaStorageResult,
    ) -> Result<SfaStorageFinish, DriverError> {
        self.queue
            .finish_storage_maintenance(result, self.lifecycle.load() == PublicationState::Open)
    }

    pub(crate) fn record_storage_cleanup_failure(
        &mut self,
        failure: SfaCleanupFailure,
    ) -> Result<(), DriverError> {
        self.queue.record_storage_cleanup_failure(failure)
    }

    fn clear_unresolved_rejected_frames(&mut self) {
        let completed_fsn = self.queue.completed_fsn();
        self.rejected_frames.retain(|rejected| {
            completed_fsn.is_some_and(|completed_fsn| rejected.fsn <= completed_fsn)
        });
    }

    fn record_rejected_frame(
        &mut self,
        fsn: u64,
        wire_seq: u64,
        error: QwpServerError,
        policy: QwpWsErrorPolicy,
    ) -> QwpWsSenderError {
        self.last_server_error = Some(error.clone());
        let sender_error = sender_error_for_qwp_error(&error, wire_seq, fsn, policy);
        self.push_sender_error(sender_error.clone());
        if self.sender_errors.capacity() != 0 {
            if self.rejected_frames.len() == self.sender_errors.capacity() {
                self.rejected_frames.pop_front();
            }
            self.rejected_frames.push_back(QwpRejectedFrame {
                fsn,
                wire_seq,
                error,
            });
        }
        sender_error
    }

    fn record_reject_error(
        &mut self,
        fsn: u64,
        wire_seq: u64,
        error: QwpServerError,
        policy: QwpWsErrorPolicy,
    ) -> QwpWsSenderError {
        let sender_error = sender_error_for_qwp_error(&error, wire_seq, fsn, policy);
        self.push_sender_error(sender_error.clone());
        self.last_server_error = Some(error);
        sender_error
    }

    fn delivery_status(
        &self,
        send_cursor: &SendCursor,
        durable_ack: Option<&DurableAckTracker>,
        receipt: QwpReceipt,
    ) -> Result<Option<DeliveryOutcome>, DriverError> {
        match self.receipt_status(send_cursor, durable_ack, receipt) {
            QwpReceiptStatus::Completed { .. } => Ok(Some(DeliveryOutcome::Completed)),
            QwpReceiptStatus::Terminal { .. } => Ok(Some(DeliveryOutcome::Terminal)),
            QwpReceiptStatus::Published { .. } | QwpReceiptStatus::Sent { .. } => Ok(None),
            QwpReceiptStatus::Unknown { fsn } => Err(DriverError::UnknownReceipt { fsn }),
        }
    }

    pub(crate) fn set_closing(&mut self) {
        self.lifecycle.begin_close();
    }

    pub(crate) fn all_published_receipts_resolved(&self) -> bool {
        match self.queue.published_fsn() {
            None => true,
            Some(published_fsn) => self
                .queue
                .completed_fsn()
                .is_some_and(|completed_fsn| completed_fsn >= published_fsn),
        }
    }

    pub(crate) fn published_fsn(&self) -> Option<u64> {
        self.queue.published_fsn()
    }

    pub(crate) fn completed_fsn(&self) -> Option<u64> {
        self.queue.completed_fsn()
    }

    pub(crate) fn close_queue(&mut self) -> Result<(), DriverError> {
        self.queue.close()
    }

    pub(crate) fn record_protocol_violation(
        &mut self,
        close_code: Option<u16>,
        reason: String,
    ) -> Error {
        let from_fsn = self
            .queue
            .completed_fsn()
            .map_or(0, |fsn| fsn.saturating_add(1));
        let to_fsn = self.queue.published_fsn().unwrap_or(from_fsn).max(from_fsn);
        let message = match (close_code, reason.is_empty()) {
            (Some(close_code), true) => format!("ws-close[{close_code}]"),
            (Some(close_code), false) => format!("ws-close[{close_code}]: {reason}"),
            (None, true) => "WebSocket protocol violation".to_string(),
            (None, false) => reason,
        };
        let sender_error = QwpWsSenderError {
            category: QwpWsErrorCategory::ProtocolViolation,
            applied_policy: QwpWsErrorPolicy::Terminal,
            status: None,
            message: Some(message.clone()),
            message_sequence: None,
            from_fsn,
            to_fsn,
        };
        self.terminal_sender_error = Some(sender_error.clone());
        self.push_sender_error(sender_error.clone());
        error::fmt!(
            ServerRejection,
            "QWP/WebSocket protocol violation: {message}"
        )
        .with_qwp_ws_rejection(sender_error)
    }

    /// Terminal for a well-formed frame the server keeps rejecting without ACK
    /// progress because of its role/writability state — a read-only replica
    /// after an in-place primary→replica switch — not because the frame is
    /// malformed. Unlike [`Self::record_protocol_violation`] this is NOT a
    /// protocol violation: it is recorded under the reject's own category
    /// (`NotWritable`) and surfaced as `StoreResendRequired`, so a file-backed
    /// slot's orphan drainer (or a fresh sender) resends the affected data
    /// rather than mislabeling a graceful role switch as a wire-protocol
    /// violation.
    pub(crate) fn record_role_reject_resend(&mut self, status: u8, reason: String) -> Error {
        let from_fsn = self
            .queue
            .completed_fsn()
            .map_or(0, |fsn| fsn.saturating_add(1));
        let to_fsn = self.queue.published_fsn().unwrap_or(from_fsn).max(from_fsn);
        let sender_error = QwpWsSenderError {
            category: server_error_category(status),
            applied_policy: QwpWsErrorPolicy::Terminal,
            status: Some(status),
            message: Some(reason.clone()),
            message_sequence: None,
            from_fsn,
            to_fsn,
        };
        self.terminal_sender_error = Some(sender_error.clone());
        self.push_sender_error(sender_error.clone());
        error::fmt!(StoreResendRequired, "{reason}").with_qwp_ws_rejection(sender_error)
    }

    pub(crate) fn poll_sender_error(&mut self) -> Option<QwpWsSenderError> {
        self.sender_errors.poll()
    }

    pub(crate) fn poll_sender_error_notification(&mut self) -> Option<QwpWsSenderError> {
        self.sender_errors.poll_notification()
    }

    pub(crate) fn sender_errors_dropped_total(&self) -> u64 {
        self.sender_errors.dropped_total()
    }

    pub(crate) fn poll_event(&mut self) -> Option<DriverEvent> {
        self.events.pop()
    }

    pub(crate) fn events_dropped_total(&self) -> u64 {
        self.events.dropped_total()
    }

    pub(crate) fn terminal_error(&self) -> Option<&Error> {
        self.terminal_error.as_ref()
    }

    pub(crate) fn terminal_sender_error(&self) -> Option<&QwpWsSenderError> {
        self.terminal_sender_error.as_ref()
    }

    pub(crate) fn poll_sender_error_overlapping(
        &mut self,
        from_fsn: u64,
        to_fsn: u64,
    ) -> Option<QwpWsSenderError> {
        if let Some(error) = self.terminal_sender_error.as_ref()
            && sender_error_overlaps(error, from_fsn, to_fsn)
        {
            return Some(error.clone());
        }
        self.sender_errors.poll_overlapping(from_fsn, to_fsn)
    }

    pub(crate) fn last_server_error(&self) -> Option<&QwpServerError> {
        self.last_server_error.as_ref()
    }

    pub(crate) fn rejected_frame(&self, receipt: QwpReceipt) -> Option<&QwpRejectedFrame> {
        self.rejected_frames
            .iter()
            .find(|rejected| rejected.fsn == receipt.fsn)
    }

    fn push_event(&mut self, event: DriverEvent) {
        self.events.push(event);
    }

    fn push_sender_error(&mut self, error: QwpWsSenderError) {
        self.sender_errors.push(error);
    }
}

impl<T: QwpWsCoreTransport> QwpWsSendCore<T> {
    pub(crate) fn new(
        transport: T,
        max_in_flight: usize,
        reconnect_policy: ReconnectPolicy,
    ) -> Self {
        Self::new_with_durable_ack(transport, max_in_flight, reconnect_policy, false)
    }

    pub(crate) fn new_with_durable_ack(
        transport: T,
        max_in_flight: usize,
        reconnect_policy: ReconnectPolicy,
        durable_ack: bool,
    ) -> Self {
        Self::new_with_durable_ack_and_rejection_limit(
            transport,
            max_in_flight,
            reconnect_policy,
            durable_ack,
            DEFAULT_MAX_FRAME_REJECTIONS,
            Duration::ZERO,
        )
    }

    pub(crate) fn new_with_durable_ack_and_rejection_limit(
        transport: T,
        max_in_flight: usize,
        reconnect_policy: ReconnectPolicy,
        durable_ack: bool,
        max_frame_rejections: usize,
        poison_min_escalation_window: Duration,
    ) -> Self {
        Self {
            transport,
            send_cursor: SendCursor::new(max_in_flight),
            dict_mirror: SentDictMirror::new(false),
            catch_up_pending: false,
            durable_ack: durable_ack.then(DurableAckTracker::new),
            reconnect_policy,
            pending_reconnect: None,
            poison_tracker: PoisonFrameTracker::default(),
            max_frame_rejections,
            poison_min_escalation_window,
            sends_on_connection: 0,
        }
    }

    fn apply_response<Q: PublicationLog>(
        &mut self,
        store: &mut QwpWsPublicationStore<Q>,
        response: TransportResponse,
        defer_reconnect: bool,
    ) -> Result<DriveOutcome, DriverError> {
        match response {
            TransportResponse::Ack { wire_seq } => {
                store.counters.total_acks += 1;
                self.complete_ack_through(store, wire_seq)
            }
            TransportResponse::DurableOk {
                wire_seq,
                table_seq_txns,
            } => {
                store.counters.total_acks += 1;
                if self.durable_ack.is_some() {
                    self.apply_durable_ok(store, wire_seq, table_seq_txns)
                } else {
                    self.complete_ack_through(store, wire_seq)
                }
            }
            TransportResponse::DurableAck { table_seq_txns } => {
                store.counters.total_acks += 1;
                let Some(tracker) = self.durable_ack.as_mut() else {
                    return Ok(DriveOutcome::Idle);
                };
                tracker.apply_ack(table_seq_txns);
                self.complete_ready_durable(store)
            }
            TransportResponse::Reject { wire_seq, error } => {
                store.counters.total_server_errors += 1;
                let policy = server_error_policy(error.status);
                let Some((fsn, _effect_wire_seq)) =
                    self.send_cursor.reject_fsn_for_wire_seq(wire_seq)?
                else {
                    return self.record_presend_reject(
                        store,
                        wire_seq,
                        error,
                        policy,
                        defer_reconnect,
                    );
                };
                if self.reject_target_already_accounted(store, fsn) {
                    store.record_reject_error(fsn, wire_seq, error, policy);
                    return Ok(DriveOutcome::Idle);
                }
                if !self.reject_target_can_complete(store, fsn) {
                    let err = self.reject_gap_protocol_error(store, fsn);
                    store.last_server_error = Some(error.clone());
                    store.mark_terminal(Some(err));
                    return Ok(DriveOutcome::Terminal);
                }

                if policy == QwpWsErrorPolicy::Terminal {
                    let sender_error =
                        store.record_reject_error(fsn, wire_seq, error.clone(), policy);
                    store.terminal_sender_error = Some(sender_error.clone());
                    store.mark_terminal(Some(server_rejection_error(
                        error.error.clone(),
                        sender_error,
                    )));
                    return Ok(DriveOutcome::Terminal);
                }

                if self.rejected_head_is_poison(store, fsn) {
                    let strikes = self.poison_tracker.strikes();
                    let reason = if error.message.is_empty() {
                        format!(
                            "QWP/WebSocket frame fsn {fsn} was rejected {strikes} times without ACK progress"
                        )
                    } else {
                        format!(
                            "QWP/WebSocket frame fsn {fsn} was rejected {} times without ACK \
                             progress; last server error: {}",
                            strikes, error.message
                        )
                    };
                    let status = error.status;
                    store.last_server_error = Some(error);
                    // A read-only/role reject (RetriableOther, e.g. a replica
                    // after an in-place role switch) is not a protocol
                    // violation: the frame is well-formed, the server just will
                    // not take it while read-only. Terminalize it as "resend
                    // required" under its own category so a file-backed slot's
                    // orphan drainer resends it, instead of mislabeling a
                    // graceful role switch as a wire-protocol violation.
                    let err = if policy == QwpWsErrorPolicy::RetriableOther {
                        store.record_role_reject_resend(status, reason)
                    } else {
                        store.record_protocol_violation(None, reason)
                    };
                    store.mark_terminal(Some(err));
                    return Ok(DriveOutcome::Terminal);
                }

                let error_for_reconnect = error.error.clone();
                let reconnect_reason = reconnect_reason_for_policy(policy);
                let pace = self.reconnect_pace_for_reject_policy(policy);
                let sender_error = store.record_rejected_frame(fsn, wire_seq, error, policy);
                store.push_event(DriverEvent::Rejected { fsn, wire_seq });
                let initial_error = server_rejection_error(error_for_reconnect, sender_error);
                self.pending_reconnect = Some(
                    self.begin_reconnect(
                        "QWP/WebSocket reconnect after server rejection",
                        reconnect_reason,
                        initial_error,
                    )
                    .with_pace(pace),
                );
                self.continue_or_defer_reconnect(store, defer_reconnect)
            }
        }
    }

    fn reject_target_already_accounted<Q: PublicationLog>(
        &self,
        store: &QwpWsPublicationStore<Q>,
        fsn: u64,
    ) -> bool {
        self.durable_ack
            .as_ref()
            .is_some_and(|tracker| tracker.pending_wire_seq_for_fsn(fsn).is_some())
            || store
                .queue
                .completed_fsn()
                .is_some_and(|completed_fsn| fsn <= completed_fsn)
    }

    fn reject_target_can_complete<Q: PublicationLog>(
        &self,
        store: &QwpWsPublicationStore<Q>,
        fsn: u64,
    ) -> bool {
        let Some(oldest) = store.queue.oldest_unresolved_fsn() else {
            return false;
        };
        if fsn == oldest {
            return true;
        }
        self.durable_ack
            .as_ref()
            .is_some_and(|tracker| tracker.pending_prefix_covers(oldest, fsn))
    }

    fn reject_gap_protocol_error<Q: PublicationLog>(
        &self,
        store: &mut QwpWsPublicationStore<Q>,
        fsn: u64,
    ) -> Error {
        let oldest = store.queue.oldest_unresolved_fsn();
        store.record_protocol_violation(
            None,
            match oldest {
                Some(oldest) => format!(
                    "QWP/WebSocket reject response for fsn {fsn} skipped unresolved fsn {oldest}"
                ),
                None => {
                    format!("QWP/WebSocket reject response for fsn {fsn} has no unresolved frame")
                }
            },
        )
    }

    fn rejected_head_is_poison<Q: PublicationLog>(
        &mut self,
        store: &QwpWsPublicationStore<Q>,
        fsn: u64,
    ) -> bool {
        if store.queue.oldest_unresolved_fsn() != Some(fsn) {
            return false;
        }
        let now = Instant::now();
        self.poison_tracker.record_failure(
            fsn,
            store.queue.completed_fsn(),
            self.max_frame_rejections,
            self.poison_min_escalation_window,
            now,
        )
    }

    fn record_presend_reject<Q: PublicationLog>(
        &mut self,
        store: &mut QwpWsPublicationStore<Q>,
        wire_seq: u64,
        error: QwpServerError,
        policy: QwpWsErrorPolicy,
        defer_reconnect: bool,
    ) -> Result<DriveOutcome, DriverError> {
        let from_fsn = store
            .queue
            .completed_fsn()
            .map_or(0, |fsn| fsn.saturating_add(1));
        let to_fsn = store
            .queue
            .published_fsn()
            .unwrap_or(from_fsn)
            .max(from_fsn);
        let sender_error =
            sender_error_for_qwp_error_span(&error, wire_seq, from_fsn, to_fsn, policy);
        if policy == QwpWsErrorPolicy::Terminal {
            store.terminal_sender_error = Some(sender_error.clone());
            store.push_sender_error(sender_error.clone());
            store.last_server_error = Some(error.clone());
            store.mark_terminal(Some(server_rejection_error(
                error.error.clone(),
                sender_error,
            )));
            Ok(DriveOutcome::Terminal)
        } else {
            // A Retriable presend reject carries no FSN -- most commonly the server
            // rejecting the table-less symbol-dictionary catch-up frame a reconnect
            // emits before replaying the queued frames (e.g. a read-only replica
            // after an in-place role switch). It still has to be bounded: the
            // transport reconnect itself succeeds (the server accepts the
            // connection, it just rejects the catch-up), so the reconnect retry
            // budget -- which only counts failed dials -- never trips, and without
            // escalation a server that persistently rejects the catch-up would
            // reconnect-loop forever, masking a permanent failure as a hang until
            // the caller's own deadline. Attribute it to the oldest unresolved
            // frame (the one the catch-up exists to unblock) and run it through the
            // same poison tracker as a real-frame reject, so repeated no-progress
            // rejects escalate to a loud terminal ("resend required") after
            // max_frame_rejections while a transient/role reject still failovers.
            if let Some(oldest) = store.queue.oldest_unresolved_fsn()
                && self.rejected_head_is_poison(store, oldest)
            {
                let strikes = self.poison_tracker.strikes();
                let reason = if error.message.is_empty() {
                    format!(
                        "QWP/WebSocket symbol-dictionary catch-up before fsn {oldest} was \
                         rejected {strikes} times without progress"
                    )
                } else {
                    format!(
                        "QWP/WebSocket symbol-dictionary catch-up before fsn {oldest} was \
                         rejected {} times without progress; last server error: {}",
                        strikes, error.message
                    )
                };
                let status = error.status;
                store.push_sender_error(sender_error);
                store.last_server_error = Some(error);
                // See `handle_reject`: a role/read-only catch-up reject is
                // "resend required", not a protocol violation.
                let err = if policy == QwpWsErrorPolicy::RetriableOther {
                    store.record_role_reject_resend(status, reason)
                } else {
                    store.record_protocol_violation(None, reason)
                };
                store.mark_terminal(Some(err));
                return Ok(DriveOutcome::Terminal);
            }
            let initial_error = server_rejection_error(error.error.clone(), sender_error.clone());
            store.push_sender_error(sender_error);
            store.last_server_error = Some(error);
            let pace = self.reconnect_pace_for_reject_policy(policy);
            self.pending_reconnect = Some(
                self.begin_reconnect(
                    "QWP/WebSocket reconnect after server rejection",
                    reconnect_reason_for_policy(policy),
                    initial_error,
                )
                .with_pace(pace),
            );
            self.continue_or_defer_reconnect(store, defer_reconnect)
        }
    }

    fn reconnect_pace_for_reject_policy(&self, policy: QwpWsErrorPolicy) -> Duration {
        if policy == QwpWsErrorPolicy::Retriable {
            self.reconnect_pace_for_strikes(self.poison_tracker.strikes().max(1))
        } else {
            Duration::ZERO
        }
    }

    fn reconnect_pace_for_strikes(&self, strikes: usize) -> Duration {
        let dose = pace_dose(
            self.reconnect_policy.initial_backoff,
            self.reconnect_policy.max_backoff,
            strikes,
        );
        pace_jitter_duration(dose)
    }

    fn complete_ack_through<Q: PublicationLog>(
        &mut self,
        store: &mut QwpWsPublicationStore<Q>,
        wire_seq: u64,
    ) -> Result<DriveOutcome, DriverError> {
        let Some((fsn, ack_wire_seq)) = self.send_cursor.ack_fsn_for_wire_seq(wire_seq)? else {
            return Ok(DriveOutcome::Idle);
        };
        self.complete_through(store, fsn, ack_wire_seq)
    }

    fn apply_durable_ok<Q: PublicationLog>(
        &mut self,
        store: &mut QwpWsPublicationStore<Q>,
        wire_seq: u64,
        table_seq_txns: Vec<TableSeqTxn>,
    ) -> Result<DriveOutcome, DriverError> {
        let Some((fsn, ack_wire_seq)) = self.send_cursor.ack_fsn_for_wire_seq(wire_seq)? else {
            return Ok(DriveOutcome::Idle);
        };
        if self
            .durable_ack
            .as_ref()
            .is_some_and(|tracker| tracker.pending_wire_seq_for_fsn(fsn).is_some())
        {
            self.send_cursor.ack_through(fsn);
            return Ok(DriveOutcome::Idle);
        }
        if store
            .queue
            .completed_fsn()
            .is_some_and(|completed_fsn| fsn <= completed_fsn)
        {
            self.send_cursor.ack_through(fsn);
            return Ok(DriveOutcome::Acked {
                wire_seq: ack_wire_seq,
            });
        }
        self.send_cursor.ack_through(fsn);
        let tracker = self.durable_ack.as_mut().expect("durable ACK mode");
        tracker.enqueue_ok(ack_wire_seq, fsn, table_seq_txns);
        self.complete_ready_durable(store)
    }

    fn complete_ready_durable<Q: PublicationLog>(
        &mut self,
        store: &mut QwpWsPublicationStore<Q>,
    ) -> Result<DriveOutcome, DriverError> {
        let mut highest_resolved_wire_seq = None;
        while let Some(resolved) = self
            .durable_ack
            .as_mut()
            .and_then(DurableAckTracker::pop_ready)
        {
            self.complete_through(store, resolved.fsn, resolved.wire_seq)?;
            highest_resolved_wire_seq = Some(resolved.wire_seq);
        }
        Ok(
            highest_resolved_wire_seq.map_or(DriveOutcome::Idle, |wire_seq| DriveOutcome::Acked {
                wire_seq,
            }),
        )
    }

    fn complete_through<Q: PublicationLog>(
        &mut self,
        store: &mut QwpWsPublicationStore<Q>,
        fsn: u64,
        wire_seq: u64,
    ) -> Result<DriveOutcome, DriverError> {
        let progress = store.progress_view();
        let advanced = progress
            .complete_through_fsn(fsn)
            .map_err(DriverError::from)?;
        self.send_cursor.ack_through(fsn);
        if advanced {
            self.poison_tracker.clear();
            store.record_completed_through_event(fsn, wire_seq);
        }
        Ok(DriveOutcome::Acked { wire_seq })
    }

    pub(crate) fn next_outbound_sfa_frame(
        &mut self,
        progress: &SfaProgressView,
    ) -> Result<Option<OutboundFrame>, DriverError> {
        progress.next_outbound_frame(&mut self.send_cursor)
    }

    pub(crate) fn send_frame(
        &mut self,
        outbound: OutboundFrame,
    ) -> (SentFrame, Result<TransportSendResult, TransportFailure>) {
        let frame = outbound.sent_frame();
        self.sends_on_connection = self.sends_on_connection.saturating_add(1);
        // Split borrows so the mirror can capture the payload alongside the
        // transport. `accumulate` is a no-op in full-dict mode.
        let transport = &mut self.transport;
        let dict_mirror = &mut self.dict_mirror;
        let result = outbound.with_view(|view| {
            let payload = view.payload;
            let sent = transport.send_frame(view);
            if sent.is_ok() {
                // The frame's delta is on the wire; mirror the symbols it
                // introduced so a later reconnect can re-register them.
                dict_mirror.accumulate(payload);
            }
            sent
        });
        (frame, result)
    }

    /// Torn-dictionary guard, checked just before a store-and-forward frame is
    /// sent. A replayed delta frame whose base (`delta_start`) exceeds the symbols
    /// the mirror has re-registered on this connection references dictionary
    /// entries a host/power crash tore away from the side-file (and that no
    /// surviving earlier frame carries): the frame is unrecoverable, so fail
    /// loudly rather than send the server a frame it cannot decode. `Ok(())` for
    /// non-dict frames and self-sufficient (base-0) frames.
    pub(crate) fn guard_dict_not_torn(&self, payload: &[u8]) -> Result<(), Error> {
        let Some(delta_start) = frame_delta_start(payload) else {
            return Ok(()); // not a delta-dict frame -> nothing to re-register
        };
        if !self.dict_mirror.is_enabled() {
            // Full-dict (dense) mode: every legitimate frame re-ships its whole
            // dictionary from id 0 and is self-sufficient (`delta_start == 0`). A
            // base above 0 with the mirror disabled means either the foreground
            // encoder emitted delta while the driver mirror stayed dense (a lockstep
            // wiring bug) or a delta-encoded slot was reopened with delta disabled
            // (e.g. its side-file could not be opened) -- in both cases no catch-up
            // will re-register ids [0, delta_start), so replaying the frame would
            // corrupt the server dictionary. Fail loud rather than send it.
            if delta_start > 0 {
                return Err(error::fmt!(
                    StoreResendRequired,
                    "QWP/WebSocket store-and-forward: a stored frame bases at symbol \
                     id {} but delta symbol-dictionary mode is disabled on this \
                     connection, so the dictionary it depends on cannot be \
                     re-registered; the affected data must be resent",
                    delta_start
                ));
            }
            return Ok(());
        }
        let registered = u64::from(self.dict_mirror.count());
        if delta_start > registered {
            return Err(error::fmt!(
                StoreResendRequired,
                "QWP/WebSocket store-and-forward symbol dictionary is torn: a stored \
                 frame references symbol id {} but only {} dictionary entries were \
                 recovered (a host crash lost entries the frame depends on); the \
                 affected data must be resent",
                delta_start,
                registered
            ));
        }
        // Overlap without a gap: the frame re-registers ids the mirror already
        // holds. That is a benign replay only if the symbols MATCH. The foreground
        // dict is append-only, so a *differing* redefinition of an already-mirrored
        // id can only mean the recovered history and the queued frames disagree (a
        // host crash that tore the side-file so its recovered entries desynced from
        // a later frame that reused those ids). `accumulate` would keep the stale
        // mapping (it drops fully-overlapping regions), so the reconnect catch-up
        // would re-register the wrong symbol and mis-decode later delta-less
        // references -- silent corruption. Reject it as torn instead.
        if self.dict_mirror.conflicts_with(payload) {
            return Err(error::fmt!(
                StoreResendRequired,
                "QWP/WebSocket store-and-forward symbol dictionary is torn: a stored \
                 frame redefines an already-registered symbol id to a different \
                 symbol (the recovered dictionary disagrees with the queued frames, \
                 most often a host crash that tore the side-file); the affected data \
                 must be resent"
            ));
        }
        Ok(())
    }

    /// Enables delta symbol-dict mode on this connection's send loop and seeds
    /// the catch-up mirror from a recovered persisted dictionary (`seed_entries`
    /// = the concatenated `[len][utf8]` region in id order, `seed_count`
    /// entries). Called once at construction by the store when the slot's mode
    /// supports delta (memory always; file iff the persisted dict opened). Pass
    /// `(&[], 0)` to enable without a recovered dictionary (fresh memory-mode).
    ///
    /// A non-empty seed means this is a file-mode recovery / orphan-drain: the
    /// queued frames are mid-stream deltas that reference a dictionary the fresh
    /// server has never seen, so arm the catch-up to re-register it before the
    /// first replay — exactly as [`Self::finish_reconnect_success`] does on a
    /// reconnect. Without this, the initial connect replays a `delta_start > 0`
    /// frame against an empty server dictionary (undecodable / silent
    /// corruption). Redundant-but-safe when nothing was acked (seed count 0
    /// stays disarmed; a seed covering already-registered ids reproduces the
    /// tested reconnect-with-nothing-acked overlap case).
    pub(crate) fn enable_delta_dict(&mut self, seed_entries: &[u8], seed_count: u32) {
        self.dict_mirror = SentDictMirror::new(true);
        self.dict_mirror.seed(seed_entries, seed_count);
        self.catch_up_pending = !self.dict_mirror.is_empty();
    }

    /// Sends the full-dictionary catch-up frame(s) on the freshly reconnected
    /// transport — split so none exceeds the server's batch cap — and returns how
    /// many were sent (they consume wire seqs `[0, n)`). The caller then calls
    /// [`SendCursor::begin_catch_up`] so the queued replay frames map onto
    /// `fsn_at_zero`. Only invoked when the mirror is enabled and non-empty.
    fn emit_dict_catch_up(&mut self) -> Result<u64, DictCatchUpError> {
        let cap = self.transport.server_max_batch_size();
        let version = self.transport.negotiated_qwp_version();
        // Stream the catch-up frame(s): build, send, drop each before the next, so
        // only one frame is resident rather than a second copy of the whole
        // dictionary -- even on a flapping connection that repeats the catch-up on
        // every reconnect.
        let transport = &mut self.transport;
        let mut wire_seq = 0u64;
        self.dict_mirror
            .for_each_catch_up_frame(cap, version, |frame_bytes| {
                // A catch-up frame carries no FSN; the transport only reads
                // `payload` and correlates acks by `wire_seq`, so seqs [0, n) keep
                // the FIFO ack stream aligned (their acks resolve to no real FSN --
                // see `SendCursor::ack_fsn_for_wire_seq`).
                let view = OutboundFrameView {
                    fsn: 0,
                    wire_seq,
                    payload: frame_bytes,
                };
                wire_seq += 1;
                transport.send_frame(view).map(|_| ())
            })
            .map_err(|e| match e {
                CatchUpStreamError::EntryTooLarge(e) => DictCatchUpError::EntryTooLarge(e),
                CatchUpStreamError::Emit(failure) => DictCatchUpError::Transport(failure),
            })
    }

    /// If a reconnect armed the symbol-dict catch-up, emit the catch-up frame(s)
    /// and set up the cursor; otherwise a no-op. Shared by the manual send path
    /// ([`Self::drive_send_available`]) and the background runner's send loop, so
    /// both re-register the whole dictionary before replaying delta frames. A
    /// transport drop means reconnect again; an oversized entry is terminal.
    pub(crate) fn drive_catch_up(&mut self) -> Result<(), CatchUpDriveError> {
        if !self.catch_up_pending {
            return Ok(());
        }
        self.catch_up_pending = false;
        match self.emit_dict_catch_up() {
            Ok(catch_up_frames) => {
                self.send_cursor.begin_catch_up(catch_up_frames);
                Ok(())
            }
            Err(DictCatchUpError::Transport(failure)) => Err(CatchUpDriveError::Transport(failure)),
            Err(DictCatchUpError::EntryTooLarge(e)) => {
                // Decided entirely client-side from the server's advertised batch
                // cap -- nothing was sent back -- so this is `BatchTooLarge` (the
                // same code the foreground uses for a frame that overflows the cap
                // in publish_chunk_sfa / publish_arrow_sfa), not `ServerFlushError`
                // ("error sent back from the server").
                //
                // The foreground marks this terminal (the caller learns at once to
                // resend / investigate), whereas an orphan drainer maps the same
                // condition to RetryLater. The asymmetry is intentional and does not
                // abandon data: `mark_terminal` only records the error -- it never
                // deletes the slot's segments or side-file -- so a disk slot's queued
                // frames stay on disk and a later orphan drain / borrow re-attempts
                // them, giving a failover to a larger-cap endpoint another chance. (A
                // single symbol larger than a server's batch cap -- caps are MBs,
                // symbols tiny -- is essentially unreachable in practice.)
                Err(CatchUpDriveError::Terminal(error::fmt!(
                    BatchTooLarge,
                    "QWP/WebSocket symbol dictionary entry ({} bytes) exceeds the server \
                 batch cap ({} bytes) during reconnect catch-up; cannot re-register \
                 the dictionary -- resend required",
                    e.entry_bytes,
                    e.budget
                )))
            }
        }
    }

    pub(crate) fn finish_send_result<Q: PublicationLog>(
        &mut self,
        store: &mut QwpWsPublicationStore<Q>,
        frame: SentFrame,
        send_result: TransportSendResult,
    ) -> Result<QwpWsSendProgress, DriverError> {
        match self.finish_send_result_hot(frame, send_result)? {
            QwpWsHotSendProgress::NoResponse { frame } => {
                store.record_sent_event(frame);
                Ok(QwpWsSendProgress::Outcome(DriveOutcome::Sent(frame)))
            }
            QwpWsHotSendProgress::Response { frame, response } => {
                store.record_sent_event(frame);
                self.apply_response(store, response, false)
                    .map(QwpWsSendProgress::Outcome)
            }
            QwpWsHotSendProgress::TransportFailure { frame, failure } => {
                store.record_sent_event(frame);
                Ok(QwpWsSendProgress::TransportFailure(failure))
            }
        }
    }

    pub(crate) fn finish_send_result_hot(
        &mut self,
        frame: SentFrame,
        send_result: TransportSendResult,
    ) -> Result<QwpWsHotSendProgress, DriverError> {
        self.send_cursor.commit_sent(frame)?;
        match send_result {
            TransportSendResult::NoResponse => Ok(QwpWsHotSendProgress::NoResponse { frame }),
            TransportSendResult::Response(response) => {
                Ok(QwpWsHotSendProgress::Response { frame, response })
            }
            TransportSendResult::Failure(failure) => {
                Ok(QwpWsHotSendProgress::TransportFailure { frame, failure })
            }
        }
    }

    pub(crate) fn try_poll_response(&mut self) -> Result<TransportPoll, TransportFailure> {
        self.transport.try_poll_response()
    }

    pub(crate) fn send_durable_ack_keepalive_if_due(
        &mut self,
        durable_ack_pending: bool,
    ) -> Result<bool, TransportFailure> {
        self.transport
            .send_durable_ack_keepalive_if_due(durable_ack_pending)
    }

    pub(crate) fn finish_response<Q: PublicationLog>(
        &mut self,
        store: &mut QwpWsPublicationStore<Q>,
        response: TransportResponse,
    ) -> Result<DriveOutcome, DriverError> {
        self.apply_response(store, response, false)
    }

    pub(crate) fn finish_response_defer_reconnect<Q: PublicationLog>(
        &mut self,
        store: &mut QwpWsPublicationStore<Q>,
        response: TransportResponse,
    ) -> Result<DriveOutcome, DriverError> {
        self.apply_response(store, response, true)
    }

    pub(crate) fn finish_ack_response_sfa(
        &mut self,
        progress: &SfaProgressView,
        wire_seq: u64,
    ) -> Result<QwpWsHotResponseProgress, DriverError> {
        let Some((fsn, ack_wire_seq)) = self.send_cursor.ack_fsn_for_wire_seq(wire_seq)? else {
            return Ok(QwpWsHotResponseProgress::idle());
        };
        let advanced = progress
            .complete_through_fsn(fsn)
            .map_err(DriverError::from)?;
        self.send_cursor.ack_through(fsn);
        if advanced {
            self.poison_tracker.clear();
        }
        let event = advanced.then_some(DriverEvent::CompletedThrough {
            fsn,
            wire_seq: ack_wire_seq,
        });
        Ok(QwpWsHotResponseProgress::from_optional_event(
            DriveOutcome::Acked {
                wire_seq: ack_wire_seq,
            },
            event,
        )
        .with_ok_fsn(fsn))
    }

    pub(crate) fn finish_durable_ok_response_sfa(
        &mut self,
        progress: &SfaProgressView,
        wire_seq: u64,
        table_seq_txns: Vec<TableSeqTxn>,
    ) -> Result<QwpWsHotResponseProgress, DriverError> {
        if self.durable_ack.is_none() {
            return self.finish_ack_response_sfa(progress, wire_seq);
        }

        let Some((fsn, ack_wire_seq)) = self.send_cursor.ack_fsn_for_wire_seq(wire_seq)? else {
            return Ok(QwpWsHotResponseProgress::idle());
        };
        if self
            .durable_ack
            .as_ref()
            .is_some_and(|tracker| tracker.pending_wire_seq_for_fsn(fsn).is_some())
        {
            self.send_cursor.ack_through(fsn);
            return Ok(QwpWsHotResponseProgress::idle().with_ok_fsn(fsn));
        }
        if progress
            .completed_fsn()
            .is_some_and(|completed_fsn| fsn <= completed_fsn)
        {
            self.send_cursor.ack_through(fsn);
            return Ok(QwpWsHotResponseProgress {
                outcome: DriveOutcome::Acked {
                    wire_seq: ack_wire_seq,
                },
                events: Vec::new(),
                ok_fsn: Some(fsn),
            });
        }

        self.send_cursor.ack_through(fsn);
        let tracker = self.durable_ack.as_mut().expect("durable ACK mode");
        tracker.enqueue_ok(ack_wire_seq, fsn, table_seq_txns);
        Ok(self.complete_ready_durable_sfa(progress)?.with_ok_fsn(fsn))
    }

    pub(crate) fn finish_durable_ack_response_sfa(
        &mut self,
        progress: &SfaProgressView,
        table_seq_txns: Vec<TableSeqTxn>,
    ) -> Result<QwpWsHotResponseProgress, DriverError> {
        let Some(tracker) = self.durable_ack.as_mut() else {
            return Ok(QwpWsHotResponseProgress::idle());
        };
        tracker.apply_ack(table_seq_txns);
        self.complete_ready_durable_sfa(progress)
    }

    fn complete_ready_durable_sfa(
        &mut self,
        progress: &SfaProgressView,
    ) -> Result<QwpWsHotResponseProgress, DriverError> {
        let mut highest_resolved_wire_seq = None;
        let mut events = Vec::new();
        while let Some(resolved) = self
            .durable_ack
            .as_mut()
            .and_then(DurableAckTracker::pop_ready)
        {
            let advanced = progress
                .complete_through_fsn(resolved.fsn)
                .map_err(DriverError::from)?;
            self.send_cursor.ack_through(resolved.fsn);
            if advanced {
                self.poison_tracker.clear();
                events.push(DriverEvent::CompletedThrough {
                    fsn: resolved.fsn,
                    wire_seq: resolved.wire_seq,
                });
            }
            highest_resolved_wire_seq = Some(resolved.wire_seq);
        }
        Ok(QwpWsHotResponseProgress {
            outcome: highest_resolved_wire_seq.map_or(DriveOutcome::Idle, |wire_seq| {
                DriveOutcome::Acked { wire_seq }
            }),
            events,
            ok_fsn: None,
        })
    }

    pub(crate) fn receipt_status<Q: PublicationLog>(
        &self,
        store: &QwpWsPublicationStore<Q>,
        receipt: QwpReceipt,
    ) -> QwpReceiptStatus {
        store.receipt_status(&self.send_cursor, self.durable_ack.as_ref(), receipt)
    }

    pub(crate) fn delivery_status<Q: PublicationLog>(
        &self,
        store: &QwpWsPublicationStore<Q>,
        receipt: QwpReceipt,
    ) -> Result<Option<DeliveryOutcome>, DriverError> {
        store.delivery_status(&self.send_cursor, self.durable_ack.as_ref(), receipt)
    }

    pub(crate) fn has_pending_durable_ack(&self) -> bool {
        self.durable_ack
            .as_ref()
            .is_some_and(DurableAckTracker::has_pending)
    }

    pub(crate) fn transport_failure_action<Q: PublicationLog>(
        &mut self,
        store: &mut QwpWsPublicationStore<Q>,
        failure: TransportFailure,
    ) -> QwpWsTransportFailureAction {
        match failure {
            TransportFailure::Disconnect(initial_error) => QwpWsTransportFailureAction::Reconnect {
                reason: ReconnectReason::Disconnect,
                initial_error,
                pace: Duration::ZERO,
            },
            TransportFailure::ServerClose(initial_error) => {
                if self.sends_on_connection == 0 {
                    return QwpWsTransportFailureAction::Reconnect {
                        reason: ReconnectReason::Disconnect,
                        initial_error,
                        pace: Duration::ZERO,
                    };
                }
                if let Some(error) = self.server_close_poison_error(store) {
                    store.mark_terminal(Some(error.clone()));
                    QwpWsTransportFailureAction::Terminal(error)
                } else {
                    let pace = self.reconnect_pace_for_strikes(self.poison_tracker.strikes());
                    QwpWsTransportFailureAction::Reconnect {
                        reason: ReconnectReason::Disconnect,
                        initial_error,
                        pace,
                    }
                }
            }
            TransportFailure::Retryable(initial_error) => QwpWsTransportFailureAction::Reconnect {
                reason: ReconnectReason::RetryableFailure,
                initial_error,
                pace: Duration::ZERO,
            },
            TransportFailure::Terminal(error) => {
                store.mark_terminal(Some(error.clone()));
                QwpWsTransportFailureAction::Terminal(error)
            }
            TransportFailure::ProtocolViolation { close_code, reason } => {
                let error = store.record_protocol_violation(close_code, reason);
                store.mark_terminal(Some(error.clone()));
                QwpWsTransportFailureAction::Terminal(error)
            }
        }
    }

    fn server_close_poison_error<Q: PublicationLog>(
        &mut self,
        store: &mut QwpWsPublicationStore<Q>,
    ) -> Option<Error> {
        let fsn = store.queue.oldest_unresolved_fsn()?;
        let now = Instant::now();
        if self.poison_tracker.record_failure(
            fsn,
            store.queue.completed_fsn(),
            self.max_frame_rejections,
            self.poison_min_escalation_window,
            now,
        ) {
            let strikes = self.poison_tracker.strikes();
            return Some(store.record_protocol_violation(
                None,
                format!(
                    "QWP/WebSocket frame fsn {fsn} was closed {strikes} times without ACK progress"
                ),
            ));
        }
        None
    }

    pub(crate) fn restart_connection(
        &mut self,
        reason: ReconnectReason,
    ) -> Result<(), DriverError> {
        self.transport.restart_connection(reason)
    }

    pub(crate) fn begin_reconnect(
        &self,
        context: &'static str,
        reason: ReconnectReason,
        initial_error: Error,
    ) -> QwpWsReconnectState {
        QwpWsReconnectState::new(self.reconnect_policy, context, reason, initial_error)
    }

    pub(crate) fn has_pending_reconnect(&self) -> bool {
        self.pending_reconnect.is_some()
    }

    pub(crate) fn take_pending_reconnect(&mut self) -> Option<QwpWsReconnectState> {
        self.pending_reconnect.take()
    }

    pub(crate) fn reconnect_once(
        &mut self,
        reconnect: &mut QwpWsReconnectState,
    ) -> Result<QwpWsReconnectStep, DriverError> {
        if reconnect.deadline_expired() {
            return Ok(QwpWsReconnectStep::Terminal(
                reconnect.retry_budget_exhausted_error(),
            ));
        }

        reconnect.attempts += 1;
        match self.restart_connection(reconnect.reason) {
            Ok(()) => Ok(QwpWsReconnectStep::Reconnected {
                reason: reconnect.reason,
            }),
            Err(err) => match reconnect_attempt_error(err) {
                Ok(err) if reconnect_error_is_terminal(&err) => {
                    Ok(QwpWsReconnectStep::Terminal(err))
                }
                Ok(err) => {
                    let sleep_for = reconnect.record_retryable_error(err);
                    Ok(QwpWsReconnectStep::RetryAfter { sleep_for })
                }
                Err(err) => Err(err),
            },
        }
    }

    pub(crate) fn finish_reconnect_success<Q: PublicationLog>(
        &mut self,
        store: &mut QwpWsPublicationStore<Q>,
        reason: ReconnectReason,
    ) -> DriveOutcome {
        self.pending_reconnect = None;
        self.sends_on_connection = 0;
        self.send_cursor.restart(&store.queue);
        if self.durable_ack.is_some() {
            store.clear_unresolved_rejected_frames();
        }
        if let Some(tracker) = self.durable_ack.as_mut() {
            tracker.reset();
        }
        // Delta mode: the fresh server's dictionary is empty. Arm the catch-up so
        // the next send iteration re-registers the whole dictionary before the
        // queued delta frames (which reference ids above 0) replay.
        self.catch_up_pending = self.dict_mirror.is_enabled() && !self.dict_mirror.is_empty();
        store.counters.total_reconnects_succeeded += 1;
        store.push_event(DriverEvent::Reconnected { reason });
        DriveOutcome::Reconnected { reason }
    }

    fn continue_or_defer_reconnect<Q: PublicationLog>(
        &mut self,
        store: &mut QwpWsPublicationStore<Q>,
        defer_reconnect: bool,
    ) -> Result<DriveOutcome, DriverError> {
        if defer_reconnect {
            let deadline = self
                .pending_reconnect
                .as_ref()
                .and_then(QwpWsReconnectState::deadline);
            Ok(DriveOutcome::ReconnectDelay {
                sleep_for: Duration::ZERO,
                deadline,
            })
        } else {
            self.continue_reconnect(store)
        }
    }

    fn continue_reconnect<Q: PublicationLog>(
        &mut self,
        store: &mut QwpWsPublicationStore<Q>,
    ) -> Result<DriveOutcome, DriverError> {
        let Some(mut reconnect) = self.pending_reconnect.take() else {
            return Ok(DriveOutcome::Idle);
        };
        if let Some(sleep_for) = reconnect.take_first_attempt_pace() {
            let deadline = reconnect.deadline();
            self.pending_reconnect = Some(reconnect);
            return Ok(DriveOutcome::ReconnectDelay {
                sleep_for,
                deadline,
            });
        }
        // Mirrors the background runner's pre-attempt bump in
        // reconnect_with_policy so manual-mode drivers expose the same
        // cumulative counter.
        store.record_reconnect_attempt();
        match self.reconnect_once(&mut reconnect)? {
            QwpWsReconnectStep::Reconnected { reason } => {
                Ok(self.finish_reconnect_success(store, reason))
            }
            QwpWsReconnectStep::RetryAfter { sleep_for } => {
                let deadline = reconnect.deadline();
                self.pending_reconnect = Some(reconnect);
                Ok(DriveOutcome::ReconnectDelay {
                    sleep_for,
                    deadline,
                })
            }
            QwpWsReconnectStep::Terminal(error) => {
                if reconnect_error_is_terminal(&error) {
                    store.mark_terminal(Some(error));
                    Ok(DriveOutcome::Terminal)
                } else {
                    let sleep_for = reconnect.policy.initial_backoff();
                    let next = QwpWsReconnectState::new(
                        reconnect.policy,
                        reconnect.context,
                        reconnect.reason,
                        error,
                    );
                    let deadline = next.deadline();
                    self.pending_reconnect = Some(next);
                    Ok(DriveOutcome::ReconnectDelay {
                        sleep_for,
                        deadline,
                    })
                }
            }
        }
    }

    pub(crate) fn drive_once<Q: PublicationLog>(
        &mut self,
        store: &mut QwpWsPublicationStore<Q>,
    ) -> Result<DriveOutcome, DriverError> {
        if store.is_terminal() {
            return Ok(DriveOutcome::Terminal);
        }
        if self.pending_reconnect.is_some() {
            return self.continue_reconnect(store);
        }

        let mut outcome = DriveOutcome::Idle;
        if let Some(send_outcome) = self.drive_send_available(store)? {
            if drive_outcome_stops_tick(send_outcome) {
                return Ok(send_outcome);
            }
            if send_outcome != DriveOutcome::Idle {
                outcome = send_outcome;
            }
        }

        let receive = self.drive_receive_ready_until_idle(store)?;
        if drive_outcome_stops_tick(receive) {
            return Ok(receive);
        }
        if receive != DriveOutcome::Idle
            && (outcome == DriveOutcome::Idle || receive != DriveOutcome::Progress)
        {
            outcome = receive;
        }

        if self.drive_storage_once(store)? && outcome == DriveOutcome::Idle {
            outcome = DriveOutcome::Progress;
        }

        if outcome == DriveOutcome::Idle {
            outcome = self.drive_durable_ack_keepalive_once(store)?;
        }
        Ok(outcome)
    }

    pub(crate) fn close_drain_ready_once<Q: PublicationLog>(
        &mut self,
        store: &mut QwpWsPublicationStore<Q>,
    ) -> Result<CloseOutcome, DriverError> {
        store.set_closing();

        if store.is_terminal() {
            return Ok(CloseOutcome::Terminal);
        }
        if store.all_published_receipts_resolved() {
            store.close_queue()?;
            return Ok(CloseOutcome::Drained);
        }
        match self.drive_once(store)? {
            DriveOutcome::Terminal => return Ok(CloseOutcome::Terminal),
            DriveOutcome::ReconnectDelay {
                sleep_for,
                deadline,
            } => {
                return Ok(CloseOutcome::Waiting {
                    sleep_for,
                    deadline,
                });
            }
            _ => {}
        }

        if store.is_terminal() {
            Ok(CloseOutcome::Terminal)
        } else if store.all_published_receipts_resolved() {
            store.close_queue()?;
            Ok(CloseOutcome::Drained)
        } else {
            Ok(CloseOutcome::Timeout)
        }
    }

    pub(crate) fn close_drain_ready_step<Q: PublicationLog>(
        &mut self,
        store: &mut QwpWsPublicationStore<Q>,
    ) -> Result<CloseStepOutcome, DriverError> {
        store.set_closing();

        if store.is_terminal() {
            return Ok(CloseStepOutcome::Terminal);
        }
        if store.all_published_receipts_resolved() {
            store.close_queue()?;
            return Ok(CloseStepOutcome::Drained);
        }

        let outcome = self.drive_once(store)?;
        match outcome {
            DriveOutcome::Terminal => return Ok(CloseStepOutcome::Terminal),
            DriveOutcome::ReconnectDelay {
                sleep_for,
                deadline,
            } => {
                return Ok(CloseStepOutcome::Waiting {
                    sleep_for,
                    deadline,
                });
            }
            _ => {}
        }
        if store.is_terminal() {
            return Ok(CloseStepOutcome::Terminal);
        }
        if store.all_published_receipts_resolved() {
            store.close_queue()?;
            return Ok(CloseStepOutcome::Drained);
        }
        if outcome == DriveOutcome::Idle {
            Ok(CloseStepOutcome::Idle)
        } else {
            Ok(CloseStepOutcome::Progress)
        }
    }

    pub(crate) fn drive_storage_once<Q: PublicationLog>(
        &mut self,
        store: &mut QwpWsPublicationStore<Q>,
    ) -> Result<bool, DriverError> {
        let Some(step) = store.take_storage_maintenance_step()? else {
            return Ok(false);
        };
        let changed_before_io = step.changes_queue_before_io();
        let result = step.perform()?;
        let finish = store.finish_storage_maintenance(result)?;
        let changed = changed_before_io || finish.did_change();
        if let Some(cleanup) = finish.into_cleanup()
            && let Some(failure) = cleanup.perform()
        {
            store.record_storage_cleanup_failure(failure)?;
        }
        Ok(changed)
    }

    pub(crate) fn drive_send_once<Q: PublicationLog>(
        &mut self,
        store: &mut QwpWsPublicationStore<Q>,
    ) -> Result<DriveOutcome, DriverError> {
        if store.is_terminal() {
            return Ok(DriveOutcome::Terminal);
        }
        if self.pending_reconnect.is_some() {
            return self.continue_reconnect(store);
        }

        Ok(self
            .drive_send_available(store)?
            .unwrap_or(DriveOutcome::Idle))
    }

    pub(crate) fn drive_receive_once<Q: PublicationLog>(
        &mut self,
        store: &mut QwpWsPublicationStore<Q>,
    ) -> Result<DriveOutcome, DriverError> {
        if store.is_terminal() {
            return Ok(DriveOutcome::Terminal);
        }
        if self.pending_reconnect.is_some() {
            return self.continue_reconnect(store);
        }

        let response = self.try_poll_response();
        match response {
            Ok(TransportPoll::Response(response)) => self.finish_polled_response(store, response),
            Ok(TransportPoll::Progress) => Ok(DriveOutcome::Progress),
            Ok(TransportPoll::Idle) => Ok(DriveOutcome::Idle),
            Err(failure) => self.apply_transport_failure(store, failure),
        }
    }

    fn drive_receive_ready_until_idle<Q: PublicationLog>(
        &mut self,
        store: &mut QwpWsPublicationStore<Q>,
    ) -> Result<DriveOutcome, DriverError> {
        if store.is_terminal() {
            return Ok(DriveOutcome::Terminal);
        }
        if self.pending_reconnect.is_some() {
            return self.continue_reconnect(store);
        }

        let mut outcome = DriveOutcome::Idle;
        loop {
            match self.try_poll_response() {
                Ok(TransportPoll::Response(response)) => {
                    let response_outcome = self.finish_polled_response(store, response)?;
                    if response_outcome == DriveOutcome::Terminal {
                        return Ok(response_outcome);
                    }
                    if response_outcome != DriveOutcome::Idle {
                        outcome = response_outcome;
                    }
                }
                Ok(TransportPoll::Progress) => {
                    if outcome == DriveOutcome::Idle {
                        outcome = DriveOutcome::Progress;
                    }
                }
                Ok(TransportPoll::Idle) => return Ok(outcome),
                Err(failure) => return self.apply_transport_failure(store, failure),
            }
        }
    }

    fn finish_polled_response<Q: PublicationLog>(
        &mut self,
        store: &mut QwpWsPublicationStore<Q>,
        response: TransportResponse,
    ) -> Result<DriveOutcome, DriverError> {
        let outcome = self.finish_response(store, response)?;
        Ok(if outcome == DriveOutcome::Idle {
            DriveOutcome::Progress
        } else {
            outcome
        })
    }

    fn drive_durable_ack_keepalive_once<Q: PublicationLog>(
        &mut self,
        store: &mut QwpWsPublicationStore<Q>,
    ) -> Result<DriveOutcome, DriverError> {
        let durable_ack_pending = self.has_pending_durable_ack();
        match self.send_durable_ack_keepalive_if_due(durable_ack_pending) {
            Ok(true) | Ok(false) => Ok(DriveOutcome::Idle),
            Err(failure) => self.apply_transport_failure(store, failure),
        }
    }

    fn drive_send_available<Q: PublicationLog>(
        &mut self,
        store: &mut QwpWsPublicationStore<Q>,
    ) -> Result<Option<DriveOutcome>, DriverError> {
        match self.drive_catch_up() {
            Ok(()) => {}
            Err(CatchUpDriveError::Transport(failure)) => {
                return Ok(Some(self.apply_transport_failure(store, failure)?));
            }
            Err(CatchUpDriveError::Terminal(err)) => {
                store.mark_terminal(Some(err));
                return Ok(Some(DriveOutcome::Terminal));
            }
        }
        let progress = store.progress_view();
        let Some(outbound) = self.next_outbound_sfa_frame(&progress)? else {
            return Ok(None);
        };
        if let Err(err) = outbound.with_view(|view| self.guard_dict_not_torn(view.payload)) {
            store.mark_terminal(Some(err));
            return Ok(Some(DriveOutcome::Terminal));
        }

        let (frame, send_result) = self.send_frame(outbound);
        let send_result = match send_result {
            Ok(result) => result,
            Err(failure) => {
                return Ok(Some(self.apply_transport_failure(store, failure)?));
            }
        };
        match self.finish_send_result(store, frame, send_result)? {
            QwpWsSendProgress::Outcome(outcome) => Ok(Some(outcome)),
            QwpWsSendProgress::TransportFailure(failure) => {
                Ok(Some(self.apply_transport_failure(store, failure)?))
            }
        }
    }

    fn apply_transport_failure<Q: PublicationLog>(
        &mut self,
        store: &mut QwpWsPublicationStore<Q>,
        failure: TransportFailure,
    ) -> Result<DriveOutcome, DriverError> {
        match self.transport_failure_action(store, failure) {
            QwpWsTransportFailureAction::Reconnect {
                reason,
                initial_error,
                pace,
            } => {
                self.pending_reconnect = Some(
                    self.begin_reconnect("QWP/WebSocket reconnect", reason, initial_error)
                        .with_pace(pace),
                );
                self.continue_reconnect(store)
            }
            QwpWsTransportFailureAction::Terminal(error) => {
                self.pending_reconnect = None;
                store.mark_terminal(Some(error));
                Ok(DriveOutcome::Terminal)
            }
        }
    }
}

#[cfg(test)]
impl QwpWsCoreTestHarness<SfaFrameQueue, FakeOrderedServer> {
    pub(crate) fn new(
        options: SfaMemoryQueueOptions,
        server: FakeOrderedServer,
    ) -> Result<Self, DriverError> {
        let queue = SfaFrameQueue::open_memory(options)?;
        let max_in_flight = queue.max_in_flight();
        Ok(Self {
            store: QwpWsPublicationStore::new(queue, DEFAULT_EVENT_CAPACITY),
            send_core: QwpWsSendCore::new(
                server,
                max_in_flight,
                ReconnectPolicy::no_backoff(Duration::MAX),
            ),
        })
    }
}

#[cfg(test)]
impl<Q: PublicationLog, T: QwpWsCoreTransport> QwpWsCoreTestHarness<Q, T> {
    pub(crate) fn from_queue(queue: Q, transport: T) -> Self {
        let max_in_flight = queue.max_in_flight();
        Self {
            store: QwpWsPublicationStore::new(queue, DEFAULT_EVENT_CAPACITY),
            send_core: QwpWsSendCore::new(
                transport,
                max_in_flight,
                ReconnectPolicy::no_backoff(Duration::MAX),
            ),
        }
    }

    pub(crate) fn from_queue_with_reconnect_policy(
        queue: Q,
        transport: T,
        reconnect_policy: ReconnectPolicy,
        durable_ack: bool,
    ) -> Self {
        let max_in_flight = queue.max_in_flight();
        Self {
            store: QwpWsPublicationStore::new(queue, DEFAULT_EVENT_CAPACITY),
            send_core: QwpWsSendCore::new_with_durable_ack(
                transport,
                max_in_flight,
                reconnect_policy,
                durable_ack,
            ),
        }
    }

    pub(crate) fn from_queue_with_rejection_limit_and_window(
        queue: Q,
        transport: T,
        max_frame_rejections: usize,
        poison_min_escalation_window: Duration,
    ) -> Self {
        let max_in_flight = queue.max_in_flight();
        Self {
            store: QwpWsPublicationStore::new(queue, DEFAULT_EVENT_CAPACITY),
            send_core: QwpWsSendCore::new_with_durable_ack_and_rejection_limit(
                transport,
                max_in_flight,
                ReconnectPolicy::no_backoff(Duration::MAX),
                false,
                max_frame_rejections,
                poison_min_escalation_window,
            ),
        }
    }

    pub(crate) fn from_queue_with_event_capacity(
        queue: Q,
        transport: T,
        event_capacity: usize,
    ) -> Self {
        let max_in_flight = queue.max_in_flight();
        Self {
            store: QwpWsPublicationStore::new(queue, event_capacity),
            send_core: QwpWsSendCore::new(
                transport,
                max_in_flight,
                ReconnectPolicy::no_backoff(Duration::MAX),
            ),
        }
    }

    fn from_queue_with_durable_ack(queue: Q, transport: T) -> Self {
        let max_in_flight = queue.max_in_flight();
        Self {
            store: QwpWsPublicationStore::new(queue, DEFAULT_EVENT_CAPACITY),
            send_core: QwpWsSendCore::new_with_durable_ack(
                transport,
                max_in_flight,
                ReconnectPolicy::no_backoff(Duration::MAX),
                true,
            ),
        }
    }

    pub(crate) fn try_submit(&mut self, payload: &[u8]) -> Result<QwpReceipt, DriverError> {
        self.store.try_submit(payload)
    }

    pub(crate) fn set_closing(&mut self) {
        self.store.set_closing();
    }

    pub(crate) fn submit_with_drive_limit(
        &mut self,
        payload: &[u8],
        max_drive_steps: usize,
    ) -> Result<QwpReceipt, DriverError> {
        let mut drive_steps = 0;
        loop {
            if self.store.is_terminal() {
                return Err(DriverError::Terminal);
            }
            match self.store.try_submit(payload) {
                Ok(receipt) => return Ok(receipt),
                Err(DriverError::Queue(
                    QueueError::FrameCapacityFull { .. }
                    | QueueError::ByteCapacityFull { .. }
                    | QueueError::MaxInFlightReached { .. }
                    | QueueError::StorageSpareNotReady { .. }
                    | QueueError::StorageSegmentCapFull { .. },
                )) if drive_steps < max_drive_steps => {
                    self.drive_once()?;
                    drive_steps += 1;
                }
                Err(DriverError::Queue(
                    err @ (QueueError::FrameCapacityFull { .. }
                    | QueueError::ByteCapacityFull { .. }
                    | QueueError::MaxInFlightReached { .. }
                    | QueueError::StorageSpareNotReady { .. }
                    | QueueError::StorageSegmentCapFull { .. }),
                )) => {
                    return Err(DriverError::SubmitTimedOut {
                        backpressure: Some(err),
                    });
                }
                Err(
                    err @ (DriverError::Queue(
                        QueueError::InvalidCapacity
                        | QueueError::EmptyPayload
                        | QueueError::PayloadExceedsByteCapacity { .. }
                        | QueueError::NoUnsentFrame
                        | QueueError::ProtocolAckWithoutConnection
                        | QueueError::ProtocolAckBeyondSent { .. }
                        | QueueError::ProtocolAckedUnsentFrame { .. }
                        | QueueError::ProtocolRejectWithoutConnection
                        | QueueError::ProtocolRejectBeyondSent { .. }
                        | QueueError::ProtocolRejectedUnsentFrame { .. }
                        | QueueError::OutboundFrameUnavailable { .. }
                        | QueueError::SequenceOverflow,
                    )
                    | DriverError::Transport(_)
                    | DriverError::Storage(_)
                    | DriverError::SubmitTimedOut { .. }
                    | DriverError::Terminal
                    | DriverError::Closing
                    | DriverError::UnknownReceipt { .. }),
                ) => return Err(err),
            }
        }
    }

    pub(crate) fn submit_with_drive_deadline(
        &mut self,
        payload: &[u8],
        append_deadline: Duration,
    ) -> Result<QwpReceipt, DriverError> {
        let deadline = Instant::now().checked_add(append_deadline);
        loop {
            if self.store.is_terminal() {
                return Err(DriverError::Terminal);
            }
            match self.store.try_submit(payload) {
                Ok(receipt) => return Ok(receipt),
                Err(err) => {
                    let Some(backpressure) = driver_backpressure_queue(&err) else {
                        return Err(err);
                    };
                    if drive_deadline_expired(deadline) {
                        return Err(DriverError::SubmitTimedOut {
                            backpressure: Some(backpressure),
                        });
                    }
                    if self.drive_once()? == DriveOutcome::Idle {
                        sleep_until_drive_deadline(deadline);
                    }
                }
            }
        }
    }

    pub(crate) fn drive_once(&mut self) -> Result<DriveOutcome, DriverError> {
        self.send_core.drive_once(&mut self.store)
    }

    pub(crate) fn drive_send_once(&mut self) -> Result<DriveOutcome, DriverError> {
        self.send_core.drive_send_once(&mut self.store)
    }

    pub(crate) fn drive_receive_once(&mut self) -> Result<DriveOutcome, DriverError> {
        self.send_core.drive_receive_once(&mut self.store)
    }

    /// Reads the receipt's current delivery state without driving the transport.
    pub(crate) fn delivery_status(
        &self,
        receipt: QwpReceipt,
    ) -> Result<Option<DeliveryOutcome>, DriverError> {
        self.send_core.delivery_status(&self.store, receipt)
    }

    pub(crate) fn close_drain_steps(
        &mut self,
        max_drive_steps: usize,
    ) -> Result<CloseOutcome, DriverError> {
        self.store.set_closing();

        for _ in 0..max_drive_steps {
            if self.store.is_terminal() {
                return Ok(CloseOutcome::Terminal);
            }
            if self.store.all_published_receipts_resolved() {
                self.store.close_queue()?;
                return Ok(CloseOutcome::Drained);
            }
            if self.drive_once()? == DriveOutcome::Terminal {
                return Ok(CloseOutcome::Terminal);
            }
        }

        if self.store.is_terminal() {
            Ok(CloseOutcome::Terminal)
        } else if self.store.all_published_receipts_resolved() {
            self.store.close_queue()?;
            Ok(CloseOutcome::Drained)
        } else {
            Ok(CloseOutcome::Timeout)
        }
    }

    pub(crate) fn close_drain_ready_once(&mut self) -> Result<CloseOutcome, DriverError> {
        self.send_core.close_drain_ready_once(&mut self.store)
    }

    pub(crate) fn close_drain_ready_step(&mut self) -> Result<CloseStepOutcome, DriverError> {
        self.send_core.close_drain_ready_step(&mut self.store)
    }

    pub(crate) fn receipt_status(&self, receipt: QwpReceipt) -> QwpReceiptStatus {
        self.send_core.receipt_status(&self.store, receipt)
    }

    pub(crate) fn poll_event(&mut self) -> Option<DriverEvent> {
        self.store.poll_event()
    }

    pub(crate) fn events_dropped_total(&self) -> u64 {
        self.store.events_dropped_total()
    }

    pub(crate) fn terminal_error(&self) -> Option<&Error> {
        self.store.terminal_error()
    }

    pub(crate) fn terminal_sender_error(&self) -> Option<&QwpWsSenderError> {
        self.store.terminal_sender_error()
    }

    pub(crate) fn published_fsn(&self) -> Option<u64> {
        self.store.queue.published_fsn()
    }

    pub(crate) fn acked_fsn(&self) -> Option<u64> {
        self.store.queue.completed_fsn()
    }

    pub(crate) fn poll_sender_error(&mut self) -> Option<QwpWsSenderError> {
        self.store.poll_sender_error()
    }

    pub(crate) fn poll_sender_error_notification(&mut self) -> Option<QwpWsSenderError> {
        self.store.poll_sender_error_notification()
    }

    pub(crate) fn sender_errors_dropped_total(&self) -> u64 {
        self.store.sender_errors_dropped_total()
    }

    pub(crate) fn counters(&self) -> QwpWsCounters {
        self.store.counters()
    }

    pub(crate) fn last_server_error(&self) -> Option<&QwpServerError> {
        self.store.last_server_error()
    }

    pub(crate) fn rejected_frame(&self, receipt: QwpReceipt) -> Option<&QwpRejectedFrame> {
        self.store.rejected_frame(receipt)
    }

    pub(crate) fn is_terminal(&self) -> bool {
        self.store.is_terminal()
    }

    pub(crate) fn into_parts(self) -> (QwpWsPublicationStore<Q>, QwpWsSendCore<T>) {
        (self.store, self.send_core)
    }
}

pub(super) fn reconnect_attempt_error(err: DriverError) -> Result<Error, DriverError> {
    match err {
        DriverError::Transport(err) | DriverError::Storage(err) => Ok(err),
        err => Err(err),
    }
}

pub(crate) fn reconnect_error_is_terminal(err: &Error) -> bool {
    if is_qwp_ws_role_reject_error(err) {
        return false;
    }
    matches!(
        err.code(),
        ErrorCode::AuthError
            | ErrorCode::ConfigError
            | ErrorCode::ProtocolVersionError
            | ErrorCode::StoreResendRequired
    )
}

pub(super) fn is_qwp_ws_role_reject_error(err: &Error) -> bool {
    err.qwp_ws_role_reject().is_some()
}

fn reconnect_deadline_expired(deadline: Option<Instant>) -> bool {
    deadline.is_some_and(|deadline| Instant::now() >= deadline)
}

fn double_duration(duration: Duration) -> Duration {
    duration.checked_mul(2).unwrap_or(Duration::MAX)
}

fn pace_dose(initial_backoff: Duration, max_backoff: Duration, strikes: usize) -> Duration {
    if initial_backoff.is_zero() {
        return Duration::ZERO;
    }
    let shift = strikes.max(1).saturating_sub(1).min(6) as u32;
    initial_backoff
        .checked_mul(1u32 << shift)
        .unwrap_or(Duration::MAX)
        .min(max_backoff)
}

#[cfg(feature = "sync-sender-qwp-ws")]
fn pace_jitter_duration(dose: Duration) -> Duration {
    let dose_nanos = dose.as_nanos().min(u128::from(u64::MAX)) as u64;
    if dose_nanos == 0 {
        return dose;
    }
    let extra = rand::rng().random_range(0..dose_nanos);
    Duration::from_nanos(dose_nanos.saturating_add(extra))
}

#[cfg(not(feature = "sync-sender-qwp-ws"))]
fn pace_jitter_duration(dose: Duration) -> Duration {
    dose
}

#[cfg(feature = "sync-sender-qwp-ws")]
fn centered_jitter_duration(base: Duration) -> Duration {
    let base_nanos = base.as_nanos().min(u128::from(u64::MAX)) as u64;
    if base_nanos == 0 {
        return base;
    }
    // Centered jitter: a half-backoff floor plus a uniform draw over a full
    // backoff -> sleep in [base/2, 3*base/2), centered on `base`. Scatters
    // retries around the target delay (sometimes sooner, sometimes later) and
    // decorrelates concurrent reconnects. Egress failover uses full jitter
    // (failover.md §3.1); the two schemes are intentionally separate.
    let extra = rand::rng().random_range(0..base_nanos);
    Duration::from_nanos((base_nanos / 2).saturating_add(extra))
}

#[cfg(not(feature = "sync-sender-qwp-ws"))]
fn centered_jitter_duration(base: Duration) -> Duration {
    base
}

pub(super) fn reconnect_sleep_duration(
    role_reject: bool,
    initial_backoff: Duration,
    backoff: Duration,
) -> Duration {
    if role_reject {
        initial_backoff
    } else {
        centered_jitter_duration(backoff)
    }
}

/// One reconnect backoff step for the column-sender re-borrow loop, matching the
/// row runner's discipline: returns the delay to sleep before the next attempt
/// (role-reject → fixed `initial_backoff`; else centered-jittered `backoff`) and
/// the updated `backoff` state (role-reject resets to `initial_backoff`; else
/// doubles, capped at `max_backoff`).
#[cfg(feature = "sync-sender-qwp-ws")]
pub(crate) fn reconnect_backoff_step(
    err: &Error,
    initial_backoff: Duration,
    max_backoff: Duration,
    backoff: Duration,
) -> (Duration, Duration) {
    let role_reject = is_qwp_ws_role_reject_error(err);
    let sleep_for = reconnect_sleep_duration(role_reject, initial_backoff, backoff);
    let next_backoff = if role_reject {
        initial_backoff
    } else {
        double_duration(backoff).min(max_backoff)
    };
    (sleep_for, next_backoff)
}

pub(super) fn retry_budget_exhausted_error(
    context: &str,
    attempts: usize,
    started: Instant,
    last_error: Option<Error>,
) -> Error {
    let elapsed_ms = started.elapsed().as_millis();
    let code = last_error
        .as_ref()
        .map_or(ErrorCode::SocketError, |err| err.code());
    let last_error_msg = last_error
        .as_ref()
        .map_or_else(|| "none".to_string(), |err| err.msg().to_string());
    let qwp_ws_rejection = last_error
        .as_ref()
        .and_then(|err| err.qwp_ws_rejection().cloned());
    let qwp_ws_role_reject = last_error
        .as_ref()
        .and_then(|err| err.qwp_ws_role_reject().cloned());

    let mut err = Error::new(
        code,
        format!(
            "{context} retry budget exhausted [attempts={attempts}, elapsed_ms={elapsed_ms}, last_error={last_error_msg}]"
        ),
    );
    if let Some(rejection) = qwp_ws_rejection {
        err = err.with_qwp_ws_rejection(rejection);
    }
    if let Some(role_reject) = qwp_ws_role_reject {
        err = err.with_qwp_ws_role_reject(role_reject);
    }
    err
}

pub(crate) trait PublicationLog {
    fn try_publish(&mut self, payload: &[u8]) -> Result<QwpReceipt, DriverError>;
    fn take_producer(&mut self) -> Option<SfaProducer> {
        None
    }
    fn progress_view(&self) -> SfaProgressView;
    fn take_storage_maintenance_step(
        &mut self,
        _allow_create: bool,
    ) -> Result<Option<SfaStorageStep>, DriverError> {
        Ok(None)
    }
    fn finish_storage_maintenance(
        &mut self,
        _result: SfaStorageResult,
        _allow_install: bool,
    ) -> Result<SfaStorageFinish, DriverError> {
        Ok(SfaStorageFinish::unchanged())
    }
    fn record_storage_cleanup_failure(
        &mut self,
        _failure: SfaCleanupFailure,
    ) -> Result<(), DriverError> {
        Ok(())
    }
    fn oldest_unresolved_fsn(&self) -> Option<u64>;
    fn persist_completed_fsn(&mut self, _fsn: u64) {}
    fn close(&mut self) -> Result<(), DriverError> {
        Ok(())
    }
    fn receipt_status(&self, receipt: QwpReceipt) -> QwpReceiptStatus;
    fn published_fsn(&self) -> Option<u64>;
    fn completed_fsn(&self) -> Option<u64>;
    fn max_in_flight(&self) -> usize;
}

#[derive(Debug)]
pub(crate) struct SendCursor {
    max_in_flight: usize,
    fsn_at_zero: Option<u64>,
    next_fsn: Option<u64>,
    next_wire_seq: u64,
    /// Number of out-of-band symbol-dict catch-up frames prepended on the
    /// current connection. They occupy wire seqs `[0, catch_up_offset)`; real
    /// replay frames start at `catch_up_offset` and map to `fsn_at_zero` onward.
    /// 0 whenever no catch-up was sent (always, in full-dict mode), so the
    /// mapping is unchanged there. Reset by [`Self::restart`].
    catch_up_offset: u64,
    last_sent_wire_seq: Option<u64>,
    in_flight: VecDeque<SentFrame>,
    sfa_cursor: Option<SfaSendCursor>,
}

impl SendCursor {
    fn new(max_in_flight: usize) -> Self {
        Self {
            max_in_flight,
            fsn_at_zero: None,
            next_fsn: None,
            next_wire_seq: 0,
            catch_up_offset: 0,
            last_sent_wire_seq: None,
            in_flight: VecDeque::new(),
            sfa_cursor: None,
        }
    }

    pub(crate) fn sfa_cursor_mut(&mut self) -> &mut Option<SfaSendCursor> {
        &mut self.sfa_cursor
    }

    pub(crate) fn peek_next_frame_from_oldest(
        &mut self,
        oldest_unresolved_fsn: Option<u64>,
    ) -> Result<Option<(u64, u64)>, DriverError> {
        if self.in_flight.len() >= self.max_in_flight {
            return Ok(None);
        }

        let fsn = match self.next_fsn {
            Some(fsn) => fsn,
            None => {
                let Some(fsn) = oldest_unresolved_fsn else {
                    return Ok(None);
                };
                self.fsn_at_zero = Some(fsn);
                self.next_fsn = Some(fsn);
                fsn
            }
        };

        Ok(Some((fsn, self.next_wire_seq)))
    }

    fn commit_sent(&mut self, frame: SentFrame) -> Result<(), DriverError> {
        if self.in_flight.len() >= self.max_in_flight {
            return Err(DriverError::Queue(QueueError::MaxInFlightReached {
                max_in_flight: self.max_in_flight,
            }));
        }
        if self.next_fsn != Some(frame.fsn) || self.next_wire_seq != frame.wire_seq {
            return Err(DriverError::Queue(QueueError::OutboundFrameUnavailable {
                fsn: frame.fsn,
                wire_seq: frame.wire_seq,
            }));
        }

        self.next_fsn = Some(
            frame
                .fsn
                .checked_add(1)
                .ok_or(DriverError::Queue(QueueError::SequenceOverflow))?,
        );
        self.next_wire_seq = self
            .next_wire_seq
            .checked_add(1)
            .ok_or(DriverError::Queue(QueueError::SequenceOverflow))?;
        self.last_sent_wire_seq = Some(frame.wire_seq);
        self.in_flight.push_back(frame);
        Ok(())
    }

    fn reject_fsn_for_wire_seq(&self, wire_seq: u64) -> Result<Option<(u64, u64)>, DriverError> {
        let Some(fsn_at_zero) = self.fsn_at_zero else {
            return Ok(None);
        };
        let Some(last_sent_wire_seq) = self.last_sent_wire_seq else {
            return Ok(None);
        };
        let effect_wire_seq = wire_seq.min(last_sent_wire_seq);
        let Some(real_delta) = effect_wire_seq.checked_sub(self.catch_up_offset) else {
            return Ok(None); // a catch-up frame; no real FSN to resolve
        };
        let fsn = fsn_at_zero
            .checked_add(real_delta)
            .ok_or(DriverError::Queue(QueueError::SequenceOverflow))?;
        Ok(Some((fsn, effect_wire_seq)))
    }

    fn ack_fsn_for_wire_seq(&self, wire_seq: u64) -> Result<Option<(u64, u64)>, DriverError> {
        let Some(fsn_at_zero) = self.fsn_at_zero else {
            return Ok(None);
        };
        let Some(last_sent_wire_seq) = self.last_sent_wire_seq else {
            return Ok(None);
        };
        let ack_wire_seq = wire_seq.min(last_sent_wire_seq);
        // Catch-up frames occupy wire seqs [0, catch_up_offset); their acks map to
        // no real FSN (a harmless no-op — nothing to complete). Real replay frames
        // start at catch_up_offset and map onto fsn_at_zero.
        let Some(real_delta) = ack_wire_seq.checked_sub(self.catch_up_offset) else {
            return Ok(None);
        };
        let fsn = fsn_at_zero
            .checked_add(real_delta)
            .ok_or(DriverError::Queue(QueueError::SequenceOverflow))?;
        Ok(Some((fsn, ack_wire_seq)))
    }

    fn ack_through(&mut self, acked_fsn: u64) {
        while self
            .in_flight
            .front()
            .is_some_and(|frame| frame.fsn <= acked_fsn)
        {
            self.in_flight.pop_front();
        }
    }

    fn restart<Q: PublicationLog>(&mut self, log: &Q) {
        self.in_flight.clear();
        self.fsn_at_zero = log.oldest_unresolved_fsn();
        self.next_fsn = self.fsn_at_zero;
        self.next_wire_seq = 0;
        self.catch_up_offset = 0;
        self.last_sent_wire_seq = None;
        self.sfa_cursor = None;
    }

    /// Records that `catch_up_frames` out-of-band symbol-dict catch-up frames
    /// were sent on the fresh connection ahead of the queued replay frames. The
    /// wire seqs they occupy (`[0, catch_up_frames)`) map to no real FSN, and the
    /// first replay frame lands at `fsn_at_zero`. Must be called immediately
    /// after [`Self::restart`], before any real frame is sent.
    fn begin_catch_up(&mut self, catch_up_frames: u64) {
        self.catch_up_offset = catch_up_frames;
        self.next_wire_seq = catch_up_frames;
    }

    fn wire_seq_for_fsn(&self, fsn: u64) -> Option<u64> {
        self.in_flight
            .iter()
            .find(|frame| frame.fsn == fsn)
            .map(|frame| frame.wire_seq)
    }
}

pub(crate) trait QwpWsCoreTransport {
    fn try_poll_response(&mut self) -> Result<TransportPoll, TransportFailure>;

    fn send_durable_ack_keepalive_if_due(
        &mut self,
        _durable_ack_pending: bool,
    ) -> Result<bool, TransportFailure> {
        Ok(false)
    }

    // The outbound payload may borrow queue-owned storage and is valid only for
    // this call. Transports must write it or copy it synchronously.
    fn send_frame(
        &mut self,
        frame: OutboundFrameView<'_>,
    ) -> Result<TransportSendResult, TransportFailure>;

    fn restart_connection(&mut self, _reason: ReconnectReason) -> Result<(), DriverError> {
        Ok(())
    }

    /// The server's advertised max batch size in bytes, or 0 when the server
    /// advertised no cap. Used to split symbol-dict catch-up frames on reconnect
    /// so no single frame exceeds it. Defaults to uncapped for test transports.
    fn server_max_batch_size(&self) -> usize {
        0
    }

    /// The negotiated QWP protocol version, written into catch-up frame headers.
    /// Defaults to v1 (the only version) for test transports.
    fn negotiated_qwp_version(&self) -> u8 {
        1
    }
}

#[cfg(feature = "sync-sender-qwp-ws")]
pub(crate) struct BlockingQwpWsTransport {
    endpoints: Arc<[QwpWsEndpoint]>,
    previous_idx: Option<usize>,
    tracker: QwpWsHostHealthTracker,
    use_tls: bool,
    tls_settings: Option<TlsSettings>,
    qwp_ws: QwpWsConfig,
    auth_header: Option<String>,
    negotiated_version: u8,
    server_max_batch_size: Arc<AtomicUsize>,
    stream: WsStream,
    reader: WsFrameReader,
    send_buf: Vec<u8>,
    pending_wire_sequences: VecDeque<u64>,
    last_durable_keepalive_ping: Option<Instant>,
}

#[cfg(feature = "sync-sender-qwp-ws")]
impl BlockingQwpWsTransport {
    pub(crate) fn connect(
        host: impl Into<String>,
        port: impl Into<String>,
        use_tls: bool,
        tls_settings: Option<TlsSettings>,
        qwp_ws: QwpWsConfig,
        auth_header: Option<String>,
        server_max_batch_size: Arc<AtomicUsize>,
    ) -> crate::Result<Self> {
        let host = host.into();
        let port = port.into();
        let endpoints = qwp_ws_configured_endpoints(&host, &port, &qwp_ws);
        let mut tracker = QwpWsHostHealthTracker::new(endpoints.len());
        let mut previous_idx = None;
        let connected = connect_qwp_ws_endpoint_round(
            &endpoints,
            &mut tracker,
            &mut previous_idx,
            None,
            use_tls,
            tls_settings.clone(),
            &qwp_ws,
            auth_header.as_deref(),
        )?;
        Ok(Self::from_connected(
            endpoints,
            tracker,
            use_tls,
            tls_settings,
            qwp_ws,
            auth_header,
            server_max_batch_size,
            connected,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_connected(
        endpoints: Arc<[QwpWsEndpoint]>,
        tracker: QwpWsHostHealthTracker,
        use_tls: bool,
        tls_settings: Option<TlsSettings>,
        qwp_ws: QwpWsConfig,
        auth_header: Option<String>,
        server_max_batch_size: Arc<AtomicUsize>,
        connected: QwpWsConnectRoundSuccess,
    ) -> Self {
        server_max_batch_size.store(connected.server_max_batch_size, Ordering::Relaxed);
        Self {
            endpoints,
            previous_idx: Some(connected.endpoint_idx),
            tracker,
            use_tls,
            tls_settings,
            qwp_ws,
            auth_header,
            negotiated_version: connected.negotiated_version,
            server_max_batch_size,
            stream: connected.stream,
            reader: WsFrameReader::with_initial_input(connected.leftover),
            send_buf: Vec::with_capacity(16 * 1024),
            pending_wire_sequences: VecDeque::new(),
            last_durable_keepalive_ping: None,
        }
    }

    pub(crate) fn negotiated_version(&self) -> u8 {
        self.negotiated_version
    }

    fn reconnect(&mut self, reason: ReconnectReason) -> Result<(), DriverError> {
        let connected = connect_qwp_ws_endpoint_round(
            &self.endpoints,
            &mut self.tracker,
            &mut self.previous_idx,
            Some(reason),
            self.use_tls,
            self.tls_settings.clone(),
            &self.qwp_ws,
            self.auth_header.as_deref(),
        )
        .map_err(DriverError::Transport)?;
        self.previous_idx = Some(connected.endpoint_idx);
        self.stream = connected.stream;
        self.negotiated_version = connected.negotiated_version;
        self.server_max_batch_size
            .store(connected.server_max_batch_size, Ordering::Relaxed);
        self.reader = WsFrameReader::with_initial_input(connected.leftover);
        self.send_buf.clear();
        self.pending_wire_sequences.clear();
        self.last_durable_keepalive_ping = None;
        Ok(())
    }

    fn complete_pending_through(&mut self, sequence: u64) {
        while let Some(wire_seq) = self.pending_wire_sequences.front() {
            if *wire_seq > sequence {
                break;
            }
            self.pending_wire_sequences.pop_front();
        }
    }
}

fn decode_transport_response(
    payload: &[u8],
) -> Result<Option<TransportResponse>, TransportFailure> {
    match codec::parse_pipelined_response(payload) {
        Ok(PipelinedResponse::Ok { sequence }) => {
            Ok(Some(TransportResponse::Ack { wire_seq: sequence }))
        }
        Ok(PipelinedResponse::DurableAck) => Ok(None),
        Ok(PipelinedResponse::Error(error)) => {
            let wire_seq = error.sequence;
            let server_error = QwpServerError::from(error);
            Ok(Some(TransportResponse::Reject {
                wire_seq,
                error: server_error,
            }))
        }
        Err(err) => Err(TransportFailure::Retryable(err)),
    }
}

fn decode_durable_transport_response(
    payload: &[u8],
) -> Result<Option<TransportResponse>, TransportFailure> {
    let mut table_seq_txns = Vec::new();
    let mut handler = |_, table: &str, seq_txn| {
        table_seq_txns.push(TableSeqTxn {
            table: table.to_string(),
            seq_txn,
        });
        Ok(())
    };
    match codec::parse_pipelined_response_with_table_handler(payload, Some(&mut handler)) {
        Ok(PipelinedResponse::Ok { sequence }) => Ok(Some(TransportResponse::DurableOk {
            wire_seq: sequence,
            table_seq_txns,
        })),
        Ok(PipelinedResponse::DurableAck) => {
            Ok(Some(TransportResponse::DurableAck { table_seq_txns }))
        }
        Ok(PipelinedResponse::Error(error)) => {
            let wire_seq = error.sequence;
            let server_error = QwpServerError::from(error);
            Ok(Some(TransportResponse::Reject {
                wire_seq,
                error: server_error,
            }))
        }
        Err(err) => Err(TransportFailure::Retryable(err)),
    }
}

#[cfg(feature = "sync-sender-qwp-ws")]
impl QwpWsCoreTransport for BlockingQwpWsTransport {
    fn try_poll_response(&mut self) -> Result<TransportPoll, TransportFailure> {
        if self.pending_wire_sequences.is_empty() && !*self.qwp_ws.request_durable_ack {
            return Ok(TransportPoll::Idle);
        }
        let read = self
            .reader
            .try_read_one(&mut self.stream, &mut self.send_buf)
            .map_err(|err| match err {
                super::qwp_ws::WsMessageError::Close(close) if close.is_orderly() => {
                    TransportFailure::Disconnect(close.into_error())
                }
                super::qwp_ws::WsMessageError::Close(close) => {
                    TransportFailure::ServerClose(close.into_error())
                }
                super::qwp_ws::WsMessageError::ProtocolViolation(reason) => {
                    TransportFailure::ProtocolViolation {
                        close_code: None,
                        reason,
                    }
                }
                super::qwp_ws::WsMessageError::Error(err) => match err.code() {
                    ErrorCode::SocketError => TransportFailure::Disconnect(err),
                    ErrorCode::AuthError | ErrorCode::ProtocolVersionError => {
                        TransportFailure::Terminal(err)
                    }
                    _ => TransportFailure::Terminal(err),
                },
            })?;
        let WsFrameRead::Message { opcode } = read else {
            return Ok(match read {
                WsFrameRead::Progress => TransportPoll::Progress,
                WsFrameRead::Idle => TransportPoll::Idle,
                WsFrameRead::Message { .. } => unreachable!(),
            });
        };
        if opcode != OPCODE_BINARY {
            self.reader.clear_message();
            return Err(TransportFailure::ProtocolViolation {
                close_code: None,
                reason: "QWP/WebSocket server response was not a binary frame".to_string(),
            });
        }

        let response = if *self.qwp_ws.request_durable_ack {
            decode_durable_transport_response(self.reader.message())
        } else {
            decode_transport_response(self.reader.message())
        };
        self.reader.clear_message();
        let response = response?;
        if let Some(
            TransportResponse::Ack { wire_seq }
            | TransportResponse::DurableOk { wire_seq, .. }
            | TransportResponse::Reject { wire_seq, .. },
        ) = &response
        {
            self.complete_pending_through(*wire_seq);
        }
        Ok(match response {
            Some(response) => TransportPoll::Response(response),
            None => TransportPoll::Progress,
        })
    }

    fn send_durable_ack_keepalive_if_due(
        &mut self,
        durable_ack_pending: bool,
    ) -> Result<bool, TransportFailure> {
        if !durable_ack_pending || !*self.qwp_ws.request_durable_ack {
            return Ok(false);
        }
        let interval = *self.qwp_ws.durable_ack_keepalive_interval;
        if interval.is_zero() {
            return Ok(false);
        }
        if self
            .last_durable_keepalive_ping
            .is_some_and(|sent_at| sent_at.elapsed() < interval)
        {
            return Ok(false);
        }
        write_ping_frame(&mut self.stream, &mut self.send_buf, b"").map_err(|io| {
            TransportFailure::Disconnect(error::fmt!(
                SocketError,
                "Could not send WebSocket durable ACK keepalive PING: {}",
                io
            ))
        })?;
        self.stream.flush().map_err(|io| {
            TransportFailure::Disconnect(error::fmt!(
                SocketError,
                "Could not flush WebSocket durable ACK keepalive PING: {}",
                io
            ))
        })?;
        self.last_durable_keepalive_ping = Some(Instant::now());
        Ok(true)
    }

    fn send_frame(
        &mut self,
        frame: OutboundFrameView<'_>,
    ) -> Result<TransportSendResult, TransportFailure> {
        write_binary_frame(&mut self.stream, &mut self.send_buf, frame.payload).map_err(|io| {
            TransportFailure::Disconnect(error::fmt!(
                SocketError,
                "Could not send WebSocket frame: {}",
                io
            ))
        })?;
        self.stream.flush().map_err(|io| {
            TransportFailure::Disconnect(error::fmt!(
                SocketError,
                "Could not flush WebSocket frame: {}",
                io
            ))
        })?;
        self.pending_wire_sequences.push_back(frame.wire_seq);
        Ok(TransportSendResult::NoResponse)
    }

    fn restart_connection(&mut self, reason: ReconnectReason) -> Result<(), DriverError> {
        self.reconnect(reason)
    }

    fn server_max_batch_size(&self) -> usize {
        self.server_max_batch_size.load(Ordering::Relaxed)
    }

    fn negotiated_qwp_version(&self) -> u8 {
        self.negotiated_version
    }
}

/// Failure emitting the reconnect symbol-dict catch-up (see
/// [`QwpWsSendCore::emit_dict_catch_up`]).
enum DictCatchUpError {
    /// The transport dropped while sending a catch-up frame; recover by
    /// reconnecting again.
    Transport(TransportFailure),
    /// A single dictionary entry does not fit the server's batch cap, so the
    /// dictionary cannot be re-registered on the fresh server; terminal.
    EntryTooLarge(CatchUpEntryTooLarge),
}

/// Outcome of [`QwpWsSendCore::drive_catch_up`] that the caller must act on: a
/// transport drop (reconnect again) or a terminal error (fail the sender).
pub(crate) enum CatchUpDriveError {
    Transport(TransportFailure),
    Terminal(Error),
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum DriverError {
    Queue(QueueError),
    Transport(Error),
    Storage(Error),
    SubmitTimedOut { backpressure: Option<QueueError> },
    Terminal,
    Closing,
    UnknownReceipt { fsn: u64 },
}

impl From<QueueError> for DriverError {
    fn from(value: QueueError) -> Self {
        Self::Queue(value)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct QwpServerError {
    pub(crate) status: u8,
    pub(crate) message: String,
    pub(crate) error: Error,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct QwpRejectedFrame {
    pub(crate) fsn: u64,
    pub(crate) wire_seq: u64,
    pub(crate) error: QwpServerError,
}

impl From<codec::PipelinedError> for QwpServerError {
    fn from(value: codec::PipelinedError) -> Self {
        Self {
            status: value.status,
            message: value.message,
            error: value.err,
        }
    }
}

fn server_error_category(status: u8) -> QwpWsErrorCategory {
    match status {
        codec::WS_STATUS_SCHEMA_MISMATCH => QwpWsErrorCategory::SchemaMismatch,
        codec::WS_STATUS_PARSE_ERROR => QwpWsErrorCategory::ParseError,
        codec::WS_STATUS_INTERNAL_ERROR => QwpWsErrorCategory::InternalError,
        codec::WS_STATUS_SECURITY_ERROR => QwpWsErrorCategory::SecurityError,
        codec::WS_STATUS_WRITE_ERROR => QwpWsErrorCategory::WriteError,
        codec::WS_STATUS_NOT_WRITABLE => QwpWsErrorCategory::NotWritable,
        _ => QwpWsErrorCategory::Unknown,
    }
}

fn server_error_policy(status: u8) -> QwpWsErrorPolicy {
    match status {
        codec::WS_STATUS_WRITE_ERROR | codec::WS_STATUS_INTERNAL_ERROR => {
            QwpWsErrorPolicy::Retriable
        }
        codec::WS_STATUS_NOT_WRITABLE => QwpWsErrorPolicy::RetriableOther,
        codec::WS_STATUS_SCHEMA_MISMATCH
        | codec::WS_STATUS_PARSE_ERROR
        | codec::WS_STATUS_SECURITY_ERROR => QwpWsErrorPolicy::Terminal,
        _ => QwpWsErrorPolicy::Retriable,
    }
}

fn reconnect_reason_for_policy(policy: QwpWsErrorPolicy) -> ReconnectReason {
    match policy {
        QwpWsErrorPolicy::Retriable => ReconnectReason::RetryableFailure,
        QwpWsErrorPolicy::RetriableOther => ReconnectReason::NotWritable,
        QwpWsErrorPolicy::Terminal => ReconnectReason::RetryableFailure,
    }
}

fn sender_error_for_qwp_error(
    error: &QwpServerError,
    wire_seq: u64,
    fsn: u64,
    applied_policy: QwpWsErrorPolicy,
) -> QwpWsSenderError {
    sender_error_for_qwp_error_span(error, wire_seq, fsn, fsn, applied_policy)
}

fn sender_error_for_qwp_error_span(
    error: &QwpServerError,
    wire_seq: u64,
    from_fsn: u64,
    to_fsn: u64,
    applied_policy: QwpWsErrorPolicy,
) -> QwpWsSenderError {
    QwpWsSenderError {
        category: server_error_category(error.status),
        applied_policy,
        status: Some(error.status),
        message: (!error.message.is_empty()).then(|| error.message.clone()),
        message_sequence: Some(wire_seq),
        from_fsn,
        to_fsn,
    }
}

fn server_rejection_error(error: Error, sender_error: QwpWsSenderError) -> Error {
    Error::new(ErrorCode::ServerRejection, error.msg().to_string())
        .with_qwp_ws_rejection(sender_error)
}

#[cfg(test)]
fn fake_transport_error(message: &'static str) -> Error {
    Error::new(ErrorCode::SocketError, message)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DriveOutcome {
    Idle,
    Sent(SentFrame),
    Acked {
        wire_seq: u64,
    },
    Rejected {
        fsn: u64,
        wire_seq: u64,
    },
    Reconnected {
        reason: ReconnectReason,
    },
    ReconnectDelay {
        sleep_for: Duration,
        deadline: Option<Instant>,
    },
    Progress,
    Terminal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DriverEvent {
    Published { fsn: u64 },
    Sent { fsn: u64, wire_seq: u64 },
    CompletedThrough { fsn: u64, wire_seq: u64 },
    Rejected { fsn: u64, wire_seq: u64 },
    Reconnected { reason: ReconnectReason },
    Terminal,
}

fn drive_outcome_stops_tick(outcome: DriveOutcome) -> bool {
    matches!(
        outcome,
        DriveOutcome::Terminal | DriveOutcome::ReconnectDelay { .. }
    )
}

fn driver_backpressure_queue(err: &DriverError) -> Option<QueueError> {
    match err {
        DriverError::Queue(
            err @ (QueueError::FrameCapacityFull { .. }
            | QueueError::ByteCapacityFull { .. }
            | QueueError::MaxInFlightReached { .. }
            | QueueError::StorageSpareNotReady { .. }
            | QueueError::StorageSegmentCapFull { .. }),
        ) => Some(*err),
        _ => None,
    }
}

fn drive_deadline_expired(deadline: Option<Instant>) -> bool {
    deadline.is_some_and(|deadline| deadline <= Instant::now())
}

fn sleep_until_drive_deadline(deadline: Option<Instant>) {
    let sleep_for = match deadline {
        Some(deadline) => {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return;
            }
            remaining.min(Duration::from_millis(10))
        }
        None => Duration::from_millis(10),
    };
    std::thread::sleep(sleep_for);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReconnectReason {
    Disconnect,
    RetryableFailure,
    NotWritable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeliveryOutcome {
    Completed,
    Terminal,
    Timeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CloseOutcome {
    Drained,
    Waiting {
        sleep_for: Duration,
        deadline: Option<Instant>,
    },
    Timeout,
    Terminal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CloseStepOutcome {
    Drained,
    Terminal,
    Waiting {
        sleep_for: Duration,
        deadline: Option<Instant>,
    },
    Progress,
    Idle,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum TransportSendResult {
    NoResponse,
    Response(TransportResponse),
    Failure(TransportFailure),
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum TransportFailure {
    Disconnect(Error),
    ServerClose(Error),
    Retryable(Error),
    Terminal(Error),
    ProtocolViolation {
        close_code: Option<u16>,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum TransportPoll {
    Response(TransportResponse),
    Progress,
    Idle,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum TransportResponse {
    Ack {
        wire_seq: u64,
    },
    DurableOk {
        wire_seq: u64,
        table_seq_txns: Vec<TableSeqTxn>,
    },
    DurableAck {
        table_seq_txns: Vec<TableSeqTxn>,
    },
    Reject {
        wire_seq: u64,
        error: QwpServerError,
    },
}

#[cfg(test)]
pub(crate) type FakeServerResponse = TransportResponse;

#[derive(Debug)]
struct DriverEventRing {
    events: VecDeque<DriverEvent>,
    capacity: usize,
    dropped_total: u64,
}

#[derive(Debug)]
struct SenderErrorLog {
    errors: VecDeque<QwpWsSenderError>,
    capacity: usize,
    dropped_total: u64,
    first_seq: u64,
    next_seq: u64,
    poll_next_seq: u64,
    notification_next_seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TableSeqTxn {
    pub(crate) table: String,
    pub(crate) seq_txn: i64,
}

#[derive(Debug)]
struct DurableAckTracker {
    table_watermarks: HashMap<String, i64>,
    pending: VecDeque<PendingDurableFrame>,
}

#[derive(Debug)]
enum PendingDurableFrame {
    Ok {
        wire_seq: u64,
        fsn: u64,
        table_seq_txns: Vec<TableSeqTxn>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DurableCompletion {
    wire_seq: u64,
    fsn: u64,
}

impl DurableAckTracker {
    fn new() -> Self {
        Self {
            table_watermarks: HashMap::new(),
            pending: VecDeque::new(),
        }
    }

    fn reset(&mut self) {
        self.table_watermarks.clear();
        self.pending.clear();
    }

    fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    fn enqueue_ok(&mut self, wire_seq: u64, fsn: u64, table_seq_txns: Vec<TableSeqTxn>) {
        self.pending.push_back(PendingDurableFrame::Ok {
            wire_seq,
            fsn,
            table_seq_txns,
        });
    }

    fn apply_ack(&mut self, table_seq_txns: Vec<TableSeqTxn>) {
        for entry in table_seq_txns {
            match self.table_watermarks.get_mut(&entry.table) {
                Some(current) if entry.seq_txn > *current => {
                    *current = entry.seq_txn;
                }
                Some(_) => {}
                None => {
                    self.table_watermarks.insert(entry.table, entry.seq_txn);
                }
            }
        }
    }

    fn pending_wire_seq_for_fsn(&self, fsn: u64) -> Option<u64> {
        self.pending
            .iter()
            .find(|entry| entry.fsn() == fsn)
            .map(PendingDurableFrame::wire_seq)
    }

    fn pending_prefix_covers(&self, start_fsn: u64, end_before_fsn: u64) -> bool {
        let mut next_fsn = start_fsn;
        for entry in &self.pending {
            if next_fsn >= end_before_fsn {
                return true;
            }
            let PendingDurableFrame::Ok { fsn, .. } = entry;
            if *fsn < next_fsn {
                continue;
            }
            next_fsn = match fsn.checked_add(1) {
                Some(next_fsn) => next_fsn,
                None => return false,
            }
        }
        next_fsn >= end_before_fsn
    }

    fn pop_ready(&mut self) -> Option<DurableCompletion> {
        if !self
            .pending
            .front()
            .is_some_and(|entry| entry.is_covered_by(&self.table_watermarks))
        {
            return None;
        }
        match self.pending.pop_front().unwrap() {
            PendingDurableFrame::Ok { wire_seq, fsn, .. } => {
                Some(DurableCompletion { wire_seq, fsn })
            }
        }
    }
}

impl PendingDurableFrame {
    fn is_covered_by(&self, table_watermarks: &HashMap<String, i64>) -> bool {
        match self {
            PendingDurableFrame::Ok { table_seq_txns, .. } => table_seq_txns.iter().all(|entry| {
                table_watermarks
                    .get(&entry.table)
                    .is_some_and(|watermark| *watermark >= entry.seq_txn)
            }),
        }
    }

    fn fsn(&self) -> u64 {
        match self {
            PendingDurableFrame::Ok { fsn, .. } => *fsn,
        }
    }

    fn wire_seq(&self) -> u64 {
        match self {
            PendingDurableFrame::Ok { wire_seq, .. } => *wire_seq,
        }
    }
}

impl SenderErrorLog {
    fn new(capacity: usize) -> Self {
        Self {
            errors: VecDeque::with_capacity(capacity),
            capacity,
            dropped_total: 0,
            first_seq: 0,
            next_seq: 0,
            poll_next_seq: 0,
            notification_next_seq: 0,
        }
    }

    fn push(&mut self, error: QwpWsSenderError) {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        if self.capacity == 0 {
            self.dropped_total += 1;
            self.first_seq = self.next_seq;
            self.poll_next_seq = self.poll_next_seq.max(self.first_seq);
            self.notification_next_seq = self.notification_next_seq.max(self.first_seq);
            return;
        }
        self.discard_consumed_prefix();
        if self.errors.len() == self.capacity {
            self.errors.pop_front();
            self.first_seq = self.first_seq.saturating_add(1);
            self.dropped_total += 1;
            self.poll_next_seq = self.poll_next_seq.max(self.first_seq);
            self.notification_next_seq = self.notification_next_seq.max(self.first_seq);
        }
        debug_assert_eq!(self.first_seq + self.errors.len() as u64, seq);
        self.errors.push_back(error);
    }

    fn poll(&mut self) -> Option<QwpWsSenderError> {
        let (next_seq, error) = self.poll_at(self.poll_next_seq);
        self.poll_next_seq = next_seq;
        self.discard_consumed_prefix();
        error
    }

    fn poll_notification(&mut self) -> Option<QwpWsSenderError> {
        let (next_seq, error) = self.poll_at(self.notification_next_seq);
        self.notification_next_seq = next_seq;
        self.discard_consumed_prefix();
        error
    }

    fn poll_at(&self, mut next_seq: u64) -> (u64, Option<QwpWsSenderError>) {
        next_seq = next_seq.max(self.first_seq);
        if next_seq >= self.next_seq {
            return (next_seq, None);
        }
        let index = (next_seq - self.first_seq) as usize;
        match self.errors.get(index) {
            Some(error) => (next_seq.saturating_add(1), Some(error.clone())),
            None => (self.next_seq, None),
        }
    }

    fn poll_overlapping(&mut self, from_fsn: u64, to_fsn: u64) -> Option<QwpWsSenderError> {
        let mut next_seq = self.poll_next_seq.max(self.first_seq);
        while next_seq < self.next_seq {
            let index = (next_seq - self.first_seq) as usize;
            let Some(error) = self.errors.get(index) else {
                self.poll_next_seq = self.next_seq;
                self.discard_consumed_prefix();
                return None;
            };
            if error.from_fsn > to_fsn {
                self.poll_next_seq = next_seq;
                self.discard_consumed_prefix();
                return None;
            }

            next_seq = next_seq.saturating_add(1);
            if sender_error_overlaps(error, from_fsn, to_fsn) {
                let error = error.clone();
                self.poll_next_seq = next_seq;
                self.discard_consumed_prefix();
                return Some(error);
            }
        }

        self.poll_next_seq = next_seq;
        self.discard_consumed_prefix();
        None
    }

    fn discard_consumed_prefix(&mut self) {
        let keep_from = self.poll_next_seq.min(self.notification_next_seq);
        while self.first_seq < keep_from && !self.errors.is_empty() {
            self.errors.pop_front();
            self.first_seq = self.first_seq.saturating_add(1);
        }
    }

    fn capacity(&self) -> usize {
        self.capacity
    }

    fn dropped_total(&self) -> u64 {
        self.dropped_total
    }
}

fn sender_error_overlaps(error: &QwpWsSenderError, from_fsn: u64, to_fsn: u64) -> bool {
    error.from_fsn <= to_fsn && error.to_fsn >= from_fsn
}

impl DriverEventRing {
    fn new(capacity: usize) -> Self {
        Self {
            events: VecDeque::with_capacity(capacity),
            capacity,
            dropped_total: 0,
        }
    }

    fn push(&mut self, event: DriverEvent) {
        if self.capacity == 0 {
            self.dropped_total += 1;
            return;
        }
        if self.events.len() == self.capacity {
            self.events.pop_front();
            self.dropped_total += 1;
        }
        self.events.push_back(event);
    }

    fn pop(&mut self) -> Option<DriverEvent> {
        self.events.pop_front()
    }

    fn dropped_total(&self) -> u64 {
        self.dropped_total
    }
}

#[cfg(test)]
#[derive(Debug)]
pub(crate) struct FakeOrderedServer {
    send_results: VecDeque<FakeSendResult>,
    poll_responses: VecDeque<TransportResponse>,
    default_send_result: FakeSendResult,
    sent_frames: Vec<SentFrame>,
    sent_payloads: Vec<Vec<u8>>,
    /// Advertised max batch size in bytes (0 = uncapped), used to drive the
    /// reconnect symbol-dict catch-up frame splitting.
    server_max_batch_size: usize,
}

#[cfg(test)]
impl FakeOrderedServer {
    pub(crate) fn no_response() -> Self {
        Self::with_default(FakeSendResult::NoResponse)
    }

    pub(crate) fn ack_each_send() -> Self {
        Self::with_default(FakeSendResult::AckSent)
    }

    pub(crate) fn scripted(send_results: impl IntoIterator<Item = FakeSendResult>) -> Self {
        let mut server = Self::no_response();
        server.send_results.extend(send_results);
        server
    }

    pub(crate) fn push_response(&mut self, response: TransportResponse) {
        self.poll_responses.push_back(response);
    }

    pub(crate) fn sent_frames(&self) -> &[SentFrame] {
        &self.sent_frames
    }

    pub(crate) fn sent_payloads(&self) -> &[Vec<u8>] {
        &self.sent_payloads
    }

    /// Advertise a server batch cap (bytes) so the reconnect catch-up splits its
    /// symbol-dictionary re-registration across multiple frames (or fails when a
    /// single entry cannot fit).
    pub(crate) fn with_batch_cap(mut self, cap: usize) -> Self {
        self.server_max_batch_size = cap;
        self
    }

    fn with_default(default_send_result: FakeSendResult) -> Self {
        Self {
            send_results: VecDeque::new(),
            poll_responses: VecDeque::new(),
            default_send_result,
            sent_frames: Vec::new(),
            sent_payloads: Vec::new(),
            server_max_batch_size: 0,
        }
    }
}

#[cfg(test)]
impl QwpWsCoreTransport for FakeOrderedServer {
    fn try_poll_response(&mut self) -> Result<TransportPoll, TransportFailure> {
        Ok(self
            .poll_responses
            .pop_front()
            .map_or(TransportPoll::Idle, TransportPoll::Response))
    }

    fn send_frame(
        &mut self,
        frame: OutboundFrameView<'_>,
    ) -> Result<TransportSendResult, TransportFailure> {
        self.sent_payloads.push(frame.payload.to_vec());
        let frame = frame.sent_frame();
        let wire_seq = frame.wire_seq;
        self.sent_frames.push(frame);
        let result = self
            .send_results
            .pop_front()
            .unwrap_or(self.default_send_result);
        Ok(match result {
            FakeSendResult::NoResponse => TransportSendResult::NoResponse,
            FakeSendResult::AckSent => {
                TransportSendResult::Response(TransportResponse::Ack { wire_seq })
            }
            FakeSendResult::AckWire { wire_seq } => {
                TransportSendResult::Response(TransportResponse::Ack { wire_seq })
            }
            FakeSendResult::RejectWire { wire_seq } => {
                TransportSendResult::Response(TransportResponse::Reject {
                    wire_seq,
                    error: QwpServerError {
                        status: codec::WS_STATUS_WRITE_ERROR,
                        message: "fake write error".to_string(),
                        error: Error::new(ErrorCode::ServerFlushError, "fake write error"),
                    },
                })
            }
            FakeSendResult::RejectWireNotWritable { wire_seq } => {
                TransportSendResult::Response(TransportResponse::Reject {
                    wire_seq,
                    error: QwpServerError {
                        status: codec::WS_STATUS_NOT_WRITABLE,
                        message: "replica is read-only".to_string(),
                        error: Error::new(ErrorCode::ServerFlushError, "replica is read-only"),
                    },
                })
            }
            FakeSendResult::Disconnect => TransportSendResult::Failure(
                TransportFailure::Disconnect(fake_transport_error("fake disconnect")),
            ),
            FakeSendResult::RetryableFailure => TransportSendResult::Failure(
                TransportFailure::Retryable(fake_transport_error("fake retryable failure")),
            ),
            FakeSendResult::TerminalFailure => TransportSendResult::Failure(
                TransportFailure::Terminal(fake_transport_error("fake terminal failure")),
            ),
        })
    }

    fn server_max_batch_size(&self) -> usize {
        self.server_max_batch_size
    }
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FakeSendResult {
    NoResponse,
    AckSent,
    AckWire {
        wire_seq: u64,
    },
    RejectWire {
        wire_seq: u64,
    },
    /// A read-only / role reject (`WS_STATUS_NOT_WRITABLE`) — e.g. a replica
    /// after an in-place primary→replica switch.
    RejectWireNotWritable {
        wire_seq: u64,
    },
    Disconnect,
    RetryableFailure,
    TerminalFailure,
}

#[cfg(test)]
mod tests {
    use super::super::qwp_ws_publisher::QwpWsReplayEncoder;
    use super::*;
    use crate::ingress::buffer::{QwpWsColumnarBuffer, QwpWsEncodeScratch, SymbolGlobalDict};
    use crate::ingress::{Buffer, QwpWsErrorCategory, QwpWsErrorPolicy, TimestampNanos};

    #[test]
    fn catch_up_offset_maps_replay_acks_and_ignores_catch_up_acks() {
        let mut cursor = SendCursor::new(100);
        // Simulate a reconnect that rewound to oldest-unresolved FSN 5, then a
        // 3-frame dictionary catch-up sent ahead of the replay frames.
        cursor.fsn_at_zero = Some(5);
        cursor.next_fsn = Some(5);
        cursor.begin_catch_up(3);
        assert_eq!(
            cursor.next_wire_seq, 3,
            "replay resumes past the catch-up frames"
        );

        // Two replay frames follow the catch-up: fsn 5 @ wire 3, fsn 6 @ wire 4.
        cursor
            .commit_sent(SentFrame {
                fsn: 5,
                wire_seq: 3,
                payload_len: 0,
            })
            .unwrap();
        cursor
            .commit_sent(SentFrame {
                fsn: 6,
                wire_seq: 4,
                payload_len: 0,
            })
            .unwrap();

        // Acks for the catch-up frames (wire 0..3) resolve to no real FSN.
        assert_eq!(cursor.ack_fsn_for_wire_seq(0).unwrap(), None);
        assert_eq!(cursor.ack_fsn_for_wire_seq(2).unwrap(), None);
        // Acks for the replay frames map back onto their FSNs.
        assert_eq!(cursor.ack_fsn_for_wire_seq(3).unwrap(), Some((5, 3)));
        assert_eq!(cursor.ack_fsn_for_wire_seq(4).unwrap(), Some((6, 4)));
        // The reject path shares the mapping.
        assert_eq!(cursor.reject_fsn_for_wire_seq(1).unwrap(), None);
        assert_eq!(cursor.reject_fsn_for_wire_seq(4).unwrap(), Some((6, 4)));
    }

    #[test]
    fn no_catch_up_leaves_wire_mapping_unchanged() {
        // catch_up_offset stays 0 (full-dict mode / no reconnect catch-up), so the
        // mapping is the plain fsn_at_zero + wire_seq it always was.
        let mut cursor = SendCursor::new(100);
        cursor.fsn_at_zero = Some(10);
        cursor.next_fsn = Some(10);
        cursor
            .commit_sent(SentFrame {
                fsn: 10,
                wire_seq: 0,
                payload_len: 0,
            })
            .unwrap();
        cursor
            .commit_sent(SentFrame {
                fsn: 11,
                wire_seq: 1,
                payload_len: 0,
            })
            .unwrap();
        assert_eq!(cursor.ack_fsn_for_wire_seq(0).unwrap(), Some((10, 0)));
        assert_eq!(cursor.ack_fsn_for_wire_seq(1).unwrap(), Some((11, 1)));
    }

    fn write_frame_varint(out: &mut Vec<u8>, mut value: u64) {
        while value > 0x7F {
            out.push(((value & 0x7F) as u8) | 0x80);
            value >>= 7;
        }
        out.push(value as u8);
    }

    fn read_frame_varint(buf: &[u8], mut pos: usize) -> (u64, usize) {
        let mut value = 0u64;
        let mut shift = 0;
        loop {
            let b = buf[pos];
            pos += 1;
            value |= u64::from(b & 0x7F) << shift;
            if b & 0x80 == 0 {
                return (value, pos);
            }
            shift += 7;
        }
    }

    /// A valid QWP frame: 12-byte header (DELTA flag) + `[delta_start][count]` +
    /// `[len][utf8]` symbols + a filler byte standing in for the table block the
    /// dictionary mirror ignores.
    fn make_delta_frame(delta_start: u64, symbols: &[&[u8]]) -> Vec<u8> {
        let mut payload = Vec::new();
        write_frame_varint(&mut payload, delta_start);
        write_frame_varint(&mut payload, symbols.len() as u64);
        for s in symbols {
            write_frame_varint(&mut payload, s.len() as u64);
            payload.extend_from_slice(s);
        }
        payload.push(0xAB); // stand-in for the table block
        let mut frame = Vec::new();
        frame.extend_from_slice(b"QWP1");
        frame.push(1); // version
        frame.push(0x08); // FLAG_DELTA_SYMBOL_DICT
        frame.extend_from_slice(&1u16.to_le_bytes()); // table_count
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(&payload);
        frame
    }

    /// Asserts `frame` is a table-less full-dictionary catch-up frame carrying
    /// exactly `expected` symbols starting at id 0.
    fn assert_catch_up_frame(frame: &[u8], expected: &[&[u8]]) {
        assert_eq!(&frame[0..4], b"QWP1", "catch-up frame magic");
        assert_eq!(
            frame[5] & 0x08,
            0x08,
            "catch-up frame carries the delta flag"
        );
        assert_eq!(
            u16::from_le_bytes([frame[6], frame[7]]),
            0,
            "catch-up frame is table-less"
        );
        let (delta_start, p) = read_frame_varint(frame, 12);
        assert_eq!(delta_start, 0, "catch-up re-registers from id 0");
        let (count, mut p) = read_frame_varint(frame, p);
        assert_eq!(count as usize, expected.len(), "catch-up entry count");
        for exp in expected {
            let (len, after) = read_frame_varint(frame, p);
            let end = after + len as usize;
            assert_eq!(&frame[after..end], *exp, "catch-up entry bytes");
            p = end;
        }
        assert_eq!(p, frame.len(), "no trailing bytes after the dictionary");
    }

    #[test]
    fn reconnect_emits_full_dict_catch_up_before_replay() {
        let frame = make_delta_frame(0, &[b"AAPL", b"GOOG"]);

        let mut driver = driver(FakeOrderedServer::no_response());
        driver.send_core.enable_delta_dict(&[], 0);

        // Send the frame: the I/O-thread mirror accumulates AAPL, GOOG.
        driver.try_submit(&frame).unwrap();
        driver.drive_send_once().unwrap();
        assert_eq!(driver.send_core.dict_mirror.count(), 2);
        assert_eq!(driver.send_core.transport.sent_payloads().len(), 1);

        // The frame is unacked (NoResponse), so it stays queued for replay.
        // Simulate a successful reconnect: restart the cursor and arm the catch-up.
        let outcome = driver
            .send_core
            .finish_reconnect_success(&mut driver.store, ReconnectReason::Disconnect);
        assert!(matches!(outcome, DriveOutcome::Reconnected { .. }));
        assert!(driver.send_core.catch_up_pending);

        // The next send re-registers the whole dictionary, then replays the frame.
        driver.drive_send_once().unwrap();
        assert!(!driver.send_core.catch_up_pending, "catch-up consumed");

        let payloads = driver.send_core.transport.sent_payloads();
        // [0] = original send, [1] = catch-up (table-less full dict), [2] = replay.
        assert_eq!(payloads.len(), 3, "catch-up frame + replay emitted");
        assert_catch_up_frame(&payloads[1], &[b"AAPL", b"GOOG"]);
        assert_eq!(payloads[2], frame, "the original frame replays verbatim");
    }

    #[test]
    fn recovery_seed_emits_catch_up_on_first_connect_before_replay() {
        // Regression: a file-mode slot recovered / orphan-drained with a
        // non-empty persisted dictionary (ids 0,1 = a,b) seeds the mirror, and
        // its queued frames are mid-stream deltas (delta_start > 0). On the
        // FIRST connect to a fresh server -- with NO reconnect -- the whole
        // dictionary must be re-registered via a catch-up frame before the
        // mid-stream frame replays, or the server cannot resolve ids
        // [0, delta_start). The catch-up used to be armed only on reconnect, so
        // this path replayed a delta_start > 0 frame against an empty server
        // dictionary (undecodable / silent corruption).
        let mut driver = driver(FakeOrderedServer::no_response());
        driver.send_core.enable_delta_dict(&[1, b'a', 1, b'b'], 2);
        // Enabling with a non-empty (recovered) seed arms the catch-up up front,
        // without waiting for a reconnect.
        assert!(
            driver.send_core.catch_up_pending,
            "a recovered seed must arm the first-connect catch-up"
        );

        // A queued mid-stream frame: base id 2, introduces id 2 = "c".
        let frame = make_delta_frame(2, &[b"c"]);
        driver.try_submit(&frame).unwrap();
        driver.drive_send_once().unwrap();
        assert!(
            !driver.send_core.catch_up_pending,
            "catch-up consumed on the first send"
        );

        let payloads = driver.send_core.transport.sent_payloads();
        // [0] = catch-up (table-less, re-registers a,b from id 0), [1] = replay.
        assert_eq!(payloads.len(), 2, "catch-up frame precedes the replay");
        assert_catch_up_frame(&payloads[0], &[b"a", b"b"]);
        assert_eq!(payloads[1], frame, "the stored frame replays verbatim");
    }

    #[test]
    fn torn_dict_guard_rejects_a_conflicting_symbol_redefinition() {
        let mut driver = driver(FakeOrderedServer::no_response());
        // Torn recovery: the side-file recovered only id0 = a, but an earlier queued
        // frame re-registers id1 = b, extending the mirror to [a, b].
        driver.send_core.enable_delta_dict(&[1, b'a'], 1);
        driver
            .send_core
            .dict_mirror
            .accumulate(&make_delta_frame(1, &[b"b"]));
        assert_eq!(driver.send_core.dict_mirror.count(), 2);

        // Re-registering id1 = b (the same symbol) is a benign replay -> allowed.
        let same = make_delta_frame(1, &[b"b"]);
        assert!(driver.send_core.guard_dict_not_torn(&same).is_ok());

        // But a fresh frame redefining id1 = c to a DIFFERENT symbol -- which the
        // append-only foreground only did because it was seeded with the short
        // recovered count -- means the recovered dictionary disagrees with the
        // queue. `accumulate` would drop it (fully overlapping) and keep the stale
        // b, so the reconnect catch-up would mis-register id1; reject it as torn.
        let conflicting = make_delta_frame(1, &[b"c"]);
        let err = driver
            .send_core
            .guard_dict_not_torn(&conflicting)
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::StoreResendRequired);
    }

    #[test]
    fn torn_dict_guard_rejects_a_frame_referencing_lost_symbols() {
        let mut driver = driver(FakeOrderedServer::no_response());
        // A recovered dictionary of two symbols (ids 0, 1).
        driver.send_core.enable_delta_dict(&[1, b'a', 1, b'b'], 2);

        // A frame whose base is within the re-registered dictionary is fine...
        let ok = make_delta_frame(2, &[b"c"]);
        assert!(driver.send_core.guard_dict_not_torn(&ok).is_ok());
        // ...but a base beyond it references entries a host crash tore away (and
        // that no surviving earlier frame carries): unrecoverable, so fail loudly.
        let torn = make_delta_frame(5, &[b"z"]);
        let err = driver.send_core.guard_dict_not_torn(&torn).unwrap_err();
        assert_eq!(err.code(), ErrorCode::StoreResendRequired);
        assert!(
            err.msg().contains("dictionary is torn"),
            "msg: {}",
            err.msg()
        );
    }

    #[test]
    fn torn_dict_guard_in_full_dict_mode_passes_dense_frames_but_rejects_stray_deltas() {
        // Full-dict (dense) mode: the driver mirror is disabled. A real dense frame
        // always bases at id 0 (it re-ships its whole dictionary), so it passes.
        let driver = driver(FakeOrderedServer::no_response());
        let dense = make_delta_frame(0, &[b"z"]);
        assert!(driver.send_core.guard_dict_not_torn(&dense).is_ok());
        // But a frame basing above 0 with the mirror disabled is a lockstep
        // violation (or a delta slot reopened with delta disabled): no catch-up will
        // register ids [0, base), so it is rejected loudly rather than replayed into
        // a corrupt server dictionary.
        let stray = make_delta_frame(9, &[b"z"]);
        let err = driver.send_core.guard_dict_not_torn(&stray).unwrap_err();
        assert_eq!(err.code(), ErrorCode::StoreResendRequired);
        assert!(
            err.msg()
                .contains("delta symbol-dictionary mode is disabled"),
            "msg: {}",
            err.msg()
        );
    }

    #[test]
    fn reconnect_error_is_terminal_treats_store_resend_required_as_terminal() {
        // The torn-dict guard (above) and the corrupt-recovered-dict seed both
        // fail with ErrorCode::StoreResendRequired ("resend from source"). The
        // reconnect / failover classifier must treat that as TERMINAL so the
        // sender's own retry loops (e.g. `reconnect_pick`) stop instead of
        // re-reading the same unrecoverable on-disk state to their deadline --
        // while a transient SocketError stays retryable.
        assert!(
            reconnect_error_is_terminal(&Error::new(
                ErrorCode::StoreResendRequired,
                "the affected data must be resent"
            )),
            "StoreResendRequired must be terminal so the reconnect loop stops"
        );
        assert!(
            !reconnect_error_is_terminal(&Error::new(ErrorCode::SocketError, "connection reset")),
            "a transient SocketError must stay retryable"
        );
    }

    #[test]
    fn reconnect_catch_up_splits_across_frames_when_server_caps_batch() {
        // Five recovered symbols and a server batch cap too small for a one-frame
        // re-registration: the driver must split the catch-up across multiple
        // table-less frames (each within the cap), contiguous and gap-free, before
        // the queued replay frame. Exercises emit -> multiple send_frame ->
        // begin_catch_up(n>1) end-to-end (the split is unit-tested in SentDictMirror;
        // this drives it through the send core).
        let syms: Vec<Vec<u8>> = (0..5).map(|i| format!("sy{i:02}").into_bytes()).collect();
        let mut seed = Vec::new();
        for s in &syms {
            write_frame_varint(&mut seed, s.len() as u64);
            seed.extend_from_slice(s);
        }
        // Each entry is 5 bytes ([len=4]+4); budget = cap-12-16 = 12 fits two per
        // frame, so 5 symbols span 3 frames.
        let cap = 12 + 16 + 12;
        let mut driver = driver(FakeOrderedServer::no_response().with_batch_cap(cap));
        driver.send_core.enable_delta_dict(&seed, syms.len() as u32);
        assert!(driver.send_core.catch_up_pending);

        let replay = make_delta_frame(5, &[b"new"]);
        driver.try_submit(&replay).unwrap();
        driver.drive_send_once().unwrap();
        assert!(!driver.send_core.catch_up_pending, "catch-up consumed");

        let payloads = driver.send_core.transport.sent_payloads();
        assert!(
            payloads.len() > 2,
            "expected a multi-frame catch-up split + replay, got {}",
            payloads.len()
        );
        let (catch_up, replay_sent) = payloads.split_at(payloads.len() - 1);
        assert!(catch_up.len() >= 2, "catch-up must span multiple frames");

        // Every catch-up frame is within the cap, table-less, delta-flagged, and
        // together they re-register all five symbols contiguously from id 0.
        let mut expected_start = 0u64;
        let mut reassembled: Vec<Vec<u8>> = Vec::new();
        for f in catch_up {
            assert!(
                f.len() <= cap,
                "catch-up frame ({}) exceeds cap {}",
                f.len(),
                cap
            );
            assert_eq!(&f[0..4], b"QWP1");
            assert_eq!(f[5] & 0x08, 0x08, "catch-up carries the delta flag");
            assert_eq!(
                u16::from_le_bytes([f[6], f[7]]),
                0,
                "catch-up is table-less"
            );
            let (start, p) = read_frame_varint(f, 12);
            assert_eq!(start, expected_start, "catch-up ranges are contiguous");
            let (count, mut p) = read_frame_varint(f, p);
            for _ in 0..count {
                let (len, after) = read_frame_varint(f, p);
                reassembled.push(f[after..after + len as usize].to_vec());
                p = after + len as usize;
            }
            expected_start += count;
        }
        assert_eq!(
            reassembled, syms,
            "catch-up re-registers every symbol gap-free"
        );
        assert_eq!(
            replay_sent[0], replay,
            "the queued frame replays verbatim after the catch-up"
        );
    }

    #[test]
    fn catch_up_entry_exceeding_batch_cap_marks_terminal() {
        // A single recovered symbol larger than the server's batch cap cannot be
        // re-registered, so the reconnect catch-up is terminal (resend required)
        // rather than sending an oversized frame.
        let big = vec![b'x'; 64];
        let mut seed = Vec::new();
        write_frame_varint(&mut seed, big.len() as u64);
        seed.extend_from_slice(&big);
        let mut driver = driver(FakeOrderedServer::no_response().with_batch_cap(20));
        driver.send_core.enable_delta_dict(&seed, 1);
        assert!(driver.send_core.catch_up_pending);

        let outcome = driver.drive_send_once().unwrap();
        assert!(matches!(outcome, DriveOutcome::Terminal));
        let err = driver
            .store
            .terminal_error()
            .expect("terminal error recorded");
        assert!(
            err.msg().contains("exceeds the server") && err.msg().contains("batch cap"),
            "msg: {}",
            err.msg()
        );
        // Decided client-side from the advertised cap (nothing sent back), so it
        // is BatchTooLarge -- the same code the foreground uses for an oversize
        // frame -- not ServerFlushError.
        assert_eq!(err.code(), ErrorCode::BatchTooLarge);
    }

    #[test]
    fn drive_marks_terminal_when_a_stored_frame_outruns_the_recovered_dictionary() {
        // A recovered dictionary of two symbols, but a stored frame bases at id 5
        // (a host crash tore away ids [2, 5)). The guard, wired into the send loop,
        // must mark the sender terminal rather than replay an unresolvable frame --
        // covering the guard end-to-end, not just the predicate.
        let mut driver = driver(FakeOrderedServer::no_response());
        driver.send_core.enable_delta_dict(&[1, b'a', 1, b'b'], 2);
        let torn = make_delta_frame(5, &[b"z"]);
        driver.try_submit(&torn).unwrap();

        let outcome = driver.drive_send_once().unwrap();
        assert!(matches!(outcome, DriveOutcome::Terminal));
        let err = driver
            .store
            .terminal_error()
            .expect("terminal error recorded");
        assert!(
            err.msg().contains("dictionary is torn"),
            "msg: {}",
            err.msg()
        );
    }

    #[test]
    fn presend_reject_of_the_catch_up_escalates_to_terminal_not_an_infinite_loop() {
        // A Retriable reject that maps to no FSN -- the table-less symbol-dictionary
        // catch-up frame a reconnect emits carries no FSN, so its reject lands in
        // `record_presend_reject`. That path must be bounded by the poison ceiling
        // like a real-frame reject: a server that accepts the connection but keeps
        // rejecting the catch-up (e.g. a read-only replica after an in-place role
        // switch) would otherwise reconnect-loop forever, masking a permanent
        // failure as a hang. It must escalate to a loud terminal after
        // max_frame_rejections so the caller learns the queued data needs
        // resending. (The catch-up wire-seq -> None mapping is covered by
        // `catch_up_offset_maps_replay_acks_and_ignores_catch_up_acks`.)
        let mut driver = driver(FakeOrderedServer::no_response());
        let receipt = driver.try_submit(b"queued-frame").unwrap();
        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Published { fsn: 0 },
            "the queued frame the catch-up exists to unblock",
        );

        // The first rejections still failover (a transient / role reject may
        // resolve on another endpoint), so they do not terminate...
        for _ in 0..DEFAULT_MAX_FRAME_REJECTIONS - 1 {
            let outcome = driver
                .send_core
                .record_presend_reject(
                    &mut driver.store,
                    0,
                    write_error("replica rejects writes"),
                    QwpWsErrorPolicy::Retriable,
                    true,
                )
                .unwrap();
            assert_ne!(outcome, DriveOutcome::Terminal, "must not terminate early");
        }
        // ...but with no ACK progress in between, the next one escalates.
        let outcome = driver
            .send_core
            .record_presend_reject(
                &mut driver.store,
                0,
                write_error("replica rejects writes"),
                QwpWsErrorPolicy::Retriable,
                true,
            )
            .unwrap();
        assert_eq!(
            outcome,
            DriveOutcome::Terminal,
            "a persistently-rejected catch-up must escalate, not loop forever",
        );

        // The queued data is surfaced as terminal (resend required) -- recoverable
        // and reported, not silently retried into oblivion.
        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Terminal { fsn: 0 }
        );
        let terminal = driver
            .store
            .terminal_error()
            .expect("terminal error recorded");
        assert!(
            terminal.msg().contains("catch-up"),
            "terminal error names the catch-up cause: {}",
            terminal.msg(),
        );
    }
    use std::collections::VecDeque;
    #[cfg(feature = "sync-sender-qwp-ws")]
    use std::fs::File;
    #[cfg(feature = "sync-sender-qwp-ws")]
    use std::io::{Read, Write};
    #[cfg(feature = "sync-sender-qwp-ws")]
    use std::net::TcpListener;
    #[cfg(feature = "sync-sender-qwp-ws")]
    use std::sync::mpsc;
    #[cfg(feature = "sync-sender-qwp-ws")]
    use std::thread;
    #[cfg(feature = "sync-sender-qwp-ws")]
    use std::time::Duration;

    #[cfg(feature = "sync-sender-qwp-ws")]
    use rustls::{ServerConfig, StreamOwned, server::ServerConnection};
    #[cfg(feature = "sync-sender-qwp-ws")]
    use rustls_pki_types::pem::PemObject;
    #[cfg(feature = "sync-sender-qwp-ws")]
    use rustls_pki_types::{CertificateDer, PrivateKeyDer};

    #[derive(Debug)]
    struct DelayedPollAckServer {
        polls_before_ack: usize,
        ack_sent: bool,
        sent_frames: Vec<SentFrame>,
    }

    impl DelayedPollAckServer {
        fn new(polls_before_ack: usize) -> Self {
            Self {
                polls_before_ack,
                ack_sent: false,
                sent_frames: Vec::new(),
            }
        }
    }

    impl QwpWsCoreTransport for DelayedPollAckServer {
        fn try_poll_response(&mut self) -> Result<TransportPoll, TransportFailure> {
            if self.sent_frames.is_empty() || self.ack_sent {
                return Ok(TransportPoll::Idle);
            }
            if self.polls_before_ack > 0 {
                self.polls_before_ack -= 1;
                return Ok(TransportPoll::Idle);
            }
            self.ack_sent = true;
            Ok(TransportPoll::Response(TransportResponse::Ack {
                wire_seq: self.sent_frames[0].wire_seq,
            }))
        }

        fn send_frame(
            &mut self,
            frame: OutboundFrameView<'_>,
        ) -> Result<TransportSendResult, TransportFailure> {
            self.sent_frames.push(frame.sent_frame());
            Ok(TransportSendResult::NoResponse)
        }
    }

    fn options(
        _max_frames: usize,
        max_bytes: usize,
        max_in_flight: usize,
    ) -> SfaMemoryQueueOptions {
        SfaMemoryQueueOptions {
            segment_size_bytes: 256,
            max_bytes,
            max_in_flight,
        }
    }

    fn memory_queue(options: SfaMemoryQueueOptions) -> SfaFrameQueue {
        SfaFrameQueue::open_memory(options).unwrap()
    }

    type FakeDriver = QwpWsCoreTestHarness<SfaFrameQueue, FakeOrderedServer>;

    fn driver(server: FakeOrderedServer) -> FakeDriver {
        QwpWsCoreTestHarness::new(options(8, 1024, 4), server).unwrap()
    }

    #[derive(Debug)]
    enum PublishTestError {
        Encode(crate::Error),
        Driver(DriverError),
    }

    impl From<DriverError> for PublishTestError {
        fn from(value: DriverError) -> Self {
            Self::Driver(value)
        }
    }

    fn publish_qwp<Q, T>(
        driver: &mut QwpWsCoreTestHarness<Q, T>,
        encoder: &mut QwpWsReplayEncoder,
        buffer: &QwpWsColumnarBuffer,
    ) -> Result<QwpReceipt, PublishTestError>
    where
        Q: PublicationLog,
        T: QwpWsCoreTransport,
    {
        let payload = encoder.encode(buffer).map_err(PublishTestError::Encode)?;
        Ok(driver.try_submit(payload)?)
    }

    fn wait_for_delivery<Q, T>(
        driver: &mut QwpWsCoreTestHarness<Q, T>,
        receipt: QwpReceipt,
        timeout: Duration,
    ) -> Result<DeliveryOutcome, DriverError>
    where
        Q: PublicationLog,
        T: QwpWsCoreTransport,
    {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(outcome) = driver.delivery_status(receipt)? {
                return Ok(outcome);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(DeliveryOutcome::Timeout);
            }
            if driver.drive_once()? == DriveOutcome::Idle {
                std::thread::sleep(remaining.min(Duration::from_micros(100)));
            }
        }
    }

    fn durable_driver(server: FakeOrderedServer) -> FakeDriver {
        QwpWsCoreTestHarness::from_queue_with_durable_ack(memory_queue(options(8, 1024, 4)), server)
    }

    fn durable_driver_with_options(
        options: SfaMemoryQueueOptions,
        server: FakeOrderedServer,
    ) -> FakeDriver {
        QwpWsCoreTestHarness::from_queue_with_durable_ack(memory_queue(options), server)
    }

    fn driver_with_event_capacity(server: FakeOrderedServer, event_capacity: usize) -> FakeDriver {
        QwpWsCoreTestHarness::from_queue_with_event_capacity(
            memory_queue(options(8, 1024, 4)),
            server,
            event_capacity,
        )
    }

    fn sender_error(fsn: u64) -> QwpWsSenderError {
        QwpWsSenderError {
            category: QwpWsErrorCategory::WriteError,
            applied_policy: QwpWsErrorPolicy::Retriable,
            status: Some(codec::WS_STATUS_WRITE_ERROR),
            message: Some(format!("error {fsn}")),
            message_sequence: Some(fsn),
            from_fsn: fsn,
            to_fsn: fsn,
        }
    }

    const QWP_WS_COLUMNAR_BENCH_BATCH_SIZE: usize = 1000;

    fn qwp_ws_columnar_bench_rows() -> usize {
        std::env::var("QWP_WS_COLUMNAR_BENCH_ROWS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|rows| *rows > 0)
            .unwrap_or(20_000_000)
    }

    fn fill_qwp_ws_columnar_benchmark_batch(buffer: &mut Buffer, batch_idx: usize, rows: usize) {
        let symbols = [
            "SYM000", "SYM001", "SYM002", "SYM003", "SYM004", "SYM005", "SYM006", "SYM007",
        ];
        let venues = ["ldn", "nyc", "ams", "fra", "sin", "hkg", "tyo", "sfo"];
        for row_idx in 0..rows {
            let seq = (batch_idx * QWP_WS_COLUMNAR_BENCH_BATCH_SIZE + row_idx) as i64;
            buffer
                .table("trades")
                .unwrap()
                .symbol("sym", symbols[row_idx & 7])
                .unwrap()
                .column_i64("qty", seq)
                .unwrap()
                .column_f64("px", 100.0 + (seq & 1023) as f64)
                .unwrap()
                .column_str("venue", venues[row_idx & 7])
                .unwrap()
                .column_ts("event_ts", TimestampNanos::new(seq))
                .unwrap()
                .at(TimestampNanos::new(seq))
                .unwrap();
        }
    }

    fn qwp_buffer(sym: &str, qty: i64, ts: i64) -> Buffer {
        let mut buffer = Buffer::qwp_ws_with_max_name_len(127);
        buffer
            .table("trades")
            .unwrap()
            .symbol("sym", sym)
            .unwrap()
            .column_i64("qty", qty)
            .unwrap()
            .column_f64("px", 100.0 + qty as f64)
            .unwrap()
            .at(TimestampNanos::new(ts))
            .unwrap();
        buffer
    }

    fn replay_payload(buffer: &Buffer) -> Vec<u8> {
        let mut scratch = QwpWsEncodeScratch::new();
        let mut global_dict = SymbolGlobalDict::new();
        buffer
            .as_qwp_ws()
            .unwrap()
            .encode_ws_replay_message(&mut scratch, &mut global_dict, 1)
            .unwrap();
        scratch.message
    }

    fn qwp_error_payload(status: u8, sequence: u64, message: &str) -> Vec<u8> {
        let msg = message.as_bytes();
        let mut payload = Vec::with_capacity(11 + msg.len());
        payload.push(status);
        payload.extend_from_slice(&sequence.to_le_bytes());
        payload.extend_from_slice(&(msg.len() as u16).to_le_bytes());
        payload.extend_from_slice(msg);
        payload
    }

    fn qwp_durable_ack_payload(entries: &[(&str, i64)]) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.push(codec::WS_STATUS_DURABLE_ACK);
        append_table_seq_txns(&mut payload, entries);
        payload
    }

    fn qwp_ok_payload_with_table_entries(sequence: u64, entries: &[(&str, i64)]) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.push(codec::WS_STATUS_OK);
        payload.extend_from_slice(&sequence.to_le_bytes());
        append_table_seq_txns(&mut payload, entries);
        payload
    }

    fn append_table_seq_txns(payload: &mut Vec<u8>, entries: &[(&str, i64)]) {
        payload.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        for (table, seq_txn) in entries {
            payload.extend_from_slice(&(table.len() as u16).to_le_bytes());
            payload.extend_from_slice(table.as_bytes());
            payload.extend_from_slice(&seq_txn.to_le_bytes());
        }
    }

    fn table_seq_txns(entries: &[(&str, i64)]) -> Vec<TableSeqTxn> {
        entries
            .iter()
            .map(|(table, seq_txn)| TableSeqTxn {
                table: (*table).to_string(),
                seq_txn: *seq_txn,
            })
            .collect()
    }

    fn schema_mismatch_error(message: &str) -> QwpServerError {
        QwpServerError {
            status: codec::WS_STATUS_SCHEMA_MISMATCH,
            message: message.to_string(),
            error: Error::new(ErrorCode::InvalidApiCall, message),
        }
    }

    fn write_error(message: &str) -> QwpServerError {
        QwpServerError {
            status: codec::WS_STATUS_WRITE_ERROR,
            message: message.to_string(),
            error: Error::new(ErrorCode::ServerFlushError, message),
        }
    }

    fn not_writable_error(message: &str) -> QwpServerError {
        QwpServerError {
            status: codec::WS_STATUS_NOT_WRITABLE,
            message: message.to_string(),
            error: Error::new(ErrorCode::ServerFlushError, message),
        }
    }

    fn drain_events<Q: PublicationLog, T: QwpWsCoreTransport>(
        driver: &mut QwpWsCoreTestHarness<Q, T>,
    ) -> Vec<DriverEvent> {
        let mut events = Vec::new();
        while let Some(event) = driver.poll_event() {
            events.push(event);
        }
        events
    }

    #[derive(Debug)]
    struct TestTransport {
        send_results: VecDeque<Result<TransportSendResult, TransportFailure>>,
        poll_results: VecDeque<Result<TransportPoll, TransportFailure>>,
        keepalive_results: VecDeque<Result<bool, TransportFailure>>,
        restart_results: VecDeque<Result<(), DriverError>>,
        keepalive_attempts: usize,
        keepalive_pending_args: Vec<bool>,
        restart_attempts: usize,
        restart_reasons: Vec<ReconnectReason>,
        sent_frames: Vec<SentFrame>,
        sent_payloads: Vec<Vec<u8>>,
    }

    impl TestTransport {
        fn scripted(
            send_results: impl IntoIterator<Item = Result<TransportSendResult, TransportFailure>>,
        ) -> Self {
            Self {
                send_results: send_results.into_iter().collect(),
                poll_results: VecDeque::new(),
                keepalive_results: VecDeque::new(),
                restart_results: VecDeque::new(),
                keepalive_attempts: 0,
                keepalive_pending_args: Vec::new(),
                restart_attempts: 0,
                restart_reasons: Vec::new(),
                sent_frames: Vec::new(),
                sent_payloads: Vec::new(),
            }
        }

        fn with_restart_results(
            mut self,
            restart_results: impl IntoIterator<Item = Result<(), DriverError>>,
        ) -> Self {
            self.restart_results = restart_results.into_iter().collect();
            self
        }

        fn with_poll_results(
            mut self,
            poll_results: impl IntoIterator<Item = Result<Option<TransportResponse>, TransportFailure>>,
        ) -> Self {
            self.poll_results = poll_results
                .into_iter()
                .map(|result| {
                    result.map(|response| {
                        response.map_or(TransportPoll::Idle, TransportPoll::Response)
                    })
                })
                .collect();
            self
        }

        fn with_poll_events(
            mut self,
            poll_results: impl IntoIterator<Item = Result<TransportPoll, TransportFailure>>,
        ) -> Self {
            self.poll_results = poll_results.into_iter().collect();
            self
        }

        fn with_keepalive_results(
            mut self,
            keepalive_results: impl IntoIterator<Item = Result<bool, TransportFailure>>,
        ) -> Self {
            self.keepalive_results = keepalive_results.into_iter().collect();
            self
        }
    }

    impl QwpWsCoreTransport for TestTransport {
        fn try_poll_response(&mut self) -> Result<TransportPoll, TransportFailure> {
            self.poll_results
                .pop_front()
                .unwrap_or(Ok(TransportPoll::Idle))
        }

        fn send_durable_ack_keepalive_if_due(
            &mut self,
            durable_ack_pending: bool,
        ) -> Result<bool, TransportFailure> {
            self.keepalive_attempts += 1;
            self.keepalive_pending_args.push(durable_ack_pending);
            if !durable_ack_pending {
                return Ok(false);
            }
            self.keepalive_results.pop_front().unwrap_or(Ok(false))
        }

        fn send_frame(
            &mut self,
            frame: OutboundFrameView<'_>,
        ) -> Result<TransportSendResult, TransportFailure> {
            self.sent_frames.push(frame.sent_frame());
            self.sent_payloads.push(frame.payload.to_vec());
            self.send_results
                .pop_front()
                .unwrap_or(Ok(TransportSendResult::NoResponse))
        }

        fn restart_connection(&mut self, reason: ReconnectReason) -> Result<(), DriverError> {
            self.restart_attempts += 1;
            self.restart_reasons.push(reason);
            self.restart_results.pop_front().unwrap_or(Ok(()))
        }
    }

    #[test]
    fn publisher_sends_replay_payload_to_driver_transport() {
        let buffer = qwp_buffer("SYM_001", 7, 1_000);
        let expected = replay_payload(&buffer);
        let driver = QwpWsCoreTestHarness::from_queue(
            memory_queue(options(8, 4096, 4)),
            TestTransport::scripted([Ok(TransportSendResult::NoResponse)]),
        );
        let mut driver = driver;
        let mut encoder = QwpWsReplayEncoder::new(1);

        let receipt = publish_qwp(&mut driver, &mut encoder, buffer.as_qwp_ws().unwrap()).unwrap();
        let outcome = driver.drive_once().unwrap();

        assert_eq!(receipt, QwpReceipt { fsn: 0 });
        assert_eq!(
            outcome,
            DriveOutcome::Sent(SentFrame {
                fsn: 0,
                wire_seq: 0,
                payload_len: expected.len(),
            })
        );
        assert_eq!(driver.send_core.transport.sent_payloads, vec![expected]);
    }

    #[test]
    fn publisher_rejects_empty_buffer_without_publication() {
        let buffer = Buffer::qwp_ws_with_max_name_len(127);
        let driver = QwpWsCoreTestHarness::from_queue(
            memory_queue(options(8, 4096, 4)),
            TestTransport::scripted([]),
        );
        let mut driver = driver;
        let mut encoder = QwpWsReplayEncoder::new(1);

        let err = publish_qwp(&mut driver, &mut encoder, buffer.as_qwp_ws().unwrap()).unwrap_err();

        match err {
            PublishTestError::Encode(err) => {
                assert_eq!(err.code(), crate::ErrorCode::InvalidApiCall);
                assert_eq!(err.msg(), "Cannot submit an empty QWP/WebSocket buffer.");
            }
            PublishTestError::Driver(err) => panic!("unexpected driver error: {err:?}"),
        }
        assert!(driver.send_core.transport.sent_payloads.is_empty());
    }

    #[test]
    fn publisher_failed_queue_publication_does_not_consume_fsn() {
        let first = qwp_buffer("SYM_001", 1, 1_000);
        let second = qwp_buffer("SYM_002", 2, 2_000);
        let third = qwp_buffer("SYM_003", 3, 3_000);
        let driver = QwpWsCoreTestHarness::from_queue(
            memory_queue(options(1, 4096, 1)),
            TestTransport::scripted([Ok(TransportSendResult::Response(TransportResponse::Ack {
                wire_seq: 0,
            }))]),
        );
        let mut driver = driver;
        let mut encoder = QwpWsReplayEncoder::new(1);

        let first_receipt =
            publish_qwp(&mut driver, &mut encoder, first.as_qwp_ws().unwrap()).unwrap();
        let err = publish_qwp(&mut driver, &mut encoder, second.as_qwp_ws().unwrap()).unwrap_err();
        assert!(matches!(
            err,
            PublishTestError::Driver(DriverError::Queue(QueueError::MaxInFlightReached {
                max_in_flight: 1
            }))
        ));
        assert_eq!(
            wait_for_delivery(&mut driver, first_receipt, Duration::from_secs(5)).unwrap(),
            DeliveryOutcome::Completed
        );

        let third_receipt =
            publish_qwp(&mut driver, &mut encoder, third.as_qwp_ws().unwrap()).unwrap();
        assert_eq!(third_receipt, QwpReceipt { fsn: 1 });
    }

    /// Run with:
    /// `cargo test --features sync-sender-qwp-ws --lib publisher_memory_sfa_zero_alloc_after_warmup -- --ignored --test-threads=1`
    #[test]
    #[ignore]
    fn publisher_memory_sfa_zero_alloc_after_warmup() {
        use crate::alloc_counter;

        let buffer = qwp_buffer("SYM_001", 7, 1_000);
        let queue = memory_queue(options(8, 4096, 4));
        let driver = QwpWsCoreTestHarness::from_queue(queue, FakeOrderedServer::ack_each_send());
        let mut driver = driver;
        let mut encoder = QwpWsReplayEncoder::new(1);

        for _ in 0..4 {
            let receipt =
                publish_qwp(&mut driver, &mut encoder, buffer.as_qwp_ws().unwrap()).unwrap();
            assert_eq!(
                wait_for_delivery(&mut driver, receipt, Duration::from_secs(5)).unwrap(),
                DeliveryOutcome::Completed
            );
        }

        alloc_counter::start_counting();
        let receipt = publish_qwp(&mut driver, &mut encoder, buffer.as_qwp_ws().unwrap()).unwrap();
        let alloc_count = alloc_counter::stop_counting();

        assert_eq!(receipt, QwpReceipt { fsn: 4 });
        assert_eq!(
            alloc_count, 0,
            "Expected zero allocations for warmed QWP/WebSocket memory publication, got {alloc_count}"
        );
    }

    /// Run with:
    /// `cargo test --release --manifest-path questdb-rs/Cargo.toml --features sync-sender-qwp-ws qwp_ws_columnar_memory_publication_benchmark --lib -- --ignored --nocapture --test-threads=1`
    #[test]
    #[ignore = "performance benchmark"]
    fn qwp_ws_columnar_memory_publication_benchmark() {
        let rows = qwp_ws_columnar_bench_rows();
        let batches = rows.div_ceil(QWP_WS_COLUMNAR_BENCH_BATCH_SIZE);
        let mut buffer = Buffer::qwp_ws_with_max_name_len(127);
        let queue = memory_queue(options(8, 1 << 20, 4));
        let driver = QwpWsCoreTestHarness::from_queue(queue, FakeOrderedServer::ack_each_send());
        let mut driver = driver;
        let mut encoder = QwpWsReplayEncoder::new(1);

        fill_qwp_ws_columnar_benchmark_batch(&mut buffer, 0, QWP_WS_COLUMNAR_BENCH_BATCH_SIZE);
        let receipt = publish_qwp(&mut driver, &mut encoder, buffer.as_qwp_ws().unwrap()).unwrap();
        assert_eq!(
            wait_for_delivery(&mut driver, receipt, Duration::from_secs(5)).unwrap(),
            DeliveryOutcome::Completed
        );
        buffer.clear();

        let started = std::time::Instant::now();
        let mut published_rows = 0usize;
        for batch_idx in 0..batches {
            let rows_in_batch = (rows - published_rows).min(QWP_WS_COLUMNAR_BENCH_BATCH_SIZE);
            fill_qwp_ws_columnar_benchmark_batch(&mut buffer, batch_idx, rows_in_batch);
            let receipt =
                publish_qwp(&mut driver, &mut encoder, buffer.as_qwp_ws().unwrap()).unwrap();
            assert_eq!(
                wait_for_delivery(&mut driver, receipt, Duration::from_secs(5)).unwrap(),
                DeliveryOutcome::Completed
            );
            buffer.clear();
            published_rows += rows_in_batch;
        }
        let elapsed = started.elapsed();
        eprintln!(
            "qwp_ws_columnar_memory_publication_benchmark rows={} batch_size={} end_to_end_ms={} rows_per_sec={:.2}",
            rows,
            QWP_WS_COLUMNAR_BENCH_BATCH_SIZE,
            elapsed.as_millis(),
            rows as f64 / elapsed.as_secs_f64()
        );
    }

    #[cfg(feature = "sync-sender-qwp-ws")]
    fn tls_certs_dir() -> std::path::PathBuf {
        let mut certs_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        certs_dir.pop();
        certs_dir.push("tls_certs");
        certs_dir
    }

    #[cfg(feature = "sync-sender-qwp-ws")]
    fn tls_server_config() -> std::sync::Arc<ServerConfig> {
        let certs_dir = tls_certs_dir();
        let cert_file = File::open(certs_dir.join("server.crt")).unwrap();
        let private_key_file = File::open(certs_dir.join("server.key")).unwrap();
        let certs = CertificateDer::pem_reader_iter(cert_file)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let private_key = PrivateKeyDer::from_pem_reader(private_key_file).unwrap();
        std::sync::Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, private_key)
                .unwrap(),
        )
    }

    #[cfg(feature = "sync-sender-qwp-ws")]
    fn tls_client_settings() -> TlsSettings {
        let cert_file = File::open(tls_certs_dir().join("server_rootCA.pem")).unwrap();
        let certs = CertificateDer::pem_reader_iter(cert_file)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        TlsSettings::PemFile(certs)
    }

    #[cfg(feature = "sync-sender-qwp-ws")]
    fn read_request_until_blank<S: Read>(stream: &mut S) -> std::io::Result<String> {
        let mut bytes = Vec::new();
        let mut tmp = [0u8; 256];
        loop {
            let n = stream.read(&mut tmp)?;
            if n == 0 {
                break;
            }
            bytes.extend_from_slice(&tmp[..n]);
            if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        Ok(String::from_utf8_lossy(&bytes).to_string())
    }

    #[cfg(feature = "sync-sender-qwp-ws")]
    fn header_value(request: &str, name: &str) -> String {
        request
            .split("\r\n")
            .find_map(|line| {
                let (key, value) = line.split_once(':')?;
                key.trim()
                    .eq_ignore_ascii_case(name)
                    .then(|| value.trim().to_string())
            })
            .unwrap()
    }

    #[cfg(feature = "sync-sender-qwp-ws")]
    fn read_client_frame<S: Read>(stream: &mut S) -> std::io::Result<Vec<u8>> {
        let mut hdr = [0u8; 2];
        stream.read_exact(&mut hdr)?;
        let len_short = hdr[1] & 0x7f;
        let payload_len = match len_short {
            126 => {
                let mut bytes = [0u8; 2];
                stream.read_exact(&mut bytes)?;
                u16::from_be_bytes(bytes) as usize
            }
            127 => {
                let mut bytes = [0u8; 8];
                stream.read_exact(&mut bytes)?;
                u64::from_be_bytes(bytes) as usize
            }
            len => len as usize,
        };
        let mut mask = [0u8; 4];
        stream.read_exact(&mut mask)?;
        let mut payload = vec![0u8; payload_len];
        stream.read_exact(&mut payload)?;
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index & 3];
        }
        Ok(payload)
    }

    #[cfg(feature = "sync-sender-qwp-ws")]
    fn write_server_binary_frame<S: Write>(stream: &mut S, payload: &[u8]) -> std::io::Result<()> {
        let mut frame = vec![0x82];
        match payload.len() {
            len @ 0..=125 => frame.push(len as u8),
            len @ 126..=0xffff => {
                frame.push(126);
                frame.extend_from_slice(&(len as u16).to_be_bytes());
            }
            len => {
                frame.push(127);
                frame.extend_from_slice(&(len as u64).to_be_bytes());
            }
        }
        frame.extend_from_slice(payload);
        stream.write_all(&frame)
    }

    #[cfg(feature = "sync-sender-qwp-ws")]
    fn write_ok_response<S: Write>(stream: &mut S, wire_seq: u64) -> std::io::Result<()> {
        let mut ok = vec![0u8];
        ok.extend_from_slice(&wire_seq.to_le_bytes());
        ok.extend_from_slice(&0u16.to_le_bytes());
        write_server_binary_frame(stream, &ok)
    }

    #[cfg(feature = "sync-sender-qwp-ws")]
    fn serve_qwp_ws_connection<S: Read + Write>(
        stream: &mut S,
        frames: usize,
        payload_tx: mpsc::Sender<Vec<u8>>,
    ) {
        let request = read_request_until_blank(stream).unwrap();
        let accept =
            crate::ws::crypto::compute_accept(&header_value(&request, "Sec-WebSocket-Key"));
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: {accept}\r\n\
             X-QWP-Version: 1\r\n\
             \r\n"
        );
        stream.write_all(response.as_bytes()).unwrap();

        for wire_seq in 0..frames {
            let payload = read_client_frame(stream).unwrap();
            payload_tx.send(payload).unwrap();
            write_ok_response(stream, wire_seq as u64).unwrap();
        }

        // Stay alive until the client closes the connection so close_drain on
        // the client side never races a server-side EOF.
        let mut sink = [0u8; 1024];
        while matches!(stream.read(&mut sink), Ok(n) if n > 0) {}
    }

    #[cfg(feature = "sync-sender-qwp-ws")]
    fn spawn_real_qwp_ws_server(
        use_tls: bool,
        frames: usize,
    ) -> (String, u16, mpsc::Receiver<Vec<u8>>) {
        let host = if use_tls { "localhost" } else { "127.0.0.1" };
        let listener = TcpListener::bind((host, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let (payload_tx, payload_rx) = mpsc::channel();
        thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            if use_tls {
                let server = ServerConnection::new(tls_server_config()).unwrap();
                let mut stream = StreamOwned::new(server, stream);
                serve_qwp_ws_connection(&mut stream, frames, payload_tx);
            } else {
                let mut stream = stream;
                serve_qwp_ws_connection(&mut stream, frames, payload_tx);
            }
        });
        (host.to_string(), port, payload_rx)
    }

    #[test]
    fn submit_returns_before_ack() {
        let mut driver = driver(FakeOrderedServer::ack_each_send());

        let receipt = driver.try_submit(b"payload").unwrap();

        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Published { fsn: 0 }
        );
        assert_eq!(
            drain_events(&mut driver),
            vec![DriverEvent::Published { fsn: 0 }]
        );
    }

    #[test]
    fn drive_send_once_sends_without_polling_for_ack() {
        let transport = TestTransport::scripted([
            Ok(TransportSendResult::NoResponse),
            Ok(TransportSendResult::NoResponse),
        ])
        .with_poll_results([Err(TransportFailure::Terminal(fake_transport_error(
            "should not poll",
        )))]);
        let mut driver =
            QwpWsCoreTestHarness::from_queue(memory_queue(options(8, 1024, 2)), transport);
        let first = driver.try_submit(b"first").unwrap();
        let second = driver.try_submit(b"second").unwrap();

        assert_eq!(
            driver.drive_send_once().unwrap(),
            DriveOutcome::Sent(SentFrame {
                fsn: first.fsn,
                wire_seq: 0,
                payload_len: b"first".len(),
            })
        );
        assert_eq!(
            driver.drive_send_once().unwrap(),
            DriveOutcome::Sent(SentFrame {
                fsn: second.fsn,
                wire_seq: 1,
                payload_len: b"second".len(),
            })
        );
        assert_eq!(driver.drive_send_once().unwrap(), DriveOutcome::Idle);
        assert_eq!(
            driver.receipt_status(first),
            QwpReceiptStatus::Sent {
                fsn: first.fsn,
                wire_seq: 0,
            }
        );
        assert_eq!(
            driver.receipt_status(second),
            QwpReceiptStatus::Sent {
                fsn: second.fsn,
                wire_seq: 1,
            }
        );
        assert_eq!(
            driver.send_core.transport.sent_frames.as_slice(),
            &[
                SentFrame {
                    fsn: first.fsn,
                    wire_seq: 0,
                    payload_len: b"first".len(),
                },
                SentFrame {
                    fsn: second.fsn,
                    wire_seq: 1,
                    payload_len: b"second".len(),
                },
            ]
        );
    }

    #[test]
    fn drive_send_once_applies_immediate_transport_response() {
        let transport =
            TestTransport::scripted([Ok(TransportSendResult::Response(TransportResponse::Ack {
                wire_seq: 0,
            }))]);
        let mut driver =
            QwpWsCoreTestHarness::from_queue(memory_queue(options(8, 1024, 2)), transport);
        let receipt = driver.try_submit(b"payload").unwrap();

        assert_eq!(
            driver.drive_send_once().unwrap(),
            DriveOutcome::Acked { wire_seq: 0 }
        );
        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Completed { fsn: receipt.fsn }
        );
    }

    #[cfg(feature = "sync-sender-qwp-ws")]
    #[test]
    fn sender_qwp_ws_round_trip_delivers_replay_payload() {
        let (host, port, payload_rx) = spawn_real_qwp_ws_server(false, 1);
        let mut buffer = qwp_buffer("SYM_REAL", 42, 42_000);
        let expected = replay_payload(&buffer);

        let conf = format!("qwpws::addr={host}:{port};");
        let mut sender = crate::ingress::Sender::from_conf(&conf).unwrap();
        sender.flush(&mut buffer).unwrap();
        sender.close_drain().unwrap();

        assert_eq!(
            payload_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            expected
        );
    }

    #[cfg(feature = "sync-sender-qwp-ws")]
    #[test]
    fn sender_qwp_wss_round_trip_delivers_replay_payload() {
        let (host, port, payload_rx) = spawn_real_qwp_ws_server(true, 1);
        let mut buffer = qwp_buffer("SYM_SECURE", 7, 7_000);
        let expected = replay_payload(&buffer);

        let ca_path = tls_certs_dir().join("server_rootCA.pem");
        let conf = format!(
            "qwpwss::addr={host}:{port};tls_roots={};",
            ca_path.display()
        );
        let mut sender = crate::ingress::Sender::from_conf(&conf).unwrap();
        sender.flush(&mut buffer).unwrap();
        sender.close_drain().unwrap();

        assert_eq!(
            payload_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            expected
        );
    }

    #[test]
    fn submit_success_queues_published_event_but_failed_submit_queues_nothing() {
        let mut driver = driver(FakeOrderedServer::ack_each_send());

        assert_eq!(
            driver.try_submit(b""),
            Err(DriverError::Queue(QueueError::EmptyPayload))
        );
        assert_eq!(driver.poll_event(), None);

        let receipt = driver.try_submit(b"payload").unwrap();

        assert_eq!(
            driver.poll_event(),
            Some(DriverEvent::Published { fsn: receipt.fsn })
        );
        assert_eq!(driver.poll_event(), None);
        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Published { fsn: 0 }
        );
    }

    #[test]
    fn empty_submit_returns_api_error_without_receipt() {
        let mut driver = driver(FakeOrderedServer::ack_each_send());

        assert_eq!(
            driver.try_submit(b""),
            Err(DriverError::Queue(QueueError::EmptyPayload))
        );
        assert_eq!(driver.poll_event(), None);

        let receipt = driver.try_submit(b"payload").unwrap();
        assert_eq!(receipt, QwpReceipt { fsn: 0 });
    }

    #[test]
    fn blocking_submit_drives_until_local_capacity_frees() {
        let mut driver =
            QwpWsCoreTestHarness::new(options(1, 1024, 1), FakeOrderedServer::ack_each_send())
                .unwrap();
        let first = driver.try_submit(b"first").unwrap();

        let second = driver.submit_with_drive_limit(b"second", 1).unwrap();

        assert_eq!(
            driver.receipt_status(first),
            QwpReceiptStatus::Completed { fsn: 0 }
        );
        assert_eq!(
            driver.receipt_status(second),
            QwpReceiptStatus::Published { fsn: 1 }
        );
        assert_eq!(driver.send_core.transport.sent_frames().len(), 1);
    }

    #[test]
    fn blocking_submit_times_out_when_capacity_does_not_free() {
        let mut driver =
            QwpWsCoreTestHarness::new(options(1, 1024, 1), FakeOrderedServer::no_response())
                .unwrap();
        driver.try_submit(b"first").unwrap();

        assert_eq!(
            driver.submit_with_drive_limit(b"second", 1),
            Err(DriverError::SubmitTimedOut {
                backpressure: Some(QueueError::MaxInFlightReached { max_in_flight: 1 })
            })
        );
    }

    #[test]
    fn blocking_submit_deadline_continues_past_fixed_step_budget() {
        let queue = memory_queue(options(1, 1024, 1));
        let mut driver = QwpWsCoreTestHarness::from_queue(queue, DelayedPollAckServer::new(20));
        let first = driver.try_submit(b"first").unwrap();

        let second = driver
            .submit_with_drive_deadline(b"second", Duration::from_secs(2))
            .unwrap();

        assert_eq!(
            driver.receipt_status(first),
            QwpReceiptStatus::Completed { fsn: 0 }
        );
        assert_eq!(
            driver.receipt_status(second),
            QwpReceiptStatus::Published { fsn: 1 }
        );
        assert_eq!(driver.send_core.transport.sent_frames.len(), 1);
    }

    #[test]
    fn blocking_submit_deadline_can_expire_before_driving() {
        let mut driver =
            QwpWsCoreTestHarness::new(options(1, 1024, 1), FakeOrderedServer::no_response())
                .unwrap();
        driver.try_submit(b"first").unwrap();

        assert_eq!(
            driver.submit_with_drive_deadline(b"second", Duration::ZERO),
            Err(DriverError::SubmitTimedOut {
                backpressure: Some(QueueError::MaxInFlightReached { max_in_flight: 1 })
            })
        );
        assert!(driver.send_core.transport.sent_frames().is_empty());
    }

    #[test]
    fn blocking_submit_propagates_non_backpressure_errors() {
        let mut driver = driver(FakeOrderedServer::ack_each_send());

        assert_eq!(
            driver.submit_with_drive_limit(b"", 1),
            Err(DriverError::Queue(QueueError::EmptyPayload))
        );
    }

    #[test]
    fn drive_once_sends_until_max_in_flight() {
        let mut driver =
            QwpWsCoreTestHarness::new(options(8, 1024, 2), FakeOrderedServer::no_response())
                .unwrap();
        driver.try_submit(b"a").unwrap();
        driver.try_submit(b"b").unwrap();
        assert!(matches!(
            driver.try_submit(b"c"),
            Err(DriverError::Queue(QueueError::MaxInFlightReached {
                max_in_flight: 2
            }))
        ));

        assert!(matches!(
            driver.drive_once().unwrap(),
            DriveOutcome::Sent(_)
        ));
        assert!(matches!(
            driver.drive_once().unwrap(),
            DriveOutcome::Sent(_)
        ));
        assert_eq!(driver.drive_once().unwrap(), DriveOutcome::Idle);
    }

    #[test]
    fn send_event_agrees_with_sent_receipt_status() {
        let mut driver = driver(FakeOrderedServer::no_response());
        let receipt = driver.try_submit(b"payload").unwrap();

        assert!(matches!(
            driver.drive_once().unwrap(),
            DriveOutcome::Sent(_)
        ));

        assert_eq!(
            drain_events(&mut driver),
            vec![
                DriverEvent::Published { fsn: 0 },
                DriverEvent::Sent {
                    fsn: 0,
                    wire_seq: 0,
                },
            ]
        );
        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Sent {
                fsn: 0,
                wire_seq: 0,
            }
        );
    }

    #[test]
    fn reconnect_policy_retries_failed_reconnect_until_success() {
        let transport = TestTransport::scripted([Ok(TransportSendResult::Failure(
            TransportFailure::Disconnect(fake_transport_error("disconnect before reconnect")),
        ))])
        .with_restart_results([
            Err(DriverError::Transport(fake_transport_error(
                "reconnect failed once",
            ))),
            Ok(()),
        ]);
        let mut driver = QwpWsCoreTestHarness::from_queue_with_reconnect_policy(
            memory_queue(options(8, 1024, 4)),
            transport,
            ReconnectPolicy::no_backoff(Duration::from_secs(1)),
            false,
        );
        let receipt = driver.try_submit(b"payload").unwrap();

        assert!(matches!(
            driver.drive_once().unwrap(),
            DriveOutcome::ReconnectDelay {
                sleep_for: Duration::ZERO,
                ..
            }
        ));
        assert_eq!(
            driver.drive_once().unwrap(),
            DriveOutcome::Reconnected {
                reason: ReconnectReason::Disconnect,
            }
        );
        assert_eq!(driver.send_core.transport.restart_attempts, 2);
        assert_eq!(
            driver.send_core.transport.sent_payloads,
            vec![b"payload".to_vec()]
        );
        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Published { fsn: 0 }
        );
        assert_eq!(
            drain_events(&mut driver),
            vec![
                DriverEvent::Published { fsn: 0 },
                DriverEvent::Sent {
                    fsn: 0,
                    wire_seq: 0,
                },
                DriverEvent::Reconnected {
                    reason: ReconnectReason::Disconnect,
                },
            ]
        );
    }

    fn paced_policy() -> ReconnectPolicy {
        ReconnectPolicy::bounded(
            Duration::from_secs(10),
            Duration::from_millis(100),
            Duration::from_secs(1),
        )
    }

    fn assert_pace_range(actual: Duration, min: Duration, max: Duration) {
        assert!(
            actual >= min && actual < max,
            "pace {actual:?} outside [{min:?}, {max:?})"
        );
    }

    #[test]
    fn retriable_nack_below_threshold_paces_before_first_reconnect_attempt() {
        let transport = TestTransport::scripted([Ok(TransportSendResult::Response(
            TransportResponse::Reject {
                wire_seq: 0,
                error: write_error("write failed"),
            },
        ))])
        .with_restart_results([Ok(())]);
        let mut driver = QwpWsCoreTestHarness::from_queue_with_reconnect_policy(
            memory_queue(options(8, 1024, 4)),
            transport,
            paced_policy(),
            false,
        );
        driver.try_submit(b"payload").unwrap();

        match driver.drive_once().unwrap() {
            DriveOutcome::ReconnectDelay { sleep_for, .. } => {
                assert_pace_range(
                    sleep_for,
                    Duration::from_millis(100),
                    Duration::from_millis(200),
                );
            }
            other => panic!("expected paced reconnect delay, got {other:?}"),
        }
        assert_eq!(driver.send_core.transport.restart_attempts, 0);

        assert_eq!(
            driver.drive_once().unwrap(),
            DriveOutcome::Reconnected {
                reason: ReconnectReason::RetryableFailure
            }
        );
        assert_eq!(driver.send_core.transport.restart_attempts, 1);
    }

    #[test]
    fn second_same_frame_strike_doubles_pace_dose() {
        let transport = TestTransport::scripted([
            Ok(TransportSendResult::Response(TransportResponse::Reject {
                wire_seq: 0,
                error: write_error("write failed once"),
            })),
            Ok(TransportSendResult::Response(TransportResponse::Reject {
                wire_seq: 0,
                error: write_error("write failed twice"),
            })),
        ])
        .with_restart_results([Ok(()), Ok(())]);
        let mut driver = QwpWsCoreTestHarness::from_queue_with_reconnect_policy(
            memory_queue(options(8, 1024, 4)),
            transport,
            paced_policy(),
            false,
        );
        driver.try_submit(b"payload").unwrap();

        match driver.drive_once().unwrap() {
            DriveOutcome::ReconnectDelay { sleep_for, .. } => {
                assert_pace_range(
                    sleep_for,
                    Duration::from_millis(100),
                    Duration::from_millis(200),
                );
            }
            other => panic!("expected first paced reconnect delay, got {other:?}"),
        }
        assert_eq!(
            driver.drive_once().unwrap(),
            DriveOutcome::Reconnected {
                reason: ReconnectReason::RetryableFailure
            }
        );
        match driver.drive_once().unwrap() {
            DriveOutcome::ReconnectDelay { sleep_for, .. } => {
                assert_pace_range(
                    sleep_for,
                    Duration::from_millis(200),
                    Duration::from_millis(400),
                );
            }
            other => panic!("expected second paced reconnect delay, got {other:?}"),
        }
        assert_eq!(driver.send_core.transport.restart_attempts, 1);
    }

    #[test]
    fn not_writable_reject_reconnects_immediately_without_pace() {
        let transport = TestTransport::scripted([Ok(TransportSendResult::Response(
            TransportResponse::Reject {
                wire_seq: 0,
                error: not_writable_error("replica access is read-only"),
            },
        ))])
        .with_restart_results([Ok(())]);
        let mut driver = QwpWsCoreTestHarness::from_queue_with_reconnect_policy(
            memory_queue(options(8, 1024, 4)),
            transport,
            paced_policy(),
            false,
        );
        driver.try_submit(b"payload").unwrap();

        assert_eq!(
            driver.drive_once().unwrap(),
            DriveOutcome::Reconnected {
                reason: ReconnectReason::NotWritable
            }
        );
        assert_eq!(driver.send_core.transport.restart_attempts, 1);
    }

    #[test]
    fn presend_reject_paces_with_min_one_strike() {
        let transport = TestTransport::scripted([]).with_restart_results([Ok(())]);
        let mut driver = QwpWsCoreTestHarness::from_queue_with_reconnect_policy(
            memory_queue(options(8, 1024, 4)),
            transport,
            paced_policy(),
            false,
        );
        driver.try_submit(b"payload").unwrap();

        match driver
            .send_core
            .finish_response(
                &mut driver.store,
                TransportResponse::Reject {
                    wire_seq: 0,
                    error: write_error("pre-send reject"),
                },
            )
            .unwrap()
        {
            DriveOutcome::ReconnectDelay { sleep_for, .. } => {
                assert_pace_range(
                    sleep_for,
                    Duration::from_millis(100),
                    Duration::from_millis(200),
                );
            }
            other => panic!("expected paced reconnect delay, got {other:?}"),
        }
        assert_eq!(driver.send_core.transport.restart_attempts, 0);
    }

    #[test]
    fn zero_initial_backoff_keeps_legacy_immediate_reconnect() {
        let transport = TestTransport::scripted([Ok(TransportSendResult::Response(
            TransportResponse::Reject {
                wire_seq: 0,
                error: write_error("write failed"),
            },
        ))])
        .with_restart_results([Ok(())]);
        let mut driver = QwpWsCoreTestHarness::from_queue_with_reconnect_policy(
            memory_queue(options(8, 1024, 4)),
            transport,
            ReconnectPolicy::no_backoff(Duration::MAX),
            false,
        );
        driver.try_submit(b"payload").unwrap();

        assert_eq!(
            driver.drive_once().unwrap(),
            DriveOutcome::Reconnected {
                reason: ReconnectReason::RetryableFailure
            }
        );
        assert_eq!(driver.send_core.transport.restart_attempts, 1);
    }

    #[test]
    fn server_close_below_threshold_paces_reconnect() {
        let transport = TestTransport::scripted([Ok(TransportSendResult::NoResponse)])
            .with_poll_events([Err(TransportFailure::ServerClose(fake_transport_error(
                "server close",
            )))])
            .with_restart_results([Ok(())]);
        let mut driver = QwpWsCoreTestHarness::from_queue_with_reconnect_policy(
            memory_queue(options(8, 1024, 4)),
            transport,
            paced_policy(),
            false,
        );
        driver.try_submit(b"payload").unwrap();

        match driver.drive_once().unwrap() {
            DriveOutcome::ReconnectDelay { sleep_for, .. } => {
                assert_pace_range(
                    sleep_for,
                    Duration::from_millis(100),
                    Duration::from_millis(200),
                );
            }
            other => panic!("expected paced reconnect delay, got {other:?}"),
        }
        assert_eq!(driver.send_core.transport.restart_attempts, 0);
    }

    #[test]
    fn role_reject_reconnect_sleep_uses_fixed_initial_backoff() {
        let initial = Duration::from_millis(100);
        let current = Duration::from_millis(400);

        assert_eq!(reconnect_sleep_duration(true, initial, current), initial);
        assert_eq!(
            reconnect_sleep_duration(false, initial, Duration::ZERO),
            Duration::ZERO
        );
    }

    #[test]
    fn centered_jitter_reconnect_sleep_scatters_around_backoff() {
        // Non-role-reject reconnects use centered jitter: sleep in
        // [base/2, 3*base/2), centered on the backoff.
        let unused_initial = Duration::from_millis(100);
        for base_ms in [2u64, 80, 100, 1_000, 5_000] {
            let base = Duration::from_millis(base_ms);
            for _ in 0..10_000 {
                let d = reconnect_sleep_duration(false, unused_initial, base);
                assert!(
                    d >= base / 2 && d < base + base / 2,
                    "centered-jitter sleep {d:?} outside [base/2, 3*base/2) for base={base:?}"
                );
            }
        }
    }

    #[test]
    fn pace_dose_doubles_per_strike_and_caps_at_max_backoff() {
        let initial = Duration::from_millis(100);
        let max = Duration::from_millis(1000);

        assert_eq!(pace_dose(initial, max, 0), Duration::from_millis(100));
        assert_eq!(pace_dose(initial, max, 1), Duration::from_millis(100));
        assert_eq!(pace_dose(initial, max, 2), Duration::from_millis(200));
        assert_eq!(pace_dose(initial, max, 3), Duration::from_millis(400));
        assert_eq!(pace_dose(initial, max, 4), Duration::from_millis(800));
        assert_eq!(pace_dose(initial, max, 5), Duration::from_millis(1000));
        assert_eq!(pace_dose(initial, max, 99), Duration::from_millis(1000));
        assert_eq!(
            pace_dose(Duration::ZERO, max, 4),
            Duration::ZERO,
            "zero initial backoff preserves legacy immediate reconnects"
        );
    }

    #[test]
    fn pace_jitter_stays_within_one_to_two_dose() {
        for dose_ms in [1u64, 80, 100, 1_000] {
            let dose = Duration::from_millis(dose_ms);
            for _ in 0..10_000 {
                let d = pace_jitter_duration(dose);
                assert!(
                    d >= dose && d < dose + dose,
                    "paced jitter {d:?} outside [dose, 2*dose) for dose={dose:?}"
                );
            }
        }
    }

    #[test]
    fn poison_tracker_dwell_holds_escalation_until_window_elapses() {
        let mut tracker = PoisonFrameTracker::default();
        let started = Instant::now();
        let window = Duration::from_secs(5);

        assert!(!tracker.record_failure(7, None, 2, window, started));
        assert!(!tracker.record_failure(7, None, 2, window, started + Duration::from_secs(1)));
        assert_eq!(tracker.strikes(), 2);
        assert!(tracker.record_failure(7, None, 2, window, started + window));
        assert_eq!(tracker.strikes(), 3);
    }

    #[test]
    fn poison_tracker_dwell_restamps_when_suspect_key_changes() {
        let mut tracker = PoisonFrameTracker::default();
        let started = Instant::now();
        let window = Duration::from_secs(5);

        assert!(!tracker.record_failure(7, None, 2, window, started));
        assert!(!tracker.record_failure(8, None, 2, window, started + Duration::from_secs(10)));
        assert_eq!(tracker.strikes(), 1);
        assert!(!tracker.record_failure(8, None, 2, window, started + Duration::from_secs(11)));
        assert!(tracker.record_failure(8, None, 2, window, started + Duration::from_secs(15)));
    }

    #[test]
    fn poison_tracker_window_zero_escalates_exactly_at_threshold() {
        let mut tracker = PoisonFrameTracker::default();
        let started = Instant::now();

        assert!(!tracker.record_failure(7, None, 2, Duration::ZERO, started));
        assert!(tracker.record_failure(7, None, 2, Duration::ZERO, started));
    }

    #[test]
    fn poison_tracker_clear_resets_first_strike_timestamp() {
        let mut tracker = PoisonFrameTracker::default();
        let started = Instant::now();
        let window = Duration::from_secs(5);

        assert!(!tracker.record_failure(7, None, 2, window, started));
        tracker.clear();
        assert_eq!(tracker.strikes(), 0);
        assert!(!tracker.record_failure(7, None, 1, window, started + Duration::from_secs(10)));
    }

    #[test]
    fn reconnect_terminal_classification_keeps_protocol_version_errors_terminal() {
        let durable_ack_mismatch = Error::new(
            ErrorCode::ProtocolVersionError,
            "server did not enable durable ACK",
        );
        assert!(reconnect_error_is_terminal(&durable_ack_mismatch));

        let retryable_upgrade_version_error =
            Error::new(ErrorCode::SocketError, "unsupported X-QWP-Version");
        assert!(!reconnect_error_is_terminal(
            &retryable_upgrade_version_error
        ));
    }

    #[test]
    fn reconnect_terminal_classification_retries_structured_role_rejects() {
        let all_role_rejected = Error::new(
            ErrorCode::ProtocolVersionError,
            "server did not enable durable ACK; all endpoints rejected by role",
        )
        .with_qwp_ws_role_reject(crate::ingress::QwpWsRoleReject::new("REPLICA", None));

        assert!(!reconnect_error_is_terminal(&all_role_rejected));
    }

    #[test]
    fn transport_write_failure_does_not_commit_sent_receipt() {
        let transport = TestTransport::scripted([Err(TransportFailure::Disconnect(
            fake_transport_error("write failed"),
        ))]);
        let mut driver =
            QwpWsCoreTestHarness::from_queue(memory_queue(options(8, 1024, 4)), transport);
        let receipt = driver.try_submit(b"payload").unwrap();

        assert_eq!(
            driver.drive_once().unwrap(),
            DriveOutcome::Reconnected {
                reason: ReconnectReason::Disconnect,
            }
        );
        assert_eq!(
            driver.send_core.transport.sent_payloads,
            vec![b"payload".to_vec()]
        );
        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Published { fsn: 0 }
        );
        assert_eq!(
            drain_events(&mut driver),
            vec![
                DriverEvent::Published { fsn: 0 },
                DriverEvent::Reconnected {
                    reason: ReconnectReason::Disconnect,
                },
            ]
        );
    }

    #[test]
    fn transport_poll_failure_enters_reconnect_policy() {
        let transport = TestTransport::scripted([Ok(TransportSendResult::NoResponse)])
            .with_poll_results([Err(TransportFailure::Disconnect(fake_transport_error(
                "poll failed",
            )))]);
        let mut driver =
            QwpWsCoreTestHarness::from_queue(memory_queue(options(8, 1024, 4)), transport);
        let receipt = driver.try_submit(b"payload").unwrap();

        assert_eq!(
            driver.drive_once().unwrap(),
            DriveOutcome::Reconnected {
                reason: ReconnectReason::Disconnect,
            }
        );
        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Published { fsn: 0 }
        );
        assert_eq!(
            drain_events(&mut driver),
            vec![
                DriverEvent::Published { fsn: 0 },
                DriverEvent::Sent {
                    fsn: 0,
                    wire_seq: 0,
                },
                DriverEvent::Reconnected {
                    reason: ReconnectReason::Disconnect,
                },
            ]
        );
    }

    #[test]
    fn raw_qwp_schema_and_write_errors_decode_as_rejections() {
        for (status, expected_code) in [
            (codec::WS_STATUS_SCHEMA_MISMATCH, ErrorCode::InvalidApiCall),
            (codec::WS_STATUS_WRITE_ERROR, ErrorCode::ServerFlushError),
        ] {
            let payload = qwp_error_payload(status, 42, "server says no");

            let response = decode_transport_response(&payload).unwrap().unwrap();

            match response {
                TransportResponse::Reject { wire_seq, error } => {
                    assert_eq!(wire_seq, 42);
                    assert_eq!(error.status, status);
                    assert_eq!(error.message, "server says no");
                    assert_eq!(error.error.code(), expected_code);
                    assert!(error.error.msg().contains("server says no"));
                }
                other => panic!("unexpected response: {other:?}"),
            }
        }
    }

    /// `cargo test --features sync-sender-qwp-ws --lib non_durable_ok_decode_with_table_entries_zero_alloc_after_warmup -- --ignored --test-threads=1`
    #[test]
    #[ignore = "uses the process-global allocation counter"]
    fn non_durable_ok_decode_with_table_entries_zero_alloc_after_warmup() {
        use crate::alloc_counter;

        let payload = qwp_ok_payload_with_table_entries(7, &[("table_a", 42), ("table_b", -7)]);
        assert!(matches!(
            decode_transport_response(&payload).unwrap(),
            Some(TransportResponse::Ack { wire_seq: 7 })
        ));

        alloc_counter::start_counting();
        let response = decode_transport_response(&payload).unwrap();
        let alloc_count = alloc_counter::stop_counting();

        assert!(matches!(
            response,
            Some(TransportResponse::Ack { wire_seq: 7 })
        ));
        assert_eq!(
            alloc_count, 0,
            "Expected zero allocations for non-durable OK decode, got {alloc_count}"
        );
    }

    #[test]
    fn durable_decode_preserves_ok_and_durable_ack_table_entries() {
        let ok_payload = qwp_ok_payload_with_table_entries(7, &[("table_a", 42)]);
        assert_eq!(
            decode_durable_transport_response(&ok_payload).unwrap(),
            Some(TransportResponse::DurableOk {
                wire_seq: 7,
                table_seq_txns: table_seq_txns(&[("table_a", 42)])
            })
        );

        let durable_ack_payload = qwp_durable_ack_payload(&[("table_a", 42), ("table_b", 99)]);
        assert_eq!(
            decode_durable_transport_response(&durable_ack_payload).unwrap(),
            Some(TransportResponse::DurableAck {
                table_seq_txns: table_seq_txns(&[("table_a", 42), ("table_b", 99)])
            })
        );
    }

    #[test]
    fn malformed_qwp_response_frames_are_retryable_failures() {
        let failure = decode_transport_response(&[codec::WS_STATUS_OK]).unwrap_err();
        assert_retryable_transport_failure(failure, "QWP OK response truncated");

        let failure =
            decode_durable_transport_response(&[codec::WS_STATUS_DURABLE_ACK]).unwrap_err();
        assert_retryable_transport_failure(failure, "QWP durable ACK response truncated");
    }

    fn assert_retryable_transport_failure(failure: TransportFailure, expected_message: &str) {
        match failure {
            TransportFailure::Retryable(error) => assert!(
                error.msg().contains(expected_message),
                "expected error message containing {expected_message:?}, got {:?}",
                error.msg()
            ),
            other => panic!("expected retryable transport failure, got {other:?}"),
        }
    }

    #[test]
    fn durable_pending_ok_triggers_ready_keepalive() {
        let transport = TestTransport::scripted([Ok(TransportSendResult::NoResponse)])
            .with_poll_results([
                Ok(Some(TransportResponse::DurableOk {
                    wire_seq: 0,
                    table_seq_txns: table_seq_txns(&[("trades", 10)]),
                })),
                Ok(None),
            ])
            .with_keepalive_results([Ok(false), Ok(true)]);
        let mut driver = QwpWsCoreTestHarness::from_queue_with_durable_ack(
            memory_queue(options(8, 1024, 4)),
            transport,
        );
        let receipt = driver.try_submit(b"payload").unwrap();

        assert!(matches!(
            driver.drive_once().unwrap(),
            DriveOutcome::Sent(_)
        ));
        assert_eq!(driver.drive_once().unwrap(), DriveOutcome::Idle);
        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Sent {
                fsn: 0,
                wire_seq: 0,
            }
        );

        assert_eq!(driver.drive_once().unwrap(), DriveOutcome::Idle);
        assert_eq!(driver.send_core.transport.keepalive_attempts, 2);
        assert_eq!(
            driver.send_core.transport.keepalive_pending_args,
            vec![true, true]
        );
    }

    #[test]
    fn durable_keepalive_disconnect_reports_reconnect() {
        let transport = TestTransport::scripted([Ok(TransportSendResult::NoResponse)])
            .with_poll_results([
                Ok(Some(TransportResponse::DurableOk {
                    wire_seq: 0,
                    table_seq_txns: table_seq_txns(&[("trades", 10)]),
                })),
                Ok(None),
            ])
            .with_keepalive_results([Err(TransportFailure::Disconnect(fake_transport_error(
                "keepalive disconnect",
            )))])
            .with_restart_results([Ok(())]);
        let mut driver = QwpWsCoreTestHarness::from_queue_with_durable_ack(
            memory_queue(options(8, 1024, 4)),
            transport,
        );
        driver.try_submit(b"payload").unwrap();

        assert!(matches!(
            driver.drive_once().unwrap(),
            DriveOutcome::Sent(_)
        ));
        assert_eq!(
            driver.drive_once().unwrap(),
            DriveOutcome::Reconnected {
                reason: ReconnectReason::Disconnect
            }
        );
        assert_eq!(driver.send_core.transport.keepalive_attempts, 1);
        assert_eq!(driver.send_core.transport.restart_attempts, 1);
    }

    #[test]
    fn durable_keepalive_terminal_failure_reports_terminal() {
        let transport = TestTransport::scripted([Ok(TransportSendResult::NoResponse)])
            .with_poll_results([
                Ok(Some(TransportResponse::DurableOk {
                    wire_seq: 0,
                    table_seq_txns: table_seq_txns(&[("trades", 10)]),
                })),
                Ok(None),
            ])
            .with_keepalive_results([Err(TransportFailure::Terminal(fake_transport_error(
                "terminal keepalive failure",
            )))]);
        let mut driver = QwpWsCoreTestHarness::from_queue_with_durable_ack(
            memory_queue(options(8, 1024, 4)),
            transport,
        );
        driver.try_submit(b"payload").unwrap();

        assert!(matches!(
            driver.drive_once().unwrap(),
            DriveOutcome::Sent(_)
        ));
        assert_eq!(driver.drive_once().unwrap(), DriveOutcome::Terminal);
        assert!(driver.is_terminal());
        assert_eq!(driver.send_core.transport.keepalive_attempts, 1);
    }

    #[test]
    fn consumed_durable_ok_is_progress_and_does_not_send_keepalive() {
        let transport = TestTransport::scripted([Ok(TransportSendResult::NoResponse)])
            .with_poll_results([
                Ok(Some(TransportResponse::DurableOk {
                    wire_seq: 0,
                    table_seq_txns: table_seq_txns(&[("trades", 10)]),
                })),
                Ok(None),
            ])
            .with_keepalive_results([Ok(true)]);
        let mut driver = QwpWsCoreTestHarness::from_queue_with_durable_ack(
            memory_queue(options(8, 1024, 4)),
            transport,
        );
        let receipt = driver.try_submit(b"payload").unwrap();

        assert!(matches!(
            driver.drive_send_once().unwrap(),
            DriveOutcome::Sent(_)
        ));
        assert_eq!(driver.drive_once().unwrap(), DriveOutcome::Progress);
        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Sent {
                fsn: 0,
                wire_seq: 0,
            }
        );
        assert_eq!(driver.send_core.transport.keepalive_attempts, 0);
    }

    #[test]
    fn drive_ready_drains_control_progress_and_durable_ack_until_idle() {
        let transport = TestTransport::scripted([Ok(TransportSendResult::NoResponse)])
            .with_poll_events([
                Ok(TransportPoll::Response(TransportResponse::DurableOk {
                    wire_seq: 0,
                    table_seq_txns: table_seq_txns(&[("trades", 10)]),
                })),
                Ok(TransportPoll::Progress),
                Ok(TransportPoll::Response(TransportResponse::DurableAck {
                    table_seq_txns: table_seq_txns(&[("trades", 10)]),
                })),
                Ok(TransportPoll::Idle),
            ])
            .with_keepalive_results([Ok(true)]);
        let mut driver = QwpWsCoreTestHarness::from_queue_with_durable_ack(
            memory_queue(options(8, 1024, 4)),
            transport,
        );
        let receipt = driver.try_submit(b"payload").unwrap();

        assert_eq!(
            driver.drive_once().unwrap(),
            DriveOutcome::Acked { wire_seq: 0 }
        );
        assert!(matches!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Completed { fsn: 0 }
        ));
        assert_eq!(driver.send_core.transport.keepalive_attempts, 0);
    }

    #[test]
    fn durable_ok_releases_send_window_without_completing_receipt() {
        let mut server = FakeOrderedServer::no_response();
        server.push_response(TransportResponse::DurableOk {
            wire_seq: 0,
            table_seq_txns: table_seq_txns(&[("trades", 10)]),
        });
        let mut driver = durable_driver_with_options(options(4, 1024, 2), server);
        let first = driver.try_submit(b"first").unwrap();
        let second = driver.try_submit(b"second").unwrap();

        assert!(matches!(
            driver.drive_send_once().unwrap(),
            DriveOutcome::Sent(_)
        ));
        assert_eq!(driver.drive_receive_once().unwrap(), DriveOutcome::Progress);

        assert_eq!(driver.acked_fsn(), None);
        assert_eq!(
            driver.receipt_status(first),
            QwpReceiptStatus::Sent {
                fsn: 0,
                wire_seq: 0
            }
        );
        assert_eq!(
            driver.drive_send_once().unwrap(),
            DriveOutcome::Sent(SentFrame {
                fsn: 1,
                wire_seq: 1,
                payload_len: 6,
            })
        );
        assert_eq!(
            driver.receipt_status(second),
            QwpReceiptStatus::Sent {
                fsn: 1,
                wire_seq: 1
            }
        );
    }

    #[test]
    fn durable_ack_covering_pending_ok_advances_acked_fsn() {
        let mut driver = durable_driver(FakeOrderedServer::no_response());
        let receipt = driver.try_submit(b"payload").unwrap();

        assert!(matches!(
            driver.drive_send_once().unwrap(),
            DriveOutcome::Sent(_)
        ));
        driver
            .send_core
            .transport
            .push_response(TransportResponse::DurableOk {
                wire_seq: 0,
                table_seq_txns: table_seq_txns(&[("trades", 10)]),
            });
        assert_eq!(driver.drive_receive_once().unwrap(), DriveOutcome::Progress);

        driver
            .send_core
            .transport
            .push_response(TransportResponse::DurableAck {
                table_seq_txns: table_seq_txns(&[("trades", 10)]),
            });
        assert_eq!(
            driver.drive_receive_once().unwrap(),
            DriveOutcome::Acked { wire_seq: 0 }
        );

        assert_eq!(driver.acked_fsn(), Some(0));
        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Completed { fsn: 0 }
        );
    }

    #[test]
    fn future_durable_ok_wire_sequence_clamps_to_highest_sent_like_java() {
        let mut driver = durable_driver(FakeOrderedServer::no_response());
        let receipt = driver.try_submit(b"payload").unwrap();

        assert!(matches!(
            driver.drive_send_once().unwrap(),
            DriveOutcome::Sent(SentFrame { wire_seq: 0, .. })
        ));
        driver
            .send_core
            .transport
            .push_response(TransportResponse::DurableOk {
                wire_seq: 99,
                table_seq_txns: table_seq_txns(&[("trades", 10)]),
            });
        assert_eq!(driver.drive_receive_once().unwrap(), DriveOutcome::Progress);
        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Sent {
                fsn: 0,
                wire_seq: 0
            }
        );

        driver
            .send_core
            .transport
            .push_response(TransportResponse::DurableAck {
                table_seq_txns: table_seq_txns(&[("trades", 10)]),
            });
        assert_eq!(
            driver.drive_receive_once().unwrap(),
            DriveOutcome::Acked { wire_seq: 0 }
        );
        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Completed { fsn: 0 }
        );
    }

    #[test]
    fn future_durable_reject_wire_sequence_reconnects_from_highest_sent_like_java_v2() {
        let mut driver = durable_driver(FakeOrderedServer::no_response());
        let first = driver.try_submit(b"first").unwrap();
        let second = driver.try_submit(b"second").unwrap();

        driver.drive_send_once().unwrap();
        driver.drive_send_once().unwrap();
        driver
            .send_core
            .transport
            .push_response(TransportResponse::DurableOk {
                wire_seq: 0,
                table_seq_txns: table_seq_txns(&[("trades", 10)]),
            });
        assert_eq!(driver.drive_receive_once().unwrap(), DriveOutcome::Progress);
        driver
            .send_core
            .transport
            .push_response(TransportResponse::Reject {
                wire_seq: 99,
                error: write_error("write failed"),
            });

        assert_eq!(
            driver.drive_receive_once().unwrap(),
            DriveOutcome::Reconnected {
                reason: ReconnectReason::RetryableFailure
            }
        );
        assert_eq!(
            driver.receipt_status(first),
            QwpReceiptStatus::Published { fsn: 0 }
        );
        assert_eq!(
            driver.receipt_status(second),
            QwpReceiptStatus::Published { fsn: 1 }
        );

        let error = driver.poll_sender_error().unwrap();
        assert_eq!(error.message_sequence, Some(99));
        assert_eq!(error.from_fsn, 1);
        assert_eq!(error.to_fsn, 1);
    }

    #[test]
    fn late_future_durable_reject_for_acked_frame_reports_error_without_reblocking_tracker() {
        let mut driver = durable_driver(FakeOrderedServer::no_response());
        let receipt = driver.try_submit(b"payload").unwrap();

        assert!(matches!(
            driver.drive_send_once().unwrap(),
            DriveOutcome::Sent(SentFrame { fsn: 0, .. })
        ));
        driver
            .send_core
            .transport
            .push_response(TransportResponse::DurableOk {
                wire_seq: 0,
                table_seq_txns: table_seq_txns(&[("trades", 10)]),
            });
        assert_eq!(driver.drive_receive_once().unwrap(), DriveOutcome::Progress);
        driver
            .send_core
            .transport
            .push_response(TransportResponse::DurableAck {
                table_seq_txns: table_seq_txns(&[("trades", 10)]),
            });
        assert_eq!(
            driver.drive_receive_once().unwrap(),
            DriveOutcome::Acked { wire_seq: 0 }
        );
        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Completed { fsn: 0 }
        );
        assert_eq!(driver.poll_sender_error(), None);

        driver
            .send_core
            .transport
            .push_response(TransportResponse::Reject {
                wire_seq: 99,
                error: write_error("late write failure"),
            });
        assert_eq!(driver.drive_receive_once().unwrap(), DriveOutcome::Progress);
        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Completed { fsn: 0 }
        );

        let error = driver.poll_sender_error().unwrap();
        assert_eq!(error.applied_policy, QwpWsErrorPolicy::Retriable);
        assert_eq!(error.message_sequence, Some(99));
        assert_eq!(error.from_fsn, 0);
        assert_eq!(error.to_fsn, 0);
    }

    #[test]
    fn future_durable_reject_for_pending_ok_reports_error_without_duplicate_tracker_entry() {
        let mut driver = durable_driver(FakeOrderedServer::no_response());
        let receipt = driver.try_submit(b"payload").unwrap();

        assert!(matches!(
            driver.drive_send_once().unwrap(),
            DriveOutcome::Sent(SentFrame { fsn: 0, .. })
        ));
        driver
            .send_core
            .transport
            .push_response(TransportResponse::DurableOk {
                wire_seq: 99,
                table_seq_txns: table_seq_txns(&[("trades", 10)]),
            });
        assert_eq!(driver.drive_receive_once().unwrap(), DriveOutcome::Progress);
        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Sent {
                fsn: 0,
                wire_seq: 0
            }
        );

        driver
            .send_core
            .transport
            .push_response(TransportResponse::Reject {
                wire_seq: 99,
                error: write_error("late write failure"),
            });
        assert_eq!(driver.drive_receive_once().unwrap(), DriveOutcome::Progress);
        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Sent {
                fsn: 0,
                wire_seq: 0
            }
        );

        let error = driver.poll_sender_error().unwrap();
        assert_eq!(error.applied_policy, QwpWsErrorPolicy::Retriable);
        assert_eq!(error.message_sequence, Some(99));
        assert_eq!(error.from_fsn, 0);
        assert_eq!(error.to_fsn, 0);

        driver
            .send_core
            .transport
            .push_response(TransportResponse::DurableAck {
                table_seq_txns: table_seq_txns(&[("trades", 10)]),
            });
        assert_eq!(
            driver.drive_receive_once().unwrap(),
            DriveOutcome::Acked { wire_seq: 0 }
        );
        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Completed { fsn: 0 }
        );
        assert_eq!(driver.poll_sender_error(), None);
    }

    #[test]
    fn durable_ack_does_not_skip_earlier_pending_ok_gap() {
        let mut driver = durable_driver(FakeOrderedServer::no_response());
        let first = driver.try_submit(b"first").unwrap();
        let second = driver.try_submit(b"second").unwrap();

        assert!(matches!(
            driver.drive_send_once().unwrap(),
            DriveOutcome::Sent(SentFrame { wire_seq: 0, .. })
        ));
        assert!(matches!(
            driver.drive_send_once().unwrap(),
            DriveOutcome::Sent(SentFrame { wire_seq: 1, .. })
        ));
        driver
            .send_core
            .transport
            .push_response(TransportResponse::DurableOk {
                wire_seq: 0,
                table_seq_txns: table_seq_txns(&[("a", 10)]),
            });
        driver
            .send_core
            .transport
            .push_response(TransportResponse::DurableOk {
                wire_seq: 1,
                table_seq_txns: table_seq_txns(&[("b", 20)]),
            });
        assert_eq!(driver.drive_receive_once().unwrap(), DriveOutcome::Progress);
        assert_eq!(driver.drive_receive_once().unwrap(), DriveOutcome::Progress);

        driver
            .send_core
            .transport
            .push_response(TransportResponse::DurableAck {
                table_seq_txns: table_seq_txns(&[("b", 20)]),
            });
        assert_eq!(driver.drive_receive_once().unwrap(), DriveOutcome::Progress);
        assert_eq!(driver.acked_fsn(), None);

        driver
            .send_core
            .transport
            .push_response(TransportResponse::DurableAck {
                table_seq_txns: table_seq_txns(&[("a", 10)]),
            });
        assert_eq!(
            driver.drive_receive_once().unwrap(),
            DriveOutcome::Acked { wire_seq: 1 }
        );

        assert_eq!(
            driver.receipt_status(first),
            QwpReceiptStatus::Completed { fsn: 0 }
        );
        assert_eq!(
            driver.receipt_status(second),
            QwpReceiptStatus::Completed { fsn: 1 }
        );
    }

    #[test]
    fn durable_empty_ok_waits_behind_prior_non_empty_ok() {
        let mut driver = durable_driver(FakeOrderedServer::no_response());
        let first = driver.try_submit(b"first").unwrap();
        let second = driver.try_submit(b"second").unwrap();

        driver.drive_send_once().unwrap();
        driver.drive_send_once().unwrap();
        driver
            .send_core
            .transport
            .push_response(TransportResponse::DurableOk {
                wire_seq: 0,
                table_seq_txns: table_seq_txns(&[("trades", 10)]),
            });
        driver
            .send_core
            .transport
            .push_response(TransportResponse::DurableOk {
                wire_seq: 1,
                table_seq_txns: Vec::new(),
            });
        assert_eq!(driver.drive_receive_once().unwrap(), DriveOutcome::Progress);
        assert_eq!(driver.drive_receive_once().unwrap(), DriveOutcome::Progress);
        assert_eq!(driver.acked_fsn(), None);

        driver
            .send_core
            .transport
            .push_response(TransportResponse::DurableAck {
                table_seq_txns: table_seq_txns(&[("trades", 10)]),
            });
        assert_eq!(
            driver.drive_receive_once().unwrap(),
            DriveOutcome::Acked { wire_seq: 1 }
        );

        assert_eq!(
            driver.receipt_status(first),
            QwpReceiptStatus::Completed { fsn: 0 }
        );
        assert_eq!(
            driver.receipt_status(second),
            QwpReceiptStatus::Completed { fsn: 1 }
        );
    }

    #[test]
    fn stale_durable_ack_watermark_does_not_move_tracker_backwards() {
        let mut driver = durable_driver(FakeOrderedServer::no_response());
        let first = driver.try_submit(b"first").unwrap();
        let second = driver.try_submit(b"second").unwrap();

        driver.drive_send_once().unwrap();
        driver.drive_send_once().unwrap();
        driver
            .send_core
            .transport
            .push_response(TransportResponse::DurableOk {
                wire_seq: 0,
                table_seq_txns: table_seq_txns(&[("trades", 10)]),
            });
        driver
            .send_core
            .transport
            .push_response(TransportResponse::DurableAck {
                table_seq_txns: table_seq_txns(&[("trades", 10)]),
            });
        assert_eq!(driver.drive_receive_once().unwrap(), DriveOutcome::Progress);
        assert_eq!(
            driver.drive_receive_once().unwrap(),
            DriveOutcome::Acked { wire_seq: 0 }
        );

        driver
            .send_core
            .transport
            .push_response(TransportResponse::DurableOk {
                wire_seq: 1,
                table_seq_txns: table_seq_txns(&[("trades", 12)]),
            });
        assert_eq!(driver.drive_receive_once().unwrap(), DriveOutcome::Progress);
        driver
            .send_core
            .transport
            .push_response(TransportResponse::DurableAck {
                table_seq_txns: table_seq_txns(&[("trades", 9)]),
            });
        assert_eq!(driver.drive_receive_once().unwrap(), DriveOutcome::Progress);
        assert_eq!(
            driver.receipt_status(second),
            QwpReceiptStatus::Sent {
                fsn: 1,
                wire_seq: 1
            }
        );

        driver
            .send_core
            .transport
            .push_response(TransportResponse::DurableAck {
                table_seq_txns: table_seq_txns(&[("trades", 12)]),
            });
        assert_eq!(
            driver.drive_receive_once().unwrap(),
            DriveOutcome::Acked { wire_seq: 1 }
        );
        assert_eq!(
            driver.receipt_status(first),
            QwpReceiptStatus::Completed { fsn: 0 }
        );
        assert_eq!(
            driver.receipt_status(second),
            QwpReceiptStatus::Completed { fsn: 1 }
        );
    }

    #[test]
    fn durable_ack_before_ok_drains_when_ok_later_arrives() {
        let mut driver = durable_driver(FakeOrderedServer::no_response());
        let receipt = driver.try_submit(b"payload").unwrap();

        driver.drive_send_once().unwrap();
        driver
            .send_core
            .transport
            .push_response(TransportResponse::DurableAck {
                table_seq_txns: table_seq_txns(&[("trades", 10)]),
            });
        assert_eq!(driver.drive_receive_once().unwrap(), DriveOutcome::Progress);

        driver
            .send_core
            .transport
            .push_response(TransportResponse::DurableOk {
                wire_seq: 0,
                table_seq_txns: table_seq_txns(&[("trades", 10)]),
            });
        assert_eq!(
            driver.drive_receive_once().unwrap(),
            DriveOutcome::Acked { wire_seq: 0 }
        );
        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Completed { fsn: 0 }
        );
    }

    #[test]
    fn stale_durable_ok_after_completion_does_not_reblock_tracker() {
        let mut driver = durable_driver(FakeOrderedServer::no_response());
        let first = driver.try_submit(b"first").unwrap();
        let second = driver.try_submit(b"second").unwrap();

        driver.drive_send_once().unwrap();
        driver.drive_send_once().unwrap();
        driver
            .send_core
            .transport
            .push_response(TransportResponse::DurableOk {
                wire_seq: 0,
                table_seq_txns: table_seq_txns(&[("trades", 10)]),
            });
        driver
            .send_core
            .transport
            .push_response(TransportResponse::DurableAck {
                table_seq_txns: table_seq_txns(&[("trades", 10)]),
            });
        assert_eq!(driver.drive_receive_once().unwrap(), DriveOutcome::Progress);
        assert_eq!(
            driver.drive_receive_once().unwrap(),
            DriveOutcome::Acked { wire_seq: 0 }
        );

        driver
            .send_core
            .transport
            .push_response(TransportResponse::DurableOk {
                wire_seq: 0,
                table_seq_txns: table_seq_txns(&[("trades", 99)]),
            });
        assert_eq!(
            driver.drive_receive_once().unwrap(),
            DriveOutcome::Acked { wire_seq: 0 }
        );
        driver
            .send_core
            .transport
            .push_response(TransportResponse::DurableOk {
                wire_seq: 1,
                table_seq_txns: table_seq_txns(&[("trades", 12)]),
            });
        driver
            .send_core
            .transport
            .push_response(TransportResponse::DurableAck {
                table_seq_txns: table_seq_txns(&[("trades", 12)]),
            });
        assert_eq!(driver.drive_receive_once().unwrap(), DriveOutcome::Progress);
        assert_eq!(
            driver.drive_receive_once().unwrap(),
            DriveOutcome::Acked { wire_seq: 1 }
        );

        assert_eq!(
            driver.receipt_status(first),
            QwpReceiptStatus::Completed { fsn: 0 }
        );
        assert_eq!(
            driver.receipt_status(second),
            QwpReceiptStatus::Completed { fsn: 1 }
        );
    }

    #[test]
    fn durable_reconnect_clears_pending_ok_tracking_for_replay() {
        let mut driver = durable_driver(FakeOrderedServer::no_response());
        let receipt = driver.try_submit(b"payload").unwrap();

        assert_eq!(
            driver.drive_send_once().unwrap(),
            DriveOutcome::Sent(SentFrame {
                fsn: 0,
                wire_seq: 0,
                payload_len: 7,
            })
        );
        driver
            .send_core
            .transport
            .push_response(TransportResponse::DurableOk {
                wire_seq: 0,
                table_seq_txns: table_seq_txns(&[("trades", 10)]),
            });
        assert_eq!(driver.drive_receive_once().unwrap(), DriveOutcome::Progress);
        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Sent {
                fsn: 0,
                wire_seq: 0
            }
        );

        assert_eq!(
            driver
                .send_core
                .finish_reconnect_success(&mut driver.store, ReconnectReason::Disconnect),
            DriveOutcome::Reconnected {
                reason: ReconnectReason::Disconnect
            }
        );
        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Published { fsn: 0 }
        );
        assert_eq!(
            driver.drive_send_once().unwrap(),
            DriveOutcome::Sent(SentFrame {
                fsn: 0,
                wire_seq: 0,
                payload_len: 7,
            })
        );
    }

    #[test]
    fn durable_reconnect_clears_unresolved_reject_so_replayed_ok_can_complete() {
        let mut driver = durable_driver(FakeOrderedServer::no_response());
        let first = driver.try_submit(b"first").unwrap();
        let second = driver.try_submit(b"second").unwrap();

        driver.drive_send_once().unwrap();
        driver.drive_send_once().unwrap();
        driver
            .send_core
            .transport
            .push_response(TransportResponse::DurableOk {
                wire_seq: 0,
                table_seq_txns: table_seq_txns(&[("trades", 10)]),
            });
        driver
            .send_core
            .transport
            .push_response(TransportResponse::Reject {
                wire_seq: 1,
                error: write_error("write failed"),
            });
        assert_eq!(driver.drive_receive_once().unwrap(), DriveOutcome::Progress);
        assert_eq!(
            driver.drive_receive_once().unwrap(),
            DriveOutcome::Reconnected {
                reason: ReconnectReason::RetryableFailure
            }
        );
        assert_eq!(
            driver.receipt_status(second),
            QwpReceiptStatus::Published { fsn: 1 }
        );

        assert_eq!(
            driver
                .send_core
                .finish_reconnect_success(&mut driver.store, ReconnectReason::Disconnect),
            DriveOutcome::Reconnected {
                reason: ReconnectReason::Disconnect
            }
        );
        assert_eq!(
            driver.receipt_status(second),
            QwpReceiptStatus::Published { fsn: 1 }
        );

        assert!(matches!(
            driver.drive_send_once().unwrap(),
            DriveOutcome::Sent(SentFrame { fsn: 0, .. })
        ));
        assert!(matches!(
            driver.drive_send_once().unwrap(),
            DriveOutcome::Sent(SentFrame { fsn: 1, .. })
        ));
        driver
            .send_core
            .transport
            .push_response(TransportResponse::DurableOk {
                wire_seq: 0,
                table_seq_txns: table_seq_txns(&[("trades", 10)]),
            });
        driver
            .send_core
            .transport
            .push_response(TransportResponse::DurableAck {
                table_seq_txns: table_seq_txns(&[("trades", 10)]),
            });
        driver
            .send_core
            .transport
            .push_response(TransportResponse::DurableOk {
                wire_seq: 1,
                table_seq_txns: table_seq_txns(&[("quotes", 20)]),
            });
        driver
            .send_core
            .transport
            .push_response(TransportResponse::DurableAck {
                table_seq_txns: table_seq_txns(&[("quotes", 20)]),
            });

        assert_eq!(driver.drive_receive_once().unwrap(), DriveOutcome::Progress);
        assert_eq!(
            driver.drive_receive_once().unwrap(),
            DriveOutcome::Acked { wire_seq: 0 }
        );
        assert_eq!(driver.drive_receive_once().unwrap(), DriveOutcome::Progress);
        assert_eq!(
            driver.drive_receive_once().unwrap(),
            DriveOutcome::Acked { wire_seq: 1 }
        );
        assert_eq!(
            driver.receipt_status(first),
            QwpReceiptStatus::Completed { fsn: 0 }
        );
        assert_eq!(
            driver.receipt_status(second),
            QwpReceiptStatus::Completed { fsn: 1 }
        );
        assert_eq!(driver.acked_fsn(), Some(1));
    }

    #[test]
    fn durable_reconnect_clears_unresolved_reject_so_replayed_reject_retries_again() {
        let mut driver = durable_driver(FakeOrderedServer::no_response());
        let first = driver.try_submit(b"first").unwrap();
        let second = driver.try_submit(b"second").unwrap();

        driver.drive_send_once().unwrap();
        driver.drive_send_once().unwrap();
        driver
            .send_core
            .transport
            .push_response(TransportResponse::DurableOk {
                wire_seq: 0,
                table_seq_txns: table_seq_txns(&[("trades", 10)]),
            });
        driver
            .send_core
            .transport
            .push_response(TransportResponse::Reject {
                wire_seq: 1,
                error: write_error("write failed"),
            });
        assert_eq!(driver.drive_receive_once().unwrap(), DriveOutcome::Progress);
        assert_eq!(
            driver.drive_receive_once().unwrap(),
            DriveOutcome::Reconnected {
                reason: ReconnectReason::RetryableFailure
            }
        );

        assert_eq!(
            driver
                .send_core
                .finish_reconnect_success(&mut driver.store, ReconnectReason::Disconnect),
            DriveOutcome::Reconnected {
                reason: ReconnectReason::Disconnect
            }
        );

        assert!(matches!(
            driver.drive_send_once().unwrap(),
            DriveOutcome::Sent(SentFrame { fsn: 0, .. })
        ));
        assert!(matches!(
            driver.drive_send_once().unwrap(),
            DriveOutcome::Sent(SentFrame { fsn: 1, .. })
        ));
        driver
            .send_core
            .transport
            .push_response(TransportResponse::DurableOk {
                wire_seq: 0,
                table_seq_txns: table_seq_txns(&[("trades", 10)]),
            });
        driver
            .send_core
            .transport
            .push_response(TransportResponse::DurableAck {
                table_seq_txns: table_seq_txns(&[("trades", 10)]),
            });
        driver
            .send_core
            .transport
            .push_response(TransportResponse::Reject {
                wire_seq: 1,
                error: write_error("write failed again"),
            });

        assert_eq!(driver.drive_receive_once().unwrap(), DriveOutcome::Progress);
        assert_eq!(
            driver.drive_receive_once().unwrap(),
            DriveOutcome::Acked { wire_seq: 0 }
        );
        assert_eq!(
            driver.drive_receive_once().unwrap(),
            DriveOutcome::Reconnected {
                reason: ReconnectReason::RetryableFailure
            }
        );
        assert_eq!(
            driver.receipt_status(first),
            QwpReceiptStatus::Completed { fsn: 0 }
        );
        assert_eq!(
            driver.receipt_status(second),
            QwpReceiptStatus::Published { fsn: 1 }
        );
        assert_eq!(driver.acked_fsn(), Some(0));
    }

    #[test]
    fn durable_retryable_reject_preserves_prior_pending_ok_for_replay() {
        let mut driver = durable_driver(FakeOrderedServer::no_response());
        let first = driver.try_submit(b"first").unwrap();
        let second = driver.try_submit(b"second").unwrap();
        let third = driver.try_submit(b"third").unwrap();

        driver.drive_send_once().unwrap();
        driver.drive_send_once().unwrap();
        driver.drive_send_once().unwrap();
        driver
            .send_core
            .transport
            .push_response(TransportResponse::DurableOk {
                wire_seq: 0,
                table_seq_txns: table_seq_txns(&[("trades", 10)]),
            });
        assert_eq!(driver.drive_receive_once().unwrap(), DriveOutcome::Progress);
        driver
            .send_core
            .transport
            .push_response(TransportResponse::Reject {
                wire_seq: 1,
                error: write_error("write failed"),
            });

        assert_eq!(
            driver.drive_receive_once().unwrap(),
            DriveOutcome::Reconnected {
                reason: ReconnectReason::RetryableFailure
            }
        );
        assert!(driver.receipt_status(first).is_pending());
        assert!(driver.receipt_status(second).is_pending());
        assert!(driver.receipt_status(third).is_pending());
        assert_eq!(driver.acked_fsn(), None);
        assert_eq!(
            driver
                .last_server_error()
                .map(|err| (err.status, err.message.as_str())),
            Some((codec::WS_STATUS_WRITE_ERROR, "write failed"))
        );
        assert_eq!(
            driver.poll_sender_error().map(|err| err.applied_policy),
            Some(QwpWsErrorPolicy::Retriable)
        );
    }

    #[test]
    fn durable_reject_after_cumulative_pending_ok_reconnects_without_gap_violation() {
        let mut driver = durable_driver(FakeOrderedServer::no_response());
        let first = driver.try_submit(b"first").unwrap();
        let second = driver.try_submit(b"second").unwrap();
        let third = driver.try_submit(b"third").unwrap();

        driver.drive_send_once().unwrap();
        driver.drive_send_once().unwrap();
        driver.drive_send_once().unwrap();
        driver
            .send_core
            .transport
            .push_response(TransportResponse::DurableOk {
                wire_seq: 1,
                table_seq_txns: table_seq_txns(&[("trades", 10)]),
            });
        assert_eq!(driver.drive_receive_once().unwrap(), DriveOutcome::Progress);

        driver
            .send_core
            .transport
            .push_response(TransportResponse::Reject {
                wire_seq: 2,
                error: write_error("write failed"),
            });
        assert_eq!(
            driver.drive_receive_once().unwrap(),
            DriveOutcome::Reconnected {
                reason: ReconnectReason::RetryableFailure
            }
        );
        assert!(!driver.is_terminal());
        assert!(driver.receipt_status(first).is_pending());
        assert!(driver.receipt_status(second).is_pending());
        assert!(driver.receipt_status(third).is_pending());
        assert_eq!(
            driver.poll_sender_error().map(|err| err.applied_policy),
            Some(QwpWsErrorPolicy::Retriable)
        );
    }

    #[test]
    fn durable_consecutive_retryable_rejects_preserve_replay_tail() {
        let mut driver = durable_driver(FakeOrderedServer::no_response());
        let first = driver.try_submit(b"first").unwrap();
        let second = driver.try_submit(b"second").unwrap();
        let third = driver.try_submit(b"third").unwrap();
        let fourth = driver.try_submit(b"fourth").unwrap();

        driver.drive_send_once().unwrap();
        driver.drive_send_once().unwrap();
        driver.drive_send_once().unwrap();
        driver.drive_send_once().unwrap();
        driver
            .send_core
            .transport
            .push_response(TransportResponse::DurableOk {
                wire_seq: 0,
                table_seq_txns: table_seq_txns(&[("trades", 10)]),
            });
        driver
            .send_core
            .transport
            .push_response(TransportResponse::Reject {
                wire_seq: 1,
                error: write_error("write failed"),
            });
        assert_eq!(driver.drive_receive_once().unwrap(), DriveOutcome::Progress);
        assert!(matches!(
            driver.drive_receive_once().unwrap(),
            DriveOutcome::Reconnected {
                reason: ReconnectReason::RetryableFailure
            }
        ));
        assert!(driver.receipt_status(first).is_pending());
        assert!(driver.receipt_status(second).is_pending());
        assert!(driver.receipt_status(third).is_pending());
        assert!(driver.receipt_status(fourth).is_pending());
        assert_eq!(driver.acked_fsn(), None);
    }

    #[test]
    fn stale_durable_ok_after_retryable_reject_does_not_complete_before_replay() {
        let mut driver = durable_driver(FakeOrderedServer::no_response());
        let first = driver.try_submit(b"first").unwrap();
        let second = driver.try_submit(b"second").unwrap();

        driver.drive_send_once().unwrap();
        driver.drive_send_once().unwrap();
        driver
            .send_core
            .transport
            .push_response(TransportResponse::Reject {
                wire_seq: 0,
                error: write_error("write failed"),
            });
        assert_eq!(
            driver.drive_receive_once().unwrap(),
            DriveOutcome::Reconnected {
                reason: ReconnectReason::RetryableFailure
            }
        );
        assert!(driver.receipt_status(first).is_pending());
        assert!(driver.receipt_status(second).is_pending());
        let first_error = driver.poll_sender_error().unwrap();
        assert_eq!(first_error.message_sequence, Some(0));
        assert_eq!(first_error.message.as_deref(), Some("write failed"));
        assert_eq!(
            drain_events(&mut driver),
            vec![
                DriverEvent::Published { fsn: 0 },
                DriverEvent::Published { fsn: 1 },
                DriverEvent::Sent {
                    fsn: 0,
                    wire_seq: 0,
                },
                DriverEvent::Sent {
                    fsn: 1,
                    wire_seq: 1,
                },
                DriverEvent::Rejected {
                    fsn: 0,
                    wire_seq: 0,
                },
                DriverEvent::Reconnected {
                    reason: ReconnectReason::RetryableFailure,
                },
            ]
        );

        driver
            .send_core
            .transport
            .push_response(TransportResponse::DurableOk {
                wire_seq: 0,
                table_seq_txns: table_seq_txns(&[("trades", 99)]),
            });
        assert_eq!(driver.drive_receive_once().unwrap(), DriveOutcome::Progress);
        assert!(driver.receipt_status(first).is_pending());
        assert!(driver.receipt_status(second).is_pending());

        assert!(matches!(
            driver.drive_send_once().unwrap(),
            DriveOutcome::Sent(SentFrame { fsn: 0, .. })
        ));
        assert!(matches!(
            driver.drive_send_once().unwrap(),
            DriveOutcome::Sent(SentFrame { fsn: 1, .. })
        ));
        driver
            .send_core
            .transport
            .push_response(TransportResponse::DurableOk {
                wire_seq: 0,
                table_seq_txns: table_seq_txns(&[("trades", 10)]),
            });
        driver
            .send_core
            .transport
            .push_response(TransportResponse::DurableAck {
                table_seq_txns: table_seq_txns(&[("trades", 10)]),
            });
        driver
            .send_core
            .transport
            .push_response(TransportResponse::DurableOk {
                wire_seq: 1,
                table_seq_txns: table_seq_txns(&[("quotes", 20)]),
            });
        driver
            .send_core
            .transport
            .push_response(TransportResponse::DurableAck {
                table_seq_txns: table_seq_txns(&[("quotes", 20)]),
            });
        assert_eq!(driver.drive_receive_once().unwrap(), DriveOutcome::Progress);
        assert_eq!(
            driver.drive_receive_once().unwrap(),
            DriveOutcome::Acked { wire_seq: 0 }
        );
        assert_eq!(driver.drive_receive_once().unwrap(), DriveOutcome::Progress);
        assert_eq!(
            driver.drive_receive_once().unwrap(),
            DriveOutcome::Acked { wire_seq: 1 }
        );
        assert_eq!(
            driver.receipt_status(first),
            QwpReceiptStatus::Completed { fsn: 0 }
        );
        assert_eq!(
            driver.receipt_status(second),
            QwpReceiptStatus::Completed { fsn: 1 }
        );
    }

    #[test]
    fn stale_durable_reject_before_replay_reconnects_without_completion() {
        let mut driver = durable_driver(FakeOrderedServer::no_response());
        let first = driver.try_submit(b"first").unwrap();
        let second = driver.try_submit(b"second").unwrap();

        driver.drive_send_once().unwrap();
        driver.drive_send_once().unwrap();
        driver
            .send_core
            .transport
            .push_response(TransportResponse::Reject {
                wire_seq: 0,
                error: write_error("write failed"),
            });
        assert_eq!(
            driver.drive_receive_once().unwrap(),
            DriveOutcome::Reconnected {
                reason: ReconnectReason::RetryableFailure
            }
        );
        assert!(driver.receipt_status(first).is_pending());
        assert!(driver.receipt_status(second).is_pending());
        let first_error = driver.poll_sender_error().unwrap();
        assert_eq!(first_error.message_sequence, Some(0));
        assert_eq!(first_error.message.as_deref(), Some("write failed"));

        driver
            .send_core
            .transport
            .push_response(TransportResponse::Reject {
                wire_seq: 0,
                error: write_error("write failed again"),
            });
        assert_eq!(
            driver.drive_receive_once().unwrap(),
            DriveOutcome::Reconnected {
                reason: ReconnectReason::RetryableFailure
            }
        );
        assert!(driver.receipt_status(first).is_pending());
        assert!(driver.receipt_status(second).is_pending());
        let stale_error = driver.poll_sender_error().unwrap();
        assert_eq!(stale_error.message_sequence, Some(0));
        assert_eq!(stale_error.message.as_deref(), Some("write failed again"));

        assert!(matches!(
            driver.drive_send_once().unwrap(),
            DriveOutcome::Sent(SentFrame { fsn: 0, .. })
        ));
        assert!(matches!(
            driver.drive_send_once().unwrap(),
            DriveOutcome::Sent(SentFrame { fsn: 1, .. })
        ));
        driver
            .send_core
            .transport
            .push_response(TransportResponse::DurableOk {
                wire_seq: 0,
                table_seq_txns: table_seq_txns(&[("trades", 10)]),
            });
        driver
            .send_core
            .transport
            .push_response(TransportResponse::DurableAck {
                table_seq_txns: table_seq_txns(&[("trades", 10)]),
            });
        driver
            .send_core
            .transport
            .push_response(TransportResponse::DurableOk {
                wire_seq: 1,
                table_seq_txns: table_seq_txns(&[("quotes", 20)]),
            });
        driver
            .send_core
            .transport
            .push_response(TransportResponse::DurableAck {
                table_seq_txns: table_seq_txns(&[("quotes", 20)]),
            });
        assert_eq!(driver.drive_receive_once().unwrap(), DriveOutcome::Progress);
        assert_eq!(
            driver.drive_receive_once().unwrap(),
            DriveOutcome::Acked { wire_seq: 0 }
        );
        assert_eq!(driver.drive_receive_once().unwrap(), DriveOutcome::Progress);
        assert_eq!(
            driver.drive_receive_once().unwrap(),
            DriveOutcome::Acked { wire_seq: 1 }
        );
        assert_eq!(
            driver.receipt_status(first),
            QwpReceiptStatus::Completed { fsn: 0 }
        );
        assert_eq!(
            driver.receipt_status(second),
            QwpReceiptStatus::Completed { fsn: 1 }
        );
    }

    #[test]
    fn server_error_policy_matches_java_v2_defaults() {
        for (status, category, policy) in [
            (
                codec::WS_STATUS_SCHEMA_MISMATCH,
                QwpWsErrorCategory::SchemaMismatch,
                QwpWsErrorPolicy::Terminal,
            ),
            (
                codec::WS_STATUS_PARSE_ERROR,
                QwpWsErrorCategory::ParseError,
                QwpWsErrorPolicy::Terminal,
            ),
            (
                codec::WS_STATUS_SECURITY_ERROR,
                QwpWsErrorCategory::SecurityError,
                QwpWsErrorPolicy::Terminal,
            ),
            (
                codec::WS_STATUS_WRITE_ERROR,
                QwpWsErrorCategory::WriteError,
                QwpWsErrorPolicy::Retriable,
            ),
            (
                codec::WS_STATUS_INTERNAL_ERROR,
                QwpWsErrorCategory::InternalError,
                QwpWsErrorPolicy::Retriable,
            ),
            (
                codec::WS_STATUS_NOT_WRITABLE,
                QwpWsErrorCategory::NotWritable,
                QwpWsErrorPolicy::RetriableOther,
            ),
            (
                0x7f,
                QwpWsErrorCategory::Unknown,
                QwpWsErrorPolicy::Retriable,
            ),
        ] {
            assert_eq!(server_error_category(status), category);
            assert_eq!(server_error_policy(status), policy);
        }
    }

    #[test]
    fn not_writable_reject_uses_role_reconnect_reason_and_preserves_receipt() {
        let transport = TestTransport::scripted([Ok(TransportSendResult::Response(
            TransportResponse::Reject {
                wire_seq: 0,
                error: not_writable_error("replica access is read-only"),
            },
        ))]);
        let mut driver =
            QwpWsCoreTestHarness::from_queue(memory_queue(options(8, 1024, 4)), transport);
        let receipt = driver.try_submit(b"payload").unwrap();

        assert_eq!(
            driver.drive_once(),
            Ok(DriveOutcome::Reconnected {
                reason: ReconnectReason::NotWritable
            })
        );
        assert_eq!(driver.send_core.transport.restart_attempts, 1);
        assert_eq!(
            driver.send_core.transport.restart_reasons,
            [ReconnectReason::NotWritable]
        );
        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Published { fsn: 0 }
        );
        assert_eq!(driver.acked_fsn(), None);

        let error = driver.poll_sender_error().unwrap();
        assert_eq!(error.category, QwpWsErrorCategory::NotWritable);
        assert_eq!(error.applied_policy, QwpWsErrorPolicy::RetriableOther);
        assert_eq!(error.status, Some(codec::WS_STATUS_NOT_WRITABLE));
        assert_eq!(
            error.message.as_deref(),
            Some("replica access is read-only")
        );
    }

    #[test]
    fn raw_qwp_error_statuses_decode_with_expected_error_codes() {
        for (status, expected_code) in [
            (codec::WS_STATUS_PARSE_ERROR, ErrorCode::InvalidApiCall),
            (codec::WS_STATUS_INTERNAL_ERROR, ErrorCode::ServerFlushError),
            (codec::WS_STATUS_SECURITY_ERROR, ErrorCode::AuthError),
            (codec::WS_STATUS_NOT_WRITABLE, ErrorCode::ServerFlushError),
            (0x7f, ErrorCode::ServerFlushError),
        ] {
            let payload = qwp_error_payload(status, 7, "fatal server error");

            let response = decode_transport_response(&payload).unwrap().unwrap();

            match response {
                TransportResponse::Reject { wire_seq, error } => {
                    assert_eq!(wire_seq, 7);
                    assert_eq!(error.status, status);
                    assert_eq!(error.error.code(), expected_code);
                    assert!(error.error.msg().contains("fatal server error"));
                }
                other => panic!("unexpected response: {other:?}"),
            }
        }
    }

    #[test]
    fn future_ack_wire_sequence_clamps_to_highest_sent_like_java() {
        let mut driver = driver(FakeOrderedServer::scripted([FakeSendResult::AckWire {
            wire_seq: 99,
        }]));
        let receipt = driver.try_submit(b"payload").unwrap();

        assert_eq!(driver.drive_once(), Ok(DriveOutcome::Acked { wire_seq: 0 }));
        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Completed { fsn: 0 }
        );
    }

    #[test]
    fn future_reject_wire_sequence_reconnects_from_highest_sent_like_java_v2() {
        let mut driver = driver(FakeOrderedServer::scripted([FakeSendResult::RejectWire {
            wire_seq: 99,
        }]));
        let receipt = driver.try_submit(b"payload").unwrap();

        assert_eq!(
            driver.drive_once(),
            Ok(DriveOutcome::Reconnected {
                reason: ReconnectReason::RetryableFailure
            })
        );
        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Published { fsn: 0 }
        );
        assert_eq!(driver.acked_fsn(), None);

        let error = driver.poll_sender_error().unwrap();
        assert_eq!(error.applied_policy, QwpWsErrorPolicy::Retriable);
        assert_eq!(error.message_sequence, Some(99));
        assert_eq!(error.from_fsn, 0);
        assert_eq!(error.to_fsn, 0);
    }

    #[test]
    fn late_future_reject_for_acked_frame_reports_error_without_changing_receipt() {
        let mut driver = driver(FakeOrderedServer::no_response());
        let receipt = driver.try_submit(b"payload").unwrap();

        assert!(matches!(
            driver.drive_send_once().unwrap(),
            DriveOutcome::Sent(SentFrame { fsn: 0, .. })
        ));
        driver
            .send_core
            .transport
            .push_response(TransportResponse::Ack { wire_seq: 0 });
        assert_eq!(
            driver.drive_receive_once().unwrap(),
            DriveOutcome::Acked { wire_seq: 0 }
        );
        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Completed { fsn: 0 }
        );
        assert_eq!(driver.poll_sender_error(), None);

        driver
            .send_core
            .transport
            .push_response(TransportResponse::Reject {
                wire_seq: 99,
                error: write_error("late write failure"),
            });
        assert_eq!(driver.drive_receive_once().unwrap(), DriveOutcome::Progress);

        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Completed { fsn: 0 }
        );
        assert_eq!(driver.acked_fsn(), Some(0));

        let error = driver.poll_sender_error().unwrap();
        assert_eq!(error.applied_policy, QwpWsErrorPolicy::Retriable);
        assert_eq!(error.message_sequence, Some(99));
        assert_eq!(error.from_fsn, 0);
        assert_eq!(error.to_fsn, 0);
    }

    #[test]
    fn wait_drives_until_receipt_acked() {
        let mut driver = driver(FakeOrderedServer::ack_each_send());
        let receipt = driver.try_submit(b"payload").unwrap();

        driver.drive_once().unwrap();

        assert_eq!(
            driver.delivery_status(receipt).unwrap(),
            Some(DeliveryOutcome::Completed)
        );
        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Completed { fsn: 0 }
        );
    }

    #[test]
    fn coalesced_ack_completes_multiple_receipts() {
        let mut driver = driver(FakeOrderedServer::scripted([
            FakeSendResult::NoResponse,
            FakeSendResult::AckWire { wire_seq: 1 },
        ]));
        let first = driver.try_submit(b"a").unwrap();
        let second = driver.try_submit(b"b").unwrap();

        assert!(matches!(
            driver.drive_once().unwrap(),
            DriveOutcome::Sent(_)
        ));
        assert_eq!(
            driver.drive_once().unwrap(),
            DriveOutcome::Acked { wire_seq: 1 }
        );

        assert_eq!(
            driver.receipt_status(first),
            QwpReceiptStatus::Completed { fsn: 0 }
        );
        assert_eq!(
            driver.receipt_status(second),
            QwpReceiptStatus::Completed { fsn: 1 }
        );
    }

    #[test]
    fn cumulative_ack_event_agrees_with_wait_and_receipt_status() {
        let mut driver = driver(FakeOrderedServer::scripted([
            FakeSendResult::NoResponse,
            FakeSendResult::AckWire { wire_seq: 1 },
        ]));
        let first = driver.try_submit(b"a").unwrap();
        let second = driver.try_submit(b"b").unwrap();

        driver.drive_once().unwrap();
        driver.drive_once().unwrap();
        assert_eq!(
            driver.delivery_status(second).unwrap(),
            Some(DeliveryOutcome::Completed)
        );

        assert_eq!(
            drain_events(&mut driver),
            vec![
                DriverEvent::Published { fsn: 0 },
                DriverEvent::Published { fsn: 1 },
                DriverEvent::Sent {
                    fsn: 0,
                    wire_seq: 0,
                },
                DriverEvent::Sent {
                    fsn: 1,
                    wire_seq: 1,
                },
                DriverEvent::CompletedThrough {
                    fsn: 1,
                    wire_seq: 1,
                },
            ]
        );
        assert_eq!(
            driver.receipt_status(first),
            QwpReceiptStatus::Completed { fsn: 0 }
        );
        assert_eq!(
            driver.receipt_status(second),
            QwpReceiptStatus::Completed { fsn: 1 }
        );
    }

    #[test]
    fn stale_completion_response_does_not_emit_duplicate_progress_event() {
        let mut driver = driver(FakeOrderedServer::scripted([
            FakeSendResult::NoResponse,
            FakeSendResult::AckWire { wire_seq: 1 },
        ]));
        let first = driver.try_submit(b"a").unwrap();
        let second = driver.try_submit(b"b").unwrap();

        driver.drive_once().unwrap();
        assert_eq!(
            driver.drive_once().unwrap(),
            DriveOutcome::Acked { wire_seq: 1 }
        );
        driver
            .send_core
            .transport
            .push_response(FakeServerResponse::Ack { wire_seq: 0 });
        assert_eq!(
            driver.drive_once().unwrap(),
            DriveOutcome::Acked { wire_seq: 0 }
        );

        assert_eq!(
            drain_events(&mut driver),
            vec![
                DriverEvent::Published { fsn: 0 },
                DriverEvent::Published { fsn: 1 },
                DriverEvent::Sent {
                    fsn: 0,
                    wire_seq: 0,
                },
                DriverEvent::Sent {
                    fsn: 1,
                    wire_seq: 1,
                },
                DriverEvent::CompletedThrough {
                    fsn: 1,
                    wire_seq: 1,
                },
            ]
        );
        assert_eq!(
            driver.receipt_status(first),
            QwpReceiptStatus::Completed { fsn: 0 }
        );
        assert_eq!(
            driver.receipt_status(second),
            QwpReceiptStatus::Completed { fsn: 1 }
        );
    }

    #[test]
    fn disconnect_replays_from_oldest_unresolved_with_zero_based_wire_sequence() {
        let mut driver = driver(FakeOrderedServer::scripted([
            FakeSendResult::NoResponse,
            FakeSendResult::Disconnect,
            FakeSendResult::AckSent,
        ]));
        let first = driver.try_submit(b"first").unwrap();
        let second = driver.try_submit(b"second").unwrap();

        assert_eq!(
            driver.drive_once().unwrap(),
            DriveOutcome::Sent(SentFrame {
                fsn: 0,
                wire_seq: 0,
                payload_len: 5
            })
        );
        assert_eq!(
            driver.drive_once().unwrap(),
            DriveOutcome::Reconnected {
                reason: ReconnectReason::Disconnect
            }
        );
        assert_eq!(
            driver.receipt_status(first),
            QwpReceiptStatus::Published { fsn: 0 }
        );
        assert_eq!(
            driver.receipt_status(second),
            QwpReceiptStatus::Published { fsn: 1 }
        );

        assert_eq!(
            driver.drive_once().unwrap(),
            DriveOutcome::Acked { wire_seq: 0 }
        );
        assert_eq!(
            driver.receipt_status(first),
            QwpReceiptStatus::Completed { fsn: 0 }
        );
        assert_eq!(
            driver.send_core.transport.sent_frames(),
            &[
                SentFrame {
                    fsn: 0,
                    wire_seq: 0,
                    payload_len: 5,
                },
                SentFrame {
                    fsn: 1,
                    wire_seq: 1,
                    payload_len: 6,
                },
                SentFrame {
                    fsn: 0,
                    wire_seq: 0,
                    payload_len: 5,
                },
            ]
        );
    }

    #[test]
    fn retryable_failure_does_not_complete_receipt() {
        let mut driver = driver(FakeOrderedServer::scripted([
            FakeSendResult::RetryableFailure,
            FakeSendResult::AckSent,
        ]));
        let receipt = driver.try_submit(b"payload").unwrap();

        assert_eq!(
            driver.drive_once().unwrap(),
            DriveOutcome::Reconnected {
                reason: ReconnectReason::RetryableFailure
            }
        );
        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Published { fsn: 0 }
        );

        assert_eq!(
            driver.drive_once().unwrap(),
            DriveOutcome::Acked { wire_seq: 0 }
        );
        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Completed { fsn: 0 }
        );
    }

    #[test]
    fn reconnect_event_agrees_with_republished_receipt_status() {
        let mut driver = driver(FakeOrderedServer::scripted([
            FakeSendResult::RetryableFailure,
        ]));
        let receipt = driver.try_submit(b"payload").unwrap();

        assert_eq!(
            driver.drive_once().unwrap(),
            DriveOutcome::Reconnected {
                reason: ReconnectReason::RetryableFailure,
            }
        );

        assert_eq!(
            drain_events(&mut driver),
            vec![
                DriverEvent::Published { fsn: 0 },
                DriverEvent::Sent {
                    fsn: 0,
                    wire_seq: 0,
                },
                DriverEvent::Reconnected {
                    reason: ReconnectReason::RetryableFailure,
                },
            ]
        );
        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Published { fsn: 0 }
        );
    }

    #[test]
    fn reconnect_policy_exhaustion_keeps_sf_receipts_replayable() {
        let transport = TestTransport::scripted([Ok(TransportSendResult::Failure(
            TransportFailure::Retryable(fake_transport_error("retryable outage")),
        ))])
        .with_restart_results([Err(DriverError::Transport(fake_transport_error(
            "reconnect failed once",
        )))]);
        let mut driver = QwpWsCoreTestHarness::from_queue_with_reconnect_policy(
            memory_queue(options(8, 1024, 4)),
            transport,
            ReconnectPolicy::bounded(
                Duration::from_millis(1),
                Duration::from_millis(10),
                Duration::from_millis(10),
            ),
            false,
        );
        let first = driver.try_submit(b"first").unwrap();
        let second = driver.try_submit(b"second").unwrap();

        assert!(matches!(
            driver.drive_once().unwrap(),
            DriveOutcome::ReconnectDelay { .. }
        ));
        std::thread::sleep(Duration::from_millis(20));
        assert!(matches!(
            driver.drive_once().unwrap(),
            DriveOutcome::ReconnectDelay { .. }
        ));
        assert_eq!(driver.send_core.transport.restart_attempts, 1);
        assert_eq!(driver.terminal_error(), None);
        assert!(driver.receipt_status(first).is_pending());
        assert!(driver.receipt_status(second).is_pending());
        assert!(driver.try_submit(b"third").is_ok());
    }

    #[test]
    fn terminal_event_is_emitted_once_on_transition() {
        let mut driver = driver(FakeOrderedServer::scripted([
            FakeSendResult::TerminalFailure,
        ]));
        let receipt = driver.try_submit(b"payload").unwrap();

        assert_eq!(driver.drive_once().unwrap(), DriveOutcome::Terminal);
        assert_eq!(driver.drive_once().unwrap(), DriveOutcome::Terminal);

        assert_eq!(
            drain_events(&mut driver),
            vec![
                DriverEvent::Published { fsn: 0 },
                DriverEvent::Sent {
                    fsn: 0,
                    wire_seq: 0,
                },
                DriverEvent::Terminal,
            ]
        );
        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Terminal { fsn: 0 }
        );
        assert_eq!(
            driver.delivery_status(receipt).unwrap(),
            Some(DeliveryOutcome::Terminal)
        );
    }

    #[test]
    fn lifecycle_terminalizes_when_store_terminalizes() {
        let queue = memory_queue(options(4, 1024, 2));
        let mut store = QwpWsPublicationStore::new(queue, DEFAULT_EVENT_CAPACITY);
        let lifecycle = store.lifecycle();

        store.mark_terminal(Some(Error::new(ErrorCode::SocketError, "terminal")));

        assert_eq!(lifecycle.load(), PublicationState::Terminal);
        assert!(store.is_terminal());
    }

    #[test]
    fn close_drain_drives_until_all_published_receipts_resolve() {
        let mut driver = driver(FakeOrderedServer::ack_each_send());
        let first = driver.try_submit(b"first").unwrap();
        let second = driver.try_submit(b"second").unwrap();

        assert_eq!(driver.close_drain_steps(2).unwrap(), CloseOutcome::Drained);

        assert_eq!(
            driver.receipt_status(first),
            QwpReceiptStatus::Completed { fsn: 0 }
        );
        assert_eq!(
            driver.receipt_status(second),
            QwpReceiptStatus::Completed { fsn: 1 }
        );
        assert_eq!(driver.try_submit(b"third"), Err(DriverError::Closing));
    }

    #[test]
    fn close_drain_timeout_keeps_existing_receipt_observable() {
        let mut driver = driver(FakeOrderedServer::no_response());
        let receipt = driver.try_submit(b"payload").unwrap();

        assert_eq!(driver.close_drain_steps(1).unwrap(), CloseOutcome::Timeout);

        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Sent {
                fsn: 0,
                wire_seq: 0,
            }
        );
        assert_eq!(driver.delivery_status(receipt).unwrap(), None);
        assert_eq!(driver.try_submit(b"next"), Err(DriverError::Closing));
    }

    #[test]
    fn close_drain_clamps_future_ack_and_drains() {
        let mut server = FakeOrderedServer::no_response();
        server.push_response(FakeServerResponse::Ack { wire_seq: 1 });
        let mut driver = driver(server);
        let receipt = driver.try_submit(b"payload").unwrap();

        assert_eq!(driver.close_drain_steps(2).unwrap(), CloseOutcome::Drained);

        assert_eq!(driver.try_submit(b"next"), Err(DriverError::Closing));
        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Completed { fsn: 0 }
        );
        assert_eq!(
            drain_events(&mut driver),
            vec![
                DriverEvent::Published { fsn: 0 },
                DriverEvent::Sent {
                    fsn: 0,
                    wire_seq: 0,
                },
                DriverEvent::CompletedThrough {
                    fsn: 0,
                    wire_seq: 0,
                }
            ]
        );
    }

    #[test]
    fn close_drain_reports_terminal_failure() {
        let mut driver = driver(FakeOrderedServer::scripted([
            FakeSendResult::TerminalFailure,
        ]));
        let receipt = driver.try_submit(b"payload").unwrap();

        assert_eq!(driver.close_drain_steps(1).unwrap(), CloseOutcome::Terminal);

        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Terminal { fsn: 0 }
        );
        assert_eq!(driver.drive_once().unwrap(), DriveOutcome::Terminal);
        assert_eq!(driver.try_submit(b"next"), Err(DriverError::Terminal));
    }

    #[test]
    fn terminal_failure_marks_unresolved_receipts_and_rejects_future_submit() {
        let mut driver = driver(FakeOrderedServer::scripted([
            FakeSendResult::NoResponse,
            FakeSendResult::TerminalFailure,
        ]));
        let first = driver.try_submit(b"first").unwrap();
        let second = driver.try_submit(b"second").unwrap();

        assert!(matches!(
            driver.drive_once().unwrap(),
            DriveOutcome::Sent(_)
        ));
        assert_eq!(driver.drive_once().unwrap(), DriveOutcome::Terminal);
        assert_eq!(
            driver.terminal_error().map(Error::msg),
            Some("fake terminal failure")
        );

        assert_eq!(
            driver.receipt_status(first),
            QwpReceiptStatus::Terminal { fsn: 0 }
        );
        assert_eq!(
            driver.receipt_status(second),
            QwpReceiptStatus::Terminal { fsn: 1 }
        );
        assert_eq!(
            driver.delivery_status(first).unwrap(),
            Some(DeliveryOutcome::Terminal)
        );
        assert_eq!(driver.drive_once().unwrap(), DriveOutcome::Terminal);
        assert_eq!(driver.try_submit(b"third"), Err(DriverError::Terminal));
    }

    #[test]
    fn retriable_reject_after_prior_ack_reconnects_and_preserves_replay_tail() {
        let mut driver = driver(FakeOrderedServer::scripted([
            FakeSendResult::AckWire { wire_seq: 0 },
            FakeSendResult::RejectWire { wire_seq: 1 },
        ]));
        let first = driver.try_submit(b"first").unwrap();
        let second = driver.try_submit(b"second").unwrap();
        let third = driver.try_submit(b"third").unwrap();

        assert_eq!(
            driver.drive_once().unwrap(),
            DriveOutcome::Acked { wire_seq: 0 }
        );
        assert_eq!(
            driver.drive_once().unwrap(),
            DriveOutcome::Reconnected {
                reason: ReconnectReason::RetryableFailure
            }
        );

        assert_eq!(
            driver.receipt_status(first),
            QwpReceiptStatus::Completed { fsn: 0 }
        );
        assert_eq!(
            driver.receipt_status(second),
            QwpReceiptStatus::Published { fsn: 1 }
        );
        assert_eq!(
            driver
                .last_server_error()
                .map(|err| (err.status, err.message.as_str())),
            Some((codec::WS_STATUS_WRITE_ERROR, "fake write error"))
        );
        assert_eq!(
            driver.receipt_status(third),
            QwpReceiptStatus::Published { fsn: 2 }
        );
    }

    #[test]
    fn reject_gap_terminalizes_without_completing_unresolved_lower_frame() {
        let mut driver = driver(FakeOrderedServer::scripted([
            FakeSendResult::NoResponse,
            FakeSendResult::RejectWire { wire_seq: 1 },
        ]));
        let first = driver.try_submit(b"first").unwrap();
        let second = driver.try_submit(b"second").unwrap();

        assert!(matches!(
            driver.drive_once().unwrap(),
            DriveOutcome::Sent(_)
        ));
        assert_eq!(driver.drive_once().unwrap(), DriveOutcome::Terminal);

        assert_eq!(
            driver.receipt_status(first),
            QwpReceiptStatus::Terminal { fsn: 0 }
        );
        assert_eq!(
            driver.receipt_status(second),
            QwpReceiptStatus::Terminal { fsn: 1 }
        );
        let terminal_error = driver.terminal_sender_error().unwrap();
        assert_eq!(
            terminal_error.category,
            QwpWsErrorCategory::ProtocolViolation
        );
        assert!(terminal_error.message.as_deref().is_some_and(|message| {
            message.contains("reject response for fsn 1 skipped unresolved fsn 0")
        }));
    }

    #[test]
    fn retriable_rejection_event_agrees_with_pending_replay_status() {
        let mut driver = driver(FakeOrderedServer::scripted([
            FakeSendResult::AckWire { wire_seq: 0 },
            FakeSendResult::RejectWire { wire_seq: 1 },
        ]));
        let first = driver.try_submit(b"first").unwrap();
        let second = driver.try_submit(b"second").unwrap();
        let third = driver.try_submit(b"third").unwrap();

        assert_eq!(
            driver.drive_once().unwrap(),
            DriveOutcome::Acked { wire_seq: 0 }
        );
        driver.drive_once().unwrap();
        assert_eq!(driver.delivery_status(second).unwrap(), None);

        assert_eq!(
            drain_events(&mut driver),
            vec![
                DriverEvent::Published { fsn: 0 },
                DriverEvent::Published { fsn: 1 },
                DriverEvent::Published { fsn: 2 },
                DriverEvent::Sent {
                    fsn: 0,
                    wire_seq: 0,
                },
                DriverEvent::CompletedThrough {
                    fsn: 0,
                    wire_seq: 0,
                },
                DriverEvent::Sent {
                    fsn: 1,
                    wire_seq: 1,
                },
                DriverEvent::Rejected {
                    fsn: 1,
                    wire_seq: 1,
                },
                DriverEvent::Reconnected {
                    reason: ReconnectReason::RetryableFailure,
                },
            ]
        );
        assert_eq!(
            driver.receipt_status(first),
            QwpReceiptStatus::Completed { fsn: 0 }
        );
        assert_eq!(
            driver.receipt_status(second),
            QwpReceiptStatus::Published { fsn: 1 }
        );
        assert_eq!(
            driver.receipt_status(third),
            QwpReceiptStatus::Published { fsn: 2 }
        );
    }

    #[test]
    fn retriable_reject_replays_from_rejected_frame_before_later_receipt() {
        let mut driver = driver(FakeOrderedServer::scripted([
            FakeSendResult::AckWire { wire_seq: 0 },
            FakeSendResult::RejectWire { wire_seq: 1 },
            FakeSendResult::AckWire { wire_seq: 2 },
        ]));
        let first = driver.try_submit(b"first").unwrap();
        let second = driver.try_submit(b"second").unwrap();
        let third = driver.try_submit(b"third").unwrap();

        assert_eq!(
            driver.drive_once().unwrap(),
            DriveOutcome::Acked { wire_seq: 0 }
        );
        assert_eq!(
            driver.drive_once().unwrap(),
            DriveOutcome::Reconnected {
                reason: ReconnectReason::RetryableFailure
            }
        );
        assert_eq!(
            driver.drive_once().unwrap(),
            DriveOutcome::Acked { wire_seq: 0 }
        );

        assert_eq!(
            driver.receipt_status(first),
            QwpReceiptStatus::Completed { fsn: 0 }
        );
        assert_eq!(
            driver.receipt_status(second),
            QwpReceiptStatus::Completed { fsn: 1 }
        );
        assert_eq!(
            driver.receipt_status(third),
            QwpReceiptStatus::Published { fsn: 2 }
        );
    }

    #[test]
    fn wait_keeps_receipt_pending_after_retriable_reject_until_replay_ack() {
        let mut driver = driver(FakeOrderedServer::scripted([FakeSendResult::RejectWire {
            wire_seq: 0,
        }]));
        let receipt = driver.try_submit(b"payload").unwrap();

        driver.drive_once().unwrap();

        assert_eq!(driver.delivery_status(receipt).unwrap(), None);
        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Published { fsn: 0 }
        );
    }

    #[test]
    fn retriable_server_error_is_pollable() {
        let mut driver = driver(FakeOrderedServer::scripted([FakeSendResult::RejectWire {
            wire_seq: 0,
        }]));
        let receipt = driver.try_submit(b"payload").unwrap();

        driver.drive_once().unwrap();
        assert_eq!(driver.delivery_status(receipt).unwrap(), None);

        let error = driver.poll_sender_error().unwrap();
        assert_eq!(error.category, QwpWsErrorCategory::WriteError);
        assert_eq!(error.applied_policy, QwpWsErrorPolicy::Retriable);
        assert_eq!(error.status, Some(codec::WS_STATUS_WRITE_ERROR));
        assert_eq!(error.message.as_deref(), Some("fake write error"));
        assert_eq!(error.message_sequence, Some(0));
        assert_eq!(error.from_fsn, 0);
        assert_eq!(error.to_fsn, 0);
        assert_eq!(driver.terminal_sender_error(), None);
        assert_eq!(driver.poll_sender_error(), None);
    }

    #[test]
    fn retriable_reject_poison_terminal_carries_last_server_error() {
        let mut driver = driver(FakeOrderedServer::scripted([
            FakeSendResult::RejectWire { wire_seq: 0 },
            FakeSendResult::RejectWire { wire_seq: 1 },
            FakeSendResult::RejectWire { wire_seq: 2 },
            FakeSendResult::RejectWire { wire_seq: 3 },
        ]));
        let receipt = driver.try_submit(b"payload").unwrap();

        let mut outcome = driver.drive_once().unwrap();
        for _ in 0..8 {
            if outcome == DriveOutcome::Terminal {
                break;
            }
            outcome = driver.drive_once().unwrap();
        }
        assert_eq!(outcome, DriveOutcome::Terminal);
        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Terminal { fsn: 0 }
        );

        let terminal_error = driver.terminal_sender_error().unwrap();
        assert_eq!(
            terminal_error.category,
            QwpWsErrorCategory::ProtocolViolation
        );
        assert!(
            terminal_error.message.as_deref().is_some_and(|message| {
                message.contains("was rejected 4 times without ACK progress")
                    && message.contains("fake write error")
            }),
            "poison terminal must carry the last server error, got: {:?}",
            terminal_error.message
        );
    }

    #[test]
    fn role_reject_poison_terminal_is_resend_required_not_protocol_violation() {
        // A read-only / role reject (NOT_WRITABLE, e.g. a replica after an
        // in-place role switch) that persists past the poison budget must
        // terminalize under the NotWritable category as "resend required" - NOT
        // as a ProtocolViolation. A graceful role switch is not a wire-protocol
        // violation, and the queued data stays recoverable for a resend.
        let mut driver = driver(FakeOrderedServer::scripted([
            FakeSendResult::RejectWireNotWritable { wire_seq: 0 },
            FakeSendResult::RejectWireNotWritable { wire_seq: 1 },
            FakeSendResult::RejectWireNotWritable { wire_seq: 2 },
            FakeSendResult::RejectWireNotWritable { wire_seq: 3 },
        ]));
        let receipt = driver.try_submit(b"payload").unwrap();

        let mut outcome = driver.drive_once().unwrap();
        for _ in 0..8 {
            if outcome == DriveOutcome::Terminal {
                break;
            }
            outcome = driver.drive_once().unwrap();
        }
        assert_eq!(outcome, DriveOutcome::Terminal);
        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Terminal { fsn: 0 }
        );

        let terminal_error = driver.terminal_sender_error().unwrap();
        assert_eq!(
            terminal_error.category,
            QwpWsErrorCategory::NotWritable,
            "role reject must terminalize under its own category, not ProtocolViolation"
        );
        assert_ne!(
            terminal_error.category,
            QwpWsErrorCategory::ProtocolViolation
        );
        assert_eq!(terminal_error.applied_policy, QwpWsErrorPolicy::Terminal);
        assert_eq!(terminal_error.status, Some(codec::WS_STATUS_NOT_WRITABLE));
    }

    #[test]
    fn poison_dwell_driver_holds_terminal_until_window_elapses() {
        let mut driver = QwpWsCoreTestHarness::from_queue_with_rejection_limit_and_window(
            memory_queue(options(8, 1024, 4)),
            FakeOrderedServer::scripted([
                FakeSendResult::RejectWire { wire_seq: 0 },
                FakeSendResult::RejectWire { wire_seq: 1 },
                FakeSendResult::RejectWire { wire_seq: 2 },
            ]),
            2,
            Duration::from_millis(200),
        );
        let receipt = driver.try_submit(b"payload").unwrap();

        assert_eq!(
            driver.drive_once().unwrap(),
            DriveOutcome::Reconnected {
                reason: ReconnectReason::RetryableFailure
            }
        );
        assert_eq!(
            driver.drive_once().unwrap(),
            DriveOutcome::Reconnected {
                reason: ReconnectReason::RetryableFailure
            }
        );
        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Published { fsn: 0 }
        );

        std::thread::sleep(Duration::from_millis(250));
        assert_eq!(driver.drive_once().unwrap(), DriveOutcome::Terminal);
        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Terminal { fsn: 0 }
        );

        let terminal_error = driver.terminal_sender_error().unwrap();
        assert!(
            terminal_error.message.as_deref().is_some_and(|message| {
                message.contains("was rejected 3 times without ACK progress")
                    && message.contains("fake write error")
            }),
            "poison terminal must report actual strike count, got: {:?}",
            terminal_error.message
        );
    }

    #[test]
    fn server_close_before_any_send_does_not_strike() {
        let mut driver = QwpWsCoreTestHarness::from_queue_with_rejection_limit_and_window(
            memory_queue(options(8, 1024, 4)),
            FakeOrderedServer::no_response(),
            1,
            Duration::ZERO,
        );
        driver.try_submit(b"payload").unwrap();

        match driver.send_core.transport_failure_action(
            &mut driver.store,
            TransportFailure::ServerClose(fake_transport_error("server close")),
        ) {
            QwpWsTransportFailureAction::Reconnect { reason, .. } => {
                assert_eq!(reason, ReconnectReason::Disconnect);
            }
            other => panic!("expected reconnect, got {other:?}"),
        }
        assert_eq!(driver.send_core.poison_tracker.strikes(), 0);
        assert!(!driver.is_terminal());
    }

    #[test]
    fn server_close_after_send_still_strikes() {
        let mut driver = QwpWsCoreTestHarness::from_queue_with_rejection_limit_and_window(
            memory_queue(options(8, 1024, 4)),
            FakeOrderedServer::no_response(),
            1,
            Duration::ZERO,
        );
        driver.try_submit(b"payload").unwrap();

        assert!(matches!(
            driver.drive_send_once().unwrap(),
            DriveOutcome::Sent(_)
        ));
        match driver.send_core.transport_failure_action(
            &mut driver.store,
            TransportFailure::ServerClose(fake_transport_error("server close")),
        ) {
            QwpWsTransportFailureAction::Terminal(err) => {
                assert!(
                    err.msg()
                        .contains("was closed 1 times without ACK progress"),
                    "unexpected terminal error: {}",
                    err.msg()
                );
            }
            other => panic!("expected terminal, got {other:?}"),
        }
        assert!(driver.is_terminal());
    }

    #[test]
    fn sender_error_log_cursors_are_independent() {
        let mut log = SenderErrorLog::new(2);
        let error = sender_error(0);

        log.push(error.clone());

        assert_eq!(log.poll_notification(), Some(error.clone()));
        assert_eq!(log.poll(), Some(error));
        assert_eq!(log.poll_notification(), None);
        assert_eq!(log.poll(), None);
        assert_eq!(log.dropped_total(), 0);
    }

    #[test]
    fn sender_error_log_range_poll_consumes_stale_and_overlapping_not_future() {
        let mut log = SenderErrorLog::new(4);
        let stale = sender_error(0);
        let overlapping = sender_error(1);
        let future = sender_error(3);

        log.push(stale);
        log.push(overlapping.clone());
        log.push(future.clone());

        assert_eq!(log.poll_overlapping(1, 1), Some(overlapping));
        assert_eq!(log.poll_overlapping(1, 1), None);
        assert_eq!(log.poll(), Some(future));
        assert_eq!(log.poll(), None);
    }

    #[test]
    fn sender_error_log_drop_count_is_unified_across_cursors() {
        let mut log = SenderErrorLog::new(1);
        let first = sender_error(0);
        let second = sender_error(1);

        log.push(first.clone());
        assert_eq!(log.poll(), Some(first));

        log.push(second.clone());

        assert_eq!(log.dropped_total(), 1);
        assert_eq!(log.poll_notification(), Some(second.clone()));
        assert_eq!(log.poll(), Some(second));
    }

    #[test]
    fn terminal_qwp_server_error_is_pollable_after_terminalization() {
        let mut driver = driver(FakeOrderedServer::no_response());
        let receipt = driver.try_submit(b"payload").unwrap();
        assert!(matches!(
            driver.drive_once().unwrap(),
            DriveOutcome::Sent(_)
        ));
        driver
            .send_core
            .transport
            .push_response(TransportResponse::Reject {
                wire_seq: 0,
                error: QwpServerError {
                    status: codec::WS_STATUS_PARSE_ERROR,
                    message: "bad payload".to_string(),
                    error: error::fmt!(InvalidApiCall, "QWP parse error: bad payload"),
                },
            });

        assert_eq!(driver.drive_once().unwrap(), DriveOutcome::Terminal);
        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Terminal { fsn: 0 }
        );

        let terminal_error = driver.terminal_sender_error().unwrap();
        assert_eq!(terminal_error.category, QwpWsErrorCategory::ParseError);
        assert_eq!(terminal_error.applied_policy, QwpWsErrorPolicy::Terminal);
        assert_eq!(terminal_error.status, Some(codec::WS_STATUS_PARSE_ERROR));
        assert_eq!(terminal_error.message.as_deref(), Some("bad payload"));
        assert_eq!(terminal_error.message_sequence, Some(0));
        assert_eq!(terminal_error.from_fsn, 0);
        assert_eq!(terminal_error.to_fsn, 0);

        let latched_error = driver.terminal_error().unwrap();
        assert_eq!(latched_error.code(), ErrorCode::ServerRejection);
        assert_eq!(latched_error.qwp_ws_rejection(), Some(terminal_error));

        let error = driver.poll_sender_error().unwrap();
        assert_eq!(error.category, QwpWsErrorCategory::ParseError);
        assert_eq!(error.applied_policy, QwpWsErrorPolicy::Terminal);
        assert_eq!(error.status, Some(codec::WS_STATUS_PARSE_ERROR));
        assert_eq!(error.message.as_deref(), Some("bad payload"));
        assert_eq!(error.message_sequence, Some(0));
        assert_eq!(error.from_fsn, 0);
        assert_eq!(error.to_fsn, 0);
        assert_eq!(driver.terminal_sender_error(), Some(&error));
    }

    #[test]
    fn protocol_violation_error_records_unresolved_fsn_span() {
        let mut driver = driver(FakeOrderedServer::no_response());
        driver.try_submit(b"first").unwrap();
        driver.try_submit(b"second").unwrap();

        assert_eq!(
            driver
                .send_core
                .apply_transport_failure(
                    &mut driver.store,
                    TransportFailure::ProtocolViolation {
                        close_code: Some(1002),
                        reason: "bad frame".to_string(),
                    },
                )
                .unwrap(),
            DriveOutcome::Terminal
        );

        let terminal_error = driver.terminal_sender_error().unwrap();
        assert_eq!(
            terminal_error.category,
            QwpWsErrorCategory::ProtocolViolation
        );
        assert_eq!(terminal_error.applied_policy, QwpWsErrorPolicy::Terminal);
        assert_eq!(terminal_error.status, None);
        assert_eq!(terminal_error.message_sequence, None);
        assert_eq!(terminal_error.from_fsn, 0);
        assert_eq!(terminal_error.to_fsn, 1);
        assert!(
            terminal_error
                .message
                .as_deref()
                .unwrap()
                .contains("bad frame")
        );

        let error = driver.poll_sender_error().unwrap();
        assert_eq!(error.category, QwpWsErrorCategory::ProtocolViolation);
        assert_eq!(error.applied_policy, QwpWsErrorPolicy::Terminal);
        assert_eq!(error.status, None);
        assert_eq!(error.message_sequence, None);
        assert_eq!(error.from_fsn, 0);
        assert_eq!(error.to_fsn, 1);
        assert!(error.message.unwrap().contains("bad frame"));
    }

    #[test]
    fn sender_error_overflow_drops_oldest_error() {
        let mut driver = driver_with_event_capacity(
            FakeOrderedServer::scripted([
                FakeSendResult::RejectWire { wire_seq: 0 },
                FakeSendResult::RejectWire { wire_seq: 1 },
            ]),
            1,
        );
        driver.try_submit(b"first").unwrap();
        driver.try_submit(b"second").unwrap();

        assert!(matches!(
            driver.drive_once().unwrap(),
            DriveOutcome::Reconnected {
                reason: ReconnectReason::RetryableFailure
            }
        ));
        assert!(matches!(
            driver.drive_once().unwrap(),
            DriveOutcome::Reconnected {
                reason: ReconnectReason::RetryableFailure
            }
        ));

        assert_eq!(driver.sender_errors_dropped_total(), 1);
        let error = driver.poll_sender_error().unwrap();
        assert_eq!(error.from_fsn, 0);
        assert_eq!(driver.poll_sender_error(), None);
    }

    #[test]
    fn delivery_status_returns_completed_for_completed_receipts() {
        let mut driver = driver(FakeOrderedServer::ack_each_send());
        let receipt = driver.try_submit(b"payload").unwrap();
        driver.drive_once().unwrap();

        assert_eq!(
            driver.delivery_status(receipt).unwrap(),
            Some(DeliveryOutcome::Completed)
        );
    }

    #[test]
    fn completed_receipt_is_observable_without_redriving() {
        let mut driver = driver(FakeOrderedServer::ack_each_send());
        let receipt = driver.try_submit(b"payload").unwrap();
        driver.drive_once().unwrap();

        assert_eq!(
            driver.delivery_status(receipt).unwrap(),
            Some(DeliveryOutcome::Completed)
        );
        assert_eq!(driver.drive_once().unwrap(), DriveOutcome::Idle);
    }

    #[test]
    fn delivery_status_unknown_receipt_is_api_error() {
        let driver = driver(FakeOrderedServer::ack_each_send());

        assert_eq!(
            driver.delivery_status(QwpReceipt { fsn: 99 }),
            Err(DriverError::UnknownReceipt { fsn: 99 })
        );
    }

    #[test]
    fn pending_receipt_status_after_drive_without_ack() {
        let mut driver = driver(FakeOrderedServer::no_response());
        let receipt = driver.try_submit(b"payload").unwrap();

        driver.drive_once().unwrap();

        assert_eq!(driver.delivery_status(receipt).unwrap(), None);
        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Sent {
                fsn: 0,
                wire_seq: 0
            }
        );
    }

    #[test]
    fn drive_receive_once_ignores_ack_before_send_like_java() {
        let mut server = FakeOrderedServer::no_response();
        server.push_response(FakeServerResponse::Ack { wire_seq: 0 });
        let mut driver = driver(server);
        let receipt = driver.try_submit(b"payload").unwrap();

        assert_eq!(driver.drive_receive_once(), Ok(DriveOutcome::Progress));

        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Published { fsn: 0 }
        );
        assert_eq!(driver.acked_fsn(), None);
        assert_eq!(driver.poll_sender_error(), None);
    }

    #[test]
    fn drive_receive_once_terminalizes_presend_schema_reject_without_ack_advance() {
        let mut server = FakeOrderedServer::no_response();
        server.push_response(FakeServerResponse::Reject {
            wire_seq: 42,
            error: schema_mismatch_error("pre-send schema mismatch"),
        });
        let mut driver = driver(server);
        let receipt = driver.try_submit(b"payload").unwrap();

        assert_eq!(driver.drive_receive_once(), Ok(DriveOutcome::Terminal));

        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Terminal { fsn: 0 }
        );
        assert_eq!(driver.acked_fsn(), None);
        assert!(driver.terminal_sender_error().is_some());

        let error = driver.poll_sender_error().unwrap();
        assert_eq!(error.category, QwpWsErrorCategory::SchemaMismatch);
        assert_eq!(error.applied_policy, QwpWsErrorPolicy::Terminal);
        assert_eq!(error.status, Some(codec::WS_STATUS_SCHEMA_MISMATCH));
        assert_eq!(error.message.as_deref(), Some("pre-send schema mismatch"));
        assert_eq!(error.message_sequence, Some(42));
        assert_eq!(error.from_fsn, 0);
        assert_eq!(error.to_fsn, 0);
    }

    #[test]
    fn drive_receive_once_reconnects_presend_retryable_reject_without_ack_advance() {
        let mut server = FakeOrderedServer::no_response();
        server.push_response(FakeServerResponse::Reject {
            wire_seq: 42,
            error: write_error("pre-send write failure"),
        });
        let mut driver = driver(server);
        let receipt = driver.try_submit(b"payload").unwrap();

        assert_eq!(
            driver.drive_receive_once(),
            Ok(DriveOutcome::Reconnected {
                reason: ReconnectReason::RetryableFailure
            })
        );

        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Published { fsn: 0 }
        );
        assert_eq!(driver.acked_fsn(), None);
        assert_eq!(driver.terminal_sender_error(), None);

        let error = driver.poll_sender_error().unwrap();
        assert_eq!(error.category, QwpWsErrorCategory::WriteError);
        assert_eq!(error.applied_policy, QwpWsErrorPolicy::Retriable);
        assert_eq!(error.status, Some(codec::WS_STATUS_WRITE_ERROR));
        assert_eq!(error.message.as_deref(), Some("pre-send write failure"));
        assert_eq!(error.message_sequence, Some(42));
        assert_eq!(error.from_fsn, 0);
        assert_eq!(error.to_fsn, 0);
    }

    #[test]
    fn drive_receive_once_terminalizes_presend_terminal_reject_without_ack_advance_like_java() {
        let mut server = FakeOrderedServer::no_response();
        server.push_response(FakeServerResponse::Reject {
            wire_seq: 7,
            error: QwpServerError {
                status: codec::WS_STATUS_PARSE_ERROR,
                message: "bad pre-send payload".to_string(),
                error: error::fmt!(InvalidApiCall, "QWP parse error: bad pre-send payload"),
            },
        });
        let mut driver = driver(server);
        let receipt = driver.try_submit(b"payload").unwrap();

        assert_eq!(driver.drive_receive_once(), Ok(DriveOutcome::Terminal));

        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Terminal { fsn: 0 }
        );
        assert_eq!(driver.acked_fsn(), None);

        let terminal_error = driver.terminal_sender_error().unwrap();
        assert_eq!(terminal_error.category, QwpWsErrorCategory::ParseError);
        assert_eq!(terminal_error.applied_policy, QwpWsErrorPolicy::Terminal);
        assert_eq!(terminal_error.message_sequence, Some(7));
        assert_eq!(terminal_error.from_fsn, 0);
        assert_eq!(terminal_error.to_fsn, 0);
    }

    #[test]
    fn event_ring_overflow_drops_old_events_without_corrupting_receipt_status() {
        let mut driver = driver_with_event_capacity(FakeOrderedServer::ack_each_send(), 2);
        let first = driver.try_submit(b"first").unwrap();
        let second = driver.try_submit(b"second").unwrap();

        driver.drive_once().unwrap();
        driver.drive_once().unwrap();
        assert_eq!(
            driver.delivery_status(first).unwrap(),
            Some(DeliveryOutcome::Completed)
        );
        assert_eq!(
            driver.delivery_status(second).unwrap(),
            Some(DeliveryOutcome::Completed)
        );

        assert_eq!(driver.events_dropped_total(), 4);
        assert_eq!(
            drain_events(&mut driver),
            vec![
                DriverEvent::Sent {
                    fsn: 1,
                    wire_seq: 1,
                },
                DriverEvent::CompletedThrough {
                    fsn: 1,
                    wire_seq: 1,
                },
            ]
        );
        assert_eq!(
            driver.receipt_status(first),
            QwpReceiptStatus::Completed { fsn: 0 }
        );
        assert_eq!(
            driver.receipt_status(second),
            QwpReceiptStatus::Completed { fsn: 1 }
        );
    }
}
