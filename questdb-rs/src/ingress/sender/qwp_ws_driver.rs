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

//! Manual QWP/WebSocket driver prototype over an explicit transport seam.
//!
//! This module validates Step 6 control flow without hard-wiring real WebSocket
//! I/O. The driver owns the publication log, connection-local send cursor, and
//! transport; every progress method takes `&mut self`, preserving the
//! one-progress-owner rule from Step 2.

use std::collections::VecDeque;
#[cfg(feature = "sync-sender-qwp-ws")]
use std::io::Write;
use std::time::{Duration, Instant};

#[cfg(feature = "sync-sender-qwp-ws")]
use crate::error;
#[cfg(feature = "sync-sender-qwp-ws")]
use crate::ingress::conf::QwpWsConfig;
#[cfg(feature = "sync-sender-qwp-ws")]
use crate::ingress::tls::TlsSettings;
use crate::{Error, ErrorCode};

#[cfg(feature = "sync-sender-qwp-ws")]
use super::qwp_ws::{WsStream, establish_connection, read_message, write_binary_frame};
#[cfg(feature = "sync-sender-qwp-ws")]
use super::qwp_ws_codec::WS_OPCODE_BINARY;
use super::qwp_ws_codec::{self as codec, PipelinedResponse};
use super::qwp_ws_queue::{
    OutboundFrame, QueueError, QwpReceipt, QwpReceiptStatus, SentFrame, SharedPayload,
    VolatileFrameQueue, VolatileQueueOptions,
};

const DEFAULT_EVENT_CAPACITY: usize = 1024;

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

#[derive(Debug)]
pub(crate) struct ManualDriverPrototype<Q = VolatileFrameQueue, T = FakeOrderedServer> {
    queue: Q,
    send_cursor: SendCursor,
    transport: Option<T>,
    events: DriverEventRing,
    terminal: bool,
    terminal_fsn: Option<u64>,
    terminal_error: Option<Error>,
    last_server_error: Option<QwpServerError>,
    rejected_frames: VecDeque<QwpRejectedFrame>,
    closing: bool,
    reconnect_policy: ReconnectPolicy,
}

impl ManualDriverPrototype<VolatileFrameQueue> {
    pub(crate) fn new(
        options: VolatileQueueOptions,
        server: FakeOrderedServer,
    ) -> Result<Self, DriverError> {
        let queue = VolatileFrameQueue::new(options)?;
        Ok(Self {
            send_cursor: SendCursor::new(queue.max_in_flight()),
            queue,
            transport: Some(server),
            events: DriverEventRing::new(DEFAULT_EVENT_CAPACITY),
            terminal: false,
            terminal_fsn: None,
            terminal_error: None,
            last_server_error: None,
            rejected_frames: VecDeque::new(),
            closing: false,
            reconnect_policy: ReconnectPolicy::no_backoff(Duration::MAX),
        })
    }
}

impl<Q: PublicationLog, T: ManualDriverTransport> ManualDriverPrototype<Q, T> {
    pub(crate) fn from_queue(queue: Q, transport: T) -> Self {
        let send_cursor = SendCursor::new(queue.max_in_flight());
        Self {
            send_cursor,
            queue,
            transport: Some(transport),
            events: DriverEventRing::new(DEFAULT_EVENT_CAPACITY),
            terminal: false,
            terminal_fsn: None,
            terminal_error: None,
            last_server_error: None,
            rejected_frames: VecDeque::new(),
            closing: false,
            reconnect_policy: ReconnectPolicy::no_backoff(Duration::MAX),
        }
    }

    pub(crate) fn from_queue_with_reconnect_policy(
        queue: Q,
        transport: T,
        reconnect_policy: ReconnectPolicy,
    ) -> Self {
        let send_cursor = SendCursor::new(queue.max_in_flight());
        Self {
            send_cursor,
            queue,
            transport: Some(transport),
            events: DriverEventRing::new(DEFAULT_EVENT_CAPACITY),
            terminal: false,
            terminal_fsn: None,
            terminal_error: None,
            last_server_error: None,
            rejected_frames: VecDeque::new(),
            closing: false,
            reconnect_policy,
        }
    }

    pub(crate) fn from_queue_with_event_capacity(
        queue: Q,
        transport: T,
        event_capacity: usize,
    ) -> Self {
        let send_cursor = SendCursor::new(queue.max_in_flight());
        Self {
            send_cursor,
            queue,
            transport: Some(transport),
            events: DriverEventRing::new(event_capacity),
            terminal: false,
            terminal_fsn: None,
            terminal_error: None,
            last_server_error: None,
            rejected_frames: VecDeque::new(),
            closing: false,
            reconnect_policy: ReconnectPolicy::no_backoff(Duration::MAX),
        }
    }

    pub(crate) fn try_submit(&mut self, payload: &[u8]) -> Result<QwpReceipt, DriverError> {
        if self.terminal {
            return Err(DriverError::Terminal);
        }
        if self.closing {
            return Err(DriverError::Closing);
        }
        let receipt = self.queue.try_publish(payload)?;
        self.push_event(DriverEvent::Published { fsn: receipt.fsn });
        Ok(receipt)
    }

    pub(crate) fn submit_with_drive_limit(
        &mut self,
        payload: &[u8],
        max_drive_steps: usize,
    ) -> Result<QwpReceipt, DriverError> {
        let mut drive_steps = 0;
        loop {
            if self.terminal {
                return Err(DriverError::Terminal);
            }
            if self.closing {
                return Err(DriverError::Closing);
            }
            match self.queue.try_publish(payload) {
                Ok(receipt) => {
                    self.push_event(DriverEvent::Published { fsn: receipt.fsn });
                    return Ok(receipt);
                }
                Err(DriverError::Queue(
                    QueueError::FrameCapacityFull { .. } | QueueError::ByteCapacityFull { .. },
                )) if drive_steps < max_drive_steps => {
                    self.drive_once()?;
                    drive_steps += 1;
                }
                Err(DriverError::Queue(
                    QueueError::FrameCapacityFull { .. } | QueueError::ByteCapacityFull { .. },
                )) => {
                    return Err(DriverError::SubmitTimedOut);
                }
                Err(
                    err @ (DriverError::Queue(
                        QueueError::InvalidCapacity
                        | QueueError::EmptyPayload
                        | QueueError::PayloadExceedsByteCapacity { .. }
                        | QueueError::MaxInFlightReached { .. }
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
                    | DriverError::SubmitTimedOut
                    | DriverError::Terminal
                    | DriverError::Closing
                    | DriverError::UnknownReceipt { .. }),
                ) => return Err(err),
            }
        }
    }

    pub(crate) fn drive_once(&mut self) -> Result<DriveOutcome, DriverError> {
        if self.terminal {
            return Ok(DriveOutcome::Terminal);
        }

        if let Some(outcome) = self.drive_send_available()? {
            return Ok(outcome);
        }

        self.drive_receive_once()
    }

    pub(crate) fn drive_send_once(&mut self) -> Result<DriveOutcome, DriverError> {
        if self.terminal {
            return Ok(DriveOutcome::Terminal);
        }

        Ok(self.drive_send_available()?.unwrap_or(DriveOutcome::Idle))
    }

    pub(crate) fn drive_receive_once(&mut self) -> Result<DriveOutcome, DriverError> {
        if self.terminal {
            return Ok(DriveOutcome::Terminal);
        }

        let response = self.transport_mut().poll_response();
        match response {
            Ok(Some(response)) => self.apply_response(response),
            Ok(None) => Ok(DriveOutcome::Idle),
            Err(failure) => self.apply_transport_failure(failure),
        }
    }

    pub(crate) fn drive_receive_ready_once(&mut self) -> Result<DriveOutcome, DriverError> {
        if self.terminal {
            return Ok(DriveOutcome::Terminal);
        }

        let response = self.transport_mut().try_poll_response();
        match response {
            Ok(Some(response)) => self.apply_response(response),
            Ok(None) => Ok(DriveOutcome::Idle),
            Err(failure) => self.apply_transport_failure(failure),
        }
    }

    fn drive_send_available(&mut self) -> Result<Option<DriveOutcome>, DriverError> {
        let Some(outbound) = self.send_cursor.next_outbound_frame(&self.queue)? else {
            return Ok(None);
        };

        let frame = outbound.sent_frame();
        let send_result = match self.transport_mut().send_frame(outbound) {
            Ok(result) => result,
            Err(failure) => return self.apply_transport_failure(failure).map(Some),
        };
        self.commit_sent_frame(frame)?;

        match send_result {
            TransportSendResult::NoResponse => Ok(Some(DriveOutcome::Sent(frame))),
            TransportSendResult::Response(response) => self.apply_response(response).map(Some),
            TransportSendResult::Failure(failure) => {
                self.apply_transport_failure(failure).map(Some)
            }
        }
    }

    pub(crate) fn wait_steps(
        &mut self,
        receipt: QwpReceipt,
        max_drive_steps: usize,
    ) -> Result<DeliveryOutcome, DriverError> {
        for _ in 0..max_drive_steps {
            match self.delivery_status(receipt)? {
                Some(outcome) => return Ok(outcome),
                None => self.drive_once().map(|_| ())?,
            }
        }

        Ok(self
            .delivery_status(receipt)?
            .unwrap_or(DeliveryOutcome::Timeout))
    }

    pub(crate) fn close_drain_steps(
        &mut self,
        max_drive_steps: usize,
    ) -> Result<CloseOutcome, DriverError> {
        self.closing = true;

        for _ in 0..max_drive_steps {
            if self.terminal {
                return Ok(CloseOutcome::Terminal);
            }
            if self.all_published_receipts_resolved() {
                self.queue.close()?;
                return Ok(CloseOutcome::Drained);
            }
            if self.drive_once()? == DriveOutcome::Terminal {
                return Ok(CloseOutcome::Terminal);
            }
        }

        if self.terminal {
            Ok(CloseOutcome::Terminal)
        } else if self.all_published_receipts_resolved() {
            self.queue.close()?;
            Ok(CloseOutcome::Drained)
        } else {
            Ok(CloseOutcome::Timeout)
        }
    }

    pub(crate) fn receipt_status(&self, receipt: QwpReceipt) -> QwpReceiptStatus {
        let status = self.queue.receipt_status(receipt);
        if let Some(terminal_fsn) = self.terminal_fsn
            && receipt.fsn <= terminal_fsn
            && status.is_pending()
        {
            return QwpReceiptStatus::Terminal { fsn: receipt.fsn };
        }
        if matches!(status, QwpReceiptStatus::Published { .. })
            && let Some(wire_seq) = self.send_cursor.wire_seq_for_fsn(receipt.fsn)
        {
            return QwpReceiptStatus::Sent {
                fsn: receipt.fsn,
                wire_seq,
            };
        }
        status
    }

    pub(crate) fn sent_frames(&self) -> &[SentFrame] {
        self.transport
            .as_ref()
            .map(ManualDriverTransport::sent_frames)
            .unwrap_or(&[])
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

    pub(crate) fn last_server_error(&self) -> Option<&QwpServerError> {
        self.last_server_error.as_ref()
    }

    pub(crate) fn rejected_frame(&self, receipt: QwpReceipt) -> Option<&QwpRejectedFrame> {
        self.rejected_frames
            .iter()
            .find(|rejected| rejected.fsn == receipt.fsn)
    }

    fn delivery_status(&self, receipt: QwpReceipt) -> Result<Option<DeliveryOutcome>, DriverError> {
        match self.receipt_status(receipt) {
            QwpReceiptStatus::Acked { .. } => Ok(Some(DeliveryOutcome::Acked)),
            QwpReceiptStatus::Rejected { .. } => Ok(Some(DeliveryOutcome::Rejected)),
            QwpReceiptStatus::Terminal { .. } => Ok(Some(DeliveryOutcome::Terminal)),
            QwpReceiptStatus::Published { .. } | QwpReceiptStatus::Sent { .. } => Ok(None),
            QwpReceiptStatus::Unknown { fsn } => Err(DriverError::UnknownReceipt { fsn }),
        }
    }

    fn all_published_receipts_resolved(&self) -> bool {
        match self.queue.published_fsn() {
            None => true,
            Some(published_fsn) => self
                .queue
                .completed_fsn()
                .is_some_and(|completed_fsn| completed_fsn >= published_fsn),
        }
    }

    fn apply_response(&mut self, response: TransportResponse) -> Result<DriveOutcome, DriverError> {
        match response {
            TransportResponse::Ack { wire_seq } => {
                let completed_before = self.queue.completed_fsn();
                let fsn = self
                    .send_cursor
                    .fsn_for_wire_seq(wire_seq, WireResponseKind::Ack)?;
                self.queue.complete_through(fsn)?;
                self.send_cursor.ack_through(fsn);
                let completed_after = self.queue.completed_fsn();
                if completed_after > completed_before {
                    self.push_event(DriverEvent::AckedThrough { fsn, wire_seq });
                }
                Ok(DriveOutcome::Acked { wire_seq })
            }
            TransportResponse::Reject { wire_seq, error } => {
                let fsn = self
                    .send_cursor
                    .fsn_for_wire_seq(wire_seq, WireResponseKind::Reject)?;
                let receipt = self.queue.reject_fsn(fsn)?;
                self.send_cursor.ack_through(fsn);
                let rejected = QwpRejectedFrame {
                    fsn: receipt.fsn,
                    wire_seq,
                    error,
                };
                self.last_server_error = Some(rejected.error.clone());
                self.rejected_frames.push_back(rejected);
                if wire_seq > 0 {
                    self.push_event(DriverEvent::AckedThrough {
                        fsn: receipt.fsn - 1,
                        wire_seq: wire_seq - 1,
                    });
                }
                self.push_event(DriverEvent::Rejected {
                    fsn: receipt.fsn,
                    wire_seq,
                });
                Ok(DriveOutcome::Rejected {
                    fsn: receipt.fsn,
                    wire_seq,
                })
            }
        }
    }

    fn apply_transport_failure(
        &mut self,
        failure: TransportFailure,
    ) -> Result<DriveOutcome, DriverError> {
        match failure {
            TransportFailure::Disconnect(error) => {
                self.reconnect_with_policy(ReconnectReason::Disconnect, error)
            }
            TransportFailure::Retryable(error) => {
                self.reconnect_with_policy(ReconnectReason::RetryableFailure, error)
            }
            TransportFailure::Terminal(error) => {
                self.mark_terminal(Some(error));
                Ok(DriveOutcome::Terminal)
            }
        }
    }

    fn reconnect_with_policy(
        &mut self,
        reason: ReconnectReason,
        initial_error: Error,
    ) -> Result<DriveOutcome, DriverError> {
        let policy = self.reconnect_policy;
        let deadline = Instant::now().checked_add(policy.max_duration);
        if reconnect_deadline_expired(deadline) {
            self.mark_terminal(Some(initial_error));
            return Ok(DriveOutcome::Terminal);
        }

        let mut attempts = 0usize;
        let mut backoff = policy.initial_backoff;
        let mut last_error = initial_error;

        while !reconnect_deadline_expired(deadline) {
            if attempts > 0 {
                if !sleep_before_reconnect(deadline, backoff) {
                    break;
                }
                backoff = double_duration(backoff).min(policy.max_backoff);
            }

            attempts += 1;
            match self.transport_mut().restart_connection(reason) {
                Ok(()) => {
                    self.send_cursor.restart(&self.queue);
                    self.push_event(DriverEvent::Reconnected { reason });
                    return Ok(DriveOutcome::Reconnected { reason });
                }
                Err(err) => match reconnect_attempt_error(err) {
                    Ok(err) if reconnect_error_is_terminal(&err) => {
                        self.mark_terminal(Some(err));
                        return Ok(DriveOutcome::Terminal);
                    }
                    Ok(err) => last_error = err,
                    Err(err) => return Err(err),
                },
            }
        }

        self.mark_terminal(Some(last_error));
        Ok(DriveOutcome::Terminal)
    }

    fn mark_terminal(&mut self, error: Option<Error>) {
        if !self.terminal {
            self.terminal = true;
            self.terminal_fsn = self.queue.published_fsn();
            self.terminal_error = error;
            self.push_event(DriverEvent::Terminal);
        }
    }

    fn push_event(&mut self, event: DriverEvent) {
        self.events.push(event);
    }

    pub(crate) fn is_terminal(&self) -> bool {
        self.terminal
    }

    pub(crate) fn detach_send_available(&mut self) -> Result<Option<DetachedSend<T>>, DriverError> {
        if self.terminal {
            return Ok(None);
        }

        let Some(outbound) = self.send_cursor.next_outbound_frame(&self.queue)? else {
            return Ok(None);
        };
        let frame = outbound.sent_frame();
        let transport = self.take_transport();
        Ok(Some(DetachedSend {
            transport,
            outbound,
            frame,
        }))
    }

    pub(crate) fn finish_detached_send(
        &mut self,
        transport: T,
        frame: SentFrame,
        send_result: Result<TransportSendResult, TransportFailure>,
    ) -> Result<DetachedProgress<T>, DriverError> {
        let send_result = match send_result {
            Ok(send_result) => send_result,
            Err(failure) => return Ok(self.prepare_detached_failure(transport, failure)),
        };

        match send_result {
            TransportSendResult::NoResponse => {
                self.restore_transport(transport);
                self.commit_sent_frame(frame)?;
                Ok(DetachedProgress::Outcome(DriveOutcome::Sent(frame)))
            }
            TransportSendResult::Response(response) => {
                self.restore_transport(transport);
                self.commit_sent_frame(frame)?;
                self.apply_response(response).map(DetachedProgress::Outcome)
            }
            TransportSendResult::Failure(failure) => {
                if let Err(err) = self.commit_sent_frame(frame) {
                    self.restore_transport(transport);
                    return Err(err);
                }
                Ok(self.prepare_detached_failure(transport, failure))
            }
        }
    }

    pub(crate) fn detach_receive_ready(&mut self) -> Option<DetachedReceive<T>> {
        if self.terminal {
            return None;
        }
        Some(DetachedReceive {
            transport: self.take_transport(),
        })
    }

    pub(crate) fn finish_detached_receive(
        &mut self,
        transport: T,
        response: Result<Option<TransportResponse>, TransportFailure>,
    ) -> Result<DetachedProgress<T>, DriverError> {
        match response {
            Ok(Some(response)) => {
                self.restore_transport(transport);
                self.apply_response(response).map(DetachedProgress::Outcome)
            }
            Ok(None) => {
                self.restore_transport(transport);
                Ok(DetachedProgress::Outcome(DriveOutcome::Idle))
            }
            Err(failure) => Ok(self.prepare_detached_failure(transport, failure)),
        }
    }

    pub(crate) fn finish_detached_reconnect_success(
        &mut self,
        transport: T,
        reason: ReconnectReason,
    ) -> Result<DriveOutcome, DriverError> {
        self.restore_transport(transport);
        self.send_cursor.restart(&self.queue);
        self.push_event(DriverEvent::Reconnected { reason });
        Ok(DriveOutcome::Reconnected { reason })
    }

    pub(crate) fn finish_detached_reconnect_terminal(
        &mut self,
        transport: T,
        error: Error,
    ) -> DriveOutcome {
        self.restore_transport(transport);
        self.mark_terminal(Some(error));
        DriveOutcome::Terminal
    }

    pub(crate) fn restore_detached_transport(&mut self, transport: T) {
        self.restore_transport(transport);
    }

    fn prepare_detached_failure(
        &mut self,
        transport: T,
        failure: TransportFailure,
    ) -> DetachedProgress<T> {
        match failure {
            TransportFailure::Disconnect(error) => DetachedProgress::Reconnect(DetachedReconnect {
                transport,
                reason: ReconnectReason::Disconnect,
                initial_error: error,
                policy: self.reconnect_policy,
            }),
            TransportFailure::Retryable(error) => DetachedProgress::Reconnect(DetachedReconnect {
                transport,
                reason: ReconnectReason::RetryableFailure,
                initial_error: error,
                policy: self.reconnect_policy,
            }),
            TransportFailure::Terminal(error) => {
                self.restore_transport(transport);
                self.mark_terminal(Some(error));
                DetachedProgress::Outcome(DriveOutcome::Terminal)
            }
        }
    }

    fn commit_sent_frame(&mut self, frame: SentFrame) -> Result<(), DriverError> {
        self.send_cursor.commit_sent(frame)?;
        self.push_event(DriverEvent::Sent {
            fsn: frame.fsn,
            wire_seq: frame.wire_seq,
        });
        Ok(())
    }

    fn transport_mut(&mut self) -> &mut T {
        self.transport
            .as_mut()
            .expect("QWP/WebSocket transport detached during driver progress")
    }

    fn take_transport(&mut self) -> T {
        self.transport
            .take()
            .expect("QWP/WebSocket transport detached twice")
    }

    fn restore_transport(&mut self, transport: T) {
        debug_assert!(self.transport.is_none());
        self.transport = Some(transport);
    }
}

fn reconnect_attempt_error(err: DriverError) -> Result<Error, DriverError> {
    match err {
        DriverError::Transport(err) | DriverError::Storage(err) => Ok(err),
        err => Err(err),
    }
}

pub(crate) fn reconnect_error_is_terminal(err: &Error) -> bool {
    matches!(
        err.code(),
        ErrorCode::AuthError | ErrorCode::ProtocolVersionError
    )
}

fn reconnect_deadline_expired(deadline: Option<Instant>) -> bool {
    deadline.is_some_and(|deadline| Instant::now() >= deadline)
}

fn sleep_before_reconnect(deadline: Option<Instant>, backoff: Duration) -> bool {
    if backoff.is_zero() {
        return !reconnect_deadline_expired(deadline);
    }

    let sleep_for = match deadline {
        Some(deadline) => {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            backoff.min(remaining)
        }
        None => backoff,
    };
    std::thread::sleep(sleep_for);
    !reconnect_deadline_expired(deadline)
}

fn double_duration(duration: Duration) -> Duration {
    duration.checked_mul(2).unwrap_or(Duration::MAX)
}

pub(crate) trait PublicationLog {
    fn try_publish(&mut self, payload: &[u8]) -> Result<QwpReceipt, DriverError>;
    fn shared_payload_for_fsn(&self, fsn: u64) -> Result<Option<SharedPayload>, DriverError>;
    fn oldest_unresolved_fsn(&self) -> Option<u64>;
    fn complete_through(&mut self, fsn: u64) -> Result<(), DriverError>;
    fn reject_fsn(&mut self, fsn: u64) -> Result<QwpReceipt, DriverError>;
    fn close(&mut self) -> Result<(), DriverError> {
        Ok(())
    }
    fn receipt_status(&self, receipt: QwpReceipt) -> QwpReceiptStatus;
    fn published_fsn(&self) -> Option<u64>;
    fn completed_fsn(&self) -> Option<u64>;
    fn max_in_flight(&self) -> usize;
}

#[derive(Debug)]
struct SendCursor {
    max_in_flight: usize,
    fsn_at_zero: Option<u64>,
    next_fsn: Option<u64>,
    next_wire_seq: u64,
    last_sent_wire_seq: Option<u64>,
    in_flight: VecDeque<SentFrame>,
}

impl SendCursor {
    fn new(max_in_flight: usize) -> Self {
        Self {
            max_in_flight,
            fsn_at_zero: None,
            next_fsn: None,
            next_wire_seq: 0,
            last_sent_wire_seq: None,
            in_flight: VecDeque::new(),
        }
    }

    fn next_outbound_frame<Q: PublicationLog>(
        &mut self,
        log: &Q,
    ) -> Result<Option<OutboundFrame>, DriverError> {
        if self.in_flight.len() >= self.max_in_flight {
            return Ok(None);
        }

        let fsn = match self.next_fsn {
            Some(fsn) => fsn,
            None => {
                let Some(fsn) = log.oldest_unresolved_fsn() else {
                    return Ok(None);
                };
                self.fsn_at_zero = Some(fsn);
                self.next_fsn = Some(fsn);
                fsn
            }
        };

        let Some(payload) = log.shared_payload_for_fsn(fsn)? else {
            return Ok(None);
        };
        Ok(Some(OutboundFrame {
            fsn,
            wire_seq: self.next_wire_seq,
            payload,
        }))
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

    fn fsn_for_wire_seq(&self, wire_seq: u64, kind: WireResponseKind) -> Result<u64, DriverError> {
        let Some(fsn_at_zero) = self.fsn_at_zero else {
            return Err(DriverError::Queue(match kind {
                WireResponseKind::Ack => QueueError::ProtocolAckWithoutConnection,
                WireResponseKind::Reject => QueueError::ProtocolRejectWithoutConnection,
            }));
        };
        let last_sent_wire_seq = self.last_sent_wire_seq;
        if last_sent_wire_seq.is_none_or(|last_sent| wire_seq > last_sent) {
            return Err(DriverError::Queue(match kind {
                WireResponseKind::Ack => QueueError::ProtocolAckBeyondSent {
                    wire_seq,
                    last_sent_wire_seq,
                },
                WireResponseKind::Reject => QueueError::ProtocolRejectBeyondSent {
                    wire_seq,
                    last_sent_wire_seq,
                },
            }));
        }
        fsn_at_zero
            .checked_add(wire_seq)
            .ok_or(DriverError::Queue(QueueError::SequenceOverflow))
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
        self.last_sent_wire_seq = None;
    }

    fn wire_seq_for_fsn(&self, fsn: u64) -> Option<u64> {
        self.in_flight
            .iter()
            .find(|frame| frame.fsn == fsn)
            .map(|frame| frame.wire_seq)
    }
}

#[derive(Debug, Clone, Copy)]
enum WireResponseKind {
    Ack,
    Reject,
}

pub(crate) trait ManualDriverTransport {
    fn poll_response(&mut self) -> Result<Option<TransportResponse>, TransportFailure>;

    fn try_poll_response(&mut self) -> Result<Option<TransportResponse>, TransportFailure> {
        self.poll_response()
    }

    fn send_frame(&mut self, frame: OutboundFrame)
    -> Result<TransportSendResult, TransportFailure>;

    fn restart_connection(&mut self, _reason: ReconnectReason) -> Result<(), DriverError> {
        Ok(())
    }

    fn sent_frames(&self) -> &[SentFrame] {
        &[]
    }
}

#[cfg(feature = "sync-sender-qwp-ws")]
pub(crate) struct BlockingQwpWsTransport {
    host: String,
    port: String,
    use_tls: bool,
    tls_settings: Option<TlsSettings>,
    qwp_ws: QwpWsConfig,
    auth_header: Option<String>,
    negotiated_version: u8,
    stream: WsStream,
    recv: Vec<u8>,
    send_buf: Vec<u8>,
    pending_wire_sequences: VecDeque<u64>,
    sent_frames: Vec<SentFrame>,
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
    ) -> crate::Result<Self> {
        let host = host.into();
        let port = port.into();
        let (stream, negotiated_version) = establish_connection(
            &host,
            &port,
            use_tls,
            tls_settings.clone(),
            &qwp_ws,
            auth_header.as_deref(),
        )?;
        Ok(Self {
            host,
            port,
            use_tls,
            tls_settings,
            qwp_ws,
            auth_header,
            negotiated_version,
            stream,
            recv: Vec::new(),
            send_buf: Vec::with_capacity(16 * 1024),
            pending_wire_sequences: VecDeque::new(),
            sent_frames: Vec::new(),
        })
    }

    pub(crate) fn negotiated_version(&self) -> u8 {
        self.negotiated_version
    }

    fn reconnect(&mut self) -> Result<(), DriverError> {
        let (stream, negotiated_version) = establish_connection(
            &self.host,
            &self.port,
            self.use_tls,
            self.tls_settings.clone(),
            &self.qwp_ws,
            self.auth_header.as_deref(),
        )
        .map_err(DriverError::Transport)?;
        self.stream = stream;
        self.negotiated_version = negotiated_version;
        self.recv.clear();
        self.send_buf.clear();
        self.pending_wire_sequences.clear();
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
            match server_error_policy(server_error.status) {
                ServerErrorPolicy::RejectAndContinue => Ok(Some(TransportResponse::Reject {
                    wire_seq,
                    error: server_error,
                })),
                ServerErrorPolicy::Terminal => Err(TransportFailure::Terminal(server_error.error)),
            }
        }
        Err(err) => Err(TransportFailure::Terminal(err)),
    }
}

#[cfg(feature = "sync-sender-qwp-ws")]
impl ManualDriverTransport for BlockingQwpWsTransport {
    fn try_poll_response(&mut self) -> Result<Option<TransportResponse>, TransportFailure> {
        if self.pending_wire_sequences.is_empty() {
            return Ok(None);
        }
        match self.stream.can_read_without_blocking() {
            Ok(true) => self.poll_response(),
            Ok(false) => Ok(None),
            Err(io) => Err(TransportFailure::Disconnect(error::fmt!(
                SocketError,
                "Could not check WebSocket readability: {}",
                io
            ))),
        }
    }

    fn poll_response(&mut self) -> Result<Option<TransportResponse>, TransportFailure> {
        if self.pending_wire_sequences.is_empty() {
            return Ok(None);
        }

        let opcode =
            read_message(&mut self.stream, &mut self.send_buf, &mut self.recv).map_err(|err| {
                match err.code() {
                    ErrorCode::SocketError => TransportFailure::Disconnect(err),
                    ErrorCode::AuthError | ErrorCode::ProtocolVersionError => {
                        TransportFailure::Terminal(err)
                    }
                    _ => TransportFailure::Terminal(err),
                }
            })?;
        if opcode != WS_OPCODE_BINARY {
            return Err(TransportFailure::Terminal(error::fmt!(
                SocketError,
                "QWP/WebSocket server response was not a binary frame"
            )));
        }

        let response = decode_transport_response(&self.recv)?;
        if let Some(
            TransportResponse::Ack { wire_seq } | TransportResponse::Reject { wire_seq, .. },
        ) = &response
        {
            self.complete_pending_through(*wire_seq);
        }
        Ok(response)
    }

    fn send_frame(
        &mut self,
        frame: OutboundFrame,
    ) -> Result<TransportSendResult, TransportFailure> {
        let sent_frame = frame.sent_frame();
        write_binary_frame(&mut self.stream, &mut self.send_buf, frame.payload.as_ref()).map_err(
            |io| {
                TransportFailure::Disconnect(error::fmt!(
                    SocketError,
                    "Could not send WebSocket frame: {}",
                    io
                ))
            },
        )?;
        self.stream.flush().map_err(|io| {
            TransportFailure::Disconnect(error::fmt!(
                SocketError,
                "Could not flush WebSocket frame: {}",
                io
            ))
        })?;
        self.pending_wire_sequences.push_back(frame.wire_seq);
        self.sent_frames.push(sent_frame);
        Ok(TransportSendResult::NoResponse)
    }

    fn restart_connection(&mut self, _reason: ReconnectReason) -> Result<(), DriverError> {
        self.reconnect()
    }

    fn sent_frames(&self) -> &[SentFrame] {
        &self.sent_frames
    }
}

impl PublicationLog for VolatileFrameQueue {
    fn try_publish(&mut self, payload: &[u8]) -> Result<QwpReceipt, DriverError> {
        Ok(VolatileFrameQueue::try_submit(self, payload)?)
    }

    fn shared_payload_for_fsn(&self, fsn: u64) -> Result<Option<SharedPayload>, DriverError> {
        Ok(VolatileFrameQueue::shared_payload_for_fsn(self, fsn))
    }

    fn oldest_unresolved_fsn(&self) -> Option<u64> {
        VolatileFrameQueue::oldest_unresolved_fsn(self)
    }

    fn complete_through(&mut self, fsn: u64) -> Result<(), DriverError> {
        Ok(VolatileFrameQueue::complete_through_fsn(self, fsn)?)
    }

    fn reject_fsn(&mut self, fsn: u64) -> Result<QwpReceipt, DriverError> {
        Ok(VolatileFrameQueue::reject_fsn(self, fsn)?)
    }

    fn receipt_status(&self, receipt: QwpReceipt) -> QwpReceiptStatus {
        VolatileFrameQueue::receipt_status(self, receipt)
    }

    fn published_fsn(&self) -> Option<u64> {
        VolatileFrameQueue::published_fsn(self)
    }

    fn completed_fsn(&self) -> Option<u64> {
        VolatileFrameQueue::completed_fsn(self)
    }

    fn max_in_flight(&self) -> usize {
        VolatileFrameQueue::max_in_flight(self)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum DriverError {
    Queue(QueueError),
    Transport(Error),
    Storage(Error),
    SubmitTimedOut,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServerErrorPolicy {
    RejectAndContinue,
    Terminal,
}

fn server_error_policy(status: u8) -> ServerErrorPolicy {
    match status {
        codec::WS_STATUS_SCHEMA_MISMATCH | codec::WS_STATUS_WRITE_ERROR => {
            ServerErrorPolicy::RejectAndContinue
        }
        codec::WS_STATUS_PARSE_ERROR
        | codec::WS_STATUS_INTERNAL_ERROR
        | codec::WS_STATUS_SECURITY_ERROR => ServerErrorPolicy::Terminal,
        _ => ServerErrorPolicy::Terminal,
    }
}

fn fake_transport_error(message: &'static str) -> Error {
    Error::new(ErrorCode::SocketError, message)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DriveOutcome {
    Idle,
    Sent(SentFrame),
    Acked { wire_seq: u64 },
    Rejected { fsn: u64, wire_seq: u64 },
    Reconnected { reason: ReconnectReason },
    Terminal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DriverEvent {
    Published { fsn: u64 },
    Sent { fsn: u64, wire_seq: u64 },
    AckedThrough { fsn: u64, wire_seq: u64 },
    Rejected { fsn: u64, wire_seq: u64 },
    Reconnected { reason: ReconnectReason },
    Terminal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReconnectReason {
    Disconnect,
    RetryableFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeliveryOutcome {
    Acked,
    Rejected,
    Terminal,
    Timeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CloseOutcome {
    Drained,
    Timeout,
    Terminal,
}

#[derive(Debug)]
pub(crate) struct DetachedSend<T> {
    pub(crate) transport: T,
    pub(crate) outbound: OutboundFrame,
    pub(crate) frame: SentFrame,
}

#[derive(Debug)]
pub(crate) struct DetachedReceive<T> {
    pub(crate) transport: T,
}

#[derive(Debug)]
pub(crate) enum DetachedProgress<T> {
    Outcome(DriveOutcome),
    Reconnect(DetachedReconnect<T>),
}

#[derive(Debug)]
pub(crate) struct DetachedReconnect<T> {
    pub(crate) transport: T,
    pub(crate) reason: ReconnectReason,
    pub(crate) initial_error: Error,
    pub(crate) policy: ReconnectPolicy,
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
    Retryable(Error),
    Terminal(Error),
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum TransportResponse {
    Ack {
        wire_seq: u64,
    },
    Reject {
        wire_seq: u64,
        error: QwpServerError,
    },
}

pub(crate) type FakeServerResponse = TransportResponse;

#[derive(Debug)]
struct DriverEventRing {
    events: VecDeque<DriverEvent>,
    capacity: usize,
    dropped_total: u64,
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

#[derive(Debug)]
pub(crate) struct FakeOrderedServer {
    send_results: VecDeque<FakeSendResult>,
    poll_responses: VecDeque<TransportResponse>,
    default_send_result: FakeSendResult,
    sent_frames: Vec<SentFrame>,
}

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

    fn with_default(default_send_result: FakeSendResult) -> Self {
        Self {
            send_results: VecDeque::new(),
            poll_responses: VecDeque::new(),
            default_send_result,
            sent_frames: Vec::new(),
        }
    }
}

impl ManualDriverTransport for FakeOrderedServer {
    fn poll_response(&mut self) -> Result<Option<TransportResponse>, TransportFailure> {
        Ok(self.poll_responses.pop_front())
    }

    fn send_frame(
        &mut self,
        frame: OutboundFrame,
    ) -> Result<TransportSendResult, TransportFailure> {
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
                        status: codec::WS_STATUS_SCHEMA_MISMATCH,
                        message: "fake schema mismatch".to_string(),
                        error: Error::new(ErrorCode::InvalidApiCall, "fake schema mismatch"),
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

    fn sent_frames(&self) -> &[SentFrame] {
        &self.sent_frames
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FakeSendResult {
    NoResponse,
    AckSent,
    AckWire { wire_seq: u64 },
    RejectWire { wire_seq: u64 },
    Disconnect,
    RetryableFailure,
    TerminalFailure,
}

#[cfg(test)]
mod tests {
    use super::super::qwp_ws_publisher::{QwpWsPublicationDriver, QwpWsPublicationError};
    use super::*;
    use crate::ingress::buffer::{QwpWsEncodeScratch, SymbolGlobalDict};
    use crate::ingress::{Buffer, TimestampNanos};
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

    fn options(max_frames: usize, max_bytes: usize, max_in_flight: usize) -> VolatileQueueOptions {
        VolatileQueueOptions {
            max_frames,
            max_bytes,
            max_in_flight,
        }
    }

    fn driver(server: FakeOrderedServer) -> ManualDriverPrototype {
        ManualDriverPrototype::new(options(8, 1024, 4), server).unwrap()
    }

    fn driver_with_event_capacity(
        server: FakeOrderedServer,
        event_capacity: usize,
    ) -> ManualDriverPrototype {
        ManualDriverPrototype::from_queue_with_event_capacity(
            VolatileFrameQueue::new(options(8, 1024, 4)).unwrap(),
            server,
            event_capacity,
        )
    }

    fn qwp_buffer(sym: &str, qty: i64, ts: i64) -> Buffer {
        let mut buffer = Buffer::new_qwp();
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
            .as_qwp()
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

    fn drain_events<Q: PublicationLog, T: ManualDriverTransport>(
        driver: &mut ManualDriverPrototype<Q, T>,
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
        poll_results: VecDeque<Result<Option<TransportResponse>, TransportFailure>>,
        restart_results: VecDeque<Result<(), DriverError>>,
        restart_attempts: usize,
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
                restart_results: VecDeque::new(),
                restart_attempts: 0,
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
            self.poll_results = poll_results.into_iter().collect();
            self
        }
    }

    impl ManualDriverTransport for TestTransport {
        fn poll_response(&mut self) -> Result<Option<TransportResponse>, TransportFailure> {
            self.poll_results.pop_front().unwrap_or(Ok(None))
        }

        fn send_frame(
            &mut self,
            frame: OutboundFrame,
        ) -> Result<TransportSendResult, TransportFailure> {
            self.sent_frames.push(frame.sent_frame());
            self.sent_payloads.push(frame.payload.to_vec());
            self.send_results
                .pop_front()
                .unwrap_or(Ok(TransportSendResult::NoResponse))
        }

        fn restart_connection(&mut self, _reason: ReconnectReason) -> Result<(), DriverError> {
            self.restart_attempts += 1;
            self.restart_results.pop_front().unwrap_or(Ok(()))
        }

        fn sent_frames(&self) -> &[SentFrame] {
            &self.sent_frames
        }
    }

    #[test]
    fn publisher_sends_replay_payload_to_driver_transport() {
        let buffer = qwp_buffer("SYM_001", 7, 1_000);
        let expected = replay_payload(&buffer);
        let driver = ManualDriverPrototype::from_queue(
            VolatileFrameQueue::new(options(8, 4096, 4)).unwrap(),
            TestTransport::scripted([Ok(TransportSendResult::NoResponse)]),
        );
        let mut publisher = QwpWsPublicationDriver::new(driver, 1);

        let receipt = publisher.try_submit_qwp(buffer.as_qwp().unwrap()).unwrap();
        let outcome = publisher.drive_once().unwrap();

        assert_eq!(receipt, QwpReceipt { fsn: 0 });
        assert_eq!(
            outcome,
            DriveOutcome::Sent(SentFrame {
                fsn: 0,
                wire_seq: 0,
                payload_len: expected.len(),
            })
        );
        let driver = publisher.into_driver();
        assert_eq!(
            driver.transport.as_ref().unwrap().sent_payloads,
            vec![expected]
        );
    }

    #[test]
    fn publisher_rejects_empty_buffer_without_publication() {
        let buffer = Buffer::new_qwp();
        let driver = ManualDriverPrototype::from_queue(
            VolatileFrameQueue::new(options(8, 4096, 4)).unwrap(),
            TestTransport::scripted([]),
        );
        let mut publisher = QwpWsPublicationDriver::new(driver, 1);

        let err = publisher
            .try_submit_qwp(buffer.as_qwp().unwrap())
            .unwrap_err();

        match err {
            QwpWsPublicationError::Encode(err) => {
                assert_eq!(err.code(), crate::ErrorCode::InvalidApiCall);
                assert_eq!(err.msg(), "Cannot submit an empty QWP/WebSocket buffer.");
            }
            QwpWsPublicationError::Driver(err) => panic!("unexpected driver error: {err:?}"),
        }
        assert!(publisher.sent_frames().is_empty());
        let driver = publisher.into_driver();
        assert!(driver.transport.as_ref().unwrap().sent_payloads.is_empty());
    }

    #[test]
    fn publisher_failed_queue_publication_does_not_consume_fsn() {
        let first = qwp_buffer("SYM_001", 1, 1_000);
        let second = qwp_buffer("SYM_002", 2, 2_000);
        let third = qwp_buffer("SYM_003", 3, 3_000);
        let driver = ManualDriverPrototype::from_queue(
            VolatileFrameQueue::new(options(1, 4096, 1)).unwrap(),
            TestTransport::scripted([Ok(TransportSendResult::Response(TransportResponse::Ack {
                wire_seq: 0,
            }))]),
        );
        let mut publisher = QwpWsPublicationDriver::new(driver, 1);

        let first_receipt = publisher.try_submit_qwp(first.as_qwp().unwrap()).unwrap();
        let err = publisher
            .try_submit_qwp(second.as_qwp().unwrap())
            .unwrap_err();
        assert!(matches!(
            err,
            QwpWsPublicationError::Driver(DriverError::Queue(QueueError::FrameCapacityFull {
                max_frames: 1
            }))
        ));
        assert_eq!(
            publisher.wait_steps(first_receipt, 2).unwrap(),
            DeliveryOutcome::Acked
        );

        let third_receipt = publisher.try_submit_qwp(third.as_qwp().unwrap()).unwrap();
        assert_eq!(third_receipt, QwpReceipt { fsn: 1 });
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
    #[derive(Clone, Copy)]
    enum RealServerAckMode {
        AckEach,
        CumulativeAfterAll,
    }

    #[cfg(feature = "sync-sender-qwp-ws")]
    fn serve_qwp_ws_connection<S: Read + Write>(
        stream: &mut S,
        frames: usize,
        payload_tx: mpsc::Sender<Vec<u8>>,
        ack_mode: RealServerAckMode,
    ) {
        let request = read_request_until_blank(stream).unwrap();
        let accept = codec::compute_accept(&header_value(&request, "Sec-WebSocket-Key"));
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: {accept}\r\n\
             X-QWP-Version: 1\r\n\
             \r\n"
        );
        stream.write_all(response.as_bytes()).unwrap();

        match ack_mode {
            RealServerAckMode::AckEach => {
                for wire_seq in 0..frames {
                    let payload = read_client_frame(stream).unwrap();
                    payload_tx.send(payload).unwrap();
                    write_ok_response(stream, wire_seq as u64).unwrap();
                }
            }
            RealServerAckMode::CumulativeAfterAll => {
                for _ in 0..frames {
                    let payload = read_client_frame(stream).unwrap();
                    payload_tx.send(payload).unwrap();
                }
                if frames > 0 {
                    write_ok_response(stream, frames as u64 - 1).unwrap();
                }
            }
        }
        thread::sleep(Duration::from_millis(50));
    }

    #[cfg(feature = "sync-sender-qwp-ws")]
    fn spawn_real_qwp_ws_server(
        use_tls: bool,
        frames: usize,
    ) -> (String, u16, mpsc::Receiver<Vec<u8>>) {
        spawn_real_qwp_ws_server_with_ack_mode(use_tls, frames, RealServerAckMode::AckEach)
    }

    #[cfg(feature = "sync-sender-qwp-ws")]
    fn spawn_real_qwp_ws_server_with_ack_mode(
        use_tls: bool,
        frames: usize,
        ack_mode: RealServerAckMode,
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
                serve_qwp_ws_connection(&mut stream, frames, payload_tx, ack_mode);
            } else {
                let mut stream = stream;
                serve_qwp_ws_connection(&mut stream, frames, payload_tx, ack_mode);
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
        assert!(driver.sent_frames().is_empty());
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
        let mut driver = ManualDriverPrototype::from_queue(
            VolatileFrameQueue::new(options(8, 1024, 2)).unwrap(),
            transport,
        );
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
            driver.sent_frames(),
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
        let mut driver = ManualDriverPrototype::from_queue(
            VolatileFrameQueue::new(options(8, 1024, 2)).unwrap(),
            transport,
        );
        let receipt = driver.try_submit(b"payload").unwrap();

        assert_eq!(
            driver.drive_send_once().unwrap(),
            DriveOutcome::Acked { wire_seq: 0 }
        );
        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Acked { fsn: receipt.fsn }
        );
    }

    #[cfg(feature = "sync-sender-qwp-ws")]
    #[test]
    fn blocking_real_ws_transport_drives_submit_and_wait() {
        let (host, port, payload_rx) = spawn_real_qwp_ws_server(false, 1);
        let transport = BlockingQwpWsTransport::connect(
            host,
            port.to_string(),
            false,
            None,
            QwpWsConfig::default(),
            None,
        )
        .unwrap();
        let mut driver = ManualDriverPrototype::from_queue(
            VolatileFrameQueue::new(options(8, 1024, 4)).unwrap(),
            transport,
        );

        let receipt = driver.try_submit(b"qwp-payload").unwrap();
        let outcome = driver.wait_steps(receipt, 4).unwrap();

        assert_eq!(outcome, DeliveryOutcome::Acked);
        assert_eq!(
            payload_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            b"qwp-payload"
        );
        assert_eq!(
            driver.sent_frames(),
            &[SentFrame {
                fsn: 0,
                wire_seq: 0,
                payload_len: b"qwp-payload".len(),
            }]
        );
    }

    #[cfg(feature = "sync-sender-qwp-ws")]
    #[test]
    fn blocking_real_ws_transport_sends_publication_replay_payload() {
        let buffer = qwp_buffer("SYM_REAL", 42, 42_000);
        let expected = replay_payload(&buffer);
        let (host, port, payload_rx) = spawn_real_qwp_ws_server(false, 1);
        let transport = BlockingQwpWsTransport::connect(
            host,
            port.to_string(),
            false,
            None,
            QwpWsConfig::default(),
            None,
        )
        .unwrap();
        let driver = ManualDriverPrototype::from_queue(
            VolatileFrameQueue::new(options(8, 4096, 4)).unwrap(),
            transport,
        );
        let mut publisher = QwpWsPublicationDriver::new(driver, 1);

        let receipt = publisher.try_submit_qwp(buffer.as_qwp().unwrap()).unwrap();
        let outcome = publisher.wait_steps(receipt, 4).unwrap();

        assert_eq!(outcome, DeliveryOutcome::Acked);
        assert_eq!(
            payload_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            expected
        );
        assert_eq!(
            publisher.sent_frames(),
            &[SentFrame {
                fsn: 0,
                wire_seq: 0,
                payload_len: expected.len(),
            }]
        );
    }

    #[cfg(feature = "sync-sender-qwp-ws")]
    #[test]
    fn blocking_real_ws_transport_handles_cumulative_ack_after_multiple_sends() {
        let (host, port, payload_rx) =
            spawn_real_qwp_ws_server_with_ack_mode(false, 2, RealServerAckMode::CumulativeAfterAll);
        let transport = BlockingQwpWsTransport::connect(
            host,
            port.to_string(),
            false,
            None,
            QwpWsConfig::default(),
            None,
        )
        .unwrap();
        let mut driver = ManualDriverPrototype::from_queue(
            VolatileFrameQueue::new(options(8, 1024, 4)).unwrap(),
            transport,
        );

        let first = driver.try_submit(b"qwp-payload-0").unwrap();
        let second = driver.try_submit(b"qwp-payload-1").unwrap();
        let outcome = driver.wait_steps(second, 6).unwrap();

        assert_eq!(outcome, DeliveryOutcome::Acked);
        assert_eq!(
            driver.receipt_status(first),
            QwpReceiptStatus::Acked { fsn: 0 }
        );
        assert_eq!(
            payload_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            b"qwp-payload-0"
        );
        assert_eq!(
            payload_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            b"qwp-payload-1"
        );
        assert_eq!(
            driver.sent_frames(),
            &[
                SentFrame {
                    fsn: 0,
                    wire_seq: 0,
                    payload_len: b"qwp-payload-0".len(),
                },
                SentFrame {
                    fsn: 1,
                    wire_seq: 1,
                    payload_len: b"qwp-payload-1".len(),
                },
            ]
        );
    }

    #[cfg(feature = "sync-sender-qwp-ws")]
    #[test]
    fn blocking_real_wss_transport_drives_submit_and_wait() {
        let (host, port, payload_rx) = spawn_real_qwp_ws_server(true, 1);
        let transport = BlockingQwpWsTransport::connect(
            host,
            port.to_string(),
            true,
            Some(tls_client_settings()),
            QwpWsConfig::default(),
            None,
        )
        .unwrap();
        let mut driver = ManualDriverPrototype::from_queue(
            VolatileFrameQueue::new(options(8, 1024, 4)).unwrap(),
            transport,
        );

        let receipt = driver.try_submit(b"qwp-secure-payload").unwrap();
        let outcome = driver.wait_steps(receipt, 4).unwrap();

        assert_eq!(outcome, DeliveryOutcome::Acked);
        assert_eq!(
            payload_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            b"qwp-secure-payload"
        );
        assert_eq!(
            driver.sent_frames(),
            &[SentFrame {
                fsn: 0,
                wire_seq: 0,
                payload_len: b"qwp-secure-payload".len(),
            }]
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
        assert!(driver.sent_frames().is_empty());

        let receipt = driver.try_submit(b"payload").unwrap();
        assert_eq!(receipt, QwpReceipt { fsn: 0 });
    }

    #[test]
    fn blocking_submit_drives_until_local_capacity_frees() {
        let mut driver =
            ManualDriverPrototype::new(options(1, 1024, 1), FakeOrderedServer::ack_each_send())
                .unwrap();
        let first = driver.try_submit(b"first").unwrap();

        let second = driver.submit_with_drive_limit(b"second", 1).unwrap();

        assert_eq!(
            driver.receipt_status(first),
            QwpReceiptStatus::Acked { fsn: 0 }
        );
        assert_eq!(
            driver.receipt_status(second),
            QwpReceiptStatus::Published { fsn: 1 }
        );
        assert_eq!(driver.sent_frames().len(), 1);
    }

    #[test]
    fn blocking_submit_times_out_when_capacity_does_not_free() {
        let mut driver =
            ManualDriverPrototype::new(options(1, 1024, 1), FakeOrderedServer::no_response())
                .unwrap();
        driver.try_submit(b"first").unwrap();

        assert_eq!(
            driver.submit_with_drive_limit(b"second", 1),
            Err(DriverError::SubmitTimedOut)
        );
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
            ManualDriverPrototype::new(options(8, 1024, 2), FakeOrderedServer::no_response())
                .unwrap();
        driver.try_submit(b"a").unwrap();
        driver.try_submit(b"b").unwrap();
        let third = driver.try_submit(b"c").unwrap();

        assert!(matches!(
            driver.drive_once().unwrap(),
            DriveOutcome::Sent(_)
        ));
        assert!(matches!(
            driver.drive_once().unwrap(),
            DriveOutcome::Sent(_)
        ));
        assert_eq!(driver.drive_once().unwrap(), DriveOutcome::Idle);
        assert_eq!(
            driver.receipt_status(third),
            QwpReceiptStatus::Published { fsn: 2 }
        );
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
        let mut driver = ManualDriverPrototype::from_queue_with_reconnect_policy(
            VolatileFrameQueue::new(options(8, 1024, 4)).unwrap(),
            transport,
            ReconnectPolicy::no_backoff(Duration::from_secs(1)),
        );
        let receipt = driver.try_submit(b"payload").unwrap();

        assert_eq!(
            driver.drive_once().unwrap(),
            DriveOutcome::Reconnected {
                reason: ReconnectReason::Disconnect,
            }
        );
        assert_eq!(driver.transport.as_ref().unwrap().restart_attempts, 2);
        assert_eq!(
            driver.transport.as_ref().unwrap().sent_payloads,
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

    #[test]
    fn transport_write_failure_does_not_commit_sent_receipt() {
        let transport = TestTransport::scripted([Err(TransportFailure::Disconnect(
            fake_transport_error("write failed"),
        ))]);
        let mut driver = ManualDriverPrototype::from_queue(
            VolatileFrameQueue::new(options(8, 1024, 4)).unwrap(),
            transport,
        );
        let receipt = driver.try_submit(b"payload").unwrap();

        assert_eq!(
            driver.drive_once().unwrap(),
            DriveOutcome::Reconnected {
                reason: ReconnectReason::Disconnect,
            }
        );
        assert_eq!(
            driver.transport.as_ref().unwrap().sent_payloads,
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
        let mut driver = ManualDriverPrototype::from_queue(
            VolatileFrameQueue::new(options(8, 1024, 4)).unwrap(),
            transport,
        );
        let receipt = driver.try_submit(b"payload").unwrap();

        assert_eq!(
            driver.drive_once().unwrap(),
            DriveOutcome::Sent(SentFrame {
                fsn: 0,
                wire_seq: 0,
                payload_len: 7,
            })
        );
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
    fn raw_qwp_schema_and_write_errors_reject_and_continue_like_java() {
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

    #[test]
    fn raw_qwp_parse_internal_security_and_unknown_errors_are_terminal_like_java() {
        for (status, expected_code) in [
            (codec::WS_STATUS_PARSE_ERROR, ErrorCode::InvalidApiCall),
            (codec::WS_STATUS_INTERNAL_ERROR, ErrorCode::ServerFlushError),
            (codec::WS_STATUS_SECURITY_ERROR, ErrorCode::AuthError),
            (0x7f, ErrorCode::ServerFlushError),
        ] {
            let payload = qwp_error_payload(status, 7, "fatal server error");

            let err = decode_transport_response(&payload).unwrap_err();

            match err {
                TransportFailure::Terminal(err) => {
                    assert_eq!(err.code(), expected_code);
                    assert!(err.msg().contains("fatal server error"));
                }
                other => panic!("unexpected transport failure: {other:?}"),
            }
        }
    }

    #[test]
    fn wait_drives_until_receipt_acked() {
        let mut driver = driver(FakeOrderedServer::ack_each_send());
        let receipt = driver.try_submit(b"payload").unwrap();

        let outcome = driver.wait_steps(receipt, 1).unwrap();

        assert_eq!(outcome, DeliveryOutcome::Acked);
        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Acked { fsn: 0 }
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
            QwpReceiptStatus::Acked { fsn: 0 }
        );
        assert_eq!(
            driver.receipt_status(second),
            QwpReceiptStatus::Acked { fsn: 1 }
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
        assert_eq!(
            driver.wait_steps(second, 1).unwrap(),
            DeliveryOutcome::Acked
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
                DriverEvent::AckedThrough {
                    fsn: 1,
                    wire_seq: 1,
                },
            ]
        );
        assert_eq!(
            driver.receipt_status(first),
            QwpReceiptStatus::Acked { fsn: 0 }
        );
        assert_eq!(
            driver.receipt_status(second),
            QwpReceiptStatus::Acked { fsn: 1 }
        );
    }

    #[test]
    fn stale_ack_response_does_not_emit_ack_progress_event() {
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
            .transport
            .as_mut()
            .unwrap()
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
                DriverEvent::AckedThrough {
                    fsn: 1,
                    wire_seq: 1,
                },
            ]
        );
        assert_eq!(
            driver.receipt_status(first),
            QwpReceiptStatus::Acked { fsn: 0 }
        );
        assert_eq!(
            driver.receipt_status(second),
            QwpReceiptStatus::Acked { fsn: 1 }
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
            QwpReceiptStatus::Acked { fsn: 0 }
        );
        assert_eq!(
            driver.sent_frames(),
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
            QwpReceiptStatus::Acked { fsn: 0 }
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
    fn reconnect_policy_exhaustion_terminalizes_current_unresolved_receipts() {
        let transport = TestTransport::scripted([Ok(TransportSendResult::Failure(
            TransportFailure::Retryable(fake_transport_error("retryable outage")),
        ))])
        .with_restart_results([Err(DriverError::Transport(fake_transport_error(
            "reconnect failed once",
        )))]);
        let mut driver = ManualDriverPrototype::from_queue_with_reconnect_policy(
            VolatileFrameQueue::new(options(8, 1024, 4)).unwrap(),
            transport,
            ReconnectPolicy::bounded(
                Duration::from_millis(1),
                Duration::from_millis(10),
                Duration::from_millis(10),
            ),
        );
        let first = driver.try_submit(b"first").unwrap();
        let second = driver.try_submit(b"second").unwrap();

        assert_eq!(driver.drive_once().unwrap(), DriveOutcome::Terminal);
        assert_eq!(driver.transport.as_ref().unwrap().restart_attempts, 1);
        assert_eq!(
            driver.terminal_error().map(Error::msg),
            Some("reconnect failed once")
        );
        assert_eq!(
            driver.receipt_status(first),
            QwpReceiptStatus::Terminal { fsn: 0 }
        );
        assert_eq!(
            driver.receipt_status(second),
            QwpReceiptStatus::Terminal { fsn: 1 }
        );
        assert_eq!(driver.try_submit(b"third"), Err(DriverError::Terminal));
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
            driver.wait_steps(receipt, 0).unwrap(),
            DeliveryOutcome::Terminal
        );
    }

    #[test]
    fn close_drain_drives_until_all_published_receipts_resolve() {
        let mut driver = driver(FakeOrderedServer::ack_each_send());
        let first = driver.try_submit(b"first").unwrap();
        let second = driver.try_submit(b"second").unwrap();

        assert_eq!(driver.close_drain_steps(2).unwrap(), CloseOutcome::Drained);

        assert_eq!(
            driver.receipt_status(first),
            QwpReceiptStatus::Acked { fsn: 0 }
        );
        assert_eq!(
            driver.receipt_status(second),
            QwpReceiptStatus::Acked { fsn: 1 }
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
        assert_eq!(
            driver.wait_steps(receipt, 0).unwrap(),
            DeliveryOutcome::Timeout
        );
        assert_eq!(driver.try_submit(b"next"), Err(DriverError::Closing));
    }

    #[test]
    fn close_drain_error_keeps_sender_closing_and_existing_receipt_observable() {
        let mut server = FakeOrderedServer::no_response();
        server.push_response(FakeServerResponse::Ack { wire_seq: 1 });
        let mut driver = driver(server);
        let receipt = driver.try_submit(b"payload").unwrap();

        assert_eq!(
            driver.close_drain_steps(2),
            Err(DriverError::Queue(QueueError::ProtocolAckBeyondSent {
                wire_seq: 1,
                last_sent_wire_seq: Some(0),
            }))
        );

        assert_eq!(driver.try_submit(b"next"), Err(DriverError::Closing));
        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Sent {
                fsn: 0,
                wire_seq: 0
            }
        );
        assert_eq!(
            drain_events(&mut driver),
            vec![
                DriverEvent::Published { fsn: 0 },
                DriverEvent::Sent {
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
            driver.wait_steps(first, 0).unwrap(),
            DeliveryOutcome::Terminal
        );
        assert_eq!(driver.drive_once().unwrap(), DriveOutcome::Terminal);
        assert_eq!(driver.try_submit(b"third"), Err(DriverError::Terminal));
    }

    #[test]
    fn ordered_reject_acks_prior_frame_and_leaves_later_frame_unresolved() {
        let mut driver = driver(FakeOrderedServer::scripted([
            FakeSendResult::NoResponse,
            FakeSendResult::RejectWire { wire_seq: 1 },
        ]));
        let first = driver.try_submit(b"first").unwrap();
        let second = driver.try_submit(b"second").unwrap();
        let third = driver.try_submit(b"third").unwrap();

        assert!(matches!(
            driver.drive_once().unwrap(),
            DriveOutcome::Sent(_)
        ));
        assert_eq!(
            driver.drive_once().unwrap(),
            DriveOutcome::Rejected {
                fsn: 1,
                wire_seq: 1
            }
        );

        assert_eq!(
            driver.receipt_status(first),
            QwpReceiptStatus::Acked { fsn: 0 }
        );
        assert_eq!(
            driver.receipt_status(second),
            QwpReceiptStatus::Rejected { fsn: 1 }
        );
        assert_eq!(
            driver
                .last_server_error()
                .map(|err| (err.status, err.message.as_str())),
            Some((codec::WS_STATUS_SCHEMA_MISMATCH, "fake schema mismatch"))
        );
        assert_eq!(
            driver.receipt_status(third),
            QwpReceiptStatus::Published { fsn: 2 }
        );
    }

    #[test]
    fn rejection_event_agrees_with_wait_and_receipt_status() {
        let mut driver = driver(FakeOrderedServer::scripted([
            FakeSendResult::NoResponse,
            FakeSendResult::RejectWire { wire_seq: 1 },
        ]));
        let first = driver.try_submit(b"first").unwrap();
        let second = driver.try_submit(b"second").unwrap();
        let third = driver.try_submit(b"third").unwrap();

        driver.drive_once().unwrap();
        assert_eq!(
            driver.wait_steps(second, 1).unwrap(),
            DeliveryOutcome::Rejected
        );

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
                DriverEvent::Sent {
                    fsn: 1,
                    wire_seq: 1,
                },
                DriverEvent::AckedThrough {
                    fsn: 0,
                    wire_seq: 0,
                },
                DriverEvent::Rejected {
                    fsn: 1,
                    wire_seq: 1,
                },
            ]
        );
        assert_eq!(
            driver.receipt_status(first),
            QwpReceiptStatus::Acked { fsn: 0 }
        );
        assert_eq!(
            driver.receipt_status(second),
            QwpReceiptStatus::Rejected { fsn: 1 }
        );
        assert_eq!(
            driver.receipt_status(third),
            QwpReceiptStatus::Published { fsn: 2 }
        );
    }

    #[test]
    fn ack_after_ordered_reject_completes_later_receipt() {
        let mut driver = driver(FakeOrderedServer::scripted([
            FakeSendResult::NoResponse,
            FakeSendResult::RejectWire { wire_seq: 1 },
            FakeSendResult::AckWire { wire_seq: 2 },
        ]));
        let first = driver.try_submit(b"first").unwrap();
        let second = driver.try_submit(b"second").unwrap();
        let third = driver.try_submit(b"third").unwrap();

        assert!(matches!(
            driver.drive_once().unwrap(),
            DriveOutcome::Sent(_)
        ));
        assert_eq!(
            driver.drive_once().unwrap(),
            DriveOutcome::Rejected {
                fsn: 1,
                wire_seq: 1
            }
        );
        assert_eq!(
            driver.drive_once().unwrap(),
            DriveOutcome::Acked { wire_seq: 2 }
        );

        assert_eq!(
            driver.receipt_status(first),
            QwpReceiptStatus::Acked { fsn: 0 }
        );
        assert_eq!(
            driver.receipt_status(second),
            QwpReceiptStatus::Rejected { fsn: 1 }
        );
        assert_eq!(
            driver.receipt_status(third),
            QwpReceiptStatus::Acked { fsn: 2 }
        );
    }

    #[test]
    fn wait_reports_rejected_receipt() {
        let mut driver = driver(FakeOrderedServer::scripted([FakeSendResult::RejectWire {
            wire_seq: 0,
        }]));
        let receipt = driver.try_submit(b"payload").unwrap();

        let outcome = driver.wait_steps(receipt, 1).unwrap();

        assert_eq!(outcome, DeliveryOutcome::Rejected);
        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Rejected { fsn: 0 }
        );
    }

    #[test]
    fn wait_returns_immediately_for_completed_receipts() {
        let mut driver = driver(FakeOrderedServer::ack_each_send());
        let receipt = driver.try_submit(b"payload").unwrap();
        driver.drive_once().unwrap();

        assert_eq!(
            driver.wait_steps(receipt, 0).unwrap(),
            DeliveryOutcome::Acked
        );
    }

    #[test]
    fn wait_returns_completed_receipt_before_driving_again() {
        let mut driver = driver(FakeOrderedServer::ack_each_send());
        let receipt = driver.try_submit(b"payload").unwrap();
        driver.drive_once().unwrap();

        assert_eq!(
            driver.wait_steps(receipt, 1).unwrap(),
            DeliveryOutcome::Acked
        );
        assert_eq!(driver.sent_frames().len(), 1);
    }

    #[test]
    fn wait_unknown_receipt_is_api_error() {
        let mut driver = driver(FakeOrderedServer::ack_each_send());

        assert_eq!(
            driver.wait_steps(QwpReceipt { fsn: 99 }, 1),
            Err(DriverError::UnknownReceipt { fsn: 99 })
        );
    }

    #[test]
    fn wait_timeout_keeps_receipt_valid() {
        let mut driver = driver(FakeOrderedServer::no_response());
        let receipt = driver.try_submit(b"payload").unwrap();

        let outcome = driver.wait_steps(receipt, 1).unwrap();

        assert_eq!(outcome, DeliveryOutcome::Timeout);
        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Sent {
                fsn: 0,
                wire_seq: 0
            }
        );
    }

    #[test]
    fn drive_receive_once_reports_response_before_connection_as_protocol_error() {
        let mut server = FakeOrderedServer::no_response();
        server.push_response(FakeServerResponse::Ack { wire_seq: 0 });
        let mut driver = driver(server);
        let receipt = driver.try_submit(b"payload").unwrap();

        assert_eq!(
            driver.drive_receive_once(),
            Err(DriverError::Queue(QueueError::ProtocolAckWithoutConnection))
        );

        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Published { fsn: 0 }
        );
    }

    #[test]
    fn event_ring_overflow_drops_old_events_without_corrupting_receipt_status() {
        let mut driver = driver_with_event_capacity(FakeOrderedServer::ack_each_send(), 2);
        let first = driver.try_submit(b"first").unwrap();
        let second = driver.try_submit(b"second").unwrap();

        assert_eq!(driver.wait_steps(first, 1).unwrap(), DeliveryOutcome::Acked);
        assert_eq!(
            driver.wait_steps(second, 1).unwrap(),
            DeliveryOutcome::Acked
        );

        assert_eq!(driver.events_dropped_total(), 4);
        assert_eq!(
            drain_events(&mut driver),
            vec![
                DriverEvent::Sent {
                    fsn: 1,
                    wire_seq: 1,
                },
                DriverEvent::AckedThrough {
                    fsn: 1,
                    wire_seq: 1,
                },
            ]
        );
        assert_eq!(
            driver.receipt_status(first),
            QwpReceiptStatus::Acked { fsn: 0 }
        );
        assert_eq!(
            driver.receipt_status(second),
            QwpReceiptStatus::Acked { fsn: 1 }
        );
    }
}
