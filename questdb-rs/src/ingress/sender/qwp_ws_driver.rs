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
//! I/O. The driver owns the queue and transport; every progress method takes
//! `&mut self`, preserving the one-progress-owner rule from Step 2.

use std::collections::VecDeque;
#[cfg(feature = "sync-sender-qwp-ws")]
use std::io::Write;

#[cfg(feature = "sync-sender-qwp-ws")]
use crate::ErrorCode;
#[cfg(feature = "sync-sender-qwp-ws")]
use crate::ingress::conf::QwpWsConfig;
#[cfg(feature = "sync-sender-qwp-ws")]
use crate::ingress::tls::TlsSettings;

#[cfg(feature = "sync-sender-qwp-ws")]
use super::qwp_ws::{WsStream, establish_connection, read_message, write_binary_frame};
#[cfg(feature = "sync-sender-qwp-ws")]
use super::qwp_ws_codec::{self as codec, PipelinedResponse, WS_OPCODE_BINARY};
use super::qwp_ws_queue::{
    OutboundFrame, QueueError, QwpReceipt, QwpReceiptStatus, SentFrame, VolatileFrameQueue,
    VolatileQueueOptions,
};
use super::qwp_ws_sf_queue::{SfFrameQueue, SfQueueError};

const DEFAULT_EVENT_CAPACITY: usize = 1024;

#[derive(Debug)]
pub(crate) struct ManualDriverPrototype<Q = VolatileFrameQueue, T = FakeOrderedServer> {
    queue: Q,
    transport: T,
    events: DriverEventRing,
    terminal: bool,
    terminal_fsn: Option<u64>,
    closing: bool,
    retry_budget_remaining: Option<usize>,
}

impl ManualDriverPrototype<VolatileFrameQueue> {
    pub(crate) fn new(
        options: VolatileQueueOptions,
        server: FakeOrderedServer,
    ) -> Result<Self, DriverError> {
        Ok(Self {
            queue: VolatileFrameQueue::new(options)?,
            transport: server,
            events: DriverEventRing::new(DEFAULT_EVENT_CAPACITY),
            terminal: false,
            terminal_fsn: None,
            closing: false,
            retry_budget_remaining: None,
        })
    }
}

impl<Q: ManualDriverQueue, T: ManualDriverTransport> ManualDriverPrototype<Q, T> {
    pub(crate) fn from_queue(queue: Q, transport: T) -> Self {
        Self {
            queue,
            transport,
            events: DriverEventRing::new(DEFAULT_EVENT_CAPACITY),
            terminal: false,
            terminal_fsn: None,
            closing: false,
            retry_budget_remaining: None,
        }
    }

    pub(crate) fn from_queue_with_retry_budget(
        queue: Q,
        transport: T,
        retry_budget: usize,
    ) -> Self {
        Self {
            queue,
            transport,
            events: DriverEventRing::new(DEFAULT_EVENT_CAPACITY),
            terminal: false,
            terminal_fsn: None,
            closing: false,
            retry_budget_remaining: Some(retry_budget),
        }
    }

    pub(crate) fn from_queue_with_event_capacity(
        queue: Q,
        transport: T,
        event_capacity: usize,
    ) -> Self {
        Self {
            queue,
            transport,
            events: DriverEventRing::new(event_capacity),
            terminal: false,
            terminal_fsn: None,
            closing: false,
            retry_budget_remaining: None,
        }
    }

    pub(crate) fn try_submit(&mut self, payload: &[u8]) -> Result<QwpReceipt, DriverError> {
        if self.terminal {
            return Err(DriverError::Terminal);
        }
        if self.closing {
            return Err(DriverError::Closing);
        }
        let receipt = self.queue.try_submit(payload)?;
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
            match self.queue.try_submit(payload) {
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
                    | DriverError::Transport
                    | DriverError::Storage
                    | DriverError::CorruptLog { .. }
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

        if !self.transport.send_before_poll() {
            match self.transport.poll_response() {
                Ok(Some(response)) => return self.apply_response(response),
                Ok(None) => {}
                Err(failure) => return self.apply_transport_failure(failure),
            }
        }

        match self.queue.next_outbound_frame() {
            Ok(outbound) => {
                let frame = outbound.sent_frame();
                let send_result = match self.transport.send_frame(outbound) {
                    Ok(result) => result,
                    Err(failure) => return self.apply_transport_failure(failure),
                };
                self.queue.commit_sent(frame)?;
                self.push_event(DriverEvent::Sent {
                    fsn: frame.fsn,
                    wire_seq: frame.wire_seq,
                });

                match send_result {
                    TransportSendResult::NoResponse => Ok(DriveOutcome::Sent(frame)),
                    TransportSendResult::Response(response) => self.apply_response(response),
                    TransportSendResult::Failure(failure) => self.apply_transport_failure(failure),
                }
            }
            Err(DriverError::Queue(
                QueueError::NoUnsentFrame | QueueError::MaxInFlightReached { .. },
            )) => {
                if self.transport.send_before_poll() {
                    match self.transport.poll_response() {
                        Ok(Some(response)) => self.apply_response(response),
                        Ok(None) => Ok(DriveOutcome::Idle),
                        Err(failure) => self.apply_transport_failure(failure),
                    }
                } else {
                    Ok(DriveOutcome::Idle)
                }
            }
            Err(
                err @ (DriverError::Queue(
                    QueueError::InvalidCapacity
                    | QueueError::EmptyPayload
                    | QueueError::FrameCapacityFull { .. }
                    | QueueError::PayloadExceedsByteCapacity { .. }
                    | QueueError::ByteCapacityFull { .. }
                    | QueueError::ProtocolAckWithoutConnection
                    | QueueError::ProtocolAckBeyondSent { .. }
                    | QueueError::ProtocolAckedUnsentFrame { .. }
                    | QueueError::ProtocolRejectWithoutConnection
                    | QueueError::ProtocolRejectBeyondSent { .. }
                    | QueueError::ProtocolRejectedUnsentFrame { .. }
                    | QueueError::OutboundFrameUnavailable { .. }
                    | QueueError::SequenceOverflow,
                )
                | DriverError::Transport
                | DriverError::Storage
                | DriverError::CorruptLog { .. }
                | DriverError::SubmitTimedOut
                | DriverError::Terminal
                | DriverError::Closing
                | DriverError::UnknownReceipt { .. }),
            ) => Err(err),
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
                return Ok(CloseOutcome::Drained);
            }
            if self.drive_once()? == DriveOutcome::Terminal {
                return Ok(CloseOutcome::Terminal);
            }
        }

        if self.terminal {
            Ok(CloseOutcome::Terminal)
        } else if self.all_published_receipts_resolved() {
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
        status
    }

    pub(crate) fn sent_frames(&self) -> &[SentFrame] {
        self.transport.sent_frames()
    }

    pub(crate) fn poll_event(&mut self) -> Option<DriverEvent> {
        self.events.pop()
    }

    pub(crate) fn events_dropped_total(&self) -> u64 {
        self.events.dropped_total()
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
                self.queue.ack_wire(wire_seq)?;
                let completed_after = self.queue.completed_fsn();
                if completed_after > completed_before {
                    let fsn = self.queue.fsn_for_wire_seq(wire_seq)?;
                    self.push_event(DriverEvent::AckedThrough { fsn, wire_seq });
                }
                Ok(DriveOutcome::Acked { wire_seq })
            }
            TransportResponse::Reject { wire_seq } => {
                let receipt = self.queue.reject_wire(wire_seq)?;
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
            TransportFailure::Disconnect => self.restart_connection(ReconnectReason::Disconnect),
            TransportFailure::Retryable => {
                if let Some(remaining) = &mut self.retry_budget_remaining {
                    if *remaining == 0 {
                        self.mark_terminal();
                        return Ok(DriveOutcome::Terminal);
                    }
                    *remaining -= 1;
                }
                self.restart_for_retryable_failure()
            }
            TransportFailure::Terminal => {
                self.mark_terminal();
                Ok(DriveOutcome::Terminal)
            }
        }
    }

    fn restart_for_retryable_failure(&mut self) -> Result<DriveOutcome, DriverError> {
        self.restart_connection(ReconnectReason::RetryableFailure)
    }

    fn restart_connection(&mut self, reason: ReconnectReason) -> Result<DriveOutcome, DriverError> {
        self.transport.restart_connection(reason)?;
        self.queue.restart_connection();
        self.push_event(DriverEvent::Reconnected { reason });
        Ok(DriveOutcome::Reconnected { reason })
    }

    fn mark_terminal(&mut self) {
        if !self.terminal {
            self.terminal = true;
            self.terminal_fsn = self.queue.published_fsn();
            self.push_event(DriverEvent::Terminal);
        }
    }

    fn push_event(&mut self, event: DriverEvent) {
        self.events.push(event);
    }
}

pub(crate) trait ManualDriverQueue {
    fn try_submit(&mut self, payload: &[u8]) -> Result<QwpReceipt, DriverError>;
    fn next_outbound_frame(&self) -> Result<OutboundFrame<'_>, DriverError>;
    fn commit_sent(&mut self, frame: SentFrame) -> Result<(), DriverError>;
    fn ack_wire(&mut self, wire_seq: u64) -> Result<(), DriverError>;
    fn reject_wire(&mut self, wire_seq: u64) -> Result<QwpReceipt, DriverError>;
    fn restart_connection(&mut self);
    fn receipt_status(&self, receipt: QwpReceipt) -> QwpReceiptStatus;
    fn published_fsn(&self) -> Option<u64>;
    fn completed_fsn(&self) -> Option<u64>;
    fn fsn_for_wire_seq(&self, wire_seq: u64) -> Result<u64, DriverError>;
}

pub(crate) trait ManualDriverTransport {
    fn poll_response(&mut self) -> Result<Option<TransportResponse>, TransportFailure>;
    fn send_frame(
        &mut self,
        frame: OutboundFrame<'_>,
    ) -> Result<TransportSendResult, TransportFailure>;

    fn send_before_poll(&self) -> bool {
        false
    }

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
        let (stream, _version) = establish_connection(
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
            stream,
            recv: Vec::new(),
            send_buf: Vec::with_capacity(16 * 1024),
            pending_wire_sequences: VecDeque::new(),
            sent_frames: Vec::new(),
        })
    }

    fn reconnect(&mut self) -> Result<(), DriverError> {
        let (stream, _version) = establish_connection(
            &self.host,
            &self.port,
            self.use_tls,
            self.tls_settings.clone(),
            &self.qwp_ws,
            self.auth_header.as_deref(),
        )
        .map_err(|_| DriverError::Transport)?;
        self.stream = stream;
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

#[cfg(feature = "sync-sender-qwp-ws")]
impl ManualDriverTransport for BlockingQwpWsTransport {
    fn send_before_poll(&self) -> bool {
        true
    }

    fn poll_response(&mut self) -> Result<Option<TransportResponse>, TransportFailure> {
        if self.pending_wire_sequences.is_empty() {
            return Ok(None);
        }

        let opcode =
            read_message(&mut self.stream, &mut self.send_buf, &mut self.recv).map_err(|err| {
                match err.code() {
                    ErrorCode::SocketError => TransportFailure::Disconnect,
                    ErrorCode::AuthError | ErrorCode::ProtocolVersionError => {
                        TransportFailure::Terminal
                    }
                    _ => TransportFailure::Terminal,
                }
            })?;
        if opcode != WS_OPCODE_BINARY {
            return Err(TransportFailure::Terminal);
        }

        match codec::parse_pipelined_response(&self.recv) {
            Ok(PipelinedResponse::Ok { sequence }) => {
                self.complete_pending_through(sequence);
                Ok(Some(TransportResponse::Ack { wire_seq: sequence }))
            }
            Ok(PipelinedResponse::DurableAck) => Ok(None),
            Ok(PipelinedResponse::Error { sequence, err }) => match err.code() {
                ErrorCode::InvalidApiCall => {
                    self.complete_pending_through(sequence);
                    Ok(Some(TransportResponse::Reject { wire_seq: sequence }))
                }
                ErrorCode::ServerFlushError | ErrorCode::SocketError => {
                    Err(TransportFailure::Retryable)
                }
                ErrorCode::AuthError | ErrorCode::ProtocolVersionError => {
                    Err(TransportFailure::Terminal)
                }
                _ => Err(TransportFailure::Terminal),
            },
            Err(_) => Err(TransportFailure::Terminal),
        }
    }

    fn send_frame(
        &mut self,
        frame: OutboundFrame<'_>,
    ) -> Result<TransportSendResult, TransportFailure> {
        let sent_frame = frame.sent_frame();
        write_binary_frame(&mut self.stream, &mut self.send_buf, frame.payload)
            .map_err(|_| TransportFailure::Disconnect)?;
        self.stream
            .flush()
            .map_err(|_| TransportFailure::Disconnect)?;
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

impl ManualDriverQueue for VolatileFrameQueue {
    fn try_submit(&mut self, payload: &[u8]) -> Result<QwpReceipt, DriverError> {
        Ok(VolatileFrameQueue::try_submit(self, payload)?)
    }

    fn next_outbound_frame(&self) -> Result<OutboundFrame<'_>, DriverError> {
        Ok(VolatileFrameQueue::next_outbound_frame(self)?)
    }

    fn commit_sent(&mut self, frame: SentFrame) -> Result<(), DriverError> {
        Ok(VolatileFrameQueue::commit_sent(self, frame)?)
    }

    fn ack_wire(&mut self, wire_seq: u64) -> Result<(), DriverError> {
        Ok(VolatileFrameQueue::ack_wire(self, wire_seq)?)
    }

    fn reject_wire(&mut self, wire_seq: u64) -> Result<QwpReceipt, DriverError> {
        Ok(VolatileFrameQueue::reject_wire(self, wire_seq)?)
    }

    fn restart_connection(&mut self) {
        VolatileFrameQueue::restart_connection(self);
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

    fn fsn_for_wire_seq(&self, wire_seq: u64) -> Result<u64, DriverError> {
        let fsn_at_zero = VolatileFrameQueue::fsn_at_zero(self)
            .ok_or(DriverError::Queue(QueueError::ProtocolAckWithoutConnection))?;
        fsn_at_zero
            .checked_add(wire_seq)
            .ok_or(DriverError::Queue(QueueError::SequenceOverflow))
    }
}

impl ManualDriverQueue for SfFrameQueue {
    fn try_submit(&mut self, payload: &[u8]) -> Result<QwpReceipt, DriverError> {
        Ok(SfFrameQueue::try_submit(self, payload)?)
    }

    fn next_outbound_frame(&self) -> Result<OutboundFrame<'_>, DriverError> {
        Ok(SfFrameQueue::next_outbound_frame(self)?)
    }

    fn commit_sent(&mut self, frame: SentFrame) -> Result<(), DriverError> {
        Ok(SfFrameQueue::commit_sent(self, frame)?)
    }

    fn ack_wire(&mut self, wire_seq: u64) -> Result<(), DriverError> {
        Ok(SfFrameQueue::ack_wire(self, wire_seq)?)
    }

    fn reject_wire(&mut self, wire_seq: u64) -> Result<QwpReceipt, DriverError> {
        Ok(SfFrameQueue::reject_wire(self, wire_seq)?)
    }

    fn restart_connection(&mut self) {
        SfFrameQueue::restart_connection(self);
    }

    fn receipt_status(&self, receipt: QwpReceipt) -> QwpReceiptStatus {
        SfFrameQueue::receipt_status(self, receipt)
    }

    fn published_fsn(&self) -> Option<u64> {
        SfFrameQueue::published_fsn(self)
    }

    fn completed_fsn(&self) -> Option<u64> {
        SfFrameQueue::completed_fsn(self)
    }

    fn fsn_for_wire_seq(&self, wire_seq: u64) -> Result<u64, DriverError> {
        let fsn_at_zero = SfFrameQueue::fsn_at_zero(self)
            .ok_or(DriverError::Queue(QueueError::ProtocolAckWithoutConnection))?;
        fsn_at_zero
            .checked_add(wire_seq)
            .ok_or(DriverError::Queue(QueueError::SequenceOverflow))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DriverError {
    Queue(QueueError),
    Transport,
    Storage,
    CorruptLog { offset: usize, reason: &'static str },
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

impl From<SfQueueError> for DriverError {
    fn from(value: SfQueueError) -> Self {
        match value {
            SfQueueError::Queue(err) => Self::Queue(err),
            SfQueueError::Io(_) => Self::Storage,
            SfQueueError::CorruptLog { offset, reason } => Self::CorruptLog { offset, reason },
        }
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransportSendResult {
    NoResponse,
    Response(TransportResponse),
    Failure(TransportFailure),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransportFailure {
    Disconnect,
    Retryable,
    Terminal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransportResponse {
    Ack { wire_seq: u64 },
    Reject { wire_seq: u64 },
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
        frame: OutboundFrame<'_>,
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
                TransportSendResult::Response(TransportResponse::Reject { wire_seq })
            }
            FakeSendResult::Disconnect => {
                TransportSendResult::Failure(TransportFailure::Disconnect)
            }
            FakeSendResult::RetryableFailure => {
                TransportSendResult::Failure(TransportFailure::Retryable)
            }
            FakeSendResult::TerminalFailure => {
                TransportSendResult::Failure(TransportFailure::Terminal)
            }
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
    use super::super::qwp_ws_sf_queue::SfQueueOptions;
    use super::*;
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
    use tempfile::TempDir;

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

    fn driver_with_retry_budget(
        server: FakeOrderedServer,
        retry_budget: usize,
    ) -> ManualDriverPrototype {
        ManualDriverPrototype::from_queue_with_retry_budget(
            VolatileFrameQueue::new(options(8, 1024, 4)).unwrap(),
            server,
            retry_budget,
        )
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

    fn drain_events<Q: ManualDriverQueue, T: ManualDriverTransport>(
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
        restart_result: Result<(), DriverError>,
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
                restart_result: Ok(()),
                sent_frames: Vec::new(),
                sent_payloads: Vec::new(),
            }
        }

        fn with_restart_result(mut self, restart_result: Result<(), DriverError>) -> Self {
            self.restart_result = restart_result;
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
            frame: OutboundFrame<'_>,
        ) -> Result<TransportSendResult, TransportFailure> {
            self.sent_frames.push(frame.sent_frame());
            self.sent_payloads.push(frame.payload.to_vec());
            self.send_results
                .pop_front()
                .unwrap_or(Ok(TransportSendResult::NoResponse))
        }

        fn restart_connection(&mut self, _reason: ReconnectReason) -> Result<(), DriverError> {
            self.restart_result
        }

        fn sent_frames(&self) -> &[SentFrame] {
            &self.sent_frames
        }
    }

    fn sf_options(dir: &TempDir) -> SfQueueOptions {
        SfQueueOptions {
            dir: dir.path().to_path_buf(),
            max_frames: 8,
            max_bytes: 1024,
            max_in_flight: 4,
        }
    }

    fn sf_driver(dir: &TempDir, server: FakeOrderedServer) -> ManualDriverPrototype<SfFrameQueue> {
        ManualDriverPrototype::from_queue(SfFrameQueue::open(sf_options(dir)).unwrap(), server)
    }

    fn sf_driver_with_retry_budget(
        dir: &TempDir,
        server: FakeOrderedServer,
        retry_budget: usize,
    ) -> ManualDriverPrototype<SfFrameQueue> {
        ManualDriverPrototype::from_queue_with_retry_budget(
            SfFrameQueue::open(sf_options(dir)).unwrap(),
            server,
            retry_budget,
        )
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
    fn transport_reconnect_failure_keeps_sent_receipt_observable() {
        let transport = TestTransport::scripted([Ok(TransportSendResult::Failure(
            TransportFailure::Disconnect,
        ))])
        .with_restart_result(Err(DriverError::Transport));
        let mut driver = ManualDriverPrototype::from_queue(
            VolatileFrameQueue::new(options(8, 1024, 4)).unwrap(),
            transport,
        );
        let receipt = driver.try_submit(b"payload").unwrap();

        assert_eq!(driver.drive_once(), Err(DriverError::Transport));
        assert_eq!(driver.transport.sent_payloads, vec![b"payload".to_vec()]);
        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Sent {
                fsn: 0,
                wire_seq: 0,
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
            ]
        );
    }

    #[test]
    fn transport_write_failure_does_not_commit_sent_receipt() {
        let transport = TestTransport::scripted([Err(TransportFailure::Disconnect)]);
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
        assert_eq!(driver.transport.sent_payloads, vec![b"payload".to_vec()]);
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
            .with_poll_results([Ok(None), Err(TransportFailure::Disconnect)]);
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
    fn retry_budget_exhaustion_terminalizes_current_unresolved_receipts() {
        let mut driver = driver_with_retry_budget(
            FakeOrderedServer::scripted([
                FakeSendResult::RetryableFailure,
                FakeSendResult::RetryableFailure,
            ]),
            1,
        );
        let first = driver.try_submit(b"first").unwrap();
        let second = driver.try_submit(b"second").unwrap();

        assert_eq!(
            driver.drive_once().unwrap(),
            DriveOutcome::Reconnected {
                reason: ReconnectReason::RetryableFailure,
            }
        );
        assert_eq!(
            driver.receipt_status(first),
            QwpReceiptStatus::Published { fsn: 0 }
        );

        assert_eq!(driver.drive_once().unwrap(), DriveOutcome::Terminal);
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
        server.push_response(FakeServerResponse::Ack { wire_seq: 0 });
        let mut driver = driver(server);
        let receipt = driver.try_submit(b"payload").unwrap();

        assert_eq!(
            driver.close_drain_steps(1),
            Err(DriverError::Queue(QueueError::ProtocolAckWithoutConnection))
        );

        assert_eq!(driver.try_submit(b"next"), Err(DriverError::Closing));
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
    fn queued_fake_response_before_connection_is_protocol_error() {
        let mut server = FakeOrderedServer::no_response();
        server.push_response(FakeServerResponse::Ack { wire_seq: 0 });
        let mut driver = driver(server);
        let receipt = driver.try_submit(b"payload").unwrap();

        assert_eq!(
            driver.drive_once(),
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

    #[test]
    fn sf_close_drain_timeout_leaves_unresolved_frame_recoverable() {
        let dir = TempDir::new().unwrap();
        let receipt;
        {
            let mut driver = sf_driver(&dir, FakeOrderedServer::no_response());
            receipt = driver.try_submit(b"payload").unwrap();

            assert_eq!(driver.close_drain_steps(1).unwrap(), CloseOutcome::Timeout);
            assert_eq!(
                driver.receipt_status(receipt),
                QwpReceiptStatus::Sent {
                    fsn: 0,
                    wire_seq: 0,
                }
            );
            assert_eq!(driver.try_submit(b"next"), Err(DriverError::Closing));
        }

        let mut recovered = sf_driver(&dir, FakeOrderedServer::ack_each_send());

        assert_eq!(
            recovered.receipt_status(receipt),
            QwpReceiptStatus::Published { fsn: 0 }
        );
        assert_eq!(
            recovered.close_drain_steps(1).unwrap(),
            CloseOutcome::Drained
        );
        assert_eq!(
            recovered.receipt_status(receipt),
            QwpReceiptStatus::Acked { fsn: 0 }
        );
    }

    #[test]
    fn sf_retry_budget_exhaustion_leaves_unresolved_frame_recoverable() {
        let dir = TempDir::new().unwrap();
        let receipt;
        {
            let mut driver = sf_driver_with_retry_budget(
                &dir,
                FakeOrderedServer::scripted([FakeSendResult::RetryableFailure]),
                0,
            );
            receipt = driver.try_submit(b"payload").unwrap();

            assert_eq!(driver.drive_once().unwrap(), DriveOutcome::Terminal);
            assert_eq!(
                driver.receipt_status(receipt),
                QwpReceiptStatus::Terminal { fsn: 0 }
            );
            assert_eq!(driver.try_submit(b"next"), Err(DriverError::Terminal));
        }

        let mut recovered = sf_driver(&dir, FakeOrderedServer::ack_each_send());

        assert_eq!(
            recovered.receipt_status(receipt),
            QwpReceiptStatus::Published { fsn: 0 }
        );
        assert_eq!(
            recovered.wait_steps(receipt, 1).unwrap(),
            DeliveryOutcome::Acked
        );
    }

    #[test]
    fn sf_driver_reopens_and_replays_from_first_unresolved_fsn() {
        let dir = TempDir::new().unwrap();
        let first;
        let second;
        let third;
        {
            let mut driver = sf_driver(
                &dir,
                FakeOrderedServer::scripted([FakeSendResult::AckSent, FakeSendResult::NoResponse]),
            );
            first = driver.try_submit(b"first").unwrap();
            second = driver.try_submit(b"second").unwrap();
            third = driver.try_submit(b"third").unwrap();

            assert_eq!(
                driver.drive_once().unwrap(),
                DriveOutcome::Acked { wire_seq: 0 }
            );
            assert_eq!(
                driver.drive_once().unwrap(),
                DriveOutcome::Sent(SentFrame {
                    fsn: 1,
                    wire_seq: 1,
                    payload_len: 6,
                })
            );
        }

        let mut recovered = sf_driver(&dir, FakeOrderedServer::ack_each_send());

        assert_eq!(
            recovered.receipt_status(first),
            QwpReceiptStatus::Acked { fsn: 0 }
        );
        assert_eq!(
            recovered.receipt_status(second),
            QwpReceiptStatus::Published { fsn: 1 }
        );
        assert_eq!(
            recovered.receipt_status(third),
            QwpReceiptStatus::Published { fsn: 2 }
        );
        assert_eq!(
            recovered.drive_once().unwrap(),
            DriveOutcome::Acked { wire_seq: 0 }
        );
        assert_eq!(
            recovered.sent_frames(),
            &[SentFrame {
                fsn: 1,
                wire_seq: 0,
                payload_len: 6,
            }]
        );
        assert_eq!(
            recovered.receipt_status(second),
            QwpReceiptStatus::Acked { fsn: 1 }
        );
    }

    #[test]
    fn sf_driver_persists_rejection_gap_and_later_ack_after_reopen() {
        let dir = TempDir::new().unwrap();
        let first;
        let second;
        let third;
        {
            let mut driver = sf_driver(
                &dir,
                FakeOrderedServer::scripted([
                    FakeSendResult::NoResponse,
                    FakeSendResult::RejectWire { wire_seq: 1 },
                    FakeSendResult::AckWire { wire_seq: 2 },
                ]),
            );
            first = driver.try_submit(b"first").unwrap();
            second = driver.try_submit(b"second").unwrap();
            third = driver.try_submit(b"third").unwrap();

            assert!(matches!(
                driver.drive_once().unwrap(),
                DriveOutcome::Sent(_)
            ));
            assert_eq!(
                driver.drive_once().unwrap(),
                DriveOutcome::Rejected {
                    fsn: 1,
                    wire_seq: 1,
                }
            );
            assert_eq!(
                driver.drive_once().unwrap(),
                DriveOutcome::Acked { wire_seq: 2 }
            );
        }

        let mut recovered = sf_driver(&dir, FakeOrderedServer::no_response());

        assert_eq!(
            recovered.wait_steps(first, 0).unwrap(),
            DeliveryOutcome::Acked
        );
        assert_eq!(
            recovered.wait_steps(second, 0).unwrap(),
            DeliveryOutcome::Rejected
        );
        assert_eq!(
            recovered.wait_steps(third, 0).unwrap(),
            DeliveryOutcome::Acked
        );
        assert!(recovered.sent_frames().is_empty());
    }

    #[test]
    fn sf_driver_terminal_failure_does_not_mark_recovered_frames_rejected() {
        let dir = TempDir::new().unwrap();
        let first;
        {
            let mut driver = sf_driver(
                &dir,
                FakeOrderedServer::scripted([FakeSendResult::TerminalFailure]),
            );
            first = driver.try_submit(b"first").unwrap();

            assert_eq!(driver.drive_once().unwrap(), DriveOutcome::Terminal);
            assert_eq!(
                driver.receipt_status(first),
                QwpReceiptStatus::Terminal { fsn: 0 }
            );
            assert_eq!(driver.try_submit(b"second"), Err(DriverError::Terminal));
        }

        let mut recovered = sf_driver(&dir, FakeOrderedServer::ack_each_send());

        assert_eq!(
            recovered.receipt_status(first),
            QwpReceiptStatus::Published { fsn: 0 }
        );
        assert_eq!(
            recovered.wait_steps(first, 1).unwrap(),
            DeliveryOutcome::Acked
        );
        assert_eq!(
            recovered.sent_frames(),
            &[SentFrame {
                fsn: 0,
                wire_seq: 0,
                payload_len: 5,
            }]
        );
    }
}
