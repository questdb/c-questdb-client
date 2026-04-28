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

//! Manual QWP/WebSocket driver prototype over a fake ordered server.
//!
//! This module validates Step 6 control flow without real WebSocket I/O. The
//! driver owns the queue and fake server; every progress method takes
//! `&mut self`, preserving the one-progress-owner rule from Step 2.

use std::collections::VecDeque;

use super::qwp_ws_queue::{
    QueueError, QwpReceipt, QwpReceiptStatus, SentFrame, VolatileFrameQueue, VolatileQueueOptions,
};
use super::qwp_ws_sf_queue::{SfFrameQueue, SfQueueError};

const DEFAULT_EVENT_CAPACITY: usize = 1024;

#[derive(Debug)]
pub(crate) struct ManualDriverPrototype<Q = VolatileFrameQueue> {
    queue: Q,
    server: FakeOrderedServer,
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
            server,
            events: DriverEventRing::new(DEFAULT_EVENT_CAPACITY),
            terminal: false,
            terminal_fsn: None,
            closing: false,
            retry_budget_remaining: None,
        })
    }
}

impl<Q: ManualDriverQueue> ManualDriverPrototype<Q> {
    pub(crate) fn from_queue(queue: Q, server: FakeOrderedServer) -> Self {
        Self {
            queue,
            server,
            events: DriverEventRing::new(DEFAULT_EVENT_CAPACITY),
            terminal: false,
            terminal_fsn: None,
            closing: false,
            retry_budget_remaining: None,
        }
    }

    pub(crate) fn from_queue_with_retry_budget(
        queue: Q,
        server: FakeOrderedServer,
        retry_budget: usize,
    ) -> Self {
        Self {
            queue,
            server,
            events: DriverEventRing::new(DEFAULT_EVENT_CAPACITY),
            terminal: false,
            terminal_fsn: None,
            closing: false,
            retry_budget_remaining: Some(retry_budget),
        }
    }

    pub(crate) fn from_queue_with_event_capacity(
        queue: Q,
        server: FakeOrderedServer,
        event_capacity: usize,
    ) -> Self {
        Self {
            queue,
            server,
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
                        | QueueError::SequenceOverflow,
                    )
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

        if let Some(response) = self.server.poll_response() {
            return self.apply_response(response);
        }

        match self.queue.send_next() {
            Ok(frame) => {
                self.push_event(DriverEvent::Sent {
                    fsn: frame.fsn,
                    wire_seq: frame.wire_seq,
                });
                match self.server.on_send(frame) {
                    FakeSendResult::NoResponse => Ok(DriveOutcome::Sent(frame)),
                    FakeSendResult::AckSent => self.apply_response(FakeServerResponse::Ack {
                        wire_seq: frame.wire_seq,
                    }),
                    FakeSendResult::AckWire { wire_seq } => {
                        self.apply_response(FakeServerResponse::Ack { wire_seq })
                    }
                    FakeSendResult::RejectWire { wire_seq } => {
                        self.apply_response(FakeServerResponse::Reject { wire_seq })
                    }
                    FakeSendResult::Disconnect => {
                        self.apply_response(FakeServerResponse::Disconnect)
                    }
                    FakeSendResult::RetryableFailure => {
                        self.apply_response(FakeServerResponse::RetryableFailure)
                    }
                    FakeSendResult::TerminalFailure => {
                        self.apply_response(FakeServerResponse::TerminalFailure)
                    }
                }
            }
            Err(DriverError::Queue(
                QueueError::NoUnsentFrame | QueueError::MaxInFlightReached { .. },
            )) => Ok(DriveOutcome::Idle),
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
                    | QueueError::SequenceOverflow,
                )
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
        self.server.sent_frames()
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
            QwpReceiptStatus::Poisoned { .. } => Ok(Some(DeliveryOutcome::Poisoned)),
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

    fn apply_response(
        &mut self,
        response: FakeServerResponse,
    ) -> Result<DriveOutcome, DriverError> {
        match response {
            FakeServerResponse::Ack { wire_seq } => {
                let completed_before = self.queue.completed_fsn();
                self.queue.ack_wire(wire_seq)?;
                let completed_after = self.queue.completed_fsn();
                if completed_after > completed_before {
                    let fsn = self.queue.fsn_for_wire_seq(wire_seq)?;
                    self.push_event(DriverEvent::AckedThrough { fsn, wire_seq });
                }
                Ok(DriveOutcome::Acked { wire_seq })
            }
            FakeServerResponse::Reject { wire_seq } => {
                let receipt = self.queue.reject_wire(wire_seq)?;
                if wire_seq > 0 {
                    self.push_event(DriverEvent::AckedThrough {
                        fsn: receipt.fsn - 1,
                        wire_seq: wire_seq - 1,
                    });
                }
                self.push_event(DriverEvent::Poisoned {
                    fsn: receipt.fsn,
                    wire_seq,
                });
                Ok(DriveOutcome::Poisoned {
                    fsn: receipt.fsn,
                    wire_seq,
                })
            }
            FakeServerResponse::Disconnect => self.restart_connection(ReconnectReason::Disconnect),
            FakeServerResponse::RetryableFailure => {
                if let Some(remaining) = &mut self.retry_budget_remaining {
                    if *remaining == 0 {
                        self.mark_terminal();
                        return Ok(DriveOutcome::Terminal);
                    }
                    *remaining -= 1;
                }
                self.restart_for_retryable_failure()
            }
            FakeServerResponse::TerminalFailure => {
                self.mark_terminal();
                Ok(DriveOutcome::Terminal)
            }
        }
    }

    fn restart_for_retryable_failure(&mut self) -> Result<DriveOutcome, DriverError> {
        self.restart_connection(ReconnectReason::RetryableFailure)
    }

    fn restart_connection(&mut self, reason: ReconnectReason) -> Result<DriveOutcome, DriverError> {
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
    fn send_next(&mut self) -> Result<SentFrame, DriverError>;
    fn ack_wire(&mut self, wire_seq: u64) -> Result<(), DriverError>;
    fn reject_wire(&mut self, wire_seq: u64) -> Result<QwpReceipt, DriverError>;
    fn restart_connection(&mut self);
    fn receipt_status(&self, receipt: QwpReceipt) -> QwpReceiptStatus;
    fn published_fsn(&self) -> Option<u64>;
    fn completed_fsn(&self) -> Option<u64>;
    fn fsn_for_wire_seq(&self, wire_seq: u64) -> Result<u64, DriverError>;
}

impl ManualDriverQueue for VolatileFrameQueue {
    fn try_submit(&mut self, payload: &[u8]) -> Result<QwpReceipt, DriverError> {
        Ok(VolatileFrameQueue::try_submit(self, payload)?)
    }

    fn send_next(&mut self) -> Result<SentFrame, DriverError> {
        Ok(VolatileFrameQueue::send_next(self)?)
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

    fn send_next(&mut self) -> Result<SentFrame, DriverError> {
        Ok(SfFrameQueue::send_next(self)?)
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
    Poisoned { fsn: u64, wire_seq: u64 },
    Reconnected { reason: ReconnectReason },
    Terminal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DriverEvent {
    Published { fsn: u64 },
    Sent { fsn: u64, wire_seq: u64 },
    AckedThrough { fsn: u64, wire_seq: u64 },
    Poisoned { fsn: u64, wire_seq: u64 },
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
    Poisoned,
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
    poll_responses: VecDeque<FakeServerResponse>,
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

    pub(crate) fn push_response(&mut self, response: FakeServerResponse) {
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

    fn poll_response(&mut self) -> Option<FakeServerResponse> {
        self.poll_responses.pop_front()
    }

    fn on_send(&mut self, frame: SentFrame) -> FakeSendResult {
        self.sent_frames.push(frame);
        self.send_results
            .pop_front()
            .unwrap_or(self.default_send_result)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FakeServerResponse {
    Ack { wire_seq: u64 },
    Reject { wire_seq: u64 },
    Disconnect,
    RetryableFailure,
    TerminalFailure,
}

#[cfg(test)]
mod tests {
    use super::super::qwp_ws_sf_queue::SfQueueOptions;
    use super::*;
    use tempfile::TempDir;

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

    fn drain_events(driver: &mut ManualDriverPrototype) -> Vec<DriverEvent> {
        let mut events = Vec::new();
        while let Some(event) = driver.poll_event() {
            events.push(event);
        }
        events
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
            .server
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
            DriveOutcome::Poisoned {
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
            QwpReceiptStatus::Poisoned { fsn: 1 }
        );
        assert_eq!(
            driver.receipt_status(third),
            QwpReceiptStatus::Published { fsn: 2 }
        );
    }

    #[test]
    fn poison_event_agrees_with_wait_and_receipt_status() {
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
            DeliveryOutcome::Poisoned
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
                DriverEvent::Poisoned {
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
            QwpReceiptStatus::Poisoned { fsn: 1 }
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
            DriveOutcome::Poisoned {
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
            QwpReceiptStatus::Poisoned { fsn: 1 }
        );
        assert_eq!(
            driver.receipt_status(third),
            QwpReceiptStatus::Acked { fsn: 2 }
        );
    }

    #[test]
    fn wait_reports_poisoned_receipt() {
        let mut driver = driver(FakeOrderedServer::scripted([FakeSendResult::RejectWire {
            wire_seq: 0,
        }]));
        let receipt = driver.try_submit(b"payload").unwrap();

        let outcome = driver.wait_steps(receipt, 1).unwrap();

        assert_eq!(outcome, DeliveryOutcome::Poisoned);
        assert_eq!(
            driver.receipt_status(receipt),
            QwpReceiptStatus::Poisoned { fsn: 0 }
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
    fn sf_driver_persists_poison_gap_and_later_ack_after_reopen() {
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
                DriveOutcome::Poisoned {
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
            DeliveryOutcome::Poisoned
        );
        assert_eq!(
            recovered.wait_steps(third, 0).unwrap(),
            DeliveryOutcome::Acked
        );
        assert!(recovered.sent_frames().is_empty());
    }

    #[test]
    fn sf_driver_terminal_failure_does_not_poison_recovered_frames() {
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
