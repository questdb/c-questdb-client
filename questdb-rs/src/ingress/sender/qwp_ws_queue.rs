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

//! Transport-free volatile QWP/WebSocket queue prototype.
//!
//! This module validates the Step 5 queue and receipt semantics without real
//! WebSocket I/O, disk Store-and-Forward, or public FFI shape. Frames are opaque
//! QWP payload bytes; the replay encoder is validated separately.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct QwpReceipt {
    pub(crate) fsn: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QwpReceiptStatus {
    Unknown { fsn: u64 },
    Published { fsn: u64 },
    Sent { fsn: u64, wire_seq: u64 },
    Acked { fsn: u64 },
    Poisoned { fsn: u64 },
    Terminal { fsn: u64 },
}

impl QwpReceiptStatus {
    pub(crate) fn is_pending(&self) -> bool {
        matches!(
            self,
            QwpReceiptStatus::Published { .. } | QwpReceiptStatus::Sent { .. }
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VolatileQueueOptions {
    pub(crate) max_frames: usize,
    pub(crate) max_bytes: usize,
    pub(crate) max_in_flight: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SentFrame {
    pub(crate) fsn: u64,
    pub(crate) wire_seq: u64,
    pub(crate) payload_len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OutboundFrame<'a> {
    pub(crate) fsn: u64,
    pub(crate) wire_seq: u64,
    pub(crate) payload: &'a [u8],
}

impl OutboundFrame<'_> {
    pub(crate) fn sent_frame(&self) -> SentFrame {
        SentFrame {
            fsn: self.fsn,
            wire_seq: self.wire_seq,
            payload_len: self.payload.len(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QueueError {
    InvalidCapacity,
    EmptyPayload,
    FrameCapacityFull {
        max_frames: usize,
    },
    PayloadExceedsByteCapacity {
        payload_len: usize,
        max_bytes: usize,
    },
    ByteCapacityFull {
        payload_len: usize,
        bytes_used: usize,
        max_bytes: usize,
    },
    MaxInFlightReached {
        max_in_flight: usize,
    },
    NoUnsentFrame,
    ProtocolAckWithoutConnection,
    ProtocolAckBeyondSent {
        wire_seq: u64,
        last_sent_wire_seq: Option<u64>,
    },
    ProtocolAckedUnsentFrame {
        fsn: u64,
    },
    ProtocolRejectWithoutConnection,
    ProtocolRejectBeyondSent {
        wire_seq: u64,
        last_sent_wire_seq: Option<u64>,
    },
    ProtocolRejectedUnsentFrame {
        fsn: u64,
    },
    OutboundFrameUnavailable {
        fsn: u64,
        wire_seq: u64,
    },
    SequenceOverflow,
}

#[derive(Debug)]
pub(crate) struct VolatileFrameQueue {
    slots: Vec<FrameSlot>,
    head: usize,
    len: usize,
    bytes_used: usize,
    max_bytes: usize,
    next_fsn: u64,
    published_fsn: Option<u64>,
    server_acked_fsn: Option<u64>,
    completed_fsn: Option<u64>,
    poisoned_fsns: Vec<u64>,
    connection: ConnectionState,
    in_flight: InFlightRing,
}

impl VolatileFrameQueue {
    pub(crate) fn new(options: VolatileQueueOptions) -> Result<Self, QueueError> {
        if options.max_frames == 0 || options.max_bytes == 0 || options.max_in_flight == 0 {
            return Err(QueueError::InvalidCapacity);
        }
        if options.max_in_flight > options.max_frames {
            return Err(QueueError::InvalidCapacity);
        }

        let slots = (0..options.max_frames)
            .map(|_| FrameSlot::default())
            .collect();

        Ok(Self {
            slots,
            head: 0,
            len: 0,
            bytes_used: 0,
            max_bytes: options.max_bytes,
            next_fsn: 0,
            published_fsn: None,
            server_acked_fsn: None,
            completed_fsn: None,
            poisoned_fsns: Vec::new(),
            connection: ConnectionState::default(),
            in_flight: InFlightRing::new(options.max_in_flight),
        })
    }

    pub(crate) fn try_submit(&mut self, payload: &[u8]) -> Result<QwpReceipt, QueueError> {
        if payload.is_empty() {
            return Err(QueueError::EmptyPayload);
        }
        if self.len == self.slots.len() {
            return Err(QueueError::FrameCapacityFull {
                max_frames: self.slots.len(),
            });
        }
        if payload.len() > self.max_bytes {
            return Err(QueueError::PayloadExceedsByteCapacity {
                payload_len: payload.len(),
                max_bytes: self.max_bytes,
            });
        }
        let Some(new_bytes_used) = self.bytes_used.checked_add(payload.len()) else {
            return Err(QueueError::ByteCapacityFull {
                payload_len: payload.len(),
                bytes_used: self.bytes_used,
                max_bytes: self.max_bytes,
            });
        };
        if new_bytes_used > self.max_bytes {
            return Err(QueueError::ByteCapacityFull {
                payload_len: payload.len(),
                bytes_used: self.bytes_used,
                max_bytes: self.max_bytes,
            });
        }

        let fsn = self.next_fsn;
        self.next_fsn = self
            .next_fsn
            .checked_add(1)
            .ok_or(QueueError::SequenceOverflow)?;

        let tail = self.slot_index(self.len);
        let slot = &mut self.slots[tail];
        slot.fsn = fsn;
        slot.payload.clear();
        slot.payload.extend_from_slice(payload);
        slot.state = FrameState::Published;

        self.len += 1;
        self.bytes_used = new_bytes_used;
        self.published_fsn = Some(fsn);

        Ok(QwpReceipt { fsn })
    }

    pub(crate) fn send_next(&mut self) -> Result<SentFrame, QueueError> {
        let frame = {
            let outbound = self.next_outbound_frame()?;
            outbound.sent_frame()
        };
        self.commit_sent(frame)?;
        Ok(frame)
    }

    pub(crate) fn next_outbound_frame(&self) -> Result<OutboundFrame<'_>, QueueError> {
        if self.in_flight.is_full() {
            return Err(QueueError::MaxInFlightReached {
                max_in_flight: self.in_flight.capacity(),
            });
        }

        let Some(offset) = self.first_published_offset() else {
            return Err(QueueError::NoUnsentFrame);
        };

        let wire_seq = self.connection.next_wire_seq;
        wire_seq
            .checked_add(1)
            .ok_or(QueueError::SequenceOverflow)?;

        let index = self.slot_index(offset);
        let slot = &self.slots[index];
        Ok(OutboundFrame {
            fsn: slot.fsn,
            wire_seq,
            payload: &slot.payload,
        })
    }

    pub(crate) fn commit_sent(&mut self, frame: SentFrame) -> Result<(), QueueError> {
        if self.in_flight.is_full() {
            return Err(QueueError::MaxInFlightReached {
                max_in_flight: self.in_flight.capacity(),
            });
        }

        let Some(offset) = self.first_published_offset() else {
            return Err(QueueError::NoUnsentFrame);
        };
        let index = self.slot_index(offset);
        let slot = &self.slots[index];
        if slot.fsn != frame.fsn
            || !matches!(slot.state, FrameState::Published)
            || slot.payload.len() != frame.payload_len
            || self.connection.next_wire_seq != frame.wire_seq
        {
            return Err(QueueError::OutboundFrameUnavailable {
                fsn: frame.fsn,
                wire_seq: frame.wire_seq,
            });
        }
        let next_wire_seq = self
            .connection
            .next_wire_seq
            .checked_add(1)
            .ok_or(QueueError::SequenceOverflow)?;

        self.ensure_connection_started()?;
        self.connection.next_wire_seq = next_wire_seq;
        self.connection.last_sent_wire_seq = Some(frame.wire_seq);

        let slot = &mut self.slots[index];
        slot.state = FrameState::Sent {
            wire_seq: frame.wire_seq,
        };
        self.in_flight.push(InFlightSlot {
            fsn: slot.fsn,
            wire_seq: frame.wire_seq,
        })?;
        Ok(())
    }

    pub(crate) fn ack_wire(&mut self, wire_seq: u64) -> Result<(), QueueError> {
        let Some(fsn_at_zero) = self.connection.fsn_at_zero else {
            return Err(QueueError::ProtocolAckWithoutConnection);
        };
        let last_sent_wire_seq = self.connection.last_sent_wire_seq;
        if last_sent_wire_seq.is_none_or(|last_sent| wire_seq > last_sent) {
            return Err(QueueError::ProtocolAckBeyondSent {
                wire_seq,
                last_sent_wire_seq,
            });
        }

        let acked_fsn = fsn_at_zero
            .checked_add(wire_seq)
            .ok_or(QueueError::SequenceOverflow)?;

        if self
            .server_acked_fsn
            .is_some_and(|server_acked_fsn| acked_fsn <= server_acked_fsn)
        {
            return Ok(());
        }

        self.complete_through(acked_fsn)?;
        self.advance_server_acked_to(acked_fsn);
        Ok(())
    }

    pub(crate) fn reject_wire(&mut self, wire_seq: u64) -> Result<QwpReceipt, QueueError> {
        let Some(fsn_at_zero) = self.connection.fsn_at_zero else {
            return Err(QueueError::ProtocolRejectWithoutConnection);
        };
        let last_sent_wire_seq = self.connection.last_sent_wire_seq;
        if last_sent_wire_seq.is_none_or(|last_sent| wire_seq > last_sent) {
            return Err(QueueError::ProtocolRejectBeyondSent {
                wire_seq,
                last_sent_wire_seq,
            });
        }

        let rejected_fsn = fsn_at_zero
            .checked_add(wire_seq)
            .ok_or(QueueError::SequenceOverflow)?;

        if rejected_fsn > fsn_at_zero {
            let prior_fsn = rejected_fsn - 1;
            if self
                .completed_fsn
                .is_none_or(|completed_fsn| prior_fsn > completed_fsn)
            {
                self.complete_through(prior_fsn)?;
            }
            self.advance_server_acked_to(prior_fsn);
        }

        self.complete_poisoned(rejected_fsn)?;
        Ok(QwpReceipt { fsn: rejected_fsn })
    }

    fn advance_server_acked_to(&mut self, acked_fsn: u64) {
        let candidate = match self
            .poisoned_fsns
            .iter()
            .copied()
            .filter(|poisoned_fsn| *poisoned_fsn <= acked_fsn)
            .min()
        {
            Some(0) => None,
            Some(first_poisoned_fsn) => Some(first_poisoned_fsn - 1),
            None => Some(acked_fsn),
        };

        if let Some(candidate) = candidate
            && self
                .server_acked_fsn
                .is_none_or(|server_acked_fsn| candidate > server_acked_fsn)
        {
            self.server_acked_fsn = Some(candidate);
        }
    }

    pub(crate) fn restart_connection(&mut self) {
        self.in_flight.clear();
        self.connection = ConnectionState::default();
        for offset in 0..self.len {
            let index = self.slot_index(offset);
            if matches!(self.slots[index].state, FrameState::Sent { .. }) {
                self.slots[index].state = FrameState::Published;
            }
        }
    }

    pub(crate) fn receipt_status(&self, receipt: QwpReceipt) -> QwpReceiptStatus {
        let fsn = receipt.fsn;
        if self.poisoned_fsns.contains(&fsn) {
            return QwpReceiptStatus::Poisoned { fsn };
        }
        if self
            .completed_fsn
            .is_some_and(|completed_fsn| fsn <= completed_fsn)
        {
            return QwpReceiptStatus::Acked { fsn };
        }
        if self
            .published_fsn
            .is_none_or(|published_fsn| fsn > published_fsn)
        {
            return QwpReceiptStatus::Unknown { fsn };
        }

        if let Some(slot) = self.slot_for_fsn(fsn) {
            return match slot.state {
                FrameState::Published => QwpReceiptStatus::Published { fsn },
                FrameState::Sent { wire_seq } => QwpReceiptStatus::Sent { fsn, wire_seq },
                FrameState::Free => QwpReceiptStatus::Unknown { fsn },
            };
        }

        QwpReceiptStatus::Unknown { fsn }
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn bytes_used(&self) -> usize {
        self.bytes_used
    }

    pub(crate) fn in_flight_len(&self) -> usize {
        self.in_flight.len()
    }

    pub(crate) fn fsn_at_zero(&self) -> Option<u64> {
        self.connection.fsn_at_zero
    }

    pub(crate) fn published_fsn(&self) -> Option<u64> {
        self.published_fsn
    }

    pub(crate) fn server_acked_fsn(&self) -> Option<u64> {
        self.server_acked_fsn
    }

    pub(crate) fn completed_fsn(&self) -> Option<u64> {
        self.completed_fsn
    }

    fn ensure_connection_started(&mut self) -> Result<(), QueueError> {
        if self.connection.fsn_at_zero.is_none() {
            self.connection.fsn_at_zero = Some(self.oldest_unresolved_fsn()?);
        }
        Ok(())
    }

    fn oldest_unresolved_fsn(&self) -> Result<u64, QueueError> {
        if self.len == 0 {
            return Err(QueueError::NoUnsentFrame);
        }
        Ok(self.slots[self.head].fsn)
    }

    fn first_published_offset(&self) -> Option<usize> {
        (0..self.len).find(|offset| {
            let index = self.slot_index(*offset);
            matches!(self.slots[index].state, FrameState::Published)
        })
    }

    fn complete_through(&mut self, acked_fsn: u64) -> Result<(), QueueError> {
        let mut complete_count = 0;
        for offset in 0..self.len {
            let index = self.slot_index(offset);
            let slot = &self.slots[index];
            if slot.fsn > acked_fsn {
                break;
            }
            if !matches!(slot.state, FrameState::Sent { .. }) {
                return Err(QueueError::ProtocolAckedUnsentFrame { fsn: slot.fsn });
            }
            complete_count += 1;
        }

        for _ in 0..complete_count {
            let head = self.head;
            let fsn = self.slots[head].fsn;
            self.bytes_used -= self.slots[head].payload.len();
            self.slots[head].payload.clear();
            self.slots[head].state = FrameState::Free;
            self.completed_fsn = Some(fsn);
            self.head = (self.head + 1) % self.slots.len();
            self.len -= 1;
        }

        self.in_flight.pop_acked_through(acked_fsn);
        Ok(())
    }

    fn complete_poisoned(&mut self, rejected_fsn: u64) -> Result<(), QueueError> {
        if self.len == 0 || self.slots[self.head].fsn != rejected_fsn {
            return Err(QueueError::ProtocolRejectedUnsentFrame { fsn: rejected_fsn });
        }
        if !matches!(self.slots[self.head].state, FrameState::Sent { .. }) {
            return Err(QueueError::ProtocolRejectedUnsentFrame { fsn: rejected_fsn });
        }

        self.bytes_used -= self.slots[self.head].payload.len();
        self.slots[self.head].payload.clear();
        self.slots[self.head].state = FrameState::Free;
        self.completed_fsn = Some(rejected_fsn);
        self.poisoned_fsns.push(rejected_fsn);
        self.head = (self.head + 1) % self.slots.len();
        self.len -= 1;
        self.in_flight.pop_acked_through(rejected_fsn);
        Ok(())
    }

    fn slot_for_fsn(&self, fsn: u64) -> Option<&FrameSlot> {
        if self.len == 0 {
            return None;
        }
        let oldest = self.slots[self.head].fsn;
        if fsn < oldest {
            return None;
        }
        let offset = usize::try_from(fsn.checked_sub(oldest)?).ok()?;
        if offset >= self.len {
            return None;
        }
        Some(&self.slots[self.slot_index(offset)])
    }

    fn slot_index(&self, offset: usize) -> usize {
        (self.head + offset) % self.slots.len()
    }
}

#[derive(Debug, Default)]
struct FrameSlot {
    fsn: u64,
    payload: Vec<u8>,
    state: FrameState,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum FrameState {
    #[default]
    Free,
    Published,
    Sent {
        wire_seq: u64,
    },
}

#[derive(Debug, Default)]
struct ConnectionState {
    fsn_at_zero: Option<u64>,
    next_wire_seq: u64,
    last_sent_wire_seq: Option<u64>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct InFlightSlot {
    fsn: u64,
    wire_seq: u64,
}

#[derive(Debug)]
struct InFlightRing {
    slots: Vec<InFlightSlot>,
    head: usize,
    len: usize,
}

impl InFlightRing {
    fn new(capacity: usize) -> Self {
        Self {
            slots: vec![InFlightSlot::default(); capacity],
            head: 0,
            len: 0,
        }
    }

    fn capacity(&self) -> usize {
        self.slots.len()
    }

    fn len(&self) -> usize {
        self.len
    }

    fn is_full(&self) -> bool {
        self.len == self.slots.len()
    }

    fn push(&mut self, slot: InFlightSlot) -> Result<(), QueueError> {
        if self.is_full() {
            return Err(QueueError::MaxInFlightReached {
                max_in_flight: self.capacity(),
            });
        }
        let tail = self.slot_index(self.len);
        self.slots[tail] = slot;
        self.len += 1;
        Ok(())
    }

    fn pop_acked_through(&mut self, acked_fsn: u64) {
        while self.len > 0 {
            let slot = self.slots[self.head];
            if slot.fsn > acked_fsn {
                break;
            }
            self.head = (self.head + 1) % self.slots.len();
            self.len -= 1;
        }
    }

    fn clear(&mut self) {
        self.head = 0;
        self.len = 0;
    }

    fn slot_index(&self, offset: usize) -> usize {
        (self.head + offset) % self.slots.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn queue(max_frames: usize, max_bytes: usize, max_in_flight: usize) -> VolatileFrameQueue {
        VolatileFrameQueue::new(VolatileQueueOptions {
            max_frames,
            max_bytes,
            max_in_flight,
        })
        .unwrap()
    }

    #[test]
    fn invalid_capacity_options_are_rejected() {
        assert_eq!(
            VolatileFrameQueue::new(VolatileQueueOptions {
                max_frames: 0,
                max_bytes: 1024,
                max_in_flight: 1,
            })
            .unwrap_err(),
            QueueError::InvalidCapacity
        );
        assert_eq!(
            VolatileFrameQueue::new(VolatileQueueOptions {
                max_frames: 1,
                max_bytes: 0,
                max_in_flight: 1,
            })
            .unwrap_err(),
            QueueError::InvalidCapacity
        );
        assert_eq!(
            VolatileFrameQueue::new(VolatileQueueOptions {
                max_frames: 1,
                max_bytes: 1024,
                max_in_flight: 0,
            })
            .unwrap_err(),
            QueueError::InvalidCapacity
        );
        assert_eq!(
            VolatileFrameQueue::new(VolatileQueueOptions {
                max_frames: 1,
                max_bytes: 1024,
                max_in_flight: 2,
            })
            .unwrap_err(),
            QueueError::InvalidCapacity
        );
    }

    #[test]
    fn pending_helper_is_false_for_terminal_statuses() {
        assert!(!QwpReceiptStatus::Unknown { fsn: 0 }.is_pending());
        assert!(!QwpReceiptStatus::Acked { fsn: 0 }.is_pending());
        assert!(!QwpReceiptStatus::Poisoned { fsn: 0 }.is_pending());
        assert!(!QwpReceiptStatus::Terminal { fsn: 0 }.is_pending());
    }

    #[test]
    fn submit_returns_value_receipts_and_published_status() {
        let mut queue = queue(4, 1024, 2);

        let first = queue.try_submit(b"first").unwrap();
        let second = queue.try_submit(b"second").unwrap();

        assert_eq!(first, QwpReceipt { fsn: 0 });
        assert_eq!(second, QwpReceipt { fsn: 1 });
        assert_eq!(queue.published_fsn(), Some(1));
        assert_eq!(
            queue.receipt_status(first),
            QwpReceiptStatus::Published { fsn: 0 }
        );
        assert!(queue.receipt_status(second).is_pending());
    }

    #[test]
    fn empty_payload_is_rejected_without_consuming_fsn() {
        let mut queue = queue(4, 1024, 2);

        assert_eq!(queue.try_submit(b""), Err(QueueError::EmptyPayload));
        assert_eq!(queue.len(), 0);
        assert_eq!(queue.bytes_used(), 0);

        let receipt = queue.try_submit(b"payload").unwrap();
        assert_eq!(receipt, QwpReceipt { fsn: 0 });
    }

    #[test]
    fn send_next_on_empty_queue_returns_no_unsent_frame() {
        let mut queue = queue(1, 1024, 1);

        assert_eq!(queue.send_next(), Err(QueueError::NoUnsentFrame));
    }

    #[test]
    fn byte_capacity_arithmetic_overflow_is_reported_as_capacity_full() {
        let mut queue = queue(4, usize::MAX, 2);
        queue.bytes_used = usize::MAX;

        assert_eq!(
            queue.try_submit(b"x"),
            Err(QueueError::ByteCapacityFull {
                payload_len: 1,
                bytes_used: usize::MAX,
                max_bytes: usize::MAX
            })
        );
    }

    #[test]
    fn queue_full_is_deterministic_and_returns_no_receipt() {
        let mut queue = queue(2, 7, 2);

        let first = queue.try_submit(b"abc").unwrap();
        let second = queue.try_submit(b"de").unwrap();

        assert_eq!(
            queue.try_submit(b"fg"),
            Err(QueueError::FrameCapacityFull { max_frames: 2 })
        );
        assert_eq!(queue.len(), 2);
        assert_eq!(queue.bytes_used(), 5);
        assert_eq!(
            queue.receipt_status(first),
            QwpReceiptStatus::Published { fsn: 0 }
        );
        assert_eq!(
            queue.receipt_status(second),
            QwpReceiptStatus::Published { fsn: 1 }
        );

        queue.send_next().unwrap();
        queue.ack_wire(0).unwrap();

        let third = queue.try_submit(b"fg").unwrap();
        assert_eq!(third, QwpReceipt { fsn: 2 });
    }

    #[test]
    fn byte_capacity_full_is_deterministic() {
        let mut queue = queue(4, 5, 2);

        queue.try_submit(b"abc").unwrap();

        assert_eq!(
            queue.try_submit(b"def"),
            Err(QueueError::ByteCapacityFull {
                payload_len: 3,
                bytes_used: 3,
                max_bytes: 5
            })
        );
        assert_eq!(
            queue.try_submit(b"abcdef"),
            Err(QueueError::PayloadExceedsByteCapacity {
                payload_len: 6,
                max_bytes: 5
            })
        );
    }

    #[test]
    fn send_assigns_zero_based_wire_sequences_in_fsn_order() {
        let mut queue = queue(4, 1024, 3);
        let first = queue.try_submit(b"first").unwrap();
        let second = queue.try_submit(b"second").unwrap();

        assert_eq!(
            queue.send_next().unwrap(),
            SentFrame {
                fsn: 0,
                wire_seq: 0,
                payload_len: 5
            }
        );
        assert_eq!(queue.fsn_at_zero(), Some(0));
        assert_eq!(
            queue.receipt_status(first),
            QwpReceiptStatus::Sent {
                fsn: 0,
                wire_seq: 0
            }
        );

        assert_eq!(
            queue.send_next().unwrap(),
            SentFrame {
                fsn: 1,
                wire_seq: 1,
                payload_len: 6
            }
        );
        assert_eq!(
            queue.receipt_status(second),
            QwpReceiptStatus::Sent {
                fsn: 1,
                wire_seq: 1
            }
        );
        assert_eq!(queue.send_next(), Err(QueueError::NoUnsentFrame));
    }

    #[test]
    fn max_in_flight_applies_backpressure_to_sends_not_submission() {
        let mut queue = queue(4, 1024, 2);
        queue.try_submit(b"a").unwrap();
        queue.try_submit(b"b").unwrap();
        let third = queue.try_submit(b"c").unwrap();

        queue.send_next().unwrap();
        queue.send_next().unwrap();

        assert_eq!(
            queue.send_next(),
            Err(QueueError::MaxInFlightReached { max_in_flight: 2 })
        );
        assert_eq!(
            queue.receipt_status(third),
            QwpReceiptStatus::Published { fsn: 2 }
        );
    }

    #[test]
    fn cumulative_ack_completes_all_covered_receipts_and_frees_slots() {
        let mut queue = queue(4, 1024, 3);
        let first = queue.try_submit(b"a").unwrap();
        let second = queue.try_submit(b"bb").unwrap();
        let third = queue.try_submit(b"ccc").unwrap();
        queue.send_next().unwrap();
        queue.send_next().unwrap();
        queue.send_next().unwrap();

        queue.ack_wire(2).unwrap();

        assert_eq!(queue.server_acked_fsn(), Some(2));
        assert_eq!(queue.completed_fsn(), Some(2));
        assert_eq!(queue.len(), 0);
        assert_eq!(queue.bytes_used(), 0);
        assert_eq!(queue.in_flight_len(), 0);
        assert_eq!(
            queue.receipt_status(first),
            QwpReceiptStatus::Acked { fsn: 0 }
        );
        assert_eq!(
            queue.receipt_status(second),
            QwpReceiptStatus::Acked { fsn: 1 }
        );
        assert_eq!(
            queue.receipt_status(third),
            QwpReceiptStatus::Acked { fsn: 2 }
        );
    }

    #[test]
    fn later_frames_never_jump_earlier_unresolved_frames() {
        let mut queue = queue(4, 1024, 3);
        let first = queue.try_submit(b"first").unwrap();
        let second = queue.try_submit(b"second").unwrap();
        let third = queue.try_submit(b"third").unwrap();

        let sent_first = queue.send_next().unwrap();
        let sent_second = queue.send_next().unwrap();
        let sent_third = queue.send_next().unwrap();

        assert_eq!(sent_first.fsn, first.fsn);
        assert_eq!(sent_second.fsn, second.fsn);
        assert_eq!(sent_third.fsn, third.fsn);
        assert_eq!(sent_first.wire_seq, 0);
        assert_eq!(sent_second.wire_seq, 1);
        assert_eq!(sent_third.wire_seq, 2);
    }

    #[test]
    fn ack_beyond_last_sent_is_protocol_error() {
        let mut queue = queue(4, 1024, 3);
        queue.try_submit(b"a").unwrap();
        queue.try_submit(b"b").unwrap();
        queue.send_next().unwrap();

        assert_eq!(
            queue.ack_wire(1),
            Err(QueueError::ProtocolAckBeyondSent {
                wire_seq: 1,
                last_sent_wire_seq: Some(0)
            })
        );
    }

    #[test]
    fn stale_ack_is_ignored_after_receipt_already_completed() {
        let mut queue = queue(4, 1024, 3);
        let first = queue.try_submit(b"first").unwrap();
        let second = queue.try_submit(b"second").unwrap();
        queue.send_next().unwrap();
        queue.send_next().unwrap();
        queue.ack_wire(1).unwrap();

        queue.ack_wire(0).unwrap();

        assert_eq!(queue.server_acked_fsn(), Some(1));
        assert_eq!(queue.completed_fsn(), Some(1));
        assert_eq!(
            queue.receipt_status(first),
            QwpReceiptStatus::Acked { fsn: 0 }
        );
        assert_eq!(
            queue.receipt_status(second),
            QwpReceiptStatus::Acked { fsn: 1 }
        );
    }

    #[test]
    fn ack_covering_published_but_unsent_frame_is_protocol_error() {
        let mut queue = queue(4, 1024, 3);
        queue.try_submit(b"first").unwrap();
        queue.try_submit(b"second").unwrap();
        queue.send_next().unwrap();

        queue.connection.last_sent_wire_seq = Some(1);

        assert_eq!(
            queue.ack_wire(1),
            Err(QueueError::ProtocolAckedUnsentFrame { fsn: 1 })
        );
    }

    #[test]
    fn reject_marks_frame_poisoned_acks_prior_only_and_leaves_later_unresolved() {
        let mut queue = queue(4, 1024, 3);
        let first = queue.try_submit(b"first").unwrap();
        let second = queue.try_submit(b"second").unwrap();
        let third = queue.try_submit(b"third").unwrap();
        queue.send_next().unwrap();
        queue.send_next().unwrap();
        queue.send_next().unwrap();

        assert_eq!(queue.reject_wire(1).unwrap(), second);

        assert_eq!(queue.server_acked_fsn(), Some(0));
        assert_eq!(queue.completed_fsn(), Some(1));
        assert_eq!(
            queue.receipt_status(first),
            QwpReceiptStatus::Acked { fsn: 0 }
        );
        assert_eq!(
            queue.receipt_status(second),
            QwpReceiptStatus::Poisoned { fsn: 1 }
        );
        assert_eq!(
            queue.receipt_status(third),
            QwpReceiptStatus::Sent {
                fsn: 2,
                wire_seq: 2
            }
        );
    }

    #[test]
    fn first_frame_poison_gap_prevents_server_acked_from_advancing() {
        let mut queue = queue(4, 1024, 3);
        let first = queue.try_submit(b"first").unwrap();
        let second = queue.try_submit(b"second").unwrap();
        queue.send_next().unwrap();
        queue.send_next().unwrap();

        queue.reject_wire(0).unwrap();
        queue.ack_wire(1).unwrap();

        assert_eq!(queue.server_acked_fsn(), None);
        assert_eq!(queue.completed_fsn(), Some(1));
        assert_eq!(
            queue.receipt_status(first),
            QwpReceiptStatus::Poisoned { fsn: 0 }
        );
        assert_eq!(
            queue.receipt_status(second),
            QwpReceiptStatus::Acked { fsn: 1 }
        );
    }

    #[test]
    fn reject_without_connection_is_protocol_error() {
        let mut queue = queue(4, 1024, 3);
        queue.try_submit(b"first").unwrap();

        assert_eq!(
            queue.reject_wire(0),
            Err(QueueError::ProtocolRejectWithoutConnection)
        );
    }

    #[test]
    fn reject_beyond_last_sent_is_protocol_error() {
        let mut queue = queue(4, 1024, 3);
        queue.try_submit(b"first").unwrap();
        queue.send_next().unwrap();

        assert_eq!(
            queue.reject_wire(1),
            Err(QueueError::ProtocolRejectBeyondSent {
                wire_seq: 1,
                last_sent_wire_seq: Some(0)
            })
        );
    }

    #[test]
    fn reject_already_completed_frame_is_protocol_error() {
        let mut queue = queue(4, 1024, 3);
        queue.try_submit(b"first").unwrap();
        queue.try_submit(b"second").unwrap();
        queue.send_next().unwrap();
        queue.send_next().unwrap();
        queue.ack_wire(0).unwrap();

        assert_eq!(
            queue.reject_wire(0),
            Err(QueueError::ProtocolRejectedUnsentFrame { fsn: 0 })
        );
    }

    #[test]
    fn reject_published_frame_with_forged_connection_state_is_protocol_error() {
        let mut queue = queue(4, 1024, 3);
        queue.try_submit(b"first").unwrap();
        queue.connection.fsn_at_zero = Some(0);
        queue.connection.last_sent_wire_seq = Some(0);

        assert_eq!(
            queue.reject_wire(0),
            Err(QueueError::ProtocolRejectedUnsentFrame { fsn: 0 })
        );
    }

    #[test]
    fn reject_published_but_unsent_frame_is_protocol_error() {
        let mut queue = queue(4, 1024, 3);
        queue.try_submit(b"first").unwrap();
        queue.try_submit(b"second").unwrap();
        queue.send_next().unwrap();

        assert_eq!(
            queue.reject_wire(1),
            Err(QueueError::ProtocolRejectBeyondSent {
                wire_seq: 1,
                last_sent_wire_seq: Some(0)
            })
        );
    }

    #[test]
    fn ack_after_reject_completes_later_receipt_without_crossing_poison_gap() {
        let mut queue = queue(4, 1024, 3);
        let first = queue.try_submit(b"first").unwrap();
        let second = queue.try_submit(b"second").unwrap();
        let third = queue.try_submit(b"third").unwrap();
        queue.send_next().unwrap();
        queue.send_next().unwrap();
        queue.send_next().unwrap();

        queue.reject_wire(1).unwrap();
        queue.ack_wire(2).unwrap();

        assert_eq!(queue.server_acked_fsn(), Some(0));
        assert_eq!(queue.completed_fsn(), Some(2));
        assert_eq!(
            queue.receipt_status(first),
            QwpReceiptStatus::Acked { fsn: 0 }
        );
        assert_eq!(
            queue.receipt_status(second),
            QwpReceiptStatus::Poisoned { fsn: 1 }
        );
        assert_eq!(
            queue.receipt_status(third),
            QwpReceiptStatus::Acked { fsn: 2 }
        );
    }

    #[test]
    fn in_flight_ring_rejects_direct_push_when_full() {
        let mut ring = InFlightRing::new(1);
        ring.push(InFlightSlot {
            fsn: 0,
            wire_seq: 0,
        })
        .unwrap();

        assert_eq!(
            ring.push(InFlightSlot {
                fsn: 1,
                wire_seq: 1,
            }),
            Err(QueueError::MaxInFlightReached { max_in_flight: 1 })
        );
    }

    #[test]
    fn receipt_status_distinguishes_old_future_and_completed_unknowns() {
        let mut queue = queue(4, 1024, 3);
        let first = queue.try_submit(b"first").unwrap();
        queue.send_next().unwrap();

        assert_eq!(
            queue.receipt_status(QwpReceipt { fsn: 99 }),
            QwpReceiptStatus::Unknown { fsn: 99 }
        );

        queue.ack_wire(0).unwrap();

        assert_eq!(
            queue.receipt_status(first),
            QwpReceiptStatus::Acked { fsn: 0 }
        );
        assert_eq!(
            queue.receipt_status(QwpReceipt { fsn: 99 }),
            QwpReceiptStatus::Unknown { fsn: 99 }
        );
    }

    #[test]
    fn reconnect_resets_wire_sequence_and_replays_from_oldest_unresolved() {
        let mut queue = queue(4, 1024, 3);
        let first = queue.try_submit(b"first").unwrap();
        let second = queue.try_submit(b"second").unwrap();
        let third = queue.try_submit(b"third").unwrap();

        queue.send_next().unwrap();
        queue.send_next().unwrap();
        queue.ack_wire(0).unwrap();

        assert_eq!(
            queue.receipt_status(first),
            QwpReceiptStatus::Acked { fsn: 0 }
        );
        assert_eq!(
            queue.receipt_status(second),
            QwpReceiptStatus::Sent {
                fsn: 1,
                wire_seq: 1
            }
        );
        assert_eq!(
            queue.receipt_status(third),
            QwpReceiptStatus::Published { fsn: 2 }
        );

        queue.restart_connection();

        assert_eq!(queue.fsn_at_zero(), None);
        assert_eq!(
            queue.receipt_status(second),
            QwpReceiptStatus::Published { fsn: 1 }
        );
        assert_eq!(
            queue.send_next().unwrap(),
            SentFrame {
                fsn: 1,
                wire_seq: 0,
                payload_len: 6
            }
        );
        assert_eq!(queue.fsn_at_zero(), Some(1));
        assert_eq!(
            queue.send_next().unwrap(),
            SentFrame {
                fsn: 2,
                wire_seq: 1,
                payload_len: 5
            }
        );
        queue.ack_wire(1).unwrap();

        assert_eq!(
            queue.receipt_status(second),
            QwpReceiptStatus::Acked { fsn: 1 }
        );
        assert_eq!(
            queue.receipt_status(third),
            QwpReceiptStatus::Acked { fsn: 2 }
        );
    }
}
