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

use std::sync::Arc;

pub(crate) type SharedPayload = Arc<[u8]>;

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
    Rejected { fsn: u64 },
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OutboundFrame {
    pub(crate) fsn: u64,
    pub(crate) wire_seq: u64,
    pub(crate) payload: SharedPayload,
}

impl OutboundFrame {
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
    completed_fsn: Option<u64>,
    rejected_fsns: Vec<u64>,
    max_in_flight: usize,
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
            completed_fsn: None,
            rejected_fsns: Vec::new(),
            max_in_flight: options.max_in_flight,
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
        slot.payload = Some(Arc::from(payload));
        slot.state = FrameState::Published;

        self.len += 1;
        self.bytes_used = new_bytes_used;
        self.published_fsn = Some(fsn);

        Ok(QwpReceipt { fsn })
    }

    pub(crate) fn payload_for_fsn(&self, fsn: u64) -> Option<&[u8]> {
        self.slot_for_fsn(fsn)
            .filter(|slot| !matches!(slot.state, FrameState::Free))
            .and_then(|slot| slot.payload.as_deref())
    }

    pub(crate) fn shared_payload_for_fsn(&self, fsn: u64) -> Option<SharedPayload> {
        self.slot_for_fsn(fsn)
            .filter(|slot| !matches!(slot.state, FrameState::Free))
            .and_then(|slot| slot.payload.clone())
    }

    pub(crate) fn oldest_unresolved_fsn(&self) -> Option<u64> {
        (self.len > 0).then(|| self.slots[self.head].fsn)
    }

    pub(crate) fn complete_through_fsn(&mut self, acked_fsn: u64) -> Result<(), QueueError> {
        if self
            .completed_fsn
            .is_some_and(|completed_fsn| acked_fsn <= completed_fsn)
        {
            return Ok(());
        }
        let Some(published_fsn) = self.published_fsn else {
            return Err(QueueError::ProtocolAckedUnsentFrame { fsn: acked_fsn });
        };
        if acked_fsn > published_fsn {
            return Err(QueueError::ProtocolAckedUnsentFrame { fsn: acked_fsn });
        }

        while self.len > 0 && self.slots[self.head].fsn <= acked_fsn {
            let head = self.head;
            let fsn = self.slots[head].fsn;
            if let Some(payload) = self.slots[head].payload.take() {
                self.bytes_used -= payload.len();
            }
            self.slots[head].state = FrameState::Free;
            self.completed_fsn = Some(fsn);
            self.head = (self.head + 1) % self.slots.len();
            self.len -= 1;
        }

        Ok(())
    }

    pub(crate) fn reject_fsn(&mut self, rejected_fsn: u64) -> Result<QwpReceipt, QueueError> {
        if self
            .published_fsn
            .is_none_or(|published_fsn| rejected_fsn > published_fsn)
        {
            return Err(QueueError::ProtocolRejectedUnsentFrame { fsn: rejected_fsn });
        }
        if self.payload_for_fsn(rejected_fsn).is_none() {
            return Err(QueueError::ProtocolRejectedUnsentFrame { fsn: rejected_fsn });
        }

        self.complete_through_fsn(rejected_fsn)?;
        if !self.rejected_fsns.contains(&rejected_fsn) {
            self.rejected_fsns.push(rejected_fsn);
        }
        Ok(QwpReceipt { fsn: rejected_fsn })
    }

    pub(crate) fn receipt_status(&self, receipt: QwpReceipt) -> QwpReceiptStatus {
        let fsn = receipt.fsn;
        if self.rejected_fsns.contains(&fsn) {
            return QwpReceiptStatus::Rejected { fsn };
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

    pub(crate) fn published_fsn(&self) -> Option<u64> {
        self.published_fsn
    }

    pub(crate) fn completed_fsn(&self) -> Option<u64> {
        self.completed_fsn
    }

    pub(crate) fn max_in_flight(&self) -> usize {
        self.max_in_flight
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
    payload: Option<SharedPayload>,
    state: FrameState,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum FrameState {
    #[default]
    Free,
    Published,
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
        assert!(!QwpReceiptStatus::Rejected { fsn: 0 }.is_pending());
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

        queue.complete_through_fsn(0).unwrap();

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
    fn max_in_flight_is_configuration_for_driver_cursor_not_submission() {
        let mut queue = queue(4, 1024, 2);
        queue.try_submit(b"a").unwrap();
        queue.try_submit(b"b").unwrap();
        let third = queue.try_submit(b"c").unwrap();

        assert_eq!(queue.max_in_flight(), 2);
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

        queue.complete_through_fsn(2).unwrap();

        assert_eq!(queue.completed_fsn(), Some(2));
        assert_eq!(queue.len(), 0);
        assert_eq!(queue.bytes_used(), 0);
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
    fn oldest_unresolved_payload_advances_in_fsn_order() {
        let mut queue = queue(4, 1024, 3);
        let first = queue.try_submit(b"first").unwrap();
        let second = queue.try_submit(b"second").unwrap();
        let third = queue.try_submit(b"third").unwrap();

        assert_eq!(first.fsn, 0);
        assert_eq!(second.fsn, 1);
        assert_eq!(third.fsn, 2);
        assert_eq!(queue.oldest_unresolved_fsn(), Some(0));
        assert_eq!(queue.payload_for_fsn(0), Some(&b"first"[..]));

        queue.complete_through_fsn(0).unwrap();

        assert_eq!(queue.oldest_unresolved_fsn(), Some(1));
        assert_eq!(queue.payload_for_fsn(1), Some(&b"second"[..]));
    }

    #[test]
    fn stale_completion_is_ignored_after_receipt_already_completed() {
        let mut queue = queue(4, 1024, 3);
        let first = queue.try_submit(b"first").unwrap();
        let second = queue.try_submit(b"second").unwrap();

        queue.complete_through_fsn(1).unwrap();
        queue.complete_through_fsn(0).unwrap();

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
    fn reject_marks_frame_rejected_acks_prior_only_and_leaves_later_unresolved() {
        let mut queue = queue(4, 1024, 3);
        let first = queue.try_submit(b"first").unwrap();
        let second = queue.try_submit(b"second").unwrap();
        let third = queue.try_submit(b"third").unwrap();

        assert_eq!(queue.reject_fsn(1).unwrap(), second);

        assert_eq!(queue.completed_fsn(), Some(1));
        assert_eq!(
            queue.receipt_status(first),
            QwpReceiptStatus::Acked { fsn: 0 }
        );
        assert_eq!(
            queue.receipt_status(second),
            QwpReceiptStatus::Rejected { fsn: 1 }
        );
        assert_eq!(
            queue.receipt_status(third),
            QwpReceiptStatus::Published { fsn: 2 }
        );
    }

    #[test]
    fn reject_already_completed_frame_is_protocol_error() {
        let mut queue = queue(4, 1024, 3);
        queue.try_submit(b"first").unwrap();
        queue.try_submit(b"second").unwrap();
        queue.complete_through_fsn(0).unwrap();

        assert_eq!(
            queue.reject_fsn(0),
            Err(QueueError::ProtocolRejectedUnsentFrame { fsn: 0 })
        );
    }

    #[test]
    fn reject_unknown_frame_is_protocol_error() {
        let mut queue = queue(4, 1024, 3);
        queue.try_submit(b"first").unwrap();

        assert_eq!(
            queue.reject_fsn(1),
            Err(QueueError::ProtocolRejectedUnsentFrame { fsn: 1 })
        );
    }

    #[test]
    fn completion_after_reject_completes_later_receipt() {
        let mut queue = queue(4, 1024, 3);
        let first = queue.try_submit(b"first").unwrap();
        let second = queue.try_submit(b"second").unwrap();
        let third = queue.try_submit(b"third").unwrap();

        queue.reject_fsn(1).unwrap();
        queue.complete_through_fsn(2).unwrap();

        assert_eq!(queue.completed_fsn(), Some(2));
        assert_eq!(
            queue.receipt_status(first),
            QwpReceiptStatus::Acked { fsn: 0 }
        );
        assert_eq!(
            queue.receipt_status(second),
            QwpReceiptStatus::Rejected { fsn: 1 }
        );
        assert_eq!(
            queue.receipt_status(third),
            QwpReceiptStatus::Acked { fsn: 2 }
        );
    }

    #[test]
    fn receipt_status_distinguishes_old_future_and_completed_unknowns() {
        let mut queue = queue(4, 1024, 3);
        let first = queue.try_submit(b"first").unwrap();

        assert_eq!(
            queue.receipt_status(QwpReceipt { fsn: 99 }),
            QwpReceiptStatus::Unknown { fsn: 99 }
        );

        queue.complete_through_fsn(0).unwrap();

        assert_eq!(
            queue.receipt_status(first),
            QwpReceiptStatus::Acked { fsn: 0 }
        );
        assert_eq!(
            queue.receipt_status(QwpReceipt { fsn: 99 }),
            QwpReceiptStatus::Unknown { fsn: 99 }
        );
    }
}
