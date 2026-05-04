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

use std::cell::UnsafeCell;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LockFreePublishError {
    Queue(QueueError),
    Terminal,
    Closing,
}

impl From<QueueError> for LockFreePublishError {
    fn from(value: QueueError) -> Self {
        Self::Queue(value)
    }
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

#[derive(Clone)]
pub(crate) struct LockFreeVolatileFrameQueue {
    inner: Arc<LockFreeVolatileFrameQueueInner>,
}

#[derive(Debug)]
pub(crate) struct LockFreeVolatileProducer {
    queue: LockFreeVolatileFrameQueue,
}

#[derive(Debug)]
pub(crate) struct LockFreeVolatilePublicationLog {
    queue: LockFreeVolatileFrameQueue,
    producer: Option<LockFreeVolatileProducer>,
}

struct LockFreeVolatileFrameQueueInner {
    slots: Box<[LockFreeFrameSlot]>,
    max_bytes: usize,
    max_in_flight: usize,
    bytes_used: AtomicUsize,
    next_fsn: AtomicU64,
    published_upper: AtomicU64,
    completed_upper: AtomicU64,
    rejected_fsns: Mutex<Vec<u64>>,
    publisher_state: AtomicU8,
    producer_claimed: AtomicBool,
    publish_active: AtomicBool,
}

struct LockFreeFrameSlot {
    fsn: AtomicU64,
    payload: UnsafeCell<Option<SharedPayload>>,
    state: AtomicU8,
}

const LOCK_FREE_SLOT_FREE: u8 = 0;
const LOCK_FREE_SLOT_PUBLISHED: u8 = 1;
const LOCK_FREE_PUBLISHER_OPEN: u8 = 0;
const LOCK_FREE_PUBLISHER_CLOSING: u8 = 1;
const LOCK_FREE_PUBLISHER_TERMINAL: u8 = 2;

// The log is deliberately SPSC: the sender thread owns the producer handle, and
// the runner thread is the only consumer/completer. Slot payload access is gated
// by release/acquire state transitions plus the completed cursor.
unsafe impl Send for LockFreeVolatileFrameQueueInner {}
unsafe impl Sync for LockFreeVolatileFrameQueueInner {}

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

impl LockFreeVolatileFrameQueue {
    pub(crate) fn new(options: VolatileQueueOptions) -> Result<Self, QueueError> {
        if options.max_frames == 0 || options.max_bytes == 0 || options.max_in_flight == 0 {
            return Err(QueueError::InvalidCapacity);
        }
        if options.max_in_flight > options.max_frames {
            return Err(QueueError::InvalidCapacity);
        }

        let slots = (0..options.max_frames)
            .map(|_| LockFreeFrameSlot {
                fsn: AtomicU64::new(0),
                payload: UnsafeCell::new(None),
                state: AtomicU8::new(LOCK_FREE_SLOT_FREE),
            })
            .collect();

        Ok(Self {
            inner: Arc::new(LockFreeVolatileFrameQueueInner {
                slots,
                max_bytes: options.max_bytes,
                max_in_flight: options.max_in_flight,
                bytes_used: AtomicUsize::new(0),
                next_fsn: AtomicU64::new(0),
                published_upper: AtomicU64::new(0),
                completed_upper: AtomicU64::new(0),
                rejected_fsns: Mutex::new(Vec::new()),
                publisher_state: AtomicU8::new(LOCK_FREE_PUBLISHER_OPEN),
                producer_claimed: AtomicBool::new(false),
                publish_active: AtomicBool::new(false),
            }),
        })
    }

    pub(crate) fn claim_producer(&self) -> Option<LockFreeVolatileProducer> {
        self.inner
            .producer_claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| LockFreeVolatileProducer {
                queue: self.clone(),
            })
    }

    pub(crate) fn close_for_publication(&self) {
        let _ = self.inner.publisher_state.compare_exchange(
            LOCK_FREE_PUBLISHER_OPEN,
            LOCK_FREE_PUBLISHER_CLOSING,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        self.wait_for_active_publish();
    }

    pub(crate) fn terminalize_publication(&self) {
        self.inner
            .publisher_state
            .store(LOCK_FREE_PUBLISHER_TERMINAL, Ordering::Release);
        self.wait_for_active_publish();
    }

    fn try_submit(&self, payload: &[u8]) -> Result<QwpReceipt, LockFreePublishError> {
        let _guard = self.enter_publish()?;
        self.try_submit_open(payload).map_err(Into::into)
    }

    pub(crate) fn shared_payload_for_fsn(&self, fsn: u64) -> Option<SharedPayload> {
        if !self.fsn_is_published_and_unresolved(fsn) {
            return None;
        }
        let slot = self.slot_for_fsn(fsn);
        if slot.state.load(Ordering::Acquire) != LOCK_FREE_SLOT_PUBLISHED {
            return None;
        }
        if slot.fsn.load(Ordering::Acquire) != fsn {
            return None;
        }

        // SPSC invariant: only the runner thread clones/takes payloads after the
        // producer publishes them. Completion cannot run concurrently with this
        // read because both are driven by the same runner core.
        unsafe { (&*slot.payload.get()).as_ref().map(Arc::clone) }
    }

    pub(crate) fn oldest_unresolved_fsn(&self) -> Option<u64> {
        let completed = self.inner.completed_upper.load(Ordering::Acquire);
        let published = self.inner.published_upper.load(Ordering::Acquire);
        (completed < published).then_some(completed)
    }

    pub(crate) fn complete_through_fsn(&self, acked_fsn: u64) -> Result<(), QueueError> {
        let target_upper = acked_fsn
            .checked_add(1)
            .ok_or(QueueError::ProtocolAckedUnsentFrame { fsn: acked_fsn })?;
        let completed = self.inner.completed_upper.load(Ordering::Acquire);
        if target_upper <= completed {
            return Ok(());
        }
        let published = self.inner.published_upper.load(Ordering::Acquire);
        if target_upper > published {
            return Err(QueueError::ProtocolAckedUnsentFrame { fsn: acked_fsn });
        }

        for fsn in completed..target_upper {
            let slot = self.slot_for_fsn(fsn);
            if slot.fsn.load(Ordering::Acquire) != fsn
                || slot.state.load(Ordering::Acquire) != LOCK_FREE_SLOT_PUBLISHED
            {
                return Err(QueueError::ProtocolAckedUnsentFrame { fsn });
            }
        }

        for fsn in completed..target_upper {
            let slot = self.slot_for_fsn(fsn);
            // SPSC invariant: the producer cannot reuse this slot until it sees
            // completed_upper advance, which happens after the slot is freed.
            let payload = unsafe { (&mut *slot.payload.get()).take() };
            if let Some(payload) = payload {
                self.inner
                    .bytes_used
                    .fetch_sub(payload.len(), Ordering::AcqRel);
            }
            slot.state.store(LOCK_FREE_SLOT_FREE, Ordering::Release);
        }

        self.inner
            .completed_upper
            .store(target_upper, Ordering::Release);
        Ok(())
    }

    pub(crate) fn reject_fsn(&self, rejected_fsn: u64) -> Result<QwpReceipt, QueueError> {
        if !self.fsn_is_published_and_unresolved(rejected_fsn) {
            return Err(QueueError::ProtocolRejectedUnsentFrame { fsn: rejected_fsn });
        }
        {
            let mut rejected = self.inner.rejected_fsns.lock().map_err(|_| {
                QueueError::ProtocolRejectedUnsentFrame { fsn: rejected_fsn }
            })?;
            if !rejected.contains(&rejected_fsn) {
                rejected.push(rejected_fsn);
            }
        }
        self.complete_through_fsn(rejected_fsn)?;
        Ok(QwpReceipt { fsn: rejected_fsn })
    }

    pub(crate) fn receipt_status(&self, receipt: QwpReceipt) -> QwpReceiptStatus {
        let fsn = receipt.fsn;
        if let Ok(rejected) = self.inner.rejected_fsns.lock()
            && rejected.contains(&fsn)
        {
            return QwpReceiptStatus::Rejected { fsn };
        }
        if fsn < self.inner.completed_upper.load(Ordering::Acquire) {
            return QwpReceiptStatus::Acked { fsn };
        }
        if fsn >= self.inner.published_upper.load(Ordering::Acquire) {
            return QwpReceiptStatus::Unknown { fsn };
        }

        let slot = self.slot_for_fsn(fsn);
        if slot.fsn.load(Ordering::Acquire) == fsn
            && slot.state.load(Ordering::Acquire) == LOCK_FREE_SLOT_PUBLISHED
        {
            QwpReceiptStatus::Published { fsn }
        } else {
            QwpReceiptStatus::Unknown { fsn }
        }
    }

    pub(crate) fn published_fsn(&self) -> Option<u64> {
        self.inner
            .published_upper
            .load(Ordering::Acquire)
            .checked_sub(1)
    }

    pub(crate) fn completed_fsn(&self) -> Option<u64> {
        self.inner
            .completed_upper
            .load(Ordering::Acquire)
            .checked_sub(1)
    }

    pub(crate) fn max_in_flight(&self) -> usize {
        self.inner.max_in_flight
    }

    #[cfg(test)]
    pub(crate) fn bytes_used(&self) -> usize {
        self.inner.bytes_used.load(Ordering::Acquire)
    }

    fn try_submit_open(&self, payload: &[u8]) -> Result<QwpReceipt, QueueError> {
        if payload.is_empty() {
            return Err(QueueError::EmptyPayload);
        }
        if payload.len() > self.inner.max_bytes {
            return Err(QueueError::PayloadExceedsByteCapacity {
                payload_len: payload.len(),
                max_bytes: self.inner.max_bytes,
            });
        }

        let fsn = self.inner.next_fsn.load(Ordering::Relaxed);
        let next_fsn = fsn.checked_add(1).ok_or(QueueError::SequenceOverflow)?;
        let completed = self.inner.completed_upper.load(Ordering::Acquire);
        if fsn.saturating_sub(completed) >= self.inner.slots.len() as u64 {
            return Err(QueueError::FrameCapacityFull {
                max_frames: self.inner.slots.len(),
            });
        }

        self.reserve_bytes(payload.len())?;
        let slot = self.slot_for_fsn(fsn);
        if slot.state.load(Ordering::Acquire) != LOCK_FREE_SLOT_FREE {
            self.inner.bytes_used.fetch_sub(payload.len(), Ordering::AcqRel);
            return Err(QueueError::FrameCapacityFull {
                max_frames: self.inner.slots.len(),
            });
        }

        let stored_payload: SharedPayload = Arc::from(payload);
        slot.fsn.store(fsn, Ordering::Relaxed);
        unsafe {
            *slot.payload.get() = Some(stored_payload);
        }
        slot.state
            .store(LOCK_FREE_SLOT_PUBLISHED, Ordering::Release);
        self.inner.next_fsn.store(next_fsn, Ordering::Relaxed);
        self.inner
            .published_upper
            .store(next_fsn, Ordering::Release);

        Ok(QwpReceipt { fsn })
    }

    fn reserve_bytes(&self, payload_len: usize) -> Result<(), QueueError> {
        loop {
            let bytes_used = self.inner.bytes_used.load(Ordering::Acquire);
            let Some(new_bytes_used) = bytes_used.checked_add(payload_len) else {
                return Err(QueueError::ByteCapacityFull {
                    payload_len,
                    bytes_used,
                    max_bytes: self.inner.max_bytes,
                });
            };
            if new_bytes_used > self.inner.max_bytes {
                return Err(QueueError::ByteCapacityFull {
                    payload_len,
                    bytes_used,
                    max_bytes: self.inner.max_bytes,
                });
            }
            if self
                .inner
                .bytes_used
                .compare_exchange_weak(
                    bytes_used,
                    new_bytes_used,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                return Ok(());
            }
        }
    }

    fn fsn_is_published_and_unresolved(&self, fsn: u64) -> bool {
        fsn >= self.inner.completed_upper.load(Ordering::Acquire)
            && fsn < self.inner.published_upper.load(Ordering::Acquire)
    }

    fn enter_publish(&self) -> Result<PublishGuard<'_>, LockFreePublishError> {
        match self.inner.publisher_state.load(Ordering::Acquire) {
            LOCK_FREE_PUBLISHER_OPEN => {}
            LOCK_FREE_PUBLISHER_CLOSING => return Err(LockFreePublishError::Closing),
            LOCK_FREE_PUBLISHER_TERMINAL => return Err(LockFreePublishError::Terminal),
            _ => return Err(LockFreePublishError::Terminal),
        }

        self.inner.publish_active.store(true, Ordering::Release);
        match self.inner.publisher_state.load(Ordering::Acquire) {
            LOCK_FREE_PUBLISHER_OPEN => Ok(PublishGuard {
                active: &self.inner.publish_active,
            }),
            LOCK_FREE_PUBLISHER_CLOSING => {
                self.inner.publish_active.store(false, Ordering::Release);
                Err(LockFreePublishError::Closing)
            }
            LOCK_FREE_PUBLISHER_TERMINAL => {
                self.inner.publish_active.store(false, Ordering::Release);
                Err(LockFreePublishError::Terminal)
            }
            _ => {
                self.inner.publish_active.store(false, Ordering::Release);
                Err(LockFreePublishError::Terminal)
            }
        }
    }

    fn slot_for_fsn(&self, fsn: u64) -> &LockFreeFrameSlot {
        let slot_index = (fsn % self.inner.slots.len() as u64) as usize;
        &self.inner.slots[slot_index]
    }

    fn wait_for_active_publish(&self) {
        while self.inner.publish_active.load(Ordering::Acquire) {
            std::hint::spin_loop();
        }
    }
}

struct PublishGuard<'a> {
    active: &'a AtomicBool,
}

impl Drop for PublishGuard<'_> {
    fn drop(&mut self) {
        self.active.store(false, Ordering::Release);
    }
}

impl LockFreeVolatileProducer {
    pub(crate) fn try_submit(
        &mut self,
        payload: &[u8],
    ) -> Result<QwpReceipt, LockFreePublishError> {
        self.queue.try_submit(payload)
    }
}

impl LockFreeVolatilePublicationLog {
    pub(crate) fn new(options: VolatileQueueOptions) -> Result<Self, QueueError> {
        let queue = LockFreeVolatileFrameQueue::new(options)?;
        let producer = queue.claim_producer();
        Ok(Self { queue, producer })
    }

    pub(crate) fn claim_producer(&mut self) -> Option<LockFreeVolatileProducer> {
        self.producer.take()
    }

    pub(crate) fn try_submit(
        &mut self,
        payload: &[u8],
    ) -> Result<QwpReceipt, LockFreePublishError> {
        let Some(producer) = self.producer.as_mut() else {
            return Err(LockFreePublishError::Closing);
        };
        producer.try_submit(payload)
    }

    pub(crate) fn close_for_publication(&self) {
        self.queue.close_for_publication();
    }

    pub(crate) fn terminalize_publication(&self) {
        self.queue.terminalize_publication();
    }

    pub(crate) fn shared_payload_for_fsn(&self, fsn: u64) -> Option<SharedPayload> {
        self.queue.shared_payload_for_fsn(fsn)
    }

    pub(crate) fn oldest_unresolved_fsn(&self) -> Option<u64> {
        self.queue.oldest_unresolved_fsn()
    }

    pub(crate) fn complete_through_fsn(&self, acked_fsn: u64) -> Result<(), QueueError> {
        self.queue.complete_through_fsn(acked_fsn)
    }

    pub(crate) fn reject_fsn(&self, rejected_fsn: u64) -> Result<QwpReceipt, QueueError> {
        self.queue.reject_fsn(rejected_fsn)
    }

    pub(crate) fn receipt_status(&self, receipt: QwpReceipt) -> QwpReceiptStatus {
        self.queue.receipt_status(receipt)
    }

    pub(crate) fn published_fsn(&self) -> Option<u64> {
        self.queue.published_fsn()
    }

    pub(crate) fn completed_fsn(&self) -> Option<u64> {
        self.queue.completed_fsn()
    }

    pub(crate) fn max_in_flight(&self) -> usize {
        self.queue.max_in_flight()
    }
}

impl std::fmt::Debug for LockFreeVolatileFrameQueue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LockFreeVolatileFrameQueue")
            .field("max_frames", &self.inner.slots.len())
            .field("max_bytes", &self.inner.max_bytes)
            .field("max_in_flight", &self.inner.max_in_flight)
            .field("bytes_used", &self.inner.bytes_used.load(Ordering::Relaxed))
            .field("next_fsn", &self.inner.next_fsn.load(Ordering::Relaxed))
            .field(
                "published_upper",
                &self.inner.published_upper.load(Ordering::Relaxed),
            )
            .field(
                "completed_upper",
                &self.inner.completed_upper.load(Ordering::Relaxed),
            )
            .finish()
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

    fn lock_free_queue(
        max_frames: usize,
        max_bytes: usize,
        max_in_flight: usize,
    ) -> LockFreeVolatileFrameQueue {
        LockFreeVolatileFrameQueue::new(VolatileQueueOptions {
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
    fn lock_free_publish_returns_value_receipts_and_published_status() {
        let queue = lock_free_queue(4, 1024, 2);
        let mut producer = queue.claim_producer().unwrap();

        let first = producer.try_submit(b"first").unwrap();
        let second = producer.try_submit(b"second").unwrap();

        assert_eq!(first, QwpReceipt { fsn: 0 });
        assert_eq!(second, QwpReceipt { fsn: 1 });
        assert_eq!(queue.published_fsn(), Some(1));
        assert_eq!(
            queue.shared_payload_for_fsn(0).as_deref(),
            Some(&b"first"[..])
        );
        assert_eq!(
            queue.receipt_status(first),
            QwpReceiptStatus::Published { fsn: 0 }
        );
    }

    #[test]
    fn lock_free_queue_exposes_only_one_producer_handle() {
        let queue = lock_free_queue(4, 1024, 2);

        assert!(queue.claim_producer().is_some());
        assert!(queue.claim_producer().is_none());
    }

    #[test]
    fn lock_free_queue_reuses_slots_after_completion() {
        let queue = lock_free_queue(2, 7, 2);
        let mut producer = queue.claim_producer().unwrap();

        let first = producer.try_submit(b"abc").unwrap();
        let second = producer.try_submit(b"de").unwrap();

        assert_eq!(
            producer.try_submit(b"fg"),
            Err(LockFreePublishError::Queue(QueueError::FrameCapacityFull {
                max_frames: 2
            }))
        );

        queue.complete_through_fsn(first.fsn).unwrap();
        let third = producer.try_submit(b"fg").unwrap();

        assert_eq!(second, QwpReceipt { fsn: 1 });
        assert_eq!(third, QwpReceipt { fsn: 2 });
        assert_eq!(
            queue.shared_payload_for_fsn(third.fsn).as_deref(),
            Some(&b"fg"[..])
        );
        assert_eq!(queue.bytes_used(), 4);
    }

    #[test]
    fn lock_free_queue_releases_byte_capacity_on_ack() {
        let queue = lock_free_queue(4, 5, 2);
        let mut producer = queue.claim_producer().unwrap();

        let first = producer.try_submit(b"abc").unwrap();
        assert_eq!(
            producer.try_submit(b"def"),
            Err(LockFreePublishError::Queue(QueueError::ByteCapacityFull {
                payload_len: 3,
                bytes_used: 3,
                max_bytes: 5
            }))
        );

        queue.complete_through_fsn(first.fsn).unwrap();
        let second = producer.try_submit(b"def").unwrap();

        assert_eq!(second, QwpReceipt { fsn: 1 });
        assert_eq!(queue.bytes_used(), 3);
    }

    #[test]
    fn lock_free_reject_marks_receipt_rejected_and_completes_prior_frames() {
        let queue = lock_free_queue(4, 1024, 4);
        let mut producer = queue.claim_producer().unwrap();

        let first = producer.try_submit(b"first").unwrap();
        let second = producer.try_submit(b"second").unwrap();
        let third = producer.try_submit(b"third").unwrap();

        queue.reject_fsn(second.fsn).unwrap();

        assert_eq!(
            queue.receipt_status(first),
            QwpReceiptStatus::Acked { fsn: first.fsn }
        );
        assert_eq!(
            queue.receipt_status(second),
            QwpReceiptStatus::Rejected { fsn: second.fsn }
        );
        assert_eq!(
            queue.receipt_status(third),
            QwpReceiptStatus::Published { fsn: third.fsn }
        );
    }

    #[test]
    fn lock_free_queue_closing_and_terminal_reject_publication() {
        let queue = lock_free_queue(4, 1024, 2);
        let mut producer = queue.claim_producer().unwrap();

        queue.close_for_publication();
        assert_eq!(producer.try_submit(b"payload"), Err(LockFreePublishError::Closing));

        queue.terminalize_publication();
        assert_eq!(producer.try_submit(b"payload"), Err(LockFreePublishError::Terminal));
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
