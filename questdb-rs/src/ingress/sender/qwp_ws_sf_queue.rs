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

//! Minimal file-backed Store-and-Forward QWP/WebSocket queue prototype.
//!
//! This module validates the Step 8 durability model without real WebSocket I/O
//! or public FFI shape. The journal stores only local publication and receipt
//! completion records. Connection-local state such as `Sent` and WebSocket wire
//! sequence is deliberately not durable.

use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use super::qwp_ws_queue::{OutboundFrame, QueueError, QwpReceipt, QwpReceiptStatus, SentFrame};

const LOG_FILE_NAME: &str = "qwp-ws-sf.log";
const LOG_MAGIC: &[u8; 8] = b"QWPSF001";
const RECORD_HEADER_LEN: usize = 4;
const TAG_FRAME: u8 = b'F';
const TAG_ACK_THROUGH: u8 = b'A';
const TAG_POISON: u8 = b'P';
const CONTROL_BODY_LEN: usize = 1 + 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SfQueueOptions {
    pub(crate) dir: PathBuf,
    pub(crate) max_frames: usize,
    pub(crate) max_bytes: usize,
    pub(crate) max_in_flight: usize,
}

#[derive(Debug)]
pub(crate) enum SfQueueError {
    Queue(QueueError),
    Io(io::Error),
    CorruptLog { offset: usize, reason: &'static str },
}

impl From<QueueError> for SfQueueError {
    fn from(value: QueueError) -> Self {
        Self::Queue(value)
    }
}

impl From<io::Error> for SfQueueError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Debug)]
pub(crate) struct SfFrameQueue {
    log: File,
    frames: VecDeque<SfFrame>,
    bytes_used: usize,
    max_frames: usize,
    max_bytes: usize,
    next_fsn: u64,
    published_fsn: Option<u64>,
    server_acked_fsn: Option<u64>,
    completed_fsn: Option<u64>,
    poisoned_fsns: Vec<u64>,
    connection: ConnectionState,
    in_flight: InFlightRing,
}

impl SfFrameQueue {
    pub(crate) fn open(options: SfQueueOptions) -> Result<Self, SfQueueError> {
        if options.max_frames == 0 || options.max_bytes == 0 || options.max_in_flight == 0 {
            return Err(QueueError::InvalidCapacity.into());
        }
        if options.max_in_flight > options.max_frames {
            return Err(QueueError::InvalidCapacity.into());
        }

        fs::create_dir_all(&options.dir)?;
        let log_path = options.dir.join(LOG_FILE_NAME);
        initialize_log(&log_path)?;

        let recovered = recover_log(&log_path, options.max_frames, options.max_bytes)?;
        if recovered.valid_len < fs::metadata(&log_path)?.len() {
            let log = OpenOptions::new().write(true).open(&log_path)?;
            log.set_len(recovered.valid_len)?;
        }
        let log = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(log_path)?;

        Ok(Self {
            log,
            frames: recovered.frames,
            bytes_used: recovered.bytes_used,
            max_frames: options.max_frames,
            max_bytes: options.max_bytes,
            next_fsn: recovered.next_fsn,
            published_fsn: recovered.published_fsn,
            server_acked_fsn: recovered.server_acked_fsn,
            completed_fsn: recovered.completed_fsn,
            poisoned_fsns: recovered.poisoned_fsns,
            connection: ConnectionState::default(),
            in_flight: InFlightRing::new(options.max_in_flight),
        })
    }

    pub(crate) fn try_submit(&mut self, payload: &[u8]) -> Result<QwpReceipt, SfQueueError> {
        if payload.is_empty() {
            return Err(QueueError::EmptyPayload.into());
        }
        if self.frames.len() == self.max_frames {
            return Err(QueueError::FrameCapacityFull {
                max_frames: self.max_frames,
            }
            .into());
        }
        if payload.len() > self.max_bytes {
            return Err(QueueError::PayloadExceedsByteCapacity {
                payload_len: payload.len(),
                max_bytes: self.max_bytes,
            }
            .into());
        }
        let Some(new_bytes_used) = self.bytes_used.checked_add(payload.len()) else {
            return Err(QueueError::ByteCapacityFull {
                payload_len: payload.len(),
                bytes_used: self.bytes_used,
                max_bytes: self.max_bytes,
            }
            .into());
        };
        if new_bytes_used > self.max_bytes {
            return Err(QueueError::ByteCapacityFull {
                payload_len: payload.len(),
                bytes_used: self.bytes_used,
                max_bytes: self.max_bytes,
            }
            .into());
        }

        let fsn = self.next_fsn;
        let next_fsn = self
            .next_fsn
            .checked_add(1)
            .ok_or(QueueError::SequenceOverflow)?;

        self.append_frame(fsn, payload)?;

        self.next_fsn = next_fsn;
        self.published_fsn = Some(fsn);
        self.bytes_used = new_bytes_used;
        self.frames.push_back(SfFrame {
            fsn,
            payload: payload.to_vec(),
            state: FrameState::Published,
        });

        Ok(QwpReceipt { fsn })
    }

    pub(crate) fn send_next(&mut self) -> Result<SentFrame, SfQueueError> {
        let frame = {
            let outbound = self.next_outbound_frame()?;
            outbound.sent_frame()
        };
        self.commit_sent(frame)?;
        Ok(frame)
    }

    pub(crate) fn next_outbound_frame(&self) -> Result<OutboundFrame<'_>, SfQueueError> {
        if self.in_flight.is_full() {
            return Err(QueueError::MaxInFlightReached {
                max_in_flight: self.in_flight.capacity(),
            }
            .into());
        }

        let Some(offset) = self.first_published_offset() else {
            return Err(QueueError::NoUnsentFrame.into());
        };

        let wire_seq = self.connection.next_wire_seq;
        wire_seq
            .checked_add(1)
            .ok_or(QueueError::SequenceOverflow)?;

        let frame = &self.frames[offset];
        Ok(OutboundFrame {
            fsn: frame.fsn,
            wire_seq,
            payload: &frame.payload,
        })
    }

    pub(crate) fn commit_sent(&mut self, frame: SentFrame) -> Result<(), SfQueueError> {
        if self.in_flight.is_full() {
            return Err(QueueError::MaxInFlightReached {
                max_in_flight: self.in_flight.capacity(),
            }
            .into());
        }

        let Some(offset) = self.first_published_offset() else {
            return Err(QueueError::NoUnsentFrame.into());
        };
        let stored = &self.frames[offset];
        if stored.fsn != frame.fsn
            || !matches!(stored.state, FrameState::Published)
            || stored.payload.len() != frame.payload_len
            || self.connection.next_wire_seq != frame.wire_seq
        {
            return Err(QueueError::OutboundFrameUnavailable {
                fsn: frame.fsn,
                wire_seq: frame.wire_seq,
            }
            .into());
        }
        let next_wire_seq = self
            .connection
            .next_wire_seq
            .checked_add(1)
            .ok_or(QueueError::SequenceOverflow)?;

        self.ensure_connection_started()?;
        self.connection.next_wire_seq = next_wire_seq;
        self.connection.last_sent_wire_seq = Some(frame.wire_seq);

        let stored = &mut self.frames[offset];
        stored.state = FrameState::Sent {
            wire_seq: frame.wire_seq,
        };
        self.in_flight.push(InFlightSlot {
            fsn: stored.fsn,
            wire_seq: frame.wire_seq,
        })?;
        Ok(())
    }

    pub(crate) fn ack_wire(&mut self, wire_seq: u64) -> Result<(), SfQueueError> {
        let acked_fsn = self.fsn_for_wire(wire_seq, AckKind::Ack)?;

        if self
            .server_acked_fsn
            .is_some_and(|server_acked_fsn| acked_fsn <= server_acked_fsn)
        {
            return Ok(());
        }
        if self
            .completed_fsn
            .is_some_and(|completed_fsn| acked_fsn <= completed_fsn)
        {
            self.advance_server_acked_to(acked_fsn);
            return Ok(());
        }

        self.ensure_ackable_through(acked_fsn)?;
        self.append_ack_through(acked_fsn)?;
        self.apply_ack_through(acked_fsn);
        self.advance_server_acked_to(acked_fsn);
        Ok(())
    }

    pub(crate) fn reject_wire(&mut self, wire_seq: u64) -> Result<QwpReceipt, SfQueueError> {
        let rejected_fsn = self.fsn_for_wire(wire_seq, AckKind::Reject)?;
        self.ensure_rejectable(rejected_fsn)?;

        self.append_poison(rejected_fsn)?;
        if rejected_fsn > 0 {
            self.advance_server_acked_to(rejected_fsn - 1);
        }
        self.apply_poison(rejected_fsn);

        Ok(QwpReceipt { fsn: rejected_fsn })
    }

    pub(crate) fn restart_connection(&mut self) {
        self.in_flight.clear();
        self.connection = ConnectionState::default();
        for frame in &mut self.frames {
            if matches!(frame.state, FrameState::Sent { .. }) {
                frame.state = FrameState::Published;
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

        if let Some(frame) = self.frame_for_fsn(fsn) {
            return match frame.state {
                FrameState::Published => QwpReceiptStatus::Published { fsn },
                FrameState::Sent { wire_seq } => QwpReceiptStatus::Sent { fsn, wire_seq },
            };
        }

        QwpReceiptStatus::Unknown { fsn }
    }

    pub(crate) fn payload_for_fsn(&self, fsn: u64) -> Option<&[u8]> {
        self.frame_for_fsn(fsn)
            .map(|frame| frame.payload.as_slice())
    }

    pub(crate) fn len(&self) -> usize {
        self.frames.len()
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

    fn append_frame(&mut self, fsn: u64, payload: &[u8]) -> Result<(), SfQueueError> {
        append_record(&mut self.log, TAG_FRAME, fsn, payload)
    }

    fn append_ack_through(&mut self, fsn: u64) -> Result<(), SfQueueError> {
        append_record(&mut self.log, TAG_ACK_THROUGH, fsn, &[])
    }

    fn append_poison(&mut self, fsn: u64) -> Result<(), SfQueueError> {
        append_record(&mut self.log, TAG_POISON, fsn, &[])
    }

    fn ensure_connection_started(&mut self) -> Result<(), QueueError> {
        if self.connection.fsn_at_zero.is_none() {
            self.connection.fsn_at_zero = Some(self.oldest_unresolved_fsn()?);
        }
        Ok(())
    }

    fn oldest_unresolved_fsn(&self) -> Result<u64, QueueError> {
        self.frames
            .front()
            .map(|frame| frame.fsn)
            .ok_or(QueueError::NoUnsentFrame)
    }

    fn first_published_offset(&self) -> Option<usize> {
        self.frames
            .iter()
            .position(|frame| matches!(frame.state, FrameState::Published))
    }

    fn fsn_for_wire(&self, wire_seq: u64, kind: AckKind) -> Result<u64, QueueError> {
        let Some(fsn_at_zero) = self.connection.fsn_at_zero else {
            return Err(match kind {
                AckKind::Ack => QueueError::ProtocolAckWithoutConnection,
                AckKind::Reject => QueueError::ProtocolRejectWithoutConnection,
            });
        };
        let last_sent_wire_seq = self.connection.last_sent_wire_seq;
        if last_sent_wire_seq.is_none_or(|last_sent| wire_seq > last_sent) {
            return Err(match kind {
                AckKind::Ack => QueueError::ProtocolAckBeyondSent {
                    wire_seq,
                    last_sent_wire_seq,
                },
                AckKind::Reject => QueueError::ProtocolRejectBeyondSent {
                    wire_seq,
                    last_sent_wire_seq,
                },
            });
        }

        fsn_at_zero
            .checked_add(wire_seq)
            .ok_or(QueueError::SequenceOverflow)
    }

    fn ensure_ackable_through(&self, acked_fsn: u64) -> Result<(), QueueError> {
        for frame in &self.frames {
            if frame.fsn > acked_fsn {
                break;
            }
            if !matches!(frame.state, FrameState::Sent { .. }) {
                return Err(QueueError::ProtocolAckedUnsentFrame { fsn: frame.fsn });
            }
        }
        Ok(())
    }

    fn ensure_rejectable(&self, rejected_fsn: u64) -> Result<(), QueueError> {
        let mut saw_rejected = false;
        for frame in &self.frames {
            if frame.fsn > rejected_fsn {
                break;
            }
            if !matches!(frame.state, FrameState::Sent { .. }) {
                return if frame.fsn == rejected_fsn {
                    Err(QueueError::ProtocolRejectedUnsentFrame { fsn: frame.fsn })
                } else {
                    Err(QueueError::ProtocolAckedUnsentFrame { fsn: frame.fsn })
                };
            }
            if frame.fsn == rejected_fsn {
                saw_rejected = true;
            }
        }

        if saw_rejected {
            Ok(())
        } else {
            Err(QueueError::ProtocolRejectedUnsentFrame { fsn: rejected_fsn })
        }
    }

    fn apply_ack_through(&mut self, acked_fsn: u64) {
        while self
            .frames
            .front()
            .is_some_and(|frame| frame.fsn <= acked_fsn)
        {
            let frame = self.frames.pop_front().unwrap();
            self.bytes_used -= frame.payload.len();
            self.completed_fsn = Some(frame.fsn);
        }

        self.in_flight.pop_acked_through(acked_fsn);
    }

    fn apply_poison(&mut self, rejected_fsn: u64) {
        while self
            .frames
            .front()
            .is_some_and(|frame| frame.fsn <= rejected_fsn)
        {
            let frame = self.frames.pop_front().unwrap();
            self.bytes_used -= frame.payload.len();
            self.completed_fsn = Some(frame.fsn);
        }

        self.poisoned_fsns.push(rejected_fsn);
        self.in_flight.pop_acked_through(rejected_fsn);
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

    fn frame_for_fsn(&self, fsn: u64) -> Option<&SfFrame> {
        self.frames.iter().find(|frame| frame.fsn == fsn)
    }
}

#[derive(Debug)]
struct RecoveredQueue {
    frames: VecDeque<SfFrame>,
    bytes_used: usize,
    next_fsn: u64,
    valid_len: u64,
    published_fsn: Option<u64>,
    server_acked_fsn: Option<u64>,
    completed_fsn: Option<u64>,
    poisoned_fsns: Vec<u64>,
}

impl RecoveredQueue {
    fn empty() -> Self {
        Self {
            frames: VecDeque::new(),
            bytes_used: 0,
            next_fsn: 0,
            valid_len: LOG_MAGIC.len() as u64,
            published_fsn: None,
            server_acked_fsn: None,
            completed_fsn: None,
            poisoned_fsns: Vec::new(),
        }
    }

    fn apply_frame(
        &mut self,
        fsn: u64,
        payload: &[u8],
        max_frames: usize,
        max_bytes: usize,
        offset: usize,
    ) -> Result<(), SfQueueError> {
        if fsn != self.next_fsn {
            return Err(SfQueueError::CorruptLog {
                offset,
                reason: "non-contiguous frame sequence",
            });
        }
        if payload.is_empty() {
            return Err(SfQueueError::CorruptLog {
                offset,
                reason: "empty frame payload",
            });
        }
        if payload.len() > max_bytes {
            return Err(SfQueueError::CorruptLog {
                offset,
                reason: "frame payload exceeds byte capacity",
            });
        }
        if self.frames.len() == max_frames {
            return Err(SfQueueError::CorruptLog {
                offset,
                reason: "frame capacity exceeded",
            });
        }
        let Some(new_bytes_used) = self.bytes_used.checked_add(payload.len()) else {
            return Err(SfQueueError::CorruptLog {
                offset,
                reason: "byte capacity overflow",
            });
        };
        if new_bytes_used > max_bytes {
            return Err(SfQueueError::CorruptLog {
                offset,
                reason: "byte capacity exceeded",
            });
        }

        self.next_fsn += 1;
        self.published_fsn = Some(fsn);
        self.bytes_used = new_bytes_used;
        self.frames.push_back(SfFrame {
            fsn,
            payload: payload.to_vec(),
            state: FrameState::Published,
        });
        Ok(())
    }

    fn apply_ack_through(&mut self, fsn: u64, offset: usize) -> Result<(), SfQueueError> {
        if self
            .published_fsn
            .is_none_or(|published_fsn| fsn > published_fsn)
        {
            return Err(SfQueueError::CorruptLog {
                offset,
                reason: "ack references unpublished frame",
            });
        }

        while self.frames.front().is_some_and(|frame| frame.fsn <= fsn) {
            let frame = self.frames.pop_front().unwrap();
            self.bytes_used -= frame.payload.len();
            self.completed_fsn = Some(frame.fsn);
        }
        if self
            .completed_fsn
            .is_none_or(|completed_fsn| fsn > completed_fsn)
        {
            self.completed_fsn = Some(fsn);
        }
        self.advance_server_acked_to(fsn);
        Ok(())
    }

    fn apply_poison(&mut self, fsn: u64, offset: usize) -> Result<(), SfQueueError> {
        if self
            .published_fsn
            .is_none_or(|published_fsn| fsn > published_fsn)
        {
            return Err(SfQueueError::CorruptLog {
                offset,
                reason: "poison references unpublished frame",
            });
        }
        if self.poisoned_fsns.contains(&fsn) {
            return Err(SfQueueError::CorruptLog {
                offset,
                reason: "duplicate poison marker",
            });
        }
        if self
            .completed_fsn
            .is_some_and(|completed_fsn| fsn <= completed_fsn)
        {
            return Err(SfQueueError::CorruptLog {
                offset,
                reason: "poison references completed frame",
            });
        }

        while self.frames.front().is_some_and(|frame| frame.fsn <= fsn) {
            let frame = self.frames.pop_front().unwrap();
            self.bytes_used -= frame.payload.len();
            self.completed_fsn = Some(frame.fsn);
        }
        if self
            .completed_fsn
            .is_none_or(|completed_fsn| fsn > completed_fsn)
        {
            self.completed_fsn = Some(fsn);
        }
        self.poisoned_fsns.push(fsn);
        if fsn > 0 {
            self.advance_server_acked_to(fsn - 1);
        }
        Ok(())
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
}

fn initialize_log(path: &Path) -> Result<(), SfQueueError> {
    if path.exists() && path.metadata()?.len() != 0 {
        return Ok(());
    }

    let mut log = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;
    log.write_all(LOG_MAGIC)?;
    log.flush()?;
    Ok(())
}

fn recover_log(
    path: &Path,
    max_frames: usize,
    max_bytes: usize,
) -> Result<RecoveredQueue, SfQueueError> {
    let mut bytes = Vec::new();
    File::open(path)?.read_to_end(&mut bytes)?;
    if bytes.len() < LOG_MAGIC.len() {
        return Err(SfQueueError::CorruptLog {
            offset: 0,
            reason: "missing log header",
        });
    }
    if &bytes[..LOG_MAGIC.len()] != LOG_MAGIC {
        return Err(SfQueueError::CorruptLog {
            offset: 0,
            reason: "invalid log header",
        });
    }

    let mut recovered = RecoveredQueue::empty();
    let mut offset = LOG_MAGIC.len();
    while offset < bytes.len() {
        if bytes.len() - offset < RECORD_HEADER_LEN {
            break;
        }

        let len = u32::from_le_bytes(
            bytes[offset..offset + RECORD_HEADER_LEN]
                .try_into()
                .unwrap(),
        ) as usize;
        let body_offset = offset + RECORD_HEADER_LEN;
        let next_offset = body_offset.saturating_add(len);
        if next_offset > bytes.len() {
            break;
        }
        if len < CONTROL_BODY_LEN {
            return Err(SfQueueError::CorruptLog {
                offset,
                reason: "record too short",
            });
        }

        let body = &bytes[body_offset..next_offset];
        let tag = body[0];
        let fsn = u64::from_le_bytes(body[1..9].try_into().unwrap());
        match tag {
            TAG_FRAME => recovered.apply_frame(
                fsn,
                &body[CONTROL_BODY_LEN..],
                max_frames,
                max_bytes,
                offset,
            )?,
            TAG_ACK_THROUGH if len == CONTROL_BODY_LEN => {
                recovered.apply_ack_through(fsn, offset)?
            }
            TAG_POISON if len == CONTROL_BODY_LEN => recovered.apply_poison(fsn, offset)?,
            TAG_ACK_THROUGH | TAG_POISON => {
                return Err(SfQueueError::CorruptLog {
                    offset,
                    reason: "control record has payload",
                });
            }
            _ => {
                return Err(SfQueueError::CorruptLog {
                    offset,
                    reason: "unknown record tag",
                });
            }
        }

        offset = next_offset;
        recovered.valid_len = offset as u64;
    }

    Ok(recovered)
}

fn append_record(log: &mut File, tag: u8, fsn: u64, payload: &[u8]) -> Result<(), SfQueueError> {
    let body_len = CONTROL_BODY_LEN
        .checked_add(payload.len())
        .ok_or(SfQueueError::CorruptLog {
            offset: 0,
            reason: "record length overflow",
        })?;
    let body_len = u32::try_from(body_len).map_err(|_| SfQueueError::CorruptLog {
        offset: 0,
        reason: "record length exceeds u32",
    })?;

    let mut record = Vec::with_capacity(RECORD_HEADER_LEN + body_len as usize);
    record.extend_from_slice(&body_len.to_le_bytes());
    record.push(tag);
    record.extend_from_slice(&fsn.to_le_bytes());
    record.extend_from_slice(payload);

    log.write_all(&record)?;
    log.flush()?;
    Ok(())
}

#[derive(Debug)]
struct SfFrame {
    fsn: u64,
    payload: Vec<u8>,
    state: FrameState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FrameState {
    Published,
    Sent { wire_seq: u64 },
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

#[derive(Debug, Clone, Copy)]
enum AckKind {
    Ack,
    Reject,
}

#[cfg(test)]
mod tests {
    use std::io::Seek;

    use tempfile::TempDir;

    use super::*;

    fn options(dir: &TempDir) -> SfQueueOptions {
        options_with(dir, 8, 1024, 4)
    }

    fn options_with(
        dir: &TempDir,
        max_frames: usize,
        max_bytes: usize,
        max_in_flight: usize,
    ) -> SfQueueOptions {
        SfQueueOptions {
            dir: dir.path().to_path_buf(),
            max_frames,
            max_bytes,
            max_in_flight,
        }
    }

    fn open(dir: &TempDir) -> SfFrameQueue {
        SfFrameQueue::open(options(dir)).unwrap()
    }

    fn open_with(
        dir: &TempDir,
        max_frames: usize,
        max_bytes: usize,
        max_in_flight: usize,
    ) -> SfFrameQueue {
        SfFrameQueue::open(options_with(dir, max_frames, max_bytes, max_in_flight)).unwrap()
    }

    fn write_log(dir: &TempDir, bytes: &[u8]) {
        fs::write(dir.path().join(LOG_FILE_NAME), bytes).unwrap();
    }

    fn append_raw_record(dir: &TempDir, tag: u8, fsn: u64, payload: &[u8]) {
        let log_path = dir.path().join(LOG_FILE_NAME);
        let mut log = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
            .unwrap();
        append_record(&mut log, tag, fsn, payload).unwrap();
    }

    fn assert_corrupt_log(result: Result<SfFrameQueue, SfQueueError>, reason: &'static str) {
        assert!(matches!(
            result,
            Err(SfQueueError::CorruptLog {
                reason: actual,
                ..
            }) if actual == reason
        ));
    }

    #[test]
    fn invalid_capacity_options_are_rejected() {
        let dir = TempDir::new().unwrap();

        assert!(matches!(
            SfFrameQueue::open(options_with(&dir, 0, 1024, 1)),
            Err(SfQueueError::Queue(QueueError::InvalidCapacity))
        ));
        assert!(matches!(
            SfFrameQueue::open(options_with(&dir, 1, 0, 1)),
            Err(SfQueueError::Queue(QueueError::InvalidCapacity))
        ));
        assert!(matches!(
            SfFrameQueue::open(options_with(&dir, 1, 1024, 0)),
            Err(SfQueueError::Queue(QueueError::InvalidCapacity))
        ));
        assert!(matches!(
            SfFrameQueue::open(options_with(&dir, 1, 1024, 2)),
            Err(SfQueueError::Queue(QueueError::InvalidCapacity))
        ));
    }

    #[test]
    fn failed_submit_attempts_do_not_publish_or_consume_fsn() {
        let dir = TempDir::new().unwrap();
        let mut queue = open_with(&dir, 2, 5, 2);

        assert!(matches!(
            queue.try_submit(b""),
            Err(SfQueueError::Queue(QueueError::EmptyPayload))
        ));
        assert!(matches!(
            queue.try_submit(b"abcdef"),
            Err(SfQueueError::Queue(
                QueueError::PayloadExceedsByteCapacity {
                    payload_len: 6,
                    max_bytes: 5,
                }
            ))
        ));
        assert_eq!(queue.try_submit(b"ab").unwrap(), QwpReceipt { fsn: 0 });
        assert!(matches!(
            queue.try_submit(b"cdef"),
            Err(SfQueueError::Queue(QueueError::ByteCapacityFull {
                payload_len: 4,
                bytes_used: 2,
                max_bytes: 5,
            }))
        ));

        queue.send_next().unwrap();
        queue.ack_wire(0).unwrap();

        assert_eq!(queue.try_submit(b"cde").unwrap(), QwpReceipt { fsn: 1 });
        assert_eq!(queue.published_fsn(), Some(1));
    }

    #[test]
    fn frame_capacity_frees_after_ack_without_reusing_fsn() {
        let dir = TempDir::new().unwrap();
        let mut queue = open_with(&dir, 1, 1024, 1);

        assert_eq!(queue.try_submit(b"first").unwrap(), QwpReceipt { fsn: 0 });
        assert!(matches!(
            queue.try_submit(b"second"),
            Err(SfQueueError::Queue(QueueError::FrameCapacityFull {
                max_frames: 1
            }))
        ));

        queue.send_next().unwrap();
        queue.ack_wire(0).unwrap();

        assert_eq!(queue.try_submit(b"second").unwrap(), QwpReceipt { fsn: 1 });
        assert_eq!(queue.payload_for_fsn(1), Some(&b"second"[..]));
    }

    #[test]
    fn send_backpressure_is_not_submission_backpressure() {
        let dir = TempDir::new().unwrap();
        let mut queue = open_with(&dir, 4, 1024, 1);

        assert!(matches!(
            queue.send_next(),
            Err(SfQueueError::Queue(QueueError::NoUnsentFrame))
        ));

        let first = queue.try_submit(b"first").unwrap();
        let second = queue.try_submit(b"second").unwrap();

        assert_eq!(
            queue.send_next().unwrap(),
            SentFrame {
                fsn: 0,
                wire_seq: 0,
                payload_len: 5,
            }
        );
        assert!(matches!(
            queue.send_next(),
            Err(SfQueueError::Queue(QueueError::MaxInFlightReached {
                max_in_flight: 1,
            }))
        ));
        assert_eq!(
            queue.receipt_status(first),
            QwpReceiptStatus::Sent {
                fsn: 0,
                wire_seq: 0,
            }
        );
        assert_eq!(
            queue.receipt_status(second),
            QwpReceiptStatus::Published { fsn: 1 }
        );
    }

    #[test]
    fn restart_replays_sent_frames_with_zero_based_wire_sequence() {
        let dir = TempDir::new().unwrap();
        let mut queue = open_with(&dir, 4, 1024, 2);
        let first = queue.try_submit(b"first").unwrap();
        let second = queue.try_submit(b"second").unwrap();

        queue.send_next().unwrap();
        queue.send_next().unwrap();
        queue.restart_connection();

        assert_eq!(queue.fsn_at_zero(), None);
        assert_eq!(queue.in_flight_len(), 0);
        assert_eq!(
            queue.receipt_status(first),
            QwpReceiptStatus::Published { fsn: 0 }
        );
        assert_eq!(
            queue.receipt_status(second),
            QwpReceiptStatus::Published { fsn: 1 }
        );
        assert_eq!(
            queue.send_next().unwrap(),
            SentFrame {
                fsn: 0,
                wire_seq: 0,
                payload_len: 5,
            }
        );
    }

    #[test]
    fn protocol_responses_before_or_beyond_sent_window_are_rejected() {
        let dir = TempDir::new().unwrap();
        let mut queue = open(&dir);
        let receipt = queue.try_submit(b"first").unwrap();

        assert!(matches!(
            queue.ack_wire(0),
            Err(SfQueueError::Queue(
                QueueError::ProtocolAckWithoutConnection
            ))
        ));
        assert!(matches!(
            queue.reject_wire(0),
            Err(SfQueueError::Queue(
                QueueError::ProtocolRejectWithoutConnection
            ))
        ));

        queue.send_next().unwrap();

        assert!(matches!(
            queue.ack_wire(1),
            Err(SfQueueError::Queue(QueueError::ProtocolAckBeyondSent {
                wire_seq: 1,
                last_sent_wire_seq: Some(0),
            }))
        ));
        assert!(matches!(
            queue.reject_wire(1),
            Err(SfQueueError::Queue(QueueError::ProtocolRejectBeyondSent {
                wire_seq: 1,
                last_sent_wire_seq: Some(0),
            }))
        ));
        assert_eq!(
            queue.receipt_status(receipt),
            QwpReceiptStatus::Sent {
                fsn: 0,
                wire_seq: 0,
            }
        );
    }

    #[test]
    fn stale_reject_for_completed_frame_is_rejected() {
        let dir = TempDir::new().unwrap();
        let mut queue = open(&dir);
        let receipt = queue.try_submit(b"first").unwrap();

        queue.send_next().unwrap();
        queue.ack_wire(0).unwrap();

        assert!(matches!(
            queue.reject_wire(0),
            Err(SfQueueError::Queue(
                QueueError::ProtocolRejectedUnsentFrame { fsn: 0 }
            ))
        ));
        assert_eq!(
            queue.receipt_status(receipt),
            QwpReceiptStatus::Acked { fsn: 0 }
        );
    }

    #[test]
    fn first_frame_poison_gap_survives_restart() {
        let dir = TempDir::new().unwrap();
        {
            let mut queue = open(&dir);
            queue.try_submit(b"first").unwrap();
            queue.try_submit(b"second").unwrap();
            queue.send_next().unwrap();
            queue.send_next().unwrap();

            queue.reject_wire(0).unwrap();
            queue.ack_wire(1).unwrap();
            assert_eq!(queue.server_acked_fsn(), None);
            assert_eq!(queue.completed_fsn(), Some(1));
        }

        let recovered = open(&dir);

        assert_eq!(recovered.server_acked_fsn(), None);
        assert_eq!(recovered.completed_fsn(), Some(1));
        assert_eq!(
            recovered.receipt_status(QwpReceipt { fsn: 0 }),
            QwpReceiptStatus::Poisoned { fsn: 0 }
        );
        assert_eq!(
            recovered.receipt_status(QwpReceipt { fsn: 1 }),
            QwpReceiptStatus::Acked { fsn: 1 }
        );
    }

    #[test]
    fn submit_appends_frames_and_recover_published_state() {
        let dir = TempDir::new().unwrap();
        {
            let mut queue = open(&dir);
            assert_eq!(queue.try_submit(b"first").unwrap(), QwpReceipt { fsn: 0 });
            assert_eq!(queue.try_submit(b"second").unwrap(), QwpReceipt { fsn: 1 });
            assert_eq!(queue.published_fsn(), Some(1));
        }

        let mut recovered = open(&dir);

        assert_eq!(recovered.len(), 2);
        assert_eq!(recovered.bytes_used(), 11);
        assert_eq!(
            recovered.receipt_status(QwpReceipt { fsn: 0 }),
            QwpReceiptStatus::Published { fsn: 0 }
        );
        assert_eq!(recovered.payload_for_fsn(0), Some(&b"first"[..]));
        assert_eq!(
            recovered.send_next().unwrap(),
            SentFrame {
                fsn: 0,
                wire_seq: 0,
                payload_len: 5,
            }
        );
        assert_eq!(
            recovered.send_next().unwrap(),
            SentFrame {
                fsn: 1,
                wire_seq: 1,
                payload_len: 6,
            }
        );
    }

    #[test]
    fn caller_payload_can_change_after_local_publication() {
        let dir = TempDir::new().unwrap();
        let mut payload = b"stable".to_vec();
        {
            let mut queue = open(&dir);
            queue.try_submit(&payload).unwrap();
            payload.fill(b'X');
        }

        let recovered = open(&dir);

        assert_eq!(payload, b"XXXXXX");
        assert_eq!(recovered.payload_for_fsn(0), Some(&b"stable"[..]));
    }

    #[test]
    fn sent_state_is_not_durable_after_restart() {
        let dir = TempDir::new().unwrap();
        let first;
        let second;
        {
            let mut queue = open(&dir);
            first = queue.try_submit(b"first").unwrap();
            second = queue.try_submit(b"second").unwrap();
            queue.send_next().unwrap();
            queue.send_next().unwrap();

            assert_eq!(
                queue.receipt_status(first),
                QwpReceiptStatus::Sent {
                    fsn: 0,
                    wire_seq: 0
                }
            );
        }

        let mut recovered = open(&dir);

        assert_eq!(recovered.fsn_at_zero(), None);
        assert_eq!(recovered.in_flight_len(), 0);
        assert_eq!(
            recovered.receipt_status(first),
            QwpReceiptStatus::Published { fsn: 0 }
        );
        assert_eq!(
            recovered.receipt_status(second),
            QwpReceiptStatus::Published { fsn: 1 }
        );
        assert_eq!(
            recovered.send_next().unwrap(),
            SentFrame {
                fsn: 0,
                wire_seq: 0,
                payload_len: 5,
            }
        );
    }

    #[test]
    fn ack_marker_survives_restart_and_replay_starts_at_first_unresolved() {
        let dir = TempDir::new().unwrap();
        let first;
        let second;
        let third;
        {
            let mut queue = open(&dir);
            first = queue.try_submit(b"first").unwrap();
            second = queue.try_submit(b"second").unwrap();
            third = queue.try_submit(b"third").unwrap();
            queue.send_next().unwrap();
            queue.send_next().unwrap();
            queue.ack_wire(0).unwrap();
        }

        let mut recovered = open(&dir);

        assert_eq!(recovered.completed_fsn(), Some(0));
        assert_eq!(recovered.server_acked_fsn(), Some(0));
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
            recovered.send_next().unwrap(),
            SentFrame {
                fsn: 1,
                wire_seq: 0,
                payload_len: 6,
            }
        );
        assert_eq!(recovered.fsn_at_zero(), Some(1));
    }

    #[test]
    fn poison_gap_survives_restart_and_later_ack_does_not_advance_server_acked() {
        let dir = TempDir::new().unwrap();
        let first;
        let second;
        let third;
        {
            let mut queue = open(&dir);
            first = queue.try_submit(b"first").unwrap();
            second = queue.try_submit(b"second").unwrap();
            third = queue.try_submit(b"third").unwrap();
            queue.send_next().unwrap();
            queue.send_next().unwrap();
            queue.send_next().unwrap();
            assert_eq!(queue.reject_wire(1).unwrap(), second);
        }

        let mut recovered = open(&dir);

        assert_eq!(recovered.completed_fsn(), Some(1));
        assert_eq!(recovered.server_acked_fsn(), Some(0));
        assert_eq!(
            recovered.receipt_status(first),
            QwpReceiptStatus::Acked { fsn: 0 }
        );
        assert_eq!(
            recovered.receipt_status(second),
            QwpReceiptStatus::Poisoned { fsn: 1 }
        );
        assert_eq!(
            recovered.receipt_status(third),
            QwpReceiptStatus::Published { fsn: 2 }
        );

        assert_eq!(
            recovered.send_next().unwrap(),
            SentFrame {
                fsn: 2,
                wire_seq: 0,
                payload_len: 5,
            }
        );
        recovered.ack_wire(0).unwrap();

        assert_eq!(recovered.completed_fsn(), Some(2));
        assert_eq!(recovered.server_acked_fsn(), Some(0));
        assert_eq!(
            recovered.receipt_status(third),
            QwpReceiptStatus::Acked { fsn: 2 }
        );
    }

    #[test]
    fn completion_after_poison_gap_survives_second_restart() {
        let dir = TempDir::new().unwrap();
        {
            let mut queue = open(&dir);
            queue.try_submit(b"first").unwrap();
            queue.try_submit(b"second").unwrap();
            queue.try_submit(b"third").unwrap();
            queue.send_next().unwrap();
            queue.send_next().unwrap();
            queue.send_next().unwrap();
            queue.reject_wire(1).unwrap();
            queue.ack_wire(2).unwrap();
        }

        let recovered = open(&dir);

        assert_eq!(recovered.len(), 0);
        assert_eq!(recovered.bytes_used(), 0);
        assert_eq!(recovered.completed_fsn(), Some(2));
        assert_eq!(recovered.server_acked_fsn(), Some(0));
        assert_eq!(
            recovered.receipt_status(QwpReceipt { fsn: 0 }),
            QwpReceiptStatus::Acked { fsn: 0 }
        );
        assert_eq!(
            recovered.receipt_status(QwpReceipt { fsn: 1 }),
            QwpReceiptStatus::Poisoned { fsn: 1 }
        );
        assert_eq!(
            recovered.receipt_status(QwpReceipt { fsn: 2 }),
            QwpReceiptStatus::Acked { fsn: 2 }
        );
    }

    #[test]
    fn recovery_ignores_incomplete_tail_record() {
        let dir = TempDir::new().unwrap();
        {
            let mut queue = open(&dir);
            queue.try_submit(b"first").unwrap();
        }

        let log_path = dir.path().join(LOG_FILE_NAME);
        let mut log = OpenOptions::new().append(true).open(log_path).unwrap();
        log.write_all(&100_u32.to_le_bytes()).unwrap();
        log.write_all(&[TAG_FRAME]).unwrap();
        log.flush().unwrap();
        log.stream_position().unwrap();

        let recovered = open(&dir);

        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered.payload_for_fsn(0), Some(&b"first"[..]));
        assert_eq!(recovered.published_fsn(), Some(0));
    }

    #[test]
    fn recovery_truncates_incomplete_tail_before_appending_new_records() {
        let dir = TempDir::new().unwrap();
        {
            let mut queue = open(&dir);
            queue.try_submit(b"first").unwrap();
        }

        let log_path = dir.path().join(LOG_FILE_NAME);
        {
            let mut log = OpenOptions::new().append(true).open(&log_path).unwrap();
            log.write_all(&100_u32.to_le_bytes()).unwrap();
            log.write_all(&[TAG_FRAME]).unwrap();
            log.flush().unwrap();
        }

        {
            let mut recovered = open(&dir);
            assert_eq!(recovered.len(), 1);
            assert_eq!(
                recovered.try_submit(b"second").unwrap(),
                QwpReceipt { fsn: 1 }
            );
        }

        let recovered = open(&dir);

        assert_eq!(recovered.len(), 2);
        assert_eq!(recovered.payload_for_fsn(0), Some(&b"first"[..]));
        assert_eq!(recovered.payload_for_fsn(1), Some(&b"second"[..]));
        assert_eq!(recovered.published_fsn(), Some(1));
    }

    #[test]
    fn recovery_rejects_malformed_log_headers() {
        let dir = TempDir::new().unwrap();

        write_log(&dir, b"short");
        assert_corrupt_log(SfFrameQueue::open(options(&dir)), "missing log header");

        write_log(&dir, b"NOTQWPSF");
        assert_corrupt_log(SfFrameQueue::open(options(&dir)), "invalid log header");
    }

    #[test]
    fn recovery_rejects_malformed_record_shapes() {
        let dir = TempDir::new().unwrap();

        let mut record_too_short = LOG_MAGIC.to_vec();
        record_too_short.extend_from_slice(&1_u32.to_le_bytes());
        record_too_short.push(TAG_FRAME);
        write_log(&dir, &record_too_short);
        assert_corrupt_log(SfFrameQueue::open(options(&dir)), "record too short");

        write_log(&dir, LOG_MAGIC);
        append_raw_record(&dir, b'X', 0, b"payload");
        assert_corrupt_log(SfFrameQueue::open(options(&dir)), "unknown record tag");

        write_log(&dir, LOG_MAGIC);
        append_raw_record(&dir, TAG_ACK_THROUGH, 0, b"payload");
        assert_corrupt_log(
            SfFrameQueue::open(options(&dir)),
            "control record has payload",
        );
    }

    #[test]
    fn recovery_rejects_completion_records_for_unpublished_frames() {
        let dir = TempDir::new().unwrap();

        write_log(&dir, LOG_MAGIC);
        append_raw_record(&dir, TAG_ACK_THROUGH, 0, &[]);
        assert_corrupt_log(
            SfFrameQueue::open(options(&dir)),
            "ack references unpublished frame",
        );

        write_log(&dir, LOG_MAGIC);
        append_raw_record(&dir, TAG_POISON, 0, &[]);
        assert_corrupt_log(
            SfFrameQueue::open(options(&dir)),
            "poison references unpublished frame",
        );
    }

    #[test]
    fn recovery_rejects_inconsistent_frame_records() {
        let dir = TempDir::new().unwrap();

        write_log(&dir, LOG_MAGIC);
        append_raw_record(&dir, TAG_FRAME, 1, b"payload");
        assert_corrupt_log(
            SfFrameQueue::open(options(&dir)),
            "non-contiguous frame sequence",
        );

        write_log(&dir, LOG_MAGIC);
        append_raw_record(&dir, TAG_FRAME, 0, b"");
        assert_corrupt_log(SfFrameQueue::open(options(&dir)), "empty frame payload");

        write_log(&dir, LOG_MAGIC);
        append_raw_record(&dir, TAG_FRAME, 0, b"abcdef");
        assert_corrupt_log(
            SfFrameQueue::open(options_with(&dir, 8, 5, 4)),
            "frame payload exceeds byte capacity",
        );
    }

    #[test]
    fn recovery_rejects_frames_that_exceed_configured_capacity() {
        let dir = TempDir::new().unwrap();

        write_log(&dir, LOG_MAGIC);
        append_raw_record(&dir, TAG_FRAME, 0, b"abc");
        append_raw_record(&dir, TAG_FRAME, 1, b"def");
        assert_corrupt_log(
            SfFrameQueue::open(options_with(&dir, 8, 5, 4)),
            "byte capacity exceeded",
        );

        write_log(&dir, LOG_MAGIC);
        append_raw_record(&dir, TAG_FRAME, 0, b"a");
        append_raw_record(&dir, TAG_FRAME, 1, b"b");
        assert_corrupt_log(
            SfFrameQueue::open(options_with(&dir, 1, 1024, 1)),
            "frame capacity exceeded",
        );
    }

    #[test]
    fn recovery_rejects_poison_marker_for_completed_frame() {
        let dir = TempDir::new().unwrap();
        {
            let mut queue = open(&dir);
            queue.try_submit(b"first").unwrap();
            queue.send_next().unwrap();
            queue.ack_wire(0).unwrap();
        }

        let log_path = dir.path().join(LOG_FILE_NAME);
        let mut log = OpenOptions::new().append(true).open(log_path).unwrap();
        append_record(&mut log, TAG_POISON, 0, &[]).unwrap();

        let err = SfFrameQueue::open(options(&dir)).unwrap_err();

        assert!(matches!(
            err,
            SfQueueError::CorruptLog {
                reason: "poison references completed frame",
                ..
            }
        ));
    }

    #[test]
    fn recovery_rejects_duplicate_poison_marker() {
        let dir = TempDir::new().unwrap();
        {
            let mut queue = open(&dir);
            queue.try_submit(b"first").unwrap();
            queue.send_next().unwrap();
            queue.reject_wire(0).unwrap();
        }

        append_raw_record(&dir, TAG_POISON, 0, &[]);

        assert_corrupt_log(SfFrameQueue::open(options(&dir)), "duplicate poison marker");
    }

    #[test]
    fn stale_ack_after_poison_gap_does_not_append_duplicate_marker() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join(LOG_FILE_NAME);
        {
            let mut queue = open(&dir);
            queue.try_submit(b"first").unwrap();
            queue.try_submit(b"second").unwrap();
            queue.try_submit(b"third").unwrap();
            queue.send_next().unwrap();
            queue.send_next().unwrap();
            queue.send_next().unwrap();
            queue.reject_wire(1).unwrap();
            queue.ack_wire(2).unwrap();
        }

        let len_after_first_ack = fs::metadata(&log_path).unwrap().len();

        {
            let mut recovered = open(&dir);
            assert_eq!(recovered.completed_fsn(), Some(2));
            assert_eq!(recovered.server_acked_fsn(), Some(0));
            recovered.connection.fsn_at_zero = Some(0);
            recovered.connection.last_sent_wire_seq = Some(2);

            recovered.ack_wire(2).unwrap();
        }

        assert_eq!(fs::metadata(log_path).unwrap().len(), len_after_first_ack);
    }
}
