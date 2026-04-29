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

#![allow(dead_code)]

//! Java-compatible `.sfa` Store-and-Forward queue adapter.
//!
//! This layer persists only QWP/WebSocket replay payload frames in Java `.sfa`
//! segment files. ACK, rejection, receipt, wire-sequence, and in-flight state
//! are intentionally process-local, matching Java's at-least-once recovery
//! model after an unclean shutdown.

use std::collections::VecDeque;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error;

use super::qwp_ws_driver::{DriverError, ManualDriverQueue};
use super::qwp_ws_queue::{OutboundFrame, QueueError, QwpReceipt, QwpReceiptStatus, SentFrame};
use super::qwp_ws_sfa_segment::{
    FRAME_HEADER_SIZE, HEADER_SIZE, INITIAL_SEGMENT_FILE_NAME, SfaFrame, SfaSegment,
    SfaSegmentError, initial_segment_path, scan_file, spare_segment_path,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SfaQueueOptions {
    pub(crate) slot_dir: PathBuf,
    pub(crate) segment_size_bytes: u64,
    pub(crate) max_frames: usize,
    pub(crate) max_bytes: usize,
    pub(crate) max_in_flight: usize,
}

#[derive(Debug)]
pub(crate) enum SfaQueueError {
    Queue(QueueError),
    Segment(SfaSegmentError),
    Io(io::Error),
    CorruptSegments { reason: &'static str },
    Closed,
}

impl From<QueueError> for SfaQueueError {
    fn from(value: QueueError) -> Self {
        Self::Queue(value)
    }
}

impl From<SfaSegmentError> for SfaQueueError {
    fn from(value: SfaSegmentError) -> Self {
        Self::Segment(value)
    }
}

impl From<io::Error> for SfaQueueError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<SfaQueueError> for DriverError {
    fn from(value: SfaQueueError) -> Self {
        match value {
            SfaQueueError::Queue(err) => DriverError::Queue(err),
            SfaQueueError::Closed => DriverError::Closing,
            err => DriverError::Storage(error::fmt!(
                SocketError,
                "QWP/WebSocket store-and-forward queue error: {:?}",
                err
            )),
        }
    }
}

#[derive(Debug)]
pub(crate) struct SfaFrameQueue {
    slot_dir: PathBuf,
    active: Option<SfaSegment>,
    sealed_segments: VecDeque<SfaSegmentMeta>,
    frames: VecDeque<SfaQueuedFrame>,
    bytes_used: usize,
    max_frames: usize,
    max_bytes: usize,
    segment_size_bytes: u64,
    next_fsn: u64,
    published_fsn: Option<u64>,
    server_acked_fsn: Option<u64>,
    completed_fsn: Option<u64>,
    rejected_fsns: Vec<u64>,
    connection: ConnectionState,
    in_flight: InFlightRing,
    next_generation: u64,
    closed: bool,
}

impl SfaFrameQueue {
    pub(crate) fn open(options: SfaQueueOptions) -> Result<Self, SfaQueueError> {
        validate_options(&options)?;
        fs::create_dir_all(&options.slot_dir)?;

        let recovered = recover_segments(&options)?;
        let (active, sealed_segments, frames, bytes_used, next_fsn, next_generation) =
            match recovered {
                Some(recovered) => (
                    SfaSegment::open_existing(&recovered.active_path)?,
                    recovered.sealed_segments,
                    recovered.frames,
                    recovered.bytes_used,
                    recovered.next_fsn,
                    recovered.next_generation,
                ),
                None => {
                    let active_path = initial_segment_path(&options.slot_dir);
                    (
                        SfaSegment::create(
                            &active_path,
                            0,
                            options.segment_size_bytes,
                            unix_time_micros(),
                        )?,
                        VecDeque::new(),
                        VecDeque::new(),
                        0,
                        0,
                        scan_next_generation(&options.slot_dir)?,
                    )
                }
            };

        let published_fsn = next_fsn.checked_sub(1);
        let server_acked_fsn = frames.front().and_then(|frame| frame.fsn.checked_sub(1));

        Ok(Self {
            slot_dir: options.slot_dir,
            active: Some(active),
            sealed_segments,
            frames,
            bytes_used,
            max_frames: options.max_frames,
            max_bytes: options.max_bytes,
            segment_size_bytes: options.segment_size_bytes,
            next_fsn,
            published_fsn,
            server_acked_fsn,
            completed_fsn: server_acked_fsn,
            rejected_fsns: Vec::new(),
            connection: ConnectionState::default(),
            in_flight: InFlightRing::new(options.max_in_flight),
            next_generation,
            closed: false,
        })
    }

    pub(crate) fn close(&mut self) -> Result<(), SfaQueueError> {
        if self.closed {
            return Ok(());
        }

        let fully_drained = self.all_published_frames_resolved();
        self.active.take();
        self.closed = true;

        if fully_drained {
            remove_all_sfa_files(&self.slot_dir)?;
        }
        Ok(())
    }

    pub(crate) fn try_submit(&mut self, payload: &[u8]) -> Result<QwpReceipt, SfaQueueError> {
        self.validate_submit(payload)?;

        let fsn = self.next_fsn;
        let next_fsn = self
            .next_fsn
            .checked_add(1)
            .ok_or(QueueError::SequenceOverflow)?;
        self.append_to_active(payload)?;

        self.next_fsn = next_fsn;
        self.published_fsn = Some(fsn);
        self.bytes_used += payload.len();
        self.frames.push_back(SfaQueuedFrame {
            fsn,
            payload: payload.to_vec(),
            state: FrameState::Published,
        });

        Ok(QwpReceipt { fsn })
    }

    pub(crate) fn send_next(&mut self) -> Result<SentFrame, SfaQueueError> {
        let frame = {
            let outbound = self.next_outbound_frame()?;
            outbound.sent_frame()
        };
        self.commit_sent(frame)?;
        Ok(frame)
    }

    pub(crate) fn next_outbound_frame(&self) -> Result<OutboundFrame<'_>, SfaQueueError> {
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

    pub(crate) fn commit_sent(&mut self, frame: SentFrame) -> Result<(), SfaQueueError> {
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

    pub(crate) fn ack_wire(&mut self, wire_seq: u64) -> Result<(), SfaQueueError> {
        let acked_fsn = self.fsn_for_wire(wire_seq, AckKind::Ack)?;

        if self
            .server_acked_fsn
            .is_some_and(|server_acked_fsn| acked_fsn <= server_acked_fsn)
        {
            self.trim_acked_sealed_segments()?;
            return Ok(());
        }
        if self
            .completed_fsn
            .is_some_and(|completed_fsn| acked_fsn <= completed_fsn)
        {
            self.advance_server_acked_to(acked_fsn);
            self.trim_acked_sealed_segments()?;
            return Ok(());
        }

        self.ensure_ackable_through(acked_fsn)?;
        self.apply_ack_through(acked_fsn);
        self.advance_server_acked_to(acked_fsn);
        self.trim_acked_sealed_segments()?;
        Ok(())
    }

    pub(crate) fn reject_wire(&mut self, wire_seq: u64) -> Result<QwpReceipt, SfaQueueError> {
        let rejected_fsn = self.fsn_for_wire(wire_seq, AckKind::Reject)?;
        self.ensure_rejectable(rejected_fsn)?;

        if rejected_fsn > 0 {
            self.advance_server_acked_to(rejected_fsn - 1);
        }
        self.apply_rejection(rejected_fsn);
        self.trim_acked_sealed_segments()?;

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

    fn validate_submit(&self, payload: &[u8]) -> Result<(), QueueError> {
        if payload.is_empty() {
            return Err(QueueError::EmptyPayload);
        }
        if self.frames.len() == self.max_frames {
            return Err(QueueError::FrameCapacityFull {
                max_frames: self.max_frames,
            });
        }
        if payload.len() > self.max_bytes {
            return Err(QueueError::PayloadExceedsByteCapacity {
                payload_len: payload.len(),
                max_bytes: self.max_bytes,
            });
        }
        let segment_payload_capacity = self.segment_payload_capacity();
        if payload.len() > segment_payload_capacity {
            return Err(QueueError::PayloadExceedsByteCapacity {
                payload_len: payload.len(),
                max_bytes: segment_payload_capacity,
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
        Ok(())
    }

    fn append_to_active(&mut self, payload: &[u8]) -> Result<(), SfaQueueError> {
        if self.active_mut()?.try_append(payload)?.is_some() {
            return Ok(());
        }

        self.rotate_active()?;
        if self.active_mut()?.try_append(payload)?.is_some() {
            Ok(())
        } else {
            Err(QueueError::PayloadExceedsByteCapacity {
                payload_len: payload.len(),
                max_bytes: self.segment_payload_capacity(),
            }
            .into())
        }
    }

    fn rotate_active(&mut self) -> Result<(), SfaQueueError> {
        let active = self.active_ref()?;
        let sealed = SfaSegmentMeta {
            path: active.path().to_path_buf(),
            base_seq: active.header().base_seq,
            frame_count: active.frame_count(),
        };
        if sealed.frame_count == 0 {
            return Err(SfaQueueError::CorruptSegments {
                reason: "active segment filled before any frame was appended",
            });
        }

        let path = self.next_segment_path()?;
        let new_active = SfaSegment::create(
            &path,
            self.next_fsn,
            self.segment_size_bytes,
            unix_time_micros(),
        )?;
        self.sealed_segments.push_back(sealed);
        self.active = Some(new_active);
        Ok(())
    }

    fn next_segment_path(&mut self) -> Result<PathBuf, QueueError> {
        loop {
            let generation = self.next_generation;
            self.next_generation = self
                .next_generation
                .checked_add(1)
                .ok_or(QueueError::SequenceOverflow)?;
            let path = spare_segment_path(&self.slot_dir, generation);
            if !path.exists() {
                return Ok(path);
            }
        }
    }

    fn trim_acked_sealed_segments(&mut self) -> Result<(), SfaQueueError> {
        let Some(acked_fsn) = self.server_acked_fsn else {
            return Ok(());
        };

        while let Some(segment) = self.sealed_segments.front() {
            let last_fsn = segment.last_fsn()?;
            if last_fsn > acked_fsn {
                break;
            }
            let segment = self.sealed_segments.pop_front().unwrap();
            match fs::remove_file(&segment.path) {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                Err(err) => return Err(err.into()),
            }
        }
        Ok(())
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

    fn apply_rejection(&mut self, rejected_fsn: u64) {
        while self
            .frames
            .front()
            .is_some_and(|frame| frame.fsn <= rejected_fsn)
        {
            let frame = self.frames.pop_front().unwrap();
            self.bytes_used -= frame.payload.len();
            self.completed_fsn = Some(frame.fsn);
        }

        self.rejected_fsns.push(rejected_fsn);
        self.in_flight.pop_acked_through(rejected_fsn);
    }

    fn advance_server_acked_to(&mut self, acked_fsn: u64) {
        let candidate = match self
            .rejected_fsns
            .iter()
            .copied()
            .filter(|rejected_fsn| *rejected_fsn <= acked_fsn)
            .min()
        {
            Some(0) => None,
            Some(first_rejected_fsn) => Some(first_rejected_fsn - 1),
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

    fn frame_for_fsn(&self, fsn: u64) -> Option<&SfaQueuedFrame> {
        self.frames.iter().find(|frame| frame.fsn == fsn)
    }

    fn segment_payload_capacity(&self) -> usize {
        segment_payload_capacity(self.segment_size_bytes)
    }

    fn all_published_frames_resolved(&self) -> bool {
        match self.published_fsn {
            None => true,
            Some(published_fsn) => self
                .completed_fsn
                .is_some_and(|completed_fsn| completed_fsn >= published_fsn),
        }
    }

    fn active_ref(&self) -> Result<&SfaSegment, SfaQueueError> {
        self.active.as_ref().ok_or(SfaQueueError::Closed)
    }

    fn active_mut(&mut self) -> Result<&mut SfaSegment, SfaQueueError> {
        self.active.as_mut().ok_or(SfaQueueError::Closed)
    }
}

impl ManualDriverQueue for SfaFrameQueue {
    fn try_submit(&mut self, payload: &[u8]) -> Result<QwpReceipt, DriverError> {
        Ok(SfaFrameQueue::try_submit(self, payload)?)
    }

    fn next_outbound_frame(&self) -> Result<OutboundFrame<'_>, DriverError> {
        Ok(SfaFrameQueue::next_outbound_frame(self)?)
    }

    fn commit_sent(&mut self, frame: SentFrame) -> Result<(), DriverError> {
        Ok(SfaFrameQueue::commit_sent(self, frame)?)
    }

    fn ack_wire(&mut self, wire_seq: u64) -> Result<(), DriverError> {
        Ok(SfaFrameQueue::ack_wire(self, wire_seq)?)
    }

    fn reject_wire(&mut self, wire_seq: u64) -> Result<QwpReceipt, DriverError> {
        Ok(SfaFrameQueue::reject_wire(self, wire_seq)?)
    }

    fn close(&mut self) -> Result<(), DriverError> {
        Ok(SfaFrameQueue::close(self)?)
    }

    fn restart_connection(&mut self) {
        SfaFrameQueue::restart_connection(self);
    }

    fn receipt_status(&self, receipt: QwpReceipt) -> QwpReceiptStatus {
        SfaFrameQueue::receipt_status(self, receipt)
    }

    fn published_fsn(&self) -> Option<u64> {
        SfaFrameQueue::published_fsn(self)
    }

    fn completed_fsn(&self) -> Option<u64> {
        SfaFrameQueue::completed_fsn(self)
    }

    fn fsn_for_wire_seq(&self, wire_seq: u64) -> Result<u64, DriverError> {
        Ok(self.fsn_for_wire(wire_seq, AckKind::Ack)?)
    }
}

#[derive(Debug)]
struct RecoveredSegments {
    active_path: PathBuf,
    sealed_segments: VecDeque<SfaSegmentMeta>,
    frames: VecDeque<SfaQueuedFrame>,
    bytes_used: usize,
    next_fsn: u64,
    next_generation: u64,
}

#[derive(Debug)]
struct RecoveredSegment {
    path: PathBuf,
    base_seq: u64,
    frames: Vec<SfaFrame>,
}

fn recover_segments(options: &SfaQueueOptions) -> Result<Option<RecoveredSegments>, SfaQueueError> {
    let mut segments = Vec::new();

    for entry in fs::read_dir(&options.slot_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !is_sfa_file(&path) {
            continue;
        }

        let scan = scan_file(&path)?;
        if scan.frames.is_empty() {
            if scan.torn_tail_bytes == 0 {
                match fs::remove_file(&path) {
                    Ok(()) => {}
                    Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                    Err(err) => return Err(err.into()),
                }
                continue;
            }
            return Err(SfaQueueError::CorruptSegments {
                reason: "empty segment has torn tail",
            });
        }

        segments.push(RecoveredSegment {
            path,
            base_seq: scan.header.base_seq,
            frames: scan.frames,
        });
    }

    if segments.is_empty() {
        return Ok(None);
    }

    segments.sort_by_key(|segment| segment.base_seq);
    validate_contiguous_segments(&segments)?;

    let mut frames = VecDeque::new();
    let mut sealed_segments = VecDeque::new();
    let mut bytes_used = 0usize;
    for (index, segment) in segments.iter().enumerate() {
        if index + 1 < segments.len() {
            sealed_segments.push_back(SfaSegmentMeta {
                path: segment.path.clone(),
                base_seq: segment.base_seq,
                frame_count: segment.frames.len() as u64,
            });
        }

        for frame in &segment.frames {
            if frames.len() == options.max_frames {
                return Err(SfaQueueError::CorruptSegments {
                    reason: "recovered frame capacity exceeded",
                });
            }
            validate_recovered_frame(frame, &mut bytes_used, options)?;
            frames.push_back(SfaQueuedFrame {
                fsn: frame.fsn,
                payload: frame.payload.clone(),
                state: FrameState::Published,
            });
        }
    }

    let next_fsn = frames
        .back()
        .and_then(|frame| frame.fsn.checked_add(1))
        .ok_or(QueueError::SequenceOverflow)?;
    let active_path = segments.last().unwrap().path.clone();
    Ok(Some(RecoveredSegments {
        active_path,
        sealed_segments,
        frames,
        bytes_used,
        next_fsn,
        next_generation: scan_next_generation(&options.slot_dir)?,
    }))
}

fn validate_options(options: &SfaQueueOptions) -> Result<(), SfaQueueError> {
    if options.max_frames == 0 || options.max_bytes == 0 || options.max_in_flight == 0 {
        return Err(QueueError::InvalidCapacity.into());
    }
    if options.max_in_flight > options.max_frames {
        return Err(QueueError::InvalidCapacity.into());
    }
    if options.segment_size_bytes < (HEADER_SIZE + FRAME_HEADER_SIZE + 1) as u64 {
        return Err(SfaSegmentError::SizeTooSmall {
            size: options.segment_size_bytes,
        }
        .into());
    }
    Ok(())
}

fn validate_contiguous_segments(segments: &[RecoveredSegment]) -> Result<(), SfaQueueError> {
    for pair in segments.windows(2) {
        let previous = &pair[0];
        let current = &pair[1];
        let expected = previous
            .base_seq
            .checked_add(previous.frames.len() as u64)
            .ok_or(QueueError::SequenceOverflow)?;
        if current.base_seq != expected {
            return Err(SfaQueueError::CorruptSegments {
                reason: "non-contiguous recovered segment sequence",
            });
        }
    }
    Ok(())
}

fn validate_recovered_frame(
    frame: &SfaFrame,
    bytes_used: &mut usize,
    options: &SfaQueueOptions,
) -> Result<(), SfaQueueError> {
    if frame.payload.is_empty() {
        return Err(SfaQueueError::CorruptSegments {
            reason: "empty recovered frame payload",
        });
    }
    if frame.payload.len() > options.max_bytes {
        return Err(SfaQueueError::CorruptSegments {
            reason: "recovered frame exceeds byte capacity",
        });
    }
    if frame.payload.len() > segment_payload_capacity(options.segment_size_bytes) {
        return Err(SfaQueueError::CorruptSegments {
            reason: "recovered frame exceeds segment capacity",
        });
    }
    let new_bytes_used =
        bytes_used
            .checked_add(frame.payload.len())
            .ok_or(SfaQueueError::CorruptSegments {
                reason: "recovered byte capacity overflow",
            })?;
    if new_bytes_used > options.max_bytes {
        return Err(SfaQueueError::CorruptSegments {
            reason: "recovered byte capacity exceeded",
        });
    }
    *bytes_used = new_bytes_used;
    Ok(())
}

fn scan_next_generation(slot_dir: &Path) -> Result<u64, io::Error> {
    let mut max_generation: Option<u64> = None;
    for entry in fs::read_dir(slot_dir)? {
        let entry = entry?;
        let Some(file_name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if let Some(generation) = segment_generation(&file_name) {
            max_generation = Some(max_generation.map_or(generation, |max| max.max(generation)));
        }
    }
    Ok(max_generation.map_or(0, |generation| generation.saturating_add(1)))
}

fn segment_generation(file_name: &str) -> Option<u64> {
    let hex = file_name.strip_prefix("sf-")?.strip_suffix(".sfa")?;
    if hex.len() != 16 || file_name == INITIAL_SEGMENT_FILE_NAME {
        return None;
    }
    u64::from_str_radix(hex, 16).ok()
}

fn is_sfa_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.ends_with(".sfa"))
}

fn remove_all_sfa_files(slot_dir: &Path) -> Result<(), io::Error> {
    for entry in fs::read_dir(slot_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !is_sfa_file(&path) {
            continue;
        }
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

fn unix_time_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_micros().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

fn segment_payload_capacity(segment_size_bytes: u64) -> usize {
    segment_size_bytes
        .saturating_sub((HEADER_SIZE + FRAME_HEADER_SIZE) as u64)
        .min(usize::MAX as u64) as usize
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SfaSegmentMeta {
    path: PathBuf,
    base_seq: u64,
    frame_count: u64,
}

impl SfaSegmentMeta {
    fn last_fsn(&self) -> Result<u64, SfaQueueError> {
        if self.frame_count == 0 {
            return Err(SfaQueueError::CorruptSegments {
                reason: "sealed segment has no frames",
            });
        }
        self.base_seq
            .checked_add(self.frame_count - 1)
            .ok_or(QueueError::SequenceOverflow.into())
    }
}

#[derive(Debug)]
struct SfaQueuedFrame {
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
    use std::path::Path;

    use tempfile::TempDir;

    use super::super::qwp_ws_driver::{
        CloseOutcome, DriveOutcome, FakeOrderedServer, ManualDriverPrototype,
    };
    use super::super::qwp_ws_sfa_segment::{scan_file, spare_segment_path};
    use super::*;

    const JAVA_TWO_FRAME_FIXTURE_HEX: &str =
        include_str!("../../tests/interop/qwp-ws-sfa/java-two-frame.sfa.hex");

    fn options(dir: &TempDir) -> SfaQueueOptions {
        options_with(dir, 256, 16, 1024, 4)
    }

    fn options_with(
        dir: &TempDir,
        segment_size_bytes: u64,
        max_frames: usize,
        max_bytes: usize,
        max_in_flight: usize,
    ) -> SfaQueueOptions {
        SfaQueueOptions {
            slot_dir: dir.path().to_path_buf(),
            segment_size_bytes,
            max_frames,
            max_bytes,
            max_in_flight,
        }
    }

    fn open(dir: &TempDir) -> SfaFrameQueue {
        SfaFrameQueue::open(options(dir)).unwrap()
    }

    fn sfa_file_count(dir: &Path) -> usize {
        fs::read_dir(dir)
            .unwrap()
            .filter(|entry| is_sfa_file(&entry.as_ref().unwrap().path()))
            .count()
    }

    fn decode_hex_fixture(hex: &str) -> Vec<u8> {
        let mut nibbles = Vec::new();
        for byte in hex.bytes() {
            let value = match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                b' ' | b'\n' | b'\r' | b'\t' => continue,
                _ => panic!("invalid hex fixture byte: {byte}"),
            };
            nibbles.push(value);
        }
        assert_eq!(nibbles.len() % 2, 0, "hex fixture has odd length");

        nibbles
            .chunks_exact(2)
            .map(|pair| (pair[0] << 4) | pair[1])
            .collect()
    }

    #[test]
    fn open_creates_initial_segment_and_publishes_after_durable_append() {
        let dir = TempDir::new().unwrap();
        let mut queue = open(&dir);

        assert_eq!(queue.try_submit(b"first").unwrap(), QwpReceipt { fsn: 0 });
        assert_eq!(queue.try_submit(b"second").unwrap(), QwpReceipt { fsn: 1 });
        assert_eq!(queue.published_fsn(), Some(1));

        let scan = scan_file(initial_segment_path(dir.path())).unwrap();
        assert_eq!(scan.header.base_seq, 0);
        assert_eq!(scan.frames[0].payload, b"first");
        assert_eq!(scan.frames[1].payload, b"second");
    }

    #[test]
    fn recover_replays_payloads_from_committed_java_sfa_fixture() {
        let dir = TempDir::new().unwrap();
        fs::write(
            initial_segment_path(dir.path()),
            decode_hex_fixture(JAVA_TWO_FRAME_FIXTURE_HEX),
        )
        .unwrap();

        let mut queue = open(&dir);

        assert_eq!(queue.len(), 2);
        assert_eq!(queue.published_fsn(), Some(43));
        assert_eq!(queue.server_acked_fsn(), Some(41));
        assert_eq!(queue.payload_for_fsn(42), Some(&b"one"[..]));
        assert_eq!(queue.payload_for_fsn(43), Some(&b"two-two"[..]));
        assert_eq!(
            queue.send_next().unwrap(),
            SentFrame {
                fsn: 42,
                wire_seq: 0,
                payload_len: 3,
            }
        );
        assert_eq!(
            queue.send_next().unwrap(),
            SentFrame {
                fsn: 43,
                wire_seq: 1,
                payload_len: 7,
            }
        );
    }

    #[test]
    fn recovery_applies_configured_frame_capacity() {
        let dir = TempDir::new().unwrap();
        fs::write(
            initial_segment_path(dir.path()),
            decode_hex_fixture(JAVA_TWO_FRAME_FIXTURE_HEX),
        )
        .unwrap();

        let err = SfaFrameQueue::open(options_with(&dir, 256, 1, 1024, 1)).unwrap_err();

        assert!(matches!(
            err,
            SfaQueueError::CorruptSegments {
                reason: "recovered frame capacity exceeded",
            }
        ));
    }

    #[test]
    fn close_removes_empty_initial_segment() {
        let dir = TempDir::new().unwrap();
        let mut queue = open(&dir);

        assert_eq!(sfa_file_count(dir.path()), 1);

        queue.close().unwrap();

        assert_eq!(sfa_file_count(dir.path()), 0);
    }

    #[test]
    fn close_retains_recoverable_frames_until_they_are_resolved() {
        let dir = TempDir::new().unwrap();
        {
            let mut queue = open(&dir);
            queue.try_submit(b"first").unwrap();
            queue.close().unwrap();
        }

        assert_eq!(sfa_file_count(dir.path()), 1);

        let recovered = open(&dir);
        assert_eq!(recovered.payload_for_fsn(0), Some(&b"first"[..]));
        assert_eq!(
            recovered.receipt_status(QwpReceipt { fsn: 0 }),
            QwpReceiptStatus::Published { fsn: 0 }
        );
    }

    #[test]
    fn close_removes_sfa_files_after_all_published_frames_are_resolved() {
        let dir = TempDir::new().unwrap();
        let mut queue = open(&dir);
        queue.try_submit(b"first").unwrap();
        queue.send_next().unwrap();
        queue.ack_wire(0).unwrap();

        queue.close().unwrap();

        assert_eq!(sfa_file_count(dir.path()), 0);
    }

    #[test]
    fn sent_and_ack_state_are_not_durable_after_reopen() {
        let dir = TempDir::new().unwrap();
        let first;
        {
            let mut queue = open(&dir);
            first = queue.try_submit(b"first").unwrap();
            queue.try_submit(b"second").unwrap();
            queue.send_next().unwrap();
            queue.ack_wire(0).unwrap();

            assert_eq!(
                queue.receipt_status(first),
                QwpReceiptStatus::Acked { fsn: 0 }
            );
        }

        let mut recovered = open(&dir);

        assert_eq!(
            recovered.receipt_status(first),
            QwpReceiptStatus::Published { fsn: 0 }
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
    fn restart_replays_sent_frames_with_zero_based_wire_sequence() {
        let dir = TempDir::new().unwrap();
        let mut queue = open(&dir);
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
    fn rotation_uses_java_segment_names_and_recovers_in_fsn_order() {
        let dir = TempDir::new().unwrap();
        {
            let mut queue = SfaFrameQueue::open(options_with(&dir, 38, 8, 1024, 4)).unwrap();
            assert_eq!(queue.try_submit(b"first").unwrap(), QwpReceipt { fsn: 0 });
            assert_eq!(queue.try_submit(b"second").unwrap(), QwpReceipt { fsn: 1 });
        }

        let first_path = initial_segment_path(dir.path());
        let second_path = spare_segment_path(dir.path(), 0);
        assert!(first_path.exists());
        assert!(second_path.exists());
        assert_eq!(scan_file(&first_path).unwrap().header.base_seq, 0);
        assert_eq!(scan_file(&second_path).unwrap().header.base_seq, 1);

        let mut recovered = SfaFrameQueue::open(options_with(&dir, 38, 8, 1024, 4)).unwrap();
        assert_eq!(recovered.payload_for_fsn(0), Some(&b"first"[..]));
        assert_eq!(recovered.payload_for_fsn(1), Some(&b"second"[..]));
        assert_eq!(recovered.send_next().unwrap().fsn, 0);
        assert_eq!(recovered.send_next().unwrap().fsn, 1);
    }

    #[test]
    fn cumulative_ack_trims_fully_acked_sealed_segments_but_keeps_active() {
        let dir = TempDir::new().unwrap();
        let first_path = initial_segment_path(dir.path());
        let second_path = spare_segment_path(dir.path(), 0);
        let mut queue = SfaFrameQueue::open(options_with(&dir, 38, 8, 1024, 4)).unwrap();
        queue.try_submit(b"first").unwrap();
        queue.try_submit(b"second").unwrap();

        queue.send_next().unwrap();
        queue.send_next().unwrap();
        queue.ack_wire(1).unwrap();

        assert!(!first_path.exists());
        assert!(second_path.exists());
        assert_eq!(queue.completed_fsn(), Some(1));
    }

    #[test]
    fn driver_close_drain_removes_sfa_files_after_delivery() {
        let dir = TempDir::new().unwrap();
        let queue = open(&dir);
        let server = FakeOrderedServer::ack_each_send();
        let mut driver = ManualDriverPrototype::from_queue(queue, server);
        driver.try_submit(b"first").unwrap();

        assert_eq!(driver.close_drain_steps(4).unwrap(), CloseOutcome::Drained);

        assert_eq!(sfa_file_count(dir.path()), 0);
    }

    #[test]
    fn driver_close_timeout_retains_recoverable_sfa_files() {
        let dir = TempDir::new().unwrap();
        {
            let queue = open(&dir);
            let server = FakeOrderedServer::no_response();
            let mut driver = ManualDriverPrototype::from_queue(queue, server);
            driver.try_submit(b"first").unwrap();

            assert_eq!(driver.close_drain_steps(0).unwrap(), CloseOutcome::Timeout);
        }

        assert_eq!(sfa_file_count(dir.path()), 1);
        let recovered = open(&dir);
        assert_eq!(recovered.payload_for_fsn(0), Some(&b"first"[..]));
    }

    #[test]
    fn manual_driver_sends_recovered_sfa_frames() {
        let dir = TempDir::new().unwrap();
        fs::write(
            initial_segment_path(dir.path()),
            decode_hex_fixture(JAVA_TWO_FRAME_FIXTURE_HEX),
        )
        .unwrap();
        let queue = open(&dir);
        let server = FakeOrderedServer::ack_each_send();
        let mut driver = ManualDriverPrototype::from_queue(queue, server);

        assert_eq!(
            driver.drive_once().unwrap(),
            DriveOutcome::Acked { wire_seq: 0 }
        );
        assert_eq!(
            driver.drive_once().unwrap(),
            DriveOutcome::Acked { wire_seq: 1 }
        );
        assert_eq!(driver.sent_frames()[0].fsn, 42);
        assert_eq!(driver.sent_frames()[1].fsn, 43);
    }
}
