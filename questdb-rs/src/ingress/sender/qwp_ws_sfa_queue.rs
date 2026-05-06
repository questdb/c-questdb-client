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
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error;

use super::qwp_ws_driver::{DriverError, PublicationLog};
use super::qwp_ws_queue::{PendingPayload, QueueError, QwpReceipt, QwpReceiptStatus};
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
    InvalidSfDir,
    InvalidSenderId { sender_id: String },
    SlotInUse { slot_dir: PathBuf, holder: String },
    SlotLockUnsupported,
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
    recovery_diagnostics: Vec<SfaRecoveryDiagnostic>,
    bytes_used: usize,
    max_frames: usize,
    max_bytes: usize,
    segment_size_bytes: u64,
    next_fsn: u64,
    published_fsn: Option<u64>,
    completed_fsn: Option<u64>,
    rejected_fsns: Vec<u64>,
    max_in_flight: usize,
    next_generation: u64,
    closed: bool,
}

impl SfaFrameQueue {
    pub(crate) fn open(options: SfaQueueOptions) -> Result<Self, SfaQueueError> {
        validate_options(&options)?;
        fs::create_dir_all(&options.slot_dir)?;

        let recovered = recover_segments(&options)?;
        let recovery_diagnostics = recovered.diagnostics;
        let (active, sealed_segments, frames, bytes_used, next_fsn, next_generation) =
            match recovered.segments {
                Some(segments) => (
                    SfaSegment::open_existing(&segments.active_path)?,
                    segments.sealed_segments,
                    segments.frames,
                    segments.bytes_used,
                    segments.next_fsn,
                    segments.next_generation,
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
        let completed_fsn = frames.front().and_then(|frame| frame.fsn.checked_sub(1));

        Ok(Self {
            slot_dir: options.slot_dir,
            active: Some(active),
            sealed_segments,
            frames,
            recovery_diagnostics,
            bytes_used,
            max_frames: options.max_frames,
            max_bytes: options.max_bytes,
            segment_size_bytes: options.segment_size_bytes,
            next_fsn,
            published_fsn,
            completed_fsn,
            rejected_fsns: Vec::new(),
            max_in_flight: options.max_in_flight,
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
        let stored_payload: Arc<[u8]> = Arc::from(payload);
        self.append_to_active(stored_payload.as_ref())?;

        self.next_fsn = next_fsn;
        self.published_fsn = Some(fsn);
        self.bytes_used += stored_payload.len();
        self.frames.push_back(SfaQueuedFrame {
            fsn,
            payload: stored_payload,
        });

        Ok(QwpReceipt { fsn })
    }

    pub(crate) fn complete_through_fsn(&mut self, acked_fsn: u64) -> Result<(), SfaQueueError> {
        if self
            .completed_fsn
            .is_some_and(|completed_fsn| acked_fsn <= completed_fsn)
        {
            self.trim_acked_sealed_segments()?;
            return Ok(());
        }
        let Some(published_fsn) = self.published_fsn else {
            return Err(QueueError::ProtocolAckedUnsentFrame { fsn: acked_fsn }.into());
        };
        if acked_fsn > published_fsn {
            return Err(QueueError::ProtocolAckedUnsentFrame { fsn: acked_fsn }.into());
        }

        self.apply_ack_through(acked_fsn);
        self.trim_acked_sealed_segments()?;
        Ok(())
    }

    pub(crate) fn reject_fsn(&mut self, rejected_fsn: u64) -> Result<QwpReceipt, SfaQueueError> {
        if self
            .published_fsn
            .is_none_or(|published_fsn| rejected_fsn > published_fsn)
        {
            return Err(QueueError::ProtocolRejectedUnsentFrame { fsn: rejected_fsn }.into());
        }
        if self.payload_for_fsn(rejected_fsn).is_none() {
            return Err(QueueError::ProtocolRejectedUnsentFrame { fsn: rejected_fsn }.into());
        }

        self.apply_rejection(rejected_fsn);
        if !self.rejected_fsns.contains(&rejected_fsn) {
            self.rejected_fsns.push(rejected_fsn);
        }
        self.trim_acked_sealed_segments()?;

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

        if let Some(frame) = self.frame_for_fsn(fsn) {
            return QwpReceiptStatus::Published { fsn: frame.fsn };
        }

        QwpReceiptStatus::Unknown { fsn }
    }

    pub(crate) fn payload_for_fsn(&self, fsn: u64) -> Option<&[u8]> {
        self.frame_for_fsn(fsn).map(|frame| frame.payload.as_ref())
    }

    pub(crate) fn pending_payload_for_fsn(&self, fsn: u64) -> Option<PendingPayload> {
        self.frame_for_fsn(fsn)
            .map(|frame| PendingPayload::owned(Arc::clone(&frame.payload)))
    }

    pub(crate) fn oldest_unresolved_fsn(&self) -> Option<u64> {
        self.frames.front().map(|frame| frame.fsn)
    }

    pub(crate) fn len(&self) -> usize {
        self.frames.len()
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

    pub(crate) fn recovery_diagnostics(&self) -> &[SfaRecoveryDiagnostic] {
        &self.recovery_diagnostics
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
        let Some(acked_fsn) = self.completed_fsn else {
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

impl PublicationLog for SfaFrameQueue {
    fn try_publish(&mut self, payload: &[u8]) -> Result<QwpReceipt, DriverError> {
        Ok(SfaFrameQueue::try_submit(self, payload)?)
    }

    fn pending_payload_for_fsn(&self, fsn: u64) -> Result<Option<PendingPayload>, DriverError> {
        Ok(SfaFrameQueue::pending_payload_for_fsn(self, fsn))
    }

    fn oldest_unresolved_fsn(&self) -> Option<u64> {
        SfaFrameQueue::oldest_unresolved_fsn(self)
    }

    fn complete_through(&mut self, fsn: u64) -> Result<(), DriverError> {
        Ok(SfaFrameQueue::complete_through_fsn(self, fsn)?)
    }

    fn close(&mut self) -> Result<(), DriverError> {
        Ok(SfaFrameQueue::close(self)?)
    }

    fn reject_fsn(&mut self, fsn: u64) -> Result<QwpReceipt, DriverError> {
        Ok(SfaFrameQueue::reject_fsn(self, fsn)?)
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

    fn max_in_flight(&self) -> usize {
        SfaFrameQueue::max_in_flight(self)
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
struct RecoveredState {
    segments: Option<RecoveredSegments>,
    diagnostics: Vec<SfaRecoveryDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SfaRecoveryDiagnostic {
    SkippedSegment {
        path: PathBuf,
        error: String,
    },
    NonEmptyTornTail {
        path: PathBuf,
        torn_tail_bytes: u64,
        append_offset: u64,
        file_size: u64,
        frames_recovered: usize,
    },
}

#[derive(Debug)]
struct RecoveredSegment {
    path: PathBuf,
    base_seq: u64,
    frames: Vec<SfaFrame>,
}

fn recover_segments(options: &SfaQueueOptions) -> Result<RecoveredState, SfaQueueError> {
    let mut segments = Vec::new();
    let mut diagnostics = Vec::new();

    for entry in fs::read_dir(&options.slot_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !is_sfa_file(&path) {
            continue;
        }

        let scan = match scan_file(&path) {
            Ok(scan) => scan,
            Err(err) => {
                diagnostics.push(SfaRecoveryDiagnostic::SkippedSegment {
                    path: path.clone(),
                    error: format!("{err:?}"),
                });
                continue;
            }
        };
        if scan.frames.is_empty() {
            if scan.torn_tail_bytes == 0 {
                match fs::remove_file(&path) {
                    Ok(()) => {}
                    Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                    Err(err) => return Err(err.into()),
                }
            } else {
                quarantine_segment(&path);
            }
            continue;
        }

        if scan.torn_tail_bytes > 0 {
            diagnostics.push(SfaRecoveryDiagnostic::NonEmptyTornTail {
                path: path.clone(),
                torn_tail_bytes: scan.torn_tail_bytes,
                append_offset: scan.append_offset,
                file_size: scan.append_offset.saturating_add(scan.torn_tail_bytes),
                frames_recovered: scan.frames.len(),
            });
        }

        segments.push(RecoveredSegment {
            path,
            base_seq: scan.header.base_seq,
            frames: scan.frames,
        });
    }

    if segments.is_empty() {
        return Ok(RecoveredState {
            segments: None,
            diagnostics,
        });
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
                payload: Arc::from(frame.payload.as_slice()),
            });
        }
    }

    let next_fsn = frames
        .back()
        .and_then(|frame| frame.fsn.checked_add(1))
        .ok_or(QueueError::SequenceOverflow)?;
    let active_path = segments.last().unwrap().path.clone();
    Ok(RecoveredState {
        segments: Some(RecoveredSegments {
            active_path,
            sealed_segments,
            frames,
            bytes_used,
            next_fsn,
            next_generation: scan_next_generation(&options.slot_dir)?,
        }),
        diagnostics,
    })
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

fn corrupt_segment_path(path: &Path) -> PathBuf {
    let mut path = path.as_os_str().to_os_string();
    path.push(".corrupt");
    PathBuf::from(path)
}

fn quarantine_segment(path: &Path) {
    // Java's SegmentRing treats this quarantine as best-effort and keeps
    // recovery live even if the rename fails. It also replaces an existing
    // .corrupt file on Windows, so remove the target first before the
    // platform-neutral Rust rename.
    let corrupt_path = corrupt_segment_path(path);
    match fs::remove_file(&corrupt_path) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(_) => {}
    }
    let _ = fs::rename(path, corrupt_path);
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
    payload: Arc<[u8]>,
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

    fn write_empty_torn_segment(path: &Path, base_seq: u64, segment_size_bytes: u64) {
        let segment = SfaSegment::create(path, base_seq, segment_size_bytes, 0).unwrap();
        drop(segment);
        let mut bytes = fs::read(path).unwrap();
        bytes[HEADER_SIZE] = 0xca;
        fs::write(path, bytes).unwrap();
    }

    fn write_segment_with_one_frame(path: &Path, base_seq: u64, payload: &[u8]) {
        let mut segment = SfaSegment::create(path, base_seq, 256, 0).unwrap();
        segment.try_append(payload).unwrap();
    }

    fn write_bad_magic_segment(path: &Path) {
        let mut bytes = vec![0u8; 64];
        bytes[..4].copy_from_slice(&0xdead_beefu32.to_le_bytes());
        fs::write(path, bytes).unwrap();
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
    fn empty_payload_is_rejected_without_consuming_fsn() {
        let dir = TempDir::new().unwrap();
        let mut queue = open(&dir);

        assert!(matches!(
            queue.try_submit(b""),
            Err(SfaQueueError::Queue(QueueError::EmptyPayload))
        ));

        assert_eq!(queue.try_submit(b"payload").unwrap(), QwpReceipt { fsn: 0 });
    }

    #[test]
    fn recover_replays_payloads_from_committed_java_sfa_fixture() {
        let dir = TempDir::new().unwrap();
        fs::write(
            initial_segment_path(dir.path()),
            decode_hex_fixture(JAVA_TWO_FRAME_FIXTURE_HEX),
        )
        .unwrap();

        let queue = open(&dir);

        assert_eq!(queue.len(), 2);
        assert_eq!(queue.published_fsn(), Some(43));
        assert_eq!(queue.completed_fsn(), Some(41));
        assert_eq!(queue.oldest_unresolved_fsn(), Some(42));
        assert_eq!(queue.payload_for_fsn(42), Some(&b"one"[..]));
        assert_eq!(queue.payload_for_fsn(43), Some(&b"two-two"[..]));
    }

    #[test]
    fn recovery_rejects_empty_frame_payload() {
        let dir = TempDir::new().unwrap();
        write_segment_with_one_frame(&initial_segment_path(dir.path()), 0, b"");

        let err = SfaFrameQueue::open(options(&dir)).unwrap_err();

        assert!(matches!(
            err,
            SfaQueueError::CorruptSegments {
                reason: "empty recovered frame payload",
            }
        ));
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
    fn recovery_quarantines_empty_torn_initial_segment_and_continues() {
        let dir = TempDir::new().unwrap();
        let initial_path = initial_segment_path(dir.path());
        let corrupt_path = corrupt_segment_path(&initial_path);
        fs::write(&corrupt_path, b"stale corrupt segment").unwrap();
        write_empty_torn_segment(&initial_path, 0, 256);

        let queue = open(&dir);

        assert_eq!(queue.len(), 0);
        assert!(initial_path.exists());
        assert!(corrupt_path.exists());
        let active_scan = scan_file(&initial_path).unwrap();
        assert!(active_scan.frames.is_empty());
        assert_eq!(active_scan.torn_tail_bytes, 0);
        let corrupt_scan = scan_file(&corrupt_path).unwrap();
        assert!(corrupt_scan.frames.is_empty());
        assert!(corrupt_scan.torn_tail_bytes > 0);
    }

    #[test]
    fn recovery_quarantines_empty_torn_spare_without_dropping_valid_frames() {
        let dir = TempDir::new().unwrap();
        let initial_path = initial_segment_path(dir.path());
        let spare_path = spare_segment_path(dir.path(), 0);
        let corrupt_spare_path = corrupt_segment_path(&spare_path);

        let mut initial = SfaSegment::create(&initial_path, 0, 256, 0).unwrap();
        initial.try_append(b"first").unwrap();
        drop(initial);
        write_empty_torn_segment(&spare_path, 99, 256);

        let queue = open(&dir);

        assert_eq!(queue.len(), 1);
        assert_eq!(queue.payload_for_fsn(0), Some(&b"first"[..]));
        assert!(!spare_path.exists());
        assert!(corrupt_spare_path.exists());
    }

    #[test]
    fn recovery_skips_bad_side_file_without_dropping_contiguous_frames() {
        let dir = TempDir::new().unwrap();
        let initial_path = initial_segment_path(dir.path());
        let second_path = spare_segment_path(dir.path(), 0);
        let bad_side_path = spare_segment_path(dir.path(), 99);
        let bad_side_corrupt_path = corrupt_segment_path(&bad_side_path);

        write_segment_with_one_frame(&initial_path, 0, b"first");
        write_segment_with_one_frame(&second_path, 1, b"second");
        write_bad_magic_segment(&bad_side_path);

        let queue = open(&dir);

        assert_eq!(queue.len(), 2);
        assert_eq!(queue.payload_for_fsn(0), Some(&b"first"[..]));
        assert_eq!(queue.payload_for_fsn(1), Some(&b"second"[..]));
        assert!(bad_side_path.exists());
        assert!(!bad_side_corrupt_path.exists());
        assert!(matches!(
            queue.recovery_diagnostics(),
            [SfaRecoveryDiagnostic::SkippedSegment { path, .. }]
                if path == &bad_side_path
        ));
    }

    #[test]
    fn recovery_skips_bad_middle_file_but_preserves_gap_failure() {
        let dir = TempDir::new().unwrap();
        let initial_path = initial_segment_path(dir.path());
        let bad_middle_path = spare_segment_path(dir.path(), 0);
        let third_path = spare_segment_path(dir.path(), 1);

        write_segment_with_one_frame(&initial_path, 0, b"first");
        write_bad_magic_segment(&bad_middle_path);
        write_segment_with_one_frame(&third_path, 2, b"third");

        let err = SfaFrameQueue::open(options(&dir)).unwrap_err();

        assert!(matches!(
            err,
            SfaQueueError::CorruptSegments {
                reason: "non-contiguous recovered segment sequence",
            }
        ));
        assert!(bad_middle_path.exists());
        assert!(!corrupt_segment_path(&bad_middle_path).exists());
    }

    #[test]
    fn recovery_records_non_empty_torn_tail_diagnostic() {
        let dir = TempDir::new().unwrap();
        let initial_path = initial_segment_path(dir.path());
        fs::write(
            &initial_path,
            decode_hex_fixture(JAVA_TWO_FRAME_FIXTURE_HEX),
        )
        .unwrap();
        let mut bytes = fs::read(&initial_path).unwrap();
        bytes[44] ^= 0x01;
        fs::write(&initial_path, bytes).unwrap();

        let queue = open(&dir);

        assert_eq!(queue.len(), 1);
        assert_eq!(queue.payload_for_fsn(42), Some(&b"one"[..]));
        assert_eq!(
            queue.recovery_diagnostics(),
            &[SfaRecoveryDiagnostic::NonEmptyTornTail {
                path: initial_path,
                torn_tail_bytes: 29,
                append_offset: 35,
                file_size: 64,
                frames_recovered: 1,
            }]
        );
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
        queue.complete_through_fsn(0).unwrap();

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
            queue.complete_through_fsn(0).unwrap();

            assert_eq!(
                queue.receipt_status(first),
                QwpReceiptStatus::Acked { fsn: 0 }
            );
        }

        let recovered = open(&dir);

        assert_eq!(
            recovered.receipt_status(first),
            QwpReceiptStatus::Published { fsn: 0 }
        );
        assert_eq!(recovered.payload_for_fsn(0), Some(&b"first"[..]));
    }

    #[test]
    fn unresolved_frames_remain_published_until_completion() {
        let dir = TempDir::new().unwrap();
        let mut queue = open(&dir);
        let first = queue.try_submit(b"first").unwrap();
        let second = queue.try_submit(b"second").unwrap();

        assert_eq!(
            queue.receipt_status(first),
            QwpReceiptStatus::Published { fsn: 0 }
        );
        assert_eq!(
            queue.receipt_status(second),
            QwpReceiptStatus::Published { fsn: 1 }
        );
        assert_eq!(queue.payload_for_fsn(0), Some(&b"first"[..]));
        assert_eq!(queue.payload_for_fsn(1), Some(&b"second"[..]));
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

        let recovered = SfaFrameQueue::open(options_with(&dir, 38, 8, 1024, 4)).unwrap();
        assert_eq!(recovered.payload_for_fsn(0), Some(&b"first"[..]));
        assert_eq!(recovered.payload_for_fsn(1), Some(&b"second"[..]));
        assert_eq!(recovered.oldest_unresolved_fsn(), Some(0));
    }

    #[test]
    fn cumulative_ack_trims_fully_acked_sealed_segments_but_keeps_active() {
        let dir = TempDir::new().unwrap();
        let first_path = initial_segment_path(dir.path());
        let second_path = spare_segment_path(dir.path(), 0);
        let mut queue = SfaFrameQueue::open(options_with(&dir, 38, 8, 1024, 4)).unwrap();
        queue.try_submit(b"first").unwrap();
        queue.try_submit(b"second").unwrap();

        queue.complete_through_fsn(1).unwrap();

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
