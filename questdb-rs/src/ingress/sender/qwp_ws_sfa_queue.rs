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

use super::qwp_ws_driver::{DriverError, PublicationLog, SendCursor};
use super::qwp_ws_queue::{
    OutboundFrame, PendingPayload, QueueError, QwpReceipt, QwpReceiptStatus,
};
use super::qwp_ws_sfa_segment::{
    FRAME_HEADER_SIZE, HEADER_SIZE, INITIAL_SEGMENT_FILE_NAME, SfaSegment, SfaSegmentError,
    initial_segment_path, scan_file_metadata, spare_segment_path,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SfaQueueOptions {
    pub(crate) slot_dir: PathBuf,
    pub(crate) segment_size_bytes: u64,
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
pub(crate) enum SfaStorageStep {
    Trim(SfaStorageCleanup),
    CreateHotSpare {
        path: PathBuf,
        base_seq: u64,
        size_bytes: u64,
        created_us: u64,
    },
}

#[derive(Debug)]
pub(crate) enum SfaStorageResult {
    Trimmed {
        cleanup_failure: Option<SfaCleanupFailure>,
    },
    HotSpareCreated {
        segment: SfaSegment,
    },
}

#[derive(Debug)]
pub(crate) struct SfaStorageFinish {
    changed: bool,
    cleanup: Option<SfaStorageCleanup>,
}

#[derive(Debug)]
pub(crate) struct SfaStorageCleanup {
    segment: SfaSegment,
    path: PathBuf,
}

#[derive(Debug)]
pub(crate) struct SfaCleanupFailure {
    path: PathBuf,
    error: String,
}

impl SfaStorageStep {
    pub(crate) fn changes_queue_before_io(&self) -> bool {
        matches!(self, Self::Trim(_))
    }

    pub(crate) fn perform(self) -> Result<SfaStorageResult, SfaQueueError> {
        match self {
            Self::Trim(cleanup) => Ok(SfaStorageResult::Trimmed {
                cleanup_failure: cleanup.perform(),
            }),
            Self::CreateHotSpare {
                path,
                base_seq,
                size_bytes,
                created_us,
            } => {
                let segment = SfaSegment::create_new(&path, base_seq, size_bytes, created_us)?;
                Ok(SfaStorageResult::HotSpareCreated { segment })
            }
        }
    }
}

impl SfaStorageFinish {
    pub(crate) fn unchanged() -> Self {
        Self {
            changed: false,
            cleanup: None,
        }
    }

    fn changed() -> Self {
        Self {
            changed: true,
            cleanup: None,
        }
    }

    fn cleanup(cleanup: SfaStorageCleanup) -> Self {
        Self {
            changed: false,
            cleanup: Some(cleanup),
        }
    }

    pub(crate) fn did_change(&self) -> bool {
        self.changed
    }

    pub(crate) fn into_cleanup(self) -> Option<SfaStorageCleanup> {
        self.cleanup
    }
}

impl SfaStorageCleanup {
    fn new(segment: SfaSegment) -> Self {
        let path = segment.path().to_path_buf();
        Self { segment, path }
    }

    pub(crate) fn perform(self) -> Option<SfaCleanupFailure> {
        let path = self.path;
        drop(self.segment);
        match fs::remove_file(&path) {
            Ok(()) => None,
            Err(err) if err.kind() == io::ErrorKind::NotFound => None,
            Err(err) => Some(SfaCleanupFailure {
                path,
                error: err.to_string(),
            }),
        }
    }
}

#[derive(Debug)]
pub(crate) struct SfaFrameQueue {
    slot_dir: PathBuf,
    active: Option<SfaSegment>,
    sealed_segments: VecDeque<SfaSegment>,
    hot_spare: Option<SfaSegment>,
    allocated_segment_bytes: u64,
    recovery_diagnostics: Vec<SfaRecoveryDiagnostic>,
    max_bytes: usize,
    segment_size_bytes: u64,
    next_fsn: u64,
    published_fsn: Option<u64>,
    completed_fsn: Option<u64>,
    rejected_fsns: Vec<u64>,
    max_in_flight: usize,
    next_generation: u64,
    send_cursor: Option<SfaSendCursor>,
    closed: bool,
}

impl SfaFrameQueue {
    pub(crate) fn open(options: SfaQueueOptions) -> Result<Self, SfaQueueError> {
        validate_options(&options)?;
        fs::create_dir_all(&options.slot_dir)?;

        let recovered = recover_segments(&options)?;
        let recovery_diagnostics = recovered.diagnostics;
        let (active, sealed_segments, next_fsn, next_generation, mut allocated_segment_bytes) =
            match recovered.segments {
                Some(segments) => (
                    segments.active,
                    segments.sealed_segments,
                    segments.next_fsn,
                    segments.next_generation,
                    segments.allocated_segment_bytes,
                ),
                None => {
                    if (options.max_bytes as u64) < options.segment_size_bytes {
                        return Err(QueueError::InvalidCapacity.into());
                    }
                    let active_path = initial_segment_path(&options.slot_dir);
                    (
                        SfaSegment::create(
                            &active_path,
                            0,
                            options.segment_size_bytes,
                            unix_time_micros(),
                        )?,
                        VecDeque::new(),
                        0,
                        scan_next_generation(&options.slot_dir)?,
                        options.segment_size_bytes,
                    )
                }
            };
        let mut hot_spare = None;
        let mut next_generation = next_generation;
        if can_allocate_segment(
            allocated_segment_bytes,
            options.segment_size_bytes,
            options.max_bytes,
        ) {
            let path = next_segment_path(&options.slot_dir, &mut next_generation)?;
            hot_spare = Some(SfaSegment::create_new(
                &path,
                next_fsn,
                options.segment_size_bytes,
                unix_time_micros(),
            )?);
            allocated_segment_bytes = allocated_segment_bytes
                .checked_add(options.segment_size_bytes)
                .ok_or(QueueError::SequenceOverflow)?;
        }

        let published_fsn = next_fsn.checked_sub(1);
        let completed_fsn = first_unresolved_fsn_from_segments(&sealed_segments, &active)
            .and_then(|fsn| fsn.checked_sub(1));

        Ok(Self {
            slot_dir: options.slot_dir,
            active: Some(active),
            sealed_segments,
            hot_spare,
            allocated_segment_bytes,
            recovery_diagnostics,
            max_bytes: options.max_bytes,
            segment_size_bytes: options.segment_size_bytes,
            next_fsn,
            published_fsn,
            completed_fsn,
            rejected_fsns: Vec::new(),
            max_in_flight: options.max_in_flight,
            next_generation,
            send_cursor: None,
            closed: false,
        })
    }

    pub(crate) fn close(&mut self) -> Result<(), SfaQueueError> {
        if self.closed {
            return Ok(());
        }

        let fully_drained = self.all_published_frames_resolved();
        self.sealed_segments.clear();
        self.hot_spare.take();
        self.active.take();
        self.closed = true;

        if fully_drained {
            record_all_sfa_cleanup(&self.slot_dir, &mut self.recovery_diagnostics)?;
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

        Ok(QwpReceipt { fsn })
    }

    pub(crate) fn complete_through_fsn(&mut self, acked_fsn: u64) -> Result<(), SfaQueueError> {
        if self
            .completed_fsn
            .is_some_and(|completed_fsn| acked_fsn <= completed_fsn)
        {
            return Ok(());
        }
        let Some(published_fsn) = self.published_fsn else {
            return Err(QueueError::ProtocolAckedUnsentFrame { fsn: acked_fsn }.into());
        };
        if acked_fsn > published_fsn {
            return Err(QueueError::ProtocolAckedUnsentFrame { fsn: acked_fsn }.into());
        }

        self.apply_ack_through(acked_fsn);
        Ok(())
    }

    pub(crate) fn reject_fsn(&mut self, rejected_fsn: u64) -> Result<QwpReceipt, SfaQueueError> {
        if self
            .published_fsn
            .is_none_or(|published_fsn| rejected_fsn > published_fsn)
        {
            return Err(QueueError::ProtocolRejectedUnsentFrame { fsn: rejected_fsn }.into());
        }
        if !self.is_unresolved_fsn(rejected_fsn) {
            return Err(QueueError::ProtocolRejectedUnsentFrame { fsn: rejected_fsn }.into());
        }

        self.apply_rejection(rejected_fsn);
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

        if self.is_unresolved_fsn(fsn) {
            return QwpReceiptStatus::Published { fsn };
        }

        QwpReceiptStatus::Unknown { fsn }
    }

    pub(crate) fn payload_for_fsn(&self, fsn: u64) -> Option<&[u8]> {
        self.segment_for_fsn(fsn)
            .and_then(|segment| segment.payload_slice_for_fsn(fsn))
    }

    pub(crate) fn pending_payload_for_fsn(&self, fsn: u64) -> Option<PendingPayload> {
        self.segment_for_fsn(fsn)
            .and_then(|segment| segment.payload_for_fsn(fsn))
            .map(PendingPayload::sfa_mapped)
    }

    pub(crate) fn next_outbound_frame(
        &mut self,
        send_cursor: &mut SendCursor,
    ) -> Result<Option<OutboundFrame>, DriverError> {
        let Some((fsn, wire_seq)) = send_cursor.peek_next_frame(&*self)? else {
            return Ok(None);
        };
        let Some(payload) = self
            .next_cursor_payload_for_fsn(fsn)
            .map_err(DriverError::from)?
        else {
            return Ok(None);
        };
        Ok(Some(OutboundFrame {
            fsn,
            wire_seq,
            payload,
        }))
    }

    pub(crate) fn restart_send_cursor(&mut self) {
        self.send_cursor = None;
    }

    pub(crate) fn maintain_storage(&mut self) -> Result<bool, SfaQueueError> {
        let Some(step) = self.take_storage_maintenance_step(true)? else {
            return Ok(false);
        };
        let changed_before_io = step.changes_queue_before_io();
        let result = step.perform()?;
        let finish = self.finish_storage_maintenance(result, true)?;
        let changed = changed_before_io || finish.did_change();
        if let Some(cleanup) = finish.into_cleanup()
            && let Some(failure) = cleanup.perform()
        {
            self.record_cleanup_failure(failure);
        }
        Ok(changed)
    }

    pub(crate) fn take_storage_maintenance_step(
        &mut self,
        allow_create: bool,
    ) -> Result<Option<SfaStorageStep>, SfaQueueError> {
        if self.closed {
            return Ok(None);
        }
        if let Some(step) = self.take_one_acked_sealed_segment()? {
            return Ok(Some(step));
        }
        if !allow_create || self.hot_spare.is_some() {
            return Ok(None);
        }
        if !can_allocate_segment(
            self.allocated_segment_bytes,
            self.segment_size_bytes,
            self.max_bytes,
        ) {
            return Ok(None);
        }
        let path = self.next_segment_path()?;
        Ok(Some(SfaStorageStep::CreateHotSpare {
            path,
            base_seq: self.next_fsn,
            size_bytes: self.segment_size_bytes,
            created_us: unix_time_micros(),
        }))
    }

    pub(crate) fn finish_storage_maintenance(
        &mut self,
        result: SfaStorageResult,
        allow_install: bool,
    ) -> Result<SfaStorageFinish, SfaQueueError> {
        match result {
            SfaStorageResult::Trimmed { cleanup_failure } => {
                if let Some(failure) = cleanup_failure {
                    self.record_cleanup_failure(failure);
                }
                Ok(SfaStorageFinish::unchanged())
            }
            SfaStorageResult::HotSpareCreated { segment } => {
                if allow_install
                    && !self.closed
                    && self.hot_spare.is_none()
                    && segment.frame_count() == 0
                    && segment.size_bytes() == self.segment_size_bytes
                    && can_allocate_segment(
                        self.allocated_segment_bytes,
                        self.segment_size_bytes,
                        self.max_bytes,
                    )
                {
                    self.allocated_segment_bytes = self
                        .allocated_segment_bytes
                        .checked_add(self.segment_size_bytes)
                        .ok_or(QueueError::SequenceOverflow)?;
                    self.hot_spare = Some(segment);
                    Ok(SfaStorageFinish::changed())
                } else {
                    Ok(SfaStorageFinish::cleanup(SfaStorageCleanup::new(segment)))
                }
            }
        }
    }

    pub(crate) fn record_cleanup_failure(&mut self, failure: SfaCleanupFailure) {
        self.recovery_diagnostics
            .push(SfaRecoveryDiagnostic::CleanupFailed {
                path: failure.path,
                error: failure.error,
            });
    }

    pub(crate) fn oldest_unresolved_fsn(&self) -> Option<u64> {
        self.oldest_unresolved_fsn_from_watermark()
    }

    pub(crate) fn len(&self) -> usize {
        let Some(oldest) = self.oldest_unresolved_fsn() else {
            return 0;
        };
        self.published_fsn
            .and_then(|published| published.checked_sub(oldest))
            .and_then(|delta| usize::try_from(delta.saturating_add(1)).ok())
            .unwrap_or(usize::MAX)
    }

    pub(crate) fn bytes_used(&self) -> usize {
        0
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
        let segment_payload_capacity = self.segment_payload_capacity();
        if payload.len() > segment_payload_capacity {
            return Err(QueueError::PayloadExceedsByteCapacity {
                payload_len: payload.len(),
                max_bytes: segment_payload_capacity,
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
        let active = self.active.take().ok_or(SfaQueueError::Closed)?;
        if active.frame_count() == 0 {
            self.active = Some(active);
            return Err(SfaQueueError::CorruptSegments {
                reason: "active segment filled before any frame was appended",
            });
        }

        let Some(mut new_active) = self.hot_spare.take() else {
            self.active = Some(active);
            return Err(self.storage_backpressure_error().into());
        };
        if let Err(err) = new_active.rebase_empty(self.next_fsn) {
            // `rebase_empty` validates before mutating the segment, so
            // `new_active` is unchanged on the error path. Restore both halves
            // so the queue stays operable instead of going permanently
            // `Closed` with `allocated_segment_bytes` still counting both.
            self.hot_spare = Some(new_active);
            self.active = Some(active);
            return Err(err.into());
        }
        self.sealed_segments.push_back(active);
        self.active = Some(new_active);
        Ok(())
    }

    fn next_segment_path(&mut self) -> Result<PathBuf, QueueError> {
        next_segment_path(&self.slot_dir, &mut self.next_generation)
    }

    fn storage_backpressure_error(&self) -> QueueError {
        if can_allocate_segment(
            self.allocated_segment_bytes,
            self.segment_size_bytes,
            self.max_bytes,
        ) {
            QueueError::StorageSpareNotReady {
                segment_size_bytes: self.segment_size_bytes,
                allocated_segment_bytes: self.allocated_segment_bytes,
                max_total_bytes: self.max_bytes as u64,
            }
        } else {
            QueueError::StorageSegmentCapFull {
                segment_size_bytes: self.segment_size_bytes,
                allocated_segment_bytes: self.allocated_segment_bytes,
                max_total_bytes: self.max_bytes as u64,
            }
        }
    }

    fn take_one_acked_sealed_segment(&mut self) -> Result<Option<SfaStorageStep>, SfaQueueError> {
        let Some(acked_fsn) = self.completed_fsn else {
            return Ok(None);
        };

        let Some(segment) = self.sealed_segments.front() else {
            return Ok(None);
        };
        let last_fsn = segment.last_fsn().ok_or(SfaQueueError::CorruptSegments {
            reason: "sealed segment has no frames",
        })?;
        if last_fsn > acked_fsn {
            return Ok(None);
        }
        let segment = self.sealed_segments.pop_front().unwrap();
        let segment_size_bytes = segment.size_bytes();

        self.allocated_segment_bytes = self
            .allocated_segment_bytes
            .saturating_sub(segment_size_bytes);
        Ok(Some(SfaStorageStep::Trim(SfaStorageCleanup::new(segment))))
    }

    fn apply_ack_through(&mut self, acked_fsn: u64) {
        if self.is_unresolved_fsn(acked_fsn) {
            self.completed_fsn = Some(acked_fsn);
        }
    }

    fn apply_rejection(&mut self, rejected_fsn: u64) {
        self.apply_ack_through(rejected_fsn);
    }

    fn segment_payload_capacity(&self) -> usize {
        segment_payload_capacity(self.segment_size_bytes)
    }

    fn segment_for_fsn(&self, fsn: u64) -> Option<&SfaSegment> {
        self.sealed_segments
            .iter()
            .chain(self.active.iter())
            .find(|segment| {
                fsn >= segment.header().base_seq
                    && segment.last_fsn().is_some_and(|last_fsn| fsn <= last_fsn)
            })
    }

    fn next_cursor_payload_for_fsn(
        &mut self,
        fsn: u64,
    ) -> Result<Option<PendingPayload>, SfaQueueError> {
        let Some(cursor) = self
            .reusable_send_cursor(fsn)
            .or_else(|| self.position_send_cursor_for_fsn(fsn))
        else {
            self.send_cursor = None;
            return Ok(None);
        };

        let (payload, segment_append_offset) = {
            let Some(segment) = self.segment_at_position(cursor.segment) else {
                self.send_cursor = None;
                return Ok(None);
            };
            if segment.header().base_seq != cursor.segment_base_seq {
                self.send_cursor = None;
                return Ok(None);
            }
            let Some(payload) = segment.mapped_payload_at_offset(cursor.offset) else {
                self.send_cursor = None;
                return Ok(None);
            };
            (payload, segment.append_offset())
        };
        let next_fsn = fsn.checked_add(1).ok_or(QueueError::SequenceOverflow)?;
        let next_offset = cursor
            .offset
            .checked_add(FRAME_HEADER_SIZE as u64)
            .and_then(|offset| offset.checked_add(payload.len() as u64))
            .ok_or(QueueError::SequenceOverflow)?;
        self.send_cursor =
            Some(self.advance_send_cursor(cursor, next_fsn, next_offset, segment_append_offset));
        Ok(Some(PendingPayload::sfa_mapped(payload)))
    }

    fn reusable_send_cursor(&self, fsn: u64) -> Option<SfaSendCursor> {
        let cursor = self.send_cursor?;
        if cursor.fsn != fsn {
            return None;
        }
        let segment = self.segment_at_position(cursor.segment)?;
        (segment.header().base_seq == cursor.segment_base_seq).then_some(cursor)
    }

    fn position_send_cursor_for_fsn(&self, fsn: u64) -> Option<SfaSendCursor> {
        let segment = self.segment_position_for_fsn(fsn)?;
        let segment_ref = self.segment_at_position(segment)?;
        let offset = segment_ref.frame_offset_for_fsn(fsn)?;
        Some(SfaSendCursor {
            fsn,
            segment,
            segment_base_seq: segment_ref.header().base_seq,
            offset,
        })
    }

    fn advance_send_cursor(
        &self,
        cursor: SfaSendCursor,
        next_fsn: u64,
        next_offset: u64,
        segment_append_offset: u64,
    ) -> SfaSendCursor {
        if next_offset < segment_append_offset {
            return SfaSendCursor {
                fsn: next_fsn,
                offset: next_offset,
                ..cursor
            };
        }

        if next_offset == segment_append_offset
            && let Some(next_segment) = self
                .next_segment_position(cursor.segment)
                .and_then(|segment| self.segment_at_position(segment).map(|s| (segment, s)))
                .filter(|(_, segment)| segment.header().base_seq == next_fsn)
        {
            return SfaSendCursor {
                fsn: next_fsn,
                segment: next_segment.0,
                segment_base_seq: next_segment.1.header().base_seq,
                offset: HEADER_SIZE as u64,
            };
        }

        SfaSendCursor {
            fsn: next_fsn,
            offset: next_offset,
            ..cursor
        }
    }

    fn segment_position_for_fsn(&self, fsn: u64) -> Option<SfaCursorSegment> {
        self.sealed_segments
            .iter()
            .enumerate()
            .find(|(_, segment)| {
                fsn >= segment.header().base_seq
                    && segment.last_fsn().is_some_and(|last_fsn| fsn <= last_fsn)
            })
            .map(|(index, _)| SfaCursorSegment::Sealed(index))
            .or_else(|| {
                self.active
                    .as_ref()
                    .filter(|segment| {
                        fsn >= segment.header().base_seq
                            && segment.last_fsn().is_some_and(|last_fsn| fsn <= last_fsn)
                    })
                    .map(|_| SfaCursorSegment::Active)
            })
    }

    fn segment_at_position(&self, segment: SfaCursorSegment) -> Option<&SfaSegment> {
        match segment {
            SfaCursorSegment::Sealed(index) => self.sealed_segments.get(index),
            SfaCursorSegment::Active => self.active.as_ref(),
        }
    }

    fn next_segment_position(&self, segment: SfaCursorSegment) -> Option<SfaCursorSegment> {
        match segment {
            SfaCursorSegment::Sealed(index) => {
                if index + 1 < self.sealed_segments.len() {
                    Some(SfaCursorSegment::Sealed(index + 1))
                } else {
                    self.active.as_ref().map(|_| SfaCursorSegment::Active)
                }
            }
            SfaCursorSegment::Active => None,
        }
    }

    fn is_unresolved_fsn(&self, fsn: u64) -> bool {
        let Some(oldest) = self.oldest_unresolved_fsn_from_watermark() else {
            return false;
        };
        self.published_fsn
            .is_some_and(|published| fsn >= oldest && fsn <= published)
    }

    fn oldest_unresolved_fsn_from_watermark(&self) -> Option<u64> {
        let published = self.published_fsn?;
        let oldest = match self.completed_fsn {
            Some(completed) => completed.checked_add(1)?,
            None => 0,
        };
        (oldest <= published).then_some(oldest)
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

    fn next_outbound_frame(
        &mut self,
        send_cursor: &mut SendCursor,
    ) -> Result<Option<OutboundFrame>, DriverError> {
        SfaFrameQueue::next_outbound_frame(self, send_cursor)
    }

    fn pending_payload_for_fsn(&self, fsn: u64) -> Result<Option<PendingPayload>, DriverError> {
        Ok(SfaFrameQueue::pending_payload_for_fsn(self, fsn))
    }

    fn restart_send_cursor(&mut self) {
        SfaFrameQueue::restart_send_cursor(self);
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

    fn take_storage_maintenance_step(
        &mut self,
        allow_create: bool,
    ) -> Result<Option<SfaStorageStep>, DriverError> {
        Ok(SfaFrameQueue::take_storage_maintenance_step(
            self,
            allow_create,
        )?)
    }

    fn finish_storage_maintenance(
        &mut self,
        result: SfaStorageResult,
        allow_install: bool,
    ) -> Result<SfaStorageFinish, DriverError> {
        Ok(SfaFrameQueue::finish_storage_maintenance(
            self,
            result,
            allow_install,
        )?)
    }

    fn record_storage_cleanup_failure(
        &mut self,
        failure: SfaCleanupFailure,
    ) -> Result<(), DriverError> {
        SfaFrameQueue::record_cleanup_failure(self, failure);
        Ok(())
    }
}

#[derive(Debug)]
struct RecoveredSegments {
    active: SfaSegment,
    sealed_segments: VecDeque<SfaSegment>,
    next_fsn: u64,
    next_generation: u64,
    allocated_segment_bytes: u64,
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
    CleanupFailed {
        path: PathBuf,
        error: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SfaSendCursor {
    fsn: u64,
    segment: SfaCursorSegment,
    segment_base_seq: u64,
    offset: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SfaCursorSegment {
    Sealed(usize),
    Active,
}

#[derive(Debug)]
struct RecoveredSegment {
    path: PathBuf,
    base_seq: u64,
    frame_count: u64,
    append_offset: u64,
    torn_tail_bytes: u64,
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

        let scan = match scan_file_metadata(&path) {
            Ok(scan) => scan,
            Err(err) => {
                diagnostics.push(SfaRecoveryDiagnostic::SkippedSegment {
                    path: path.clone(),
                    error: format!("{err:?}"),
                });
                continue;
            }
        };
        if scan.frame_count == 0 {
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
        if scan.first_empty_payload_fsn.is_some() {
            return Err(SfaQueueError::CorruptSegments {
                reason: "empty recovered frame payload",
            });
        }

        if scan.torn_tail_bytes > 0 {
            diagnostics.push(SfaRecoveryDiagnostic::NonEmptyTornTail {
                path: path.clone(),
                torn_tail_bytes: scan.torn_tail_bytes,
                append_offset: scan.append_offset,
                file_size: scan.append_offset.saturating_add(scan.torn_tail_bytes),
                frames_recovered: usize::try_from(scan.frame_count).unwrap_or(usize::MAX),
            });
        }

        segments.push(RecoveredSegment {
            path,
            base_seq: scan.header.base_seq,
            frame_count: scan.frame_count,
            append_offset: scan.append_offset,
            torn_tail_bytes: scan.torn_tail_bytes,
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

    let mut sealed_segments = VecDeque::new();
    let mut allocated_segment_bytes = 0u64;
    let active_index = segments.len() - 1;
    for segment in segments.iter().take(active_index) {
        let opened = SfaSegment::open_existing(&segment.path)?;
        allocated_segment_bytes = allocated_segment_bytes
            .checked_add(opened.size_bytes())
            .ok_or(QueueError::SequenceOverflow)?;
        sealed_segments.push_back(opened);
    }

    let active = SfaSegment::open_existing(&segments[active_index].path)?;
    allocated_segment_bytes = allocated_segment_bytes
        .checked_add(active.size_bytes())
        .ok_or(QueueError::SequenceOverflow)?;
    let next_fsn = active
        .last_fsn()
        .and_then(|fsn| fsn.checked_add(1))
        .ok_or(QueueError::SequenceOverflow)?;
    Ok(RecoveredState {
        segments: Some(RecoveredSegments {
            active,
            sealed_segments,
            next_fsn,
            next_generation: scan_next_generation(&options.slot_dir)?,
            allocated_segment_bytes,
        }),
        diagnostics,
    })
}

fn validate_options(options: &SfaQueueOptions) -> Result<(), SfaQueueError> {
    if options.max_bytes == 0 || options.max_in_flight == 0 {
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
            .checked_add(previous.frame_count)
            .ok_or(QueueError::SequenceOverflow)?;
        if current.base_seq != expected {
            return Err(SfaQueueError::CorruptSegments {
                reason: "non-contiguous recovered segment sequence",
            });
        }
    }
    Ok(())
}

fn can_allocate_segment(
    allocated_segment_bytes: u64,
    segment_size_bytes: u64,
    max_total_bytes: usize,
) -> bool {
    allocated_segment_bytes
        .checked_add(segment_size_bytes)
        .is_some_and(|bytes| bytes <= max_total_bytes as u64)
}

fn next_segment_path(slot_dir: &Path, next_generation: &mut u64) -> Result<PathBuf, QueueError> {
    let generation = *next_generation;
    *next_generation = next_generation
        .checked_add(1)
        .ok_or(QueueError::SequenceOverflow)?;
    Ok(spare_segment_path(slot_dir, generation))
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
    let hex = file_name
        .strip_prefix("sf-")?
        .strip_suffix(".sfa")
        .or_else(|| file_name.strip_prefix("sf-")?.strip_suffix(".sfa.corrupt"))?;
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

fn record_all_sfa_cleanup(
    slot_dir: &Path,
    diagnostics: &mut Vec<SfaRecoveryDiagnostic>,
) -> Result<(), SfaQueueError> {
    for entry in fs::read_dir(slot_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !is_sfa_file(&path) {
            continue;
        }
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => diagnostics.push(SfaRecoveryDiagnostic::CleanupFailed {
                path,
                error: err.to_string(),
            }),
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

fn first_unresolved_fsn_from_segments(
    sealed_segments: &VecDeque<SfaSegment>,
    active: &SfaSegment,
) -> Option<u64> {
    sealed_segments
        .front()
        .map(|segment| segment.header().base_seq)
        .or_else(|| (active.frame_count() > 0).then(|| active.header().base_seq))
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
        options_with(dir, 256, 1024, 4)
    }

    fn options_with(
        dir: &TempDir,
        segment_size_bytes: u64,
        max_bytes: usize,
        max_in_flight: usize,
    ) -> SfaQueueOptions {
        SfaQueueOptions {
            slot_dir: dir.path().to_path_buf(),
            segment_size_bytes,
            max_bytes,
            max_in_flight,
        }
    }

    fn open(dir: &TempDir) -> SfaFrameQueue {
        SfaFrameQueue::open(options(dir)).unwrap()
    }

    fn submit_with_storage_maintenance(queue: &mut SfaFrameQueue, payload: &[u8]) -> QwpReceipt {
        loop {
            match queue.try_submit(payload) {
                Ok(receipt) => return receipt,
                Err(SfaQueueError::Queue(QueueError::StorageSpareNotReady { .. })) => {
                    assert!(queue.maintain_storage().unwrap());
                }
                Err(err) => panic!("unexpected SFA submit error: {err:?}"),
            }
        }
    }

    fn pending_payload_vec(payload: PendingPayload) -> Vec<u8> {
        payload.with_bytes(|bytes| bytes.to_vec())
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
    fn recovery_does_not_apply_derived_frame_capacity() {
        let dir = TempDir::new().unwrap();
        fs::write(
            initial_segment_path(dir.path()),
            decode_hex_fixture(JAVA_TWO_FRAME_FIXTURE_HEX),
        )
        .unwrap();

        let queue = SfaFrameQueue::open(options_with(&dir, 256, 1024, 4)).unwrap();

        assert_eq!(queue.len(), 2);
        assert_eq!(queue.payload_for_fsn(42), Some(&b"one"[..]));
        assert_eq!(queue.payload_for_fsn(43), Some(&b"two-two"[..]));
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

        assert_eq!(sfa_file_count(dir.path()), 2);

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

        assert_eq!(sfa_file_count(dir.path()), 2);

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
    fn send_cursor_advances_between_segments_without_repositioning() {
        let dir = TempDir::new().unwrap();
        let mut queue = SfaFrameQueue::open(options_with(&dir, 38, 38 * 8, 4)).unwrap();
        submit_with_storage_maintenance(&mut queue, b"one");
        submit_with_storage_maintenance(&mut queue, b"two");
        submit_with_storage_maintenance(&mut queue, b"tri");
        submit_with_storage_maintenance(&mut queue, b"for");

        assert_eq!(queue.sealed_segments.len(), 3);

        assert_eq!(
            pending_payload_vec(queue.next_cursor_payload_for_fsn(0).unwrap().unwrap()),
            b"one"
        );
        assert_eq!(
            queue.send_cursor.unwrap().segment,
            SfaCursorSegment::Sealed(1)
        );
        assert_eq!(
            pending_payload_vec(queue.next_cursor_payload_for_fsn(1).unwrap().unwrap()),
            b"two"
        );
        assert_eq!(
            queue.send_cursor.unwrap().segment,
            SfaCursorSegment::Sealed(2)
        );
        assert_eq!(
            pending_payload_vec(queue.next_cursor_payload_for_fsn(2).unwrap().unwrap()),
            b"tri"
        );
        assert_eq!(queue.send_cursor.unwrap().segment, SfaCursorSegment::Active);
        assert_eq!(
            pending_payload_vec(queue.next_cursor_payload_for_fsn(3).unwrap().unwrap()),
            b"for"
        );
    }

    /// Run with:
    /// `cargo test --features sync-sender-qwp-ws --lib sfa_tiny_frame_publish_zero_alloc_after_warmup -- --ignored --test-threads=1`
    #[test]
    #[ignore = "uses the process-global allocation counter"]
    fn sfa_tiny_frame_publish_zero_alloc_after_warmup() {
        use crate::alloc_counter;

        let dir = TempDir::new().unwrap();
        let mut queue = SfaFrameQueue::open(options_with(&dir, 4096, 8192, 4)).unwrap();
        for _ in 0..4 {
            queue.try_submit(b"steady-state").unwrap();
        }

        alloc_counter::start_counting();
        let receipt = queue.try_submit(b"steady-state").unwrap();
        let alloc_count = alloc_counter::stop_counting();

        assert_eq!(receipt, QwpReceipt { fsn: 4 });
        assert_eq!(
            alloc_count, 0,
            "Expected zero allocations for warmed SFA tiny-frame publication, got {alloc_count}"
        );
    }

    #[test]
    fn rotation_uses_java_segment_names_and_recovers_in_fsn_order() {
        let dir = TempDir::new().unwrap();
        {
            let mut queue = SfaFrameQueue::open(options_with(&dir, 38, 1024, 4)).unwrap();
            assert_eq!(queue.try_submit(b"first").unwrap(), QwpReceipt { fsn: 0 });
            assert_eq!(queue.try_submit(b"second").unwrap(), QwpReceipt { fsn: 1 });
        }

        let first_path = initial_segment_path(dir.path());
        let second_path = spare_segment_path(dir.path(), 0);
        assert!(first_path.exists());
        assert!(second_path.exists());
        assert_eq!(scan_file(&first_path).unwrap().header.base_seq, 0);
        assert_eq!(scan_file(&second_path).unwrap().header.base_seq, 1);

        let recovered = SfaFrameQueue::open(options_with(&dir, 38, 1024, 4)).unwrap();
        assert_eq!(recovered.payload_for_fsn(0), Some(&b"first"[..]));
        assert_eq!(recovered.payload_for_fsn(1), Some(&b"second"[..]));
        assert_eq!(recovered.oldest_unresolved_fsn(), Some(0));
    }

    #[test]
    fn rotation_uses_prepared_hot_spare_and_respects_segment_cap() {
        let dir = TempDir::new().unwrap();
        let mut queue = SfaFrameQueue::open(options_with(&dir, 38, 76, 4)).unwrap();

        assert_eq!(sfa_file_count(dir.path()), 2);
        assert_eq!(queue.try_submit(b"first").unwrap(), QwpReceipt { fsn: 0 });
        assert_eq!(queue.try_submit(b"second").unwrap(), QwpReceipt { fsn: 1 });
        assert_eq!(sfa_file_count(dir.path()), 2);

        assert!(matches!(
            queue.try_submit(b"third"),
            Err(SfaQueueError::Queue(QueueError::StorageSegmentCapFull {
                segment_size_bytes: 38,
                allocated_segment_bytes: 76,
                max_total_bytes: 76,
            }))
        ));
    }

    #[test]
    fn progress_maintains_missing_hot_spare_when_capacity_allows() {
        let dir = TempDir::new().unwrap();
        let mut queue = SfaFrameQueue::open(options_with(&dir, 38, 114, 4)).unwrap();

        queue.try_submit(b"first").unwrap();
        queue.try_submit(b"second").unwrap();
        assert!(matches!(
            queue.try_submit(b"third"),
            Err(SfaQueueError::Queue(QueueError::StorageSpareNotReady {
                segment_size_bytes: 38,
                allocated_segment_bytes: 76,
                max_total_bytes: 114,
            }))
        ));

        assert!(queue.maintain_storage().unwrap());
        assert_eq!(queue.try_submit(b"third").unwrap(), QwpReceipt { fsn: 2 });
    }

    #[test]
    fn abandoned_hot_spare_after_close_does_not_change_capacity_or_leak_file() {
        let dir = TempDir::new().unwrap();
        let mut queue = SfaFrameQueue::open(options_with(&dir, 38, 114, 4)).unwrap();
        queue.try_submit(b"first").unwrap();
        queue.try_submit(b"second").unwrap();
        assert_eq!(sfa_file_count(dir.path()), 2);
        assert_eq!(queue.allocated_segment_bytes, 76);

        let step = queue.take_storage_maintenance_step(true).unwrap().unwrap();
        assert!(!step.changes_queue_before_io());
        let result = step.perform().unwrap();
        assert_eq!(sfa_file_count(dir.path()), 3);

        queue.close().unwrap();
        let finish = queue.finish_storage_maintenance(result, true).unwrap();
        assert!(!finish.did_change());
        assert_eq!(queue.allocated_segment_bytes, 76);

        let cleanup = finish
            .into_cleanup()
            .expect("created spare should be abandoned");
        assert!(cleanup.perform().is_none());
        assert_eq!(sfa_file_count(dir.path()), 2);
    }

    #[test]
    fn abandoned_hot_spare_after_lifecycle_change_does_not_change_capacity_or_leak_file() {
        let dir = TempDir::new().unwrap();
        let mut queue = SfaFrameQueue::open(options_with(&dir, 38, 114, 4)).unwrap();
        queue.try_submit(b"first").unwrap();
        queue.try_submit(b"second").unwrap();

        let step = queue.take_storage_maintenance_step(true).unwrap().unwrap();
        let result = step.perform().unwrap();
        let finish = queue.finish_storage_maintenance(result, false).unwrap();

        assert!(!finish.did_change());
        assert!(queue.hot_spare.is_none());
        assert_eq!(queue.allocated_segment_bytes, 76);
        let cleanup = finish
            .into_cleanup()
            .expect("created spare should be abandoned");
        assert!(cleanup.perform().is_none());
        assert_eq!(sfa_file_count(dir.path()), 2);
    }

    #[test]
    fn recovered_segments_above_cap_start_but_block_new_segments() {
        let dir = TempDir::new().unwrap();
        let mut first = SfaSegment::create(initial_segment_path(dir.path()), 0, 38, 0).unwrap();
        first.try_append(b"first").unwrap();
        drop(first);
        let mut second = SfaSegment::create(spare_segment_path(dir.path(), 0), 1, 38, 0).unwrap();
        second.try_append(b"second").unwrap();
        drop(second);

        let mut queue = SfaFrameQueue::open(options_with(&dir, 38, 38, 4)).unwrap();

        assert_eq!(queue.len(), 2);
        assert_eq!(queue.payload_for_fsn(0), Some(&b"first"[..]));
        assert_eq!(queue.payload_for_fsn(1), Some(&b"second"[..]));
        assert!(matches!(
            queue.try_submit(b"third"),
            Err(SfaQueueError::Queue(QueueError::StorageSegmentCapFull {
                segment_size_bytes: 38,
                allocated_segment_bytes: 76,
                max_total_bytes: 38,
            }))
        ));
    }

    #[test]
    fn cumulative_ack_trims_fully_acked_sealed_segments_but_keeps_active() {
        let dir = TempDir::new().unwrap();
        let first_path = initial_segment_path(dir.path());
        let second_path = spare_segment_path(dir.path(), 0);
        let mut queue = SfaFrameQueue::open(options_with(&dir, 38, 1024, 4)).unwrap();
        queue.try_submit(b"first").unwrap();
        queue.try_submit(b"second").unwrap();

        queue.complete_through_fsn(1).unwrap();
        assert!(queue.maintain_storage().unwrap());

        assert!(!first_path.exists());
        assert!(second_path.exists());
        assert_eq!(queue.completed_fsn(), Some(1));
    }

    #[test]
    fn drained_trim_keeps_existing_mapped_payload_alive() {
        let dir = TempDir::new().unwrap();
        let first_path = initial_segment_path(dir.path());
        let mut queue = SfaFrameQueue::open(options_with(&dir, 38, 1024, 4)).unwrap();
        queue.try_submit(b"first").unwrap();
        queue.try_submit(b"second").unwrap();
        let payload = queue.pending_payload_for_fsn(0).unwrap();

        queue.complete_through_fsn(1).unwrap();
        let step = queue.take_storage_maintenance_step(true).unwrap().unwrap();
        assert!(step.changes_queue_before_io());
        let result = step.perform().unwrap();
        let finish = queue.finish_storage_maintenance(result, true).unwrap();

        assert!(!first_path.exists());
        assert!(!finish.did_change());
        payload.with_bytes(|bytes| assert_eq!(bytes, b"first"));
    }

    #[cfg(unix)]
    #[test]
    fn acked_segment_cleanup_failure_frees_logical_capacity() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let first_path = initial_segment_path(dir.path());
        let mut queue = SfaFrameQueue::open(options_with(&dir, 38, 76, 4)).unwrap();
        queue.try_submit(b"first").unwrap();
        queue.try_submit(b"second").unwrap();
        queue.complete_through_fsn(1).unwrap();

        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o500)).unwrap();
        let cleanup_result = queue.maintain_storage();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();

        assert!(cleanup_result.unwrap());
        assert!(first_path.exists());
        assert!(queue.recovery_diagnostics().iter().any(|diagnostic| {
            matches!(
                diagnostic,
                SfaRecoveryDiagnostic::CleanupFailed { path, .. } if path == &first_path
            )
        }));
        assert!(matches!(
            queue.try_submit(b"third"),
            Err(SfaQueueError::Queue(QueueError::StorageSpareNotReady {
                allocated_segment_bytes: 38,
                ..
            }))
        ));
        assert!(queue.maintain_storage().unwrap());
        assert_eq!(queue.try_submit(b"third").unwrap(), QwpReceipt { fsn: 2 });
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

        assert_eq!(sfa_file_count(dir.path()), 2);
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
