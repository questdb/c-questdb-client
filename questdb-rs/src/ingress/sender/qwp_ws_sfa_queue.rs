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
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use memmap2::{MmapMut, MmapOptions};

use crate::error;

use super::qwp_ws_driver::{DriverError, PublicationLog, SendCursor};
use super::qwp_ws_queue::{
    OutboundFrame, PendingPayload, QueueError, QwpReceipt, QwpReceiptStatus,
};
use super::qwp_ws_sfa_segment::{
    FRAME_HEADER_SIZE, HEADER_SIZE, INITIAL_SEGMENT_FILE_NAME, SfaMappedPayload, SfaSegment,
    SfaSegmentError, scan_file_metadata, spare_segment_path,
};

const ACK_WATERMARK_FILE_NAME: &str = ".ack-watermark";
const ACK_WATERMARK_MAGIC: u32 = 0x3157_4b41; // 'AKW1' in little-endian bytes.
const ACK_WATERMARK_SIZE: u64 = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SfaQueueOptions {
    pub(crate) slot_dir: PathBuf,
    pub(crate) segment_size_bytes: u64,
    pub(crate) max_bytes: usize,
    pub(crate) max_in_flight: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SfaMemoryQueueOptions {
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
        path: Option<PathBuf>,
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
    segment: Arc<SfaSharedSegment>,
    path: Option<PathBuf>,
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
                let segment = match path {
                    Some(path) => SfaSegment::create_new(&path, base_seq, size_bytes, created_us)?,
                    None => SfaSegment::create_memory(base_seq, size_bytes, created_us)?,
                };
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
    fn new(segment: Arc<SfaSharedSegment>) -> Self {
        let path = segment.path().map(Path::to_path_buf);
        Self { segment, path }
    }

    pub(crate) fn perform(self) -> Option<SfaCleanupFailure> {
        let path = self.path;
        drop(self.segment);
        let path = path?;
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
    engine: Arc<SfaEngine>,
    producer: Option<SfaProducer>,
    send_cursor: Option<SfaSendCursor>,
    ack_watermark: Option<SfaAckWatermark>,
}

#[derive(Debug)]
pub(crate) struct SfaProducer {
    engine: Arc<SfaEngine>,
    active: Arc<SfaSharedSegment>,
    active_append_offset: u64,
    active_frame_count: u64,
    next_fsn: u64,
}

#[derive(Debug)]
struct SfaEngine {
    slot_dir: Option<PathBuf>,
    max_bytes: usize,
    segment_size_bytes: u64,
    max_in_flight: usize,
    allow_segment_creation: bool,
    state: Mutex<SfaEngineState>,
    published_upper: AtomicU64,
    completed_upper: AtomicU64,
}

#[derive(Debug)]
struct SfaEngineState {
    active: Option<Arc<SfaSharedSegment>>,
    sealed_segments: VecDeque<Arc<SfaSharedSegment>>,
    hot_spare: Option<Arc<SfaSharedSegment>>,
    allocated_segment_bytes: u64,
    recovery_diagnostics: Vec<SfaRecoveryDiagnostic>,
    next_generation: u64,
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
                    validate_publishable_segment_capacity(
                        options.segment_size_bytes,
                        options.max_bytes,
                    )?;
                    let mut next_generation = scan_next_generation(&options.slot_dir)?;
                    let active_path = next_segment_path(&options.slot_dir, &mut next_generation)?;
                    (
                        SfaSegment::create_new(
                            &active_path,
                            0,
                            options.segment_size_bytes,
                            unix_time_micros(),
                        )?,
                        VecDeque::new(),
                        0,
                        next_generation,
                        options.segment_size_bytes,
                    )
                }
            };
        let active = Arc::new(SfaSharedSegment::new(active));
        let sealed_segments = sealed_segments
            .into_iter()
            .map(SfaSharedSegment::new)
            .map(Arc::new)
            .collect();
        let mut hot_spare = None;
        let mut next_generation = next_generation;
        if can_allocate_segment(
            allocated_segment_bytes,
            options.segment_size_bytes,
            options.max_bytes,
        ) {
            let path = next_segment_path(&options.slot_dir, &mut next_generation)?;
            hot_spare = Some(Arc::new(SfaSharedSegment::new(SfaSegment::create_new(
                &path,
                next_fsn,
                options.segment_size_bytes,
                unix_time_micros(),
            )?)));
            allocated_segment_bytes = allocated_segment_bytes
                .checked_add(options.segment_size_bytes)
                .ok_or(QueueError::SequenceOverflow)?;
        }

        let first_unresolved =
            first_unresolved_fsn_from_segments(&sealed_segments, &active).unwrap_or(next_fsn);
        let recovered_completion =
            recover_completed_upper(Some(&options.slot_dir), first_unresolved, next_fsn);
        let active_append_offset = active.published_offset();
        let active_frame_count = active.published_frame_count();
        let engine = Arc::new(SfaEngine {
            slot_dir: Some(options.slot_dir),
            max_bytes: options.max_bytes,
            segment_size_bytes: options.segment_size_bytes,
            max_in_flight: options.max_in_flight,
            allow_segment_creation: true,
            state: Mutex::new(SfaEngineState {
                active: Some(Arc::clone(&active)),
                sealed_segments,
                hot_spare,
                allocated_segment_bytes,
                recovery_diagnostics,
                next_generation,
                closed: false,
            }),
            published_upper: AtomicU64::new(next_fsn),
            completed_upper: AtomicU64::new(recovered_completion.completed_upper),
        });
        let producer = Some(SfaProducer {
            engine: Arc::clone(&engine),
            active,
            active_append_offset,
            active_frame_count,
            next_fsn,
        });

        Ok(Self {
            engine,
            producer,
            send_cursor: None,
            ack_watermark: recovered_completion.ack_watermark,
        })
    }

    pub(crate) fn open_memory(options: SfaMemoryQueueOptions) -> Result<Self, SfaQueueError> {
        validate_memory_options(&options)?;

        let active = Arc::new(SfaSharedSegment::new(SfaSegment::create_memory(
            0,
            options.segment_size_bytes,
            unix_time_micros(),
        )?));
        let next_fsn = 0;
        let mut allocated_segment_bytes = options.segment_size_bytes;
        let mut hot_spare = None;
        let mut next_generation = 0u64;
        if can_allocate_segment(
            allocated_segment_bytes,
            options.segment_size_bytes,
            options.max_bytes,
        ) {
            next_generation = next_generation
                .checked_add(1)
                .ok_or(QueueError::SequenceOverflow)?;
            hot_spare = Some(Arc::new(SfaSharedSegment::new(SfaSegment::create_memory(
                next_fsn,
                options.segment_size_bytes,
                unix_time_micros(),
            )?)));
            allocated_segment_bytes = allocated_segment_bytes
                .checked_add(options.segment_size_bytes)
                .ok_or(QueueError::SequenceOverflow)?;
        }

        let engine = Arc::new(SfaEngine {
            slot_dir: None,
            max_bytes: options.max_bytes,
            segment_size_bytes: options.segment_size_bytes,
            max_in_flight: options.max_in_flight,
            allow_segment_creation: true,
            state: Mutex::new(SfaEngineState {
                active: Some(Arc::clone(&active)),
                sealed_segments: VecDeque::new(),
                hot_spare,
                allocated_segment_bytes,
                recovery_diagnostics: Vec::new(),
                next_generation,
                closed: false,
            }),
            published_upper: AtomicU64::new(next_fsn),
            completed_upper: AtomicU64::new(next_fsn),
        });
        let producer = Some(SfaProducer {
            engine: Arc::clone(&engine),
            active,
            active_append_offset: HEADER_SIZE as u64,
            active_frame_count: 0,
            next_fsn,
        });

        Ok(Self {
            engine,
            producer,
            send_cursor: None,
            ack_watermark: None,
        })
    }

    pub(crate) fn open_replay_only(options: SfaQueueOptions) -> Result<Self, SfaQueueError> {
        validate_options(&options)?;
        let recovered = recover_segments(&options)?;
        if recovered.segments.is_none() && recovered.has_skipped_segments() {
            return Err(SfaQueueError::CorruptSegments {
                reason: "replay-only recovery found only skipped SFA segments",
            });
        }
        let recovery_diagnostics = recovered.diagnostics;
        let (active, sealed_segments, next_fsn, allocated_segment_bytes) = match recovered.segments
        {
            Some(segments) => (
                Some(Arc::new(SfaSharedSegment::new(segments.active))),
                segments
                    .sealed_segments
                    .into_iter()
                    .map(SfaSharedSegment::new)
                    .map(Arc::new)
                    .collect(),
                segments.next_fsn,
                segments.allocated_segment_bytes,
            ),
            None => (None, VecDeque::new(), 0, 0),
        };
        let first_unresolved =
            first_unresolved_fsn_from_optional_segments(&sealed_segments, active.as_ref())
                .unwrap_or(next_fsn);
        let recovered_completion =
            recover_completed_upper(Some(&options.slot_dir), first_unresolved, next_fsn);
        let engine = Arc::new(SfaEngine {
            slot_dir: Some(options.slot_dir),
            max_bytes: options.max_bytes,
            segment_size_bytes: options.segment_size_bytes,
            max_in_flight: options.max_in_flight,
            allow_segment_creation: false,
            state: Mutex::new(SfaEngineState {
                active,
                sealed_segments,
                hot_spare: None,
                allocated_segment_bytes,
                recovery_diagnostics,
                next_generation: 0,
                closed: false,
            }),
            published_upper: AtomicU64::new(next_fsn),
            completed_upper: AtomicU64::new(recovered_completion.completed_upper),
        });

        Ok(Self {
            engine,
            producer: None,
            send_cursor: None,
            ack_watermark: recovered_completion.ack_watermark,
        })
    }

    pub(crate) fn close(&mut self) -> Result<(), SfaQueueError> {
        self.producer.take();
        self.ack_watermark.take();
        self.engine.close()
    }

    pub(crate) fn try_submit(&mut self, payload: &[u8]) -> Result<QwpReceipt, SfaQueueError> {
        let Some(producer) = self.producer.as_mut() else {
            return Err(SfaQueueError::Closed);
        };
        producer.try_submit(payload)
    }

    pub(crate) fn take_producer(&mut self) -> Option<SfaProducer> {
        self.producer.take()
    }

    pub(crate) fn complete_through_fsn(&mut self, acked_fsn: u64) -> Result<(), SfaQueueError> {
        let before = self.engine.completed_upper.load(Ordering::Acquire);
        self.engine.complete_through_fsn(acked_fsn)?;
        let after = self.engine.completed_upper.load(Ordering::Acquire);
        if after > before
            && let Some(ack_watermark) = self.ack_watermark.as_mut()
        {
            ack_watermark.persist_completed_fsn(acked_fsn);
        }
        Ok(())
    }

    pub(crate) fn receipt_status(&self, receipt: QwpReceipt) -> QwpReceiptStatus {
        self.engine.receipt_status(receipt)
    }

    #[cfg(test)]
    fn payload_vec_for_fsn(&self, fsn: u64) -> Option<Vec<u8>> {
        self.engine
            .segment_for_fsn(fsn)
            .and_then(|segment| segment.payload_for_fsn(fsn))
            .map(|payload| payload.with_bytes(|bytes| bytes.to_vec()))
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
        self.engine.take_storage_maintenance_step(allow_create)
    }

    pub(crate) fn finish_storage_maintenance(
        &mut self,
        result: SfaStorageResult,
        allow_install: bool,
    ) -> Result<SfaStorageFinish, SfaQueueError> {
        self.engine
            .finish_storage_maintenance(result, allow_install)
    }

    pub(crate) fn record_cleanup_failure(&mut self, failure: SfaCleanupFailure) {
        self.engine.record_cleanup_failure(failure);
    }

    pub(crate) fn oldest_unresolved_fsn(&self) -> Option<u64> {
        self.engine.oldest_unresolved_fsn()
    }

    pub(crate) fn len(&self) -> usize {
        self.engine.len()
    }

    pub(crate) fn bytes_used(&self) -> usize {
        0
    }

    pub(crate) fn published_fsn(&self) -> Option<u64> {
        self.engine.published_fsn()
    }

    pub(crate) fn completed_fsn(&self) -> Option<u64> {
        self.engine.completed_fsn()
    }

    pub(crate) fn max_in_flight(&self) -> usize {
        self.engine.max_in_flight()
    }

    pub(crate) fn recovery_diagnostics(&self) -> Vec<SfaRecoveryDiagnostic> {
        self.engine.recovery_diagnostics()
    }

    fn next_cursor_payload_for_fsn(
        &mut self,
        fsn: u64,
    ) -> Result<Option<PendingPayload>, SfaQueueError> {
        let Some(mut cursor) = self
            .reusable_send_cursor(fsn)
            .or_else(|| self.position_send_cursor_for_fsn(fsn))
        else {
            self.send_cursor = None;
            return Ok(None);
        };

        let (payload, segment_append_offset) = match payload_at_send_cursor(&cursor) {
            Some(payload) => payload,
            None => {
                self.send_cursor = None;
                let Some(repositioned) = self.position_send_cursor_for_fsn(fsn) else {
                    return Ok(None);
                };
                cursor = repositioned;
                let Some(payload) = payload_at_send_cursor(&cursor) else {
                    self.send_cursor = None;
                    return Ok(None);
                };
                payload
            }
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
        let cursor = self.send_cursor.clone()?;
        if cursor.fsn != fsn {
            return None;
        }
        Some(cursor)
    }

    fn position_send_cursor_for_fsn(&self, fsn: u64) -> Option<SfaSendCursor> {
        let segment = self.engine.segment_for_fsn(fsn)?;
        let offset = segment.frame_offset_for_fsn(fsn)?;
        Some(SfaSendCursor {
            fsn,
            segment,
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
            && let Some(next_segment) = self.engine.next_segment_after(&cursor.segment)
            && next_segment.base_seq() == next_fsn
        {
            return SfaSendCursor {
                fsn: next_fsn,
                segment: next_segment,
                offset: HEADER_SIZE as u64,
            };
        }

        SfaSendCursor {
            fsn: next_fsn,
            offset: next_offset,
            ..cursor
        }
    }

    #[cfg(test)]
    fn sealed_segment_count(&self) -> usize {
        self.engine.segments_snapshot().sealed_segments.len()
    }

    #[cfg(test)]
    fn allocated_segment_bytes(&self) -> u64 {
        self.engine
            .with_state(|state| state.allocated_segment_bytes)
    }

    #[cfg(test)]
    fn hot_spare_installed(&self) -> bool {
        self.engine.with_state(|state| state.hot_spare.is_some())
    }

    #[cfg(test)]
    fn send_cursor_segment_base_seq(&self) -> Option<u64> {
        self.send_cursor
            .as_ref()
            .map(|cursor| cursor.segment.base_seq())
    }
}

impl SfaProducer {
    pub(crate) fn try_submit(&mut self, payload: &[u8]) -> Result<QwpReceipt, SfaQueueError> {
        self.engine.validate_submit(payload)?;
        let fsn = self.next_fsn;
        let next_fsn = fsn.checked_add(1).ok_or(QueueError::SequenceOverflow)?;
        if self.append_to_active(payload)? {
            self.publish(next_fsn);
            return Ok(QwpReceipt { fsn });
        }

        self.rotate_active()?;
        if self.append_to_active(payload)? {
            self.publish(next_fsn);
            Ok(QwpReceipt { fsn })
        } else {
            Err(QueueError::PayloadExceedsByteCapacity {
                payload_len: payload.len(),
                max_bytes: self.engine.segment_payload_capacity(),
            }
            .into())
        }
    }

    fn append_to_active(&mut self, payload: &[u8]) -> Result<bool, SfaQueueError> {
        let Some(appended) = self
            .active
            .try_append_at(self.active_append_offset, payload)?
        else {
            return Ok(false);
        };
        self.active_append_offset = appended.frame_end;
        self.active_frame_count = self
            .active_frame_count
            .checked_add(1)
            .ok_or(QueueError::SequenceOverflow)?;
        self.active
            .publish(self.active_append_offset, self.active_frame_count);
        Ok(true)
    }

    fn publish(&mut self, next_fsn: u64) {
        self.next_fsn = next_fsn;
        self.engine
            .published_upper
            .store(next_fsn, Ordering::Release);
    }

    fn rotate_active(&mut self) -> Result<(), SfaQueueError> {
        if self.active_frame_count == 0 {
            return Err(SfaQueueError::CorruptSegments {
                reason: "active segment filled before any frame was appended",
            });
        }

        let mut state = self.engine.lock_state()?;
        let active = state.active.as_ref().ok_or(SfaQueueError::Closed)?;
        if !Arc::ptr_eq(active, &self.active) {
            return Err(SfaQueueError::CorruptSegments {
                reason: "producer active segment is not the engine active segment",
            });
        }
        let Some(mut new_active) = state.hot_spare.take() else {
            return Err(self.engine.storage_backpressure_error(&state).into());
        };
        if let Some(shared) = Arc::get_mut(&mut new_active) {
            shared.rebase_empty(self.next_fsn)?;
        } else {
            state.hot_spare = Some(new_active);
            return Err(SfaQueueError::CorruptSegments {
                reason: "hot spare segment is shared before promotion",
            });
        }

        let old_active = state.active.replace(Arc::clone(&new_active)).unwrap();
        state.sealed_segments.push_back(old_active);
        drop(state);

        self.active = new_active;
        self.active_append_offset = HEADER_SIZE as u64;
        self.active_frame_count = 0;
        Ok(())
    }
}

#[derive(Debug)]
struct SfaSegmentsSnapshot {
    sealed_segments: Vec<Arc<SfaSharedSegment>>,
    active: Option<Arc<SfaSharedSegment>>,
}

impl SfaEngine {
    fn close(&self) -> Result<(), SfaQueueError> {
        let fully_drained = self.all_published_frames_resolved();
        let mut state = self.lock_state()?;
        if state.closed {
            return Ok(());
        }
        state.sealed_segments.clear();
        state.hot_spare.take();
        state.active.take();
        state.closed = true;

        if fully_drained && let Some(slot_dir) = self.slot_dir.as_deref() {
            record_all_sfa_cleanup(slot_dir, &mut state.recovery_diagnostics)?;
        }
        Ok(())
    }

    fn validate_submit(&self, payload: &[u8]) -> Result<(), QueueError> {
        if payload.is_empty() {
            return Err(QueueError::EmptyPayload);
        }
        let completed = self.completed_upper.load(Ordering::Acquire);
        let published = self.published_upper.load(Ordering::Acquire);
        if published.saturating_sub(completed) >= self.max_in_flight as u64 {
            return Err(QueueError::MaxInFlightReached {
                max_in_flight: self.max_in_flight,
            });
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

    fn complete_through_fsn(&self, acked_fsn: u64) -> Result<(), SfaQueueError> {
        let target_upper = acked_fsn
            .checked_add(1)
            .ok_or(QueueError::ProtocolAckedUnsentFrame { fsn: acked_fsn })?;
        let completed = self.completed_upper.load(Ordering::Acquire);
        if target_upper <= completed {
            return Ok(());
        }
        let published = self.published_upper.load(Ordering::Acquire);
        if target_upper > published {
            return Err(QueueError::ProtocolAckedUnsentFrame { fsn: acked_fsn }.into());
        }
        self.completed_upper.store(target_upper, Ordering::Release);
        Ok(())
    }

    fn receipt_status(&self, receipt: QwpReceipt) -> QwpReceiptStatus {
        let fsn = receipt.fsn;
        if fsn < self.completed_upper.load(Ordering::Acquire) {
            return QwpReceiptStatus::Completed { fsn };
        }
        if fsn >= self.published_upper.load(Ordering::Acquire) {
            return QwpReceiptStatus::Unknown { fsn };
        }
        QwpReceiptStatus::Published { fsn }
    }

    fn segment_for_fsn(&self, fsn: u64) -> Option<Arc<SfaSharedSegment>> {
        self.with_state(|state| {
            state
                .sealed_segments
                .iter()
                .chain(state.active.iter())
                .find(|segment| {
                    fsn >= segment.base_seq()
                        && segment.last_fsn().is_some_and(|last_fsn| fsn <= last_fsn)
                })
                .cloned()
        })
    }

    fn next_segment_after(&self, current: &Arc<SfaSharedSegment>) -> Option<Arc<SfaSharedSegment>> {
        let current_base_seq = current.base_seq();
        self.with_state(|state| {
            if state
                .active
                .as_ref()
                .is_some_and(|active| Arc::ptr_eq(active, current))
            {
                return None;
            }
            state
                .sealed_segments
                .iter()
                .find(|segment| segment.base_seq() > current_base_seq)
                .cloned()
                .or_else(|| {
                    state
                        .active
                        .as_ref()
                        .filter(|segment| segment.base_seq() > current_base_seq)
                        .cloned()
                })
        })
    }

    fn take_storage_maintenance_step(
        &self,
        allow_create: bool,
    ) -> Result<Option<SfaStorageStep>, SfaQueueError> {
        let mut state = self.lock_state()?;
        if state.closed {
            return Ok(None);
        }
        if let Some(step) = self.take_one_acked_sealed_segment(&mut state)? {
            return Ok(Some(step));
        }
        if !allow_create || !self.allow_segment_creation || state.hot_spare.is_some() {
            return Ok(None);
        }
        if !can_allocate_segment(
            state.allocated_segment_bytes,
            self.segment_size_bytes,
            self.max_bytes,
        ) {
            return Ok(None);
        }
        let path = match self.slot_dir.as_deref() {
            Some(slot_dir) => Some(next_segment_path(slot_dir, &mut state.next_generation)?),
            None => {
                state.next_generation = state
                    .next_generation
                    .checked_add(1)
                    .ok_or(QueueError::SequenceOverflow)?;
                None
            }
        };
        Ok(Some(SfaStorageStep::CreateHotSpare {
            path,
            base_seq: self.published_upper.load(Ordering::Acquire),
            size_bytes: self.segment_size_bytes,
            created_us: unix_time_micros(),
        }))
    }

    fn finish_storage_maintenance(
        &self,
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
                let segment = Arc::new(SfaSharedSegment::new(segment));
                let mut state = self.lock_state()?;
                if allow_install
                    && self.allow_segment_creation
                    && !state.closed
                    && state.hot_spare.is_none()
                    && segment.published_frame_count() == 0
                    && segment.size_bytes() == self.segment_size_bytes
                    && can_allocate_segment(
                        state.allocated_segment_bytes,
                        self.segment_size_bytes,
                        self.max_bytes,
                    )
                {
                    state.allocated_segment_bytes = state
                        .allocated_segment_bytes
                        .checked_add(self.segment_size_bytes)
                        .ok_or(QueueError::SequenceOverflow)?;
                    state.hot_spare = Some(segment);
                    Ok(SfaStorageFinish::changed())
                } else {
                    Ok(SfaStorageFinish::cleanup(SfaStorageCleanup::new(segment)))
                }
            }
        }
    }

    fn record_cleanup_failure(&self, failure: SfaCleanupFailure) {
        if let Ok(mut state) = self.state.lock() {
            state
                .recovery_diagnostics
                .push(SfaRecoveryDiagnostic::CleanupFailed {
                    path: failure.path,
                    error: failure.error,
                });
        }
    }

    fn oldest_unresolved_fsn(&self) -> Option<u64> {
        let completed = self.completed_upper.load(Ordering::Acquire);
        let published = self.published_upper.load(Ordering::Acquire);
        (completed < published).then_some(completed)
    }

    fn len(&self) -> usize {
        let completed = self.completed_upper.load(Ordering::Acquire);
        let published = self.published_upper.load(Ordering::Acquire);
        if completed >= published {
            return 0;
        }
        usize::try_from(published - completed).unwrap_or(usize::MAX)
    }

    fn published_fsn(&self) -> Option<u64> {
        self.published_upper.load(Ordering::Acquire).checked_sub(1)
    }

    fn completed_fsn(&self) -> Option<u64> {
        self.completed_upper.load(Ordering::Acquire).checked_sub(1)
    }

    fn max_in_flight(&self) -> usize {
        self.max_in_flight
    }

    fn recovery_diagnostics(&self) -> Vec<SfaRecoveryDiagnostic> {
        self.with_state(|state| state.recovery_diagnostics.clone())
    }

    fn segment_payload_capacity(&self) -> usize {
        segment_payload_capacity(self.segment_size_bytes)
    }

    fn storage_backpressure_error(&self, state: &SfaEngineState) -> QueueError {
        if can_allocate_segment(
            state.allocated_segment_bytes,
            self.segment_size_bytes,
            self.max_bytes,
        ) {
            QueueError::StorageSpareNotReady {
                segment_size_bytes: self.segment_size_bytes,
                allocated_segment_bytes: state.allocated_segment_bytes,
                max_total_bytes: self.max_bytes as u64,
            }
        } else {
            QueueError::StorageSegmentCapFull {
                segment_size_bytes: self.segment_size_bytes,
                allocated_segment_bytes: state.allocated_segment_bytes,
                max_total_bytes: self.max_bytes as u64,
            }
        }
    }

    fn take_one_acked_sealed_segment(
        &self,
        state: &mut SfaEngineState,
    ) -> Result<Option<SfaStorageStep>, SfaQueueError> {
        let Some(acked_fsn) = self.completed_fsn() else {
            return Ok(None);
        };
        let Some(segment) = state.sealed_segments.front() else {
            return Ok(None);
        };
        let last_fsn = segment.last_fsn().ok_or(SfaQueueError::CorruptSegments {
            reason: "sealed segment has no frames",
        })?;
        if last_fsn > acked_fsn {
            return Ok(None);
        }
        let segment = state.sealed_segments.pop_front().unwrap();
        state.allocated_segment_bytes = state
            .allocated_segment_bytes
            .saturating_sub(segment.size_bytes());
        Ok(Some(SfaStorageStep::Trim(SfaStorageCleanup::new(segment))))
    }

    fn all_published_frames_resolved(&self) -> bool {
        let published = self.published_upper.load(Ordering::Acquire);
        let completed = self.completed_upper.load(Ordering::Acquire);
        completed >= published
    }

    fn is_unresolved_fsn(&self, fsn: u64) -> bool {
        let completed = self.completed_upper.load(Ordering::Acquire);
        let published = self.published_upper.load(Ordering::Acquire);
        fsn >= completed && fsn < published
    }

    fn segments_snapshot(&self) -> SfaSegmentsSnapshot {
        self.with_state(|state| SfaSegmentsSnapshot {
            sealed_segments: state.sealed_segments.iter().cloned().collect(),
            active: state.active.as_ref().cloned(),
        })
    }

    fn with_state<R>(&self, f: impl FnOnce(&SfaEngineState) -> R) -> R {
        match self.state.lock() {
            Ok(state) => f(&state),
            Err(poisoned) => f(&poisoned.into_inner()),
        }
    }

    fn lock_state(&self) -> Result<std::sync::MutexGuard<'_, SfaEngineState>, SfaQueueError> {
        self.state.lock().map_err(|_| SfaQueueError::Closed)
    }
}

#[derive(Debug)]
struct SfaSharedSegment {
    segment: SfaSegment,
    published_offset: AtomicU64,
    published_frame_count: AtomicU64,
}

impl SfaSharedSegment {
    fn new(segment: SfaSegment) -> Self {
        Self {
            published_offset: AtomicU64::new(segment.append_offset()),
            published_frame_count: AtomicU64::new(segment.frame_count()),
            segment,
        }
    }

    fn try_append_at(
        &self,
        append_offset: u64,
        payload: &[u8],
    ) -> Result<Option<super::qwp_ws_sfa_segment::SfaAppend>, SfaSegmentError> {
        self.segment.try_append_at(append_offset, payload)
    }

    fn publish(&self, append_offset: u64, frame_count: u64) {
        // `published_offset` is the canonical byte-visibility barrier for the
        // segment. The producer writes length, payload, and CRC first, then
        // stores this offset with `Release`; readers `Acquire` it before
        // interpreting bytes below the cursor.
        self.published_frame_count
            .store(frame_count, Ordering::Relaxed);
        self.published_offset
            .store(append_offset, Ordering::Release);
    }

    fn rebase_empty(&mut self, base_seq: u64) -> Result<(), SfaSegmentError> {
        self.segment.rebase_empty(base_seq)?;
        self.published_frame_count.store(0, Ordering::Relaxed);
        self.published_offset
            .store(HEADER_SIZE as u64, Ordering::Release);
        Ok(())
    }

    fn payload_for_fsn(&self, fsn: u64) -> Option<SfaMappedPayload> {
        let published_offset = self.published_offset();
        let frame_count = self.published_frame_count_after_offset();
        let offset =
            self.segment
                .frame_offset_for_fsn_with_limit(fsn, frame_count, published_offset)?;
        self.segment
            .mapped_payload_at_offset_with_limit(offset, published_offset)
    }

    fn mapped_payload_at_offset(&self, offset: u64) -> Option<SfaMappedPayload> {
        let published_offset = self.published_offset();
        self.segment
            .mapped_payload_at_offset_with_limit(offset, published_offset)
    }

    fn frame_offset_for_fsn(&self, fsn: u64) -> Option<u64> {
        let published_offset = self.published_offset();
        let frame_count = self.published_frame_count_after_offset();
        self.segment
            .frame_offset_for_fsn_with_limit(fsn, frame_count, published_offset)
    }

    fn last_fsn(&self) -> Option<u64> {
        self.published_frame_count_after_offset()
            .checked_sub(1)
            .and_then(|last_index| self.base_seq().checked_add(last_index))
    }

    fn path(&self) -> Option<&Path> {
        self.segment.path()
    }

    fn base_seq(&self) -> u64 {
        self.segment.header().base_seq
    }

    fn published_offset(&self) -> u64 {
        self.published_offset.load(Ordering::Acquire)
    }

    fn published_frame_count(&self) -> u64 {
        self.published_frame_count.load(Ordering::Acquire)
    }

    fn published_frame_count_after_offset(&self) -> u64 {
        let _ = self.published_offset();
        self.published_frame_count()
    }

    fn size_bytes(&self) -> u64 {
        self.segment.size_bytes()
    }
}

impl PublicationLog for SfaFrameQueue {
    fn try_publish(&mut self, payload: &[u8]) -> Result<QwpReceipt, DriverError> {
        Ok(SfaFrameQueue::try_submit(self, payload)?)
    }

    fn take_producer(&mut self) -> Option<SfaProducer> {
        SfaFrameQueue::take_producer(self)
    }

    fn next_outbound_frame(
        &mut self,
        send_cursor: &mut SendCursor,
    ) -> Result<Option<OutboundFrame>, DriverError> {
        SfaFrameQueue::next_outbound_frame(self, send_cursor)
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

impl RecoveredState {
    fn has_skipped_segments(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|diagnostic| matches!(diagnostic, SfaRecoveryDiagnostic::SkippedSegment { .. }))
    }
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

#[derive(Debug, Clone)]
struct SfaSendCursor {
    fsn: u64,
    offset: u64,
    segment: Arc<SfaSharedSegment>,
}

#[derive(Debug)]
struct RecoveredCompletion {
    completed_upper: u64,
    ack_watermark: Option<SfaAckWatermark>,
}

struct SfaAckWatermark {
    _file: File,
    mmap: MmapMut,
    valid: bool,
}

impl std::fmt::Debug for SfaAckWatermark {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SfaAckWatermark").finish_non_exhaustive()
    }
}

impl SfaAckWatermark {
    fn open(slot_dir: &Path) -> Option<Self> {
        let path = ack_watermark_path(slot_dir);
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)
            .ok()?;
        if file.metadata().ok()?.len() < ACK_WATERMARK_SIZE
            && file.set_len(ACK_WATERMARK_SIZE).is_err()
        {
            return None;
        }
        // SAFETY: the SFA slot lock gives this process exclusive write access
        // to the slot. The queue reads and writes only the first fixed-size
        // watermark record.
        let mmap = unsafe {
            MmapOptions::new()
                .len(ACK_WATERMARK_SIZE as usize)
                .map_mut(&file)
                .ok()?
        };
        let valid = decode_ack_watermark(&mmap).is_some();
        Some(Self {
            _file: file,
            mmap,
            valid,
        })
    }

    fn recovered_fsn(&self) -> Option<u64> {
        decode_ack_watermark(&self.mmap)
    }

    fn invalidate(&mut self) {
        self.store_u32(0, 0);
        self.valid = false;
    }

    fn persist_completed_fsn(&mut self, fsn: u64) {
        let Ok(fsn) = i64::try_from(fsn) else {
            return;
        };
        self.store_fsn(fsn);
        if !self.valid {
            self.store_u32(4, 0);
            self.store_u32(0, ACK_WATERMARK_MAGIC);
            self.valid = true;
        }
    }

    fn store_fsn(&mut self, fsn: i64) {
        let ptr = unsafe { self.mmap.as_mut_ptr().add(8).cast::<i64>() };
        debug_assert_eq!((ptr as usize) % std::mem::align_of::<AtomicI64>(), 0);
        // SAFETY: the mmap covers at least ACK_WATERMARK_SIZE bytes, offset 8
        // is 8-byte aligned because mmap mappings are page-aligned, and slot
        // locking gives this process exclusive write access.
        unsafe { AtomicI64::from_ptr(ptr).store(fsn.to_le(), Ordering::Relaxed) };
    }

    fn store_u32(&mut self, offset: usize, value: u32) {
        let ptr = unsafe { self.mmap.as_mut_ptr().add(offset).cast::<u32>() };
        debug_assert_eq!((ptr as usize) % std::mem::align_of::<AtomicU32>(), 0);
        // SAFETY: callers pass fixed 4-byte-aligned offsets within the
        // watermark record, and slot locking gives exclusive write access.
        unsafe { AtomicU32::from_ptr(ptr).store(value.to_le(), Ordering::Release) };
    }
}

fn recover_completed_upper(
    slot_dir: Option<&Path>,
    segment_completed_upper: u64,
    published_upper: u64,
) -> RecoveredCompletion {
    let Some(slot_dir) = slot_dir else {
        return RecoveredCompletion {
            completed_upper: segment_completed_upper,
            ack_watermark: None,
        };
    };
    let mut ack_watermark = SfaAckWatermark::open(slot_dir);
    let completed_upper = if let Some(ack_watermark) = ack_watermark.as_mut() {
        match ack_watermark.recovered_fsn() {
            Some(acked_fsn) => match ack_watermark_completed_upper(acked_fsn, published_upper) {
                Some(upper) => segment_completed_upper.max(upper),
                None => {
                    ack_watermark.invalidate();
                    segment_completed_upper
                }
            },
            None => segment_completed_upper,
        }
    } else {
        segment_completed_upper
    };
    RecoveredCompletion {
        completed_upper,
        ack_watermark,
    }
}

fn decode_ack_watermark(bytes: &[u8]) -> Option<u64> {
    if bytes.len() < ACK_WATERMARK_SIZE as usize {
        return None;
    }
    let magic = read_ack_u32(bytes, 0);
    let reserved = read_ack_u32(bytes, 4);
    let fsn = read_ack_i64(bytes, 8);
    if magic != ACK_WATERMARK_MAGIC || reserved != 0 || fsn < 0 {
        return None;
    }
    Some(fsn as u64)
}

fn ack_watermark_completed_upper(acked_fsn: u64, published_upper: u64) -> Option<u64> {
    let published_fsn = published_upper.checked_sub(1)?;
    if acked_fsn > published_fsn {
        return None;
    }
    acked_fsn.checked_add(1)
}

fn read_ack_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_ack_i64(bytes: &[u8], offset: usize) -> i64 {
    i64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn ack_watermark_path(slot_dir: &Path) -> PathBuf {
    slot_dir.join(ACK_WATERMARK_FILE_NAME)
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

fn validate_memory_options(options: &SfaMemoryQueueOptions) -> Result<(), SfaQueueError> {
    if options.max_bytes == 0 || options.max_in_flight == 0 {
        return Err(QueueError::InvalidCapacity.into());
    }
    if options.segment_size_bytes < (HEADER_SIZE + FRAME_HEADER_SIZE + 1) as u64 {
        return Err(SfaSegmentError::SizeTooSmall {
            size: options.segment_size_bytes,
        }
        .into());
    }
    validate_publishable_segment_capacity(options.segment_size_bytes, options.max_bytes)?;
    Ok(())
}

fn validate_publishable_segment_capacity(
    segment_size_bytes: u64,
    max_bytes: usize,
) -> Result<(), SfaQueueError> {
    let min_publishable_bytes = segment_size_bytes
        .checked_mul(2)
        .ok_or(QueueError::InvalidCapacity)?;
    if (max_bytes as u64) < min_publishable_bytes {
        return Err(QueueError::InvalidCapacity.into());
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
    let mut cleanup_failed = false;
    for entry in fs::read_dir(slot_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !is_sfa_file(&path) {
            continue;
        }
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => {
                cleanup_failed = true;
                diagnostics.push(SfaRecoveryDiagnostic::CleanupFailed {
                    path,
                    error: err.to_string(),
                });
            }
        }
    }
    if !cleanup_failed {
        record_cleanup_remove_file(ack_watermark_path(slot_dir), diagnostics);
    }
    Ok(())
}

fn record_cleanup_remove_file(path: PathBuf, diagnostics: &mut Vec<SfaRecoveryDiagnostic>) {
    match fs::remove_file(&path) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => diagnostics.push(SfaRecoveryDiagnostic::CleanupFailed {
            path,
            error: err.to_string(),
        }),
    }
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
    sealed_segments: &VecDeque<Arc<SfaSharedSegment>>,
    active: &Arc<SfaSharedSegment>,
) -> Option<u64> {
    first_unresolved_fsn_from_optional_segments(sealed_segments, Some(active))
}

fn first_unresolved_fsn_from_optional_segments(
    sealed_segments: &VecDeque<Arc<SfaSharedSegment>>,
    active: Option<&Arc<SfaSharedSegment>>,
) -> Option<u64> {
    sealed_segments
        .front()
        .map(|segment| segment.base_seq())
        .or_else(|| {
            active
                .and_then(|active| (active.published_frame_count() > 0).then(|| active.base_seq()))
        })
}

fn payload_at_send_cursor(cursor: &SfaSendCursor) -> Option<(SfaMappedPayload, u64)> {
    let payload = cursor.segment.mapped_payload_at_offset(cursor.offset)?;
    Some((payload, cursor.segment.published_offset()))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use tempfile::TempDir;

    use super::super::qwp_ws_driver::{
        CloseOutcome, DriveOutcome, FakeOrderedServer, ManualDriverPrototype,
    };
    use super::super::qwp_ws_sfa_segment::{initial_segment_path, scan_file, spare_segment_path};
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

    fn memory_options(
        segment_size_bytes: u64,
        max_bytes: usize,
        max_in_flight: usize,
    ) -> SfaMemoryQueueOptions {
        SfaMemoryQueueOptions {
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

    fn memory_queue() -> SfaFrameQueue {
        SfaFrameQueue::open_memory(memory_options(48, 144, 4)).unwrap()
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

    fn write_ack_watermark(dir: &Path, fsn: i64) {
        write_ack_watermark_raw(dir, ACK_WATERMARK_MAGIC, 0, fsn);
    }

    fn write_ack_watermark_raw(dir: &Path, magic: u32, reserved: u32, fsn: i64) {
        let mut bytes = [0u8; ACK_WATERMARK_SIZE as usize];
        bytes[0..4].copy_from_slice(&magic.to_le_bytes());
        bytes[4..8].copy_from_slice(&reserved.to_le_bytes());
        bytes[8..16].copy_from_slice(&fsn.to_le_bytes());
        fs::write(ack_watermark_path(dir), bytes).unwrap();
    }

    fn recovered_ack_watermark_fsn(dir: &Path) -> Option<u64> {
        let bytes = fs::read(ack_watermark_path(dir)).unwrap();
        decode_ack_watermark(&bytes)
    }

    #[test]
    fn memory_queue_appends_and_reads_payloads_through_sfa_frames() {
        let mut queue = memory_queue();

        let first = queue.try_submit(b"first").unwrap();
        let second = queue.try_submit(b"second").unwrap();

        assert_eq!(first, QwpReceipt { fsn: 0 });
        assert_eq!(second, QwpReceipt { fsn: 1 });
        assert_eq!(queue.payload_vec_for_fsn(0).as_deref(), Some(&b"first"[..]));
        assert_eq!(
            queue.payload_vec_for_fsn(1).as_deref(),
            Some(&b"second"[..])
        );
        assert_eq!(
            queue.receipt_status(first),
            QwpReceiptStatus::Published { fsn: 0 }
        );
    }

    #[test]
    fn memory_queue_rejects_capacity_without_hot_spare_room() {
        assert!(matches!(
            SfaFrameQueue::open_memory(memory_options(48, 48, 4)),
            Err(SfaQueueError::Queue(QueueError::InvalidCapacity))
        ));
        assert!(matches!(
            SfaFrameQueue::open_memory(memory_options(48, 95, 4)),
            Err(SfaQueueError::Queue(QueueError::InvalidCapacity))
        ));

        let queue = SfaFrameQueue::open_memory(memory_options(48, 96, 4)).unwrap();
        assert!(queue.hot_spare_installed());
        assert_eq!(queue.allocated_segment_bytes(), 96);
    }

    #[test]
    fn memory_queue_rotates_and_trims_without_filesystem_cleanup() {
        let mut queue = SfaFrameQueue::open_memory(memory_options(48, 96, 8)).unwrap();

        let first = queue.try_submit(b"abcdefghij").unwrap();
        let second = queue.try_submit(b"klmnopqrst").unwrap();

        assert_eq!(first.fsn, 0);
        assert_eq!(second.fsn, 1);
        assert_eq!(queue.sealed_segment_count(), 1);
        assert_eq!(queue.allocated_segment_bytes(), 96);
        assert!(matches!(
            queue.try_submit(b"uvwxyz1234"),
            Err(SfaQueueError::Queue(QueueError::StorageSegmentCapFull {
                segment_size_bytes: 48,
                allocated_segment_bytes: 96,
                max_total_bytes: 96,
            }))
        ));

        queue.complete_through_fsn(first.fsn).unwrap();
        assert!(queue.maintain_storage().unwrap());
        assert_eq!(queue.sealed_segment_count(), 0);
        assert_eq!(queue.allocated_segment_bytes(), 48);
        assert!(!queue.hot_spare_installed());

        assert!(matches!(
            queue.try_submit(b"uvwxyz1234"),
            Err(SfaQueueError::Queue(
                QueueError::StorageSpareNotReady { .. }
            ))
        ));
        assert!(queue.maintain_storage().unwrap());
        let third = queue.try_submit(b"uvwxyz1234").unwrap();
        assert_eq!(third.fsn, 2);
    }

    #[test]
    fn memory_queue_backpressures_at_max_in_flight_before_capacity() {
        let mut queue = SfaFrameQueue::open_memory(memory_options(128, 256, 2)).unwrap();

        queue.try_submit(b"first").unwrap();
        queue.try_submit(b"second").unwrap();

        assert!(matches!(
            queue.try_submit(b"third"),
            Err(SfaQueueError::Queue(QueueError::MaxInFlightReached {
                max_in_flight: 2
            }))
        ));
        queue.complete_through_fsn(0).unwrap();
        assert_eq!(queue.try_submit(b"third").unwrap().fsn, 2);
    }

    #[test]
    fn replay_only_empty_queue_creates_no_segments_or_producer() {
        let dir = TempDir::new().unwrap();

        let mut queue = SfaFrameQueue::open_replay_only(options(&dir)).unwrap();

        assert!(queue.producer.is_none());
        assert_eq!(queue.published_fsn(), None);
        assert_eq!(queue.completed_fsn(), None);
        assert_eq!(sfa_file_count(dir.path()), 0);
        assert!(matches!(
            queue.try_submit(b"abc"),
            Err(SfaQueueError::Closed)
        ));
        assert!(!queue.maintain_storage().unwrap());
        queue.close().unwrap();
        assert_eq!(sfa_file_count(dir.path()), 0);
    }

    #[test]
    fn replay_only_replays_and_cleans_recovered_frames_without_spares() {
        let dir = TempDir::new().unwrap();
        let initial = initial_segment_path(dir.path());
        write_segment_with_one_frame(&initial, 0, b"abc");

        let mut queue = SfaFrameQueue::open_replay_only(options(&dir)).unwrap();

        assert!(queue.producer.is_none());
        assert_eq!(queue.published_fsn(), Some(0));
        assert_eq!(queue.completed_fsn(), None);
        assert_eq!(sfa_file_count(dir.path()), 1);
        assert_eq!(queue.payload_vec_for_fsn(0).as_deref(), Some(&b"abc"[..]));
        assert!(!queue.maintain_storage().unwrap());

        queue.complete_through_fsn(0).unwrap();
        assert_eq!(queue.completed_fsn(), Some(0));
        queue.close().unwrap();
        assert_eq!(sfa_file_count(dir.path()), 0);
    }

    #[test]
    fn replay_only_skips_bad_side_file_without_dropping_contiguous_frames() {
        let dir = TempDir::new().unwrap();
        let initial_path = initial_segment_path(dir.path());
        let second_path = spare_segment_path(dir.path(), 0);
        let bad_side_path = spare_segment_path(dir.path(), 99);

        write_segment_with_one_frame(&initial_path, 0, b"first");
        write_segment_with_one_frame(&second_path, 1, b"second");
        write_bad_magic_segment(&bad_side_path);

        let queue = SfaFrameQueue::open_replay_only(options(&dir)).unwrap();

        assert_eq!(queue.len(), 2);
        assert_eq!(queue.payload_vec_for_fsn(0).as_deref(), Some(&b"first"[..]));
        assert_eq!(
            queue.payload_vec_for_fsn(1).as_deref(),
            Some(&b"second"[..])
        );
        assert!(bad_side_path.exists());
        assert!(matches!(
            queue.recovery_diagnostics().as_slice(),
            [SfaRecoveryDiagnostic::SkippedSegment { path, .. }]
                if path == &bad_side_path
        ));
    }

    #[test]
    fn replay_only_skipped_middle_file_preserves_gap_failure() {
        let dir = TempDir::new().unwrap();
        let initial_path = initial_segment_path(dir.path());
        let bad_middle_path = spare_segment_path(dir.path(), 0);
        let third_path = spare_segment_path(dir.path(), 1);

        write_segment_with_one_frame(&initial_path, 0, b"first");
        write_bad_magic_segment(&bad_middle_path);
        write_segment_with_one_frame(&third_path, 2, b"third");

        let err = SfaFrameQueue::open_replay_only(options(&dir)).unwrap_err();

        assert!(matches!(
            err,
            SfaQueueError::CorruptSegments {
                reason: "non-contiguous recovered segment sequence",
            }
        ));
        assert!(bad_middle_path.exists());
    }

    #[test]
    fn replay_only_skipped_segment_is_not_treated_as_drained() {
        let dir = TempDir::new().unwrap();
        let bad_path = initial_segment_path(dir.path());
        write_bad_magic_segment(&bad_path);

        let err = SfaFrameQueue::open_replay_only(options(&dir)).unwrap_err();

        assert!(matches!(err, SfaQueueError::CorruptSegments { .. }));
        assert!(bad_path.exists());
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
    fn fresh_disk_queue_uses_generation_zero_segment_name() {
        let dir = TempDir::new().unwrap();
        let mut queue = open(&dir);

        let generation_zero = spare_segment_path(dir.path(), 0);
        assert!(generation_zero.exists());
        assert!(!initial_segment_path(dir.path()).exists());

        assert_eq!(queue.try_submit(b"first").unwrap(), QwpReceipt { fsn: 0 });
        assert_eq!(queue.try_submit(b"second").unwrap(), QwpReceipt { fsn: 1 });
        assert_eq!(queue.published_fsn(), Some(1));

        let scan = scan_file(generation_zero).unwrap();
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
    fn java_current_initial_segment_still_recovers() {
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
        assert_eq!(queue.payload_vec_for_fsn(42).as_deref(), Some(&b"one"[..]));
        assert_eq!(
            queue.payload_vec_for_fsn(43).as_deref(),
            Some(&b"two-two"[..])
        );
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
        assert_eq!(queue.payload_vec_for_fsn(42).as_deref(), Some(&b"one"[..]));
        assert_eq!(
            queue.payload_vec_for_fsn(43).as_deref(),
            Some(&b"two-two"[..])
        );
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
        assert!(!initial_path.exists());
        assert!(corrupt_path.exists());
        let active_scan = scan_file(spare_segment_path(dir.path(), 0)).unwrap();
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
        assert_eq!(queue.payload_vec_for_fsn(0).as_deref(), Some(&b"first"[..]));
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
        assert_eq!(queue.payload_vec_for_fsn(0).as_deref(), Some(&b"first"[..]));
        assert_eq!(
            queue.payload_vec_for_fsn(1).as_deref(),
            Some(&b"second"[..])
        );
        assert!(bad_side_path.exists());
        assert!(!bad_side_corrupt_path.exists());
        let diagnostics = queue.recovery_diagnostics();
        assert!(matches!(
            diagnostics.as_slice(),
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
        assert_eq!(queue.payload_vec_for_fsn(42).as_deref(), Some(&b"one"[..]));
        assert_eq!(
            queue.recovery_diagnostics(),
            vec![SfaRecoveryDiagnostic::NonEmptyTornTail {
                path: initial_path,
                torn_tail_bytes: 29,
                append_offset: 35,
                file_size: 64,
                frames_recovered: 1,
            }]
        );
    }

    #[test]
    fn close_removes_empty_generation_segments() {
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
        assert_eq!(
            recovered.payload_vec_for_fsn(0).as_deref(),
            Some(&b"first"[..])
        );
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

        assert!(ack_watermark_path(dir.path()).exists());
        queue.close().unwrap();

        assert_eq!(sfa_file_count(dir.path()), 0);
        assert!(!ack_watermark_path(dir.path()).exists());
    }

    #[test]
    fn close_keeps_ack_watermark_when_sfa_cleanup_is_partial() {
        let dir = TempDir::new().unwrap();
        let mut queue = open(&dir);
        queue.try_submit(b"first").unwrap();
        queue.complete_through_fsn(0).unwrap();
        let undeletable = dir.path().join("undeletable.sfa");
        fs::create_dir(&undeletable).unwrap();

        queue.close().unwrap();

        assert!(ack_watermark_path(dir.path()).exists());
        assert!(undeletable.exists());
        assert!(
            queue
                .recovery_diagnostics()
                .iter()
                .any(|diagnostic| matches!(
                    diagnostic,
                    SfaRecoveryDiagnostic::CleanupFailed { path, .. } if path == &undeletable
                ))
        );
    }

    #[test]
    fn ack_watermark_skips_completed_frames_after_restart() {
        let dir = TempDir::new().unwrap();
        let first;
        {
            let mut queue = open(&dir);
            first = queue.try_submit(b"first").unwrap();
            queue.try_submit(b"second").unwrap();
            queue.complete_through_fsn(0).unwrap();

            assert_eq!(
                queue.receipt_status(first),
                QwpReceiptStatus::Completed { fsn: 0 }
            );
        }

        let recovered = open(&dir);

        assert_eq!(
            recovered.receipt_status(first),
            QwpReceiptStatus::Completed { fsn: 0 }
        );
        assert_eq!(recovered.oldest_unresolved_fsn(), Some(1));
        assert_eq!(recovered.completed_fsn(), Some(0));
        assert_eq!(
            recovered.payload_vec_for_fsn(1).as_deref(),
            Some(&b"second"[..])
        );
    }

    #[test]
    fn ack_watermark_bounds_are_safe() {
        let future_dir = TempDir::new().unwrap();
        write_segment_with_one_frame(&spare_segment_path(future_dir.path(), 0), 0, b"first");
        write_ack_watermark(future_dir.path(), 10);

        let future = open(&future_dir);

        assert_eq!(future.oldest_unresolved_fsn(), Some(0));
        assert_eq!(future.completed_fsn(), None);
        assert_eq!(
            future.payload_vec_for_fsn(0).as_deref(),
            Some(&b"first"[..])
        );

        let stale_dir = TempDir::new().unwrap();
        write_segment_with_one_frame(&spare_segment_path(stale_dir.path(), 0), 5, b"survivor");
        write_ack_watermark(stale_dir.path(), 3);

        let stale = open(&stale_dir);

        assert_eq!(stale.oldest_unresolved_fsn(), Some(5));
        assert_eq!(stale.completed_fsn(), Some(4));
        assert_eq!(
            stale.payload_vec_for_fsn(5).as_deref(),
            Some(&b"survivor"[..])
        );
    }

    #[test]
    fn future_ack_watermark_is_invalidated_before_new_publish() {
        let dir = TempDir::new().unwrap();
        write_ack_watermark(dir.path(), 0);

        {
            let mut queue = open(&dir);
            assert_eq!(queue.completed_fsn(), None);
            queue.try_submit(b"first").unwrap();
        }

        assert_eq!(recovered_ack_watermark_fsn(dir.path()), None);
        let mut recovered = open(&dir);

        assert_eq!(recovered.oldest_unresolved_fsn(), Some(0));
        assert_eq!(recovered.completed_fsn(), None);
        assert_eq!(
            recovered.receipt_status(QwpReceipt { fsn: 0 }),
            QwpReceiptStatus::Published { fsn: 0 }
        );
        assert_eq!(
            recovered.payload_vec_for_fsn(0).as_deref(),
            Some(&b"first"[..])
        );
        recovered.complete_through_fsn(0).unwrap();
        drop(recovered);
        assert_eq!(recovered_ack_watermark_fsn(dir.path()), Some(0));
    }

    #[test]
    fn ack_watermark_unavailable_is_ignored_for_recovery() {
        let dir = TempDir::new().unwrap();
        write_segment_with_one_frame(&spare_segment_path(dir.path(), 0), 0, b"first");
        fs::create_dir(ack_watermark_path(dir.path())).unwrap();

        let queue = open(&dir);

        assert_eq!(queue.oldest_unresolved_fsn(), Some(0));
        assert_eq!(queue.completed_fsn(), None);
        assert_eq!(queue.payload_vec_for_fsn(0).as_deref(), Some(&b"first"[..]));
    }

    #[test]
    fn ack_watermark_invalid_contents_are_ignored_and_repaired() {
        for (name, magic, reserved) in [
            ("bad magic", 0xdead_beefu32, 0u32),
            ("bad reserved", ACK_WATERMARK_MAGIC, 7u32),
        ] {
            let dir = TempDir::new().unwrap();
            write_segment_with_one_frame(&spare_segment_path(dir.path(), 0), 0, b"first");
            write_segment_with_one_frame(&spare_segment_path(dir.path(), 1), 1, b"second");
            write_ack_watermark_raw(dir.path(), magic, reserved, 1);

            {
                let mut queue = open(&dir);
                assert_eq!(
                    queue.oldest_unresolved_fsn(),
                    Some(0),
                    "{name} should fall back to segment recovery"
                );
                queue.complete_through_fsn(0).unwrap();
            }

            assert_eq!(recovered_ack_watermark_fsn(dir.path()), Some(0));
            let recovered = open(&dir);
            assert_eq!(
                recovered.oldest_unresolved_fsn(),
                Some(1),
                "{name} should be repaired by the next completion"
            );
            assert_eq!(
                recovered.payload_vec_for_fsn(1).as_deref(),
                Some(&b"second"[..])
            );
        }
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn ack_watermark_applies_to_replay_only_orphan_open() {
        use super::super::qwp_ws_sfa_slot::SfaSlotQueue;

        let dir = TempDir::new().unwrap();
        let slot_dir = dir.path().join("orphan");
        fs::create_dir(&slot_dir).unwrap();
        write_segment_with_one_frame(&spare_segment_path(&slot_dir, 0), 0, b"first");
        write_segment_with_one_frame(&spare_segment_path(&slot_dir, 1), 1, b"second");
        write_ack_watermark(&slot_dir, 0);

        let queue = SfaSlotQueue::open_replay_only_existing(SfaQueueOptions {
            slot_dir,
            segment_size_bytes: 256,
            max_bytes: 1024,
            max_in_flight: 4,
        })
        .unwrap();
        let server = FakeOrderedServer::ack_each_send();
        let mut driver = ManualDriverPrototype::from_queue(queue, server);

        assert_eq!(
            driver.drive_once().unwrap(),
            DriveOutcome::Acked { wire_seq: 0 }
        );
        assert_eq!(driver.sent_frames()[0].fsn, 1);
    }

    #[test]
    fn missing_ack_watermark_keeps_legacy_recovery() {
        let dir = TempDir::new().unwrap();
        write_segment_with_one_frame(&initial_segment_path(dir.path()), 3, b"legacy");
        assert!(!ack_watermark_path(dir.path()).exists());

        let queue = open(&dir);

        assert_eq!(queue.oldest_unresolved_fsn(), Some(3));
        assert_eq!(queue.completed_fsn(), Some(2));
        assert_eq!(
            queue.payload_vec_for_fsn(3).as_deref(),
            Some(&b"legacy"[..])
        );
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
        assert_eq!(queue.payload_vec_for_fsn(0).as_deref(), Some(&b"first"[..]));
        assert_eq!(
            queue.payload_vec_for_fsn(1).as_deref(),
            Some(&b"second"[..])
        );
    }

    #[test]
    fn send_cursor_advances_between_segments_without_repositioning() {
        let dir = TempDir::new().unwrap();
        let mut queue = SfaFrameQueue::open(options_with(&dir, 38, 38 * 8, 4)).unwrap();
        submit_with_storage_maintenance(&mut queue, b"one");
        submit_with_storage_maintenance(&mut queue, b"two");
        submit_with_storage_maintenance(&mut queue, b"tri");
        submit_with_storage_maintenance(&mut queue, b"for");

        assert_eq!(queue.sealed_segment_count(), 3);

        assert_eq!(
            pending_payload_vec(queue.next_cursor_payload_for_fsn(0).unwrap().unwrap()),
            b"one"
        );
        assert_eq!(queue.send_cursor_segment_base_seq().unwrap(), 1);
        assert_eq!(
            pending_payload_vec(queue.next_cursor_payload_for_fsn(1).unwrap().unwrap()),
            b"two"
        );
        assert_eq!(queue.send_cursor_segment_base_seq().unwrap(), 2);
        assert_eq!(
            pending_payload_vec(queue.next_cursor_payload_for_fsn(2).unwrap().unwrap()),
            b"tri"
        );
        assert_eq!(queue.send_cursor_segment_base_seq().unwrap(), 3);
        assert_eq!(
            pending_payload_vec(queue.next_cursor_payload_for_fsn(3).unwrap().unwrap()),
            b"for"
        );
    }

    #[test]
    fn send_cursor_repositions_after_delayed_rotation() {
        let mut queue = SfaFrameQueue::open_memory(memory_options(38, 38 * 8, 4)).unwrap();
        submit_with_storage_maintenance(&mut queue, b"one");

        assert_eq!(
            pending_payload_vec(queue.next_cursor_payload_for_fsn(0).unwrap().unwrap()),
            b"one"
        );

        submit_with_storage_maintenance(&mut queue, b"two");

        assert_eq!(
            pending_payload_vec(queue.next_cursor_payload_for_fsn(1).unwrap().unwrap()),
            b"two"
        );
    }

    /// Run with:
    /// `cargo test --features sync-sender-qwp-ws --lib sfa_tiny_frame_publish_zero_alloc_after_warmup -- --ignored --test-threads=1`
    #[test]
    #[ignore = "uses the process-global allocation counter"]
    fn sfa_tiny_frame_publish_zero_alloc_after_warmup() {
        use crate::alloc_counter;

        let dir = TempDir::new().unwrap();
        let mut queue = SfaFrameQueue::open(options_with(&dir, 4096, 8192, 8)).unwrap();
        let mut producer = queue.take_producer().unwrap();
        for _ in 0..4 {
            producer.try_submit(b"steady-state").unwrap();
        }

        alloc_counter::start_counting();
        let receipt = producer.try_submit(b"steady-state").unwrap();
        let alloc_count = alloc_counter::stop_counting();

        assert_eq!(receipt, QwpReceipt { fsn: 4 });
        assert_eq!(
            alloc_count, 0,
            "Expected zero allocations for warmed SFA tiny-frame publication, got {alloc_count}"
        );
    }

    /// Run with:
    /// `cargo test --features sync-sender-qwp-ws --lib sfa_memory_tiny_frame_publish_zero_alloc_after_warmup -- --ignored --test-threads=1`
    #[test]
    #[ignore = "uses the process-global allocation counter"]
    fn sfa_memory_tiny_frame_publish_zero_alloc_after_warmup() {
        use crate::alloc_counter;

        let mut queue = SfaFrameQueue::open_memory(memory_options(4096, 8192, 8)).unwrap();
        let mut producer = queue.take_producer().unwrap();
        for _ in 0..4 {
            producer.try_submit(b"steady-state").unwrap();
        }

        alloc_counter::start_counting();
        let receipt = producer.try_submit(b"steady-state").unwrap();
        let alloc_count = alloc_counter::stop_counting();

        assert_eq!(receipt, QwpReceipt { fsn: 4 });
        assert_eq!(
            alloc_count, 0,
            "Expected zero allocations for warmed memory SFA tiny-frame publication, got {alloc_count}"
        );
    }

    /// Run with:
    /// `cargo test --features sync-sender-qwp-ws --lib sfa_send_cursor_after_rotation_zero_alloc_after_warmup -- --ignored --test-threads=1`
    #[test]
    #[ignore = "uses the process-global allocation counter"]
    fn sfa_send_cursor_after_rotation_zero_alloc_after_warmup() {
        use crate::alloc_counter;

        let mut queue = SfaFrameQueue::open_memory(memory_options(38, 38 * 8, 8)).unwrap();
        submit_with_storage_maintenance(&mut queue, b"one");
        submit_with_storage_maintenance(&mut queue, b"two");
        submit_with_storage_maintenance(&mut queue, b"tri");
        submit_with_storage_maintenance(&mut queue, b"for");
        assert_eq!(queue.sealed_segment_count(), 3);

        assert_eq!(
            pending_payload_vec(queue.next_cursor_payload_for_fsn(0).unwrap().unwrap()),
            b"one"
        );

        alloc_counter::start_counting();
        let second = queue.next_cursor_payload_for_fsn(1).unwrap().unwrap();
        let sealed_alloc_count = alloc_counter::stop_counting();
        assert_eq!(
            sealed_alloc_count, 0,
            "Expected zero allocations when sending from the next sealed segment, got {sealed_alloc_count}"
        );
        assert_eq!(pending_payload_vec(second), b"two");

        alloc_counter::start_counting();
        let third = queue.next_cursor_payload_for_fsn(2).unwrap().unwrap();
        let transition_alloc_count = alloc_counter::stop_counting();
        assert_eq!(
            transition_alloc_count, 0,
            "Expected zero allocations when advancing from sealed to active segment, got {transition_alloc_count}"
        );
        assert_eq!(pending_payload_vec(third), b"tri");
        assert_eq!(queue.send_cursor_segment_base_seq(), Some(3));
    }

    #[test]
    fn rotation_after_generation_zero_uses_generation_one() {
        let dir = TempDir::new().unwrap();
        {
            let mut queue = SfaFrameQueue::open(options_with(&dir, 38, 1024, 4)).unwrap();
            assert_eq!(queue.try_submit(b"first").unwrap(), QwpReceipt { fsn: 0 });
            assert_eq!(queue.try_submit(b"second").unwrap(), QwpReceipt { fsn: 1 });
        }

        let first_path = spare_segment_path(dir.path(), 0);
        let second_path = spare_segment_path(dir.path(), 1);
        assert!(first_path.exists());
        assert!(second_path.exists());
        assert_eq!(scan_file(&first_path).unwrap().header.base_seq, 0);
        let second_scan = scan_file(&second_path).unwrap();
        assert_eq!(second_scan.header.base_seq, 1);
        assert_eq!(second_scan.frames[0].payload, b"second");

        let recovered = SfaFrameQueue::open(options_with(&dir, 38, 1024, 4)).unwrap();
        assert_eq!(
            recovered.payload_vec_for_fsn(0).as_deref(),
            Some(&b"first"[..])
        );
        assert_eq!(
            recovered.payload_vec_for_fsn(1).as_deref(),
            Some(&b"second"[..])
        );
        assert_eq!(recovered.oldest_unresolved_fsn(), Some(0));
    }

    #[test]
    fn fresh_disk_queue_rejects_capacity_without_hot_spare_room() {
        let one_segment_dir = TempDir::new().unwrap();
        assert!(matches!(
            SfaFrameQueue::open(options_with(&one_segment_dir, 48, 48, 4)),
            Err(SfaQueueError::Queue(QueueError::InvalidCapacity))
        ));
        assert_eq!(sfa_file_count(one_segment_dir.path()), 0);

        let undersized_dir = TempDir::new().unwrap();
        assert!(matches!(
            SfaFrameQueue::open(options_with(&undersized_dir, 48, 95, 4)),
            Err(SfaQueueError::Queue(QueueError::InvalidCapacity))
        ));
        assert_eq!(sfa_file_count(undersized_dir.path()), 0);

        let publishable_dir = TempDir::new().unwrap();
        let queue = SfaFrameQueue::open(options_with(&publishable_dir, 48, 96, 4)).unwrap();
        assert!(queue.hot_spare_installed());
        assert_eq!(queue.allocated_segment_bytes(), 96);
        assert_eq!(sfa_file_count(publishable_dir.path()), 2);
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
        assert_eq!(sfa_file_count(dir.path()), 2);
        assert!(matches!(
            queue.try_submit(b"third"),
            Err(SfaQueueError::Queue(QueueError::StorageSpareNotReady {
                segment_size_bytes: 38,
                allocated_segment_bytes: 76,
                max_total_bytes: 114,
            }))
        ));
        assert_eq!(sfa_file_count(dir.path()), 2);

        assert!(queue.maintain_storage().unwrap());
        assert_eq!(queue.try_submit(b"third").unwrap(), QwpReceipt { fsn: 2 });
    }

    #[test]
    fn detached_producer_rotates_replays_and_trims_runner_owned_segments() {
        let dir = TempDir::new().unwrap();
        let mut queue = SfaFrameQueue::open(options_with(&dir, 38, 114, 4)).unwrap();
        let mut producer = queue.take_producer().unwrap();

        assert_eq!(producer.try_submit(b"one").unwrap(), QwpReceipt { fsn: 0 });
        assert_eq!(producer.try_submit(b"two").unwrap(), QwpReceipt { fsn: 1 });
        assert!(matches!(
            producer.try_submit(b"tri"),
            Err(SfaQueueError::Queue(
                QueueError::StorageSpareNotReady { .. }
            ))
        ));
        assert_eq!(sfa_file_count(dir.path()), 2);

        assert!(queue.maintain_storage().unwrap());
        assert_eq!(producer.try_submit(b"tri").unwrap(), QwpReceipt { fsn: 2 });
        assert_eq!(queue.published_fsn(), Some(2));
        assert_eq!(queue.payload_vec_for_fsn(0).as_deref(), Some(&b"one"[..]));
        assert_eq!(queue.payload_vec_for_fsn(1).as_deref(), Some(&b"two"[..]));
        assert_eq!(queue.payload_vec_for_fsn(2).as_deref(), Some(&b"tri"[..]));

        queue.complete_through_fsn(2).unwrap();
        assert!(queue.maintain_storage().unwrap());
        assert!(queue.maintain_storage().unwrap());
        assert_eq!(queue.completed_fsn(), Some(2));
        assert!(sfa_file_count(dir.path()) <= 2);
    }

    #[test]
    fn active_segment_published_offset_is_the_payload_visibility_barrier() {
        let dir = TempDir::new().unwrap();
        let queue = SfaFrameQueue::open(options_with(&dir, 256, 512, 4)).unwrap();
        let active = queue.engine.segments_snapshot().active.unwrap();

        let appended = active
            .try_append_at(HEADER_SIZE as u64, b"hidden")
            .unwrap()
            .unwrap();

        assert!(active.mapped_payload_at_offset(appended.offset).is_none());

        active.publish(appended.frame_end, 1);
        let payload = active.mapped_payload_at_offset(appended.offset).unwrap();
        payload.with_bytes(|bytes| assert_eq!(bytes, b"hidden"));
    }

    #[test]
    fn abandoned_hot_spare_after_close_does_not_change_capacity_or_leak_file() {
        let dir = TempDir::new().unwrap();
        let mut queue = SfaFrameQueue::open(options_with(&dir, 38, 114, 4)).unwrap();
        queue.try_submit(b"first").unwrap();
        queue.try_submit(b"second").unwrap();
        assert_eq!(sfa_file_count(dir.path()), 2);
        assert_eq!(queue.allocated_segment_bytes(), 76);

        let step = queue.take_storage_maintenance_step(true).unwrap().unwrap();
        assert!(!step.changes_queue_before_io());
        let result = step.perform().unwrap();
        assert_eq!(sfa_file_count(dir.path()), 3);

        queue.close().unwrap();
        let finish = queue.finish_storage_maintenance(result, true).unwrap();
        assert!(!finish.did_change());
        assert_eq!(queue.allocated_segment_bytes(), 76);

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
        assert!(!queue.hot_spare_installed());
        assert_eq!(queue.allocated_segment_bytes(), 76);
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
        assert_eq!(queue.payload_vec_for_fsn(0).as_deref(), Some(&b"first"[..]));
        assert_eq!(
            queue.payload_vec_for_fsn(1).as_deref(),
            Some(&b"second"[..])
        );
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
        let first_path = spare_segment_path(dir.path(), 0);
        let second_path = spare_segment_path(dir.path(), 1);
        let mut queue = SfaFrameQueue::open(options_with(&dir, 38, 1024, 4)).unwrap();
        queue.try_submit(b"first").unwrap();
        queue.try_submit(b"second").unwrap();

        queue.complete_through_fsn(1).unwrap();
        assert!(queue.maintain_storage().unwrap());

        assert!(!first_path.exists());
        assert!(second_path.exists());
        assert_eq!(queue.completed_fsn(), Some(1));
    }

    #[cfg(unix)]
    #[test]
    fn acked_segment_cleanup_failure_frees_logical_capacity() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let first_path = spare_segment_path(dir.path(), 0);
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
        assert_eq!(
            recovered.payload_vec_for_fsn(0).as_deref(),
            Some(&b"first"[..])
        );
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
