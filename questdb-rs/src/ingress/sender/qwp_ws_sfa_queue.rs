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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::error;

use super::qwp_ws_driver::{DriverError, PublicationLog, SendCursor};
use super::qwp_ws_queue::{OutboundFrame, QueueError, QwpReceipt, QwpReceiptStatus};
use super::qwp_ws_sfa_manifest::{
    SfManifest, SfaAckWatermark, ack_watermark_path, manifest_path, sync_directory,
};
use super::qwp_ws_sfa_segment::{
    FRAME_HEADER_SIZE, HEADER_SIZE, INITIAL_SEGMENT_FILE_NAME, SfaMappedPayload, SfaSegment,
    SfaSegmentError, scan_file_metadata, spare_segment_path,
};
use super::qwp_ws_sfa_symbol_dict::PersistedSymbolDict;

const PERIODIC_SYNC_RETRY_MAX: Duration = Duration::from_secs(1);

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
enum SfaBarrierEvent {
    CloseWatermarkWritten,
    CloseWatermarkSynced,
    CloseDirectorySynced,
    CloseHandlesReleased,
    CleanupEnumerationComplete,
    CleanupManifestCollapsed,
    CleanupSegmentUnlinked(String),
    CleanupDirectorySynced,
    CleanupWatermarkRemoved,
    CleanupManifestRemoved,
    TrimWatermarkWritten,
    TrimWatermarkSynced,
    TrimDirectorySynced,
    TrimManifestUpdated,
    TrimQueuePopped,
    RotationHeaderSynced,
    RotationManifestUpdated,
    RotationQueueMutated,
    PeriodicSyncAttempt(u64),
    PeriodicSyncCompleted,
    PeriodicSyncFailed,
}

#[cfg(test)]
thread_local! {
    static SFA_BARRIER_EVENTS: std::cell::RefCell<Vec<SfaBarrierEvent>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
fn record_sfa_barrier(event: SfaBarrierEvent) {
    SFA_BARRIER_EVENTS.with(|events| events.borrow_mut().push(event));
}

#[cfg(test)]
fn take_sfa_barriers() -> Vec<SfaBarrierEvent> {
    SFA_BARRIER_EVENTS.with(|events| std::mem::take(&mut *events.borrow_mut()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SfaQueueOptions {
    pub(crate) slot_dir: PathBuf,
    pub(crate) segment_size_bytes: u64,
    pub(crate) max_bytes: usize,
    pub(crate) max_in_flight: usize,
    pub(crate) periodic_sync_interval: Option<Duration>,
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
    Recovery { reason: String },
    SanitizedResidue { path: PathBuf },
    Durability(SfaDurabilityFailure),
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
    SyncPublished(SfaSyncBatch),
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
    PublishedSynced {
        batch: SfaSyncBatch,
        failure: Option<SfaDurabilityFailure>,
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

#[derive(Debug, Clone)]
pub(crate) struct SfaDurabilityFailure {
    message: Arc<str>,
}

#[derive(Debug)]
pub(crate) struct SfaSyncBatch {
    segments: Vec<Arc<SfaSharedSegment>>,
}

impl SfaDurabilityFailure {
    fn new(error: SfaSegmentError) -> Self {
        Self {
            message: format!("{error:?}").into(),
        }
    }

    fn message(&self) -> &str {
        &self.message
    }
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
            Self::SyncPublished(batch) => {
                let mut failure = None;
                for segment in &batch.segments {
                    #[cfg(test)]
                    record_sfa_barrier(SfaBarrierEvent::PeriodicSyncAttempt(segment.base_seq()));
                    if let Err(err) = segment.sync_published() {
                        failure = Some(SfaDurabilityFailure::new(err));
                        break;
                    }
                }
                Ok(SfaStorageResult::PublishedSynced { batch, failure })
            }
            Self::CreateHotSpare {
                path,
                base_seq,
                size_bytes,
                created_us,
            } => {
                let segment = match path {
                    Some(path) => {
                        let slot_dir = path.parent().ok_or(SfaQueueError::InvalidSfDir)?;
                        create_manifested_segment(
                            &path, base_seq, size_bytes, created_us, slot_dir,
                        )?
                    }
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
            Ok(()) => {
                let Some(slot_dir) = path.parent() else {
                    return Some(SfaCleanupFailure {
                        path,
                        error: "SFA segment path has no parent directory".to_string(),
                    });
                };
                sync_directory(slot_dir).err().map(|err| SfaCleanupFailure {
                    path,
                    error: err.to_string(),
                })
            }
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
    ack_watermark: Option<SfaAckWatermark>,
    /// Delta symbol-dict mode for this slot: always on in memory mode; in file
    /// mode on iff the persisted side-file opened (so recovery / orphan-drain can
    /// rebuild the dictionary). When off, the sender keeps full-dict frames.
    delta_dict_enabled: bool,
    /// The slot's persisted symbol dictionary (file mode only). Taken by the
    /// foreground for write-ahead; its recovered entries seed the producer dict
    /// and the driver's catch-up mirror. `None` in memory mode / on open failure.
    persisted_symbol_dict: Option<PersistedSymbolDict>,
}

#[derive(Debug)]
pub(crate) struct SfaProducer {
    engine: Arc<SfaEngine>,
    active: Arc<SfaSharedSegment>,
    active_append_offset: u64,
    active_frame_count: u64,
    next_fsn: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct SfaProgressView {
    engine: Arc<SfaEngine>,
}

#[derive(Debug)]
struct SfaEngine {
    slot_dir: Option<PathBuf>,
    max_bytes: usize,
    segment_size_bytes: u64,
    max_in_flight: usize,
    allow_segment_creation: bool,
    periodic_sync_interval: Option<Duration>,
    state: Mutex<SfaEngineState>,
    published_upper: AtomicU64,
    completed_upper: AtomicU64,
    sync_requested: AtomicBool,
    durability_failed: AtomicBool,
}

#[derive(Debug)]
struct SfaEngineState {
    active: Option<Arc<SfaSharedSegment>>,
    sealed_segments: VecDeque<Arc<SfaSharedSegment>>,
    hot_spare: Option<Arc<SfaSharedSegment>>,
    allocated_segment_bytes: u64,
    recovery_diagnostics: Vec<SfaRecoveryDiagnostic>,
    manifest: Option<SfManifest>,
    next_generation: u64,
    first_non_durable_sealed: usize,
    sync_scratch: Vec<Arc<SfaSharedSegment>>,
    last_sync_completed: Option<Instant>,
    next_sync_delay: Duration,
    durability_failure: Option<SfaDurabilityFailure>,
    periodic_sync_in_flight: bool,
    closed: bool,
}

impl SfaFrameQueue {
    pub(crate) fn open(options: SfaQueueOptions) -> Result<Self, SfaQueueError> {
        validate_options(&options)?;
        let periodic_sync_interval = options.periodic_sync_interval;
        fs::create_dir_all(&options.slot_dir)?;

        let RecoveredState {
            segments: recovered_segments,
            mut manifest,
            diagnostics: recovery_diagnostics,
        } = recover_segments(&options)?;
        let had_recovered_segments = recovered_segments.is_some();
        // Open the slot's persisted symbol dictionary aligned with segment
        // recovery: a fresh slot (no recovered segments) clears any stale side-file
        // and starts empty; a recovered slot loads it so its delta frames can be
        // re-registered on the fresh server. Delta encoding is on iff it opened.
        let persisted_symbol_dict = if had_recovered_segments {
            // Recovered slot: delta-encode ONLY when an existing, valid side-file
            // loads. If it is absent / too short / bad-magic (no dictionary that
            // mirrors the recovered segments), fall back to full-dictionary
            // (self-sufficient) frames rather than seeding an EMPTY delta
            // dictionary next to segments that already reference ids [0, K): under
            // delta a later frame would resolve those stale ids to the wrong
            // symbols on a fresh server (silent corruption). In dense mode a
            // surviving dense frame replays self-sufficiently and a surviving
            // delta frame is rejected loudly by the send loop's torn-dict guard.
            // A transient I/O error still fails construction loudly (retryable,
            // data intact) rather than destroying a dictionary it failed to read.
            PersistedSymbolDict::open_recovered(&options.slot_dir)?
        } else {
            // Fresh slot: no stored frames depend on the dictionary, so a side-file
            // that cannot be opened degrades gracefully to full-dictionary
            // (self-sufficient) frames.
            PersistedSymbolDict::remove_orphan(&options.slot_dir);
            PersistedSymbolDict::open(&options.slot_dir).ok()
        };
        let delta_dict_enabled = persisted_symbol_dict.is_some();
        // For a fresh slot, create and durably publish the zeroed dual-slot
        // watermark before any segment can reach disk. Recovery tolerates a
        // missing watermark (it recreates the file and seeds from the segment
        // floor, re-replaying any acked-but-untrimmed frames), so this
        // ordering is not load-bearing for correctness — it just narrows that
        // duplicate-replay window after a power loss.
        let fresh_ack_watermark = if had_recovered_segments {
            None
        } else {
            let watermark = SfaAckWatermark::open(&options.slot_dir)?;
            watermark.sync_data()?;
            sync_directory(&options.slot_dir)?;
            Some(watermark)
        };
        let (active, sealed_segments, next_fsn, next_generation, mut allocated_segment_bytes) =
            match recovered_segments {
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
                    let (active, fresh_manifest) = create_fresh_manifested_segment(
                        &active_path,
                        options.segment_size_bytes,
                        unix_time_micros(),
                        &options.slot_dir,
                    )?;
                    manifest = Some(fresh_manifest);
                    (
                        active,
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
            hot_spare = Some(Arc::new(SfaSharedSegment::new(create_manifested_segment(
                &path,
                next_fsn,
                options.segment_size_bytes,
                unix_time_micros(),
                &options.slot_dir,
            )?)));
            allocated_segment_bytes = allocated_segment_bytes
                .checked_add(options.segment_size_bytes)
                .ok_or(QueueError::SequenceOverflow)?;
        }

        if periodic_sync_interval.is_some() && had_recovered_segments {
            sync_live_segments(&sealed_segments, Some(&active))?;
        }
        let first_unresolved =
            first_unresolved_fsn_from_segments(&sealed_segments, &active).unwrap_or(next_fsn);
        let recovered_completion = if had_recovered_segments {
            recover_completed_upper(Some(&options.slot_dir), first_unresolved, next_fsn)?
        } else {
            RecoveredCompletion {
                completed_upper: 0,
                ack_watermark: fresh_ack_watermark,
            }
        };
        let active_append_offset = active.published_offset();
        let active_frame_count = active.published_frame_count();
        let engine = Arc::new(SfaEngine {
            slot_dir: Some(options.slot_dir),
            max_bytes: options.max_bytes,
            segment_size_bytes: options.segment_size_bytes,
            max_in_flight: options.max_in_flight,
            allow_segment_creation: true,
            periodic_sync_interval,
            state: Mutex::new(SfaEngineState {
                active: Some(Arc::clone(&active)),
                sealed_segments,
                hot_spare,
                allocated_segment_bytes,
                recovery_diagnostics,
                manifest,
                next_generation,
                first_non_durable_sealed: 0,
                sync_scratch: Vec::new(),
                last_sync_completed: None,
                next_sync_delay: periodic_sync_interval.unwrap_or(Duration::ZERO),
                durability_failure: None,
                periodic_sync_in_flight: false,
                closed: false,
            }),
            published_upper: AtomicU64::new(next_fsn),
            completed_upper: AtomicU64::new(recovered_completion.completed_upper),
            sync_requested: AtomicBool::new(periodic_sync_interval.is_some()),
            durability_failed: AtomicBool::new(false),
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
            ack_watermark: recovered_completion.ack_watermark,
            delta_dict_enabled,
            persisted_symbol_dict,
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
            periodic_sync_interval: None,
            state: Mutex::new(SfaEngineState {
                active: Some(Arc::clone(&active)),
                sealed_segments: VecDeque::new(),
                hot_spare,
                allocated_segment_bytes,
                recovery_diagnostics: Vec::new(),
                manifest: None,
                next_generation,
                first_non_durable_sealed: 0,
                sync_scratch: Vec::new(),
                last_sync_completed: None,
                next_sync_delay: Duration::ZERO,
                durability_failure: None,
                periodic_sync_in_flight: false,
                closed: false,
            }),
            published_upper: AtomicU64::new(next_fsn),
            completed_upper: AtomicU64::new(next_fsn),
            sync_requested: AtomicBool::new(false),
            durability_failed: AtomicBool::new(false),
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
            ack_watermark: None,
            // Memory mode: delta is always safe (in-process reconnect replay), and
            // there is no side-file to persist.
            delta_dict_enabled: true,
            persisted_symbol_dict: None,
        })
    }

    pub(crate) fn open_replay_only(options: SfaQueueOptions) -> Result<Self, SfaQueueError> {
        validate_options(&options)?;
        let periodic_sync_interval = options.periodic_sync_interval;
        let RecoveredState {
            segments: recovered_segments,
            manifest,
            diagnostics: recovery_diagnostics,
        } = recover_segments(&options)?;
        if recovered_segments.is_none()
            && recovery_diagnostics.iter().any(|diagnostic| {
                matches!(diagnostic, SfaRecoveryDiagnostic::SkippedSegment { .. })
            })
        {
            return Err(SfaQueueError::CorruptSegments {
                reason: "replay-only recovery found only skipped SFA segments",
            });
        }
        // Orphan-drain replays this slot's frames on a fresh server, so load its
        // persisted symbol dictionary to re-register delta frames -- but ONLY when
        // an existing, valid side-file loads. Absent / bad-magic (no dictionary
        // that mirrors the segments) falls back to dense: a surviving dense frame
        // replays self-sufficiently and a surviving delta frame is rejected loudly
        // by the torn-dict guard, rather than seeding an empty delta dictionary
        // that would misresolve stale ids. Replay-only has no producer, so the
        // dictionary is read-only here. A transient I/O error fails this drain
        // attempt (retryable; the orphan stays recoverable on disk) rather than
        // truncating the load-bearing side-file.
        let persisted_symbol_dict = PersistedSymbolDict::open_recovered(&options.slot_dir)?;
        let delta_dict_enabled = persisted_symbol_dict.is_some();
        let had_recovered_segments = recovered_segments.is_some();
        let (active, sealed_segments, next_fsn, allocated_segment_bytes) = match recovered_segments
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
        if periodic_sync_interval.is_some() && had_recovered_segments {
            sync_live_segments(&sealed_segments, active.as_ref())?;
        }
        let first_unresolved =
            first_unresolved_fsn_from_optional_segments(&sealed_segments, active.as_ref())
                .unwrap_or(next_fsn);
        let recovered_completion =
            recover_completed_upper(Some(&options.slot_dir), first_unresolved, next_fsn)?;
        let engine = Arc::new(SfaEngine {
            slot_dir: Some(options.slot_dir),
            max_bytes: options.max_bytes,
            segment_size_bytes: options.segment_size_bytes,
            max_in_flight: options.max_in_flight,
            allow_segment_creation: false,
            periodic_sync_interval,
            state: Mutex::new(SfaEngineState {
                active,
                sealed_segments,
                hot_spare: None,
                allocated_segment_bytes,
                recovery_diagnostics,
                manifest,
                next_generation: 0,
                first_non_durable_sealed: 0,
                sync_scratch: Vec::new(),
                last_sync_completed: None,
                next_sync_delay: periodic_sync_interval.unwrap_or(Duration::ZERO),
                durability_failure: None,
                periodic_sync_in_flight: false,
                closed: false,
            }),
            published_upper: AtomicU64::new(next_fsn),
            completed_upper: AtomicU64::new(recovered_completion.completed_upper),
            sync_requested: AtomicBool::new(periodic_sync_interval.is_some()),
            durability_failed: AtomicBool::new(false),
        });

        Ok(Self {
            engine,
            producer: None,
            ack_watermark: recovered_completion.ack_watermark,
            delta_dict_enabled,
            persisted_symbol_dict,
        })
    }

    /// Whether this slot delta-encodes symbol dictionaries (see the field docs).
    pub(crate) fn is_delta_dict_enabled(&self) -> bool {
        self.delta_dict_enabled
    }

    /// The recovered symbol-dict entries (`[len][utf8]...` in id order) used to
    /// seed the producer dict and the driver mirror on recovery / orphan-drain.
    /// Empty for a fresh slot or memory mode.
    pub(crate) fn recovered_symbol_dict_entries(&self) -> &[u8] {
        self.persisted_symbol_dict
            .as_ref()
            .map_or(&[][..], |pd| pd.loaded_entries())
    }

    /// Number of recovered symbol-dict entries.
    pub(crate) fn recovered_symbol_dict_count(&self) -> u32 {
        self.persisted_symbol_dict
            .as_ref()
            .map_or(0, |pd| pd.size())
    }

    /// Takes the persisted symbol dictionary for the foreground producer's
    /// write-ahead. `None` in memory mode / replay-only / on open failure.
    ///
    /// The recovered entry region (up to ~2 GiB) has already been copied out for
    /// seeding by this point: a take removes the dict from the queue, so any code
    /// needing the entries must read them via
    /// [`recovered_symbol_dict_entries`](Self::recovered_symbol_dict_entries) first
    /// (both recovery paths do — async and sync). The write-ahead handle only needs
    /// the file / append offset / size, so free that region rather than carry it
    /// dead for the whole connection lifetime.
    pub(crate) fn take_persisted_symbol_dict(&mut self) -> Option<PersistedSymbolDict> {
        let mut pd = self.persisted_symbol_dict.take();
        if let Some(pd) = pd.as_mut() {
            pd.clear_loaded_entries();
        }
        pd
    }

    pub(crate) fn close(&mut self) -> Result<(), SfaQueueError> {
        self.producer.take();
        self.engine.close(&mut self.ack_watermark)
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

    pub(crate) fn progress_view(&self) -> SfaProgressView {
        SfaProgressView {
            engine: Arc::clone(&self.engine),
        }
    }

    pub(crate) fn complete_through_fsn(&mut self, acked_fsn: u64) -> Result<(), SfaQueueError> {
        let before = self.engine.completed_upper.load(Ordering::Acquire);
        self.engine.complete_through_fsn(acked_fsn)?;
        let after = self.engine.completed_upper.load(Ordering::Acquire);
        if after > before
            && let Some(ack_watermark) = self.ack_watermark.as_mut()
        {
            ack_watermark.write(acked_fsn as i64)?;
        }
        Ok(())
    }

    pub(crate) fn persist_completed_fsn(&mut self, fsn: u64) {
        if let Some(ack_watermark) = self.ack_watermark.as_mut() {
            let _ = i64::try_from(fsn)
                .ok()
                .and_then(|fsn| ack_watermark.write(fsn).ok());
        }
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
        self.engine
            .take_storage_maintenance_step(allow_create, self.ack_watermark.as_mut())
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

    #[cfg(test)]
    fn len(&self) -> usize {
        self.engine.len()
    }

    pub(crate) fn published_fsn(&self) -> Option<u64> {
        self.engine.published_fsn()
    }

    pub(crate) fn completed_fsn(&self) -> Option<u64> {
        self.engine.completed_fsn()
    }

    pub(crate) fn check_durability(&self) -> Result<(), SfaQueueError> {
        self.engine.check_durability()
    }

    pub(crate) fn periodic_sync_in_flight(&self) -> Result<bool, SfaQueueError> {
        self.engine.periodic_sync_in_flight()
    }

    pub(crate) fn max_in_flight(&self) -> usize {
        self.engine.max_in_flight()
    }

    pub(crate) fn recovery_diagnostics(&self) -> Vec<SfaRecoveryDiagnostic> {
        self.engine.recovery_diagnostics()
    }

    fn next_cursor_payload_for_fsn(
        &self,
        send_cursor: &mut Option<SfaSendCursor>,
        fsn: u64,
    ) -> Result<Option<SfaMappedPayload>, SfaQueueError> {
        self.progress_view()
            .next_cursor_payload_for_fsn(send_cursor, fsn)
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
}

impl SfaProgressView {
    pub(crate) fn next_outbound_frame(
        &self,
        send_cursor: &mut SendCursor,
    ) -> Result<Option<OutboundFrame>, DriverError> {
        let Some((fsn, wire_seq)) =
            send_cursor.peek_next_frame_from_oldest(self.oldest_unresolved_fsn())?
        else {
            return Ok(None);
        };
        let Some(payload) = self
            .next_cursor_payload_for_fsn(send_cursor.sfa_cursor_mut(), fsn)
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

    pub(crate) fn oldest_unresolved_fsn(&self) -> Option<u64> {
        self.engine.oldest_unresolved_fsn()
    }

    pub(crate) fn completed_fsn(&self) -> Option<u64> {
        self.engine.completed_fsn()
    }

    pub(crate) fn completion_reaches_published(&self, acked_fsn: u64) -> bool {
        acked_fsn.checked_add(1).is_some_and(|target_upper| {
            target_upper == self.engine.published_upper.load(Ordering::Acquire)
        })
    }

    pub(crate) fn complete_through_fsn(&self, acked_fsn: u64) -> Result<bool, SfaQueueError> {
        let before = self.engine.completed_upper.load(Ordering::Acquire);
        self.engine.complete_through_fsn(acked_fsn)?;
        let after = self.engine.completed_upper.load(Ordering::Acquire);
        Ok(after > before)
    }

    fn next_cursor_payload_for_fsn(
        &self,
        send_cursor: &mut Option<SfaSendCursor>,
        fsn: u64,
    ) -> Result<Option<SfaMappedPayload>, SfaQueueError> {
        let Some(mut cursor) = Self::reusable_send_cursor(send_cursor, fsn)
            .or_else(|| self.position_send_cursor_for_fsn(fsn))
        else {
            *send_cursor = None;
            return Ok(None);
        };

        let (payload, segment_append_offset) = match payload_at_send_cursor(&cursor) {
            Some(payload) => payload,
            None => {
                *send_cursor = None;
                let Some(repositioned) = self.position_send_cursor_for_fsn(fsn) else {
                    return Ok(None);
                };
                cursor = repositioned;
                let Some(payload) = payload_at_send_cursor(&cursor) else {
                    *send_cursor = None;
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
        *send_cursor =
            Some(self.advance_send_cursor(cursor, next_fsn, next_offset, segment_append_offset));
        Ok(Some(payload))
    }

    fn reusable_send_cursor(
        send_cursor: &Option<SfaSendCursor>,
        fsn: u64,
    ) -> Option<SfaSendCursor> {
        let cursor = send_cursor.clone()?;
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
}

impl SfaProducer {
    pub(crate) fn try_submit(&mut self, payload: &[u8]) -> Result<QwpReceipt, SfaQueueError> {
        self.engine.check_durability()?;
        self.engine.validate_submit(payload)?;
        let fsn = self.next_fsn;
        let next_fsn = fsn.checked_add(1).ok_or(QueueError::SequenceOverflow)?;
        if self.append_to_active(payload, next_fsn)? {
            return Ok(QwpReceipt { fsn });
        }

        self.rotate_active()?;
        if self.append_to_active(payload, next_fsn)? {
            Ok(QwpReceipt { fsn })
        } else {
            Err(QueueError::PayloadExceedsByteCapacity {
                payload_len: payload.len(),
                max_bytes: self.engine.segment_payload_capacity(),
            }
            .into())
        }
    }

    pub(crate) fn published_fsn(&self) -> Option<u64> {
        self.engine.published_fsn()
    }

    pub(crate) fn completed_fsn(&self) -> Option<u64> {
        self.engine.completed_fsn()
    }

    pub(crate) fn check_durability(&self) -> Result<(), SfaQueueError> {
        self.engine.check_durability()
    }

    /// Append `payload` to the active segment and advance `published_upper`
    /// to `next_fsn` *before* publishing segment visibility.
    ///
    /// The ordering matters: once `active.publish` makes the frame readable
    /// by the sender thread, the server can ACK it. The ACK path validates
    /// `target_upper <= engine.published_upper` and would raise
    /// `ProtocolAckedUnsentFrame` if the engine's watermark hadn't caught
    /// up yet. So `engine.published_upper` is bumped first, then the frame
    /// is made visible — readers may briefly observe `published_upper`
    /// ahead of the segment (handled by the runner returning Idle), but
    /// they can never observe a visible frame whose ack would violate the
    /// watermark.
    fn append_to_active(&mut self, payload: &[u8], next_fsn: u64) -> Result<bool, SfaQueueError> {
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
        self.next_fsn = next_fsn;
        self.engine
            .published_upper
            .store(next_fsn, Ordering::Release);
        self.active
            .publish(self.active_append_offset, self.active_frame_count);
        Ok(true)
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
        if self.engine.request_sync_before_rotation(active) {
            return Err(self.engine.rotation_backpressure_error(&state).into());
        }
        let previous_active_base = active.base_seq();
        let new_active = match state.hot_spare.take() {
            Some(mut new_active) => {
                let rebase_result = if let Some(shared) = Arc::get_mut(&mut new_active) {
                    shared.rebase_empty(self.next_fsn)
                } else {
                    state.hot_spare = Some(new_active);
                    return Err(SfaQueueError::CorruptSegments {
                        reason: "hot spare segment is shared before promotion",
                    });
                };
                if let Err(err) = rebase_result {
                    state.hot_spare = Some(new_active);
                    return Err(err.into());
                }
                new_active
            }
            // No prepared spare. The runner's maintenance step is the normal
            // supplier, but it runs only between `drive_step` iterations — a
            // runner parked in a blocking socket send (peer zero-window) never
            // reaches it, and waiting on the backpressure notifier would starve
            // the appender until `sf_append_deadline` with the byte budget
            // still unused. Store-and-forward must keep absorbing appends up
            // to `max_bytes` through exactly that kind of outage, so allocate
            // the replacement segment inline instead.
            None => self
                .engine
                .allocate_segment_inline(&mut state, self.next_fsn)?,
        };
        #[cfg(test)]
        if state.manifest.is_some() {
            record_sfa_barrier(SfaBarrierEvent::RotationHeaderSynced);
        }

        let head_base = state
            .sealed_segments
            .front()
            .map(|segment| segment.base_seq())
            .unwrap_or(previous_active_base);
        let manifest_update_error = state
            .manifest
            .as_mut()
            .and_then(|manifest| manifest.update(head_base, self.next_fsn).err());
        if let Some(err) = manifest_update_error {
            state.hot_spare = Some(new_active);
            return Err(err.into());
        }
        #[cfg(test)]
        if state.manifest.is_some() {
            record_sfa_barrier(SfaBarrierEvent::RotationManifestUpdated);
        }
        let old_active = state.active.replace(Arc::clone(&new_active)).unwrap();
        state.sealed_segments.push_back(old_active);
        #[cfg(test)]
        if state.manifest.is_some() {
            record_sfa_barrier(SfaBarrierEvent::RotationQueueMutated);
        }
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
    fn close(&self, ack_watermark: &mut Option<SfaAckWatermark>) -> Result<(), SfaQueueError> {
        let mut state = self.lock_state()?;
        if state.closed {
            return Ok(());
        }
        let fully_drained = self.all_published_frames_resolved();
        if !fully_drained && self.periodic_sync_interval.is_some() {
            for segment in state.sealed_segments.iter().chain(state.active.iter()) {
                segment.sync_published()?;
            }
        }
        if fully_drained
            && let Some(slot_dir) = self.slot_dir.as_deref()
            && let Some(final_acked_fsn) = self.completed_fsn()
        {
            let watermark = ack_watermark
                .as_mut()
                .ok_or_else(|| SfaQueueError::Recovery {
                    reason: "fully drained SFA slot has no ACK watermark".to_string(),
                })?;
            let final_acked_fsn =
                i64::try_from(final_acked_fsn).map_err(|_| QueueError::SequenceOverflow)?;
            watermark.write(final_acked_fsn)?;
            #[cfg(test)]
            record_sfa_barrier(SfaBarrierEvent::CloseWatermarkWritten);
            watermark.sync_data()?;
            #[cfg(test)]
            record_sfa_barrier(SfaBarrierEvent::CloseWatermarkSynced);
            sync_directory(slot_dir)?;
            #[cfg(test)]
            record_sfa_barrier(SfaBarrierEvent::CloseDirectorySynced);
        }

        state.sealed_segments.clear();
        state.hot_spare.take();
        state.active.take();
        state.manifest.take();
        // The final covering barrier above is complete. Drop the watermark
        // handle before unlinking it, matching the segment mapping teardown
        // and keeping close portable to filesystems that reject deletion of an
        // open file.
        ack_watermark.take();
        #[cfg(test)]
        record_sfa_barrier(SfaBarrierEvent::CloseHandlesReleased);
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

    fn check_durability(&self) -> Result<(), SfaQueueError> {
        if !self.durability_failed.load(Ordering::Acquire) {
            return Ok(());
        }
        let state = self.lock_state()?;
        match state.durability_failure.as_ref() {
            Some(failure) => Err(SfaQueueError::Durability(failure.clone())),
            None => Ok(()),
        }
    }

    fn periodic_sync_in_flight(&self) -> Result<bool, SfaQueueError> {
        if self.periodic_sync_interval.is_none() {
            return Ok(false);
        }
        Ok(self.lock_state()?.periodic_sync_in_flight)
    }

    fn request_sync_before_rotation(&self, active: &SfaSharedSegment) -> bool {
        if self.periodic_sync_interval.is_some() && !active.is_published_durable() {
            self.sync_requested.store(true, Ordering::Release);
            return true;
        }
        false
    }

    fn rotation_backpressure_error(&self, state: &SfaEngineState) -> QueueError {
        QueueError::StorageSpareNotReady {
            segment_size_bytes: self.segment_size_bytes,
            allocated_segment_bytes: state.allocated_segment_bytes,
            max_total_bytes: self.max_bytes as u64,
        }
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
        ack_watermark: Option<&mut SfaAckWatermark>,
    ) -> Result<Option<SfaStorageStep>, SfaQueueError> {
        if let Some(step) = self.take_periodic_sync_step()? {
            return Ok(Some(step));
        }
        let trim_candidate = {
            let state = self.lock_state()?;
            if state.closed {
                return Ok(None);
            }
            self.trimmable_front(&state)?
        };
        if let Some(candidate) = trim_candidate {
            if let Some(slot_dir) = self.slot_dir.as_deref() {
                let acked_fsn = self.completed_fsn().ok_or(SfaQueueError::CorruptSegments {
                    reason: "trimmable segment exists without a completed FSN",
                })?;
                let acked_fsn =
                    i64::try_from(acked_fsn).map_err(|_| QueueError::SequenceOverflow)?;
                let watermark = ack_watermark.ok_or_else(|| SfaQueueError::Recovery {
                    reason: "cannot durably trim SFA segments without an ACK watermark".to_string(),
                })?;
                watermark.write(acked_fsn)?;
                #[cfg(test)]
                record_sfa_barrier(SfaBarrierEvent::TrimWatermarkWritten);
                watermark.sync_data()?;
                #[cfg(test)]
                record_sfa_barrier(SfaBarrierEvent::TrimWatermarkSynced);
                sync_directory(slot_dir)?;
                #[cfg(test)]
                record_sfa_barrier(SfaBarrierEvent::TrimDirectorySynced);
            }

            let mut state = self.lock_state()?;
            if state.closed {
                return Ok(None);
            }
            let Some(front) = state.sealed_segments.front() else {
                return Ok(None);
            };
            if !Arc::ptr_eq(front, &candidate) || self.trimmable_front(&state)?.is_none() {
                return Ok(None);
            }
            if self.slot_dir.is_some() {
                let active_base = state
                    .active
                    .as_ref()
                    .ok_or(SfaQueueError::Closed)?
                    .base_seq();
                let new_head_base = state
                    .sealed_segments
                    .get(1)
                    .map(|segment| segment.base_seq())
                    .unwrap_or(active_base);
                let manifest = state
                    .manifest
                    .as_mut()
                    .ok_or_else(|| SfaQueueError::Recovery {
                        reason: "cannot trim a manifested SFA slot without its manifest"
                            .to_string(),
                    })?;
                manifest.update(new_head_base, active_base)?;
                #[cfg(test)]
                record_sfa_barrier(SfaBarrierEvent::TrimManifestUpdated);
            }
            let segment = state.sealed_segments.pop_front().unwrap();
            state.first_non_durable_sealed = state.first_non_durable_sealed.saturating_sub(1);
            #[cfg(test)]
            if self.slot_dir.is_some() {
                record_sfa_barrier(SfaBarrierEvent::TrimQueuePopped);
            }
            state.allocated_segment_bytes = state
                .allocated_segment_bytes
                .saturating_sub(segment.size_bytes());
            return Ok(Some(SfaStorageStep::Trim(SfaStorageCleanup::new(segment))));
        }

        let mut state = self.lock_state()?;
        if state.closed {
            return Ok(None);
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
            SfaStorageResult::PublishedSynced { batch, failure } => {
                self.finish_periodic_sync(batch, failure)
            }
        }
    }

    fn take_periodic_sync_step(&self) -> Result<Option<SfaStorageStep>, SfaQueueError> {
        let Some(_interval) = self.periodic_sync_interval else {
            return Ok(None);
        };
        let now = Instant::now();
        let requested = self.sync_requested.load(Ordering::Acquire);
        let mut state = self.lock_state()?;
        if state.closed || state.periodic_sync_in_flight {
            return Ok(None);
        }
        let before_deadline = state.last_sync_completed.is_some_and(|last_sync| {
            now.saturating_duration_since(last_sync) < state.next_sync_delay
        });
        // A rotation request overrides the normal cadence, but must not turn
        // a failing device into a busy loop. Once a failure is latched, even
        // a still-pending request observes the bounded retry delay.
        if before_deadline && (state.durability_failure.is_some() || !requested) {
            return Ok(None);
        }

        while state.first_non_durable_sealed < state.sealed_segments.len()
            && state.sealed_segments[state.first_non_durable_sealed].is_published_durable()
        {
            state.first_non_durable_sealed += 1;
        }
        let first = state.first_non_durable_sealed;
        let mut segments = std::mem::take(&mut state.sync_scratch);
        segments.clear();
        segments.extend(state.sealed_segments.iter().skip(first).cloned());
        segments.extend(state.active.iter().cloned());
        state.periodic_sync_in_flight = true;
        Ok(Some(SfaStorageStep::SyncPublished(SfaSyncBatch {
            segments,
        })))
    }

    fn finish_periodic_sync(
        &self,
        mut batch: SfaSyncBatch,
        failure: Option<SfaDurabilityFailure>,
    ) -> Result<SfaStorageFinish, SfaQueueError> {
        let interval = self
            .periodic_sync_interval
            .ok_or(SfaQueueError::CorruptSegments {
                reason: "periodic sync result on a non-periodic SFA queue",
            })?;
        let mut state = self.lock_state()?;
        state.periodic_sync_in_flight = false;
        batch.segments.clear();
        state.sync_scratch = batch.segments;
        state.last_sync_completed = Some(Instant::now());
        if let Some(failure) = failure {
            let first_failure = state.durability_failure.is_none();
            if first_failure {
                log::error!(
                    "Periodic QWP/WebSocket SF data sync failed: {}",
                    failure.message()
                );
                state.durability_failure = Some(failure);
            }
            state.next_sync_delay = interval.min(PERIODIC_SYNC_RETRY_MAX);
            self.durability_failed.store(true, Ordering::Release);
            #[cfg(test)]
            record_sfa_barrier(SfaBarrierEvent::PeriodicSyncFailed);
            return Ok(SfaStorageFinish::changed());
        }

        let recovered = state.durability_failure.take().is_some();
        state.next_sync_delay = interval;
        if state
            .active
            .as_ref()
            .is_none_or(|active| active.is_published_durable())
        {
            self.sync_requested.store(false, Ordering::Release);
        }
        self.durability_failed.store(false, Ordering::Release);
        if recovered {
            log::info!("Periodic QWP/WebSocket SF data sync recovered");
        }
        #[cfg(test)]
        record_sfa_barrier(SfaBarrierEvent::PeriodicSyncCompleted);
        Ok(SfaStorageFinish::changed())
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

    #[cfg(test)]
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

    /// Creates a fresh segment on the appender thread when rotation finds no
    /// prepared hot spare, charging it to the byte budget under the state
    /// lock. Mirrors the `CreateHotSpare` maintenance step (same path /
    /// generation / budget bookkeeping); the runner's maintenance remains an
    /// optimization that pre-warms the spare, not a liveness requirement for
    /// appends. Fails with the storage backpressure error when creation is
    /// not allowed or the budget is exhausted, and propagates segment-creation
    /// I/O errors (the runner's maintenance path treats those as terminal
    /// storage errors too).
    fn allocate_segment_inline(
        &self,
        state: &mut SfaEngineState,
        base_seq: u64,
    ) -> Result<Arc<SfaSharedSegment>, SfaQueueError> {
        if !self.allow_segment_creation
            || !can_allocate_segment(
                state.allocated_segment_bytes,
                self.segment_size_bytes,
                self.max_bytes,
            )
        {
            return Err(self.storage_backpressure_error(state).into());
        }
        let segment = match self.slot_dir.as_deref() {
            Some(slot_dir) => {
                let path = next_segment_path(slot_dir, &mut state.next_generation)?;
                create_manifested_segment(
                    &path,
                    base_seq,
                    self.segment_size_bytes,
                    unix_time_micros(),
                    slot_dir,
                )?
            }
            None => {
                state.next_generation = state
                    .next_generation
                    .checked_add(1)
                    .ok_or(QueueError::SequenceOverflow)?;
                SfaSegment::create_memory(base_seq, self.segment_size_bytes, unix_time_micros())?
            }
        };
        state.allocated_segment_bytes = state
            .allocated_segment_bytes
            .checked_add(self.segment_size_bytes)
            .ok_or(QueueError::SequenceOverflow)?;
        Ok(Arc::new(SfaSharedSegment::new(segment)))
    }

    fn trimmable_front(
        &self,
        state: &SfaEngineState,
    ) -> Result<Option<Arc<SfaSharedSegment>>, SfaQueueError> {
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
        Ok(Some(Arc::clone(segment)))
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
    durable_cursor: AtomicU64,
}

impl SfaSharedSegment {
    fn new(segment: SfaSegment) -> Self {
        let published_offset = segment.append_offset();
        let durable_cursor = if segment.path().is_some() {
            HEADER_SIZE as u64
        } else {
            published_offset
        };
        Self {
            published_offset: AtomicU64::new(published_offset),
            published_frame_count: AtomicU64::new(segment.frame_count()),
            durable_cursor: AtomicU64::new(durable_cursor),
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
        self.segment.sync_header()?;
        self.durable_cursor
            .store(HEADER_SIZE as u64, Ordering::Release);
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

    fn is_published_durable(&self) -> bool {
        self.durable_cursor.load(Ordering::Acquire) >= self.published_offset()
    }

    fn sync_published(&self) -> Result<(), SfaSegmentError> {
        let published = self.published_offset();
        let durable = self.durable_cursor.load(Ordering::Acquire);
        if published <= durable {
            return Ok(());
        }
        self.segment.sync_published_range(durable, published)?;
        self.durable_cursor.store(published, Ordering::Release);
        Ok(())
    }
}

fn sync_live_segments(
    sealed_segments: &VecDeque<Arc<SfaSharedSegment>>,
    active: Option<&Arc<SfaSharedSegment>>,
) -> Result<(), SfaQueueError> {
    for segment in sealed_segments {
        segment.sync_published()?;
    }
    if let Some(active) = active {
        active.sync_published()?;
    }
    Ok(())
}

impl PublicationLog for SfaFrameQueue {
    fn try_publish(&mut self, payload: &[u8]) -> Result<QwpReceipt, DriverError> {
        Ok(SfaFrameQueue::try_submit(self, payload)?)
    }

    fn take_producer(&mut self) -> Option<SfaProducer> {
        SfaFrameQueue::take_producer(self)
    }

    fn progress_view(&self) -> SfaProgressView {
        SfaFrameQueue::progress_view(self)
    }

    fn check_durability(&self) -> Result<(), DriverError> {
        Ok(SfaFrameQueue::check_durability(self)?)
    }

    fn periodic_sync_in_flight(&self) -> Result<bool, DriverError> {
        Ok(SfaFrameQueue::periodic_sync_in_flight(self)?)
    }

    fn oldest_unresolved_fsn(&self) -> Option<u64> {
        SfaFrameQueue::oldest_unresolved_fsn(self)
    }

    fn persist_completed_fsn(&mut self, fsn: u64) {
        SfaFrameQueue::persist_completed_fsn(self, fsn);
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
    manifest: Option<SfManifest>,
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

#[derive(Debug, Clone)]
pub(crate) struct SfaSendCursor {
    fsn: u64,
    offset: u64,
    segment: Arc<SfaSharedSegment>,
}

#[derive(Debug)]
struct RecoveredCompletion {
    completed_upper: u64,
    ack_watermark: Option<SfaAckWatermark>,
}

fn recover_completed_upper(
    slot_dir: Option<&Path>,
    segment_completed_upper: u64,
    published_upper: u64,
) -> Result<RecoveredCompletion, SfaQueueError> {
    let Some(slot_dir) = slot_dir else {
        return Ok(RecoveredCompletion {
            completed_upper: segment_completed_upper,
            ack_watermark: None,
        });
    };
    let mut ack_watermark = SfaAckWatermark::open(slot_dir)?;
    let completed_upper = match ack_watermark.read()? {
        Some(acked_fsn) => match ack_watermark_completed_upper(acked_fsn, published_upper) {
            Some(upper) => segment_completed_upper.max(upper),
            None => {
                let segment_floor_fsn = segment_completed_upper
                    .checked_sub(1)
                    .and_then(|fsn| i64::try_from(fsn).ok())
                    .unwrap_or(-1);
                ack_watermark.write(segment_floor_fsn)?;
                segment_completed_upper
            }
        },
        None => segment_completed_upper,
    };
    Ok(RecoveredCompletion {
        completed_upper,
        ack_watermark: Some(ack_watermark),
    })
}

fn ack_watermark_completed_upper(acked_fsn: i64, published_upper: u64) -> Option<u64> {
    if acked_fsn == -1 {
        return Some(0);
    }
    let acked_fsn = u64::try_from(acked_fsn).ok()?;
    if acked_fsn >= published_upper {
        return None;
    }
    acked_fsn.checked_add(1)
}

#[derive(Debug, Clone)]
struct RecoveredSegment {
    path: PathBuf,
    base_seq: u64,
    frame_count: u64,
    append_offset: u64,
    torn_tail_bytes: u64,
    manifest_required: bool,
}

fn recover_segments(options: &SfaQueueOptions) -> Result<RecoveredState, SfaQueueError> {
    let mut all = Vec::new();
    let mut corrupt_paths = Vec::new();
    let mut diagnostics = Vec::new();

    for entry in fs::read_dir(&options.slot_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !is_sfa_file(&path) {
            continue;
        }

        let scan = match scan_file_metadata(&path) {
            Ok(scan) => scan,
            // Operational failures and unknown versions may describe an intact
            // load-bearing segment. Excluding one would silently drop frames.
            Err(err @ (SfaSegmentError::Io(_) | SfaSegmentError::UnsupportedVersion { .. })) => {
                return Err(err.into());
            }
            Err(err) => {
                diagnostics.push(SfaRecoveryDiagnostic::SkippedSegment {
                    path: path.clone(),
                    error: format!("{err:?}"),
                });
                corrupt_paths.push(path);
                continue;
            }
        };
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

        all.push(RecoveredSegment {
            path,
            base_seq: scan.header.base_seq,
            frame_count: scan.frame_count,
            append_offset: scan.append_offset,
            torn_tail_bytes: scan.torn_tail_bytes,
            manifest_required: scan.manifest_required,
        });
    }

    let mut manifest = SfManifest::open(&options.slot_dir)?;
    if all.is_empty() {
        if !corrupt_paths.is_empty() {
            if manifest.is_some() {
                return Err(recovery_error(
                    "every SFA segment is corrupt but the manifest references durable state",
                ));
            }
            quarantine_paths(&corrupt_paths);
        }
        if let Some(existing) = manifest.take() {
            if existing.head_base() != existing.active_base() {
                return Err(recovery_error(
                    "SF manifest references durable state but no segment files exist",
                ));
            }
            drop(existing);
            SfManifest::remove_file(&options.slot_dir)?;
        }
        SfaAckWatermark::remove_file(&options.slot_dir)?;
        return Ok(RecoveredState {
            segments: None,
            manifest: None,
            diagnostics,
        });
    }

    let requires_manifest = all.iter().any(|segment| segment.manifest_required);
    if manifest.is_none() && requires_manifest {
        return Err(recovery_error(
            "new-format SFA segment exists but sf-manifest.bin is missing",
        ));
    }

    let mut data: Vec<RecoveredSegment> = all
        .iter()
        .filter(|segment| segment.frame_count > 0)
        .cloned()
        .collect();
    data.sort_by_key(|segment| segment.base_seq);
    let mut chain = Vec::new();
    let legacy = manifest.is_none();
    if legacy {
        if data.is_empty() {
            let Some(active) = choose_legacy_empty(&all) else {
                cleanup_recovered_extras(&options.slot_dir, &all, &[], &mut diagnostics);
                quarantine_paths(&corrupt_paths);
                SfaAckWatermark::remove_file(&options.slot_dir)?;
                return Ok(RecoveredState {
                    segments: None,
                    manifest: None,
                    diagnostics,
                });
            };
            chain.push(active.clone());
        } else {
            validate_contiguous_segments(&data)?;
            chain = data;
        }
    } else {
        let existing = manifest.as_ref().unwrap();
        let head_base = existing.head_base();
        let active_base = existing.active_base();
        for segment in data {
            let end = segment
                .base_seq
                .checked_add(segment.frame_count)
                .ok_or(QueueError::SequenceOverflow)?;
            if segment.base_seq < head_base {
                if end > head_base {
                    return Err(recovery_error(
                        "segment overlaps committed SFA head boundary",
                    ));
                }
                continue;
            }
            if segment.base_seq > active_base {
                return Err(recovery_error(
                    "segment exists beyond committed SFA active boundary",
                ));
            }
            chain.push(segment);
        }
        if !chain.is_empty() {
            validate_contiguous_segments(&chain)?;
            if chain[0].base_seq != head_base {
                return Err(recovery_error(
                    "missing expected SFA head segment at the committed boundary",
                ));
            }
        }

        let active = find_manifest_active(&all, active_base);
        let Some(active) = active else {
            if chain.is_empty() && head_base == active_base && corrupt_paths.is_empty() {
                cleanup_recovered_extras(&options.slot_dir, &all, &[], &mut diagnostics);
                drop(manifest.take());
                SfManifest::remove_file(&options.slot_dir)?;
                SfaAckWatermark::remove_file(&options.slot_dir)?;
                PersistedSymbolDict::remove_orphan(&options.slot_dir);
                return Ok(RecoveredState {
                    segments: None,
                    manifest: None,
                    diagnostics,
                });
            }
            return Err(recovery_error(
                "missing expected SFA active segment at the committed boundary",
            ));
        };
        if chain.is_empty() {
            if head_base != active_base || active.frame_count != 0 || !corrupt_paths.is_empty() {
                return Err(recovery_error(
                    "missing SFA chain between committed boundaries",
                ));
            }
            chain.push(active.clone());
        } else if chain.last().is_none_or(|tail| tail.path != active.path) {
            let tail = chain.last().unwrap();
            let chain_end = tail
                .base_seq
                .checked_add(tail.frame_count)
                .ok_or(QueueError::SequenceOverflow)?;
            if corrupt_paths.is_empty() && active.frame_count == 0 && active.base_seq == chain_end {
                chain.push(active.clone());
            } else {
                return Err(recovery_error(
                    "missing expected SFA active or tail segment",
                ));
            }
        }
    }

    let mut opened = Vec::with_capacity(chain.len());
    for segment in &chain {
        opened.push(SfaSegment::open_existing(&segment.path)?);
    }
    if legacy {
        sanitize_sealed_residue(&mut opened, false)?;
        let head_base = opened.first().unwrap().header().base_seq;
        let active_base = opened.last().unwrap().header().base_seq;
        manifest = Some(SfManifest::create(
            &options.slot_dir,
            head_base,
            active_base,
        )?);
    } else {
        sanitize_sealed_residue(&mut opened, true)?;
    }
    for segment in &mut opened {
        segment.mark_manifest_required()?;
    }

    cleanup_recovered_extras(&options.slot_dir, &all, &chain, &mut diagnostics);
    quarantine_paths(&corrupt_paths);
    opened.last_mut().unwrap().sanitize_torn_tail()?;

    let active = opened.pop().unwrap();
    let sealed_segments = VecDeque::from(opened);
    let mut allocated_segment_bytes = 0u64;
    for opened in &sealed_segments {
        allocated_segment_bytes = allocated_segment_bytes
            .checked_add(opened.size_bytes())
            .ok_or(QueueError::SequenceOverflow)?;
    }
    allocated_segment_bytes = allocated_segment_bytes
        .checked_add(active.size_bytes())
        .ok_or(QueueError::SequenceOverflow)?;
    let next_fsn = active
        .last_fsn()
        .and_then(|fsn| fsn.checked_add(1))
        .unwrap_or(active.header().base_seq);
    Ok(RecoveredState {
        segments: Some(RecoveredSegments {
            active,
            sealed_segments,
            next_fsn,
            next_generation: scan_next_generation(&options.slot_dir)?,
            allocated_segment_bytes,
        }),
        manifest,
        diagnostics,
    })
}

fn recovery_error(reason: &'static str) -> SfaQueueError {
    SfaQueueError::Recovery {
        reason: reason.to_string(),
    }
}

fn choose_legacy_empty(all: &[RecoveredSegment]) -> Option<&RecoveredSegment> {
    let mut selected = None;
    for segment in all {
        if segment.frame_count != 0 || segment.torn_tail_bytes != 0 {
            continue;
        }
        if selected.is_none()
            || segment
                .path
                .file_name()
                .is_some_and(|name| name == INITIAL_SEGMENT_FILE_NAME)
        {
            selected = Some(segment);
        }
    }
    selected
}

fn find_manifest_active(all: &[RecoveredSegment], active_base: u64) -> Option<&RecoveredSegment> {
    let mut torn_empty = None;
    let mut clean_empty = None;
    for segment in all {
        if segment.base_seq != active_base {
            continue;
        }
        if segment.frame_count > 0 {
            return Some(segment);
        }
        if segment.torn_tail_bytes > 0 {
            torn_empty.get_or_insert(segment);
        } else {
            clean_empty.get_or_insert(segment);
        }
    }
    torn_empty.or(clean_empty)
}

fn sanitize_sealed_residue(
    chain: &mut [SfaSegment],
    fail_closed_on_sight: bool,
) -> Result<(), SfaQueueError> {
    let mut first_torn_path = None;
    let sealed_len = chain.len().saturating_sub(1);
    for segment in &mut chain[..sealed_len] {
        if segment.torn_tail_bytes() == 0 {
            continue;
        }
        let path = segment.path().map(Path::to_path_buf);
        segment.sanitize_torn_tail()?;
        if first_torn_path.is_none() {
            first_torn_path = path;
        }
    }
    if fail_closed_on_sight && let Some(path) = first_torn_path {
        return Err(SfaQueueError::SanitizedResidue { path });
    }
    Ok(())
}

fn cleanup_recovered_extras(
    slot_dir: &Path,
    all: &[RecoveredSegment],
    chain: &[RecoveredSegment],
    diagnostics: &mut Vec<SfaRecoveryDiagnostic>,
) {
    for segment in all {
        if chain.iter().any(|retained| retained.path == segment.path) {
            continue;
        }
        if segment.torn_tail_bytes > 0 {
            quarantine_segment(&segment.path);
            continue;
        }
        if let Err(err) = remove_file_if_exists(&segment.path) {
            diagnostics.push(SfaRecoveryDiagnostic::CleanupFailed {
                path: segment.path.clone(),
                error: err.to_string(),
            });
        }
    }
    if let Err(err) = sync_directory(slot_dir) {
        diagnostics.push(SfaRecoveryDiagnostic::CleanupFailed {
            path: slot_dir.to_path_buf(),
            error: err.to_string(),
        });
    }
}

fn quarantine_paths(paths: &[PathBuf]) {
    for path in paths {
        quarantine_segment(path);
    }
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

// Accounts for the `sf-*.sfa` segment files only. The slot's small side-files
// (`.symbol-dict`, `.ack-watermark`, `.lock`) are deliberately excluded: the
// `.symbol-dict` write-ahead is append-only and bounded by the connection
// symbol-dictionary cap (`MAX_CONN_SYMBOL_DICT_SIZE`), not by this segment
// budget. See the `sf_max_total_bytes` config doc.
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

fn create_manifested_segment(
    path: &Path,
    base_seq: u64,
    size_bytes: u64,
    created_us: u64,
    slot_dir: &Path,
) -> Result<SfaSegment, SfaQueueError> {
    let segment = SfaSegment::create_new_manifested(path, base_seq, size_bytes, created_us)?;
    if let Err(err) = segment
        .sync_header()
        .map_err(SfaQueueError::from)
        .and_then(|()| sync_directory(slot_dir).map_err(SfaQueueError::from))
    {
        drop(segment);
        let _ = remove_file_if_exists(path);
        let _ = sync_directory(slot_dir);
        return Err(err);
    }
    Ok(segment)
}

fn create_fresh_manifested_segment(
    path: &Path,
    size_bytes: u64,
    created_us: u64,
    slot_dir: &Path,
) -> Result<(SfaSegment, SfManifest), SfaQueueError> {
    // A manifest-required flag is a durable promise that the manifest exists.
    // Publish a valid unflagged segment first so every fresh-start crash
    // window is recoverable: legacy before the manifest, manifested after it.
    let mut segment = SfaSegment::create_new(path, 0, size_bytes, created_us)?;
    if let Err(err) = segment
        .sync_header()
        .map_err(SfaQueueError::from)
        .and_then(|()| sync_directory(slot_dir).map_err(SfaQueueError::from))
    {
        drop(segment);
        let _ = remove_file_if_exists(path);
        let _ = sync_directory(slot_dir);
        return Err(err);
    }
    let manifest = match SfManifest::create(slot_dir, 0, 0) {
        Ok(manifest) => manifest,
        Err(err) => {
            drop(segment);
            let _ = remove_file_if_exists(path);
            let _ = sync_directory(slot_dir);
            return Err(err.into());
        }
    };
    if let Err(err) = segment.mark_manifest_required() {
        drop(segment);
        // Remove the segment before its manifest. If the unlink fails, the
        // retained manifest still satisfies a partially-stamped flag and
        // lets recovery retry safely.
        let segment_removed = remove_file_if_exists(path).is_ok();
        drop(manifest);
        if segment_removed {
            let _ = SfManifest::remove_file(slot_dir);
        }
        let _ = sync_directory(slot_dir);
        return Err(err.into());
    }
    Ok((segment, manifest))
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
    let dir_iter = match fs::read_dir(slot_dir) {
        Ok(iter) => iter,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            diagnostics.push(SfaRecoveryDiagnostic::CleanupFailed {
                path: slot_dir.to_path_buf(),
                error: format!("could not enumerate SFA slot: {err}"),
            });
            return Ok(());
        }
    };
    let entries = dir_iter
        .map(|entry| {
            entry.map(|entry| {
                (
                    entry.file_name().to_string_lossy().into_owned(),
                    entry.path(),
                )
            })
        })
        .collect();
    record_all_sfa_cleanup_entries(slot_dir, diagnostics, entries)
}

fn record_all_sfa_cleanup_entries(
    slot_dir: &Path,
    diagnostics: &mut Vec<SfaRecoveryDiagnostic>,
    entries: Vec<io::Result<(String, PathBuf)>>,
) -> Result<(), SfaQueueError> {
    let mut files = Vec::new();
    for entry in entries {
        let (name, path) = match entry {
            Ok(entry) => entry,
            Err(err) => {
                // Enumeration must finish before the first unlink. The names
                // collected so far are an unsafe partial view, so discard
                // them and leave the slot intact for the next recovery.
                diagnostics.push(SfaRecoveryDiagnostic::CleanupFailed {
                    path: slot_dir.to_path_buf(),
                    error: format!("could not fully enumerate SFA slot: {err}"),
                });
                return Ok(());
            }
        };
        if !is_sfa_file(&path) {
            continue;
        }
        files.push((name, path));
    }
    #[cfg(test)]
    record_sfa_barrier(SfaBarrierEvent::CleanupEnumerationComplete);
    files.sort_by(|(left_name, _), (right_name, _)| {
        segment_cleanup_rank(left_name)
            .cmp(&segment_cleanup_rank(right_name))
            .then_with(|| left_name.cmp(right_name))
    });

    let manifest_file = manifest_path(slot_dir);
    let manifest_existed = match manifest_file.try_exists() {
        Ok(existed) => existed,
        Err(err) => {
            diagnostics.push(SfaRecoveryDiagnostic::CleanupFailed {
                path: manifest_file,
                error: format!("could not inspect SF manifest before cleanup: {err}"),
            });
            return Ok(());
        }
    };
    let mut manifest = match SfManifest::open(slot_dir) {
        Ok(manifest) => manifest,
        Err(err) => {
            diagnostics.push(SfaRecoveryDiagnostic::CleanupFailed {
                path: manifest_file,
                error: format!("could not open SF manifest before cleanup: {err}"),
            });
            return Ok(());
        }
    };
    if manifest_existed && manifest.is_none() {
        // `open` quarantined an invalid manifest. A flagged segment must never
        // be deleted using an unknown boundary, even on a fully-drained close.
        diagnostics.push(SfaRecoveryDiagnostic::CleanupFailed {
            path: manifest_file,
            error: "SF manifest was invalid; retaining all segment files".to_string(),
        });
        return Ok(());
    }
    if !files.is_empty()
        && let Some(manifest) = manifest.as_mut()
    {
        let active_base = manifest.active_base();
        if let Err(err) = manifest.update(active_base, active_base) {
            diagnostics.push(SfaRecoveryDiagnostic::CleanupFailed {
                path: manifest_file,
                error: format!("could not collapse SF manifest before cleanup: {err}"),
            });
            return Ok(());
        }
        #[cfg(test)]
        record_sfa_barrier(SfaBarrierEvent::CleanupManifestCollapsed);
    }
    drop(manifest);

    for (_name, path) in files {
        if let Err(err) = remove_file_if_exists(&path) {
            diagnostics.push(SfaRecoveryDiagnostic::CleanupFailed {
                path,
                error: err.to_string(),
            });
            return Ok(());
        }
        #[cfg(test)]
        record_sfa_barrier(SfaBarrierEvent::CleanupSegmentUnlinked(_name));
    }
    if let Err(err) = sync_directory(slot_dir) {
        diagnostics.push(SfaRecoveryDiagnostic::CleanupFailed {
            path: slot_dir.to_path_buf(),
            error: err.to_string(),
        });
        return Ok(());
    }
    #[cfg(test)]
    record_sfa_barrier(SfaBarrierEvent::CleanupDirectorySynced);

    if let Err(err) = SfaAckWatermark::remove_file(slot_dir) {
        diagnostics.push(SfaRecoveryDiagnostic::CleanupFailed {
            path: ack_watermark_path(slot_dir),
            error: err.to_string(),
        });
        return Ok(());
    }
    #[cfg(test)]
    record_sfa_barrier(SfaBarrierEvent::CleanupWatermarkRemoved);
    PersistedSymbolDict::remove_orphan(slot_dir);
    match SfManifest::remove_file(slot_dir) {
        Ok(()) => {
            #[cfg(test)]
            record_sfa_barrier(SfaBarrierEvent::CleanupManifestRemoved);
        }
        Err(err) => {
            diagnostics.push(SfaRecoveryDiagnostic::CleanupFailed {
                path: manifest_file,
                error: err.to_string(),
            });
        }
    }
    if let Err(err) = sync_directory(slot_dir) {
        diagnostics.push(SfaRecoveryDiagnostic::CleanupFailed {
            path: slot_dir.to_path_buf(),
            error: format!("could not sync SFA slot after side-file cleanup: {err}"),
        });
    }
    Ok(())
}

fn remove_file_if_exists(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

fn segment_cleanup_rank(name: &str) -> (u8, u64) {
    if name == INITIAL_SEGMENT_FILE_NAME {
        return (0, 0);
    }
    match segment_generation(name) {
        Some(generation) => (1, generation),
        None => (2, 0),
    }
}

fn unix_time_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_micros().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

pub(crate) fn segment_payload_capacity(segment_size_bytes: u64) -> usize {
    segment_size_bytes
        .saturating_sub((HEADER_SIZE + FRAME_HEADER_SIZE) as u64)
        .min(usize::MAX as u64) as usize
}

/// Largest per-frame payload that still lets two frames share one segment
/// (`HEADER_SIZE + 2 * (FRAME_HEADER_SIZE + payload) <= segment_size_bytes`).
/// The publish split valve targets this size so split output amortizes
/// segment rotation over at least two frames instead of forcing a fresh
/// segment allocation per near-cap frame.
pub(crate) fn two_frame_segment_payload_capacity(segment_size_bytes: u64) -> usize {
    segment_payload_capacity(segment_size_bytes).saturating_sub(FRAME_HEADER_SIZE) / 2
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
        CloseOutcome, DriveOutcome, DriverEvent, FakeOrderedServer, QwpWsCoreTestHarness,
    };
    use super::super::qwp_ws_sfa_segment::{
        fail_sync_after_for_test, initial_segment_path, scan_file, spare_segment_path,
    };
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
            periodic_sync_interval: None,
        }
    }

    fn periodic_options_with(
        dir: &TempDir,
        segment_size_bytes: u64,
        max_bytes: usize,
        max_in_flight: usize,
    ) -> SfaQueueOptions {
        let mut options = options_with(dir, segment_size_bytes, max_bytes, max_in_flight);
        options.periodic_sync_interval = Some(Duration::from_secs(3600));
        options
    }

    fn active_is_durable(queue: &SfaFrameQueue) -> bool {
        queue
            .engine
            .with_state(|state| state.active.as_ref().unwrap().is_published_durable())
    }

    fn reset_live_durability(queue: &SfaFrameQueue) {
        let state = queue.engine.state.lock().unwrap();
        for segment in state.sealed_segments.iter().chain(state.active.iter()) {
            segment
                .durable_cursor
                .store(HEADER_SIZE as u64, Ordering::Release);
        }
        queue.engine.sync_requested.store(true, Ordering::Release);
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

    #[test]
    fn two_frame_payload_capacity_is_maximal_two_frame_packing() {
        for segment_size in [256u64, 4096, 4 * 1024 * 1024, 4 * 1024 * 1024 + 1] {
            let cap = two_frame_segment_payload_capacity(segment_size);
            let two_frames = (HEADER_SIZE + 2 * (FRAME_HEADER_SIZE + cap)) as u64;
            assert!(
                two_frames <= segment_size,
                "two capped frames must fit one {segment_size}-byte segment"
            );
            let over = (HEADER_SIZE + 2 * (FRAME_HEADER_SIZE + cap + 1)) as u64;
            assert!(
                over > segment_size,
                "cap must be maximal for a {segment_size}-byte segment"
            );
            assert!(
                cap <= segment_payload_capacity(segment_size),
                "two-frame cap can never exceed the single-frame cap"
            );
        }
    }

    #[test]
    fn periodic_rotation_waits_for_a_requested_predecessor_sync() {
        let dir = TempDir::new().unwrap();
        let segment_size = (HEADER_SIZE + 2 * (FRAME_HEADER_SIZE + 16)) as u64;
        let mut queue = SfaFrameQueue::open(periodic_options_with(
            &dir,
            segment_size,
            3 * segment_size as usize,
            8,
        ))
        .unwrap();

        assert!(queue.maintain_storage().unwrap());
        assert!(active_is_durable(&queue));
        queue.try_submit(&[1; 16]).unwrap();
        queue.try_submit(&[2; 16]).unwrap();
        assert!(!active_is_durable(&queue));
        assert!(queue.hot_spare_installed());

        let err = queue.try_submit(&[3; 16]).unwrap_err();
        assert!(matches!(
            err,
            SfaQueueError::Queue(QueueError::StorageSpareNotReady { .. })
        ));
        assert_eq!(queue.published_fsn(), Some(1));

        take_sfa_barriers();
        assert!(queue.maintain_storage().unwrap());
        assert_eq!(
            take_sfa_barriers(),
            vec![
                SfaBarrierEvent::PeriodicSyncAttempt(0),
                SfaBarrierEvent::PeriodicSyncCompleted,
            ]
        );
        assert!(active_is_durable(&queue));

        assert_eq!(queue.try_submit(&[3; 16]).unwrap().fsn, 2);
        assert_eq!(queue.sealed_segment_count(), 1);
    }

    #[test]
    fn periodic_failure_latches_without_reserving_an_fsn_and_retry_covers_live_segments() {
        let dir = TempDir::new().unwrap();
        let segment_size = (HEADER_SIZE + 2 * (FRAME_HEADER_SIZE + 16)) as u64;
        let mut queue = SfaFrameQueue::open(periodic_options_with(
            &dir,
            segment_size,
            3 * segment_size as usize,
            8,
        ))
        .unwrap();

        queue.maintain_storage().unwrap();
        queue.try_submit(&[1; 16]).unwrap();
        queue.try_submit(&[2; 16]).unwrap();
        assert!(matches!(
            queue.try_submit(&[3; 16]).unwrap_err(),
            SfaQueueError::Queue(QueueError::StorageSpareNotReady { .. })
        ));
        queue.maintain_storage().unwrap();
        queue.try_submit(&[3; 16]).unwrap();
        reset_live_durability(&queue);

        take_sfa_barriers();
        fail_sync_after_for_test(0);
        assert!(queue.maintain_storage().unwrap());
        assert!(!queue.periodic_sync_in_flight().unwrap());
        assert_eq!(
            take_sfa_barriers(),
            vec![
                SfaBarrierEvent::PeriodicSyncAttempt(0),
                SfaBarrierEvent::PeriodicSyncFailed,
            ],
            "the pass must stop at its first failed segment"
        );
        assert_eq!(
            queue.engine.with_state(|state| state.next_sync_delay),
            PERIODIC_SYNC_RETRY_MAX
        );
        take_sfa_barriers();
        queue.maintain_storage().unwrap();
        assert!(
            !take_sfa_barriers().iter().any(|event| matches!(
                event,
                SfaBarrierEvent::PeriodicSyncAttempt(_)
                    | SfaBarrierEvent::PeriodicSyncCompleted
                    | SfaBarrierEvent::PeriodicSyncFailed
            )),
            "a pending rotation request must not bypass the failure retry delay"
        );

        let first = queue.check_durability().unwrap_err();
        let second = queue.check_durability().unwrap_err();
        let (SfaQueueError::Durability(first_failure), SfaQueueError::Durability(second_failure)) =
            (first, second)
        else {
            panic!("expected a repeated durability failure");
        };
        assert!(Arc::ptr_eq(&first_failure.message, &second_failure.message));
        let published_before = queue.published_fsn();
        assert!(matches!(
            queue.try_submit(&[4; 16]).unwrap_err(),
            SfaQueueError::Durability(_)
        ));
        assert_eq!(
            queue.published_fsn(),
            published_before,
            "a latched append must not reserve an FSN"
        );

        {
            let mut state = queue.engine.state.lock().unwrap();
            state.last_sync_completed =
                Instant::now().checked_sub(PERIODIC_SYNC_RETRY_MAX + Duration::from_millis(1));
        }
        take_sfa_barriers();
        assert!(queue.maintain_storage().unwrap());
        assert!(!queue.periodic_sync_in_flight().unwrap());
        assert_eq!(
            take_sfa_barriers(),
            vec![
                SfaBarrierEvent::PeriodicSyncAttempt(0),
                SfaBarrierEvent::PeriodicSyncAttempt(2),
                SfaBarrierEvent::PeriodicSyncCompleted,
            ]
        );
        assert_eq!(
            queue.engine.with_state(|state| state.next_sync_delay),
            Duration::from_secs(3600)
        );
        queue.check_durability().unwrap();
        assert_eq!(queue.try_submit(&[4; 16]).unwrap().fsn, 3);
    }

    #[test]
    fn periodic_open_synchronously_barriers_a_memory_mode_recovery() {
        let dir = TempDir::new().unwrap();
        {
            let mut queue = SfaFrameQueue::open(options(&dir)).unwrap();
            queue.try_submit(b"recover me").unwrap();
            queue.close().unwrap();
        }

        let queue = SfaFrameQueue::open(periodic_options_with(&dir, 256, 1024, 4)).unwrap();
        assert_eq!(queue.published_fsn(), Some(0));
        assert!(
            active_is_durable(&queue),
            "periodic open must establish a durable baseline before exposing recovered frames"
        );
    }

    #[test]
    fn periodic_undrained_close_syncs_before_teardown_and_retries_after_failure() {
        let dir = TempDir::new().unwrap();
        let mut queue = SfaFrameQueue::open(periodic_options_with(&dir, 256, 1024, 4)).unwrap();
        queue.try_submit(b"still queued").unwrap();

        fail_sync_after_for_test(0);
        assert!(queue.close().is_err());
        assert!(!queue.engine.with_state(|state| state.closed));
        assert!(queue.engine.with_state(|state| state.active.is_some()));

        queue.close().unwrap();
        assert!(queue.engine.with_state(|state| state.closed));
        assert!(
            fs::read_dir(dir.path())
                .unwrap()
                .flatten()
                .any(|entry| entry.path().extension().is_some_and(|ext| ext == "sfa")),
            "undrained close must retain the synchronized backlog"
        );
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

    fn pending_payload_vec(payload: SfaMappedPayload) -> Vec<u8> {
        payload.with_bytes(|bytes| bytes.to_vec())
    }

    fn next_cursor_payload_vec(
        queue: &SfaFrameQueue,
        cursor: &mut Option<SfaSendCursor>,
        fsn: u64,
    ) -> Vec<u8> {
        pending_payload_vec(
            queue
                .next_cursor_payload_for_fsn(cursor, fsn)
                .unwrap()
                .unwrap(),
        )
    }

    fn send_cursor_segment_base_seq(cursor: &Option<SfaSendCursor>) -> Option<u64> {
        cursor.as_ref().map(|cursor| cursor.segment.base_seq())
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
        let slot_dir = path.parent().unwrap();
        if !ack_watermark_path(slot_dir).exists() {
            write_ack_watermark(slot_dir, -1);
        }
    }

    fn write_manifested_segment(path: &Path, base_seq: u64, payload: Option<&[u8]>) {
        let mut segment = SfaSegment::create_new_manifested(path, base_seq, 256, 0).unwrap();
        if let Some(payload) = payload {
            segment.try_append(payload).unwrap();
        }
        segment.sync_header().unwrap();
    }

    fn write_torn_tail_byte(path: &Path) {
        let append_offset = scan_file(path).unwrap().append_offset as usize;
        let mut bytes = fs::read(path).unwrap();
        bytes[append_offset] = 0xa5;
        fs::write(path, bytes).unwrap();
    }

    fn create_manifested_slot(dir: &Path, head_base: u64, active_base: u64) {
        let manifest = SfManifest::create(dir, head_base, active_base).unwrap();
        drop(manifest);
        write_ack_watermark(dir, -1);
    }

    fn write_bad_magic_segment(path: &Path) {
        let mut bytes = vec![0u8; 64];
        bytes[..4].copy_from_slice(&0xdead_beefu32.to_le_bytes());
        fs::write(path, bytes).unwrap();
    }

    fn write_ack_watermark(dir: &Path, fsn: i64) {
        let mut watermark = SfaAckWatermark::open(dir).unwrap();
        watermark.write(fsn).unwrap();
        watermark.sync_data().unwrap();
    }

    fn write_ack_watermark_raw(dir: &Path, magic: u32, version: u32, fsn: i64) {
        let mut bytes = vec![0u8; super::super::qwp_ws_sfa_manifest::DUAL_SLOT_FILE_SIZE as usize];
        bytes[0..4].copy_from_slice(&magic.to_le_bytes());
        bytes[4..8].copy_from_slice(&version.to_le_bytes());
        bytes[8..16].copy_from_slice(&1i64.to_le_bytes());
        bytes[16..24].copy_from_slice(&fsn.to_le_bytes());
        let crc = crc32c::crc32c(&bytes[..60]);
        bytes[60..64].copy_from_slice(&crc.to_le_bytes());
        fs::write(ack_watermark_path(dir), bytes).unwrap();
    }

    fn recovered_ack_watermark_fsn(dir: &Path) -> Option<u64> {
        assert!(
            ack_watermark_path(dir).exists(),
            "ACK watermark file should exist at {}",
            dir.display()
        );
        let mut watermark = SfaAckWatermark::open(dir).unwrap();
        watermark
            .read()
            .unwrap()
            .and_then(|fsn| u64::try_from(fsn).ok())
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

        // Rotation self-provisions under the freed budget; no maintenance
        // step is needed for the appender to make progress.
        let third = queue.try_submit(b"uvwxyz1234").unwrap();
        assert_eq!(third.fsn, 2);
        assert_eq!(queue.allocated_segment_bytes(), 96);
        assert!(!queue.hot_spare_installed());
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
        assert!(!bad_side_path.exists());
        assert!(corrupt_segment_path(&bad_side_path).exists());
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
        assert!(!bad_path.exists());
        assert!(corrupt_segment_path(&bad_path).exists());
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
        assert!(manifest_path(dir.path()).exists());
        assert!(ack_watermark_path(dir.path()).exists());
        assert!(
            scan_file_metadata(&generation_zero)
                .unwrap()
                .manifest_required
        );

        assert_eq!(queue.try_submit(b"first").unwrap(), QwpReceipt { fsn: 0 });
        assert_eq!(queue.try_submit(b"second").unwrap(), QwpReceipt { fsn: 1 });
        assert_eq!(queue.published_fsn(), Some(1));

        let scan = scan_file(generation_zero).unwrap();
        assert_eq!(scan.header.base_seq, 0);
        assert_eq!(scan.frames[0].payload, b"first");
        assert_eq!(scan.frames[1].payload, b"second");
    }

    #[test]
    fn fresh_creation_crash_windows_recover_before_and_after_manifest_publication() {
        // Crash after the initial segment is durable but before the manifest:
        // legacy recovery creates the manifest and stamps the promise flag.
        let before_manifest = TempDir::new().unwrap();
        let before_path = spare_segment_path(before_manifest.path(), 0);
        let segment = SfaSegment::create_new(&before_path, 0, 256, 0).unwrap();
        segment.sync_header().unwrap();
        drop(segment);
        sync_directory(before_manifest.path()).unwrap();
        write_ack_watermark(before_manifest.path(), -1);

        drop(open(&before_manifest));
        assert!(
            scan_file_metadata(&before_path).unwrap().manifest_required,
            "legacy recovery must finish the interrupted fresh-slot migration"
        );
        assert!(manifest_path(before_manifest.path()).exists());

        // Crash after manifest publication but before flag stamping: the
        // manifest path accepts the unflagged active and finishes the stamp.
        let before_flag = TempDir::new().unwrap();
        let before_flag_path = spare_segment_path(before_flag.path(), 0);
        let segment = SfaSegment::create_new(&before_flag_path, 0, 256, 0).unwrap();
        segment.sync_header().unwrap();
        drop(segment);
        sync_directory(before_flag.path()).unwrap();
        drop(SfManifest::create(before_flag.path(), 0, 0).unwrap());
        write_ack_watermark(before_flag.path(), -1);

        drop(open(&before_flag));
        assert!(
            scan_file_metadata(&before_flag_path)
                .unwrap()
                .manifest_required,
            "manifest recovery must finish an interrupted flag stamp"
        );

        // A manifest whose first segment dirent never reached disk is the
        // recognized collapsed empty window and starts a new generation.
        let manifest_only = TempDir::new().unwrap();
        drop(SfManifest::create(manifest_only.path(), 0, 0).unwrap());
        write_ack_watermark(manifest_only.path(), -1);

        let queue = open(&manifest_only);
        assert_eq!(queue.published_fsn(), None);
        assert_eq!(sfa_file_count(manifest_only.path()), 2);
        assert!(manifest_path(manifest_only.path()).exists());
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
        write_ack_watermark(dir.path(), -1);

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
    fn legacy_slot_migration_creates_manifest_stamps_flags_and_resets_watermark() {
        let dir = TempDir::new().unwrap();
        let initial = initial_segment_path(dir.path());
        fs::write(&initial, decode_hex_fixture(JAVA_TWO_FRAME_FIXTURE_HEX)).unwrap();
        // The pre-milestone Rust watermark was a 16-byte, CRC-less record.
        fs::write(ack_watermark_path(dir.path()), [0u8; 16]).unwrap();

        let queue = open(&dir);

        assert_eq!(queue.oldest_unresolved_fsn(), Some(42));
        assert_eq!(queue.payload_vec_for_fsn(42).as_deref(), Some(&b"one"[..]));
        let manifest = SfManifest::open(dir.path()).unwrap().unwrap();
        assert_eq!(manifest.head_base(), 42);
        assert_eq!(manifest.active_base(), 42);
        assert!(
            scan_file_metadata(&initial).unwrap().manifest_required,
            "migration must stamp the durable manifest promise"
        );
        assert_eq!(
            fs::metadata(ack_watermark_path(dir.path())).unwrap().len(),
            super::super::qwp_ws_sfa_manifest::DUAL_SLOT_FILE_SIZE
        );
        let mut watermark = SfaAckWatermark::open(dir.path()).unwrap();
        assert_eq!(watermark.read().unwrap(), None);
    }

    #[test]
    fn manifested_segments_fail_closed_when_the_manifest_disappears() {
        let dir = TempDir::new().unwrap();
        {
            let mut queue = open(&dir);
            queue.try_submit(b"unresolved").unwrap();
        }
        fs::remove_file(manifest_path(dir.path())).unwrap();
        let snapshot = |dir: &Path| -> Vec<std::ffi::OsString> {
            let mut names: Vec<_> = fs::read_dir(dir)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect();
            names.sort();
            names
        };
        let before = snapshot(dir.path());

        // The reject must not mutate the slot: every file survives byte-
        // for-byte reachable for operator recovery, and a retry fails the
        // same way instead of drifting toward quarantine.
        for _ in 0..2 {
            let err = SfaFrameQueue::open(options(&dir)).unwrap_err();
            assert!(matches!(
                err,
                SfaQueueError::Recovery { reason }
                    if reason.contains("sf-manifest.bin is missing")
            ));
        }
        assert_eq!(snapshot(dir.path()), before);
        let retained_payloads: Vec<Vec<u8>> = fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "sfa"))
            .flat_map(|path| scan_file(&path).unwrap().frames)
            .map(|frame| frame.payload)
            .collect();
        assert_eq!(retained_payloads, [b"unresolved".to_vec()]);
    }

    #[test]
    fn partially_stamped_legacy_migration_recovers_and_completes() {
        // A crash mid-migration leaves the manifest durable with only a
        // prefix of the chain stamped MANIFEST_REQUIRED. Recovery must take
        // the manifested path, keep every frame, and finish the stamping.
        let dir = TempDir::new().unwrap();
        write_manifested_segment(&spare_segment_path(dir.path(), 0), 0, Some(b"first"));
        write_segment_with_one_frame(&spare_segment_path(dir.path(), 1), 1, b"second");
        create_manifested_slot(dir.path(), 0, 1);

        let queue = open(&dir);
        assert_eq!(queue.oldest_unresolved_fsn(), Some(0));
        assert_eq!(queue.completed_fsn(), None);
        assert_eq!(queue.payload_vec_for_fsn(0).as_deref(), Some(&b"first"[..]));
        assert_eq!(
            queue.payload_vec_for_fsn(1).as_deref(),
            Some(&b"second"[..])
        );
        drop(queue);

        for generation in [0, 1] {
            let scan = scan_file_metadata(spare_segment_path(dir.path(), generation)).unwrap();
            assert!(
                scan.manifest_required,
                "sf-{generation:016x}.sfa must be stamped after recovery"
            );
        }
    }

    #[test]
    fn manifested_sealed_torn_tail_is_sanitized_then_fails_once() {
        let dir = TempDir::new().unwrap();
        let sealed = spare_segment_path(dir.path(), 0);
        let active = spare_segment_path(dir.path(), 1);
        write_manifested_segment(&sealed, 0, Some(b"sealed"));
        write_torn_tail_byte(&sealed);
        write_manifested_segment(&active, 1, None);
        create_manifested_slot(dir.path(), 0, 1);

        let err = SfaFrameQueue::open(options(&dir)).unwrap_err();
        assert!(matches!(
            err,
            SfaQueueError::SanitizedResidue { path } if path == sealed
        ));
        assert_eq!(scan_file(&sealed).unwrap().torn_tail_bytes, 0);

        let reopened = open(&dir);
        assert_eq!(
            reopened.payload_vec_for_fsn(0).as_deref(),
            Some(&b"sealed"[..])
        );
        assert_eq!(reopened.oldest_unresolved_fsn(), Some(0));
    }

    #[test]
    fn manifested_active_torn_tail_is_sanitized_without_the_one_time_failure() {
        let dir = TempDir::new().unwrap();
        let active = spare_segment_path(dir.path(), 0);
        write_manifested_segment(&active, 0, Some(b"active"));
        write_torn_tail_byte(&active);
        create_manifested_slot(dir.path(), 0, 0);

        let queue = open(&dir);

        assert_eq!(
            queue.payload_vec_for_fsn(0).as_deref(),
            Some(&b"active"[..])
        );
        assert_eq!(scan_file(&active).unwrap().torn_tail_bytes, 0);
    }

    #[test]
    fn manifest_recovery_rejects_missing_head_straddle_beyond_active_and_missing_active() {
        // Missing committed head.
        let missing_head = TempDir::new().unwrap();
        write_manifested_segment(
            &spare_segment_path(missing_head.path(), 1),
            1,
            Some(b"tail"),
        );
        create_manifested_slot(missing_head.path(), 0, 1);
        assert!(matches!(
            SfaFrameQueue::open(options(&missing_head)),
            Err(SfaQueueError::Recovery { reason })
                if reason.contains("missing expected SFA head")
        ));

        // A segment starting below the head but ending above it straddles the
        // only safe residue boundary.
        let straddle = TempDir::new().unwrap();
        let straddling_path = spare_segment_path(straddle.path(), 0);
        let mut straddling =
            SfaSegment::create_new_manifested(&straddling_path, 0, 256, 0).unwrap();
        straddling.try_append(b"zero").unwrap();
        straddling.try_append(b"one").unwrap();
        drop(straddling);
        write_manifested_segment(&spare_segment_path(straddle.path(), 2), 2, None);
        create_manifested_slot(straddle.path(), 1, 2);
        assert!(matches!(
            SfaFrameQueue::open(options(&straddle)),
            Err(SfaQueueError::Recovery { reason })
                if reason.contains("overlaps committed SFA head")
        ));

        // Data beyond the committed active boundary cannot be a hot spare.
        let beyond = TempDir::new().unwrap();
        write_manifested_segment(&spare_segment_path(beyond.path(), 0), 0, Some(b"active"));
        write_manifested_segment(&spare_segment_path(beyond.path(), 1), 1, Some(b"future"));
        create_manifested_slot(beyond.path(), 0, 0);
        assert!(matches!(
            SfaFrameQueue::open(options(&beyond)),
            Err(SfaQueueError::Recovery { reason })
                if reason.contains("beyond committed SFA active")
        ));

        // A live chain without the segment named as active is incomplete.
        let missing_active = TempDir::new().unwrap();
        write_manifested_segment(
            &spare_segment_path(missing_active.path(), 0),
            0,
            Some(b"head"),
        );
        create_manifested_slot(missing_active.path(), 0, 1);
        assert!(matches!(
            SfaFrameQueue::open(options(&missing_active)),
            Err(SfaQueueError::Recovery { reason })
                if reason.contains("missing expected SFA active")
        ));
    }

    #[test]
    fn collapsed_manifest_accepts_clean_drain_residue_but_not_unknown_corruption() {
        let clean = TempDir::new().unwrap();
        let stale = spare_segment_path(clean.path(), 0);
        write_manifested_segment(&stale, 0, Some(b"acked"));
        create_manifested_slot(clean.path(), 5, 5);

        let recovered = recover_segments(&options(&clean)).unwrap();
        assert!(recovered.segments.is_none());
        assert!(!stale.exists());
        assert!(!manifest_path(clean.path()).exists());

        let blocked = TempDir::new().unwrap();
        write_manifested_segment(&spare_segment_path(blocked.path(), 0), 0, Some(b"acked"));
        write_bad_magic_segment(&spare_segment_path(blocked.path(), 99));
        create_manifested_slot(blocked.path(), 5, 5);
        assert!(matches!(
            recover_segments(&options(&blocked)),
            Err(SfaQueueError::Recovery { reason })
                if reason.contains("missing expected SFA active")
        ));
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
        write_ack_watermark(dir.path(), -1);

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
        write_ack_watermark(dir.path(), -1);
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
        assert!(!bad_side_path.exists());
        assert!(bad_side_corrupt_path.exists());
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

    #[cfg(unix)]
    #[test]
    fn recovery_propagates_io_error_instead_of_dropping_segment() {
        let dir = TempDir::new().unwrap();
        write_segment_with_one_frame(&initial_segment_path(dir.path()), 0, b"first");
        let unreadable = spare_segment_path(dir.path(), 7);
        std::os::unix::fs::symlink("no-such-target.sfa", &unreadable).unwrap();

        let err = SfaFrameQueue::open(options(&dir)).unwrap_err();
        assert!(matches!(
            err,
            SfaQueueError::Segment(SfaSegmentError::Io(_))
        ));
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
        write_ack_watermark(dir.path(), -1);

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
        let symbol_dict = dir
            .path()
            .join(crate::ingress::sender::qwp_ws_sfa_symbol_dict::FILE_NAME);
        let mut queue = open(&dir);
        queue.try_submit(b"first").unwrap();
        queue.complete_through_fsn(0).unwrap();

        assert!(ack_watermark_path(dir.path()).exists());
        // A file-mode slot opens a persisted symbol dictionary alongside its
        // segments (delta encoding depends on it).
        assert!(symbol_dict.exists());
        queue.close().unwrap();

        assert_eq!(sfa_file_count(dir.path()), 0);
        assert!(!ack_watermark_path(dir.path()).exists());
        // The side-file is slot state too: a fully-drained close leaves nothing.
        assert!(!symbol_dict.exists());
    }

    #[test]
    fn fully_drained_close_follows_the_crash_safe_barrier_sequence() {
        let dir = TempDir::new().unwrap();
        let mut queue = SfaFrameQueue::open(options_with(&dir, 38, 152, 8)).unwrap();
        queue.try_submit(b"one").unwrap();
        queue.try_submit(b"two").unwrap();
        queue.try_submit(b"tri").unwrap();
        queue.complete_through_fsn(2).unwrap();
        take_sfa_barriers();

        queue.close().unwrap();

        assert_eq!(
            take_sfa_barriers(),
            vec![
                SfaBarrierEvent::CloseWatermarkWritten,
                SfaBarrierEvent::CloseWatermarkSynced,
                SfaBarrierEvent::CloseDirectorySynced,
                SfaBarrierEvent::CloseHandlesReleased,
                SfaBarrierEvent::CleanupEnumerationComplete,
                SfaBarrierEvent::CleanupManifestCollapsed,
                SfaBarrierEvent::CleanupSegmentUnlinked("sf-0000000000000000.sfa".to_string()),
                SfaBarrierEvent::CleanupSegmentUnlinked("sf-0000000000000001.sfa".to_string()),
                SfaBarrierEvent::CleanupSegmentUnlinked("sf-0000000000000002.sfa".to_string()),
                SfaBarrierEvent::CleanupDirectorySynced,
                SfaBarrierEvent::CleanupWatermarkRemoved,
                SfaBarrierEvent::CleanupManifestRemoved,
            ]
        );
    }

    #[test]
    fn partial_cleanup_enumeration_deletes_nothing() {
        let dir = TempDir::new().unwrap();
        let first = spare_segment_path(dir.path(), 0);
        let second = spare_segment_path(dir.path(), 1);
        fs::write(&first, b"first").unwrap();
        fs::write(&second, b"second").unwrap();
        let mut diagnostics = Vec::new();

        record_all_sfa_cleanup_entries(
            dir.path(),
            &mut diagnostics,
            vec![
                Ok((
                    first.file_name().unwrap().to_string_lossy().into_owned(),
                    first.clone(),
                )),
                Err(io::Error::other("injected partial enumeration")),
                Ok((
                    second.file_name().unwrap().to_string_lossy().into_owned(),
                    second.clone(),
                )),
            ],
        )
        .unwrap();

        assert!(first.exists());
        assert!(second.exists());
        assert!(diagnostics.iter().any(|diagnostic| matches!(
            diagnostic,
            SfaRecoveryDiagnostic::CleanupFailed { error, .. }
                if error.contains("fully enumerate")
        )));
    }

    #[test]
    fn cleanup_sorts_segments_and_stops_on_the_first_unlink_failure() {
        let dir = TempDir::new().unwrap();
        let generation_zero = spare_segment_path(dir.path(), 0);
        let failing_generation_one = spare_segment_path(dir.path(), 1);
        let active_generation_two = spare_segment_path(dir.path(), 2);
        fs::write(&generation_zero, b"acked").unwrap();
        // remove_file reliably fails on a directory on both Unix and Windows.
        fs::create_dir(&failing_generation_one).unwrap();
        fs::write(&active_generation_two, b"active").unwrap();
        create_manifested_slot(dir.path(), 0, 2);
        let mut diagnostics = Vec::new();
        take_sfa_barriers();

        record_all_sfa_cleanup(dir.path(), &mut diagnostics).unwrap();

        assert!(!generation_zero.exists());
        assert!(failing_generation_one.exists());
        assert!(
            active_generation_two.exists(),
            "ascending stop must preserve the active suffix"
        );
        assert!(ack_watermark_path(dir.path()).exists());
        let manifest = SfManifest::open(dir.path()).unwrap().unwrap();
        assert_eq!(manifest.head_base(), 2);
        assert_eq!(manifest.active_base(), 2);
        assert_eq!(
            take_sfa_barriers(),
            vec![
                SfaBarrierEvent::CleanupEnumerationComplete,
                SfaBarrierEvent::CleanupManifestCollapsed,
                SfaBarrierEvent::CleanupSegmentUnlinked("sf-0000000000000000.sfa".to_string()),
            ]
        );
    }

    #[test]
    fn collapsed_manifest_recovers_after_a_close_crash_mid_unlink() {
        let dir = TempDir::new().unwrap();
        let first = spare_segment_path(dir.path(), 0);
        let second = spare_segment_path(dir.path(), 1);
        let active = spare_segment_path(dir.path(), 2);
        write_manifested_segment(&first, 0, Some(b"zero"));
        write_manifested_segment(&second, 1, Some(b"one"));
        write_manifested_segment(&active, 2, Some(b"two"));
        create_manifested_slot(dir.path(), 0, 2);
        write_ack_watermark(dir.path(), 2);

        let mut manifest = SfManifest::open(dir.path()).unwrap().unwrap();
        manifest.update(2, 2).unwrap();
        drop(manifest);
        fs::remove_file(&first).unwrap();

        let recovered = open(&dir);

        assert_eq!(recovered.completed_fsn(), Some(2));
        assert_eq!(recovered.oldest_unresolved_fsn(), None);
        assert!(!second.exists(), "below-head residue should be cleaned");
        assert!(active.exists());
    }

    #[test]
    fn recovered_slot_without_a_side_file_falls_back_to_dense() {
        // Regression: a recovered slot whose segments already reference symbol ids
        // but whose side-file is gone (a dense-fallback session that never wrote
        // one, or a lost/deleted file) must NOT re-enable delta with an empty
        // dictionary. Seeding ids from 0 next to segments that reference [0, K)
        // would let a later delta frame resolve those stale ids to the wrong
        // symbols on a fresh server (silent corruption). It falls back to dense
        // (self-sufficient) frames instead, and does not fabricate a side-file.
        let dir = TempDir::new().unwrap();
        let symbol_dict = dir
            .path()
            .join(crate::ingress::sender::qwp_ws_sfa_symbol_dict::FILE_NAME);

        // A first session leaves an unresolved (recoverable) segment behind.
        let mut queue = open(&dir);
        queue.try_submit(b"unresolved-frame").unwrap();
        assert!(
            queue.is_delta_dict_enabled(),
            "a fresh file slot delta-encodes"
        );
        drop(queue);
        assert!(
            sfa_file_count(dir.path()) > 0,
            "an unresolved segment survives"
        );

        // Simulate a slot whose side-file does not mirror its segments.
        std::fs::remove_file(&symbol_dict).unwrap();

        let recovered = open(&dir);
        assert!(
            !recovered.is_delta_dict_enabled(),
            "a recovered slot with no matching side-file must fall back to dense"
        );
        assert!(
            recovered.recovered_symbol_dict_entries().is_empty(),
            "dense fallback seeds nothing"
        );
        assert!(
            !symbol_dict.exists(),
            "recovery must not fabricate an empty side-file next to the segments"
        );
    }

    #[test]
    fn recovered_slot_with_a_bad_magic_side_file_falls_back_to_dense() {
        // A poisoned / externally-corrupted side-file (bad magic) beside
        // recoverable segments is treated like an absent one: dense fallback, with
        // the corrupt file left untouched (never silently rewritten fresh and
        // re-enabled for delta).
        let dir = TempDir::new().unwrap();
        let symbol_dict = dir
            .path()
            .join(crate::ingress::sender::qwp_ws_sfa_symbol_dict::FILE_NAME);

        let mut queue = open(&dir);
        queue.try_submit(b"unresolved-frame").unwrap();
        drop(queue);
        std::fs::write(&symbol_dict, b"NOPEnope-poisoned-header").unwrap();

        let recovered = open(&dir);
        assert!(
            !recovered.is_delta_dict_enabled(),
            "a recovered slot with a bad-magic side-file must fall back to dense"
        );
        assert_eq!(
            std::fs::read(&symbol_dict).unwrap(),
            b"NOPEnope-poisoned-header",
            "recovery must not rewrite the corrupt side-file"
        );
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
    fn close_with_an_invalid_manifest_retains_every_segment_and_watermark() {
        let dir = TempDir::new().unwrap();
        let mut queue = open(&dir);
        queue.try_submit(b"first").unwrap();
        queue.complete_through_fsn(0).unwrap();
        let before = sfa_file_count(dir.path());
        fs::write(
            manifest_path(dir.path()),
            vec![0xa5; super::super::qwp_ws_sfa_manifest::DUAL_SLOT_FILE_SIZE as usize],
        )
        .unwrap();

        queue.close().unwrap();

        assert_eq!(sfa_file_count(dir.path()), before);
        assert!(ack_watermark_path(dir.path()).exists());
        assert!(PathBuf::from(format!("{}.corrupt", manifest_path(dir.path()).display())).exists());
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
    fn ack_watermark_round_trips_through_plain_file_io() {
        // The watermark is kept via positional file I/O (never mmap'd), so a
        // failing disk degrades to an Err/no-op instead of a SIGBUS. Pin the
        // full lifecycle: fresh open, persist, reopen, invalidate, re-persist.
        let dir = TempDir::new().unwrap();

        let mut watermark = SfaAckWatermark::open(dir.path()).unwrap();
        assert_eq!(watermark.read().unwrap(), None);
        watermark.write(42).unwrap();
        assert_eq!(watermark.read().unwrap(), Some(42));
        drop(watermark);

        let mut reopened = SfaAckWatermark::open(dir.path()).unwrap();
        assert_eq!(reopened.read().unwrap(), Some(42));
        drop(reopened);
        fs::write(ack_watermark_path(dir.path()), [0u8; 16]).unwrap();
        let mut reset = SfaAckWatermark::open(dir.path()).unwrap();
        assert_eq!(reset.read().unwrap(), None);
        drop(reset);
        assert_eq!(recovered_ack_watermark_fsn(dir.path()), None);

        let mut again = SfaAckWatermark::open(dir.path()).unwrap();
        again.write(7).unwrap();
        drop(again);
        assert_eq!(recovered_ack_watermark_fsn(dir.path()), Some(7));
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
    fn ack_watermark_unopenable_fails_recovered_slot_open() {
        // A directory squatting on the watermark path is an operational
        // failure: the file may be intact behind it, so recovery fails
        // closed (Java parity) instead of silently replaying acked frames.
        // A merely MISSING watermark is recreated instead — see
        // missing_ack_watermark_reseeds_manifested_recovery_from_segments.
        let dir = TempDir::new().unwrap();
        write_segment_with_one_frame(&spare_segment_path(dir.path(), 0), 0, b"first");
        fs::remove_file(ack_watermark_path(dir.path())).unwrap();
        fs::create_dir(ack_watermark_path(dir.path())).unwrap();

        let err = SfaFrameQueue::open(options(&dir)).unwrap_err();
        assert!(matches!(err, SfaQueueError::Io(_)), "{err:?}");
    }

    #[test]
    fn missing_ack_watermark_reseeds_manifested_recovery_from_segments() {
        let dir = TempDir::new().unwrap();
        {
            let mut queue = open(&dir);
            queue.try_submit(b"first").unwrap();
            queue.try_submit(b"second").unwrap();
            queue.complete_through_fsn(0).unwrap();
        }
        fs::remove_file(ack_watermark_path(dir.path())).unwrap();

        // The lost watermark costs at most a re-replay of already-acked
        // frames; it must not fail the open.
        let queue = open(&dir);
        assert_eq!(queue.oldest_unresolved_fsn(), Some(0));
        assert_eq!(queue.completed_fsn(), None);
        assert_eq!(queue.payload_vec_for_fsn(0).as_deref(), Some(&b"first"[..]));
        assert!(ack_watermark_path(dir.path()).exists());
    }

    #[test]
    fn ack_watermark_invalid_contents_are_ignored_and_repaired() {
        for (name, magic, reserved) in [
            ("bad magic", 0xdead_beefu32, 1u32),
            ("bad version", 0x3157_4b41, 7u32),
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
            periodic_sync_interval: None,
        })
        .unwrap();
        let server = FakeOrderedServer::ack_each_send();
        let mut driver = QwpWsCoreTestHarness::from_queue(queue, server);

        assert_eq!(
            driver.drive_once().unwrap(),
            DriveOutcome::Acked { wire_seq: 0 }
        );
        assert_eq!(
            driver.poll_event(),
            Some(DriverEvent::Sent {
                fsn: 1,
                wire_seq: 0
            })
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn missing_ack_watermark_reseeds_replay_only_orphan_open() {
        use super::super::qwp_ws_sfa_slot::SfaSlotQueue;

        // A missing watermark must not fail the orphan open: the drainer
        // would otherwise re-enqueue the slot forever, since the condition
        // is permanent but classified as retryable.
        let dir = TempDir::new().unwrap();
        let slot_dir = dir.path().join("orphan");
        fs::create_dir(&slot_dir).unwrap();
        write_segment_with_one_frame(&spare_segment_path(&slot_dir, 0), 0, b"first");
        write_segment_with_one_frame(&spare_segment_path(&slot_dir, 1), 1, b"second");
        fs::remove_file(ack_watermark_path(&slot_dir)).unwrap();

        let queue = SfaSlotQueue::open_replay_only_existing(SfaQueueOptions {
            slot_dir,
            segment_size_bytes: 256,
            max_bytes: 1024,
            max_in_flight: 4,
            periodic_sync_interval: None,
        })
        .unwrap();
        let server = FakeOrderedServer::ack_each_send();
        let mut driver = QwpWsCoreTestHarness::from_queue(queue, server);

        assert_eq!(
            driver.drive_once().unwrap(),
            DriveOutcome::Acked { wire_seq: 0 }
        );
        assert_eq!(
            driver.poll_event(),
            Some(DriverEvent::Sent {
                fsn: 0,
                wire_seq: 0
            })
        );
    }

    #[test]
    fn missing_ack_watermark_keeps_legacy_recovery() {
        let dir = TempDir::new().unwrap();
        write_segment_with_one_frame(&initial_segment_path(dir.path()), 3, b"legacy");
        fs::remove_file(ack_watermark_path(dir.path())).unwrap();
        assert!(!ack_watermark_path(dir.path()).exists());

        let queue = open(&dir);

        assert_eq!(queue.oldest_unresolved_fsn(), Some(3));
        assert_eq!(queue.completed_fsn(), Some(2));
        assert_eq!(
            queue.payload_vec_for_fsn(3).as_deref(),
            Some(&b"legacy"[..])
        );
        assert!(ack_watermark_path(dir.path()).exists());
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
        let mut send_cursor = None;

        assert_eq!(next_cursor_payload_vec(&queue, &mut send_cursor, 0), b"one");
        assert_eq!(send_cursor_segment_base_seq(&send_cursor).unwrap(), 1);
        assert_eq!(next_cursor_payload_vec(&queue, &mut send_cursor, 1), b"two");
        assert_eq!(send_cursor_segment_base_seq(&send_cursor).unwrap(), 2);
        assert_eq!(next_cursor_payload_vec(&queue, &mut send_cursor, 2), b"tri");
        assert_eq!(send_cursor_segment_base_seq(&send_cursor).unwrap(), 3);
        assert_eq!(next_cursor_payload_vec(&queue, &mut send_cursor, 3), b"for");
    }

    #[test]
    fn send_cursor_repositions_after_delayed_rotation() {
        let mut queue = SfaFrameQueue::open_memory(memory_options(38, 38 * 8, 4)).unwrap();
        submit_with_storage_maintenance(&mut queue, b"one");
        let mut send_cursor = None;

        assert_eq!(next_cursor_payload_vec(&queue, &mut send_cursor, 0), b"one");

        submit_with_storage_maintenance(&mut queue, b"two");

        assert_eq!(next_cursor_payload_vec(&queue, &mut send_cursor, 1), b"two");
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
        let mut send_cursor = None;

        assert_eq!(next_cursor_payload_vec(&queue, &mut send_cursor, 0), b"one");

        alloc_counter::start_counting();
        let second = queue
            .next_cursor_payload_for_fsn(&mut send_cursor, 1)
            .unwrap()
            .unwrap();
        let sealed_alloc_count = alloc_counter::stop_counting();
        assert_eq!(
            sealed_alloc_count, 0,
            "Expected zero allocations when sending from the next sealed segment, got {sealed_alloc_count}"
        );
        assert_eq!(pending_payload_vec(second), b"two");

        alloc_counter::start_counting();
        let third = queue
            .next_cursor_payload_for_fsn(&mut send_cursor, 2)
            .unwrap()
            .unwrap();
        let transition_alloc_count = alloc_counter::stop_counting();
        assert_eq!(
            transition_alloc_count, 0,
            "Expected zero allocations when advancing from sealed to active segment, got {transition_alloc_count}"
        );
        assert_eq!(pending_payload_vec(third), b"tri");
        assert_eq!(send_cursor_segment_base_seq(&send_cursor), Some(3));
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
    fn rotation_syncs_the_promoted_header_before_manifest_and_queue_mutation() {
        let dir = TempDir::new().unwrap();
        let mut queue = SfaFrameQueue::open(options_with(&dir, 38, 76, 4)).unwrap();
        queue.try_submit(b"first").unwrap();
        take_sfa_barriers();

        queue.try_submit(b"second").unwrap();

        assert_eq!(
            take_sfa_barriers(),
            vec![
                SfaBarrierEvent::RotationHeaderSynced,
                SfaBarrierEvent::RotationManifestUpdated,
                SfaBarrierEvent::RotationQueueMutated,
            ]
        );
    }

    #[test]
    fn trim_covers_the_unlink_with_watermark_and_manifest_barriers_before_pop() {
        let dir = TempDir::new().unwrap();
        let mut queue = SfaFrameQueue::open(options_with(&dir, 38, 114, 4)).unwrap();
        queue.try_submit(b"first").unwrap();
        queue.try_submit(b"second").unwrap();
        queue.complete_through_fsn(0).unwrap();
        take_sfa_barriers();

        let step = queue.take_storage_maintenance_step(false).unwrap().unwrap();

        assert_eq!(
            take_sfa_barriers(),
            vec![
                SfaBarrierEvent::TrimWatermarkWritten,
                SfaBarrierEvent::TrimWatermarkSynced,
                SfaBarrierEvent::TrimDirectorySynced,
                SfaBarrierEvent::TrimManifestUpdated,
                SfaBarrierEvent::TrimQueuePopped,
            ]
        );
        assert!(matches!(step, SfaStorageStep::Trim(_)));
        step.perform().unwrap();
    }

    #[test]
    fn rotation_allocates_inline_when_hot_spare_missing() {
        // Budget for 4 segments; active + hot spare are pre-created. After the
        // spare is consumed by the first rotation, further rotations must
        // self-provision segments inline — without any maintenance running
        // (the runner may be parked in a blocking socket send) — until the
        // byte budget is exhausted.
        let mut queue = SfaFrameQueue::open_memory(memory_options(48, 192, 16)).unwrap();

        assert_eq!(queue.try_submit(b"abcdefghij").unwrap().fsn, 0);
        assert_eq!(queue.try_submit(b"klmnopqrst").unwrap().fsn, 1);
        assert!(!queue.hot_spare_installed());

        assert_eq!(queue.try_submit(b"uvwxyz1234").unwrap().fsn, 2);
        assert_eq!(queue.allocated_segment_bytes(), 144);
        assert_eq!(queue.try_submit(b"5678901234").unwrap().fsn, 3);
        assert_eq!(queue.allocated_segment_bytes(), 192);
        assert!(matches!(
            queue.try_submit(b"abcdefghij"),
            Err(SfaQueueError::Queue(QueueError::StorageSegmentCapFull {
                segment_size_bytes: 48,
                allocated_segment_bytes: 192,
                max_total_bytes: 192,
            }))
        ));
        assert_eq!(
            queue.payload_vec_for_fsn(2).as_deref(),
            Some(&b"uvwxyz1234"[..])
        );
        assert_eq!(
            queue.payload_vec_for_fsn(3).as_deref(),
            Some(&b"5678901234"[..])
        );
    }

    #[test]
    fn detached_producer_rotation_survives_stalled_runner_maintenance() {
        let dir = TempDir::new().unwrap();
        let mut queue = SfaFrameQueue::open(options_with(&dir, 38, 152, 8)).unwrap();
        let mut producer = queue.take_producer().unwrap();

        assert_eq!(producer.try_submit(b"one").unwrap().fsn, 0);
        assert_eq!(producer.try_submit(b"two").unwrap().fsn, 1);
        // No maintenance between submits (runner parked in a blocking send):
        // the detached producer must provision segment files inline up to the
        // byte budget, and every stall-window frame stays replayable.
        assert_eq!(producer.try_submit(b"tri").unwrap().fsn, 2);
        assert_eq!(sfa_file_count(dir.path()), 3);
        assert_eq!(producer.try_submit(b"for").unwrap().fsn, 3);
        assert_eq!(sfa_file_count(dir.path()), 4);
        assert!(matches!(
            producer.try_submit(b"fiv"),
            Err(SfaQueueError::Queue(
                QueueError::StorageSegmentCapFull { .. }
            ))
        ));
        assert_eq!(queue.payload_vec_for_fsn(2).as_deref(), Some(&b"tri"[..]));
        assert_eq!(queue.payload_vec_for_fsn(3).as_deref(), Some(&b"for"[..]));
    }

    #[test]
    fn progress_maintains_missing_hot_spare_when_capacity_allows() {
        let dir = TempDir::new().unwrap();
        let mut queue = SfaFrameQueue::open(options_with(&dir, 38, 114, 4)).unwrap();

        queue.try_submit(b"first").unwrap();
        queue.try_submit(b"second").unwrap();
        assert_eq!(sfa_file_count(dir.path()), 2);
        assert!(!queue.hot_spare_installed());

        assert!(queue.maintain_storage().unwrap());
        assert!(queue.hot_spare_installed());
        assert_eq!(sfa_file_count(dir.path()), 3);

        // Rotation prefers the prepared spare: no extra segment is created.
        assert_eq!(queue.try_submit(b"third").unwrap(), QwpReceipt { fsn: 2 });
        assert_eq!(sfa_file_count(dir.path()), 3);
        assert!(!queue.hot_spare_installed());
    }

    #[test]
    fn detached_producer_rotates_replays_and_trims_runner_owned_segments() {
        let dir = TempDir::new().unwrap();
        let mut queue = SfaFrameQueue::open(options_with(&dir, 38, 114, 4)).unwrap();
        let mut producer = queue.take_producer().unwrap();

        assert_eq!(producer.try_submit(b"one").unwrap(), QwpReceipt { fsn: 0 });
        assert_eq!(producer.try_submit(b"two").unwrap(), QwpReceipt { fsn: 1 });
        // The detached producer self-provisions its rotation segment when no
        // spare is prepared (no maintenance has run).
        assert_eq!(producer.try_submit(b"tri").unwrap(), QwpReceipt { fsn: 2 });
        assert_eq!(sfa_file_count(dir.path()), 3);
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
        write_ack_watermark(dir.path(), -1);

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
        // The failed unlink freed logical capacity, so rotation
        // self-provisions a new segment under the budget.
        assert_eq!(queue.try_submit(b"third").unwrap(), QwpReceipt { fsn: 2 });
        assert_eq!(queue.allocated_segment_bytes(), 76);
    }

    #[test]
    fn driver_close_drain_removes_sfa_files_after_delivery() {
        let dir = TempDir::new().unwrap();
        let queue = open(&dir);
        let server = FakeOrderedServer::ack_each_send();
        let mut driver = QwpWsCoreTestHarness::from_queue(queue, server);
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
            let mut driver = QwpWsCoreTestHarness::from_queue(queue, server);
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
        write_ack_watermark(dir.path(), -1);
        let queue = open(&dir);
        let server = FakeOrderedServer::ack_each_send();
        let mut driver = QwpWsCoreTestHarness::from_queue(queue, server);

        assert_eq!(
            driver.drive_once().unwrap(),
            DriveOutcome::Acked { wire_seq: 0 }
        );
        assert_eq!(
            driver.drive_once().unwrap(),
            DriveOutcome::Acked { wire_seq: 1 }
        );
        let mut sent_fsns = Vec::new();
        while let Some(event) = driver.poll_event() {
            if let DriverEvent::Sent { fsn, .. } = event {
                sent_fsns.push(fsn);
            }
        }
        assert_eq!(sent_fsns, vec![42, 43]);
    }
}
