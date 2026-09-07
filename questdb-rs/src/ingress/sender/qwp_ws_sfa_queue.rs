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
use super::qwp_ws_sfa_catchup::SentDictMirror;
use super::qwp_ws_sfa_manifest::{
    SfManifest, SfaAckWatermark, ack_watermark_path, manifest_path, sync_directory,
};
use super::qwp_ws_sfa_segment::{
    FRAME_HEADER_SIZE, HEADER_SIZE, INITIAL_SEGMENT_FILE_NAME, SfaMappedPayload, SfaSegment,
    SfaSegmentError, scan_file_metadata, spare_segment_path,
};
use super::qwp_ws_sfa_symbol_dict::PersistedSymbolDict;

const PERIODIC_SYNC_RETRY_MAX: Duration = Duration::from_secs(1);
const TRIM_BARRIER_RETRY_DELAY: Duration = Duration::from_secs(1);
// Keep a trim turn bounded while amortizing the crash-consistency barriers.
// Matches Java's SegmentManager quantum.
const MAX_TRIMS_PER_STORAGE_STEP: usize = 64;

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
    TrimSegmentUnlinked(String),
    TrimCleanupDirectorySynced,
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
    pub(crate) periodic_sync_interval: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SfaMemoryQueueOptions {
    pub(crate) segment_size_bytes: u64,
    pub(crate) max_bytes: usize,
}

#[derive(Debug)]
pub(crate) enum SfaQueueError {
    Queue(QueueError),
    Segment(SfaSegmentError),
    Io(io::Error),
    InvalidSfDir,
    InvalidSenderId {
        sender_id: String,
    },
    SlotInUse {
        slot_dir: PathBuf,
        holder: String,
    },
    SlotLockUnsupported,
    CorruptSegments {
        reason: &'static str,
    },
    Recovery {
        reason: String,
    },
    /// Recovery durably removed proven-dead bytes beyond the last accounted
    /// frame. Damage that removes an expected frame fails validation before
    /// mutation.
    ///
    /// Foreground startup reports this once so the attended caller retries;
    /// orphan recovery retries once internally. This mirrors Java's
    /// `SfSanitizedResidueException` contract.
    SanitizedResidue {
        path: PathBuf,
    },
    Durability(SfaDurabilityFailure),
    StorageMaintenanceInFlight,
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
        cleanup_failures: Vec<SfaCleanupFailure>,
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
    segments: Vec<Arc<SfaSharedSegment>>,
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
                cleanup_failures: cleanup.perform_trim(),
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
        Self {
            segments: vec![segment],
        }
    }

    fn new_batch(segments: Vec<Arc<SfaSharedSegment>>) -> Self {
        debug_assert!(!segments.is_empty());
        Self { segments }
    }

    pub(crate) fn perform(self) -> Option<SfaCleanupFailure> {
        self.perform_inner(false).into_iter().next()
    }

    fn perform_trim(self) -> Vec<SfaCleanupFailure> {
        self.perform_inner(true)
    }

    fn perform_inner(self, _record_trim_barriers: bool) -> Vec<SfaCleanupFailure> {
        let mut failures = Vec::new();
        let mut slot_dir = None;
        let mut removed_path = None;

        for segment in self.segments {
            let path = segment.path().map(Path::to_path_buf);
            drop(segment);
            let Some(path) = path else {
                continue;
            };
            let Some(parent) = path.parent() else {
                failures.push(SfaCleanupFailure {
                    path,
                    error: "SFA segment path has no parent directory".to_string(),
                });
                continue;
            };
            match slot_dir.as_ref() {
                Some(slot_dir) => debug_assert_eq!(slot_dir, parent),
                None => slot_dir = Some(parent.to_path_buf()),
            }
            match fs::remove_file(&path) {
                Ok(()) => {
                    #[cfg(test)]
                    if _record_trim_barriers {
                        record_sfa_barrier(SfaBarrierEvent::TrimSegmentUnlinked(
                            path.file_name()
                                .map(|name| name.to_string_lossy().into_owned())
                                .unwrap_or_else(|| path.display().to_string()),
                        ));
                    }
                    if removed_path.is_none() {
                        removed_path = Some(path);
                    }
                }
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                Err(err) => {
                    failures.push(SfaCleanupFailure {
                        path,
                        error: err.to_string(),
                    });
                }
            }
        }

        // The manifest already places every trim-batch member below its
        // durable head. Any failed or crash-restored unlink is therefore
        // harmless stale residue; one directory barrier covers all removals
        // that did succeed.
        if let (Some(slot_dir), Some(path)) = (slot_dir.as_deref(), removed_path.as_ref()) {
            match sync_directory(slot_dir) {
                Ok(()) => record_trim_cleanup_directory_sync(_record_trim_barriers),
                Err(err) => {
                    failures.push(SfaCleanupFailure {
                        path: path.clone(),
                        error: err.to_string(),
                    });
                }
            }
        }

        failures
    }
}

fn record_trim_cleanup_directory_sync(_enabled: bool) {
    #[cfg(test)]
    if _enabled {
        record_sfa_barrier(SfaBarrierEvent::TrimCleanupDirectorySynced);
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
    /// The recovered dictionary handed to the producer and the driver mirror:
    /// the side-file's intact prefix, EXTENDED by every id the surviving frames
    /// define above it (see
    /// [`rebuild_recovered_dict_from_frames`](Self::rebuild_recovered_dict_from_frames)).
    ///
    /// Owned rather than borrowed from `persisted_symbol_dict` because the
    /// side-file is only one of the two sources: a host crash can tear off the
    /// dictionary's newest entries while the frames that introduced those ids
    /// survive, and those frames carry the missing symbols in their own delta
    /// sections. Seeding from the short side-file alone would hand the producer's
    /// next new symbol an id the surviving frames already define.
    recovered_dict_entries: Vec<u8>,
    /// Entry count matching [`recovered_dict_entries`](Self::recovered_dict_entries).
    recovered_dict_count: u32,
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
    // Optional trim barriers retry without blocking publication or other
    // storage maintenance.
    trim_retry_at: Option<Instant>,
    // Reserves an ordered rotation/trim manifest transaction while its disk
    // barriers run without the state mutex. Readers continue against the old
    // topology; competing writers and close defer until commit/rollback.
    topology_io_in_flight: bool,
    // Covers the full off-lock task, including any cleanup returned by finish.
    storage_maintenance_in_flight: bool,
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
            // Recovered slot. A transient I/O error fails construction loudly
            // (retryable, data intact) rather than destroying a dictionary it merely
            // failed to read.
            //
            // An absent / too-short / bad-magic / unknown-version file used to fall
            // back to dense here, on the argument that arming delta over an EMPTY
            // dictionary next to segments referencing ids [0, K) would let a later
            // frame resolve those stale ids to the wrong symbols. That argument
            // predates `rebuild_recovered_dict_from_frames`: the ids are no longer
            // taken from the (missing) file, they are rebuilt from the surviving
            // frames' own delta sections, and where the frames cannot supply them --
            // acked and trimmed away -- the count stops short and
            // `guard_dict_not_torn` rejects the dependent frame BEFORE anything
            // commits.
            //
            // Dense, meanwhile, is not neutral: with the mirror disabled the guard
            // lets every `delta_start == 0` frame through and rejects the first
            // `delta_start > 0` frame behind it -- so the caller gets
            // `StoreResendRequired` with `in_doubt == false` ("re-ingest from
            // source") sitting on top of an already-committed prefix, and a
            // compliant resend duplicates those rows. That is the same outcome the
            // zero-entry branch below is written to avoid, and the driver cannot
            // tell the two apart. So re-create the file fresh and keep delta armed:
            // the rebuild reconstructs the ids, and the first write-ahead
            // re-persists them (it anchors to the side-file's tip, see
            // `persist_new_symbols`), healing the file. Re-creating also reclaims a
            // rejected oversize file instead of leaving it to be re-read and
            // re-rejected on every later open.
            //
            // A side-file that PARSES but loads zero entries -- a header whose
            // FIRST chunk the reader rejected, so `open_recovered` hands back
            // `Some(dict)` with `size() == 0` -- reaches the same armed-empty state
            // by the same argument. It is worth naming separately only because it
            // arrives through a different branch: the file opens, so there is
            // nothing to re-create, and the handle is already usable for
            // write-ahead.
            //
            // The hazard an armed-empty dictionary WOULD carry is the producer
            // refilling the file with different symbols at ids the surviving frames
            // reference -- and that one is not a narrow window, it is a certainty:
            // seeded from an empty file the producer's `next_id` is 0 while the
            // replayed frames define ids [0, K), so its very first new symbol takes
            // an id one of them already owns. `conflicts_with` then terminally fails
            // the store, AFTER the backlog replayed. That is what the rebuild below
            // removes, and it is what makes arming empty safe on every branch.
            //
            // So the dictionary handed to the producer is not the side-file's
            // prefix: `rebuild_recovered_dict_from_frames` extends it with every id
            // the surviving frames define in their OWN delta sections, using the
            // same `SentDictMirror` fold the driver applies as those frames go back
            // on the wire. Producer and mirror therefore resume on the same count by
            // construction. (Matches the Java client's
            // `seedGlobalDictionaryFromPersisted`.)
            //
            // That leaves the producer AHEAD of the side-file, which the write-ahead
            // heals rather than compounds: `persist_new_symbols` (both publishers)
            // takes its start id from the SIDE-FILE's tip, not from the producer's,
            // so the first frame after recovery re-persists the frame-derived ids
            // too. Anchoring it to the producer instead would append id `K'` at file
            // position `K` and break the file's dense `id == position` invariant for
            // good -- see the note there.
            match PersistedSymbolDict::open_recovered(&options.slot_dir)? {
                Some(dict) => Some(dict),
                None => {
                    // Absent / too short / bad magic / unknown version. Log it: this
                    // is the one recovery decision that used to happen silently, and
                    // an operator seeing delta frames rebuilt from the queue rather
                    // than from disk should be able to find out why.
                    log::warn!(
                        "QWP/WebSocket store-and-forward slot {}: no usable persisted \
                         symbol dictionary (absent, truncated, or written by an \
                         incompatible version); re-creating it and rebuilding the \
                         dictionary from the stored frames.",
                        options.slot_dir.display()
                    );
                    // `open` re-creates a fresh header over whatever is there, so
                    // the producer regains a write-ahead target. Every error it can
                    // return here is a *transient* I/O failure -- a proven-corrupt
                    // file re-creates to `Ok` via `open_fresh`, and only
                    // stat/open/read/create/write errors surface as `Err` -- so
                    // propagate it rather than swallowing it to dense with `.ok()`.
                    // Dense is NOT neutral while delta frames survive: it leaves the
                    // mirror disabled, so the `delta_start == 0` frame replays and
                    // COMMITS, the `delta_start > 0` frame behind it is rejected
                    // `StoreResendRequired` (`in_doubt == false`), and a compliant
                    // resend duplicates the committed rows -- the exact hazard this
                    // branch is written to avoid. Failing construction is retryable
                    // and leaves the slot intact on disk for the next attempt,
                    // exactly as `open_recovered` does for its own transient errors
                    // above. (A genuinely unusable disk then fails loudly on every
                    // retry rather than silently duplicating.)
                    Some(PersistedSymbolDict::open(&options.slot_dir)?)
                }
            }
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
        // Kept for the rebuild's diagnostics below: the engine takes ownership of
        // `options.slot_dir` on the next line. One clone per slot open, on a path
        // that already maps segments and scans the backlog.
        let slot_dir = options.slot_dir.clone();
        let engine = Arc::new(SfaEngine {
            slot_dir: Some(options.slot_dir),
            max_bytes: options.max_bytes,
            segment_size_bytes: options.segment_size_bytes,
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
                trim_retry_at: None,
                topology_io_in_flight: false,
                storage_maintenance_in_flight: false,
                closed: false,
            }),
            published_upper: AtomicU64::new(next_fsn),
            completed_upper: AtomicU64::new(recovered_completion.completed_upper),
            sync_requested: AtomicBool::new(false),
            durability_failed: AtomicBool::new(false),
        });
        let producer = Some(SfaProducer {
            engine: Arc::clone(&engine),
            active,
            active_append_offset,
            active_frame_count,
            next_fsn,
        });

        let mut queue = Self {
            engine,
            producer,
            ack_watermark: recovered_completion.ack_watermark,
            delta_dict_enabled,
            persisted_symbol_dict,
            recovered_dict_entries: Vec::new(),
            recovered_dict_count: 0,
        };
        // This slot has a PRODUCER, so the recovered dictionary must cover every id
        // the surviving frames define -- not just the side-file's intact prefix.
        queue.rebuild_recovered_dict_from_frames(&slot_dir)?;
        Ok(queue)
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
                trim_retry_at: None,
                topology_io_in_flight: false,
                storage_maintenance_in_flight: false,
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
            // Nothing is recovered in memory mode: the queue starts empty, so the
            // producer's id space starts at 0 with no surviving frames to collide.
            recovered_dict_entries: Vec::new(),
            recovered_dict_count: 0,
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
        // persisted symbol dictionary to re-register delta frames. A transient I/O
        // error fails this drain attempt (retryable; the orphan stays recoverable
        // on disk) rather than truncating the load-bearing side-file.
        //
        // Delta stays ARMED whatever the file turns out to be -- loaded, empty,
        // absent, or unreadable. Replay-only has no producer, so the refill hazard
        // that made an empty dictionary worth distrusting in `open` cannot arise
        // here at all: the dictionary is read-only for the whole drain and
        // `qwp_ws_orphan::open` drops the handle outright.
        //
        // What dense costs, meanwhile, is the slot. `is_delta_dict_enabled` gates
        // seeding the drainer's catch-up mirror, so dense leaves it disabled: the
        // drainer replays the `delta_start == 0` frame, `guard_dict_not_torn`
        // terminally rejects the `delta_start == K` frame behind it, and
        // `OrphanDriveOutcome::RetryLater` puts the slot back on the pending queue
        // -- where the next open re-reads the same file and re-decides dense. It
        // never drains and never fails: it live-locks, holding a drainer for the
        // life of the process while the frames behind the first stay undelivered
        // and the replayed prefix is re-sent each cycle. Armed, the mirror
        // bootstraps from the frames' own delta sections (`SentDictMirror::
        // accumulate`) and the slot drains; where the frames cannot supply an id,
        // the guard rejects that frame BEFORE anything commits, which is the same
        // loud outcome dense reaches only after committing a prefix.
        //
        // No re-create here, unlike `open`: there is no producer to give a
        // write-ahead target to, and a drainer must not write to a slot another
        // process may still own.
        // `mut` so the recovered entry region can be MOVED out below rather than
        // copied; see the note at that call site.
        let mut persisted_symbol_dict = PersistedSymbolDict::open_recovered(&options.slot_dir)?;
        if persisted_symbol_dict.is_none() {
            log::warn!(
                "QWP/WebSocket orphan slot {}: no usable persisted symbol dictionary \
                 (absent, truncated, or written by an incompatible version); draining \
                 with the dictionary the stored frames carry.",
                options.slot_dir.display()
            );
        }
        let delta_dict_enabled = true;
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
                trim_retry_at: None,
                topology_io_in_flight: false,
                storage_maintenance_in_flight: false,
                closed: false,
            }),
            published_upper: AtomicU64::new(next_fsn),
            completed_upper: AtomicU64::new(recovered_completion.completed_upper),
            sync_requested: AtomicBool::new(false),
            durability_failed: AtomicBool::new(false),
        });

        // MOVE the recovered region out of the handle rather than copying it. A
        // `to_vec` here would be an infallible allocation of up to `MAX_FILE_LEN`
        // (~2 GiB for a crafted CRC-valid side-file) on the orphan drainer's
        // background thread, and Rust's allocator ABORTS the host process on OOM --
        // exactly what `qwp_ws_orphan`'s `try_dup_recovered` of these same bytes
        // exists to prevent, and what the reader's own `try_reserve`s uphold. A copy
        // here would sit upstream of that guard, so the guard could never fire.
        // Moving also keeps the orphan-open peak at two concurrent copies rather
        // than three. The handle keeps its `file` / `append_offset` / `size`, which
        // is all replay-only ever needs from it.
        let (recovered_dict_entries, recovered_dict_count) = persisted_symbol_dict
            .as_mut()
            .map_or_else(Default::default, |pd| (pd.take_loaded_entries(), pd.size()));
        Ok(Self {
            engine,
            producer: None,
            ack_watermark: recovered_completion.ack_watermark,
            delta_dict_enabled,
            persisted_symbol_dict,
            // Replay-only: the side-file's prefix verbatim, with NO frame-derived
            // extension. The extension exists to keep a producer's next id above
            // the surviving frames' ids, and this path builds no producer -- the
            // drainer's own mirror still folds each frame's delta in as it replays
            // (`SentDictMirror::accumulate`), which is what makes the drain work on
            // a torn dictionary. Scanning every frame up front here would cost a
            // full extra pass to reach the same mirror state.
            recovered_dict_entries,
            recovered_dict_count,
        })
    }

    /// Whether this slot delta-encodes symbol dictionaries (see the field docs).
    pub(crate) fn is_delta_dict_enabled(&self) -> bool {
        self.delta_dict_enabled
    }

    /// The recovered symbol-dict entries (`[len][utf8]...` in id order) used to
    /// seed the producer dict and the driver mirror on recovery / orphan-drain.
    /// Empty for a fresh slot or memory mode.
    ///
    /// On a slot with a producer this is the side-file's prefix PLUS every id the
    /// surviving frames define above it; see
    /// [`rebuild_recovered_dict_from_frames`](Self::rebuild_recovered_dict_from_frames).
    pub(crate) fn recovered_symbol_dict_entries(&self) -> &[u8] {
        &self.recovered_dict_entries
    }

    /// Number of recovered symbol-dict entries.
    pub(crate) fn recovered_symbol_dict_count(&self) -> u32 {
        self.recovered_dict_count
    }

    /// Rebuilds the recovered dictionary from BOTH sources the driver's mirror is
    /// built from, in the same order, so the producer's next id and the mirror's
    /// count land on the same number **by construction**:
    ///
    /// 1. the side-file's intact prefix (already loaded at `open`), then
    /// 2. every id the surviving frames define above it, read out of those frames'
    ///    own delta sections.
    ///
    /// Source 2 is not redundant. The side-file is not fsync'd (see
    /// [`super::qwp_ws_sfa_symbol_dict`]), so a host/power crash can tear off its
    /// newest entries while the frames that introduced those ids survive — and the
    /// newest frames, being the least likely to be acked, are exactly the ones that
    /// replay. Seeded from the short prefix alone the producer's `next_id` sits
    /// BELOW ids the surviving frames already define, so its first new symbol takes
    /// an id one of those frames uses for a different string. The driver's mirror
    /// has meanwhile accumulated the real mapping from the replayed frames, so
    /// `guard_dict_not_torn`'s `conflicts_with` sees a differing redefinition of a
    /// held id and terminally fails the store (`StoreResendRequired`) — after the
    /// backlog already replayed. That is a guaranteed kill on the first new symbol,
    /// not a rare race.
    ///
    /// The fold is done by [`SentDictMirror`] itself over the same frame range the
    /// driver replays (`[oldest_unresolved_fsn, published_upper)`, the range its
    /// send cursor walks), so this cannot drift from the live mirror's arithmetic.
    /// A frame whose `delta_start` is ABOVE the running count is a genuine gap —
    /// its ids came from frames since acked and trimmed, and nothing can rebuild
    /// them — so `accumulate` skips it and the count stops there, leaving exactly
    /// the torn-dictionary case `guard_dict_not_torn` already reports.
    ///
    /// The fold stops on one more condition, and `accumulate` alone will not
    /// supply it: a frame that *disagrees* with the running mirror about an id it
    /// already holds. `accumulate` matches on POSITION only, so it would append
    /// such a frame's suffix on top of a contradicting prefix and yield a region
    /// with repeated ids — which `SymbolGlobalDict::seed` then rejects wholesale as
    /// a duplicate entry, failing construction on every later open and blaming a
    /// side-file that is byte-perfect. So each frame is put to
    /// [`conflicts_with`](SentDictMirror::conflicts_with) — the same question
    /// `guard_dict_not_torn` asks before sending — and a disagreement stops the
    /// fold exactly as a gap does. This needs frames that were written against a
    /// different dictionary generation than the side-file (a session that ran
    /// dense because the side-file was unwritable, say); it cannot fire on a
    /// contiguous `delta_start == tip` extension, which overlaps nothing.
    ///
    /// Cheap on the common path: an untorn side-file already covers every id, so
    /// every frame folds to a no-op overlap and only the (cold, once-per-open) scan
    /// remains. The scan is bounded by the configured store-and-forward byte ring.
    ///
    /// # The side-file is left SHORT, deliberately
    ///
    /// This does not write the rebuilt ids back. On return the producer resumes at
    /// `K'` while the side-file still holds only its intact prefix `K`, and the
    /// write-ahead closes the gap on the next frame because
    /// `persist_new_symbols` anchors to the side-file's tip rather than the
    /// producer's id. Healing lazily rather than here keeps `open` read-only on the
    /// dictionary (a crash in the window before the first flush just re-runs this
    /// rebuild against the same intact prefix) and keeps a write failure out of the
    /// recovery path.
    fn rebuild_recovered_dict_from_frames(&mut self, slot_dir: &Path) -> Result<(), SfaQueueError> {
        let mut mirror = SentDictMirror::new(true);
        if let Some(pd) = self.persisted_symbol_dict.as_ref() {
            // `seed`'s allocation-failure degrade (disable the mirror, keep going) is
            // written for the DRIVER's mirror, where a disabled mirror makes the
            // torn-dict guard reject frames rather than ship them. Here the mirror is
            // a fold helper over recovered state, so the same degrade would instead
            // no-op every `accumulate`, leave `recovered_dict_count` at 0, and (below)
            // free the side-file's only in-memory copy -- while `delta_dict_enabled`
            // stays true. The producer would then resume at id 0 against frames
            // defining [0, K): the guaranteed collision this whole function exists to
            // prevent, reached by an allocation failure instead of prevented by one.
            // Fail construction instead, leaving the slot intact on disk for a retry.
            if !mirror.seed(pd.loaded_entries(), pd.size()) {
                return Err(SfaQueueError::Io(io::Error::other(
                    "could not allocate the recovered symbol dictionary while \
                     rebuilding it from the stored frames",
                )));
            }
        } else {
            // No side-file: nothing was recovered and nothing may be delta-encoded
            // against it, so there is no id space to align.
            return Ok(());
        }
        if let Some(oldest) = self.oldest_unresolved_fsn() {
            // `published_fsn()` is the last published FSN; the range the driver's
            // send cursor walks is inclusive of it.
            let last = self.published_fsn().unwrap_or(oldest);
            let mut cursor = None;
            let mut fsn = oldest;
            while fsn <= last {
                let Some(payload) = self.next_cursor_payload_for_fsn(&mut cursor, fsn)? else {
                    break;
                };
                // `accumulate` compares POSITIONS, never bytes: it folds in any frame
                // that covers the tip and reaches past it, whatever the overlapping
                // ids actually say. So a frame that REDEFINES an id the running
                // mirror already holds would have its suffix appended on top of a
                // prefix that disagrees with it, and the result is not a dictionary
                // at all -- ids repeat, and `SymbolGlobalDict::seed` rejects the whole
                // region as a duplicate entry, failing construction on every later
                // open with a diagnostic blaming a torn side-file that is in fact
                // intact. Ask the same question the send loop asks
                // (`guard_dict_not_torn` -> `conflicts_with`) and stop here instead,
                // exactly as the `delta_start > count` gap below does: the count
                // stays at the last frame that agreed, the producer resumes there,
                // and the disagreeing frame is rejected loudly at send time
                // ("resend required") rather than silently rebuilt into nonsense.
                // No-op on the common path -- a contiguous `delta_start == tip`
                // extension overlaps nothing, so this cannot fire.
                // `Disagreed` stops the fold and is recoverable (the frames before
                // this one still rebuild); `OutOfMemory` must fail construction --
                // `accumulate` leaves the mirror disabled and empty on that path, so
                // continuing would hand the producer an id space of 0 against frames
                // defining [0, K), the same guaranteed collision the `seed` guard
                // above exists to prevent, reached by an allocation failure instead
                // of prevented by one.
                enum Fold {
                    Ok,
                    Disagreed,
                    OutOfMemory,
                }
                let folded = payload.with_bytes(|frame| {
                    if mirror.conflicts_with(frame) {
                        return Fold::Disagreed;
                    }
                    if !mirror.accumulate(frame) {
                        return Fold::OutOfMemory;
                    }
                    Fold::Ok
                });
                match folded {
                    Fold::Ok => {}
                    Fold::Disagreed => {
                        log::warn!(
                            "QWP/WebSocket store-and-forward slot {}: stored frame {fsn} \
                             redefines a symbol id the recovered dictionary already holds; \
                             rebuilding the dictionary from the frames before it and \
                             leaving that frame for the send loop to reject as \
                             resend-required.",
                            slot_dir.display()
                        );
                        break;
                    }
                    Fold::OutOfMemory => {
                        return Err(SfaQueueError::Io(io::Error::other(
                            "could not allocate the recovered symbol dictionary while \
                             folding a stored frame into it",
                        )));
                    }
                }
                fsn += 1;
            }
        }
        self.recovered_dict_count = mirror.count();
        self.recovered_dict_entries = mirror.into_entries();
        // The side-file's own copy is now redundant -- this rebuild is a superset of
        // it, and it is the only thing production reads from here on. Freeing it now
        // rather than at `take_persisted_symbol_dict` keeps the rebuild from adding a
        // second full dictionary to the connect-time peak; it lowers it, since the
        // two no longer coexist for the whole of construction.
        if let Some(pd) = self.persisted_symbol_dict.as_mut() {
            pd.clear_loaded_entries();
        }
        Ok(())
    }

    /// Takes the persisted symbol dictionary for the foreground producer's
    /// write-ahead. `None` in memory mode / replay-only / on open failure.
    ///
    /// The recovered entry region (up to ~2 GiB) has already been copied out for
    /// seeding by this point: a take removes the dict from the queue, so any code
    /// needing the entries must read them via
    /// [`recovered_symbol_dict_entries`](Self::recovered_symbol_dict_entries) first
    /// (both recovery paths do — async and sync). The write-ahead handle only needs
    /// the file / append offset / size, so free BOTH that region and this queue's
    /// rebuilt copy rather than carry them dead for the whole connection lifetime.
    pub(crate) fn take_persisted_symbol_dict(&mut self) -> Option<PersistedSymbolDict> {
        let mut pd = self.persisted_symbol_dict.take();
        if let Some(pd) = pd.as_mut() {
            pd.clear_loaded_entries();
        }
        // `Vec::new` (not `clear`) so the backing capacity is released.
        self.recovered_dict_entries = Vec::new();
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
            let acked_fsn = i64::try_from(acked_fsn).map_err(|_| QueueError::SequenceOverflow)?;
            ack_watermark.write(acked_fsn)?;
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
        let result = match step.perform() {
            Ok(result) => result,
            Err(err) => {
                self.complete_storage_maintenance()?;
                return Err(err);
            }
        };
        let finish = match self.finish_storage_maintenance(result, true) {
            Ok(finish) => finish,
            Err(err) => {
                self.complete_storage_maintenance()?;
                return Err(err);
            }
        };
        let changed = changed_before_io || finish.did_change();
        if let Some(cleanup) = finish.into_cleanup()
            && let Some(failure) = cleanup.perform()
        {
            self.record_cleanup_failure(failure);
        }
        self.complete_storage_maintenance()?;
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

    pub(crate) fn complete_storage_maintenance(&mut self) -> Result<(), SfaQueueError> {
        self.engine.complete_storage_maintenance()
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

    pub(crate) fn storage_maintenance_in_flight(&self) -> Result<bool, SfaQueueError> {
        self.engine.storage_maintenance_in_flight()
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

        enum Candidate {
            Existing(Arc<SfaSharedSegment>),
            Create {
                path: Option<PathBuf>,
                created_us: u64,
            },
        }

        // Reserve the topology transaction and detach its manifest writer.
        // Until commit, readers keep seeing the previous active and sealed
        // chain. No filesystem operation below holds the engine-state mutex.
        let (candidate, mut manifest, old_active, head_base, reserved_new_segment) = {
            let mut state = self.engine.lock_state()?;
            let active = state.active.as_ref().ok_or(SfaQueueError::Closed)?;
            if !Arc::ptr_eq(active, &self.active) {
                return Err(SfaQueueError::CorruptSegments {
                    reason: "producer active segment is not the engine active segment",
                });
            }
            if state.topology_io_in_flight {
                return Err(self.engine.rotation_backpressure_error(&state).into());
            }
            if self.engine.request_sync_before_rotation(active) {
                return Err(self.engine.rotation_backpressure_error(&state).into());
            }
            if self.engine.slot_dir.is_some() && state.manifest.is_none() {
                return Err(SfaQueueError::Recovery {
                    reason: "cannot rotate a manifested SFA slot without its manifest".to_string(),
                });
            }

            let old_active = Arc::clone(active);
            let head_base = state
                .sealed_segments
                .front()
                .map(|segment| segment.base_seq())
                .unwrap_or_else(|| active.base_seq());
            let (candidate, reserved_new_segment) = match state.hot_spare.take() {
                Some(segment) => (Candidate::Existing(segment), false),
                None => {
                    // The runner normally prepares the spare. If it is parked
                    // in socket I/O, reserve budget and create the successor on
                    // this appender without monopolizing topology readers.
                    if !self.engine.allow_segment_creation
                        || !can_allocate_segment(
                            state.allocated_segment_bytes,
                            self.engine.segment_size_bytes,
                            self.engine.max_bytes,
                        )
                    {
                        return Err(self.engine.storage_backpressure_error(&state).into());
                    }
                    let path = match self.engine.slot_dir.as_deref() {
                        Some(slot_dir) => {
                            Some(next_segment_path(slot_dir, &mut state.next_generation)?)
                        }
                        None => {
                            state.next_generation = state
                                .next_generation
                                .checked_add(1)
                                .ok_or(QueueError::SequenceOverflow)?;
                            None
                        }
                    };
                    state.allocated_segment_bytes = state
                        .allocated_segment_bytes
                        .checked_add(self.engine.segment_size_bytes)
                        .ok_or(QueueError::SequenceOverflow)?;
                    (
                        Candidate::Create {
                            path,
                            created_us: unix_time_micros(),
                        },
                        true,
                    )
                }
            };
            let manifest = state.manifest.take();
            state.topology_io_in_flight = true;
            (
                candidate,
                manifest,
                old_active,
                head_base,
                reserved_new_segment,
            )
        };

        let prepared = match candidate {
            Candidate::Existing(mut segment) => {
                let result = match Arc::get_mut(&mut segment) {
                    Some(shared) => shared.rebase_empty(self.next_fsn).map_err(Into::into),
                    None => Err(SfaQueueError::CorruptSegments {
                        reason: "hot spare segment is shared before promotion",
                    }),
                };
                match result {
                    Ok(()) => Ok(segment),
                    Err(err) => Err((Some(segment), err)),
                }
            }
            Candidate::Create { path, created_us } => {
                let result = match path.as_deref() {
                    Some(path) => match path.parent() {
                        Some(slot_dir) => create_manifested_segment(
                            path,
                            self.next_fsn,
                            self.engine.segment_size_bytes,
                            created_us,
                            slot_dir,
                        ),
                        None => Err(SfaQueueError::InvalidSfDir),
                    },
                    None => SfaSegment::create_memory(
                        self.next_fsn,
                        self.engine.segment_size_bytes,
                        created_us,
                    )
                    .map_err(Into::into),
                };
                result
                    .map(|segment| Arc::new(SfaSharedSegment::new(segment)))
                    .map_err(|err| (None, err))
            }
        };

        let new_active = match prepared {
            Ok(segment) => segment,
            Err((candidate, err)) => {
                let mut state = self.engine.lock_state()?;
                state.manifest = manifest;
                state.topology_io_in_flight = false;
                if let Some(candidate) = candidate {
                    debug_assert!(state.hot_spare.is_none());
                    state.hot_spare = Some(candidate);
                } else if reserved_new_segment {
                    state.allocated_segment_bytes = state
                        .allocated_segment_bytes
                        .saturating_sub(self.engine.segment_size_bytes);
                }
                return Err(err);
            }
        };
        #[cfg(test)]
        if manifest.is_some() {
            record_sfa_barrier(SfaBarrierEvent::RotationHeaderSynced);
        }

        let manifest_update_error = manifest
            .as_mut()
            .and_then(|manifest| manifest.update(head_base, self.next_fsn).err());

        let mut state = self.engine.lock_state()?;
        state.manifest = manifest;
        state.topology_io_in_flight = false;
        if let Some(err) = manifest_update_error {
            debug_assert!(state.hot_spare.is_none());
            state.hot_spare = Some(new_active);
            return Err(err.into());
        }
        if state.closed
            || !state
                .active
                .as_ref()
                .is_some_and(|active| Arc::ptr_eq(active, &old_active))
        {
            debug_assert!(state.hot_spare.is_none());
            state.hot_spare = Some(new_active);
            return Err(SfaQueueError::Closed);
        }
        #[cfg(test)]
        if state.manifest.is_some() {
            record_sfa_barrier(SfaBarrierEvent::RotationManifestUpdated);
        }
        let replaced = state.active.replace(Arc::clone(&new_active)).unwrap();
        state.sealed_segments.push_back(replaced);
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
        if state.storage_maintenance_in_flight || state.topology_io_in_flight {
            return Err(SfaQueueError::StorageMaintenanceInFlight);
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

    fn storage_maintenance_in_flight(&self) -> Result<bool, SfaQueueError> {
        let state = self.lock_state()?;
        Ok(state.storage_maintenance_in_flight || state.topology_io_in_flight)
    }

    fn complete_storage_maintenance(&self) -> Result<(), SfaQueueError> {
        let mut state = self.lock_state()?;
        if !state.storage_maintenance_in_flight {
            return Err(SfaQueueError::CorruptSegments {
                reason: "storage maintenance completed without an in-flight step",
            });
        }
        state.storage_maintenance_in_flight = false;
        Ok(())
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
        let state = self.lock_state()?;
        if state.storage_maintenance_in_flight || state.topology_io_in_flight {
            return Ok(None);
        }
        drop(state);
        if let Some(step) = self.take_periodic_sync_step()? {
            return Ok(Some(step));
        }
        let trim_candidates = {
            let state = self.lock_state()?;
            if state.closed || state.topology_io_in_flight {
                return Ok(None);
            }
            if state
                .trim_retry_at
                .is_some_and(|retry_at| Instant::now() < retry_at)
            {
                Vec::new()
            } else {
                self.trimmable_prefix(&state, MAX_TRIMS_PER_STORAGE_STEP)?
            }
        };
        if !trim_candidates.is_empty() {
            if let Some(slot_dir) = self.slot_dir.as_deref() {
                let acked_fsn = self.completed_fsn().ok_or(SfaQueueError::CorruptSegments {
                    reason: "trimmable segment exists without a completed FSN",
                })?;
                let acked_fsn =
                    i64::try_from(acked_fsn).map_err(|_| QueueError::SequenceOverflow)?;
                let watermark = ack_watermark.ok_or_else(|| SfaQueueError::Recovery {
                    reason: "cannot durably trim SFA segments without an ACK watermark".to_string(),
                })?;
                if let Err(err) = watermark.write(acked_fsn) {
                    return self.defer_trim_barrier_failure(err);
                }
                #[cfg(test)]
                record_sfa_barrier(SfaBarrierEvent::TrimWatermarkWritten);
                if let Err(err) = watermark.sync_data() {
                    return self.defer_trim_barrier_failure(err);
                }
                #[cfg(test)]
                record_sfa_barrier(SfaBarrierEvent::TrimWatermarkSynced);
                if let Err(err) = sync_directory(slot_dir) {
                    return self.defer_trim_barrier_failure(err);
                }
                #[cfg(test)]
                record_sfa_barrier(SfaBarrierEvent::TrimDirectorySynced);
            }

            let mut state = self.lock_state()?;
            if state.closed || state.topology_io_in_flight {
                return Ok(None);
            }
            if state.sealed_segments.len() < trim_candidates.len()
                || !state
                    .sealed_segments
                    .iter()
                    .zip(&trim_candidates)
                    .all(|(current, candidate)| Arc::ptr_eq(current, candidate))
            {
                return Ok(None);
            }
            if self.slot_dir.is_some() {
                let active_base = state
                    .active
                    .as_ref()
                    .ok_or(SfaQueueError::Closed)?
                    .base_seq();
                // One durable head advance past the last batch member covers
                // the whole contiguous prefix. Recovery treats any member
                // surviving the subsequent unlink loop as stale below head.
                let new_head_base = state
                    .sealed_segments
                    .get(trim_candidates.len())
                    .map(|segment| segment.base_seq())
                    .unwrap_or(active_base);
                let mut manifest =
                    state
                        .manifest
                        .take()
                        .ok_or_else(|| SfaQueueError::Recovery {
                            reason: "cannot trim a manifested SFA slot without its manifest"
                                .to_string(),
                        })?;
                state.topology_io_in_flight = true;
                drop(state);

                let update_result = manifest.update(new_head_base, active_base);
                state = self.lock_state()?;
                state.manifest = Some(manifest);
                state.topology_io_in_flight = false;
                if let Err(err) = update_result {
                    drop(state);
                    return self.defer_trim_barrier_failure(err);
                }
                if state.trim_retry_at.take().is_some() {
                    log::info!("QWP/WebSocket SF trim barrier recovered");
                }
                if state.closed
                    || state.sealed_segments.len() < trim_candidates.len()
                    || !state
                        .sealed_segments
                        .iter()
                        .zip(&trim_candidates)
                        .all(|(current, candidate)| Arc::ptr_eq(current, candidate))
                {
                    return Ok(None);
                }
                #[cfg(test)]
                record_sfa_barrier(SfaBarrierEvent::TrimManifestUpdated);
            }
            let mut removed_bytes = 0_u64;
            for candidate in &trim_candidates {
                let segment = state.sealed_segments.pop_front().unwrap();
                debug_assert!(Arc::ptr_eq(&segment, candidate));
                removed_bytes = removed_bytes.saturating_add(segment.size_bytes());
                #[cfg(test)]
                if self.slot_dir.is_some() {
                    record_sfa_barrier(SfaBarrierEvent::TrimQueuePopped);
                }
            }
            state.first_non_durable_sealed = state
                .first_non_durable_sealed
                .saturating_sub(trim_candidates.len());
            state.allocated_segment_bytes =
                state.allocated_segment_bytes.saturating_sub(removed_bytes);
            state.storage_maintenance_in_flight = true;
            return Ok(Some(SfaStorageStep::Trim(SfaStorageCleanup::new_batch(
                trim_candidates,
            ))));
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
        state.storage_maintenance_in_flight = true;
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
            SfaStorageResult::Trimmed { cleanup_failures } => {
                for failure in cleanup_failures {
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
                    && !state.topology_io_in_flight
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
        if state.closed || state.storage_maintenance_in_flight || state.topology_io_in_flight {
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
        state.storage_maintenance_in_flight = true;
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

    fn defer_trim_barrier_failure(
        &self,
        err: io::Error,
    ) -> Result<Option<SfaStorageStep>, SfaQueueError> {
        // ErrorKind does not distinguish an internal validation failure from
        // every filesystem's write/fsync failures. No segment is removed until
        // the barrier is confirmed, so every barrier error is safe to retry.
        let now = Instant::now();
        let mut state = self.lock_state()?;
        if state.trim_retry_at.is_none() {
            log::error!(
                "QWP/WebSocket SF trim barrier failed; retrying in {:?}: {}",
                TRIM_BARRIER_RETRY_DELAY,
                err
            );
        }
        state.trim_retry_at = now.checked_add(TRIM_BARRIER_RETRY_DELAY).or(Some(now));
        Ok(None)
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

    fn trimmable_prefix(
        &self,
        state: &SfaEngineState,
        max_count: usize,
    ) -> Result<Vec<Arc<SfaSharedSegment>>, SfaQueueError> {
        let Some(acked_fsn) = self.completed_fsn() else {
            return Ok(Vec::new());
        };
        let mut segments = state.sealed_segments.iter().take(max_count);
        let Some(first) = segments.next() else {
            return Ok(Vec::new());
        };
        let first_last_fsn = first.last_fsn().ok_or(SfaQueueError::CorruptSegments {
            reason: "sealed segment has no frames",
        })?;
        if first_last_fsn > acked_fsn {
            return Ok(Vec::new());
        }

        let mut trimmable = Vec::with_capacity(max_count.min(state.sealed_segments.len()));
        trimmable.push(Arc::clone(first));
        for segment in segments {
            let last_fsn = segment.last_fsn().ok_or(SfaQueueError::CorruptSegments {
                reason: "sealed segment has no frames",
            })?;
            if last_fsn > acked_fsn {
                break;
            }
            trimmable.push(Arc::clone(segment));
        }
        Ok(trimmable)
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

    fn storage_maintenance_in_flight(&self) -> Result<bool, DriverError> {
        Ok(SfaFrameQueue::storage_maintenance_in_flight(self)?)
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

    fn complete_storage_maintenance(&mut self) -> Result<(), DriverError> {
        Ok(SfaFrameQueue::complete_storage_maintenance(self)?)
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
                ack_watermark.sync_data()?;
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
    if options.max_bytes == 0 {
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
    if options.max_bytes == 0 {
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
    use std::sync::{Barrier, mpsc};

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
        options_with(dir, 256, 1024)
    }

    fn options_with(dir: &TempDir, segment_size_bytes: u64, max_bytes: usize) -> SfaQueueOptions {
        SfaQueueOptions {
            slot_dir: dir.path().to_path_buf(),
            segment_size_bytes,
            max_bytes,
            periodic_sync_interval: None,
        }
    }

    fn periodic_options_with(
        dir: &TempDir,
        segment_size_bytes: u64,
        max_bytes: usize,
    ) -> SfaQueueOptions {
        let mut options = options_with(dir, segment_size_bytes, max_bytes);
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

    fn memory_options(segment_size_bytes: u64, max_bytes: usize) -> SfaMemoryQueueOptions {
        SfaMemoryQueueOptions {
            segment_size_bytes,
            max_bytes,
        }
    }

    fn file_name(path: &Path) -> String {
        path.file_name().unwrap().to_string_lossy().into_owned()
    }

    fn trim_unlinked_event(dir: &Path, generation: u64) -> SfaBarrierEvent {
        SfaBarrierEvent::TrimSegmentUnlinked(file_name(&spare_segment_path(dir, generation)))
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
    fn initial_periodic_sync_arms_cadence_when_publish_lands_before_finish() {
        let dir = TempDir::new().unwrap();
        let mut queue = SfaFrameQueue::open(periodic_options_with(&dir, 256, 1024)).unwrap();

        queue.try_submit(b"before-sync").unwrap();
        let step = queue
            .take_storage_maintenance_step(false)
            .unwrap()
            .expect("the first periodic sync is due immediately");
        assert!(matches!(step, SfaStorageStep::SyncPublished(_)));
        let result = step.perform().unwrap();

        // The detached foreground producer can publish while the runner is
        // between the off-lock sync and its finish check.
        queue.try_submit(b"during-sync").unwrap();
        queue.finish_storage_maintenance(result, true).unwrap();
        queue.complete_storage_maintenance().unwrap();

        assert!(
            queue
                .take_storage_maintenance_step(false)
                .unwrap()
                .is_none(),
            "the completed first sync must arm the one-hour cadence"
        );
    }

    #[test]
    fn periodic_failure_latches_without_reserving_an_fsn_and_retry_covers_live_segments() {
        let dir = TempDir::new().unwrap();
        let segment_size = (HEADER_SIZE + 2 * (FRAME_HEADER_SIZE + 16)) as u64;
        let mut queue = SfaFrameQueue::open(periodic_options_with(
            &dir,
            segment_size,
            3 * segment_size as usize,
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
        assert!(!queue.storage_maintenance_in_flight().unwrap());
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
        assert!(!queue.storage_maintenance_in_flight().unwrap());
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

        let queue = SfaFrameQueue::open(periodic_options_with(&dir, 256, 1024)).unwrap();
        assert_eq!(queue.published_fsn(), Some(0));
        assert!(
            active_is_durable(&queue),
            "periodic open must establish a durable baseline before exposing recovered frames"
        );
    }

    #[test]
    fn periodic_undrained_close_syncs_before_teardown_and_retries_after_failure() {
        let dir = TempDir::new().unwrap();
        let mut queue = SfaFrameQueue::open(periodic_options_with(&dir, 256, 1024)).unwrap();
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
        SfaFrameQueue::open_memory(memory_options(48, 144)).unwrap()
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
            SfaFrameQueue::open_memory(memory_options(48, 48)),
            Err(SfaQueueError::Queue(QueueError::InvalidCapacity))
        ));
        assert!(matches!(
            SfaFrameQueue::open_memory(memory_options(48, 95)),
            Err(SfaQueueError::Queue(QueueError::InvalidCapacity))
        ));

        let queue = SfaFrameQueue::open_memory(memory_options(48, 96)).unwrap();
        assert!(queue.hot_spare_installed());
        assert_eq!(queue.allocated_segment_bytes(), 96);
    }

    #[test]
    fn memory_queue_rotates_and_trims_without_filesystem_cleanup() {
        let mut queue = SfaFrameQueue::open_memory(memory_options(48, 96)).unwrap();

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
            .as_chunks::<2>()
            .0
            .iter()
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
    fn manifested_proven_dead_residue_is_sanitized_then_fails_once() {
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

        let queue = SfaFrameQueue::open(options_with(&dir, 256, 1024)).unwrap();

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
        let mut queue = SfaFrameQueue::open(options_with(&dir, 38, 152)).unwrap();
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
    fn recovered_slot_without_a_side_file_rearms_delta_and_recreates_it() {
        // This used to fall back to dense, on the argument that arming delta over
        // an empty dictionary next to segments referencing ids [0, K) would let a
        // later frame resolve those stale ids to the wrong symbols. The ids no
        // longer come from the (missing) file -- `rebuild_recovered_dict_from_frames`
        // takes them from the surviving frames' own delta sections -- so that
        // argument no longer applies, while dense's cost does: the mirror stays
        // disabled, the `delta_start == 0` frame replays and COMMITS, and the
        // `delta_start > 0` frame behind it is then terminally rejected with
        // `in_doubt == false`, so a compliant resend duplicates the committed rows.
        //
        // Re-creating the file is what gives the producer a write-ahead target
        // again; without it the slot can never persist a dictionary and every later
        // open re-decides the same thing.
        //
        // The frames must be REAL delta frames. `try_submit`ting raw bytes yields a
        // payload `parse_delta_section` rejects, which no-ops the whole rebuild --
        // so a raw-payload version of this test passes identically whether
        // `rebuild_recovered_dict_from_frames` runs on this branch or is skipped
        // outright, and pins only the re-create half of the change.
        use crate::ingress::sender::qwp_ws_sfa_catchup::make_delta_frame;

        let dir = TempDir::new().unwrap();
        let symbol_dict = dir
            .path()
            .join(crate::ingress::sender::qwp_ws_sfa_symbol_dict::FILE_NAME);

        // A first session leaves two unresolved (recoverable) delta frames behind,
        // introducing `alpha` (id 0) and `bravo` (id 1).
        let mut queue = open(&dir);
        queue
            .try_submit(&make_delta_frame(0, &[b"alpha".as_slice()], b""))
            .unwrap();
        queue
            .try_submit(&make_delta_frame(1, &[b"bravo".as_slice()], b""))
            .unwrap();
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

        let mut recovered = open(&dir);
        assert!(
            recovered.is_delta_dict_enabled(),
            "a missing side-file must not strand the slot's delta frames behind a \
             committed prefix; the dictionary is rebuilt from the frames instead"
        );
        // The load-bearing half: with no file to read, every recovered id has to
        // come out of the surviving frames' own delta sections. Skipping the
        // rebuild on this branch leaves the count at 0, the producer resumes at id
        // 0, and its first new symbol takes an id both replayed frames already own.
        assert_eq!(
            recovered.recovered_symbol_dict_count(),
            2,
            "the frames define ids 0 and 1 in their own delta sections, so recovery \
             must resume the producer at id 2 even though no side-file survived"
        );
        assert_eq!(
            recovered.recovered_symbol_dict_entries(),
            &[
                5, b'a', b'l', b'p', b'h', b'a', 5, b'b', b'r', b'a', b'v', b'o'
            ][..],
            "rebuilt in id order, in the `[len][utf8]` shape a delta section \
             carries, so the producer dict and the driver mirror seed from \
             identical bytes"
        );
        let pd = recovered.take_persisted_symbol_dict().expect(
            "the producer must get a usable side-file back, or its \
                     write-ahead is dead for the life of the slot",
        );
        assert_eq!(
            pd.size(),
            0,
            "the re-created file starts empty -- the producer is 2 ids ahead of it \
             until `persist_new_symbols` anchors to THIS number and heals it"
        );
        drop(pd);
        assert!(
            symbol_dict.exists(),
            "the re-created side-file is what the next write-ahead heals into"
        );
    }

    #[test]
    fn recovered_slot_with_a_bad_magic_side_file_rearms_delta_and_recreates_it() {
        // A poisoned / externally-corrupted / wrong-version side-file beside
        // recoverable segments reaches the driver in exactly the state an absent
        // one does -- it cannot tell them apart -- so it gets the same treatment,
        // and for the same reason: dense here commits the `delta_start == 0` frame
        // and then terminally rejects the one behind it, which a compliant resend
        // duplicates.
        //
        // Rewriting the header is safe precisely because the file was unreadable:
        // nothing is lost that could have been used, the ids come back from the
        // frames, and the alternative is a slot that stays dense forever while an
        // unreadable file sits next to it being re-read and re-rejected on every
        // open.
        //
        // Bad magic is not a hypothetical: `PersistedSymbolDict::poison` zeroes
        // these four bytes whenever a rollback truncate fails on a failing disk,
        // precisely so a later `open` rejects the file. Real delta frames for the
        // same reason as the absent-file twin above -- raw payloads carry no delta
        // section, so the rebuild folds nothing and the assertion below cannot
        // distinguish a working rebuild from a skipped one.
        use crate::ingress::sender::qwp_ws_sfa_catchup::make_delta_frame;

        let dir = TempDir::new().unwrap();
        let symbol_dict = dir
            .path()
            .join(crate::ingress::sender::qwp_ws_sfa_symbol_dict::FILE_NAME);

        let mut queue = open(&dir);
        queue
            .try_submit(&make_delta_frame(0, &[b"alpha".as_slice()], b""))
            .unwrap();
        queue
            .try_submit(&make_delta_frame(1, &[b"bravo".as_slice()], b""))
            .unwrap();
        drop(queue);
        std::fs::write(&symbol_dict, b"NOPEnope-poisoned-header").unwrap();

        let mut recovered = open(&dir);
        assert!(
            recovered.is_delta_dict_enabled(),
            "an unreadable side-file must not strand the slot's delta frames behind \
             a committed prefix"
        );
        assert_eq!(
            recovered.recovered_symbol_dict_count(),
            2,
            "the rejected bytes contribute nothing, so both ids must come back from \
             the surviving frames' own delta sections"
        );
        assert_eq!(
            recovered.recovered_symbol_dict_entries(),
            &[
                5, b'a', b'l', b'p', b'h', b'a', 5, b'b', b'r', b'a', b'v', b'o'
            ][..],
            "rebuilt in id order, in the `[len][utf8]` shape a delta section carries"
        );
        assert!(
            recovered.take_persisted_symbol_dict().is_some(),
            "the producer must get a usable side-file back"
        );
        assert!(
            crate::ingress::sender::qwp_ws_sfa_symbol_dict::parse_chunks(&symbol_dict).is_empty(),
            "the corrupt bytes are replaced by a valid, empty header the write-ahead \
             can extend -- not left in place to be re-rejected forever"
        );
    }

    #[test]
    fn recovered_slot_whose_side_file_is_legitimately_empty_keeps_delta_armed() {
        // A session can leave unresolved segments beside a side-file that is a
        // valid, untorn, EMPTY header: it queued frames but interned no symbol (a
        // table with no symbol column, or all-null symbol values). `size() == 0`
        // there means exactly what it says -- an empty dictionary -- and is NOT the
        // rejected-first-chunk state the two tests below and above deal with.
        //
        // Falling back to dense on it is self-perpetuating and unrecoverable. The
        // producer write-aheads only through the side-file handle the queue hands
        // it, so dense means the file never grows, so every later open sees an
        // empty file again and re-decides dense. Meanwhile dense re-ships
        // `[0, highest_referenced + 1)` in EVERY frame, and once that prefix alone
        // exceeds the per-frame cap the flush fails `BatchTooLarge` on a SINGLE
        // row -- nothing left for the split to halve -- so no new symbol can ever
        // be interned on that slot again.
        //
        // Nothing is at risk in this case either way: the recovered segments
        // reference no symbol ids at all, so there are no stale ids for a later
        // delta frame to misresolve.
        let dir = TempDir::new().unwrap();
        let symbol_dict = dir
            .path()
            .join(crate::ingress::sender::qwp_ws_sfa_symbol_dict::FILE_NAME);

        // A first session queues a frame carrying no symbols and leaves it
        // unresolved. `try_submit` writes a raw payload, so nothing is interned.
        let mut queue = open(&dir);
        queue.try_submit(b"unresolved-frame").unwrap();
        drop(queue);
        assert!(
            sfa_file_count(dir.path()) > 0,
            "an unresolved segment survives"
        );
        assert!(
            crate::ingress::sender::qwp_ws_sfa_symbol_dict::parse_chunks(&symbol_dict).is_empty(),
            "the side-file must be a valid, untorn, zero-chunk header -- this test \
             is about an EMPTY dictionary, not a rejected chunk"
        );

        let mut recovered = open(&dir);
        assert!(
            recovered.is_delta_dict_enabled(),
            "a valid but empty side-file is an empty dictionary, not a corrupt \
             one: delta must stay armed"
        );
        assert_eq!(recovered.recovered_symbol_dict_count(), 0);
        assert!(
            recovered.take_persisted_symbol_dict().is_some(),
            "the producer must get the live side-file handle back, so its \
             write-ahead resumes and the slot cannot get stuck empty forever"
        );
    }

    #[test]
    fn recovered_slot_whose_first_chunk_is_corrupt_keeps_delta_armed() {
        // Regression (data loss + duplication): a side-file with a VALID header
        // whose first chunk fails any reader check parses to zero entries, and
        // `open_recovered` returns `Some(dict)` -- `size() == 0`, file truncated
        // back to its header. It is tempting to treat that as the same
        // empty-delta-dictionary state the absent / bad-magic paths above avoid,
        // and fall back to dense. That is WRONG, and the cost is paid in delivered
        // data rather than in a rejected frame.
        //
        // `delta_dict_enabled` arms the driver's catch-up mirror as well as the
        // producer, and with the mirror disabled `guard_dict_not_torn` rejects
        // every `delta_start > 0` frame outright -- but only after the slot's
        // `delta_start == 0` frame has already replayed and COMMITTED on the
        // server. The caller sees `StoreResendRequired` / `in_doubt == false`
        // ("re-ingest from source") sitting on top of a committed prefix, so a
        // compliant resend duplicates those rows.
        //
        // Armed on the empty dictionary the queue bootstraps itself instead: the
        // `delta_start == 0` frame passes the guard, `SentDictMirror::accumulate`
        // folds its own delta section into the mirror, and the `delta_start == K`
        // frame behind it passes against that. Both replay, with the right
        // symbols. `store_and_forward_file_mode_replays_both_frames_when_the_first_
        // dict_chunk_is_corrupt` pins that end to end through a real sender; this
        // pins the queue-level state it depends on.
        //
        // Per-chunk framing is what makes the corruption reachable from one
        // flipped byte: a chunk is one whole frame's new symbols, so a single lost
        // page in the first flush drops every symbol that frame introduced. Under
        // the superseded per-entry CRC only a tear in entry 0 could do this --
        // which is why this case needs deciding now and did not before.
        let dir = TempDir::new().unwrap();
        let symbol_dict = dir
            .path()
            .join(crate::ingress::sender::qwp_ws_sfa_symbol_dict::FILE_NAME);

        // A first session leaves an unresolved segment plus a real one-chunk
        // side-file behind.
        let mut queue = open(&dir);
        queue.try_submit(b"unresolved-frame").unwrap();
        drop(queue);
        {
            let mut pd = crate::ingress::sender::qwp_ws_sfa_symbol_dict::PersistedSymbolDict::open(
                dir.path(),
            )
            .unwrap();
            pd.append_symbol(b"alpha").unwrap();
        }

        // Same-length value flip inside the only chunk: its stored CRC goes stale,
        // so the parse stops at chunk 0 and recovers nothing.
        let mut bytes = std::fs::read(&symbol_dict).unwrap();
        let idx = bytes
            .windows(5)
            .position(|w| w == b"alpha")
            .expect("alpha entry present");
        bytes[idx] = b'X';
        std::fs::write(&symbol_dict, &bytes).unwrap();

        let recovered = open(&dir);
        assert!(
            recovered.is_delta_dict_enabled(),
            "a recovered slot whose side-file parsed to zero entries must keep \
             delta armed so the mirror can bootstrap from the stored frames; \
             dense here strands every `delta_start > 0` frame behind a committed \
             prefix"
        );
        assert!(
            recovered.recovered_symbol_dict_entries().is_empty(),
            "the rejected chunk seeds nothing, and this slot's lone frame is a RAW \
             payload carrying no delta section, so the frame-derived rebuild has \
             nothing to contribute either -- the mirror arms empty. \
             `recovered_slot_rebuilds_the_dict_from_frames_when_the_side_file_is_torn` \
             covers the case where the frames DO carry one"
        );
        assert_eq!(recovered.recovered_symbol_dict_count(), 0);
    }

    #[test]
    fn recovered_slot_rebuilds_the_dict_from_frames_when_the_side_file_is_torn() {
        // Regression (guaranteed store kill on the first new symbol). A recovered
        // slot's producer must resume ABOVE every id the surviving frames define.
        // The side-file is not fsync'd, so a host crash can tear off its newest
        // entries while the frames that introduced those ids survive -- and the
        // newest frames, being the least likely to be acked, are exactly the ones
        // that replay.
        //
        // Seeded from the torn side-file alone the producer's `next_id` would be 0
        // while the replayed frames define ids 0 and 1. Its first new symbol would
        // take id 0, the driver's mirror -- which accumulated the real mapping as
        // those frames went out -- would see a differing redefinition of a held id,
        // and `guard_dict_not_torn`'s `conflicts_with` would terminally fail the
        // whole store with `StoreResendRequired`, AFTER the backlog replayed. That
        // is certain, not a race: any new symbol whose bytes differ from `alpha`
        // collides at id 0.
        //
        // So recovery rebuilds from BOTH sources the mirror is built from, in the
        // same order: the side-file's intact prefix (here: nothing), then the
        // frames' own delta sections. Producer and mirror then land on the same
        // count by construction. Mirrors the Java client's
        // `seedGlobalDictionaryFromPersisted`.
        //
        // The frames must be REAL delta frames: `try_submit`ting raw bytes yields a
        // payload `parse_delta_section` rejects, which no-ops the whole rebuild.
        use crate::ingress::sender::qwp_ws_sfa_catchup::make_delta_frame;

        let dir = TempDir::new().unwrap();
        let symbol_dict = dir
            .path()
            .join(crate::ingress::sender::qwp_ws_sfa_symbol_dict::FILE_NAME);

        // A first session queues two delta frames introducing `alpha` (id 0) and
        // `bravo` (id 1), and write-aheads both into the side-file as one chunk
        // each -- exactly what the producer does per frame.
        let mut queue = open(&dir);
        queue
            .try_submit(&make_delta_frame(0, &[b"alpha".as_slice()], b""))
            .unwrap();
        queue
            .try_submit(&make_delta_frame(1, &[b"bravo".as_slice()], b""))
            .unwrap();
        drop(queue);
        {
            let mut pd = crate::ingress::sender::qwp_ws_sfa_symbol_dict::PersistedSymbolDict::open(
                dir.path(),
            )
            .unwrap();
            pd.append_symbol(b"alpha").unwrap();
            pd.append_symbol(b"bravo").unwrap();
        }

        // A host crash tears chunk 0: same-length value flip, so only its stored
        // CRC goes stale. The reader stops there and truncates, so the side-file
        // contributes NOTHING -- while both queued frames still reference ids 0/1.
        let mut bytes = std::fs::read(&symbol_dict).unwrap();
        let idx = bytes
            .windows(5)
            .position(|w| w == b"alpha")
            .expect("alpha entry present");
        bytes[idx] = b'X';
        std::fs::write(&symbol_dict, &bytes).unwrap();

        let mut recovered = open(&dir);
        assert!(recovered.is_delta_dict_enabled());
        assert_eq!(
            recovered.recovered_symbol_dict_count(),
            2,
            "the surviving frames define ids 0 and 1 in their own delta sections, \
             so recovery must resume the producer at id 2 -- seeding 0 from the \
             torn side-file alone hands the next new symbol id 0, which the \
             replayed frames already own"
        );
        assert_eq!(
            recovered.recovered_symbol_dict_entries(),
            &[
                5, b'a', b'l', b'p', b'h', b'a', 5, b'b', b'r', b'a', b'v', b'o'
            ][..],
            "rebuilt in id order, in the `[len][utf8]` shape a delta section \
             carries, so the producer dict and the driver mirror seed from \
             identical bytes"
        );
        // The rebuild does NOT write those ids back, so the handle the producer
        // gets is still short. Pinned because it is the precondition for the whole
        // write-ahead anchoring rule: `persist_new_symbols` starts from THIS number,
        // not from the producer's id, and
        // `write_ahead_heals_a_side_file_left_short_by_a_frame_derived_rebuild`
        // covers what happens when it does not.
        assert_eq!(
            recovered.take_persisted_symbol_dict().unwrap().size(),
            0,
            "the side-file keeps only its intact prefix (here: nothing) -- the \
             producer is 2 ids ahead of it until the next write-ahead heals it"
        );
    }

    #[test]
    fn a_second_crash_after_a_frame_rebuilt_recovery_reads_the_dict_in_id_order() {
        // Regression, second-order, and the one that actually bites: the rebuild
        // leaves the producer ahead of the side-file, so it is the NEXT write-ahead
        // that has to close the gap. If that write-ahead anchors to the producer's
        // id instead of the file's tip, the symbol it appends lands at the file
        // position of a DIFFERENT id -- and nothing notices until the crash after
        // that, an ordinary process restart, which is exactly what
        // store-and-forward promises to survive (the original tear needed a host
        // crash).
        //
        // Walk both crashes end to end through the real publisher. Before the
        // anchoring fix this read back `[charlie, bravo, charlie]`: id 0 aliased
        // onto charlie, alpha lost, and a duplicate that makes
        // `SymbolGlobalDict::seed` refuse to open the slot ever again --
        // permanently stranding its queued frames.
        use crate::ingress::sender::qwp_ws_sfa_catchup::make_delta_frame;
        use crate::ingress::sender::qwp_ws_sfa_publisher::SfaForegroundPublisher;
        use crate::ingress::sender::qwp_ws_sfa_symbol_dict::PersistedSymbolDict;

        let dir = TempDir::new().unwrap();
        let symbol_dict = dir
            .path()
            .join(crate::ingress::sender::qwp_ws_sfa_symbol_dict::FILE_NAME);

        // Session 1: two delta frames introduce alpha (id 0) and bravo (id 1),
        // each write-ahead as its own chunk, and are left unresolved.
        let mut queue = open(&dir);
        queue
            .try_submit(&make_delta_frame(0, &[b"alpha".as_slice()], b""))
            .unwrap();
        queue
            .try_submit(&make_delta_frame(1, &[b"bravo".as_slice()], b""))
            .unwrap();
        drop(queue);
        {
            let mut pd = PersistedSymbolDict::open(dir.path()).unwrap();
            pd.append_symbol(b"alpha").unwrap();
            pd.append_symbol(b"bravo").unwrap();
        }

        // Crash 1 (host/power): a same-length flip tears chunk 0, so the reader
        // stops there and the side-file contributes NOTHING. Both ids have to come
        // back from the frames' own delta sections.
        let mut bytes = std::fs::read(&symbol_dict).unwrap();
        let idx = bytes
            .windows(5)
            .position(|w| w == b"alpha")
            .expect("alpha entry present");
        bytes[idx] = b'X';
        std::fs::write(&symbol_dict, &bytes).unwrap();

        // Session 2: recover and wire the producer exactly as
        // `PooledSenderCore::new_store_and_forward` does -- take the handle, seed
        // from the rebuilt entries -- then publish one frame introducing a third
        // symbol.
        let mut recovered = open(&dir);
        assert_eq!(recovered.recovered_symbol_dict_count(), 2);
        let entries = recovered.recovered_symbol_dict_entries().to_vec();
        let count = recovered.recovered_symbol_dict_count();
        let mut foreground =
            SfaForegroundPublisher::new(true, recovered.take_persisted_symbol_dict());
        foreground.seed(&entries, count).unwrap();
        foreground
            .encode_persist_publish(
                usize::MAX,
                |payload, global, _delta| {
                    global.intern(b"charlie")?;
                    payload.extend_from_slice(b"frame");
                    Ok(())
                },
                |_| Ok(1),
            )
            .unwrap();
        drop(foreground);
        drop(recovered);

        // Crash 2 is an ORDINARY restart -- no corruption injected. The side-file
        // must still map id i to entry i.
        let reopened = PersistedSymbolDict::open_recovered(dir.path())
            .unwrap()
            .expect("the healed side-file must open");
        assert_eq!(
            reopened.read_loaded_symbols(),
            vec![b"alpha".to_vec(), b"bravo".to_vec(), b"charlie".to_vec()],
            "the side-file must read back in id order after the write-ahead healed \
             it; anchoring that write-ahead to the producer instead yields \
             [charlie, bravo, charlie]"
        );
        drop(reopened);

        // ...and the slot still opens, with a recovered dictionary a producer can
        // resume from. Anchored to the producer this is where the duplicate lands
        // and `SymbolGlobalDict::seed` starts refusing the slot outright.
        let session_three = open(&dir);
        assert_eq!(
            session_three.recovered_symbol_dict_entries(),
            &[
                5, b'a', b'l', b'p', b'h', b'a', 5, b'b', b'r', b'a', b'v', b'o', 7, b'c', b'h',
                b'a', b'r', b'l', b'i', b'e'
            ][..],
            "recovered dictionary must be [alpha, bravo, charlie] in id order"
        );
        crate::ingress::buffer::SymbolGlobalDict::new()
            .seed(
                session_three.recovered_symbol_dict_entries(),
                session_three.recovered_symbol_dict_count(),
            )
            .expect("a healed dictionary seeds cleanly -- no duplicate, no gap");
    }

    #[test]
    fn recovered_slot_stops_the_rebuild_at_a_genuine_id_gap() {
        // The rebuild must not paper over a real gap. When the surviving frames
        // base ABOVE the side-file's prefix, the ids below their `delta_start` were
        // introduced by frames since acked and trimmed away -- they lived only in
        // the lost dictionary and nothing can reconstruct them. Folding such a
        // frame in would silently shift every id down and misattribute values.
        //
        // `SentDictMirror::accumulate` already skips a frame whose `delta_start`
        // exceeds the running count, and the rebuild reuses it precisely so this
        // case needs no second implementation. The count stays at the prefix, and
        // the send loop's `guard_dict_not_torn` then rejects the frame loudly
        // ("resend required") exactly as it does today.
        // TWO frames, so the assertion distinguishes "stopped at the gap" from
        // "never ran". A lone frame basing at id 3 over an empty side-file recovers
        // 0 entries either way -- which is what a build with the rebuild deleted
        // also produces, so it pins nothing. The contiguous frame in front of the
        // gap makes the two outcomes differ: 1 if the fold ran and then stopped, 0
        // if it never ran at all.
        use crate::ingress::sender::qwp_ws_sfa_catchup::make_delta_frame;

        let dir = TempDir::new().unwrap();

        let mut queue = open(&dir);
        // Contiguous with the (empty) prefix: the rebuild must fold this one in.
        queue
            .try_submit(&make_delta_frame(0, &[b"alpha".as_slice()], b""))
            .unwrap();
        // Bases at id 3, leaving ids 1 and 2 unaccounted for: a genuine gap.
        queue
            .try_submit(&make_delta_frame(3, &[b"delta".as_slice()], b""))
            .unwrap();
        drop(queue);

        let recovered = open(&dir);
        assert_eq!(
            recovered.recovered_symbol_dict_count(),
            1,
            "the rebuild must fold the contiguous frame in and then STOP at the gap \
             -- 0 would mean it never ran, 4 would mean it invented ids 1..3"
        );
        assert_eq!(
            recovered.recovered_symbol_dict_entries(),
            &[5, b'a', b'l', b'p', b'h', b'a'][..],
            "only the frame below the gap contributes; `delta` lives above ids \
             nothing can reconstruct, so the send loop's `guard_dict_not_torn` \
             rejects its frame loudly rather than the rebuild guessing"
        );
    }

    #[test]
    fn recovered_slot_stops_the_rebuild_at_a_frame_that_disagrees_about_an_id() {
        // Regression (permanent construction failure, misdiagnosed as disk damage).
        //
        // A gap is not the only thing the fold must stop at. `accumulate` matches on
        // POSITION only -- it folds in any frame covering the tip and reaching past
        // it, whatever the overlapping ids actually say -- so a frame that
        // REDEFINES an id the side-file already holds gets its suffix appended on
        // top of a prefix that contradicts it.
        //
        // Here the side-file holds `alpha` at id 0 and the surviving frame declares
        // id 0 = `zulu`, id 1 = `alpha`. Position-wise the frame overlaps the tip by
        // one entry and extends by one, so the unguarded fold skips one entry and
        // appends `alpha` -- yielding `[alpha][alpha]`, count 2. That is not a
        // dictionary: `SymbolGlobalDict::seed` re-interns every entry and rejects the
        // repeat with `StoreResendRequired` ("duplicate entry at index 1 (a torn or
        // zero-extended tail)"). Both recovery callers `?`-propagate that, so
        // `SenderBuilder::build` / `borrow_sender` fail -- deterministically, on
        // every retry, forever -- pointing an operator at a side-file that is
        // byte-perfect.
        //
        // So the fold asks `conflicts_with`, the same question `guard_dict_not_torn`
        // asks before sending, and stops exactly as it does at a gap. Construction
        // then succeeds on the agreeing prefix and the disagreeing frame is rejected
        // loudly at send time instead.
        //
        // Reaching this needs frames written against a different dictionary
        // generation than the side-file -- a session that ran dense because the
        // side-file was unwritable. Narrow, but the pre-rebuild code opened such a
        // slot fine, so without this guard the rebuild is a regression.
        use crate::ingress::buffer::SymbolGlobalDict;
        use crate::ingress::sender::qwp_ws_sfa_catchup::make_delta_frame;

        let dir = TempDir::new().unwrap();

        let mut queue = open(&dir);
        queue
            .try_submit(&make_delta_frame(
                0,
                &[b"zulu".as_slice(), b"alpha".as_slice()],
                b"",
            ))
            .unwrap();
        drop(queue);
        {
            let mut pd = crate::ingress::sender::qwp_ws_sfa_symbol_dict::PersistedSymbolDict::open(
                dir.path(),
            )
            .unwrap();
            pd.append_symbol(b"alpha").unwrap();
        }

        let recovered = open(&dir);
        assert!(recovered.is_delta_dict_enabled());
        assert_eq!(
            recovered.recovered_symbol_dict_count(),
            1,
            "the fold must stop AT the disagreeing frame, keeping the side-file's \
             prefix -- 2 means it folded the frame in over a contradicting prefix"
        );
        assert_eq!(
            recovered.recovered_symbol_dict_entries(),
            &[5, b'a', b'l', b'p', b'h', b'a'][..],
            "id 0 keeps the side-file's `alpha`; the frame's `zulu` is not adopted \
             and its `alpha` is not appended as a second id 1"
        );

        // The payoff: the recovered region is a usable dictionary, so recovery can
        // actually proceed. Unguarded this is `[alpha][alpha]`/2 and seeding fails.
        let mut dict = SymbolGlobalDict::new();
        dict.seed(
            recovered.recovered_symbol_dict_entries(),
            recovered.recovered_symbol_dict_count(),
        )
        .expect(
            "the rebuilt region must seed cleanly -- a duplicate here is what fails \
             construction on every later open",
        );
        assert_eq!(dict.next_id(), 1);
    }

    #[test]
    fn replay_only_slot_whose_first_chunk_is_corrupt_keeps_delta_armed() {
        // The orphan-drain twin of the test above, pinned separately because the
        // two branches fail differently and only one of them has a hazard to
        // weigh. `open_replay_only` builds no producer at all -- the recovered
        // dictionary is read-only for the whole drain, and `qwp_ws_orphan::open`
        // drops the side-file handle outright -- so the refill hazard that makes
        // a zero-entry file worth distrusting in `open` cannot arise here.
        //
        // What dense costs is the slot. `is_delta_dict_enabled` is what gates
        // seeding the drainer's catch-up mirror, so dense leaves it disabled:
        // the drainer replays the `delta_start == 0` frame, `guard_dict_not_torn`
        // rejects the `delta_start == K` frame behind it terminally, and
        // `OrphanDriveOutcome::RetryLater` puts the slot back on the pending
        // queue -- where the next open re-parses the same zero entries and
        // re-decides dense. It never drains and never fails: it live-locks,
        // holding a drainer for the life of the process while the frames behind
        // the first stay undelivered (and the replayed prefix is re-sent each
        // cycle). `qwp_ws_orphan_drain_replays_both_frames_when_the_first_dict_
        // chunk_is_corrupt` pins the drain end to end; this pins the queue-level
        // state it rests on.
        let dir = TempDir::new().unwrap();
        let symbol_dict = dir
            .path()
            .join(crate::ingress::sender::qwp_ws_sfa_symbol_dict::FILE_NAME);

        // An abandoned session leaves an unresolved segment plus a real one-chunk
        // side-file behind: the orphan slot a drainer later picks up.
        let mut queue = open(&dir);
        queue.try_submit(b"unresolved-frame").unwrap();
        drop(queue);
        {
            let mut pd = crate::ingress::sender::qwp_ws_sfa_symbol_dict::PersistedSymbolDict::open(
                dir.path(),
            )
            .unwrap();
            pd.append_symbol(b"alpha").unwrap();
        }

        // Same-length value flip inside the only chunk: its stored CRC goes
        // stale, so the parse stops at chunk 0 and recovers nothing.
        let mut bytes = std::fs::read(&symbol_dict).unwrap();
        let idx = bytes
            .windows(5)
            .position(|w| w == b"alpha")
            .expect("alpha entry present");
        bytes[idx] = b'X';
        std::fs::write(&symbol_dict, &bytes).unwrap();

        let queue = SfaFrameQueue::open_replay_only(options(&dir)).unwrap();

        assert!(
            queue.producer.is_none(),
            "replay-only has no producer, so nothing can refill the truncated \
             dictionary while the drain runs"
        );
        assert!(
            queue.is_delta_dict_enabled(),
            "a replay-only slot whose side-file parsed to zero entries must keep \
             delta armed so the drainer's mirror bootstraps from the stored \
             frames; dense here re-queues the slot forever"
        );
        assert!(
            queue.recovered_symbol_dict_entries().is_empty(),
            "the rejected chunk seeds nothing -- the mirror arms empty"
        );
        assert_eq!(queue.recovered_symbol_dict_count(), 0);
    }

    #[test]
    fn replay_only_slot_keeps_delta_armed_with_no_usable_side_file() {
        // The zero-entry case above and the absent / unreadable case reach the
        // drainer identically -- an empty mirror -- so they must be treated
        // identically, and both must stay ARMED. Dense here is what live-locks the
        // slot: the drainer replays the `delta_start == 0` frame, terminally rejects
        // the `delta_start == K` frame behind it, and `OrphanDriveOutcome::RetryLater`
        // puts the slot back on the pending queue for the next open to re-decide the
        // same way. It never drains and never fails, holding a drainer for the life
        // of the process while re-sending the replayed prefix each cycle.
        //
        // Armed, the mirror bootstraps from the frames' own delta sections instead.
        // Replay-only has no producer, so the refill hazard that makes an empty
        // dictionary worth distrusting in `open` cannot arise -- and unlike `open`,
        // nothing is re-created: a drainer must not write to a slot another process
        // may still own.
        for (name, seed_file) in [
            ("absent", None),
            ("bad magic", Some(&b"NOPEnope-poisoned-header"[..])),
        ] {
            let dir = TempDir::new().unwrap();
            let symbol_dict = dir
                .path()
                .join(crate::ingress::sender::qwp_ws_sfa_symbol_dict::FILE_NAME);

            let mut queue = open(&dir);
            queue.try_submit(b"unresolved-frame").unwrap();
            drop(queue);
            match seed_file {
                Some(bytes) => std::fs::write(&symbol_dict, bytes).unwrap(),
                None => std::fs::remove_file(&symbol_dict).unwrap(),
            }

            let queue = SfaFrameQueue::open_replay_only(options(&dir)).unwrap();
            assert!(
                queue.is_delta_dict_enabled(),
                "{name}: an orphan slot with no usable side-file must still arm the \
                 drainer's mirror, or it live-locks on RetryLater"
            );
            assert!(queue.recovered_symbol_dict_entries().is_empty());
            assert_eq!(queue.recovered_symbol_dict_count(), 0);
            if let Some(bytes) = seed_file {
                assert_eq!(
                    std::fs::read(&symbol_dict).unwrap(),
                    bytes,
                    "{name}: replay-only must not rewrite another owner's slot"
                );
            } else {
                assert!(
                    !symbol_dict.exists(),
                    "absent: replay-only must not fabricate a side-file"
                );
            }
        }
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
        let mut queue = SfaFrameQueue::open(options_with(&dir, 38, 38 * 8)).unwrap();
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
        let mut queue = SfaFrameQueue::open_memory(memory_options(38, 38 * 8)).unwrap();
        submit_with_storage_maintenance(&mut queue, b"one");
        let mut send_cursor = None;

        assert_eq!(next_cursor_payload_vec(&queue, &mut send_cursor, 0), b"one");

        submit_with_storage_maintenance(&mut queue, b"two");

        assert_eq!(next_cursor_payload_vec(&queue, &mut send_cursor, 1), b"two");
    }

    #[test]
    fn rotation_manifest_sync_does_not_block_segment_lookup() {
        let dir = TempDir::new().unwrap();
        let mut queue = SfaFrameQueue::open(options_with(&dir, 38, 38 * 4)).unwrap();
        let mut producer = queue.take_producer().unwrap();
        producer.try_submit(b"one").unwrap();

        let entered_sync = Arc::new(Barrier::new(2));
        let release_sync = Arc::new(Barrier::new(2));
        {
            let mut state = queue.engine.state.lock().unwrap();
            let entered_sync = Arc::clone(&entered_sync);
            let release_sync = Arc::clone(&release_sync);
            state
                .manifest
                .as_mut()
                .unwrap()
                .set_before_sync_hook(Arc::new(move || {
                    entered_sync.wait();
                    release_sync.wait();
                    Ok(())
                }));
        }

        let rotation = std::thread::spawn(move || producer.try_submit(b"two"));
        entered_sync.wait();

        let engine = Arc::clone(&queue.engine);
        let (lookup_done, lookup_result) = mpsc::channel();
        let lookup = std::thread::spawn(move || {
            let missed_without_blocking = engine.segment_for_fsn(1).is_none();
            lookup_done.send(missed_without_blocking).unwrap();
        });
        let completed_off_lock = lookup_result
            .recv_timeout(Duration::from_secs(1))
            .unwrap_or(false);
        assert!(queue.storage_maintenance_in_flight().unwrap());
        assert!(matches!(
            queue.close(),
            Err(SfaQueueError::StorageMaintenanceInFlight)
        ));

        release_sync.wait();
        rotation.join().unwrap().unwrap();
        lookup.join().unwrap();
        assert!(
            completed_off_lock,
            "cursor miss blocked behind manifest sync while rotation held engine state"
        );
    }

    #[test]
    fn failed_off_lock_rotation_restores_manifest_spare_and_capacity() {
        let dir = TempDir::new().unwrap();
        let mut queue = SfaFrameQueue::open(options_with(&dir, 38, 38 * 3)).unwrap();
        let mut producer = queue.take_producer().unwrap();
        producer.try_submit(b"one").unwrap();
        let allocated_before = queue.allocated_segment_bytes();
        {
            let mut state = queue.engine.state.lock().unwrap();
            state
                .manifest
                .as_mut()
                .unwrap()
                .set_before_sync_hook(Arc::new(|| {
                    Err(io::Error::other("injected manifest sync failure"))
                }));
        }

        assert!(matches!(
            producer.try_submit(b"two"),
            Err(SfaQueueError::Io(_))
        ));
        assert!(!queue.storage_maintenance_in_flight().unwrap());
        assert!(queue.hot_spare_installed());
        assert_eq!(queue.sealed_segment_count(), 0);
        assert_eq!(queue.allocated_segment_bytes(), allocated_before);

        queue
            .engine
            .state
            .lock()
            .unwrap()
            .manifest
            .as_mut()
            .unwrap()
            .clear_before_sync_hook();
        assert_eq!(producer.try_submit(b"two").unwrap().fsn, 1);
        assert_eq!(queue.sealed_segment_count(), 1);
        assert!(!queue.hot_spare_installed());
    }

    #[test]
    fn completed_hot_spare_is_abandoned_during_off_lock_rotation() {
        let dir = TempDir::new().unwrap();
        let mut queue = SfaFrameQueue::open(options_with(&dir, 38, 38 * 4)).unwrap();
        let mut producer = queue.take_producer().unwrap();
        producer.try_submit(b"one").unwrap();
        producer.try_submit(b"two").unwrap();

        let spare_step = queue.take_storage_maintenance_step(true).unwrap().unwrap();
        assert!(matches!(spare_step, SfaStorageStep::CreateHotSpare { .. }));
        let spare_result = spare_step.perform().unwrap();

        let entered_sync = Arc::new(Barrier::new(2));
        let release_sync = Arc::new(Barrier::new(2));
        {
            let mut state = queue.engine.state.lock().unwrap();
            let entered_sync = Arc::clone(&entered_sync);
            let release_sync = Arc::clone(&release_sync);
            state
                .manifest
                .as_mut()
                .unwrap()
                .set_before_sync_hook(Arc::new(move || {
                    entered_sync.wait();
                    release_sync.wait();
                    Ok(())
                }));
        }

        let rotation = std::thread::spawn(move || producer.try_submit(b"tri"));
        entered_sync.wait();

        let finish = queue
            .finish_storage_maintenance(spare_result, true)
            .unwrap();
        assert!(!finish.did_change());
        assert!(finish.into_cleanup().unwrap().perform().is_none());
        queue.complete_storage_maintenance().unwrap();
        assert!(queue.storage_maintenance_in_flight().unwrap());
        assert!(!queue.hot_spare_installed());

        release_sync.wait();
        assert_eq!(rotation.join().unwrap().unwrap().fsn, 2);
        assert_eq!(queue.sealed_segment_count(), 2);
        assert_eq!(queue.allocated_segment_bytes(), 38 * 3);
        assert_eq!(sfa_file_count(dir.path()), 3);
    }

    #[test]
    fn trim_manifest_sync_does_not_block_segment_lookup() {
        let dir = TempDir::new().unwrap();
        let mut queue = SfaFrameQueue::open(options_with(&dir, 38, 38 * 4)).unwrap();
        queue.try_submit(b"one").unwrap();
        queue.try_submit(b"two").unwrap();
        queue.complete_through_fsn(0).unwrap();
        let mut producer = queue.take_producer().unwrap();

        let entered_sync = Arc::new(Barrier::new(2));
        let release_sync = Arc::new(Barrier::new(2));
        {
            let mut state = queue.engine.state.lock().unwrap();
            let entered_sync = Arc::clone(&entered_sync);
            let release_sync = Arc::clone(&release_sync);
            state
                .manifest
                .as_mut()
                .unwrap()
                .set_before_sync_hook(Arc::new(move || {
                    entered_sync.wait();
                    release_sync.wait();
                    Ok(())
                }));
        }

        let engine = Arc::clone(&queue.engine);
        let trimming = std::thread::spawn(move || {
            let step = queue.take_storage_maintenance_step(false).unwrap().unwrap();
            (queue, step)
        });
        entered_sync.wait();

        let (lookup_done, lookup_result) = mpsc::channel();
        let lookup_engine = Arc::clone(&engine);
        let lookup = std::thread::spawn(move || {
            let found = lookup_engine.segment_for_fsn(0).is_some();
            lookup_done.send(found).unwrap();
        });
        let completed_off_lock = lookup_result
            .recv_timeout(Duration::from_secs(1))
            .unwrap_or(false);
        assert!(engine.storage_maintenance_in_flight().unwrap());
        assert!(matches!(
            producer.try_submit(b"tri"),
            Err(SfaQueueError::Queue(
                QueueError::StorageSpareNotReady { .. }
            ))
        ));

        release_sync.wait();
        let (mut queue, step) = trimming.join().unwrap();
        lookup.join().unwrap();
        assert!(
            completed_off_lock,
            "segment lookup blocked behind manifest sync while trim held engine state"
        );
        assert_eq!(queue.sealed_segment_count(), 0);
        queue
            .engine
            .state
            .lock()
            .unwrap()
            .manifest
            .as_mut()
            .unwrap()
            .clear_before_sync_hook();
        assert_eq!(producer.try_submit(b"tri").unwrap().fsn, 2);
        let result = step.perform().unwrap();
        queue.finish_storage_maintenance(result, true).unwrap();
        queue.complete_storage_maintenance().unwrap();
    }

    #[test]
    fn failed_off_lock_trim_is_deferred_and_keeps_live_prefix() {
        let dir = TempDir::new().unwrap();
        let mut queue = SfaFrameQueue::open(options_with(&dir, 38, 38 * 4)).unwrap();
        queue.try_submit(b"one").unwrap();
        queue.try_submit(b"two").unwrap();
        queue.complete_through_fsn(0).unwrap();
        let allocated_before = queue.allocated_segment_bytes();
        {
            let mut state = queue.engine.state.lock().unwrap();
            state
                .manifest
                .as_mut()
                .unwrap()
                .set_before_sync_hook(Arc::new(|| {
                    Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "injected manifest sync failure",
                    ))
                }));
        }

        assert!(
            queue
                .take_storage_maintenance_step(false)
                .unwrap()
                .is_none()
        );
        assert!(!queue.storage_maintenance_in_flight().unwrap());
        assert_eq!(queue.sealed_segment_count(), 1);
        assert_eq!(queue.allocated_segment_bytes(), allocated_before);
        assert!(queue.payload_vec_for_fsn(0).is_some());

        queue
            .engine
            .state
            .lock()
            .unwrap()
            .manifest
            .as_mut()
            .unwrap()
            .clear_before_sync_hook();
        assert_eq!(queue.try_submit(b"tri").unwrap().fsn, 2);

        // A failed optional trim must neither terminate the sender nor hammer
        // the same barrier again on every maintenance tick.
        assert!(
            queue
                .take_storage_maintenance_step(false)
                .unwrap()
                .is_none()
        );
        queue.engine.state.lock().unwrap().trim_retry_at = Some(Instant::now());
        let step = queue.take_storage_maintenance_step(false).unwrap().unwrap();
        assert_eq!(queue.sealed_segment_count(), 1);
        let result = step.perform().unwrap();
        queue.finish_storage_maintenance(result, true).unwrap();
        queue.complete_storage_maintenance().unwrap();
        assert_eq!(queue.allocated_segment_bytes(), allocated_before);
        assert!(queue.payload_vec_for_fsn(0).is_none());
        assert!(queue.payload_vec_for_fsn(1).is_some());
        assert!(queue.engine.state.lock().unwrap().trim_retry_at.is_none());
    }

    /// Run with:
    /// `cargo test --features sync-sender-qwp-ws --lib sfa_tiny_frame_publish_zero_alloc_after_warmup -- --ignored --test-threads=1`
    #[test]
    #[ignore = "uses the process-global allocation counter"]
    fn sfa_tiny_frame_publish_zero_alloc_after_warmup() {
        use crate::alloc_counter;

        let dir = TempDir::new().unwrap();
        let mut queue = SfaFrameQueue::open(options_with(&dir, 4096, 8192)).unwrap();
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

        let mut queue = SfaFrameQueue::open_memory(memory_options(4096, 8192)).unwrap();
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

        let mut queue = SfaFrameQueue::open_memory(memory_options(38, 38 * 8)).unwrap();
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
            let mut queue = SfaFrameQueue::open(options_with(&dir, 38, 1024)).unwrap();
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

        let recovered = SfaFrameQueue::open(options_with(&dir, 38, 1024)).unwrap();
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
            SfaFrameQueue::open(options_with(&one_segment_dir, 48, 48)),
            Err(SfaQueueError::Queue(QueueError::InvalidCapacity))
        ));
        assert_eq!(sfa_file_count(one_segment_dir.path()), 0);

        let undersized_dir = TempDir::new().unwrap();
        assert!(matches!(
            SfaFrameQueue::open(options_with(&undersized_dir, 48, 95)),
            Err(SfaQueueError::Queue(QueueError::InvalidCapacity))
        ));
        assert_eq!(sfa_file_count(undersized_dir.path()), 0);

        let publishable_dir = TempDir::new().unwrap();
        let queue = SfaFrameQueue::open(options_with(&publishable_dir, 48, 96)).unwrap();
        assert!(queue.hot_spare_installed());
        assert_eq!(queue.allocated_segment_bytes(), 96);
        assert_eq!(sfa_file_count(publishable_dir.path()), 2);
    }

    #[test]
    fn rotation_uses_prepared_hot_spare_and_respects_segment_cap() {
        let dir = TempDir::new().unwrap();
        let mut queue = SfaFrameQueue::open(options_with(&dir, 38, 76)).unwrap();

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
        let mut queue = SfaFrameQueue::open(options_with(&dir, 38, 76)).unwrap();
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
        let mut queue = SfaFrameQueue::open(options_with(&dir, 38, 114)).unwrap();
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
        let result = step.perform().unwrap();
        assert_eq!(
            take_sfa_barriers(),
            vec![
                trim_unlinked_event(dir.path(), 0),
                SfaBarrierEvent::TrimCleanupDirectorySynced,
            ]
        );
        queue.finish_storage_maintenance(result, true).unwrap();
        queue.complete_storage_maintenance().unwrap();
    }

    #[test]
    fn trim_batches_only_the_acked_prefix_under_one_barrier_set() {
        let dir = TempDir::new().unwrap();
        let options = options_with(&dir, 38, 38 * 6);
        let mut queue = SfaFrameQueue::open(options.clone()).unwrap();
        for payload in [b"one".as_slice(), b"two", b"tri", b"for", b"five"] {
            queue.try_submit(payload).unwrap();
        }
        assert_eq!(queue.sealed_segment_count(), 4);
        queue.complete_through_fsn(2).unwrap();
        take_sfa_barriers();

        let step = queue.take_storage_maintenance_step(false).unwrap().unwrap();
        assert!(matches!(step, SfaStorageStep::Trim(_)));
        assert_eq!(queue.sealed_segment_count(), 1);
        assert_eq!(
            take_sfa_barriers(),
            vec![
                SfaBarrierEvent::TrimWatermarkWritten,
                SfaBarrierEvent::TrimWatermarkSynced,
                SfaBarrierEvent::TrimDirectorySynced,
                SfaBarrierEvent::TrimManifestUpdated,
                SfaBarrierEvent::TrimQueuePopped,
                SfaBarrierEvent::TrimQueuePopped,
                SfaBarrierEvent::TrimQueuePopped,
            ]
        );

        let result = step.perform().unwrap();
        assert_eq!(
            take_sfa_barriers(),
            vec![
                trim_unlinked_event(dir.path(), 0),
                trim_unlinked_event(dir.path(), 1),
                trim_unlinked_event(dir.path(), 2),
                SfaBarrierEvent::TrimCleanupDirectorySynced,
            ]
        );
        queue.finish_storage_maintenance(result, true).unwrap();
        queue.complete_storage_maintenance().unwrap();
        assert_eq!(sfa_file_count(dir.path()), 2);

        drop(queue);
        let recovered = SfaFrameQueue::open(options).unwrap();
        assert_eq!(recovered.completed_fsn(), Some(2));
        assert_eq!(
            recovered.payload_vec_for_fsn(3).as_deref(),
            Some(&b"for"[..])
        );
        assert_eq!(
            recovered.payload_vec_for_fsn(4).as_deref(),
            Some(&b"five"[..])
        );
        assert!(recovered.payload_vec_for_fsn(0).is_none());
    }

    #[test]
    fn trim_batch_manifest_commit_recovers_before_unlinks() {
        let dir = TempDir::new().unwrap();
        let options = options_with(&dir, 38, 38 * 5);
        let mut queue = SfaFrameQueue::open(options.clone()).unwrap();
        for payload in [b"one".as_slice(), b"two", b"tri", b"for"] {
            queue.try_submit(payload).unwrap();
        }
        queue.complete_through_fsn(1).unwrap();

        // Taking the task durably advances the manifest past the two ACKed
        // segments. Simulate a crash before the task can unlink either file.
        let step = queue.take_storage_maintenance_step(false).unwrap().unwrap();
        assert!(matches!(step, SfaStorageStep::Trim(_)));
        assert_eq!(queue.sealed_segment_count(), 1);
        assert_eq!(sfa_file_count(dir.path()), 4);
        drop(step);
        drop(queue);

        let recovered = SfaFrameQueue::open(options).unwrap();
        assert_eq!(recovered.completed_fsn(), Some(1));
        assert!(recovered.payload_vec_for_fsn(0).is_none());
        assert_eq!(
            recovered.payload_vec_for_fsn(2).as_deref(),
            Some(&b"tri"[..])
        );
        assert_eq!(
            recovered.payload_vec_for_fsn(3).as_deref(),
            Some(&b"for"[..])
        );
    }

    #[test]
    fn trim_batch_is_bounded() {
        let segment_count = MAX_TRIMS_PER_STORAGE_STEP + 2;
        let mut queue =
            SfaFrameQueue::open_memory(memory_options(38, 38 * (segment_count + 1))).unwrap();
        for _ in 0..segment_count {
            queue.try_submit(b"x").unwrap();
        }
        assert_eq!(queue.sealed_segment_count(), segment_count - 1);
        queue
            .complete_through_fsn((segment_count - 1) as u64)
            .unwrap();

        let step = queue.take_storage_maintenance_step(false).unwrap().unwrap();
        assert!(matches!(step, SfaStorageStep::Trim(_)));
        assert_eq!(
            queue.sealed_segment_count(),
            segment_count - 1 - MAX_TRIMS_PER_STORAGE_STEP
        );
        let result = step.perform().unwrap();
        queue.finish_storage_maintenance(result, true).unwrap();
        queue.complete_storage_maintenance().unwrap();

        let step = queue.take_storage_maintenance_step(false).unwrap().unwrap();
        let result = step.perform().unwrap();
        queue.finish_storage_maintenance(result, true).unwrap();
        queue.complete_storage_maintenance().unwrap();
        assert_eq!(queue.sealed_segment_count(), 0);
    }

    #[test]
    fn rotation_allocates_inline_when_hot_spare_missing() {
        // Budget for 4 segments; active + hot spare are pre-created. After the
        // spare is consumed by the first rotation, further rotations must
        // self-provision segments inline — without any maintenance running
        // (the runner may be parked in a blocking socket send) — until the
        // byte budget is exhausted.
        let mut queue = SfaFrameQueue::open_memory(memory_options(48, 192)).unwrap();

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
        let mut queue = SfaFrameQueue::open(options_with(&dir, 38, 152)).unwrap();
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
        let mut queue = SfaFrameQueue::open(options_with(&dir, 38, 114)).unwrap();

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
        let mut queue = SfaFrameQueue::open(options_with(&dir, 38, 114)).unwrap();
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
        let queue = SfaFrameQueue::open(options_with(&dir, 256, 512)).unwrap();
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
    fn in_flight_hot_spare_blocks_close_until_abandoned() {
        let dir = TempDir::new().unwrap();
        let mut queue = SfaFrameQueue::open(options_with(&dir, 38, 114)).unwrap();
        queue.try_submit(b"first").unwrap();
        queue.try_submit(b"second").unwrap();
        assert_eq!(sfa_file_count(dir.path()), 2);
        assert_eq!(queue.allocated_segment_bytes(), 76);

        let step = queue.take_storage_maintenance_step(true).unwrap().unwrap();
        assert!(!step.changes_queue_before_io());
        let result = step.perform().unwrap();
        assert_eq!(sfa_file_count(dir.path()), 3);

        assert!(matches!(
            queue.close(),
            Err(SfaQueueError::StorageMaintenanceInFlight)
        ));
        let finish = queue.finish_storage_maintenance(result, false).unwrap();
        assert!(!finish.did_change());
        assert_eq!(queue.allocated_segment_bytes(), 76);

        let cleanup = finish
            .into_cleanup()
            .expect("created spare should be abandoned");
        assert!(cleanup.perform().is_none());
        queue.complete_storage_maintenance().unwrap();
        queue.close().unwrap();
        assert_eq!(sfa_file_count(dir.path()), 2);
    }

    #[test]
    fn fully_drained_close_waits_for_in_flight_hot_spare_creation() {
        let dir = TempDir::new().unwrap();
        let mut queue = SfaFrameQueue::open(options_with(&dir, 38, 114)).unwrap();
        queue.try_submit(b"first").unwrap();
        let last = queue.try_submit(b"second").unwrap();
        queue.complete_through_fsn(last.fsn).unwrap();
        assert!(queue.maintain_storage().unwrap());
        assert!(!queue.hot_spare_installed());

        let step = queue.take_storage_maintenance_step(true).unwrap().unwrap();
        assert!(matches!(step, SfaStorageStep::CreateHotSpare { .. }));

        assert!(matches!(
            queue.close(),
            Err(SfaQueueError::StorageMaintenanceInFlight)
        ));

        let result = step.perform().unwrap();
        let finish = queue.finish_storage_maintenance(result, false).unwrap();
        assert!(finish.into_cleanup().unwrap().perform().is_none());
        queue.complete_storage_maintenance().unwrap();
        queue.close().unwrap();
        assert_eq!(sfa_file_count(dir.path()), 0);
    }

    #[test]
    fn fully_drained_close_waits_for_in_flight_trim_cleanup() {
        let dir = TempDir::new().unwrap();
        let mut queue = SfaFrameQueue::open(options_with(&dir, 38, 114)).unwrap();
        queue.try_submit(b"first").unwrap();
        let last = queue.try_submit(b"second").unwrap();
        queue.complete_through_fsn(last.fsn).unwrap();

        let step = queue.take_storage_maintenance_step(false).unwrap().unwrap();
        assert!(matches!(step, SfaStorageStep::Trim(_)));
        assert!(matches!(
            queue.close(),
            Err(SfaQueueError::StorageMaintenanceInFlight)
        ));

        let result = step.perform().unwrap();
        queue.finish_storage_maintenance(result, false).unwrap();
        queue.complete_storage_maintenance().unwrap();
        queue.close().unwrap();
        assert_eq!(sfa_file_count(dir.path()), 0);
    }

    #[test]
    fn abandoned_hot_spare_after_lifecycle_change_does_not_change_capacity_or_leak_file() {
        let dir = TempDir::new().unwrap();
        let mut queue = SfaFrameQueue::open(options_with(&dir, 38, 114)).unwrap();
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
        queue.complete_storage_maintenance().unwrap();
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

        let mut queue = SfaFrameQueue::open(options_with(&dir, 38, 38)).unwrap();

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
        let mut queue = SfaFrameQueue::open(options_with(&dir, 38, 1024)).unwrap();
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
        let mut queue = SfaFrameQueue::open(options_with(&dir, 38, 76)).unwrap();
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
