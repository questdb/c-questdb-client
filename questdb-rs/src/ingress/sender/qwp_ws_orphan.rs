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

//! QWP/WebSocket Store-and-Forward orphan-slot discovery and draining.

#[cfg(feature = "sync-sender-qwp-ws")]
use std::collections::VecDeque;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
#[cfg(feature = "sync-sender-qwp-ws")]
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
#[cfg(feature = "sync-sender-qwp-ws")]
use std::sync::{Arc, Mutex};
#[cfg(feature = "sync-sender-qwp-ws")]
use std::thread;
#[cfg(feature = "sync-sender-qwp-ws")]
use std::time::{Duration, Instant};

#[cfg(feature = "sync-sender-qwp-ws")]
use crate::ErrorCode;
#[cfg(feature = "sync-sender-qwp-ws")]
use crate::ingress::buffer::SymbolGlobalDict;
#[cfg(feature = "sync-sender-qwp-ws")]
use crate::ingress::conf::QwpWsConfig;
use crate::ingress::conf::QwpWsManagedSlotExclusion;
#[cfg(feature = "sync-sender-qwp-ws")]
use crate::ingress::tls::TlsSettings;

#[cfg(feature = "sync-sender-qwp-ws")]
use super::qwp_ws::{QwpWsConnectKind, TrafficGate, try_dup_recovered};
#[cfg(feature = "sync-sender-qwp-ws")]
use super::qwp_ws_driver::{
    BlockingQwpWsTransport, CloseStepOutcome, DEFAULT_EVENT_CAPACITY, DriverError, PublicationLog,
    QwpWsPublicationStore, QwpWsSendCore, ReconnectPolicy,
};
#[cfg(feature = "sync-sender-qwp-ws")]
use super::qwp_ws_sfa_queue::{SfaQueueError, SfaQueueOptions};
#[cfg(feature = "sync-sender-qwp-ws")]
use super::qwp_ws_sfa_slot::SfaSlotQueue;

pub(crate) const FAILED_SENTINEL_NAME: &str = ".failed";
#[cfg(feature = "sync-sender-qwp-ws")]
const LAST_ERROR_NAME: &str = ".last_error";
#[cfg(feature = "sync-sender-qwp-ws")]
const ORPHAN_IDLE_PARK: Duration = Duration::from_millis(50);
#[cfg(feature = "sync-sender-qwp-ws")]
const ORPHAN_POOL_GRACEFUL_DRAIN: Duration = Duration::from_millis(2500);
#[cfg(feature = "sync-sender-qwp-ws")]
const ORPHAN_POOL_STOP_GRACE: Duration = Duration::from_millis(500);
#[cfg(feature = "sync-sender-qwp-ws")]
const ORPHAN_POOL_CLOSE_POLL: Duration = Duration::from_millis(10);

pub(crate) fn scan_orphan_slots(
    sf_dir: &Path,
    own_sender_id: &str,
    managed_exclusions: &[QwpWsManagedSlotExclusion],
) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(sf_dir) else {
        return Vec::new();
    };
    let mut orphans = Vec::new();
    for entry in entries.flatten() {
        let slot_path = entry.path();
        if !slot_path.is_dir() {
            continue;
        }
        if entry.file_name().to_str() == Some(own_sender_id) {
            continue;
        }
        if entry.file_name().to_str().is_some_and(|name| {
            managed_exclusions
                .iter()
                .any(|exclusion| exclusion.matches(name))
        }) {
            continue;
        }
        if !is_candidate_orphan(&slot_path) {
            continue;
        }
        orphans.push(slot_path);
    }
    orphans
}

pub(crate) fn is_candidate_orphan(slot_dir: &Path) -> bool {
    !has_failed_sentinel(slot_dir) && has_any_sfa_file(slot_dir)
}

pub(crate) fn has_failed_sentinel(slot_dir: &Path) -> bool {
    slot_dir.join(FAILED_SENTINEL_NAME).exists()
}

pub(crate) fn mark_failed(slot_dir: &Path, reason: &str) -> io::Result<()> {
    fs::write(slot_dir.join(FAILED_SENTINEL_NAME), reason)
}

pub(crate) fn has_any_sfa_file(slot_dir: &Path) -> bool {
    let Ok(entries) = fs::read_dir(slot_dir) else {
        return false;
    };
    entries
        .flatten()
        .any(|entry| entry.path().file_name().is_some_and(is_sfa_file_name))
}

fn is_sfa_file_name(name: &std::ffi::OsStr) -> bool {
    name.to_str().is_some_and(|name| name.ends_with(".sfa"))
}

#[cfg(feature = "sync-sender-qwp-ws")]
#[derive(Clone)]
pub(crate) struct OrphanDrainerConfig {
    host: String,
    port: String,
    use_tls: bool,
    tls_settings: Option<TlsSettings>,
    qwp_ws: QwpWsConfig,
    auth_header: Option<String>,
}

#[cfg(feature = "sync-sender-qwp-ws")]
impl OrphanDrainerConfig {
    pub(crate) fn new(
        host: &str,
        port: &str,
        use_tls: bool,
        tls_settings: Option<TlsSettings>,
        qwp_ws: &QwpWsConfig,
        auth_header: Option<String>,
    ) -> Self {
        Self {
            host: host.to_owned(),
            port: port.to_owned(),
            use_tls,
            tls_settings,
            qwp_ws: qwp_ws.clone(),
            auth_header,
        }
    }

    fn queue_options(&self, slot_dir: PathBuf) -> Result<SfaQueueOptions, String> {
        let max_bytes = usize::try_from(self.qwp_ws.sf_max_total_bytes())
            .map_err(|_| "sf_max_total_bytes value is too large for this platform".to_owned())?;
        Ok(SfaQueueOptions {
            slot_dir,
            segment_size_bytes: *self.qwp_ws.sf_max_segment_bytes,
            max_bytes,
            max_in_flight: *self.qwp_ws.max_in_flight,
            periodic_sync_interval: self.qwp_ws.periodic_sync_interval(),
        })
    }
}

#[cfg(feature = "sync-sender-qwp-ws")]
pub(crate) struct OrphanDrainerPool {
    stop: Arc<AtomicBool>,
    threads: Vec<(thread::JoinHandle<()>, Arc<TrafficGate>)>,
}

#[cfg(feature = "sync-sender-qwp-ws")]
impl OrphanDrainerPool {
    pub(crate) fn start(
        candidates: Vec<PathBuf>,
        max_background_drainers: usize,
        config: OrphanDrainerConfig,
    ) -> Option<Self> {
        if candidates.is_empty() || max_background_drainers == 0 {
            return None;
        }
        let pending = Arc::new(Mutex::new(VecDeque::from(candidates)));
        let stop = Arc::new(AtomicBool::new(false));
        let worker_count = max_background_drainers.min(pending.lock().ok()?.len());
        let mut threads = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            let pending = Arc::clone(&pending);
            let stop = Arc::clone(&stop);
            let config = config.clone();
            let traffic_gate = Arc::new(TrafficGate::default());
            let worker_gate = Arc::clone(&traffic_gate);
            let worker = thread::spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    let Some(slot_dir) = pop_pending_orphan(&pending) else {
                        break;
                    };
                    drain_orphan_to_completion(slot_dir, &config, &stop, &worker_gate);
                }
            });
            threads.push((worker, traffic_gate));
        }
        Some(Self { stop, threads })
    }

    pub(crate) fn close(&mut self) {
        self.close_with_timeouts(ORPHAN_POOL_GRACEFUL_DRAIN, ORPHAN_POOL_STOP_GRACE);
    }

    fn close_with_timeouts(&mut self, graceful_drain: Duration, stop_grace: Duration) {
        self.join_finished_threads();
        self.wait_for_finished_threads(graceful_drain);
        self.stop.store(true, Ordering::Release);
        self.join_finished_threads();
        for (_, traffic_gate) in &self.threads {
            if let Err(err) = traffic_gate.shutdown() {
                log::warn!("could not shut down QWP/WebSocket orphan drainer traffic: {err}");
            }
        }
        self.wait_for_finished_threads(stop_grace);
        if !self.threads.is_empty() {
            log::error!(
                "{} QWP/WebSocket orphan drainer worker(s) did not stop within {:?}; \
                 detaching them while their active slot locks remain retained",
                self.threads.len(),
                stop_grace
            );
        }
        self.threads.clear();
    }

    fn wait_for_finished_threads(&mut self, timeout: Duration) {
        let Some(deadline) = Instant::now().checked_add(timeout) else {
            return;
        };
        while !self.threads.is_empty() {
            self.join_finished_threads();
            if self.threads.is_empty() {
                return;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return;
            }
            thread::sleep(remaining.min(ORPHAN_POOL_CLOSE_POLL));
        }
    }

    fn join_finished_threads(&mut self) {
        let mut running = Vec::with_capacity(self.threads.len());
        for (thread, traffic_gate) in self.threads.drain(..) {
            if thread.is_finished() {
                let _ = thread.join();
            } else {
                running.push((thread, traffic_gate));
            }
        }
        self.threads = running;
    }
}

#[cfg(feature = "sync-sender-qwp-ws")]
impl Drop for OrphanDrainerPool {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(feature = "sync-sender-qwp-ws")]
pub(crate) struct ManualOrphanDrainers {
    pending: VecDeque<PathBuf>,
    active: Vec<OrphanDrainer>,
    next_active: usize,
    max_active: usize,
    config: OrphanDrainerConfig,
}

#[cfg(feature = "sync-sender-qwp-ws")]
impl ManualOrphanDrainers {
    pub(crate) fn new(
        candidates: Vec<PathBuf>,
        max_active: usize,
        config: OrphanDrainerConfig,
    ) -> Option<Self> {
        if candidates.is_empty() || max_active == 0 {
            return None;
        }
        Some(Self {
            pending: VecDeque::from(candidates),
            active: Vec::new(),
            next_active: 0,
            max_active,
            config,
        })
    }

    pub(crate) fn drive_once(&mut self) -> bool {
        if self.active.len() < self.max_active && self.activate_one() {
            return true;
        }
        self.drive_active_once()
    }

    fn activate_one(&mut self) -> bool {
        let Some(slot_dir) = self.pending.pop_front() else {
            return false;
        };
        if has_failed_sentinel(&slot_dir) {
            return true;
        }
        match OrphanDrainer::open(slot_dir.clone(), &self.config) {
            OrphanOpenOutcome::Drainer(drainer) => {
                self.active.push(*drainer);
                true
            }
            OrphanOpenOutcome::AlreadyDrained
            | OrphanOpenOutcome::FailedSentinel
            | OrphanOpenOutcome::Locked
            | OrphanOpenOutcome::Stopped => true,
            OrphanOpenOutcome::RetryLater(reason) => {
                let _ = record_last_error(&slot_dir, &reason);
                self.pending.push_back(slot_dir);
                true
            }
            OrphanOpenOutcome::Unrecoverable(reason) => {
                let _ = mark_failed(&slot_dir, &reason);
                true
            }
        }
    }

    fn drive_active_once(&mut self) -> bool {
        if self.active.is_empty() {
            return false;
        }
        let active_count = self.active.len();
        for _ in 0..active_count {
            let index = self.next_active % self.active.len();
            self.next_active = (index + 1) % self.active.len();
            match self.active[index].drive_once() {
                OrphanDriveOutcome::Idle => {}
                OrphanDriveOutcome::Progress => return true,
                OrphanDriveOutcome::Drained => {
                    let drainer = self.active.remove(index);
                    drainer.clear_last_error();
                    self.normalize_next_active();
                    return true;
                }
                OrphanDriveOutcome::RetryLater(reason) => {
                    let drainer = self.active.remove(index);
                    drainer.record_last_error(&reason);
                    self.pending.push_back(drainer.slot_dir.clone());
                    self.normalize_next_active();
                    return true;
                }
                OrphanDriveOutcome::Terminal(reason) => {
                    let drainer = self.active.remove(index);
                    drainer.record_last_error(&reason);
                    self.pending.push_back(drainer.slot_dir.clone());
                    self.normalize_next_active();
                    return true;
                }
                OrphanDriveOutcome::Unrecoverable(reason) => {
                    let drainer = self.active.remove(index);
                    let _ = mark_failed(&drainer.slot_dir, &reason);
                    self.normalize_next_active();
                    return true;
                }
                OrphanDriveOutcome::Stopped => return true,
            }
        }
        false
    }

    fn normalize_next_active(&mut self) {
        if self.active.is_empty() {
            self.next_active = 0;
        } else {
            self.next_active %= self.active.len();
        }
    }
}

#[cfg(feature = "sync-sender-qwp-ws")]
struct OrphanDrainer {
    slot_dir: PathBuf,
    store: QwpWsPublicationStore<SfaSlotQueue>,
    send_core: QwpWsSendCore<BlockingQwpWsTransport>,
}

#[cfg(feature = "sync-sender-qwp-ws")]
enum OrphanOpenOutcome {
    Drainer(Box<OrphanDrainer>),
    AlreadyDrained,
    FailedSentinel,
    Locked,
    RetryLater(String),
    Stopped,
    Unrecoverable(String),
}

#[cfg(feature = "sync-sender-qwp-ws")]
enum OrphanDriveOutcome {
    Idle,
    Progress,
    Drained,
    Stopped,
    /// A non-terminal drive failure that may make progress on the same store.
    RetryLater(String),
    /// A sticky store terminal: release this drainer and retry only from a fresh
    /// adoption/session.
    Terminal(String),
    /// Proven-local durable state that cannot succeed on a fresh session.
    Unrecoverable(String),
}

#[cfg(feature = "sync-sender-qwp-ws")]
impl OrphanDrainer {
    fn open(slot_dir: PathBuf, config: &OrphanDrainerConfig) -> OrphanOpenOutcome {
        Self::open_inner(slot_dir, config, None, None)
    }

    fn open_with_stop(
        slot_dir: PathBuf,
        config: &OrphanDrainerConfig,
        stop: &AtomicBool,
        traffic_gate: &Arc<TrafficGate>,
    ) -> OrphanOpenOutcome {
        Self::open_inner(slot_dir, config, Some(stop), Some(traffic_gate))
    }

    fn open_inner(
        slot_dir: PathBuf,
        config: &OrphanDrainerConfig,
        stop: Option<&AtomicBool>,
        traffic_gate: Option<&Arc<TrafficGate>>,
    ) -> OrphanOpenOutcome {
        if orphan_stop_requested(stop) {
            return OrphanOpenOutcome::Stopped;
        }
        if has_failed_sentinel(&slot_dir) {
            return OrphanOpenOutcome::FailedSentinel;
        }
        let options = match config.queue_options(slot_dir.clone()) {
            Ok(options) => options,
            Err(err) => return OrphanOpenOutcome::RetryLater(err),
        };
        let mut queue = match SfaSlotQueue::open_replay_only_existing(options) {
            Ok(queue) => queue,
            Err(SfaQueueError::SlotInUse { .. }) => return OrphanOpenOutcome::Locked,
            Err(SfaQueueError::SanitizedResidue { .. }) => {
                // Retry internally because this path is unattended and must
                // not quarantine replayable data.
                let retry_options = match config.queue_options(slot_dir.clone()) {
                    Ok(options) => options,
                    Err(err) => return OrphanOpenOutcome::RetryLater(err),
                };
                match SfaSlotQueue::open_replay_only_existing(retry_options) {
                    Ok(queue) => queue,
                    Err(SfaQueueError::SlotInUse { .. }) => {
                        return OrphanOpenOutcome::Locked;
                    }
                    Err(
                        err @ (SfaQueueError::SanitizedResidue { .. }
                        | SfaQueueError::Recovery { .. }
                        | SfaQueueError::CorruptSegments { .. }),
                    ) => {
                        return OrphanOpenOutcome::Unrecoverable(format!("{err:?}"));
                    }
                    Err(err) => return OrphanOpenOutcome::RetryLater(format!("{err:?}")),
                }
            }
            Err(err @ (SfaQueueError::Recovery { .. } | SfaQueueError::CorruptSegments { .. })) => {
                return OrphanOpenOutcome::Unrecoverable(format!("{err:?}"));
            }
            Err(err) => return OrphanOpenOutcome::RetryLater(format!("{err:?}")),
        };
        if orphan_stop_requested(stop) {
            return OrphanOpenOutcome::Stopped;
        }
        if has_failed_sentinel(&slot_dir) {
            return OrphanOpenOutcome::FailedSentinel;
        }
        if orphan_queue_drained(&queue) {
            if let Err(err) = queue.close() {
                let reason = format!("{err:?}");
                return retry_open_later(reason, stop);
            }
            let _ = clear_last_error(&slot_dir);
            return OrphanOpenOutcome::AlreadyDrained;
        }
        // Threaded orphan drainers carry a stop flag; manual-progress drainers
        // do not. Only the threaded/background form gets the finite fallback.
        let connect_kind = if stop.is_some() {
            QwpWsConnectKind::BackgroundDrainer
        } else {
            QwpWsConnectKind::Foreground
        };
        let transport = match BlockingQwpWsTransport::connect(
            config.host.clone(),
            config.port.clone(),
            config.use_tls,
            config.tls_settings.clone(),
            connect_kind,
            config.qwp_ws.clone(),
            config.auth_header.clone(),
            Arc::new(AtomicUsize::new(0)),
            traffic_gate.cloned(),
        ) {
            Ok(transport) => transport,
            Err(err) => return retry_open_later(err.to_string(), stop),
        };
        if orphan_stop_requested(stop) {
            return OrphanOpenOutcome::Stopped;
        }
        let max_in_flight = queue.max_in_flight();
        // A delta-encoded slot's stored frames are not self-sufficient, so before
        // replaying them to the fresh server the drainer must re-register the whole
        // dictionary via a catch-up frame -- exactly as the foreground does on
        // reconnect. Seed the mirror from the slot's persisted side-file (read-only
        // here: draining only replays stored frames, so there is no write-ahead and
        // the side-file handle stays with the queue). A dense (memory-mode) slot
        // reports delta disabled and needs none of this.
        let delta_dict_enabled = queue.is_delta_dict_enabled();
        // Fallible copy: a large recovered dictionary (up to ~2 GiB for a crafted
        // CRC-valid side-file) must not abort the drainer via an infallible `to_vec`;
        // the foreground guards the same copy with `try_dup_recovered`. On OOM, degrade
        // to dense (leave the mirror disabled) -- the same fallback the corrupt-dict
        // branch below takes -- so the drainer still replays the slot's frames instead
        // of crashing.
        let recovered_dict_entries = if delta_dict_enabled {
            match try_dup_recovered(queue.recovered_symbol_dict_entries()) {
                Ok(entries) => Some(entries),
                Err(err) => {
                    log::warn!(
                        "QWP/WebSocket orphan slot {}: recovered symbol dictionary is \
                         too large to allocate ({err}); draining with full-dictionary \
                         (dense) frames.",
                        slot_dir.display()
                    );
                    None
                }
            }
        } else {
            None
        };
        let recovered_dict_count = queue.recovered_symbol_dict_count();
        // The orphan drainer is replay-only: it seeds the catch-up mirror from the
        // recovered dictionary (copied out above) and never write-aheads, so it does
        // not need the side-file handle. Drop it now -- freeing the recovered entry
        // region (up to ~2 GiB) and closing the fd -- rather than carrying it dead for
        // the whole drain. This mirrors the foreground recovery paths, which
        // `take_persisted_symbol_dict` once the entries have been copied out for
        // seeding; here the taken handle is simply dropped (no write-ahead). Must
        // follow the `recovered_symbol_dict_{entries,count}` reads above, since a take
        // clears the region they borrow.
        let _ = queue.take_persisted_symbol_dict();
        let store = QwpWsPublicationStore::new(queue, DEFAULT_EVENT_CAPACITY);
        let mut send_core = QwpWsSendCore::new_with_durable_ack_and_rejection_limit(
            transport,
            max_in_flight,
            ReconnectPolicy::bounded(
                *config.qwp_ws.reconnect_max_duration,
                *config.qwp_ws.reconnect_initial_backoff,
                *config.qwp_ws.reconnect_max_backoff,
            ),
            // Honour the connect string's request_durable_ack, exactly like the
            // foreground sender. When durable-ack was requested the orphan slot
            // must be trimmed only on durable ACKs, not ordinary OKs -- otherwise
            // an OK'd-but-not-yet-durable orphan frame is dropped on a plain OK
            // and is lost when the primary fails over before the WAL upload,
            // instead of surviving in the slot and replaying to the successor.
            *config.qwp_ws.request_durable_ack,
            *config.qwp_ws.max_frame_rejections,
            *config.qwp_ws.poison_min_escalation_window,
        );
        if let Some(recovered_dict_entries) = recovered_dict_entries {
            // The orphan replay path builds no producer `SymbolGlobalDict`, so --
            // unlike the foreground recovery paths (`new_store_and_forward` /
            // `QwpWsReplayEncoder::seed_global_dict`, which seed one and propagate
            // its error) -- it would otherwise arm the mirror without ever running
            // `SymbolGlobalDict::seed`'s duplicate/torn-tail rejection. A host/power
            // crash can zero-extend the persisted side-file into a run of empty
            // `[len=0]` entries that inflate `recovered_dict_count`; seeding the
            // driver mirror with that inflated count slackens the torn-dict guard
            // (`delta_start > mirror.count()`) and lets a stored delta frame replay
            // against a desynced dictionary -- resolving ids to the wrong / empty
            // symbols on the fresh server (silent corruption). Validate the
            // recovered region with the exact same check the foreground uses (the
            // shared `SymbolGlobalDict::seed`, so the two paths cannot diverge):
            // only arm delta if a throwaway seed rebuilds a well-formed
            // (unique-entry) dictionary. On failure fall back to dense -- leave the
            // mirror disabled -- so `guard_dict_not_torn` rejects any surviving
            // `delta_start > 0` frame loudly ("resend required") instead of
            // replaying it silently, exactly the dense fallback the queue already
            // takes for an absent / bad-magic side-file.
            let recovered_dict_intact = SymbolGlobalDict::new()
                .seed(&recovered_dict_entries, recovered_dict_count)
                .is_ok();
            if recovered_dict_intact {
                send_core.enable_delta_dict(&recovered_dict_entries, recovered_dict_count);
            } else {
                log::warn!(
                    "QWP/WebSocket orphan slot {}: persisted symbol dictionary is \
                     corrupt (duplicate / torn or zero-extended tail); draining with \
                     full-dictionary (dense) frames -- any stored delta frame that \
                     depends on the lost dictionary is rejected as resend-required \
                     rather than replayed against a desynced dictionary.",
                    slot_dir.display()
                );
            }
        }
        OrphanOpenOutcome::Drainer(Box::new(Self {
            slot_dir,
            store,
            send_core,
        }))
    }

    fn drive_once(&mut self) -> OrphanDriveOutcome {
        match self.send_core.close_drain_ready_step(&mut self.store) {
            Ok(CloseStepOutcome::Drained) => OrphanDriveOutcome::Drained,
            Ok(CloseStepOutcome::Terminal) => self.terminal_outcome(),
            Ok(CloseStepOutcome::Waiting {
                sleep_for,
                deadline,
            }) => {
                sleep_before_orphan_reconnect(deadline, sleep_for, None);
                OrphanDriveOutcome::Progress
            }
            Ok(CloseStepOutcome::Progress) => OrphanDriveOutcome::Progress,
            Ok(CloseStepOutcome::Idle) => OrphanDriveOutcome::Idle,
            Err(err) => OrphanDriveOutcome::RetryLater(driver_error_message(err)),
        }
    }

    fn drive_once_with_stop(&mut self, stop: &AtomicBool) -> OrphanDriveOutcome {
        if stop.load(Ordering::Acquire) {
            return OrphanDriveOutcome::Stopped;
        }
        match self.send_core.close_drain_ready_step(&mut self.store) {
            Ok(CloseStepOutcome::Drained) => OrphanDriveOutcome::Drained,
            Ok(CloseStepOutcome::Terminal) => self.terminal_outcome(),
            Ok(CloseStepOutcome::Waiting {
                sleep_for,
                deadline,
            }) => {
                if sleep_before_orphan_reconnect(deadline, sleep_for, Some(stop)) {
                    OrphanDriveOutcome::Progress
                } else if stop.load(Ordering::Acquire) {
                    OrphanDriveOutcome::Stopped
                } else {
                    OrphanDriveOutcome::Progress
                }
            }
            Ok(CloseStepOutcome::Progress) => OrphanDriveOutcome::Progress,
            Ok(CloseStepOutcome::Idle) => OrphanDriveOutcome::Idle,
            Err(err) => OrphanDriveOutcome::RetryLater(driver_error_message(err)),
        }
    }

    fn record_last_error(&self, reason: &str) {
        let _ = record_last_error(&self.slot_dir, reason);
    }

    fn clear_last_error(&self) {
        let _ = clear_last_error(&self.slot_dir);
    }

    fn terminal_outcome(&self) -> OrphanDriveOutcome {
        let reason = self.terminal_message();
        if terminal_error_is_proven_local_unrecoverable(self.store.terminal_error()) {
            OrphanDriveOutcome::Unrecoverable(reason)
        } else {
            OrphanDriveOutcome::Terminal(reason)
        }
    }

    fn terminal_message(&self) -> String {
        if let Some(err) = self.store.terminal_error() {
            return err.to_string();
        }
        if let Some(err) = self.store.terminal_sender_error() {
            return format!("{err:?}");
        }
        "orphan drainer reached terminal state".to_owned()
    }
}

#[cfg(feature = "sync-sender-qwp-ws")]
fn terminal_error_is_proven_local_unrecoverable(error: Option<&crate::Error>) -> bool {
    error.is_some_and(|err| {
        // Bare StoreResendRequired is reserved for a persisted symbol dictionary
        // that cannot be reconstructed from this slot. The role/writability path
        // currently uses the same code, but always attaches its structured server
        // rejection; another session/endpoint may resolve that form.
        err.code() == ErrorCode::StoreResendRequired && err.qwp_ws_rejection().is_none()
    })
}

#[cfg(feature = "sync-sender-qwp-ws")]
fn orphan_reconnect_deadline_expired(deadline: Option<Instant>) -> bool {
    deadline.is_some_and(|deadline| Instant::now() >= deadline)
}

#[cfg(feature = "sync-sender-qwp-ws")]
fn sleep_before_orphan_reconnect(
    deadline: Option<Instant>,
    backoff: Duration,
    stop: Option<&AtomicBool>,
) -> bool {
    if stop.is_some_and(|stop| stop.load(Ordering::Acquire)) {
        return false;
    }
    if backoff.is_zero() {
        return stop.is_none_or(|stop| !stop.load(Ordering::Acquire))
            && !orphan_reconnect_deadline_expired(deadline);
    }

    let sleep_for = match deadline {
        Some(deadline) => {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            backoff.min(remaining)
        }
        None => backoff,
    };
    let sleep_start = Instant::now();
    while stop.is_none_or(|stop| !stop.load(Ordering::Acquire)) {
        let remaining = sleep_for.saturating_sub(sleep_start.elapsed());
        if remaining.is_zero() {
            break;
        }
        thread::sleep(remaining.min(Duration::from_millis(50)));
    }
    stop.is_none_or(|stop| !stop.load(Ordering::Acquire))
        && !orphan_reconnect_deadline_expired(deadline)
}

#[cfg(feature = "sync-sender-qwp-ws")]
fn next_orphan_retry_backoff(current: Duration, max: Duration) -> Duration {
    current.checked_mul(2).unwrap_or(Duration::MAX).min(max)
}

#[cfg(feature = "sync-sender-qwp-ws")]
fn drain_orphan_to_completion(
    slot_dir: PathBuf,
    config: &OrphanDrainerConfig,
    stop: &AtomicBool,
    traffic_gate: &Arc<TrafficGate>,
) {
    let initial_backoff = *config.qwp_ws.reconnect_initial_backoff;
    let max_backoff = *config.qwp_ws.reconnect_max_backoff;
    let mut retry_backoff = initial_backoff;
    let mut drainer = loop {
        match OrphanDrainer::open_with_stop(slot_dir.clone(), config, stop, traffic_gate) {
            OrphanOpenOutcome::Drainer(drainer) => break drainer,
            OrphanOpenOutcome::AlreadyDrained
            | OrphanOpenOutcome::FailedSentinel
            | OrphanOpenOutcome::Locked
            | OrphanOpenOutcome::Stopped => return,
            OrphanOpenOutcome::RetryLater(reason) => {
                record_last_error_unless_stopped(&slot_dir, &reason, stop);
                if !sleep_before_orphan_reconnect(None, retry_backoff, Some(stop)) {
                    return;
                }
                retry_backoff = next_orphan_retry_backoff(retry_backoff, max_backoff);
            }
            OrphanOpenOutcome::Unrecoverable(reason) => {
                mark_orphan_failed_unless_stopped(&slot_dir, &reason, stop);
                return;
            }
        }
    };
    retry_backoff = initial_backoff;
    while !stop.load(Ordering::Acquire) {
        match drainer.drive_once_with_stop(stop) {
            OrphanDriveOutcome::Drained => {
                drainer.clear_last_error();
                return;
            }
            OrphanDriveOutcome::RetryLater(reason) => {
                if !stop.load(Ordering::Acquire) {
                    drainer.record_last_error(&reason);
                }
                if !sleep_before_orphan_reconnect(None, retry_backoff, Some(stop)) {
                    return;
                }
                retry_backoff = next_orphan_retry_backoff(retry_backoff, max_backoff);
            }
            OrphanDriveOutcome::Terminal(reason) => {
                record_last_error_unless_stopped(&slot_dir, &reason, stop);
                return;
            }
            OrphanDriveOutcome::Unrecoverable(reason) => {
                mark_orphan_failed_unless_stopped(&slot_dir, &reason, stop);
                return;
            }
            OrphanDriveOutcome::Stopped => return,
            OrphanDriveOutcome::Progress => retry_backoff = initial_backoff,
            OrphanDriveOutcome::Idle => {
                retry_backoff = initial_backoff;
                thread::sleep(ORPHAN_IDLE_PARK);
            }
        }
    }
}

#[cfg(feature = "sync-sender-qwp-ws")]
fn pop_pending_orphan(pending: &Mutex<VecDeque<PathBuf>>) -> Option<PathBuf> {
    pending.lock().ok()?.pop_front()
}

#[cfg(feature = "sync-sender-qwp-ws")]
fn mark_orphan_failed_unless_stopped(slot_dir: &Path, reason: &str, stop: &AtomicBool) {
    if !stop.load(Ordering::Acquire) {
        let _ = mark_failed(slot_dir, reason);
    }
}

#[cfg(feature = "sync-sender-qwp-ws")]
fn record_last_error(slot_dir: &Path, reason: &str) -> io::Result<()> {
    fs::write(slot_dir.join(LAST_ERROR_NAME), reason)
}

#[cfg(feature = "sync-sender-qwp-ws")]
fn clear_last_error(slot_dir: &Path) -> io::Result<()> {
    match fs::remove_file(slot_dir.join(LAST_ERROR_NAME)) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

#[cfg(feature = "sync-sender-qwp-ws")]
fn record_last_error_unless_stopped(slot_dir: &Path, reason: &str, stop: &AtomicBool) {
    if !stop.load(Ordering::Acquire) {
        let _ = record_last_error(slot_dir, reason);
    }
}

#[cfg(feature = "sync-sender-qwp-ws")]
fn retry_open_later(reason: String, stop: Option<&AtomicBool>) -> OrphanOpenOutcome {
    if orphan_stop_requested(stop) {
        OrphanOpenOutcome::Stopped
    } else {
        OrphanOpenOutcome::RetryLater(reason)
    }
}

#[cfg(feature = "sync-sender-qwp-ws")]
fn orphan_stop_requested(stop: Option<&AtomicBool>) -> bool {
    stop.is_some_and(|stop| stop.load(Ordering::Acquire))
}

#[cfg(feature = "sync-sender-qwp-ws")]
fn orphan_queue_drained(queue: &SfaSlotQueue) -> bool {
    match PublicationLog::published_fsn(queue) {
        None => true,
        Some(published) => {
            PublicationLog::completed_fsn(queue).is_some_and(|completed| completed >= published)
        }
    }
}

#[cfg(feature = "sync-sender-qwp-ws")]
fn driver_error_message(err: DriverError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[cfg(feature = "sync-sender-qwp-ws")]
    use crate::ingress::conf::{ConfigSetting, QwpWsConfig};
    #[cfg(all(feature = "sync-sender-qwp-ws", any(unix, windows)))]
    use crate::ingress::sender::qwp_ws_sfa_manifest::{SfManifest, SfaAckWatermark};
    #[cfg(all(feature = "sync-sender-qwp-ws", any(unix, windows)))]
    use crate::ingress::sender::qwp_ws_sfa_queue::SfaStorageStep;
    #[cfg(all(feature = "sync-sender-qwp-ws", unix))]
    use crate::ingress::sender::qwp_ws_sfa_segment::initial_segment_path;
    #[cfg(all(feature = "sync-sender-qwp-ws", any(unix, windows)))]
    use crate::ingress::sender::qwp_ws_sfa_segment::{SfaSegment, scan_file, spare_segment_path};
    #[cfg(all(feature = "sync-sender-qwp-ws", any(unix, windows)))]
    use crate::ingress::sender::qwp_ws_sfa_slot::SfaSlotOptions;
    #[cfg(feature = "sync-sender-qwp-ws")]
    use crate::ingress::{QwpWsErrorCategory, QwpWsErrorPolicy, QwpWsSenderError};
    #[cfg(all(feature = "sync-sender-qwp-ws", any(unix, windows)))]
    use std::net::TcpListener;

    #[test]
    fn scan_returns_no_orphans_for_missing_root() {
        let temp = TempDir::new().unwrap();

        assert!(scan_orphan_slots(&temp.path().join("missing"), "default", &[]).is_empty());
    }

    #[test]
    fn scan_filters_own_slot_failed_slots_and_empty_dirs() {
        let temp = TempDir::new().unwrap();
        let own = temp.path().join("default");
        let failed = temp.path().join("failed");
        let empty = temp.path().join("empty");
        let orphan = temp.path().join("orphan");
        fs::create_dir(&own).unwrap();
        fs::create_dir(&failed).unwrap();
        fs::create_dir(&empty).unwrap();
        fs::create_dir(&orphan).unwrap();
        fs::write(own.join("sf-initial.sfa"), b"own").unwrap();
        fs::write(failed.join("sf-initial.sfa"), b"failed").unwrap();
        mark_failed(&failed, "previous drainer failed").unwrap();
        fs::write(orphan.join("sf-initial.sfa"), b"orphan").unwrap();
        fs::write(temp.path().join("top-level.sfa"), b"not a slot").unwrap();

        assert_eq!(scan_orphan_slots(temp.path(), "default", &[]), vec![orphan]);
    }

    #[test]
    fn scan_filters_canonical_managed_slot_ranges_only() {
        let temp = TempDir::new().unwrap();
        for name in [
            "default-ingest-0",
            "default-ingest-1",
            "default-ingest-2",
            "default-ingest-02",
            "default-ingest-x",
            "unmanaged-1",
            "default",
        ] {
            let slot = temp.path().join(name);
            fs::create_dir(&slot).unwrap();
            fs::write(slot.join("sf-initial.sfa"), b"queued").unwrap();
        }

        let exclusions = vec![QwpWsManagedSlotExclusion::new(
            "default-ingest-".to_owned(),
            2,
        )];
        let mut actual = scan_orphan_slots(temp.path(), "unmanaged-1", &exclusions);
        actual.sort();

        assert_eq!(
            actual,
            vec![
                temp.path().join("default"),
                temp.path().join("default-ingest-02"),
                temp.path().join("default-ingest-2"),
                temp.path().join("default-ingest-x"),
            ]
        );
    }

    #[test]
    fn failed_sentinel_is_written_with_reason() {
        let temp = TempDir::new().unwrap();

        mark_failed(temp.path(), "connect failed").unwrap();

        assert!(has_failed_sentinel(temp.path()));
        assert_eq!(
            fs::read_to_string(temp.path().join(FAILED_SENTINEL_NAME)).unwrap(),
            "connect failed"
        );
    }

    #[cfg(feature = "sync-sender-qwp-ws")]
    fn test_config() -> OrphanDrainerConfig {
        let qwp_ws = QwpWsConfig {
            sf_max_segment_bytes: ConfigSetting::new_default(256),
            sf_max_total_bytes: ConfigSetting::new_default(Some(1024)),
            ..QwpWsConfig::default()
        };
        OrphanDrainerConfig::new("127.0.0.1", "1", false, None, &qwp_ws, None)
    }

    #[cfg(feature = "sync-sender-qwp-ws")]
    #[test]
    fn background_pool_close_allows_graceful_finish_before_stop() {
        let stop = Arc::new(AtomicBool::new(false));
        let observed_stop = Arc::new(AtomicBool::new(true));
        let (ran_tx, ran_rx) = std::sync::mpsc::channel();
        let worker_stop = Arc::clone(&stop);
        let worker_observed_stop = Arc::clone(&observed_stop);
        let worker = thread::spawn(move || {
            thread::sleep(Duration::from_millis(20));
            worker_observed_stop.store(worker_stop.load(Ordering::Acquire), Ordering::Release);
            ran_tx.send(()).unwrap();
        });
        let mut pool = OrphanDrainerPool {
            stop,
            threads: vec![(worker, Arc::new(TrafficGate::default()))],
        };

        pool.close_with_timeouts(Duration::from_secs(1), Duration::from_millis(10));

        ran_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(!observed_stop.load(Ordering::Acquire));
        assert!(pool.stop.load(Ordering::Acquire));
        assert!(pool.threads.is_empty());
    }

    #[cfg(feature = "sync-sender-qwp-ws")]
    #[test]
    fn background_pool_close_detaches_worker_after_stop_grace() {
        let stop = Arc::new(AtomicBool::new(false));
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (stop_seen_tx, stop_seen_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let worker_stop = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            entered_tx.send(()).unwrap();
            while !worker_stop.load(Ordering::Acquire) {
                thread::sleep(Duration::from_millis(1));
            }
            stop_seen_tx.send(()).unwrap();
            let _ = release_rx.recv_timeout(Duration::from_secs(1));
        });
        entered_rx.recv_timeout(Duration::from_millis(500)).unwrap();
        let mut pool = OrphanDrainerPool {
            stop,
            threads: vec![(worker, Arc::new(TrafficGate::default()))],
        };

        let started = Instant::now();
        pool.close_with_timeouts(Duration::from_millis(10), Duration::from_millis(10));
        let elapsed = started.elapsed();

        assert!(
            elapsed < Duration::from_millis(500),
            "orphan pool close took {elapsed:?}"
        );
        assert!(pool.stop.load(Ordering::Acquire));
        assert!(pool.threads.is_empty());
        stop_seen_rx
            .recv_timeout(Duration::from_millis(500))
            .unwrap();
        release_tx.send(()).unwrap();
    }

    #[cfg(all(feature = "sync-sender-qwp-ws", any(unix, windows)))]
    #[test]
    fn detached_background_worker_retains_slot_until_exit() {
        let temp = TempDir::new().unwrap();
        let options = SfaSlotOptions {
            sf_dir: temp.path().to_path_buf(),
            sender_id: "orphan".to_owned(),
            segment_size_bytes: 256,
            max_bytes: 1024,
            max_in_flight: 1,
            periodic_sync_interval: None,
        };
        let stop = Arc::new(AtomicBool::new(false));
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (exited_tx, exited_rx) = std::sync::mpsc::channel();
        let worker_stop = Arc::clone(&stop);
        let worker_options = options.clone();
        let worker = thread::spawn(move || {
            let queue = SfaSlotQueue::open(worker_options).unwrap();
            entered_tx.send(()).unwrap();
            while !worker_stop.load(Ordering::Acquire) {
                thread::yield_now();
            }
            release_rx.recv().unwrap();
            drop(queue);
            exited_tx.send(()).unwrap();
        });
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let mut pool = OrphanDrainerPool {
            stop,
            threads: vec![(worker, Arc::new(TrafficGate::default()))],
        };

        pool.close_with_timeouts(Duration::from_millis(10), Duration::from_millis(10));

        assert!(matches!(
            SfaSlotQueue::open(options.clone()),
            Err(SfaQueueError::SlotInUse { .. })
        ));
        release_tx.send(()).unwrap();
        exited_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        let mut reopened = SfaSlotQueue::open(options).unwrap();
        reopened.close().unwrap();
    }

    #[cfg(feature = "sync-sender-qwp-ws")]
    #[test]
    fn orphan_reconnect_sleep_observes_stop_request() {
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let stopper = thread::spawn(move || {
            thread::sleep(Duration::from_millis(20));
            worker_stop.store(true, Ordering::Release);
        });

        let started = Instant::now();
        assert!(!sleep_before_orphan_reconnect(
            None,
            Duration::from_secs(5),
            Some(&stop)
        ));
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "orphan reconnect sleep ignored stop request"
        );
        stopper.join().unwrap();
    }

    #[cfg(feature = "sync-sender-qwp-ws")]
    #[test]
    fn orphan_retry_backoff_doubles_and_caps() {
        let max = Duration::from_millis(500);
        let mut backoff = Duration::from_millis(100);

        backoff = next_orphan_retry_backoff(backoff, max);
        assert_eq!(backoff, Duration::from_millis(200));
        backoff = next_orphan_retry_backoff(backoff, max);
        assert_eq!(backoff, Duration::from_millis(400));
        backoff = next_orphan_retry_backoff(backoff, max);
        assert_eq!(backoff, max);
        assert_eq!(next_orphan_retry_backoff(backoff, max), max);
    }

    #[cfg(feature = "sync-sender-qwp-ws")]
    #[test]
    fn only_bare_store_resend_terminal_is_proven_local_unrecoverable() {
        let local = crate::Error::new(ErrorCode::StoreResendRequired, "torn dictionary");
        assert!(terminal_error_is_proven_local_unrecoverable(Some(&local)));

        let role_rejection = QwpWsSenderError {
            category: QwpWsErrorCategory::NotWritable,
            applied_policy: QwpWsErrorPolicy::Terminal,
            status: Some(super::super::qwp_ws_codec::WS_STATUS_NOT_WRITABLE),
            message: Some("primary moved".to_owned()),
            message_sequence: None,
            from_fsn: 0,
            to_fsn: 0,
        };
        let role = crate::Error::new(ErrorCode::StoreResendRequired, "primary moved")
            .with_qwp_ws_rejection(role_rejection);
        assert!(!terminal_error_is_proven_local_unrecoverable(Some(&role)));
    }

    #[cfg(all(feature = "sync-sender-qwp-ws", any(unix, windows)))]
    fn slot_options(sf_dir: &Path, sender_id: &str) -> SfaSlotOptions {
        SfaSlotOptions {
            sf_dir: sf_dir.to_path_buf(),
            sender_id: sender_id.to_owned(),
            segment_size_bytes: 256,
            max_bytes: 1024,
            max_in_flight: 4,
            periodic_sync_interval: None,
        }
    }

    #[cfg(feature = "sync-sender-qwp-ws")]
    #[test]
    fn manual_drainer_consumes_already_drained_slot_without_network() {
        let temp = TempDir::new().unwrap();
        let slot_dir = temp.path().join("orphan");
        fs::create_dir(&slot_dir).unwrap();
        let mut drainers =
            ManualOrphanDrainers::new(vec![slot_dir.clone()], 1, test_config()).unwrap();

        assert!(drainers.drive_once());
        assert!(!has_failed_sentinel(&slot_dir));
        assert!(!drainers.drive_once());
    }

    #[cfg(all(feature = "sync-sender-qwp-ws", any(unix, windows)))]
    #[test]
    fn orphan_adoption_inherits_periodic_sync_interval_from_config() {
        let temp = TempDir::new().unwrap();
        let sf_dir = temp.path().join("sf-root");
        let slot_dir = sf_dir.join("orphan");
        {
            let mut queue = SfaSlotQueue::open(slot_options(&sf_dir, "orphan")).unwrap();
            PublicationLog::try_publish(&mut queue, b"orphaned").unwrap();
            queue.close().unwrap();
        }

        let builder = crate::ingress::SenderBuilder::from_conf(format!(
            "ws::addr=127.0.0.1:1;sf_dir={};sender_id=primary;drain_orphans=on;\
             sf_max_segment_bytes=256;sf_max_total_bytes=1024;\
             sf_durability=periodic;sf_sync_interval_millis=123;",
            sf_dir.display()
        ))
        .unwrap();
        let qwp_ws = builder.qwp_ws.as_ref().unwrap();
        let config = OrphanDrainerConfig::new("127.0.0.1", "1", false, None, qwp_ws, None);
        let queue_options = config.queue_options(slot_dir).unwrap();
        assert_eq!(
            queue_options.periodic_sync_interval,
            Some(Duration::from_millis(123))
        );

        // Exercise the same options and replay-only open used by adoption,
        // without adding a network or timer race to the test.
        let mut adopted = SfaSlotQueue::open_replay_only_existing(queue_options).unwrap();
        let sync_step = PublicationLog::take_storage_maintenance_step(&mut adopted, false)
            .unwrap()
            .expect("adopted periodic queue must schedule a sync step");
        assert!(matches!(sync_step, SfaStorageStep::SyncPublished(_)));
        let sync_result = sync_step.perform().unwrap();
        PublicationLog::finish_storage_maintenance(&mut adopted, sync_result, false).unwrap();
        PublicationLog::complete_storage_maintenance(&mut adopted).unwrap();
        adopted.close().unwrap();
    }

    #[cfg(feature = "sync-sender-qwp-ws")]
    #[test]
    fn manual_drainer_honors_failed_sentinel_created_after_scan() {
        let temp = TempDir::new().unwrap();
        let slot_dir = temp.path().join("orphan");
        fs::create_dir(&slot_dir).unwrap();
        let mut drainers =
            ManualOrphanDrainers::new(vec![slot_dir.clone()], 1, test_config()).unwrap();
        mark_failed(&slot_dir, "created after scan").unwrap();

        assert!(drainers.drive_once());
        assert!(!drainers.drive_once());
        assert_eq!(
            fs::read_to_string(slot_dir.join(FAILED_SENTINEL_NAME)).unwrap(),
            "created after scan"
        );
    }

    #[cfg(all(feature = "sync-sender-qwp-ws", any(unix, windows)))]
    #[test]
    fn manual_drainer_skips_locked_slot_without_failed_sentinel() {
        let temp = TempDir::new().unwrap();
        let sf_dir = temp.path().join("sf-root");
        let slot_dir = sf_dir.join("locked");
        let _held = SfaSlotQueue::open(slot_options(&sf_dir, "locked")).unwrap();
        assert!(
            matches!(
                OrphanDrainer::open(slot_dir.clone(), &test_config()),
                OrphanOpenOutcome::Locked
            ),
            "held slot must surface as Locked before already-drained handling"
        );
        let mut drainers =
            ManualOrphanDrainers::new(vec![slot_dir.clone()], 1, test_config()).unwrap();

        assert!(drainers.drive_once());
        assert!(!has_failed_sentinel(&slot_dir));
        assert!(!drainers.drive_once());
    }

    #[cfg(all(feature = "sync-sender-qwp-ws", any(unix, windows)))]
    #[test]
    fn manual_drainer_does_not_poison_orphan_after_connect_failure() {
        let temp = TempDir::new().unwrap();
        let sf_dir = temp.path().join("sf-root");
        let slot_dir = sf_dir.join("orphan");
        {
            let mut queue = SfaSlotQueue::open(slot_options(&sf_dir, "orphan")).unwrap();
            PublicationLog::try_publish(&mut queue, b"orphaned frame").unwrap();
            queue.close().unwrap();
        }
        assert_eq!(
            scan_orphan_slots(&sf_dir, "primary", &[]),
            vec![slot_dir.clone()]
        );

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut config = test_config();
        config.port = port.to_string();
        let mut drainers = ManualOrphanDrainers::new(vec![slot_dir.clone()], 1, config).unwrap();

        assert!(drainers.drive_once());

        assert!(
            !has_failed_sentinel(&slot_dir),
            "transient connect failure must leave orphan slot recoverable"
        );
        assert!(slot_dir.join(LAST_ERROR_NAME).exists());
        assert_eq!(scan_orphan_slots(&sf_dir, "primary", &[]), vec![slot_dir]);
    }

    #[cfg(all(feature = "sync-sender-qwp-ws", any(unix, windows)))]
    #[test]
    fn manual_drainer_retries_once_after_sanitizing_sealed_residue() {
        let temp = TempDir::new().unwrap();
        let slot_dir = temp.path().join("orphan");
        fs::create_dir(&slot_dir).unwrap();
        let sealed_path = spare_segment_path(&slot_dir, 0);
        let active_path = spare_segment_path(&slot_dir, 1);
        let mut sealed = SfaSegment::create_new_manifested(&sealed_path, 0, 256, 0).unwrap();
        sealed.try_append(b"orphaned").unwrap();
        drop(sealed);
        let append_offset = scan_file(&sealed_path).unwrap().append_offset as usize;
        let mut bytes = fs::read(&sealed_path).unwrap();
        bytes[append_offset] = 0xa5;
        fs::write(&sealed_path, bytes).unwrap();
        drop(SfaSegment::create_new_manifested(&active_path, 1, 256, 0).unwrap());
        drop(SfManifest::create(&slot_dir, 0, 1).unwrap());
        let mut watermark = SfaAckWatermark::open(&slot_dir).unwrap();
        watermark.write(-1).unwrap();
        watermark.sync_data().unwrap();
        drop(watermark);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut config = test_config();
        config.port = port.to_string();
        let mut drainers = ManualOrphanDrainers::new(vec![slot_dir.clone()], 1, config).unwrap();

        assert!(drainers.drive_once());

        assert_eq!(scan_file(&sealed_path).unwrap().torn_tail_bytes, 0);
        assert!(
            !has_failed_sentinel(&slot_dir),
            "the first sanitized-residue incident must be retried, not poisoned"
        );
        assert!(slot_dir.join(LAST_ERROR_NAME).exists());
    }

    #[cfg(all(feature = "sync-sender-qwp-ws", unix))]
    #[test]
    fn manual_drainer_marks_recovery_failure_failed_without_network() {
        let temp = TempDir::new().unwrap();
        let slot_dir = temp.path().join("orphan");
        fs::create_dir(&slot_dir).unwrap();
        let segment_path = initial_segment_path(&slot_dir);
        let mut bytes = vec![0u8; 64];
        bytes[..4].copy_from_slice(&0xdead_beefu32.to_le_bytes());
        fs::write(&segment_path, bytes).unwrap();
        let mut drainers =
            ManualOrphanDrainers::new(vec![slot_dir.clone()], 1, test_config()).unwrap();

        assert!(drainers.drive_once());
        assert!(has_failed_sentinel(&slot_dir));
        assert!(
            !segment_path.exists(),
            "manifest-less corruption must leave the .sfa scan"
        );
        assert!(
            segment_path.with_extension("sfa.corrupt").exists(),
            "quarantine must preserve the corrupt bytes for diagnosis"
        );
        assert!(!drainers.drive_once());
    }
}
