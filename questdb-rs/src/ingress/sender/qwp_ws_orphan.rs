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
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(feature = "sync-sender-qwp-ws")]
use std::sync::{Arc, Mutex};
#[cfg(feature = "sync-sender-qwp-ws")]
use std::thread;
#[cfg(feature = "sync-sender-qwp-ws")]
use std::time::{Duration, Instant};

#[cfg(feature = "sync-sender-qwp-ws")]
use crate::ingress::conf::QwpWsConfig;
#[cfg(feature = "sync-sender-qwp-ws")]
use crate::ingress::tls::TlsSettings;

#[cfg(feature = "sync-sender-qwp-ws")]
use super::qwp_ws_driver::{
    BlockingQwpWsTransport, CloseStepOutcome, DriverError, ManualDriverPrototype, PublicationLog,
    ReconnectPolicy,
};
#[cfg(feature = "sync-sender-qwp-ws")]
use super::qwp_ws_sfa_queue::{SfaQueueError, SfaQueueOptions};
#[cfg(feature = "sync-sender-qwp-ws")]
use super::qwp_ws_sfa_slot::SfaSlotQueue;

pub(crate) const FAILED_SENTINEL_NAME: &str = ".failed";
#[cfg(feature = "sync-sender-qwp-ws")]
const ORPHAN_IDLE_PARK: Duration = Duration::from_millis(50);
#[cfg(feature = "sync-sender-qwp-ws")]
const ORPHAN_POOL_GRACEFUL_DRAIN: Duration = Duration::from_millis(2500);
#[cfg(feature = "sync-sender-qwp-ws")]
const ORPHAN_POOL_STOP_GRACE: Duration = Duration::from_millis(500);
#[cfg(feature = "sync-sender-qwp-ws")]
const ORPHAN_POOL_CLOSE_POLL: Duration = Duration::from_millis(10);

pub(crate) fn scan_orphan_slots(sf_dir: &Path, own_sender_id: &str) -> Vec<PathBuf> {
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
        if has_failed_sentinel(&slot_path) || !has_any_sfa_file(&slot_path) {
            continue;
        }
        orphans.push(slot_path);
    }
    orphans
}

pub(crate) fn has_failed_sentinel(slot_dir: &Path) -> bool {
    slot_dir.join(FAILED_SENTINEL_NAME).exists()
}

pub(crate) fn mark_failed(slot_dir: &Path, reason: &str) -> io::Result<()> {
    fs::write(slot_dir.join(FAILED_SENTINEL_NAME), reason)
}

fn has_any_sfa_file(slot_dir: &Path) -> bool {
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
            segment_size_bytes: *self.qwp_ws.sf_max_bytes,
            max_bytes,
            max_in_flight: *self.qwp_ws.max_in_flight,
        })
    }
}

#[cfg(feature = "sync-sender-qwp-ws")]
pub(crate) struct OrphanDrainerPool {
    stop: Arc<AtomicBool>,
    threads: Vec<thread::JoinHandle<()>>,
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
            threads.push(thread::spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    let Some(slot_dir) = pop_pending_orphan(&pending) else {
                        break;
                    };
                    drain_orphan_to_completion(slot_dir, &config, &stop);
                }
            }));
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
        self.wait_for_finished_threads(stop_grace);
        // Remaining orphan drainers are best-effort background work. Dropping
        // their JoinHandles detaches the threads so sender close stays bounded.
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
        for thread in self.threads.drain(..) {
            if thread.is_finished() {
                let _ = thread.join();
            } else {
                running.push(thread);
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
            | OrphanOpenOutcome::FailedMarked
            | OrphanOpenOutcome::FailedSentinel
            | OrphanOpenOutcome::Locked
            | OrphanOpenOutcome::Stopped => true,
            OrphanOpenOutcome::Failed(reason) => {
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
                    self.active.remove(index);
                    self.normalize_next_active();
                    return true;
                }
                OrphanDriveOutcome::Failed(reason) => {
                    let drainer = self.active.remove(index);
                    drainer.mark_failed(&reason);
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
    driver: ManualDriverPrototype<SfaSlotQueue, BlockingQwpWsTransport>,
}

#[cfg(feature = "sync-sender-qwp-ws")]
enum OrphanOpenOutcome {
    Drainer(Box<OrphanDrainer>),
    AlreadyDrained,
    FailedMarked,
    FailedSentinel,
    Locked,
    Stopped,
    Failed(String),
}

#[cfg(feature = "sync-sender-qwp-ws")]
enum OrphanDriveOutcome {
    Idle,
    Progress,
    Drained,
    Stopped,
    Failed(String),
}

#[cfg(feature = "sync-sender-qwp-ws")]
impl OrphanDrainer {
    fn open(slot_dir: PathBuf, config: &OrphanDrainerConfig) -> OrphanOpenOutcome {
        Self::open_controlled(slot_dir, config, None)
    }

    fn open_with_stop(
        slot_dir: PathBuf,
        config: &OrphanDrainerConfig,
        stop: &AtomicBool,
    ) -> OrphanOpenOutcome {
        Self::open_controlled(slot_dir, config, Some(stop))
    }

    fn open_controlled(
        slot_dir: PathBuf,
        config: &OrphanDrainerConfig,
        stop: Option<&AtomicBool>,
    ) -> OrphanOpenOutcome {
        if orphan_stop_requested(stop) {
            return OrphanOpenOutcome::Stopped;
        }
        if has_failed_sentinel(&slot_dir) {
            return OrphanOpenOutcome::FailedSentinel;
        }
        let options = match config.queue_options(slot_dir.clone()) {
            Ok(options) => options,
            Err(err) => return OrphanOpenOutcome::Failed(err),
        };
        let mut queue = match SfaSlotQueue::open_replay_only_existing(options) {
            Ok(queue) => queue,
            Err(SfaQueueError::SlotInUse { .. }) => return OrphanOpenOutcome::Locked,
            Err(err) => return OrphanOpenOutcome::Failed(format!("{err:?}")),
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
                return mark_open_failed(&slot_dir, &reason, stop);
            }
            return OrphanOpenOutcome::AlreadyDrained;
        }
        let transport = match BlockingQwpWsTransport::connect(
            config.host.clone(),
            config.port.clone(),
            config.use_tls,
            config.tls_settings.clone(),
            config.qwp_ws.clone(),
            config.auth_header.clone(),
        ) {
            Ok(transport) => transport,
            Err(err) => {
                let reason = err.to_string();
                return mark_open_failed(&slot_dir, &reason, stop);
            }
        };
        if orphan_stop_requested(stop) {
            return OrphanOpenOutcome::Stopped;
        }
        let driver = ManualDriverPrototype::from_queue_with_reconnect_policy(
            queue,
            transport,
            ReconnectPolicy::bounded(
                *config.qwp_ws.reconnect_max_duration,
                *config.qwp_ws.reconnect_initial_backoff,
                *config.qwp_ws.reconnect_max_backoff,
            ),
            // Java orphan drainers reuse the foreground WebSocket connection
            // factory but trim orphan files on ordinary OKs, not durable ACKs.
            false,
        );
        OrphanOpenOutcome::Drainer(Box::new(Self { slot_dir, driver }))
    }

    fn drive_once(&mut self) -> OrphanDriveOutcome {
        match self.driver.close_drain_ready_step() {
            Ok(CloseStepOutcome::Drained) => OrphanDriveOutcome::Drained,
            Ok(CloseStepOutcome::Terminal) => {
                OrphanDriveOutcome::Failed(driver_terminal_message(&self.driver))
            }
            Ok(CloseStepOutcome::Progress) => OrphanDriveOutcome::Progress,
            Ok(CloseStepOutcome::Idle) => OrphanDriveOutcome::Idle,
            Ok(CloseStepOutcome::Stopped) => OrphanDriveOutcome::Stopped,
            Err(err) => OrphanDriveOutcome::Failed(driver_error_message(err)),
        }
    }

    fn drive_once_with_stop(&mut self, stop: &AtomicBool) -> OrphanDriveOutcome {
        match self.driver.close_drain_ready_step_with_stop(stop) {
            Ok(CloseStepOutcome::Drained) => OrphanDriveOutcome::Drained,
            Ok(CloseStepOutcome::Terminal) => {
                OrphanDriveOutcome::Failed(driver_terminal_message(&self.driver))
            }
            Ok(CloseStepOutcome::Progress) => OrphanDriveOutcome::Progress,
            Ok(CloseStepOutcome::Idle) => OrphanDriveOutcome::Idle,
            Ok(CloseStepOutcome::Stopped) => OrphanDriveOutcome::Stopped,
            Err(err) => OrphanDriveOutcome::Failed(driver_error_message(err)),
        }
    }

    fn mark_failed(&self, reason: &str) {
        let _ = mark_failed(&self.slot_dir, reason);
    }

    fn mark_failed_unless_stopped(&self, reason: &str, stop: &AtomicBool) {
        if !stop.load(Ordering::Acquire) {
            self.mark_failed(reason);
        }
    }
}

#[cfg(feature = "sync-sender-qwp-ws")]
fn drain_orphan_to_completion(slot_dir: PathBuf, config: &OrphanDrainerConfig, stop: &AtomicBool) {
    let mut drainer = match OrphanDrainer::open_with_stop(slot_dir.clone(), config, stop) {
        OrphanOpenOutcome::Drainer(drainer) => drainer,
        OrphanOpenOutcome::AlreadyDrained
        | OrphanOpenOutcome::FailedMarked
        | OrphanOpenOutcome::FailedSentinel
        | OrphanOpenOutcome::Locked
        | OrphanOpenOutcome::Stopped => return,
        OrphanOpenOutcome::Failed(reason) => {
            mark_orphan_failed_unless_stopped(&slot_dir, &reason, stop);
            return;
        }
    };
    while !stop.load(Ordering::Acquire) {
        match drainer.drive_once_with_stop(stop) {
            OrphanDriveOutcome::Drained => return,
            OrphanDriveOutcome::Failed(reason) => {
                drainer.mark_failed_unless_stopped(&reason, stop);
                return;
            }
            OrphanDriveOutcome::Stopped => return,
            OrphanDriveOutcome::Progress => {}
            OrphanDriveOutcome::Idle => thread::sleep(ORPHAN_IDLE_PARK),
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
fn mark_open_failed(slot_dir: &Path, reason: &str, stop: Option<&AtomicBool>) -> OrphanOpenOutcome {
    if orphan_stop_requested(stop) {
        OrphanOpenOutcome::Stopped
    } else {
        let _ = mark_failed(slot_dir, reason);
        OrphanOpenOutcome::FailedMarked
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
fn driver_terminal_message(
    driver: &ManualDriverPrototype<SfaSlotQueue, BlockingQwpWsTransport>,
) -> String {
    if let Some(err) = driver.terminal_error() {
        return err.to_string();
    }
    if let Some(err) = driver.terminal_sender_error() {
        return format!("{err:?}");
    }
    "orphan drainer reached terminal state".to_owned()
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
    #[cfg(feature = "sync-sender-qwp-ws")]
    use crate::ingress::sender::qwp_ws_sfa_segment::initial_segment_path;
    #[cfg(all(feature = "sync-sender-qwp-ws", any(unix, windows)))]
    use crate::ingress::sender::qwp_ws_sfa_slot::SfaSlotOptions;

    #[test]
    fn scan_returns_no_orphans_for_missing_root() {
        let temp = TempDir::new().unwrap();

        assert!(scan_orphan_slots(&temp.path().join("missing"), "default").is_empty());
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

        assert_eq!(scan_orphan_slots(temp.path(), "default"), vec![orphan]);
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
            sf_max_bytes: ConfigSetting::new_default(256),
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
            threads: vec![worker],
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
            threads: vec![worker],
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
    fn slot_options(sf_dir: &Path, sender_id: &str) -> SfaSlotOptions {
        SfaSlotOptions {
            sf_dir: sf_dir.to_path_buf(),
            sender_id: sender_id.to_owned(),
            segment_size_bytes: 256,
            max_bytes: 1024,
            max_in_flight: 4,
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
        assert!(segment_path.exists());
        assert!(!drainers.drive_once());
    }
}
