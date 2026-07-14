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

//! Java-compatible Store-and-Forward slot ownership for QWP/WebSocket.
//!
//! `SfaFrameQueue` owns the Java `.sfa` file format for one slot directory. This
//! layer owns the product protocol around that queue: `sf_dir` is a group root,
//! `sender_id` names the slot under it, `<sf_dir>/<sender_id>/.lock` is held for
//! the queue lifetime, and `<sf_dir>/<sender_id>/.lock.pid` records the
//! diagnostic holder PID. `QuestDb` pools keep the user-configured `sender_id`
//! as the base name and open concrete per-borrower slots such as
//! `<base>-ingest-0`.

use std::fs;
use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(windows)]
use std::os::windows::{fs::OpenOptionsExt, io::AsRawHandle};

#[cfg(windows)]
use windows_sys::Win32::Foundation::HANDLE;
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, LOCKFILE_EXCLUSIVE_LOCK,
    LOCKFILE_FAIL_IMMEDIATELY, LockFileEx, UnlockFileEx,
};
#[cfg(windows)]
use windows_sys::Win32::System::IO::OVERLAPPED;

use super::qwp_ws_driver::{DriverError, PublicationLog};
use super::qwp_ws_queue::{QwpReceipt, QwpReceiptStatus};
use super::qwp_ws_sfa_queue::{
    SfaCleanupFailure, SfaFrameQueue, SfaMemoryQueueOptions, SfaProducer, SfaQueueError,
    SfaQueueOptions, SfaStorageFinish, SfaStorageResult, SfaStorageStep,
};
use super::qwp_ws_sfa_symbol_dict::PersistedSymbolDict;
use crate::ingress::conf::{QWP_WS_DEFAULT_SENDER_ID, is_valid_qwp_ws_sender_id};

pub(crate) const DEFAULT_SENDER_ID: &str = QWP_WS_DEFAULT_SENDER_ID;
const LOCK_FILE_NAME: &str = ".lock";
const LOCK_PID_FILE_NAME: &str = ".lock.pid";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SfaSlotOptions {
    pub(crate) sf_dir: PathBuf,
    pub(crate) sender_id: String,
    pub(crate) segment_size_bytes: u64,
    pub(crate) max_bytes: usize,
    pub(crate) max_in_flight: usize,
}

#[derive(Debug)]
pub(crate) struct SfaSlotQueue {
    queue: SfaFrameQueue,
    lock: Option<SlotLock>,
}

impl SfaSlotQueue {
    pub(crate) fn open(options: SfaSlotOptions) -> Result<Self, SfaQueueError> {
        validate_sender_id(&options.sender_id)?;
        validate_sf_dir(&options.sf_dir)?;
        ensure_dir(&options.sf_dir)?;

        let slot_dir = options.sf_dir.join(&options.sender_id);
        let lock = SlotLock::acquire(slot_dir.clone())?;
        let queue = SfaFrameQueue::open(SfaQueueOptions {
            slot_dir,
            segment_size_bytes: options.segment_size_bytes,
            max_bytes: options.max_bytes,
            max_in_flight: options.max_in_flight,
        })?;

        Ok(Self {
            queue,
            lock: Some(lock),
        })
    }

    pub(crate) fn open_memory(options: SfaMemoryQueueOptions) -> Result<Self, SfaQueueError> {
        let queue = SfaFrameQueue::open_memory(options)?;
        Ok(Self { queue, lock: None })
    }

    pub(crate) fn open_replay_only_existing(
        options: SfaQueueOptions,
    ) -> Result<Self, SfaQueueError> {
        let lock = SlotLock::acquire_existing(options.slot_dir.clone())?;
        let queue = SfaFrameQueue::open_replay_only(options)?;
        Ok(Self {
            queue,
            lock: Some(lock),
        })
    }

    pub(crate) fn close(&mut self) -> Result<(), SfaQueueError> {
        let result = self.queue.close();
        drop(self.lock.take());
        result
    }

    pub(crate) fn slot_dir(&self) -> Option<&Path> {
        self.lock.as_ref().map(SlotLock::slot_dir)
    }

    pub(crate) fn is_delta_dict_enabled(&self) -> bool {
        self.queue.is_delta_dict_enabled()
    }

    pub(crate) fn recovered_symbol_dict_entries(&self) -> &[u8] {
        self.queue.recovered_symbol_dict_entries()
    }

    pub(crate) fn recovered_symbol_dict_count(&self) -> u32 {
        self.queue.recovered_symbol_dict_count()
    }

    pub(crate) fn take_persisted_symbol_dict(&mut self) -> Option<PersistedSymbolDict> {
        self.queue.take_persisted_symbol_dict()
    }
}

impl Drop for SfaSlotQueue {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

impl PublicationLog for SfaSlotQueue {
    fn try_publish(&mut self, payload: &[u8]) -> Result<QwpReceipt, DriverError> {
        Ok(self.queue.try_submit(payload)?)
    }

    fn take_producer(&mut self) -> Option<SfaProducer> {
        self.queue.take_producer()
    }

    fn progress_view(&self) -> super::qwp_ws_sfa_queue::SfaProgressView {
        self.queue.progress_view()
    }

    fn take_storage_maintenance_step(
        &mut self,
        allow_create: bool,
    ) -> Result<Option<SfaStorageStep>, DriverError> {
        Ok(self.queue.take_storage_maintenance_step(allow_create)?)
    }

    fn finish_storage_maintenance(
        &mut self,
        result: SfaStorageResult,
        allow_install: bool,
    ) -> Result<SfaStorageFinish, DriverError> {
        Ok(self
            .queue
            .finish_storage_maintenance(result, allow_install)?)
    }

    fn record_storage_cleanup_failure(
        &mut self,
        failure: SfaCleanupFailure,
    ) -> Result<(), DriverError> {
        self.queue.record_cleanup_failure(failure);
        Ok(())
    }

    fn oldest_unresolved_fsn(&self) -> Option<u64> {
        self.queue.oldest_unresolved_fsn()
    }

    fn persist_completed_fsn(&mut self, fsn: u64) {
        self.queue.persist_completed_fsn(fsn);
    }

    fn close(&mut self) -> Result<(), DriverError> {
        Ok(SfaSlotQueue::close(self)?)
    }

    fn receipt_status(&self, receipt: QwpReceipt) -> QwpReceiptStatus {
        self.queue.receipt_status(receipt)
    }

    fn published_fsn(&self) -> Option<u64> {
        self.queue.published_fsn()
    }

    fn completed_fsn(&self) -> Option<u64> {
        self.queue.completed_fsn()
    }

    fn max_in_flight(&self) -> usize {
        self.queue.max_in_flight()
    }
}

#[derive(Debug)]
struct SlotLock {
    slot_dir: PathBuf,
    file: File,
}

impl SlotLock {
    fn acquire(slot_dir: PathBuf) -> Result<Self, SfaQueueError> {
        validate_slot_dir(&slot_dir)?;
        ensure_dir(&slot_dir)?;
        Self::lock_file(slot_dir)
    }

    fn acquire_existing(slot_dir: PathBuf) -> Result<Self, SfaQueueError> {
        validate_slot_dir(&slot_dir)?;
        if !slot_dir.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("SFA slot directory does not exist: {}", slot_dir.display()),
            )
            .into());
        }
        Self::lock_file(slot_dir)
    }

    fn slot_dir(&self) -> &Path {
        &self.slot_dir
    }

    #[cfg(any(unix, windows))]
    fn lock_file(slot_dir: PathBuf) -> Result<Self, SfaQueueError> {
        let lock_path = slot_dir.join(LOCK_FILE_NAME);
        let pid_path = slot_dir.join(LOCK_PID_FILE_NAME);
        let file = open_lock_file(&lock_path)?;
        if !try_lock_file(&file) {
            let holder = read_lock_holder(&pid_path);
            return Err(SfaQueueError::SlotInUse { slot_dir, holder });
        }
        write_pid(&pid_path);
        Ok(Self { slot_dir, file })
    }

    #[cfg(not(any(unix, windows)))]
    fn lock_file(slot_dir: PathBuf) -> Result<Self, SfaQueueError> {
        let _ = slot_dir;
        Err(SfaQueueError::SlotLockUnsupported)
    }
}

#[cfg(any(unix, windows))]
impl Drop for SlotLock {
    fn drop(&mut self) {
        unlock_lock_file(&self.file);
    }
}

fn validate_sf_dir(sf_dir: &Path) -> Result<(), SfaQueueError> {
    if sf_dir.as_os_str().is_empty() {
        return Err(SfaQueueError::InvalidSfDir);
    }
    Ok(())
}

fn validate_slot_dir(slot_dir: &Path) -> Result<(), SfaQueueError> {
    if slot_dir.as_os_str().is_empty() {
        return Err(SfaQueueError::InvalidSfDir);
    }
    Ok(())
}

fn validate_sender_id(sender_id: &str) -> Result<(), SfaQueueError> {
    if !is_valid_qwp_ws_sender_id(sender_id) {
        return Err(SfaQueueError::InvalidSenderId {
            sender_id: sender_id.to_owned(),
        });
    }
    Ok(())
}

fn ensure_dir(path: &Path) -> Result<(), io::Error> {
    match fs::create_dir(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists && path.is_dir() => Ok(()),
        Err(err) => Err(err),
    }
}

fn read_lock_holder(pid_path: &Path) -> String {
    match fs::read(pid_path) {
        Ok(bytes) if !bytes.is_empty() => {
            let len = bytes.len().min(64);
            let holder = String::from_utf8_lossy(&bytes[..len]).trim().to_owned();
            if holder.is_empty() {
                "unknown".to_owned()
            } else {
                format!("pid={holder}")
            }
        }
        _ => "unknown".to_owned(),
    }
}

fn write_pid(pid_path: &Path) {
    let payload = format!("{}\n", std::process::id());
    let _ = fs::write(pid_path, payload);
}

#[cfg(unix)]
fn open_lock_file(lock_path: &Path) -> Result<File, io::Error> {
    OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(lock_path)
}

#[cfg(unix)]
fn try_lock_file(file: &File) -> bool {
    (unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) }) == 0
}

#[cfg(unix)]
fn unlock_lock_file(file: &File) {
    let _ = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
}

#[cfg(windows)]
fn open_lock_file(lock_path: &Path) -> Result<File, io::Error> {
    OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .open(lock_path)
}

#[cfg(windows)]
fn try_lock_file(file: &File) -> bool {
    let mut overlapped = OVERLAPPED::default();
    unsafe {
        LockFileEx(
            file.as_raw_handle() as HANDLE,
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            u32::MAX,
            u32::MAX,
            &mut overlapped,
        ) != 0
    }
}

#[cfg(windows)]
fn unlock_lock_file(file: &File) {
    let mut overlapped = OVERLAPPED::default();
    let _ = unsafe {
        UnlockFileEx(
            file.as_raw_handle() as HANDLE,
            0,
            u32::MAX,
            u32::MAX,
            &mut overlapped,
        )
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingress::sender::qwp_ws_sfa_segment::spare_segment_path;
    use tempfile::TempDir;

    fn options(sf_dir: &Path, sender_id: &str) -> SfaSlotOptions {
        SfaSlotOptions {
            sf_dir: sf_dir.to_path_buf(),
            sender_id: sender_id.to_owned(),
            segment_size_bytes: 256,
            max_bytes: 1024,
            max_in_flight: 4,
        }
    }

    fn queue_options(slot_dir: PathBuf) -> SfaQueueOptions {
        SfaQueueOptions {
            slot_dir,
            segment_size_bytes: 256,
            max_bytes: 1024,
            max_in_flight: 4,
        }
    }

    #[test]
    fn sender_id_validation_matches_java_slot_name_rules() {
        for valid in ["default", "primary", "A_z-09"] {
            validate_sender_id(valid).unwrap();
        }

        for invalid in ["", ".", "a.b", "a/b", "a b", "utf8-\u{e9}"] {
            let err = validate_sender_id(invalid).unwrap_err();
            assert!(matches!(err, SfaQueueError::InvalidSenderId { .. }));
        }
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn open_creates_slot_layout_and_lock_file() {
        let temp = TempDir::new().unwrap();
        let sf_dir = temp.path().join("sf-root");

        let queue = SfaSlotQueue::open(options(&sf_dir, "primary")).unwrap();

        let slot_dir = sf_dir.join("primary");
        assert_eq!(queue.slot_dir(), Some(slot_dir.as_path()));
        assert!(slot_dir.is_dir());
        assert!(slot_dir.join(LOCK_FILE_NAME).exists());
        assert!(slot_dir.join(LOCK_PID_FILE_NAME).exists());
        assert!(spare_segment_path(&slot_dir, 0).exists());
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn replay_only_existing_open_does_not_create_missing_slot() {
        let temp = TempDir::new().unwrap();
        let slot_dir = temp.path().join("sf-root").join("orphan");

        let err =
            SfaSlotQueue::open_replay_only_existing(queue_options(slot_dir.clone())).unwrap_err();

        assert!(matches!(err, SfaQueueError::Io(_)));
        assert!(!slot_dir.exists());
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn second_open_on_same_slot_fails_fast_before_interleaving_segments() {
        let temp = TempDir::new().unwrap();
        let sf_dir = temp.path().join("sf-root");
        let _first = SfaSlotQueue::open(options(&sf_dir, DEFAULT_SENDER_ID)).unwrap();
        let pid_path = sf_dir.join(DEFAULT_SENDER_ID).join(LOCK_PID_FILE_NAME);
        fs::write(&pid_path, b"4242\n").unwrap();

        let err = SfaSlotQueue::open(options(&sf_dir, DEFAULT_SENDER_ID)).unwrap_err();

        assert!(matches!(
            err,
            SfaQueueError::SlotInUse {
                slot_dir,
                holder
            } if slot_dir == sf_dir.join(DEFAULT_SENDER_ID)
                && holder == "pid=4242"
        ));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn distinct_sender_ids_are_independent_slots() {
        let temp = TempDir::new().unwrap();
        let sf_dir = temp.path().join("sf-root");

        let a = SfaSlotQueue::open(options(&sf_dir, "a")).unwrap();
        let b = SfaSlotQueue::open(options(&sf_dir, "b")).unwrap();

        assert_eq!(a.slot_dir(), Some(sf_dir.join("a").as_path()));
        assert_eq!(b.slot_dir(), Some(sf_dir.join("b").as_path()));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn close_releases_lock_but_leaves_lock_file_for_reuse() {
        let temp = TempDir::new().unwrap();
        let sf_dir = temp.path().join("sf-root");
        let mut first = SfaSlotQueue::open(options(&sf_dir, DEFAULT_SENDER_ID)).unwrap();
        let lock_path = sf_dir.join(DEFAULT_SENDER_ID).join(LOCK_FILE_NAME);
        let pid_path = sf_dir.join(DEFAULT_SENDER_ID).join(LOCK_PID_FILE_NAME);

        first.close().unwrap();
        assert!(lock_path.exists());
        assert!(pid_path.exists());

        let second = SfaSlotQueue::open(options(&sf_dir, DEFAULT_SENDER_ID)).unwrap();
        assert_eq!(
            second.slot_dir(),
            Some(sf_dir.join(DEFAULT_SENDER_ID).as_path())
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn subprocess_holder_releases_slot_lock_on_exit() {
        use std::time::Duration;

        let temp = TempDir::new().unwrap();
        let sf_dir = temp.path().join("sf-root");
        let ready_path = temp.path().join("holder-ready");
        let release_path = temp.path().join("holder-release");
        let mut holder = slot_lock_helper_command("hold", &sf_dir, DEFAULT_SENDER_ID)
            .env("QDB_SFA_SLOT_CHILD_READY", &ready_path)
            .env("QDB_SFA_SLOT_CHILD_RELEASE", &release_path)
            .spawn()
            .unwrap();

        wait_for_path(&ready_path, Duration::from_secs(5));

        let mut contender = slot_lock_helper_command("contend", &sf_dir, DEFAULT_SENDER_ID)
            .env("QDB_SFA_SLOT_CHILD_HOLDER_PID", holder.id().to_string())
            .spawn()
            .unwrap();
        wait_for_child(&mut contender, Duration::from_secs(5));

        fs::write(&release_path, b"release\n").unwrap();
        wait_for_child(&mut holder, Duration::from_secs(5));

        let mut acquirer = slot_lock_helper_command("acquire", &sf_dir, DEFAULT_SENDER_ID)
            .spawn()
            .unwrap();
        wait_for_child(&mut acquirer, Duration::from_secs(5));
    }

    #[cfg(any(unix, windows))]
    #[test]
    #[ignore = "helper for subprocess_holder_releases_slot_lock_on_exit"]
    fn qwp_ws_sfa_slot_child_process_lock_helper() {
        let Ok(mode) = std::env::var("QDB_SFA_SLOT_CHILD_MODE") else {
            return;
        };
        let sf_dir = PathBuf::from(std::env::var_os("QDB_SFA_SLOT_CHILD_SF_DIR").unwrap());
        let sender_id = std::env::var("QDB_SFA_SLOT_CHILD_SENDER_ID").unwrap();

        match mode.as_str() {
            "hold" => {
                use std::time::Duration;

                let ready_path =
                    PathBuf::from(std::env::var_os("QDB_SFA_SLOT_CHILD_READY").unwrap());
                let release_path =
                    PathBuf::from(std::env::var_os("QDB_SFA_SLOT_CHILD_RELEASE").unwrap());
                let _queue = SfaSlotQueue::open(options(&sf_dir, &sender_id)).unwrap();
                fs::write(&ready_path, b"ready\n").unwrap();
                wait_for_path(&release_path, Duration::from_secs(30));
            }
            "contend" => {
                let holder_pid = std::env::var("QDB_SFA_SLOT_CHILD_HOLDER_PID").unwrap();
                let err = SfaSlotQueue::open(options(&sf_dir, &sender_id)).unwrap_err();
                assert!(matches!(
                    err,
                    SfaQueueError::SlotInUse {
                        slot_dir,
                        holder
                    } if slot_dir == sf_dir.join(&sender_id)
                        && holder == format!("pid={holder_pid}")
                ));
            }
            "acquire" => {
                let queue = SfaSlotQueue::open(options(&sf_dir, &sender_id)).unwrap();
                assert_eq!(queue.slot_dir(), Some(sf_dir.join(&sender_id).as_path()));
            }
            mode => panic!("unknown slot lock helper mode: {mode}"),
        }
    }

    #[cfg(any(unix, windows))]
    fn slot_lock_helper_command(
        mode: &str,
        sf_dir: &Path,
        sender_id: &str,
    ) -> std::process::Command {
        const HELPER_TEST: &str =
            "ingress::sender::qwp_ws_sfa_slot::tests::qwp_ws_sfa_slot_child_process_lock_helper";

        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .arg(HELPER_TEST)
            .arg("--exact")
            .arg("--ignored")
            .arg("--nocapture")
            .env("QDB_SFA_SLOT_CHILD_MODE", mode)
            .env("QDB_SFA_SLOT_CHILD_SF_DIR", sf_dir)
            .env("QDB_SFA_SLOT_CHILD_SENDER_ID", sender_id);
        command
    }

    #[cfg(any(unix, windows))]
    fn wait_for_path(path: &Path, timeout: std::time::Duration) {
        use std::thread;
        use std::time::{Duration, Instant};

        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if path.exists() {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("timed out waiting for {}", path.display());
    }

    #[cfg(any(unix, windows))]
    fn wait_for_child(child: &mut std::process::Child, timeout: std::time::Duration) {
        use std::thread;
        use std::time::{Duration, Instant};

        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success(), "child exited with {status}");
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        let _ = child.kill();
        panic!("timed out waiting for child process");
    }

    #[cfg(not(any(unix, windows)))]
    #[test]
    fn slot_lock_is_unsupported_on_other_platforms() {
        let temp = TempDir::new().unwrap();
        let err = SlotLock::lock_file(temp.path().join("slot")).unwrap_err();

        assert!(matches!(err, SfaQueueError::SlotLockUnsupported));
    }
}
