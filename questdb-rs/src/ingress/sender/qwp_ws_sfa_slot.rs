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
//! `sender_id` names the slot under it, and `<sf_dir>/<sender_id>/.lock` is held
//! for the queue lifetime.

use std::fs;
#[cfg(unix)]
use std::fs::{File, OpenOptions};
use std::io;
#[cfg(unix)]
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::fd::AsRawFd;

use super::qwp_ws_driver::{DriverError, ManualDriverQueue};
use super::qwp_ws_queue::{OutboundFrame, QwpReceipt, QwpReceiptStatus, SentFrame};
use super::qwp_ws_sfa_queue::{SfaFrameQueue, SfaQueueError, SfaQueueOptions};
use crate::ingress::conf::{QWP_WS_DEFAULT_SENDER_ID, is_valid_qwp_ws_sender_id};

pub(crate) const DEFAULT_SENDER_ID: &str = QWP_WS_DEFAULT_SENDER_ID;
const LOCK_FILE_NAME: &str = ".lock";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SfaSlotOptions {
    pub(crate) sf_dir: PathBuf,
    pub(crate) sender_id: String,
    pub(crate) segment_size_bytes: u64,
    pub(crate) max_frames: usize,
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
            max_frames: options.max_frames,
            max_bytes: options.max_bytes,
            max_in_flight: options.max_in_flight,
        })?;

        Ok(Self {
            queue,
            lock: Some(lock),
        })
    }

    pub(crate) fn close(&mut self) -> Result<(), SfaQueueError> {
        let result = self.queue.close();
        self.lock.take();
        result
    }

    pub(crate) fn slot_dir(&self) -> Option<&Path> {
        self.lock.as_ref().map(SlotLock::slot_dir)
    }
}

impl ManualDriverQueue for SfaSlotQueue {
    fn try_submit(&mut self, payload: &[u8]) -> Result<QwpReceipt, DriverError> {
        Ok(self.queue.try_submit(payload)?)
    }

    fn next_outbound_frame(&self) -> Result<OutboundFrame<'_>, DriverError> {
        Ok(self.queue.next_outbound_frame()?)
    }

    fn commit_sent(&mut self, frame: SentFrame) -> Result<(), DriverError> {
        Ok(self.queue.commit_sent(frame)?)
    }

    fn ack_wire(&mut self, wire_seq: u64) -> Result<(), DriverError> {
        Ok(self.queue.ack_wire(wire_seq)?)
    }

    fn reject_wire(&mut self, wire_seq: u64) -> Result<QwpReceipt, DriverError> {
        Ok(self.queue.reject_wire(wire_seq)?)
    }

    fn close(&mut self) -> Result<(), DriverError> {
        Ok(SfaSlotQueue::close(self)?)
    }

    fn restart_connection(&mut self) {
        self.queue.restart_connection();
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

    fn fsn_for_wire_seq(&self, wire_seq: u64) -> Result<u64, DriverError> {
        Ok(self.queue.fsn_for_wire_seq(wire_seq)?)
    }
}

#[derive(Debug)]
struct SlotLock {
    slot_dir: PathBuf,
    #[cfg(unix)]
    file: File,
}

impl SlotLock {
    fn acquire(slot_dir: PathBuf) -> Result<Self, SfaQueueError> {
        validate_slot_dir(&slot_dir)?;
        ensure_dir(&slot_dir)?;
        Self::lock_file(slot_dir)
    }

    fn slot_dir(&self) -> &Path {
        &self.slot_dir
    }

    #[cfg(unix)]
    fn lock_file(slot_dir: PathBuf) -> Result<Self, SfaQueueError> {
        let lock_path = slot_dir.join(LOCK_FILE_NAME);
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&lock_path)?;
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            let holder = read_lock_holder(&lock_path);
            return Err(SfaQueueError::SlotInUse { slot_dir, holder });
        }
        write_pid(&mut file)?;
        Ok(Self { slot_dir, file })
    }

    #[cfg(not(unix))]
    fn lock_file(slot_dir: PathBuf) -> Result<Self, SfaQueueError> {
        let _ = slot_dir;
        Err(SfaQueueError::SlotLockUnsupported)
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

#[cfg(unix)]
fn read_lock_holder(lock_path: &Path) -> String {
    match fs::read(lock_path) {
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

#[cfg(unix)]
fn write_pid(file: &mut File) -> Result<(), io::Error> {
    let payload = format!("{}\n", std::process::id());
    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(payload.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingress::sender::qwp_ws_sfa_segment::initial_segment_path;
    use tempfile::TempDir;

    fn options(sf_dir: &Path, sender_id: &str) -> SfaSlotOptions {
        SfaSlotOptions {
            sf_dir: sf_dir.to_path_buf(),
            sender_id: sender_id.to_owned(),
            segment_size_bytes: 256,
            max_frames: 16,
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

    #[cfg(unix)]
    #[test]
    fn open_creates_java_slot_layout_and_lock_file() {
        let temp = TempDir::new().unwrap();
        let sf_dir = temp.path().join("sf-root");

        let queue = SfaSlotQueue::open(options(&sf_dir, "primary")).unwrap();

        let slot_dir = sf_dir.join("primary");
        assert_eq!(queue.slot_dir(), Some(slot_dir.as_path()));
        assert!(slot_dir.is_dir());
        assert!(slot_dir.join(LOCK_FILE_NAME).exists());
        assert!(initial_segment_path(&slot_dir).exists());
    }

    #[cfg(unix)]
    #[test]
    fn second_open_on_same_slot_fails_fast_before_interleaving_segments() {
        let temp = TempDir::new().unwrap();
        let sf_dir = temp.path().join("sf-root");
        let _first = SfaSlotQueue::open(options(&sf_dir, DEFAULT_SENDER_ID)).unwrap();

        let err = SfaSlotQueue::open(options(&sf_dir, DEFAULT_SENDER_ID)).unwrap_err();

        assert!(matches!(
            err,
            SfaQueueError::SlotInUse {
                slot_dir,
                holder
            } if slot_dir == sf_dir.join(DEFAULT_SENDER_ID)
                && holder.starts_with("pid=")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn distinct_sender_ids_are_independent_slots() {
        let temp = TempDir::new().unwrap();
        let sf_dir = temp.path().join("sf-root");

        let a = SfaSlotQueue::open(options(&sf_dir, "a")).unwrap();
        let b = SfaSlotQueue::open(options(&sf_dir, "b")).unwrap();

        assert_eq!(a.slot_dir(), Some(sf_dir.join("a").as_path()));
        assert_eq!(b.slot_dir(), Some(sf_dir.join("b").as_path()));
    }

    #[cfg(unix)]
    #[test]
    fn close_releases_lock_but_leaves_lock_file_for_reuse() {
        let temp = TempDir::new().unwrap();
        let sf_dir = temp.path().join("sf-root");
        let mut first = SfaSlotQueue::open(options(&sf_dir, DEFAULT_SENDER_ID)).unwrap();
        let lock_path = sf_dir.join(DEFAULT_SENDER_ID).join(LOCK_FILE_NAME);

        first.close().unwrap();
        assert!(lock_path.exists());

        let second = SfaSlotQueue::open(options(&sf_dir, DEFAULT_SENDER_ID)).unwrap();
        assert_eq!(
            second.slot_dir(),
            Some(sf_dir.join(DEFAULT_SENDER_ID).as_path())
        );
    }
}
