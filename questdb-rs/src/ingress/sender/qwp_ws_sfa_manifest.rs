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

//! Java-compatible crash-safe records for an SFA slot.
//!
//! Both the segment-chain manifest and ACK watermark use two independently
//! CRC-protected 64-byte records at the starts of separate 4 KiB slots. An
//! update rewrites only one slot, so a sector tear cannot destroy both the new
//! value and the previous committed value.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use super::qwp_ws_sfa_segment::{read_exact_at, write_all_at};

pub(crate) const ACK_WATERMARK_FILE_NAME: &str = ".ack-watermark";
pub(crate) const MANIFEST_FILE_NAME: &str = "sf-manifest.bin";

const ACK_WATERMARK_MAGIC: u32 = 0x3157_4b41; // 'AKW1' in little-endian bytes.
const MANIFEST_MAGIC: u32 = 0x314d_4653; // 'SFM1' in little-endian bytes.
const VERSION: u32 = 1;
const RECORD_SIZE: usize = 64;
const CRC_OFFSET: usize = 60;
const RECORD_SLOT_SIZE: u64 = 4 * 1024;
pub(crate) const DUAL_SLOT_FILE_SIZE: u64 = 8 * 1024;

#[derive(Debug)]
pub(crate) struct SfManifest {
    file: File,
    generation: u64,
    head_base: u64,
    active_base: u64,
}

#[derive(Debug)]
pub(crate) struct SfaAckWatermark {
    file: File,
    generation: u64,
    fsn: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RawRecord {
    generation: u64,
    first: i64,
    second: i64,
}

impl SfManifest {
    pub(crate) fn create(slot_dir: &Path, head_base: u64, active_base: u64) -> io::Result<Self> {
        validate_manifest_boundaries(head_base, active_base)?;
        let path = manifest_path(slot_dir);
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)?;
        let result = (|| {
            allocate_dual_slot_file(&file)?;
            let mut manifest = Self {
                file,
                generation: 0,
                head_base: 0,
                active_base: 0,
            };
            manifest.update(head_base, active_base)?;
            sync_directory(slot_dir)?;
            Ok(manifest)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&path);
        }
        result
    }

    pub(crate) fn open(slot_dir: &Path) -> io::Result<Option<Self>> {
        let path = manifest_path(slot_dir);
        let metadata = match fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err),
        };
        if metadata.len() != DUAL_SLOT_FILE_SIZE {
            quarantine_invalid_file(&path)?;
            return Ok(None);
        }

        let file = OpenOptions::new().read(true).write(true).open(&path)?;
        let selected = select_record(
            read_record(&file, 0, MANIFEST_MAGIC)?,
            read_record(&file, RECORD_SLOT_SIZE, MANIFEST_MAGIC)?,
            |record| {
                record.first >= 0
                    && record.second >= record.first
                    && u64::try_from(record.second).is_ok()
            },
        );
        let Some(record) = selected else {
            drop(file);
            quarantine_invalid_file(&path)?;
            return Ok(None);
        };
        Ok(Some(Self {
            file,
            generation: record.generation,
            head_base: record.first as u64,
            active_base: record.second as u64,
        }))
    }

    pub(crate) fn head_base(&self) -> u64 {
        self.head_base
    }

    pub(crate) fn active_base(&self) -> u64 {
        self.active_base
    }

    pub(crate) fn update(
        &mut self,
        mut new_head_base: u64,
        mut new_active_base: u64,
    ) -> io::Result<()> {
        if self.generation > 0 {
            new_head_base = new_head_base.max(self.head_base);
            new_active_base = new_active_base.max(self.active_base);
        }
        validate_manifest_boundaries(new_head_base, new_active_base)?;
        if self.generation > 0
            && new_head_base == self.head_base
            && new_active_base == self.active_base
        {
            return Ok(());
        }

        let next_generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| invalid_data("SF manifest generation overflow"))?;
        if next_generation > i64::MAX as u64 {
            return Err(invalid_data("SF manifest generation overflow"));
        }
        let record = encode_record(
            MANIFEST_MAGIC,
            next_generation,
            new_head_base as i64,
            new_active_base as i64,
        );
        write_record(&self.file, next_generation, &record)?;
        self.file.sync_all()?;
        self.generation = next_generation;
        self.head_base = new_head_base;
        self.active_base = new_active_base;
        Ok(())
    }

    pub(crate) fn remove_file(slot_dir: &Path) -> io::Result<()> {
        remove_if_exists(&manifest_path(slot_dir))
    }

    #[cfg(test)]
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }
}

impl SfaAckWatermark {
    pub(crate) fn open(slot_dir: &Path, require_existing: bool) -> io::Result<Self> {
        let path = ack_watermark_path(slot_dir);
        let existing_len = match fs::metadata(&path) {
            Ok(metadata) => Some(metadata.len()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => None,
            Err(err) => return Err(err),
        };
        if require_existing && existing_len.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "recovered SFA slot is missing ACK watermark {}",
                    path.display()
                ),
            ));
        }

        let file = if existing_len == Some(DUAL_SLOT_FILE_SIZE) {
            OpenOptions::new().read(true).write(true).open(&path)?
        } else {
            let file = OpenOptions::new()
                .create(true)
                .truncate(true)
                .read(true)
                .write(true)
                .open(&path)?;
            allocate_dual_slot_file(&file)?;
            file
        };
        let selected = select_record(
            read_record(&file, 0, ACK_WATERMARK_MAGIC)?,
            read_record(&file, RECORD_SLOT_SIZE, ACK_WATERMARK_MAGIC)?,
            |record| record.first >= -1,
        );
        Ok(match selected {
            Some(record) => Self {
                file,
                generation: record.generation,
                fsn: Some(record.first),
            },
            None => Self {
                file,
                generation: 0,
                fsn: None,
            },
        })
    }

    pub(crate) fn read(&mut self) -> io::Result<Option<i64>> {
        let selected = select_record(
            read_record(&self.file, 0, ACK_WATERMARK_MAGIC)?,
            read_record(&self.file, RECORD_SLOT_SIZE, ACK_WATERMARK_MAGIC)?,
            |record| record.first >= -1,
        );
        match selected {
            Some(record) => {
                self.generation = record.generation;
                self.fsn = Some(record.first);
            }
            None => {
                self.generation = 0;
                self.fsn = None;
            }
        }
        Ok(self.fsn)
    }

    pub(crate) fn write(&mut self, fsn: i64) -> io::Result<()> {
        if fsn < -1 {
            return Err(invalid_data("ACK watermark FSN is below -1"));
        }
        let next_generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| invalid_data("ACK watermark generation overflow"))?;
        if next_generation > i64::MAX as u64 {
            return Err(invalid_data("ACK watermark generation overflow"));
        }
        let record = encode_record(ACK_WATERMARK_MAGIC, next_generation, fsn, 0);
        write_record(&self.file, next_generation, &record)?;
        self.generation = next_generation;
        self.fsn = Some(fsn);
        Ok(())
    }

    pub(crate) fn sync_data(&self) -> io::Result<()> {
        self.file.sync_data()
    }

    pub(crate) fn remove_file(slot_dir: &Path) -> io::Result<()> {
        remove_if_exists(&ack_watermark_path(slot_dir))
    }

    #[cfg(test)]
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }
}

pub(crate) fn ack_watermark_path(slot_dir: &Path) -> PathBuf {
    slot_dir.join(ACK_WATERMARK_FILE_NAME)
}

pub(crate) fn manifest_path(slot_dir: &Path) -> PathBuf {
    slot_dir.join(MANIFEST_FILE_NAME)
}

/// Makes directory-entry changes durable on platforms with directory fsync.
#[cfg(unix)]
pub(crate) fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(not(unix))]
pub(crate) fn sync_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

fn validate_manifest_boundaries(head_base: u64, active_base: u64) -> io::Result<()> {
    if head_base > i64::MAX as u64 || active_base > i64::MAX as u64 || active_base < head_base {
        return Err(invalid_data("invalid SF manifest boundaries"));
    }
    Ok(())
}

fn allocate_dual_slot_file(file: &File) -> io::Result<()> {
    let zeroes = [0u8; DUAL_SLOT_FILE_SIZE as usize];
    write_all_at(file, &zeroes, 0)
}

fn encode_record(magic: u32, generation: u64, first: i64, second: i64) -> [u8; RECORD_SIZE] {
    let mut record = [0u8; RECORD_SIZE];
    record[0..4].copy_from_slice(&magic.to_le_bytes());
    record[4..8].copy_from_slice(&VERSION.to_le_bytes());
    record[8..16].copy_from_slice(&(generation as i64).to_le_bytes());
    record[16..24].copy_from_slice(&first.to_le_bytes());
    record[24..32].copy_from_slice(&second.to_le_bytes());
    let crc = crc32c::crc32c(&record[..CRC_OFFSET]);
    record[CRC_OFFSET..RECORD_SIZE].copy_from_slice(&crc.to_le_bytes());
    record
}

fn write_record(file: &File, generation: u64, record: &[u8; RECORD_SIZE]) -> io::Result<()> {
    let offset = (generation & 1) * RECORD_SLOT_SIZE;
    write_all_at(file, record, offset)
}

fn read_record(file: &File, offset: u64, magic: u32) -> io::Result<Option<RawRecord>> {
    let mut record = [0u8; RECORD_SIZE];
    read_exact_at(file, &mut record, offset)?;
    if read_u32(&record, 0) != magic || read_u32(&record, 4) != VERSION {
        return Ok(None);
    }
    let expected_crc = read_u32(&record, CRC_OFFSET);
    let actual_crc = crc32c::crc32c(&record[..CRC_OFFSET]);
    if expected_crc != actual_crc {
        return Ok(None);
    }
    let generation = read_i64(&record, 8);
    if generation <= 0 {
        return Ok(None);
    }
    Ok(Some(RawRecord {
        generation: generation as u64,
        first: read_i64(&record, 16),
        second: read_i64(&record, 24),
    }))
}

fn select_record(
    first: Option<RawRecord>,
    second: Option<RawRecord>,
    valid_payload: impl Fn(RawRecord) -> bool,
) -> Option<RawRecord> {
    let first = first.filter(|record| valid_payload(*record));
    let second = second.filter(|record| valid_payload(*record));
    match (first, second) {
        (None, None) => None,
        (Some(record), None) | (None, Some(record)) => Some(record),
        (Some(first), Some(second)) => {
            if first.generation > second.generation {
                Some(first)
            } else {
                Some(second)
            }
        }
    }
}

fn quarantine_invalid_file(path: &Path) -> io::Result<()> {
    let mut corrupt_path = path.as_os_str().to_os_string();
    corrupt_path.push(".corrupt");
    let corrupt_path = PathBuf::from(corrupt_path);
    match fs::remove_file(&corrupt_path) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(_) => {}
    }
    if fs::rename(path, &corrupt_path).is_ok() {
        return Ok(());
    }
    remove_if_exists(path)
}

fn remove_if_exists(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_i64(bytes: &[u8], offset: usize) -> i64 {
    i64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn manifest_first_record_uses_second_slot_and_clamps_regressions() {
        let dir = TempDir::new().unwrap();
        let mut manifest = SfManifest::create(dir.path(), 10, 20).unwrap();
        assert_eq!(manifest.generation(), 1);
        let bytes = fs::read(manifest_path(dir.path())).unwrap();
        assert!(bytes[..RECORD_SIZE].iter().all(|byte| *byte == 0));
        assert_eq!(read_u32(&bytes, RECORD_SLOT_SIZE as usize), MANIFEST_MAGIC);

        manifest.update(5, 15).unwrap();
        assert_eq!(manifest.generation(), 1);
        assert_eq!(manifest.head_base(), 10);
        assert_eq!(manifest.active_base(), 20);
        manifest.update(12, 18).unwrap();
        assert_eq!(manifest.head_base(), 12);
        assert_eq!(manifest.active_base(), 20);
        manifest.update(12, 25).unwrap();
        drop(manifest);

        let reopened = SfManifest::open(dir.path()).unwrap().unwrap();
        assert_eq!(reopened.head_base(), 12);
        assert_eq!(reopened.active_base(), 25);
    }

    #[test]
    fn manifest_falls_back_to_the_other_valid_record() {
        let dir = TempDir::new().unwrap();
        let mut manifest = SfManifest::create(dir.path(), 10, 20).unwrap();
        manifest.update(12, 25).unwrap();
        let path = manifest_path(dir.path());
        drop(manifest);

        let file = OpenOptions::new().write(true).open(&path).unwrap();
        write_all_at(&file, &[0xa5; 512], 0).unwrap();
        file.sync_all().unwrap();

        let reopened = SfManifest::open(dir.path()).unwrap().unwrap();
        assert_eq!(reopened.head_base(), 10);
        assert_eq!(reopened.active_base(), 20);
    }

    #[test]
    fn manifest_quarantines_wrong_size_and_two_invalid_records() {
        for (name, bytes) in [
            ("wrong-size", vec![0xa5; 17]),
            ("both-invalid", vec![0xa5; DUAL_SLOT_FILE_SIZE as usize]),
        ] {
            let dir = TempDir::new().unwrap();
            let path = manifest_path(dir.path());
            fs::write(&path, bytes).unwrap();

            assert!(SfManifest::open(dir.path()).unwrap().is_none(), "{name}");
            assert!(!path.exists(), "{name}");
            assert!(
                PathBuf::from(format!("{}.corrupt", path.display())).exists(),
                "{name}"
            );
        }
    }

    #[test]
    fn equal_generation_records_select_the_second_slot() {
        let dir = TempDir::new().unwrap();
        let path = manifest_path(dir.path());
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        allocate_dual_slot_file(&file).unwrap();
        write_all_at(&file, &encode_record(MANIFEST_MAGIC, 7, 10, 20), 0).unwrap();
        write_all_at(
            &file,
            &encode_record(MANIFEST_MAGIC, 7, 30, 40),
            RECORD_SLOT_SIZE,
        )
        .unwrap();
        drop(file);

        let manifest = SfManifest::open(dir.path()).unwrap().unwrap();
        assert_eq!(manifest.head_base(), 30);
        assert_eq!(manifest.active_base(), 40);
    }

    #[test]
    fn watermark_resets_legacy_size_and_falls_back_after_a_torn_update() {
        let dir = TempDir::new().unwrap();
        fs::write(ack_watermark_path(dir.path()), [0u8; 16]).unwrap();
        let mut watermark = SfaAckWatermark::open(dir.path(), true).unwrap();
        assert_eq!(watermark.read().unwrap(), None);
        assert_eq!(
            fs::metadata(ack_watermark_path(dir.path())).unwrap().len(),
            DUAL_SLOT_FILE_SIZE
        );
        watermark.write(255).unwrap();
        watermark.write(256).unwrap();
        watermark.sync_data().unwrap();
        drop(watermark);

        let file = OpenOptions::new()
            .write(true)
            .open(ack_watermark_path(dir.path()))
            .unwrap();
        write_all_at(&file, &[0xa5; 512], 0).unwrap();
        file.sync_all().unwrap();

        let mut reopened = SfaAckWatermark::open(dir.path(), true).unwrap();
        assert_eq!(reopened.read().unwrap(), Some(255));
    }

    #[test]
    fn watermark_rewrites_the_inactive_slot_even_for_the_same_fsn() {
        let dir = TempDir::new().unwrap();
        let mut watermark = SfaAckWatermark::open(dir.path(), false).unwrap();
        watermark.write(42).unwrap();
        watermark.write(42).unwrap();

        assert_eq!(watermark.generation(), 2);
        let bytes = fs::read(ack_watermark_path(dir.path())).unwrap();
        assert_eq!(read_i64(&bytes, 8), 2);
        assert_eq!(read_i64(&bytes, 16), 42);
        assert_eq!(read_i64(&bytes, RECORD_SLOT_SIZE as usize + 8), 1);
    }
}
