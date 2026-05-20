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

//! Java-compatible `.sfa` Store-and-Forward segment codec.
//!
//! This is the narrow disk-format layer shared by the future QWP/WebSocket SF
//! queue. It intentionally knows nothing about receipts, WebSocket wire
//! sequences, or server rejection policy.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::ptr;
use std::slice;
use std::sync::Arc;

use memmap2::{MmapMut, MmapOptions};

pub(crate) const FILE_MAGIC: u32 = 0x3130_4653; // 'SF01' in little-endian bytes.
pub(crate) const VERSION: u8 = 1;
pub(crate) const HEADER_SIZE: usize = 24;
pub(crate) const FRAME_HEADER_SIZE: usize = 8;
pub(crate) const INITIAL_SEGMENT_FILE_NAME: &str = "sf-initial.sfa";

// Keep the payloads in these errors: recovery reports them through Debug today,
// and tests pattern-match specific corruption details.
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) enum SfaSegmentError {
    Io(io::Error),
    FileTooShort {
        size: usize,
    },
    SizeTooSmall {
        size: u64,
    },
    BadMagic {
        actual: u32,
    },
    UnsupportedVersion {
        actual: u8,
    },
    NonZeroFlags {
        actual: u8,
    },
    NonZeroReserved {
        actual: u16,
    },
    NegativeBaseSeq {
        actual: i64,
    },
    BaseSeqTooLarge {
        base_seq: u64,
    },
    SizeTooLargeForPlatform {
        size: u64,
    },
    PayloadTooLarge {
        payload_len: usize,
    },
    OffsetOverflow,
    /// Filesystem rejected block-preallocation; the silent `set_len`
    /// fallback would expose mmap'd writes to a SIGBUS-on-ENOSPC kill.
    PreallocationUnsupported,
}

impl From<io::Error> for SfaSegmentError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SfaSegmentHeader {
    pub(crate) base_seq: u64,
    pub(crate) created_us: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(test)]
pub(crate) struct SfaFrame {
    pub(crate) fsn: u64,
    pub(crate) offset: u64,
    pub(crate) payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SfaSegmentMetadataScan {
    pub(crate) header: SfaSegmentHeader,
    pub(crate) frame_count: u64,
    pub(crate) append_offset: u64,
    pub(crate) torn_tail_bytes: u64,
    pub(crate) first_empty_payload_fsn: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(test)]
pub(crate) struct SfaSegmentScan {
    pub(crate) header: SfaSegmentHeader,
    pub(crate) frames: Vec<SfaFrame>,
    pub(crate) append_offset: u64,
    pub(crate) torn_tail_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SfaAppend {
    pub(crate) offset: u64,
    pub(crate) frame_end: u64,
}

#[derive(Debug)]
pub(crate) struct SfaSegment {
    // Kept with file-backed segments so the segment owns the file handle
    // alongside the writable mapping.
    #[allow(dead_code)]
    file: Option<File>,
    mapping: Arc<SfaSegmentMapping>,
    path: Option<PathBuf>,
    size_bytes: u64,
    header: SfaSegmentHeader,
    append_offset: u64,
    frame_count: u64,
    // Recovery records this on opened segments; queue recovery also reports the
    // metadata scan directly before opening the segment.
    #[allow(dead_code)]
    torn_tail_bytes: u64,
}

pub(crate) struct SfaMappedPayload {
    mapping: Arc<SfaSegmentMapping>,
    offset: usize,
    len: usize,
}

struct SfaSegmentMapping {
    // Field declaration order matters: `_mmap` must drop before any field that
    // reads through `base`. Today `base`/`len` carry no drop glue, but if a
    // future field gains one it must be declared *above* `_mmap` so munmap
    // runs last.
    //
    // `_mmap` is owned solely to keep the OS mapping alive (its Drop calls
    // munmap). All byte access goes through `base`; we deliberately never
    // re-borrow `MmapMut` after construction. Re-borrowing would synthesise a
    // transient `&MmapMut` / `&mut MmapMut` covering the full mapping, which
    // is aliasing UB once this struct is shared via Arc — even when the byte
    // ranges touched by concurrent callers are disjoint.
    _mmap: MmapMut,
    base: *mut u8,
    len: usize,
}

// SAFETY: `MmapMut` is itself `Send + Sync`. Concurrent access through `base`
// is coordinated by callers: the publisher only writes ranges past the segment
// append offset, while readers only read ranges below the published offset, so
// the bytes touched are disjoint and use raw-pointer provenance.
unsafe impl Send for SfaSegmentMapping {}
unsafe impl Sync for SfaSegmentMapping {}

impl SfaSegment {
    #[cfg(test)]
    pub(crate) fn create(
        path: impl AsRef<Path>,
        base_seq: u64,
        size_bytes: u64,
        created_us: u64,
    ) -> Result<Self, SfaSegmentError> {
        Self::create_inner(path, base_seq, size_bytes, created_us, false)
    }

    pub(crate) fn create_new(
        path: impl AsRef<Path>,
        base_seq: u64,
        size_bytes: u64,
        created_us: u64,
    ) -> Result<Self, SfaSegmentError> {
        Self::create_inner(path, base_seq, size_bytes, created_us, true)
    }

    pub(crate) fn create_memory(
        base_seq: u64,
        size_bytes: u64,
        created_us: u64,
    ) -> Result<Self, SfaSegmentError> {
        validate_new_segment_args(base_seq, size_bytes)?;
        let mapping = map_anon_mut(size_bytes)?;
        let header = SfaSegmentHeader {
            base_seq,
            created_us,
        };
        mapping.copy_from(0, &encode_header(header));

        Ok(Self {
            file: None,
            mapping,
            path: None,
            size_bytes,
            header,
            append_offset: HEADER_SIZE as u64,
            frame_count: 0,
            torn_tail_bytes: 0,
        })
    }

    fn create_inner(
        path: impl AsRef<Path>,
        base_seq: u64,
        size_bytes: u64,
        created_us: u64,
        create_new: bool,
    ) -> Result<Self, SfaSegmentError> {
        validate_new_segment_args(base_seq, size_bytes)?;

        let path = path.as_ref();
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        if create_new {
            options.create_new(true);
        } else {
            options.create(true).truncate(true);
        }
        let file = options.open(path)?;
        if let Err(err) = reserve_segment_blocks(&file, size_bytes) {
            if create_new {
                let _ = fs::remove_file(path);
            }
            return Err(err);
        }
        let mapping = match map_file_mut(&file, size_bytes) {
            Ok(mapping) => mapping,
            Err(err) => {
                if create_new {
                    let _ = fs::remove_file(path);
                }
                return Err(err);
            }
        };
        let header = SfaSegmentHeader {
            base_seq,
            created_us,
        };
        mapping.copy_from(0, &encode_header(header));

        Ok(Self {
            file: Some(file),
            mapping,
            path: Some(path.to_path_buf()),
            size_bytes,
            header,
            append_offset: HEADER_SIZE as u64,
            frame_count: 0,
            torn_tail_bytes: 0,
        })
    }

    pub(crate) fn open_existing(path: impl AsRef<Path>) -> Result<Self, SfaSegmentError> {
        let path = path.as_ref();
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        let size_bytes = file.metadata()?.len();
        if size_bytes < HEADER_SIZE as u64 {
            return Err(SfaSegmentError::FileTooShort {
                size: size_bytes as usize,
            });
        }
        let mapping = map_file_mut(&file, size_bytes)?;
        let scan = mapping.with_full_slice(scan_segment_metadata_bytes)?;
        Ok(Self {
            file: Some(file),
            mapping,
            path: Some(path.to_path_buf()),
            size_bytes,
            header: scan.header,
            append_offset: scan.append_offset,
            frame_count: scan.frame_count,
            torn_tail_bytes: scan.torn_tail_bytes,
        })
    }

    #[cfg(test)]
    pub(crate) fn try_append(&mut self, payload: &[u8]) -> Result<Option<u64>, SfaSegmentError> {
        let Some(appended) = self.try_append_at(self.append_offset, payload)? else {
            return Ok(None);
        };
        self.append_offset = appended.frame_end;
        self.frame_count += 1;
        self.torn_tail_bytes = 0;
        Ok(Some(appended.offset))
    }

    pub(crate) fn try_append_at(
        &self,
        append_offset: u64,
        payload: &[u8],
    ) -> Result<Option<SfaAppend>, SfaSegmentError> {
        if payload.len() > i32::MAX as usize {
            return Err(SfaSegmentError::PayloadTooLarge {
                payload_len: payload.len(),
            });
        }
        let frame_len = (FRAME_HEADER_SIZE as u64)
            .checked_add(payload.len() as u64)
            .ok_or(SfaSegmentError::OffsetOverflow)?;
        let frame_end = append_offset
            .checked_add(frame_len)
            .ok_or(SfaSegmentError::OffsetOverflow)?;
        if frame_end > self.size_bytes {
            return Ok(None);
        }

        let offset_u64 = append_offset;
        let payload_len = (payload.len() as u32).to_le_bytes();
        let crc = crc32c_update(crc32c_update(0, &payload_len), payload);
        let offset = usize::try_from(offset_u64)
            .map_err(|_| SfaSegmentError::SizeTooLargeForPlatform { size: offset_u64 })?;
        let _ =
            usize::try_from(frame_end).map_err(|_| SfaSegmentError::SizeTooLargeForPlatform {
                size: self.size_bytes,
            })?;
        self.mapping.copy_from(offset + 4, &payload_len);
        self.mapping.copy_from(offset + 8, payload);
        self.mapping.copy_from(offset, &crc.to_le_bytes());
        Ok(Some(SfaAppend {
            offset: offset_u64,
            frame_end,
        }))
    }

    pub(crate) fn rebase_empty(&mut self, base_seq: u64) -> Result<(), SfaSegmentError> {
        validate_base_seq(base_seq)?;
        if self.frame_count != 0 || self.append_offset != HEADER_SIZE as u64 {
            return Err(SfaSegmentError::OffsetOverflow);
        }
        self.header.base_seq = base_seq;
        self.mapping.copy_from(8, &base_seq.to_le_bytes());
        Ok(())
    }

    pub(crate) fn frame_offset_for_fsn_with_limit(
        &self,
        fsn: u64,
        frame_count: u64,
        append_offset: u64,
    ) -> Option<u64> {
        if fsn < self.header.base_seq {
            return None;
        }
        let frame_index = fsn.checked_sub(self.header.base_seq)?;
        if frame_index >= frame_count {
            return None;
        }
        let mut pos = HEADER_SIZE as u64;
        for _ in 0..frame_index {
            pos = self.next_frame_offset_with_limit(pos, append_offset)?;
        }
        Some(pos)
    }

    pub(crate) fn mapped_payload_at_offset_with_limit(
        &self,
        offset: u64,
        append_offset: u64,
    ) -> Option<SfaMappedPayload> {
        self.payload_at_offset_with_limit(offset, append_offset)
    }

    pub(crate) fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    pub(crate) fn header(&self) -> SfaSegmentHeader {
        self.header
    }

    pub(crate) fn append_offset(&self) -> u64 {
        self.append_offset
    }

    pub(crate) fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    pub(crate) fn frame_count(&self) -> u64 {
        self.frame_count
    }

    #[cfg(test)]
    pub(crate) fn torn_tail_bytes(&self) -> u64 {
        self.torn_tail_bytes
    }

    pub(crate) fn last_fsn(&self) -> Option<u64> {
        self.frame_count
            .checked_sub(1)
            .and_then(|last_index| self.header.base_seq.checked_add(last_index))
    }

    fn payload_at_offset_with_limit(
        &self,
        offset: u64,
        append_offset: u64,
    ) -> Option<SfaMappedPayload> {
        let offset = usize::try_from(offset).ok()?;
        let append_offset = usize::try_from(append_offset).ok()?;
        let frame_header_end = offset.checked_add(FRAME_HEADER_SIZE)?;
        if frame_header_end > append_offset {
            return None;
        }
        let payload_len = self
            .mapping
            .with_slice(offset + 4, 4, |bytes| read_i32(bytes, 0));
        if payload_len < 0 {
            return None;
        }
        let payload_len = payload_len as usize;
        let payload_start = frame_header_end;
        let payload_end = payload_start.checked_add(payload_len)?;
        if payload_end > append_offset {
            return None;
        }
        Some(SfaMappedPayload {
            mapping: Arc::clone(&self.mapping),
            offset: payload_start,
            len: payload_len,
        })
    }

    fn next_frame_offset_with_limit(&self, offset: u64, append_offset: u64) -> Option<u64> {
        let payload = self.payload_at_offset_with_limit(offset, append_offset)?;
        offset
            .checked_add(FRAME_HEADER_SIZE as u64)?
            .checked_add(payload.len as u64)
    }
}

impl SfaMappedPayload {
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn with_bytes<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        self.mapping.with_slice(self.offset, self.len, f)
    }
}

impl std::fmt::Debug for SfaMappedPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SfaMappedPayload")
            .field("offset", &self.offset)
            .field("len", &self.len)
            .finish()
    }
}

impl SfaSegmentMapping {
    fn new(mut mmap: MmapMut) -> Self {
        let len = mmap.len();
        // Take the raw pointer once, while `self` is uniquely owned. After this
        // point the cached `base` is the only access path, so no further
        // `&MmapMut` / `&mut MmapMut` is ever materialised — the pointer's
        // provenance covers the whole mapping for the lifetime of `_mmap`.
        let base = mmap.as_mut_ptr();
        Self {
            _mmap: mmap,
            base,
            len,
        }
    }

    fn copy_from(&self, offset: usize, src: &[u8]) {
        assert!(
            offset
                .checked_add(src.len())
                .is_some_and(|end| end <= self.len)
        );
        // SAFETY: callers only write ranges that are not concurrently read or
        // written. Published payload ranges are immutable; append writes
        // length/payload before publishing the CRC and advancing the segment
        // append offset. All access goes through the cached raw pointer, so
        // disjoint concurrent reads via `slice` are sound.
        unsafe {
            ptr::copy_nonoverlapping(src.as_ptr(), self.base.add(offset), src.len());
        }
    }

    fn with_slice<R>(&self, offset: usize, len: usize, f: impl FnOnce(&[u8]) -> R) -> R {
        f(self.slice(offset, len))
    }

    fn slice(&self, offset: usize, len: usize) -> &[u8] {
        assert!(offset.checked_add(len).is_some_and(|end| end <= self.len));
        // SAFETY: the returned slice covers a published immutable range. The
        // queue may append to disjoint offsets through `copy_from` while this
        // slice is alive; both paths use raw-pointer provenance and never
        // re-borrow the `MmapMut`, so the disjoint accesses do not alias.
        unsafe { slice::from_raw_parts(self.base.add(offset) as *const u8, len) }
    }

    fn with_full_slice<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        self.with_slice(0, self.len, f)
    }
}

#[cfg(test)]
pub(crate) fn initial_segment_path(slot_dir: &Path) -> PathBuf {
    slot_dir.join(INITIAL_SEGMENT_FILE_NAME)
}

pub(crate) fn spare_segment_path(slot_dir: &Path, generation: u64) -> PathBuf {
    slot_dir.join(format!("sf-{generation:016x}.sfa"))
}

#[cfg(test)]
pub(crate) fn scan_file(path: impl AsRef<Path>) -> Result<SfaSegmentScan, SfaSegmentError> {
    let bytes = fs::read(path)?;
    scan_segment_bytes(&bytes)
}

pub(crate) fn scan_file_metadata(
    path: impl AsRef<Path>,
) -> Result<SfaSegmentMetadataScan, SfaSegmentError> {
    let file = File::open(path)?;
    let size_bytes = file.metadata()?.len();
    if size_bytes < HEADER_SIZE as u64 {
        return Err(SfaSegmentError::FileTooShort {
            size: usize::try_from(size_bytes).unwrap_or(usize::MAX),
        });
    }
    let len = usize::try_from(size_bytes)
        .map_err(|_| SfaSegmentError::SizeTooLargeForPlatform { size: size_bytes })?;
    // SAFETY: this read-only mapping is used only for a synchronous metadata
    // scan while the SFA slot lock prevents another writer from mutating files
    // in this slot.
    let mmap = unsafe {
        MmapOptions::new()
            .len(len)
            .map(&file)
            .map_err(SfaSegmentError::Io)?
    };
    scan_segment_metadata_bytes(&mmap)
}

pub(crate) fn scan_segment_metadata_bytes(
    bytes: &[u8],
) -> Result<SfaSegmentMetadataScan, SfaSegmentError> {
    let raw = scan_segment_bytes_inner(bytes, |_, _, _, _| Ok(()))?;
    Ok(SfaSegmentMetadataScan {
        header: raw.header,
        frame_count: raw.frame_count,
        append_offset: raw.append_offset,
        torn_tail_bytes: raw.torn_tail_bytes,
        first_empty_payload_fsn: raw.first_empty_payload_fsn,
    })
}

#[cfg(test)]
pub(crate) fn scan_segment_bytes(bytes: &[u8]) -> Result<SfaSegmentScan, SfaSegmentError> {
    let mut frames = Vec::new();
    let raw = scan_segment_bytes_inner(bytes, |fsn, offset, _payload_len, payload| {
        frames.push(SfaFrame {
            fsn,
            offset,
            payload: payload.to_vec(),
        });
        Ok(())
    })?;

    Ok(SfaSegmentScan {
        header: raw.header,
        frames,
        append_offset: raw.append_offset,
        torn_tail_bytes: raw.torn_tail_bytes,
    })
}

struct RawSegmentScan {
    header: SfaSegmentHeader,
    frame_count: u64,
    append_offset: u64,
    torn_tail_bytes: u64,
    first_empty_payload_fsn: Option<u64>,
}

fn scan_segment_bytes_inner(
    bytes: &[u8],
    mut on_frame: impl FnMut(u64, u64, usize, &[u8]) -> Result<(), SfaSegmentError>,
) -> Result<RawSegmentScan, SfaSegmentError> {
    if bytes.len() < HEADER_SIZE {
        return Err(SfaSegmentError::FileTooShort { size: bytes.len() });
    }

    let magic = read_u32(bytes, 0);
    if magic != FILE_MAGIC {
        return Err(SfaSegmentError::BadMagic { actual: magic });
    }
    let version = bytes[4];
    if version != VERSION {
        return Err(SfaSegmentError::UnsupportedVersion { actual: version });
    }
    let flags = bytes[5];
    if flags != 0 {
        return Err(SfaSegmentError::NonZeroFlags { actual: flags });
    }
    let reserved = u16::from_le_bytes([bytes[6], bytes[7]]);
    if reserved != 0 {
        return Err(SfaSegmentError::NonZeroReserved { actual: reserved });
    }

    let base_seq_i64 = read_i64(bytes, 8);
    if base_seq_i64 < 0 {
        return Err(SfaSegmentError::NegativeBaseSeq {
            actual: base_seq_i64,
        });
    }
    let header = SfaSegmentHeader {
        base_seq: base_seq_i64 as u64,
        created_us: read_u64(bytes, 16),
    };

    let mut frame_count = 0u64;
    let mut first_empty_payload_fsn = None;
    let mut pos = HEADER_SIZE;
    while pos + FRAME_HEADER_SIZE <= bytes.len() {
        let crc_read = read_u32(bytes, pos);
        let payload_len_i32 = read_i32(bytes, pos + 4);
        if payload_len_i32 < 0 {
            break;
        }

        let payload_len = payload_len_i32 as usize;
        let frame_end = match pos
            .checked_add(FRAME_HEADER_SIZE)
            .and_then(|value| value.checked_add(payload_len))
        {
            Some(value) if value <= bytes.len() => value,
            _ => break,
        };

        let crc_calc = crc32c_update(0, &bytes[pos + 4..frame_end]);
        if crc_calc != crc_read {
            break;
        }

        let fsn = header
            .base_seq
            .checked_add(frame_count)
            .ok_or(SfaSegmentError::OffsetOverflow)?;
        let payload = &bytes[pos + FRAME_HEADER_SIZE..frame_end];
        if payload_len == 0 && first_empty_payload_fsn.is_none() {
            first_empty_payload_fsn = Some(fsn);
        }
        on_frame(fsn, pos as u64, payload_len, payload)?;
        frame_count = frame_count
            .checked_add(1)
            .ok_or(SfaSegmentError::OffsetOverflow)?;
        pos = frame_end;
    }

    Ok(RawSegmentScan {
        header,
        frame_count,
        append_offset: pos as u64,
        torn_tail_bytes: detect_torn_tail(bytes, pos),
        first_empty_payload_fsn,
    })
}

fn encode_header(header: SfaSegmentHeader) -> [u8; HEADER_SIZE] {
    let mut bytes = [0u8; HEADER_SIZE];
    bytes[..4].copy_from_slice(&FILE_MAGIC.to_le_bytes());
    bytes[4] = VERSION;
    bytes[5] = 0;
    bytes[6..8].copy_from_slice(&0u16.to_le_bytes());
    bytes[8..16].copy_from_slice(&header.base_seq.to_le_bytes());
    bytes[16..24].copy_from_slice(&header.created_us.to_le_bytes());
    bytes
}

fn validate_base_seq(base_seq: u64) -> Result<(), SfaSegmentError> {
    if base_seq > i64::MAX as u64 {
        Err(SfaSegmentError::BaseSeqTooLarge { base_seq })
    } else {
        Ok(())
    }
}

fn validate_new_segment_args(base_seq: u64, size_bytes: u64) -> Result<(), SfaSegmentError> {
    let min_size = (HEADER_SIZE + FRAME_HEADER_SIZE + 1) as u64;
    if size_bytes < min_size {
        return Err(SfaSegmentError::SizeTooSmall { size: size_bytes });
    }
    validate_base_seq(base_seq)
}

fn detect_torn_tail(bytes: &[u8], last_good: usize) -> u64 {
    if last_good >= bytes.len() {
        return 0;
    }
    let probe_len = FRAME_HEADER_SIZE.min(bytes.len() - last_good);
    if bytes[last_good..last_good + probe_len]
        .iter()
        .any(|byte| *byte != 0)
    {
        (bytes.len() - last_good) as u64
    } else {
        0
    }
}

fn crc32c_update(seed: u32, bytes: &[u8]) -> u32 {
    crc32c::crc32c_append(seed, bytes)
}

/// Reserve real disk blocks for the segment up front. A plain
/// `set_len`/`ftruncate` leaves the file sparse, so a later mmap'd
/// store faults with `SIGBUS` once the filesystem fills up. We return
/// `PreallocationUnsupported` rather than fall back to `set_len`.
#[cfg(target_os = "linux")]
fn reserve_segment_blocks(file: &File, size_bytes: u64) -> Result<(), SfaSegmentError> {
    use std::os::unix::io::AsRawFd;
    let len = libc::off_t::try_from(size_bytes).map_err(|_| {
        SfaSegmentError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "segment size exceeds off_t",
        ))
    })?;
    match unsafe { libc::posix_fallocate(file.as_raw_fd(), 0, len) } {
        0 => Ok(()),
        libc::EOPNOTSUPP | libc::ENOSYS => Err(SfaSegmentError::PreallocationUnsupported),
        errno => Err(SfaSegmentError::Io(io::Error::from_raw_os_error(errno))),
    }
}

#[cfg(target_os = "macos")]
fn reserve_segment_blocks(file: &File, size_bytes: u64) -> Result<(), SfaSegmentError> {
    use std::os::unix::io::AsRawFd;
    let len = libc::off_t::try_from(size_bytes).map_err(|_| {
        SfaSegmentError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "segment size exceeds off_t",
        ))
    })?;
    let fd = file.as_raw_fd();
    let mut store = libc::fstore_t {
        fst_flags: libc::F_ALLOCATECONTIG | libc::F_ALLOCATEALL,
        fst_posmode: libc::F_PEOFPOSMODE,
        fst_offset: 0,
        fst_length: len,
        fst_bytesalloc: 0,
    };
    let mut rc = unsafe { libc::fcntl(fd, libc::F_PREALLOCATE, &mut store) };
    if rc == -1 {
        // Retry without the contiguity constraint before giving up.
        store.fst_flags = libc::F_ALLOCATEALL;
        rc = unsafe { libc::fcntl(fd, libc::F_PREALLOCATE, &mut store) };
    }
    if rc == -1 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOTSUP) {
            return Err(SfaSegmentError::PreallocationUnsupported);
        }
        return Err(SfaSegmentError::Io(err));
    }
    // F_PREALLOCATE reserves blocks past EOF; set_len extends the logical size.
    file.set_len(size_bytes).map_err(SfaSegmentError::Io)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn reserve_segment_blocks(file: &File, size_bytes: u64) -> Result<(), SfaSegmentError> {
    file.set_len(size_bytes).map_err(SfaSegmentError::Io)
}

fn map_file_mut(file: &File, size_bytes: u64) -> Result<Arc<SfaSegmentMapping>, SfaSegmentError> {
    let len = usize::try_from(size_bytes)
        .map_err(|_| SfaSegmentError::SizeTooLargeForPlatform { size: size_bytes })?;
    // SAFETY: SFA slot locking prevents another client process from mutating
    // this segment while it is mapped by this queue. This module owns all writes
    // through the mapping and validates published offsets before reading bytes.
    unsafe {
        let mmap = MmapOptions::new()
            .len(len)
            .map_mut(file)
            .map_err(SfaSegmentError::Io)?;
        Ok(Arc::new(SfaSegmentMapping::new(mmap)))
    }
}

fn map_anon_mut(size_bytes: u64) -> Result<Arc<SfaSegmentMapping>, SfaSegmentError> {
    let len = usize::try_from(size_bytes)
        .map_err(|_| SfaSegmentError::SizeTooLargeForPlatform { size: size_bytes })?;
    let mmap = MmapMut::map_anon(len).map_err(SfaSegmentError::Io)?;
    Ok(Arc::new(SfaSegmentMapping::new(mmap)))
}

impl std::fmt::Debug for SfaSegmentMapping {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SfaSegmentMapping")
            .field("len", &self.len)
            .finish()
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_i32(bytes: &[u8], offset: usize) -> i32 {
    i32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_i64(bytes: &[u8], offset: usize) -> i64 {
    i64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use tempfile::TempDir;

    use super::*;

    const JAVA_TWO_FRAME_FIXTURE_HEX: &str =
        include_str!("../../tests/interop/qwp-ws-sfa/java-two-frame.sfa.hex");
    const JAVA_TWO_FRAME_TORN_TAIL_FIXTURE_HEX: &str =
        include_str!("../../tests/interop/qwp-ws-sfa/java-two-frame-torn-tail.sfa.hex");

    #[test]
    fn crc32c_matches_java_known_vector() {
        assert_eq!(crc32c_update(0, b""), 0);
        assert_eq!(crc32c_update(0, b"123456789"), 0xe306_9283);

        let mut chained = crc32c_update(0, b"123");
        chained = crc32c_update(chained, b"456");
        chained = crc32c_update(chained, b"789");
        assert_eq!(chained, 0xe306_9283);
    }

    #[test]
    fn scans_java_segment_header_and_frames_from_golden_bytes() {
        let fixture = java_two_frame_fixture();
        let scan = scan_segment_bytes(&fixture).unwrap();

        assert_eq!(
            scan.header,
            SfaSegmentHeader {
                base_seq: 42,
                created_us: 1_234_567_890_123,
            }
        );
        assert_eq!(fixture.len(), 64);
        assert_eq!(scan.append_offset, 50);
        assert_eq!(scan.torn_tail_bytes, 0);
        assert_eq!(
            scan.frames,
            vec![
                SfaFrame {
                    fsn: 42,
                    offset: 24,
                    payload: b"one".to_vec(),
                },
                SfaFrame {
                    fsn: 43,
                    offset: 35,
                    payload: b"two-two".to_vec(),
                },
            ]
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn create_reserves_real_disk_blocks_not_a_sparse_file() {
        use std::os::unix::fs::MetadataExt;

        let dir = TempDir::new().unwrap();
        let path = initial_segment_path(dir.path());
        let size_bytes: u64 = 1 << 20;
        let _segment = SfaSegment::create(&path, 1, size_bytes, 1).unwrap();

        let meta = fs::metadata(&path).unwrap();
        assert_eq!(meta.len(), size_bytes);
        // An `ftruncate`-only file is sparse and reports near-zero allocated
        // blocks; block reservation backs the whole logical size.
        assert!(
            meta.blocks() * 512 >= size_bytes,
            "segment file is sparse: {} allocated bytes for {size_bytes} logical bytes",
            meta.blocks() * 512,
        );
    }

    #[test]
    fn create_and_append_writes_java_compatible_bytes() {
        let dir = TempDir::new().unwrap();
        let path = initial_segment_path(dir.path());
        let mut segment = SfaSegment::create(&path, 42, 64, 1_234_567_890_123).unwrap();
        let fixture = java_two_frame_fixture();

        assert_eq!(segment.try_append(b"one").unwrap(), Some(24));
        assert_eq!(segment.try_append(b"two-two").unwrap(), Some(35));
        assert_eq!(segment.append_offset(), 50);
        assert_eq!(segment.frame_count(), 2);

        let bytes = fs::read(path).unwrap();
        assert_eq!(bytes, fixture);
    }

    #[test]
    fn create_memory_and_append_uses_same_segment_layout() {
        let mut segment = SfaSegment::create_memory(42, 64, 1_234_567_890_123).unwrap();

        assert_eq!(segment.path(), None);
        assert_eq!(segment.try_append(b"one").unwrap(), Some(24));
        assert_eq!(segment.try_append(b"two-two").unwrap(), Some(35));
        assert_eq!(segment.append_offset(), 50);
        assert_eq!(segment.frame_count(), 2);

        let scan = segment.mapping.with_full_slice(scan_segment_bytes).unwrap();
        assert_eq!(payloads(&scan), vec![b"one".to_vec(), b"two-two".to_vec()]);
        assert_eq!(scan.append_offset, 50);
        assert_eq!(scan.torn_tail_bytes, 0);
    }

    #[test]
    fn open_existing_recovers_append_cursor_from_valid_frames() {
        let dir = TempDir::new().unwrap();
        let path = initial_segment_path(dir.path());
        fs::write(&path, java_two_frame_fixture()).unwrap();

        let segment = SfaSegment::open_existing(&path).unwrap();

        assert_eq!(segment.header().base_seq, 42);
        assert_eq!(segment.append_offset(), 50);
        assert_eq!(segment.frame_count(), 2);
        assert_eq!(segment.torn_tail_bytes(), 0);
    }

    #[test]
    fn metadata_scan_counts_frames_without_payload_results() {
        let fixture = java_two_frame_fixture();
        let scan = scan_segment_metadata_bytes(&fixture).unwrap();

        assert_eq!(
            scan.header,
            SfaSegmentHeader {
                base_seq: 42,
                created_us: 1_234_567_890_123,
            }
        );
        assert_eq!(scan.frame_count, 2);
        assert_eq!(scan.append_offset, 50);
        assert_eq!(scan.torn_tail_bytes, 0);
        assert_eq!(scan.first_empty_payload_fsn, None);
    }

    #[test]
    fn scan_stops_at_crc_mismatch_and_reports_torn_tail() {
        let bytes = java_two_frame_torn_tail_fixture();

        let scan = scan_segment_bytes(&bytes).unwrap();

        assert_eq!(scan.frames.len(), 1);
        assert_eq!(scan.append_offset, 35);
        assert_eq!(scan.torn_tail_bytes, 29);
        assert_eq!(scan.frames[0].payload, b"one");
    }

    #[test]
    fn scan_treats_length_and_payload_without_crc_commit_as_torn() {
        let dir = TempDir::new().unwrap();
        let path = initial_segment_path(dir.path());
        let mut segment = SfaSegment::create(&path, 42, 80, 1_234_567_890_123).unwrap();
        assert_eq!(segment.try_append(b"one").unwrap(), Some(24));
        let torn_offset = segment.append_offset() as usize;
        drop(segment);

        let mut bytes = fs::read(&path).unwrap();
        bytes[torn_offset + 4..torn_offset + 8].copy_from_slice(&3u32.to_le_bytes());
        bytes[torn_offset + 8..torn_offset + 11].copy_from_slice(b"two");
        fs::write(&path, bytes).unwrap();

        let scan = scan_file(&path).unwrap();

        assert_eq!(payloads(&scan), vec![b"one".to_vec()]);
        assert_eq!(scan.append_offset, torn_offset as u64);
        assert_eq!(scan.torn_tail_bytes, 80 - torn_offset as u64);
    }

    #[test]
    fn clean_zero_tail_is_not_torn_tail() {
        let mut bytes = Vec::from(encode_header(SfaSegmentHeader {
            base_seq: 7,
            created_us: 11,
        }));
        bytes.resize(80, 0);

        let scan = scan_segment_bytes(&bytes).unwrap();

        assert!(scan.frames.is_empty());
        assert_eq!(scan.append_offset, HEADER_SIZE as u64);
        assert_eq!(scan.torn_tail_bytes, 0);
    }

    #[test]
    fn invalid_header_is_rejected() {
        assert!(matches!(
            scan_segment_bytes(&java_two_frame_fixture()[..HEADER_SIZE - 1]),
            Err(SfaSegmentError::FileTooShort { size }) if size == HEADER_SIZE - 1
        ));

        let mut bad_magic = java_two_frame_fixture();
        bad_magic[0] = 0;
        assert!(matches!(
            scan_segment_bytes(&bad_magic),
            Err(SfaSegmentError::BadMagic { .. })
        ));

        let mut bad_version = java_two_frame_fixture();
        bad_version[4] = 2;
        assert!(matches!(
            scan_segment_bytes(&bad_version),
            Err(SfaSegmentError::UnsupportedVersion { actual: 2 })
        ));

        let mut bad_flags = java_two_frame_fixture();
        bad_flags[5] = 1;
        assert!(matches!(
            scan_segment_bytes(&bad_flags),
            Err(SfaSegmentError::NonZeroFlags { actual: 1 })
        ));

        let mut bad_reserved = java_two_frame_fixture();
        bad_reserved[6..8].copy_from_slice(&2u16.to_le_bytes());
        assert!(matches!(
            scan_segment_bytes(&bad_reserved),
            Err(SfaSegmentError::NonZeroReserved { actual: 2 })
        ));

        let mut negative_base_seq = java_two_frame_fixture();
        negative_base_seq[15] = 0x80;
        assert!(matches!(
            scan_segment_bytes(&negative_base_seq),
            Err(SfaSegmentError::NegativeBaseSeq { actual }) if actual == i64::MIN + 42
        ));
    }

    #[test]
    fn create_rejects_base_seq_that_java_would_read_as_negative() {
        let dir = TempDir::new().unwrap();
        let path = initial_segment_path(dir.path());

        assert!(matches!(
            SfaSegment::create(&path, i64::MAX as u64 + 1, 64, 1),
            Err(SfaSegmentError::BaseSeqTooLarge { base_seq })
                if base_seq == i64::MAX as u64 + 1
        ));
    }

    #[test]
    fn segment_file_names_match_java_slot_convention() {
        let dir = Path::new("/tmp/qdb-sf/default");

        assert_eq!(
            initial_segment_path(dir),
            PathBuf::from("/tmp/qdb-sf/default/sf-initial.sfa")
        );
        assert_eq!(
            spare_segment_path(dir, 26),
            PathBuf::from("/tmp/qdb-sf/default/sf-000000000000001a.sfa")
        );
    }

    #[test]
    #[ignore = "requires QDB_JAVA_CLIENT_CORE or the local Java client checkout"]
    fn java_and_rust_read_each_others_segments() {
        let fixture = JavaSfaFixture::compile();
        let dir = TempDir::new().unwrap();

        let java_written = dir.path().join("java-written.sfa");
        fixture.run(&["write", java_written.to_str().unwrap()]);

        let scan = scan_file(&java_written).unwrap();
        assert_eq!(scan.header.base_seq, 42);
        assert!(scan.header.created_us > 0);
        assert_eq!(scan.append_offset, 50);
        assert_eq!(scan.torn_tail_bytes, 0);
        assert_eq!(payloads(&scan), vec![b"one".to_vec(), b"two-two".to_vec()]);

        let mut normalized_java_written = fs::read(&java_written).unwrap();
        normalize_created_us(&mut normalized_java_written);
        assert_eq!(normalized_java_written, java_two_frame_fixture());

        let rust_written = dir.path().join("rust-written.sfa");
        let mut segment = SfaSegment::create(&rust_written, 42, 64, 1_234_567_890_123).unwrap();
        segment.try_append(b"one").unwrap();
        segment.try_append(b"two-two").unwrap();
        drop(segment);

        let java_report = fixture.run(&["read", rust_written.to_str().unwrap()]);
        assert_report_contains(&java_report, "baseSeq=42");
        assert_report_contains(&java_report, "frameCount=2");
        assert_report_contains(&java_report, "publishedOffset=50");
        assert_report_contains(&java_report, "tornTailBytes=0");
        assert_report_contains(&java_report, "frame.0.offset=24");
        assert_report_contains(&java_report, "frame.0.payload=one");
        assert_report_contains(&java_report, "frame.1.offset=35");
        assert_report_contains(&java_report, "frame.1.payload=two-two");

        let java_torn = dir.path().join("java-torn.sfa");
        fixture.run(&["write", java_torn.to_str().unwrap()]);
        corrupt_second_payload_byte(&java_torn);
        let mut normalized_java_torn = fs::read(&java_torn).unwrap();
        normalize_created_us(&mut normalized_java_torn);
        assert_eq!(normalized_java_torn, java_two_frame_torn_tail_fixture());
        let scan = scan_file(&java_torn).unwrap();
        assert_eq!(scan.frames.len(), 1);
        assert_eq!(scan.append_offset, 35);
        assert_eq!(scan.torn_tail_bytes, 29);

        let rust_torn = dir.path().join("rust-torn.sfa");
        let mut segment = SfaSegment::create(&rust_torn, 42, 64, 1_234_567_890_123).unwrap();
        segment.try_append(b"one").unwrap();
        segment.try_append(b"two-two").unwrap();
        drop(segment);
        corrupt_second_payload_byte(&rust_torn);

        let java_report = fixture.run(&["read", rust_torn.to_str().unwrap()]);
        assert_report_contains(&java_report, "frameCount=1");
        assert_report_contains(&java_report, "publishedOffset=35");
        assert_report_contains(&java_report, "tornTailBytes=29");
        assert_report_contains(&java_report, "frame.0.payload=one");
    }

    #[test]
    #[ignore = "prints regenerated Java .sfa fixture hex"]
    fn print_java_sfa_fixture_hex() {
        let fixture = JavaSfaFixture::compile();
        let dir = TempDir::new().unwrap();

        let java_written = dir.path().join("java-two-frame.sfa");
        fixture.run(&["write", java_written.to_str().unwrap()]);
        let mut bytes = fs::read(&java_written).unwrap();
        normalize_created_us(&mut bytes);
        println!("java-two-frame.sfa.hex:\n{}", format_hex_fixture(&bytes));

        corrupt_second_payload_byte(&java_written);
        let mut bytes = fs::read(&java_written).unwrap();
        normalize_created_us(&mut bytes);
        println!(
            "java-two-frame-torn-tail.sfa.hex:\n{}",
            format_hex_fixture(&bytes)
        );
    }

    fn payloads(scan: &SfaSegmentScan) -> Vec<Vec<u8>> {
        scan.frames
            .iter()
            .map(|frame| frame.payload.clone())
            .collect()
    }

    fn corrupt_second_payload_byte(path: &Path) {
        let mut bytes = fs::read(path).unwrap();
        bytes[44] ^= 0x01;
        fs::write(path, bytes).unwrap();
    }

    fn normalize_created_us(bytes: &mut [u8]) {
        bytes[16..24].copy_from_slice(&1_234_567_890_123u64.to_le_bytes());
    }

    fn java_two_frame_fixture() -> Vec<u8> {
        decode_hex_fixture(JAVA_TWO_FRAME_FIXTURE_HEX)
    }

    fn java_two_frame_torn_tail_fixture() -> Vec<u8> {
        decode_hex_fixture(JAVA_TWO_FRAME_TORN_TAIL_FIXTURE_HEX)
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

    fn format_hex_fixture(bytes: &[u8]) -> String {
        let mut output = String::new();
        for (index, byte) in bytes.iter().enumerate() {
            if index > 0 && index % 24 == 0 {
                output.push('\n');
            }
            output.push_str(&format!("{byte:02x}"));
        }
        output
    }

    fn assert_report_contains(report: &str, expected: &str) {
        assert!(
            report.lines().any(|line| line == expected),
            "missing Java report line {expected:?} in:\n{report}"
        );
    }

    struct JavaSfaFixture {
        _work_dir: TempDir,
        classpath: String,
    }

    impl JavaSfaFixture {
        fn compile() -> Self {
            let core_dir = java_client_core_dir();
            let work_dir = TempDir::new().unwrap();
            let source_path = work_dir.path().join("SfaInteropHelper.java");
            fs::write(&source_path, JAVA_HELPER_SOURCE).unwrap();
            let classes_dir = work_dir.path().join("classes");
            fs::create_dir(&classes_dir).unwrap();

            let classpath = java_client_classpath(&core_dir, work_dir.path());
            let mmap_segment_source = core_dir
                .join("src/main/java")
                .join("io/questdb/client/cutlass/qwp/client/sf/cursor/MmapSegment.java");
            run_command(
                Command::new("javac")
                    .arg("-d")
                    .arg(&classes_dir)
                    .arg("-cp")
                    .arg(&classpath)
                    .arg(&source_path)
                    .arg(mmap_segment_source),
            );

            let separator = if cfg!(windows) { ";" } else { ":" };
            let classpath = format!("{}{}{}", classes_dir.display(), separator, classpath);
            Self {
                _work_dir: work_dir,
                classpath,
            }
        }

        fn run(&self, args: &[&str]) -> String {
            let mut command = Command::new("java");
            command.arg("-cp").arg(&self.classpath);
            command.arg("SfaInteropHelper");
            command.args(args);
            run_command(&mut command)
        }
    }

    fn java_client_core_dir() -> PathBuf {
        env::var_os("QDB_JAVA_CLIENT_CORE")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from("/home/jara/devel/oss/questdb-arrays/java-questdb-client/core")
            })
    }

    fn java_client_classpath(core_dir: &Path, work_dir: &Path) -> String {
        let target_classes = core_dir.join("target/classes");
        assert!(
            target_classes.exists(),
            "Java client target/classes missing at {}; run mvn -f {}/pom.xml test-compile or set QDB_JAVA_CLIENT_CORE",
            target_classes.display(),
            core_dir.display()
        );

        let separator = if cfg!(windows) { ";" } else { ":" };
        if let Some(extra) = env::var_os("QDB_JAVA_CLIENT_CLASSPATH") {
            return format!(
                "{}{}{}",
                target_classes.display(),
                separator,
                PathBuf::from(extra).display()
            );
        }

        let cp_file = work_dir.join("java-client-classpath.txt");
        run_command(
            Command::new("mvn")
                .arg("-q")
                .arg("-f")
                .arg(core_dir.join("pom.xml"))
                .arg("dependency:build-classpath")
                .arg(format!("-Dmdep.outputFile={}", cp_file.display())),
        );
        let dependency_cp = fs::read_to_string(cp_file).unwrap();
        let dependency_cp = dependency_cp.trim();
        if dependency_cp.is_empty() {
            target_classes.display().to_string()
        } else {
            format!("{}{}{}", target_classes.display(), separator, dependency_cp)
        }
    }

    fn run_command(command: &mut Command) -> String {
        let output = command.output().unwrap_or_else(|err| {
            panic!("failed to run command {command:?}: {err}");
        });
        if !output.status.success() {
            panic!(
                "command failed: {command:?}\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        String::from_utf8(output.stdout).unwrap()
    }

    const JAVA_HELPER_SOURCE: &str = r#"
import io.questdb.client.cutlass.qwp.client.sf.cursor.MmapSegment;
import io.questdb.client.std.MemoryTag;
import io.questdb.client.std.Unsafe;

import java.nio.charset.StandardCharsets;

public final class SfaInteropHelper {
    private static final byte[][] PAYLOADS = new byte[][] {
            "one".getBytes(StandardCharsets.UTF_8),
            "two-two".getBytes(StandardCharsets.UTF_8)
    };

    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            throw new IllegalArgumentException("usage: SfaInteropHelper <write|read> <path>");
        }
        if ("write".equals(args[0])) {
            write(args[1]);
        } else if ("read".equals(args[0])) {
            read(args[1]);
        } else {
            throw new IllegalArgumentException("unknown command: " + args[0]);
        }
    }

    private static void write(String path) {
        MmapSegment segment = MmapSegment.create(path, 42L, 64L);
        try {
            for (byte[] payload : PAYLOADS) {
                append(segment, payload);
            }
            printSegment(segment);
        } finally {
            segment.close();
        }
    }

    private static void read(String path) {
        MmapSegment segment = MmapSegment.openExisting(path);
        try {
            printSegment(segment);
            long offset = 24L;
            long published = segment.publishedOffset();
            int index = 0;
            while (offset + 8L <= published) {
                int payloadLen = Unsafe.getUnsafe().getInt(segment.address() + offset + 4L);
                byte[] payload = new byte[payloadLen];
                for (int i = 0; i < payloadLen; i++) {
                    payload[i] = Unsafe.getUnsafe().getByte(segment.address() + offset + 8L + i);
                }
                System.out.println("frame." + index + ".offset=" + offset);
                System.out.println("frame." + index + ".payload=" + new String(payload, StandardCharsets.UTF_8));
                offset += 8L + payloadLen;
                index++;
            }
        } finally {
            segment.close();
        }
    }

    private static void append(MmapSegment segment, byte[] payload) {
        long address = Unsafe.malloc(payload.length, MemoryTag.NATIVE_DEFAULT);
        try {
            for (int i = 0; i < payload.length; i++) {
                Unsafe.getUnsafe().putByte(address + i, payload[i]);
            }
            long offset = segment.tryAppend(address, payload.length);
            if (offset < 0) {
                throw new AssertionError("segment unexpectedly full");
            }
        } finally {
            Unsafe.free(address, payload.length, MemoryTag.NATIVE_DEFAULT);
        }
    }

    private static void printSegment(MmapSegment segment) {
        System.out.println("baseSeq=" + segment.baseSeq());
        System.out.println("frameCount=" + segment.frameCount());
        System.out.println("publishedOffset=" + segment.publishedOffset());
        System.out.println("tornTailBytes=" + segment.tornTailBytes());
    }
}
"#;
}
