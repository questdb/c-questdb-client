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

//! Java-compatible `.sfa` Store-and-Forward segment codec.
//!
//! This is the narrow disk-format layer shared by the future QWP/WebSocket SF
//! queue. It intentionally knows nothing about receipts, WebSocket wire
//! sequences, or server rejection policy.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub(crate) const FILE_MAGIC: u32 = 0x3130_4653; // 'SF01' in little-endian bytes.
pub(crate) const VERSION: u8 = 1;
pub(crate) const HEADER_SIZE: usize = 24;
pub(crate) const FRAME_HEADER_SIZE: usize = 8;
pub(crate) const INITIAL_SEGMENT_FILE_NAME: &str = "sf-initial.sfa";

const CRC32C_POLY_REFLECTED: u32 = 0x82f6_3b78;

#[derive(Debug)]
pub(crate) enum SfaSegmentError {
    Io(io::Error),
    FileTooShort { size: usize },
    SizeTooSmall { size: u64 },
    BadMagic { actual: u32 },
    UnsupportedVersion { actual: u8 },
    NonZeroFlags { actual: u8 },
    NonZeroReserved { actual: u16 },
    NegativeBaseSeq { actual: i64 },
    BaseSeqTooLarge { base_seq: u64 },
    PayloadTooLarge { payload_len: usize },
    OffsetOverflow,
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
pub(crate) struct SfaFrame {
    pub(crate) fsn: u64,
    pub(crate) offset: u64,
    pub(crate) payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SfaSegmentScan {
    pub(crate) header: SfaSegmentHeader,
    pub(crate) frames: Vec<SfaFrame>,
    pub(crate) append_offset: u64,
    pub(crate) torn_tail_bytes: u64,
}

#[derive(Debug)]
pub(crate) struct SfaSegment {
    file: File,
    path: PathBuf,
    size_bytes: u64,
    header: SfaSegmentHeader,
    append_offset: u64,
    frame_count: u64,
    torn_tail_bytes: u64,
}

impl SfaSegment {
    pub(crate) fn create(
        path: impl AsRef<Path>,
        base_seq: u64,
        size_bytes: u64,
        created_us: u64,
    ) -> Result<Self, SfaSegmentError> {
        let min_size = (HEADER_SIZE + FRAME_HEADER_SIZE + 1) as u64;
        if size_bytes < min_size {
            return Err(SfaSegmentError::SizeTooSmall { size: size_bytes });
        }
        validate_base_seq(base_seq)?;

        let path = path.as_ref();
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(path)?;
        file.set_len(size_bytes)?;
        let header = SfaSegmentHeader {
            base_seq,
            created_us,
        };
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&encode_header(header))?;

        Ok(Self {
            file,
            path: path.to_path_buf(),
            size_bytes,
            header,
            append_offset: HEADER_SIZE as u64,
            frame_count: 0,
            torn_tail_bytes: 0,
        })
    }

    pub(crate) fn open_existing(path: impl AsRef<Path>) -> Result<Self, SfaSegmentError> {
        let path = path.as_ref();
        let bytes = fs::read(path)?;
        let scan = scan_segment_bytes(&bytes)?;
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        Ok(Self {
            file,
            path: path.to_path_buf(),
            size_bytes: bytes.len() as u64,
            header: scan.header,
            append_offset: scan.append_offset,
            frame_count: scan.frames.len() as u64,
            torn_tail_bytes: scan.torn_tail_bytes,
        })
    }

    pub(crate) fn try_append(&mut self, payload: &[u8]) -> Result<Option<u64>, SfaSegmentError> {
        if payload.len() > i32::MAX as usize {
            return Err(SfaSegmentError::PayloadTooLarge {
                payload_len: payload.len(),
            });
        }
        let frame_len = (FRAME_HEADER_SIZE as u64)
            .checked_add(payload.len() as u64)
            .ok_or(SfaSegmentError::OffsetOverflow)?;
        let frame_end = self
            .append_offset
            .checked_add(frame_len)
            .ok_or(SfaSegmentError::OffsetOverflow)?;
        if frame_end > self.size_bytes {
            return Ok(None);
        }

        let offset = self.append_offset;
        let payload_len = (payload.len() as u32).to_le_bytes();
        let crc = crc32c_update(crc32c_update(0, &payload_len), payload);
        self.file.seek(SeekFrom::Start(offset + 4))?;
        self.file.write_all(&payload_len)?;
        self.file.write_all(payload)?;
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(&crc.to_le_bytes())?;
        self.append_offset = frame_end;
        self.frame_count += 1;
        self.torn_tail_bytes = 0;
        Ok(Some(offset))
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn header(&self) -> SfaSegmentHeader {
        self.header
    }

    pub(crate) fn append_offset(&self) -> u64 {
        self.append_offset
    }

    pub(crate) fn frame_count(&self) -> u64 {
        self.frame_count
    }

    pub(crate) fn torn_tail_bytes(&self) -> u64 {
        self.torn_tail_bytes
    }
}

pub(crate) fn initial_segment_path(slot_dir: &Path) -> PathBuf {
    slot_dir.join(INITIAL_SEGMENT_FILE_NAME)
}

pub(crate) fn spare_segment_path(slot_dir: &Path, generation: u64) -> PathBuf {
    slot_dir.join(format!("sf-{generation:016x}.sfa"))
}

pub(crate) fn scan_file(path: impl AsRef<Path>) -> Result<SfaSegmentScan, SfaSegmentError> {
    let bytes = fs::read(path)?;
    scan_segment_bytes(&bytes)
}

pub(crate) fn scan_segment_bytes(bytes: &[u8]) -> Result<SfaSegmentScan, SfaSegmentError> {
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

    let mut frames = Vec::new();
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
            .checked_add(frames.len() as u64)
            .ok_or(SfaSegmentError::OffsetOverflow)?;
        frames.push(SfaFrame {
            fsn,
            offset: pos as u64,
            payload: bytes[pos + FRAME_HEADER_SIZE..frame_end].to_vec(),
        });
        pos = frame_end;
    }

    Ok(SfaSegmentScan {
        header,
        frames,
        append_offset: pos as u64,
        torn_tail_bytes: detect_torn_tail(bytes, pos),
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
    let mut crc = !seed;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            if crc & 1 == 1 {
                crc = (crc >> 1) ^ CRC32C_POLY_REFLECTED;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
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
