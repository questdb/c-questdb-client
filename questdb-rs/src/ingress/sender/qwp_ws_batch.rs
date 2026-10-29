/*******************************************************************************
 *     ___                  _   ____  ____
 *    / _ \ _   _  ___  ___| |_|  _ \| __ )
 *   | | | | | | |/ _ \/ __| __| | | |  _ \
 *   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
 *    \__\_\\__,_|\___||___/\__|____/|____/
 *
 *  Copyright (c) 2014-2019 Appsicle
 *  Copyright (c) 2019-2025 QuestDB
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

//! Bounded wire-only batching. The SF log retains every original frame until ACK.
use std::io::{self, Write};
use std::time::{Duration, Instant};

use crate::ingress::buffer::decode_qwp_varint;
use crate::ws::frame::{Opcode, encode_client_frame};

pub(super) const NETWORK_BYTES: usize = 64 * 1024;

/// Largest masked client frame header (64-bit length).
const FRAME_OVERHEAD: usize = 14;
const DEFER_COMMIT: u8 = 1;

struct Frame {
    end: usize,
    flags_at: usize,
    flags: u8,
    mask: u8,
    fsn: u64,
}

pub(super) struct QwpWsBatch {
    interval: Option<Duration>,
    row_limit: usize,
    byte_limit: usize,
    bytes: Vec<u8>,
    frames: Vec<Frame>,
    rows: usize,
    started: Option<Instant>,
    committed_through: Option<u64>,
}

impl QwpWsBatch {
    pub(super) fn new(interval: Option<Duration>, rows: usize, bytes: usize) -> Self {
        Self {
            interval,
            row_limit: rows,
            byte_limit: if interval.is_some() {
                bytes.max(1)
            } else {
                NETWORK_BYTES
            },
            bytes: Vec::new(),
            frames: Vec::new(),
            rows: 0,
            started: None,
            committed_through: None,
        }
    }

    pub(super) fn set_byte_limit(&mut self, limit: usize) {
        if self.interval.is_some() {
            self.byte_limit = limit.max(1);
        }
    }

    /// Ends the group before a stored split so an aborted split cannot hold an earlier commit.
    pub(super) fn full_before(&self, payload: &[u8]) -> bool {
        let Some(tail) = self.frames.last() else {
            return false;
        };
        self.bytes
            .len()
            .saturating_add(payload.len())
            .saturating_add(FRAME_OVERHEAD)
            > self.byte_limit
            || self.interval.is_some()
                && tail.flags & DEFER_COMMIT == 0
                && payload
                    .get(5)
                    .is_some_and(|flags| flags & DEFER_COMMIT != 0)
    }

    /// Copies/masks one complete message; returns whether the group must close.
    pub(super) fn append(&mut self, fsn: u64, payload: &[u8], mask: [u8; 4]) -> io::Result<bool> {
        if payload.len() < 12 || &payload[..4] != b"QWP1" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid QWP batch header",
            ));
        }
        self.bytes
            .try_reserve(payload.len().saturating_add(FRAME_OVERHEAD))
            .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
        self.frames
            .try_reserve(1)
            .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
        if self.interval.is_some()
            && let Some(tail) = self.frames.last()
        {
            self.bytes[tail.flags_at] = (tail.flags | DEFER_COMMIT) ^ tail.mask;
        }
        encode_client_frame(&mut self.bytes, Opcode::Binary, mask, payload);
        self.frames.push(Frame {
            end: self.bytes.len(),
            flags_at: self.bytes.len() - payload.len() + 5,
            flags: payload[5],
            mask: mask[1],
            fsn,
        });
        if self.interval.is_some() {
            self.started.get_or_insert_with(Instant::now);
        }
        let mut unknown_rows = false;
        if self.interval.is_some() && self.row_limit > 0 {
            match single_table_rows(payload) {
                Some(rows) => self.rows = self.rows.saturating_add(rows),
                // Multi-table or non-delta frames close conservatively. No decoding of
                // column data, and no accidental treatment of a frame as one row.
                None => unknown_rows = true,
            }
        }
        Ok(unknown_rows
            || self.bytes.len() >= self.byte_limit
            || self.row_limit > 0 && self.rows >= self.row_limit)
    }

    pub(super) fn should_flush(&self, force_through: Option<u64>) -> bool {
        let Some(tail) = self.frames.last() else {
            return false;
        };
        self.interval.is_none()
            || self
                .started
                .zip(self.interval)
                .is_some_and(|(start, interval)| start.elapsed() >= interval)
            || force_through.is_some_and(|fsn| {
                tail.fsn >= fsn && self.committed_through.is_none_or(|sent| sent < fsn)
            })
    }

    pub(super) fn flush(&mut self, stream: &mut impl Write) -> io::Result<()> {
        if self.frames.is_empty() {
            return Ok(());
        }
        let mut start = 0;
        let mut end = 0;
        for frame in &self.frames {
            if end > start && frame.end - start > NETWORK_BYTES {
                stream.write_all(&self.bytes[start..end])?;
                start = end;
            }
            end = frame.end;
        }
        stream.write_all(&self.bytes[start..end])?;
        stream.flush()?;
        if let Some(tail) = self.frames.last()
            && tail.flags & DEFER_COMMIT == 0
        {
            self.committed_through = Some(tail.fsn);
        }
        self.clear();
        Ok(())
    }

    pub(super) fn clear(&mut self) {
        self.bytes.clear();
        self.frames.clear();
        self.rows = 0;
        self.started = None;
    }

    pub(super) fn reset_connection(&mut self) {
        self.clear();
        self.committed_through = None;
    }
}

/// Read only the delta dictionary lengths and the first table's row count.
/// Multiple tables need a full payload walk, so they close the window instead.
fn single_table_rows(payload: &[u8]) -> Option<usize> {
    if payload.len() < 12 || payload[5] & 8 == 0 || payload[6..8] != [1, 0] {
        return None;
    }
    let (_, pos) = decode_qwp_varint(payload, 12)?;
    let (symbols, mut pos) = decode_qwp_varint(payload, pos)?;
    for _ in 0..symbols {
        let (len, next) = decode_qwp_varint(payload, pos)?;
        pos = next.checked_add(usize::try_from(len).ok()?)?;
        if pos > payload.len() {
            return None;
        }
    }
    let (name_len, next) = decode_qwp_varint(payload, pos)?;
    let pos = next.checked_add(usize::try_from(name_len).ok()?)?;
    let (rows, _) = decode_qwp_varint(payload, pos)?;
    usize::try_from(rows).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Writer(Vec<Vec<u8>>);
    impl Write for Writer {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.push(bytes.to_vec());
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    fn frame(rows: u8, flags: u8) -> Vec<u8> {
        let mut p = b"QWP1\x01\x08\x01\x00\x06\x00\x00\x00\x00\x00\x01t\x01\x00".to_vec();
        p[5] = flags;
        p[16] = rows;
        p
    }

    #[test]
    fn network_batch_preserves_frames_and_does_not_wait_for_more_rows() {
        let mut batch = QwpWsBatch::new(None, 0, 1);
        let original = frame(1, 8);
        batch.append(0, &original, [1, 2, 3, 4]).unwrap();
        assert!(batch.should_flush(None));
        batch.append(1, &original, [1, 2, 3, 4]).unwrap();
        let mut expected = Vec::new();
        for _ in 0..2 {
            encode_client_frame(&mut expected, Opcode::Binary, [1, 2, 3, 4], &original);
        }
        let mut writer = Writer::default();
        batch.flush(&mut writer).unwrap();
        assert_eq!(writer.0, [expected]);
    }

    #[test]
    fn row_threshold_counts_rows_not_frames_and_changes_only_wire_flags() {
        let mut batch = QwpWsBatch::new(Some(Duration::from_secs(60)), 5, 4096);
        let first = frame(2, 8);
        let last = frame(3, 8);
        assert!(!batch.append(0, &first, [0; 4]).unwrap());
        assert!(!batch.should_flush(None));
        assert!(batch.append(1, &last, [0; 4]).unwrap());
        let mut expected = Vec::new();
        let mut deferred = first.clone();
        deferred[5] |= 1;
        encode_client_frame(&mut expected, Opcode::Binary, [0; 4], &deferred);
        encode_client_frame(&mut expected, Opcode::Binary, [0; 4], &last);
        let mut writer = Writer::default();
        batch.flush(&mut writer).unwrap();
        assert_eq!(writer.0, [expected]);
        assert_eq!(first[5], 8);
    }

    #[test]
    fn wait_barrier_flushes_once_and_is_rearmed_after_reconnect() {
        let mut batch = QwpWsBatch::new(Some(Duration::from_secs(60)), 1000, 4096);
        batch.append(4, &frame(1, 8), [0; 4]).unwrap();
        assert!(!batch.should_flush(Some(5)));
        assert!(batch.should_flush(Some(4)));
        batch.flush(&mut Writer::default()).unwrap();
        batch.append(5, &frame(1, 8), [0; 4]).unwrap();
        assert!(
            !batch.should_flush(Some(4)),
            "old waits must not disable the next window"
        );
        batch.reset_connection();
        batch.append(4, &frame(1, 8), [0; 4]).unwrap();
        assert!(batch.should_flush(Some(4)));
    }

    #[test]
    fn idle_tail_expires_and_stored_defer_is_never_cleared() {
        let mut batch = QwpWsBatch::new(Some(Duration::from_millis(10)), 0, 4096);
        let original = frame(1, 9);
        batch.append(0, &original, [0; 4]).unwrap();
        batch.started = Some(Instant::now() - Duration::from_millis(10));
        assert!(batch.should_flush(None));
        let mut writer = Writer::default();
        batch.flush(&mut writer).unwrap();
        let mut expected = Vec::new();
        encode_client_frame(&mut expected, Opcode::Binary, [0; 4], &original);
        assert_eq!(writer.0, [expected]);
        assert!(batch.committed_through.is_none());
    }

    #[test]
    fn byte_limit_and_large_frames_keep_complete_messages() {
        let mut batch = QwpWsBatch::new(Some(Duration::from_secs(60)), 0, 48);
        batch.append(0, &frame(1, 8), [0; 4]).unwrap();
        assert!(batch.full_before(&frame(1, 8)));
        batch.reset_connection();
        let mut large = frame(1, 8);
        large.resize(70_000, 0);
        assert!(batch.append(0, &large, [0; 4]).unwrap());
        let mut writer = Writer::default();
        batch.flush(&mut writer).unwrap();
        assert_eq!(writer.0.len(), 1);
        assert_eq!(writer.0[0].len(), 70_014);
    }

    #[test]
    fn stored_split_group_starts_after_the_committing_tail_is_sent() {
        let mut batch = QwpWsBatch::new(Some(Duration::from_secs(60)), 0, 4096);
        let committing = frame(1, 8);
        let split = frame(1, 9);
        assert!(!batch.full_before(&split));
        batch.append(0, &committing, [0; 4]).unwrap();
        assert!(!batch.full_before(&committing));
        assert!(batch.full_before(&split));
        let mut writer = Writer::default();
        batch.flush(&mut writer).unwrap();
        let mut expected = Vec::new();
        encode_client_frame(&mut expected, Opcode::Binary, [0; 4], &committing);
        assert_eq!(writer.0, [expected]);
        assert_eq!(batch.committed_through, Some(0));
        batch.append(1, &split, [0; 4]).unwrap();
        assert!(!batch.full_before(&split));
        assert!(!batch.full_before(&committing));
    }

    #[test]
    fn network_only_batching_keeps_split_frames_in_one_write() {
        let mut batch = QwpWsBatch::new(None, 0, 0);
        batch.append(0, &frame(1, 8), [0; 4]).unwrap();
        assert!(!batch.full_before(&frame(1, 9)));
    }

    #[test]
    fn unknown_or_truncated_row_metadata_closes_conservatively() {
        let mut batch = QwpWsBatch::new(Some(Duration::from_secs(60)), 10, 4096);
        for payload in [frame(1, 8)[..12].to_vec(), frame(1, 0)] {
            assert!(batch.append(0, &payload, [0; 4]).unwrap());
            batch.reset_connection();
        }
        let mut multi = frame(1, 8);
        multi[6] = 2;
        assert!(single_table_rows(&multi).is_none());
    }

    #[test]
    fn failed_write_does_not_satisfy_commit_barrier() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut batch = QwpWsBatch::new(Some(Duration::from_secs(60)), 0, 4096);
        batch.append(0, &frame(1, 8), [0; 4]).unwrap();
        assert!(batch.flush(&mut Broken).is_err());
        assert!(batch.should_flush(Some(0)));
        assert_eq!(batch.frames.len(), 1);
        batch.reset_connection();
        assert!(batch.frames.is_empty());
    }

    #[test]
    fn partial_write_is_replayed_from_original_frames_after_reset() {
        struct Partial(bool);
        impl Write for Partial {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if std::mem::replace(&mut self.0, true) {
                    Err(io::ErrorKind::BrokenPipe.into())
                } else {
                    Ok(bytes.len().min(7))
                }
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let original = frame(1, 8);
        let mut batch = QwpWsBatch::new(Some(Duration::from_secs(60)), 0, 4096);
        batch.append(0, &original, [1, 2, 3, 4]).unwrap();
        batch.append(1, &original, [5, 6, 7, 8]).unwrap();
        assert!(batch.flush(&mut Partial(false)).is_err());
        assert!(batch.committed_through.is_none());
        assert_eq!(original[5], 8);

        batch.reset_connection();
        batch.set_byte_limit(24);
        assert!(batch.append(0, &original, [1, 2, 3, 4]).unwrap());
        let mut writer = Writer::default();
        batch.flush(&mut writer).unwrap();
        let mut expected = Vec::new();
        encode_client_frame(&mut expected, Opcode::Binary, [1, 2, 3, 4], &original);
        assert_eq!(writer.0, [expected]);
        assert_eq!(batch.committed_through, Some(0));
    }
}
