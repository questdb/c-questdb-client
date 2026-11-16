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

//! Bounded wire-only batching for background sends.
//!
//! Every QWP message keeps its own WebSocket frame, wire sequence and ACK;
//! only the socket writes are grouped, so the server sees exactly the frame
//! stream it would have seen with one write per frame. The SF log retains
//! every frame until the server ACKs it, so a group whose write fails is
//! recovered by the ordinary reconnect replay.
use std::io::{self, Write};

use crate::ws::frame::{Opcode, encode_client_frame};

/// Upper bound for one grouped socket write.
pub(super) const NETWORK_BYTES: usize = 64 * 1024;

/// Largest masked client frame header (64-bit length).
const FRAME_OVERHEAD: usize = 14;

pub(super) struct QwpWsBatch {
    bytes: Vec<u8>,
    frames: usize,
}

impl QwpWsBatch {
    pub(super) fn new() -> Self {
        Self {
            bytes: Vec::new(),
            frames: 0,
        }
    }

    /// True when the group already holds frames and `payload_len` more would
    /// push the write past [`NETWORK_BYTES`]. An empty group accepts any frame.
    pub(super) fn full_before(&self, payload_len: usize) -> bool {
        self.frames > 0
            && self
                .bytes
                .len()
                .saturating_add(payload_len)
                .saturating_add(FRAME_OVERHEAD)
                > NETWORK_BYTES
    }

    /// Encodes and masks one complete message into the group; returns whether
    /// the group has reached the write limit.
    pub(super) fn append(&mut self, payload: &[u8], mask: [u8; 4]) -> io::Result<bool> {
        self.bytes
            .try_reserve(payload.len().saturating_add(FRAME_OVERHEAD))
            .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
        encode_client_frame(&mut self.bytes, Opcode::Binary, mask, payload);
        self.frames += 1;
        Ok(self.bytes.len() >= NETWORK_BYTES)
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.frames == 0
    }

    /// Writes the whole group in one call and clears it. A failed write keeps
    /// the group so the caller's reconnect discards it together with the
    /// connection; the frames stay in the SF log for replay.
    pub(super) fn flush(&mut self, stream: &mut impl Write) -> io::Result<()> {
        if self.frames == 0 {
            return Ok(());
        }
        stream.write_all(&self.bytes)?;
        stream.flush()?;
        self.clear();
        Ok(())
    }

    pub(super) fn clear(&mut self) {
        self.bytes.clear();
        self.frames = 0;
    }
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

    fn frame(len: usize) -> Vec<u8> {
        let mut p = b"QWP1\x01\x08\x01\x00\x06\x00\x00\x00\x00\x00\x01t\x01\x00".to_vec();
        p.resize(len.max(p.len()), 0);
        p
    }

    #[test]
    fn grouped_frames_are_written_once_and_byte_for_byte() {
        let mut batch = QwpWsBatch::new();
        assert!(batch.is_empty());
        let first = frame(0);
        let second = frame(200);
        assert!(!batch.append(&first, [1, 2, 3, 4]).unwrap());
        assert!(!batch.append(&second, [5, 6, 7, 8]).unwrap());
        assert!(!batch.is_empty());
        let mut expected = Vec::new();
        encode_client_frame(&mut expected, Opcode::Binary, [1, 2, 3, 4], &first);
        encode_client_frame(&mut expected, Opcode::Binary, [5, 6, 7, 8], &second);
        let mut writer = Writer::default();
        batch.flush(&mut writer).unwrap();
        assert_eq!(writer.0, [expected]);
        assert!(batch.is_empty());
        batch.flush(&mut writer).unwrap();
        assert_eq!(writer.0.len(), 1, "an empty group writes nothing");
    }

    #[test]
    fn full_before_keeps_a_non_empty_group_under_the_network_limit() {
        let mut batch = QwpWsBatch::new();
        let large = frame(NETWORK_BYTES);
        assert!(
            !batch.full_before(large.len()),
            "an empty group takes any frame"
        );
        assert!(!batch.append(&frame(NETWORK_BYTES / 2), [0; 4]).unwrap());
        assert!(!batch.full_before(16));
        assert!(batch.full_before(NETWORK_BYTES / 2));
    }

    #[test]
    fn a_frame_at_the_limit_closes_the_group_and_is_written_whole() {
        let mut batch = QwpWsBatch::new();
        let large = frame(NETWORK_BYTES + 1);
        assert!(batch.append(&large, [0; 4]).unwrap());
        let mut writer = Writer::default();
        batch.flush(&mut writer).unwrap();
        assert_eq!(writer.0.len(), 1);
        assert_eq!(writer.0[0].len(), large.len() + FRAME_OVERHEAD);
    }

    #[test]
    fn failed_write_keeps_the_group_until_it_is_cleared() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut batch = QwpWsBatch::new();
        batch.append(&frame(0), [0; 4]).unwrap();
        assert!(batch.flush(&mut Broken).is_err());
        assert!(!batch.is_empty());
        batch.clear();
        assert!(batch.is_empty());
    }
}
