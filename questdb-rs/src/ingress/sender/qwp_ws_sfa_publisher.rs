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

//! Shared foreground transaction for pooled store-and-forward ingestion.

use super::qwp_ws_sfa_symbol_dict::{PersistedSymbolDict, PersistedSymbolDictMark};
use crate::ingress::buffer::{SymbolGlobalDict, SymbolGlobalDictMark};
use crate::{Result, error};

/// Result of atomically encoding and appending one store-and-forward frame.
#[derive(Debug)]
pub(crate) enum SfaPublishOutcome {
    Published(u64),
    /// The payload exceeded the effective cap before it reached the queue.
    TooLarge {
        encoded_len: usize,
        max_buf_size: usize,
    },
}

/// The one connection-scoped symbol namespace shared by every pooled encoder.
///
/// The persisted side-file is declared before the other state so its write handle
/// is closed as part of this foreground owner before the containing backend drops
/// the background runner and releases the slot lock.
struct SymbolPublishState {
    persisted: Option<PersistedSymbolDict>,
    global: SymbolGlobalDict,
    /// Delta mode is enabled exactly when the driver's catch-up mirror is enabled.
    /// If a side-file rollback fails this flips to dense mode; self-sufficient
    /// frames then keep the live slot recoverable without the poisoned side-file.
    delta_enabled: bool,
}

impl SymbolPublishState {
    fn new(delta_enabled: bool, persisted: Option<PersistedSymbolDict>) -> Self {
        Self {
            persisted,
            global: SymbolGlobalDict::new(),
            delta_enabled,
        }
    }

    fn rollback(
        &mut self,
        global_mark: SymbolGlobalDictMark,
        persisted_mark: Option<PersistedSymbolDictMark>,
    ) {
        self.global.rollback(global_mark);
        if let Some(mark) = persisted_mark {
            let truncate_failed = self
                .persisted
                .as_mut()
                .is_some_and(|persisted| persisted.rollback(mark).is_err());
            if truncate_failed {
                self.persisted = None;
                self.delta_enabled = false;
            }
        }
    }

    /// Write-ahead the symbols introduced by the current frame. The side-file
    /// precedes the queue append so every recoverable delta frame has a durable
    /// symbol prefix from which the driver can rebuild its catch-up mirror.
    fn persist_new_symbols(&mut self, from_id: u64) -> Result<()> {
        let Self {
            persisted, global, ..
        } = self;
        let Some(persisted) = persisted.as_mut() else {
            return Ok(());
        };
        let new_symbols = global.entries_from(from_id).ok_or_else(|| {
            error::fmt!(
                SocketError,
                "internal: missing symbol id {} for persistence",
                from_id
            )
        })?;
        persisted
            .append_symbols_iter(new_symbols)
            .map_err(|e| error::fmt!(SocketError, "could not persist symbols: {}", e))
    }
}

/// Retained foreground state for all pooled store-and-forward payload shapes.
/// Encoders write directly into `payload`; the queue borrows that same allocation.
pub(crate) struct SfaForegroundPublisher {
    symbols: SymbolPublishState,
    payload: Vec<u8>,
}

impl SfaForegroundPublisher {
    pub(crate) fn new(delta_enabled: bool, persisted: Option<PersistedSymbolDict>) -> Self {
        Self {
            symbols: SymbolPublishState::new(delta_enabled, persisted),
            payload: Vec::new(),
        }
    }

    /// Seeds the foreground namespace from a recovered side-file. The driver's
    /// mirror is seeded from the same byte region and count during connect.
    pub(crate) fn seed(&mut self, entries: &[u8], count: u32) -> Result<()> {
        self.symbols.global.seed(entries, count)
    }

    /// Encode, size-check, write-ahead, and append one frame as a single
    /// transaction. On any failure, the in-memory dictionary and persisted
    /// side-file return to their pre-encode marks. `encode` writes directly into
    /// the retained payload vector; `publish` borrows it without a copy.
    pub(crate) fn encode_persist_publish(
        &mut self,
        max_buf_size: usize,
        encode: impl FnOnce(&mut Vec<u8>, &mut SymbolGlobalDict, bool) -> Result<()>,
        publish: impl FnOnce(&[u8]) -> Result<u64>,
    ) -> Result<SfaPublishOutcome> {
        self.payload.clear();
        let global_mark = self.symbols.global.mark();
        let global_len_before = self.symbols.global.next_id();
        let persisted_mark = self.symbols.persisted.as_ref().map(|p| p.mark());

        if let Err(err) = encode(
            &mut self.payload,
            &mut self.symbols.global,
            self.symbols.delta_enabled,
        ) {
            self.symbols.rollback(global_mark, persisted_mark);
            return Err(err);
        }

        let encoded_len = self.payload.len();
        if encoded_len > max_buf_size {
            self.symbols.rollback(global_mark, persisted_mark);
            return Ok(SfaPublishOutcome::TooLarge {
                encoded_len,
                max_buf_size,
            });
        }

        if let Err(err) = self.symbols.persist_new_symbols(global_len_before) {
            self.symbols.rollback(global_mark, persisted_mark);
            return Err(err);
        }

        match publish(&self.payload) {
            Ok(fsn) => Ok(SfaPublishOutcome::Published(fsn)),
            Err(err) => {
                self.symbols.rollback(global_mark, persisted_mark);
                Err(err)
            }
        }
    }
}

#[cfg(all(test, feature = "sync-sender-qwp-ws"))]
mod tests {
    use super::*;
    use crate::ErrorCode;
    use crate::ingress::column_sender::{Chunk, encoder};
    use crate::ingress::sender::qwp_ws_sfa_catchup::SentDictMirror;

    fn one_symbol_chunk<'a>(
        codes: &'a [i32],
        offsets: &'a [i32],
        ts: &'a [i64],
        symbol: &'a [u8],
    ) -> Chunk<'a> {
        let mut chunk = Chunk::new("trades");
        chunk
            .symbol_i32("sym", codes, offsets, symbol, None)
            .unwrap();
        chunk.at_nanos(ts).unwrap();
        chunk
    }

    fn publish_chunk(
        foreground: &mut SfaForegroundPublisher,
        scratch: &mut encoder::EncodeScratch,
        chunk: &Chunk<'_>,
        max_buf_size: usize,
        publish: impl FnOnce(&[u8]) -> Result<u64>,
    ) -> Result<SfaPublishOutcome> {
        foreground.encode_persist_publish(
            max_buf_size,
            |payload, global, delta_enabled| {
                if delta_enabled {
                    encoder::encode_chunk_into(payload, chunk, global, scratch, false)
                } else {
                    encoder::encode_chunk_replay_into(payload, chunk, global, scratch)
                }
            },
            publish,
        )
    }

    fn read_varint(bytes: &[u8], pos: &mut usize) -> u64 {
        let mut value = 0u64;
        let mut shift = 0u32;
        loop {
            let byte = bytes[*pos];
            *pos += 1;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return value;
            }
            shift += 7;
        }
    }

    fn delta_prefix(payload: &[u8]) -> (u64, Vec<Vec<u8>>) {
        assert_eq!(&payload[..4], b"QWP1");
        let mut pos = 12;
        let start = read_varint(payload, &mut pos);
        let count = read_varint(payload, &mut pos) as usize;
        let mut symbols = Vec::with_capacity(count);
        for _ in 0..count {
            let len = read_varint(payload, &mut pos) as usize;
            symbols.push(payload[pos..pos + len].to_vec());
            pos += len;
        }
        (start, symbols)
    }

    fn assert_symbol_state(foreground: &SfaForegroundPublisher, expected: &[&[u8]]) {
        assert_eq!(foreground.symbols.global.next_id(), expected.len() as u64);
        for (id, symbol) in expected.iter().enumerate() {
            assert_eq!(foreground.symbols.global.entry(id as u64), Some(*symbol));
        }
        assert_eq!(
            foreground.symbols.persisted.as_ref().unwrap().size(),
            expected.len() as u32,
            "persisted and in-memory symbol counts must stay in lockstep"
        );
    }

    #[test]
    fn injected_transaction_failures_roll_back_memory_disk_and_driver_mirror() {
        let dir = tempfile::tempdir().unwrap();
        let persisted = PersistedSymbolDict::open(dir.path()).unwrap();
        let mut foreground = SfaForegroundPublisher::new(true, Some(persisted));
        let mut scratch = encoder::EncodeScratch::new();
        let mut mirror = SentDictMirror::new(true);
        let codes = [0i32];
        let offsets = [0i32, 2];

        // Establish id 0 in all three views: foreground, side-file, and the
        // driver's sent-frame mirror.
        let first = one_symbol_chunk(&codes, &offsets, &[1], b"S0");
        let mut first_payload = Vec::new();
        let outcome = publish_chunk(
            &mut foreground,
            &mut scratch,
            &first,
            usize::MAX,
            |payload| {
                first_payload.extend_from_slice(payload);
                Ok(1)
            },
        )
        .unwrap();
        assert!(matches!(outcome, SfaPublishOutcome::Published(1)));
        mirror.accumulate(&first_payload);
        assert_eq!(mirror.count(), 1);
        assert_symbol_state(&foreground, &[b"S0"]);

        // Encode failure after allocating id 1.
        let err = foreground
            .encode_persist_publish(
                usize::MAX,
                |_payload, global, _delta_enabled| {
                    global.intern(b"encode-failure")?;
                    Err(error::fmt!(InvalidApiCall, "injected encode failure"))
                },
                |_| panic!("an encode failure must not publish"),
            )
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert_symbol_state(&foreground, &[b"S0"]);
        assert_eq!(mirror.count(), 1);

        // Size failure after a real encoder allocates id 1.
        let second = one_symbol_chunk(&codes, &offsets, &[2], b"S1");
        let outcome = publish_chunk(&mut foreground, &mut scratch, &second, 1, |_| {
            panic!("an oversize frame must not publish")
        })
        .unwrap();
        assert!(matches!(outcome, SfaPublishOutcome::TooLarge { .. }));
        assert_symbol_state(&foreground, &[b"S0"]);
        assert_eq!(mirror.count(), 1);

        // Clean side-file append failure: no bytes reach the file and both marks
        // stay at id 1. Delta mode remains usable because rollback succeeded.
        foreground
            .symbols
            .persisted
            .as_mut()
            .unwrap()
            .arm_fail_next_append();
        let err = publish_chunk(&mut foreground, &mut scratch, &second, usize::MAX, |_| {
            panic!("a failed write-ahead must not publish")
        })
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::SocketError);
        assert_symbol_state(&foreground, &[b"S0"]);
        assert!(foreground.symbols.delta_enabled);
        assert_eq!(mirror.count(), 1);

        // Queue append failure after successful write-ahead must truncate the
        // side-file and free id 1 again. The driver never saw this frame.
        let err = publish_chunk(&mut foreground, &mut scratch, &second, usize::MAX, |_| {
            Err(error::fmt!(SocketError, "injected queue append failure"))
        })
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::SocketError);
        assert_symbol_state(&foreground, &[b"S0"]);
        assert_eq!(mirror.count(), 1);

        // The next success reuses id 1. Accumulating it must extend the driver
        // mirror without a gap, and reconnect catch-up must contain exactly the
        // foreground/side-file dictionary.
        let third = one_symbol_chunk(&codes, &offsets, &[3], b"S2");
        let mut third_payload = Vec::new();
        let outcome = publish_chunk(
            &mut foreground,
            &mut scratch,
            &third,
            usize::MAX,
            |payload| {
                third_payload.extend_from_slice(payload);
                Ok(2)
            },
        )
        .unwrap();
        assert!(matches!(outcome, SfaPublishOutcome::Published(2)));
        assert_eq!(delta_prefix(&third_payload), (1, vec![b"S2".to_vec()]));
        mirror.accumulate(&third_payload);
        assert_eq!(mirror.count(), 2);
        assert_symbol_state(&foreground, &[b"S0", b"S2"]);
        let catch_up = mirror.build_catch_up_frames(0, 1).unwrap();
        assert_eq!(catch_up.len(), 1);
        assert_eq!(
            delta_prefix(&catch_up[0]),
            (0, vec![b"S0".to_vec(), b"S2".to_vec()])
        );

        // Process-restart view: the persisted state contains the same two ids;
        // seeding both foreground and driver mirror from it makes the next frame
        // resume at id 2 and reconnect catch-up remains gap-free.
        drop(foreground);
        let reopened = PersistedSymbolDict::open(dir.path()).unwrap();
        assert_eq!(
            reopened.read_loaded_symbols(),
            vec![b"S0".to_vec(), b"S2".to_vec()]
        );
        let recovered_entries = reopened.loaded_entries().to_vec();
        let recovered_count = reopened.size();
        let mut recovered = SfaForegroundPublisher::new(true, Some(reopened));
        recovered.seed(&recovered_entries, recovered_count).unwrap();
        let mut recovered_mirror = SentDictMirror::new(true);
        recovered_mirror.seed(&recovered_entries, recovered_count);
        let fourth = one_symbol_chunk(&codes, &offsets, &[4], b"S3");
        let mut fourth_payload = Vec::new();
        publish_chunk(
            &mut recovered,
            &mut scratch,
            &fourth,
            usize::MAX,
            |payload| {
                fourth_payload.extend_from_slice(payload);
                Ok(3)
            },
        )
        .unwrap();
        assert_eq!(delta_prefix(&fourth_payload), (2, vec![b"S3".to_vec()]));
        recovered_mirror.accumulate(&fourth_payload);
        assert_eq!(recovered_mirror.count(), 3);
        let catch_up = recovered_mirror.build_catch_up_frames(0, 1).unwrap();
        assert_eq!(
            delta_prefix(&catch_up[0]),
            (0, vec![b"S0".to_vec(), b"S2".to_vec(), b"S3".to_vec()])
        );
    }

    #[test]
    fn column_sfa_side_file_rollback_failure_drops_handle_and_disables_delta() {
        let dir = tempfile::tempdir().unwrap();
        let mut persisted = PersistedSymbolDict::open(dir.path()).unwrap();
        persisted.arm_fail_next_append_cleanup();
        let mut foreground = SfaForegroundPublisher::new(true, Some(persisted));
        let mut scratch = encoder::EncodeScratch::new();
        let codes = [0i32];
        let offsets = [0i32, 5];
        let chunk = one_symbol_chunk(&codes, &offsets, &[1], b"alpha");

        let err = publish_chunk(&mut foreground, &mut scratch, &chunk, usize::MAX, |_| {
            panic!("a failed write-ahead must not publish")
        })
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::SocketError);
        assert!(err.msg().contains("persist"), "{err}");
        assert!(foreground.symbols.persisted.is_none());
        assert!(!foreground.symbols.delta_enabled);
        assert_eq!(foreground.symbols.global.next_id(), 0);
    }
}
