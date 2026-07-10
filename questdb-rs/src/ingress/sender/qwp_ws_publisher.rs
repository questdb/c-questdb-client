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

//! Replay encoder for the pipelined QWP/WebSocket sender.

use super::qwp_ws_sfa_symbol_dict::{PersistedSymbolDict, PersistedSymbolDictMark};
use crate::error;
use crate::ingress::buffer::{
    QwpWsColumnarBuffer, QwpWsEncodeScratch, SymbolGlobalDict, SymbolGlobalDictMark,
};

pub(crate) struct QwpWsReplayEncoder {
    scratch: QwpWsEncodeScratch,
    global_dict: SymbolGlobalDict,
    version: u8,
    /// When true, each frame ships only the symbol ids new since the connection
    /// dict last grew (delta); the driver re-registers the whole dictionary via a
    /// catch-up frame on reconnect. When false, every frame re-ships the full
    /// dictionary from id 0. Set by the SFA store for memory-mode senders.
    delta_dict_enabled: bool,
    /// The slot's persisted symbol dictionary (file-mode SFA) for write-ahead:
    /// the symbols each frame introduces are appended here before the frame is
    /// published, so recovery / orphan-drain can rebuild the dictionary. `None`
    /// in memory mode / on open failure (dense fallback).
    persisted_symbol_dict: Option<PersistedSymbolDict>,
}

impl QwpWsReplayEncoder {
    pub(crate) fn new(version: u8) -> Self {
        Self {
            scratch: QwpWsEncodeScratch::new(),
            global_dict: SymbolGlobalDict::new(),
            version,
            delta_dict_enabled: false,
            persisted_symbol_dict: None,
        }
    }

    /// Enables delta symbol-dict encoding (memory-mode SFA). Must be kept in
    /// lockstep with the driver's catch-up mirror.
    pub(crate) fn set_delta_dict_enabled(&mut self, enabled: bool) {
        self.delta_dict_enabled = enabled;
    }

    /// Installs the slot's persisted symbol dictionary for file-mode write-ahead.
    pub(crate) fn set_persisted_symbol_dict(&mut self, pd: Option<PersistedSymbolDict>) {
        self.persisted_symbol_dict = pd;
    }

    /// Seeds the connection dict from a recovered persisted side-file so newly
    /// ingested symbols continue above the recovered ids (rather than colliding
    /// with them at 0). File-mode recovery / orphan-drain only.
    pub(crate) fn seed_global_dict(&mut self, entries: &[u8], count: u32) -> crate::Result<()> {
        self.global_dict.seed(entries, count)
    }

    /// Releases the connection dictionary this (row) encoder interned at connect.
    /// A column sender forces async connect, which seeds the recovered dictionary
    /// into this encoder as a synchronous validator -- but the column backend uses
    /// its own dictionary and never touches this encoder, so the seeded copy (up to
    /// one full dictionary) is dead weight for the connection's life. Called by the
    /// column sender once it has claimed the side-file.
    pub(crate) fn release_dormant_dict(&mut self) {
        self.global_dict = SymbolGlobalDict::new();
    }

    /// Appends the symbols `[from_id, next_id)` this frame introduced to the
    /// persisted side-file. No-op in memory mode (no side-file).
    fn persist_new_symbols(&mut self, from_id: u64) -> crate::Result<()> {
        let Self {
            global_dict,
            persisted_symbol_dict,
            ..
        } = self;
        let Some(pd) = persisted_symbol_dict.as_mut() else {
            return Ok(());
        };
        // Gather the frame's new symbols, then write them ahead in one batched
        // write_all rather than one alloc + one write() syscall per symbol.
        let mut new_symbols: Vec<&[u8]> = Vec::new();
        for id in from_id..global_dict.next_id() {
            let bytes = global_dict.entry(id).ok_or_else(|| {
                error::fmt!(
                    SocketError,
                    "internal: missing symbol id {} for persistence",
                    id
                )
            })?;
            new_symbols.push(bytes);
        }
        pd.append_symbols(&new_symbols)
            .map_err(|e| error::fmt!(SocketError, "could not persist symbols: {}", e))?;
        Ok(())
    }

    fn encode_to_scratch(&mut self, buffer: &QwpWsColumnarBuffer) -> crate::Result<()> {
        if buffer.is_empty() {
            return Err(error::fmt!(
                InvalidApiCall,
                "Cannot submit an empty QWP/WebSocket buffer."
            ));
        }
        buffer.encode_ws_replay_message_with_defer(
            &mut self.scratch,
            &mut self.global_dict,
            self.version,
            false,
            self.delta_dict_enabled,
        )?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn encode(&mut self, buffer: &QwpWsColumnarBuffer) -> crate::Result<&[u8]> {
        self.encode_to_scratch(buffer)?;
        Ok(&self.scratch.message)
    }

    /// Rolls the connection dict and its persisted side-file back to the marks
    /// taken before a frame was encoded, discarding any symbols that frame
    /// introduced. If the side-file truncate fails (a failing disk),
    /// [`PersistedSymbolDict::rollback`] poisons the on-disk file (recovery
    /// starts fresh) and the handle is dropped so this slot stops persisting --
    /// the side-file must never linger ahead of the in-memory dictionary and the
    /// driver's send mirror. Dropping the handle also disables delta encoding
    /// (falls back to dense, self-sufficient frames) so subsequent frames stay
    /// crash-recoverable without the side-file. Mirrors
    /// `SfaColumnBackend::rollback_frame`.
    fn rollback_frame(
        &mut self,
        global_dict_mark: SymbolGlobalDictMark,
        pd_mark: Option<PersistedSymbolDictMark>,
    ) {
        self.global_dict.rollback(global_dict_mark);
        if let Some(mark) = pd_mark {
            let truncate_failed = self
                .persisted_symbol_dict
                .as_mut()
                .is_some_and(|pd| pd.rollback(mark).is_err());
            if truncate_failed {
                self.persisted_symbol_dict = None;
                self.delta_dict_enabled = false;
            }
        }
    }

    /// Encodes `buffer` into the scratch message and write-aheads the symbols it
    /// introduces, returning the rollback marks so a *later* publish failure can
    /// undo the dict/side-file advance. On any encode / size / persist error the
    /// dictionary and side-file are rolled back here and the error is returned.
    ///
    /// Write-ahead ordering: the frame's new symbols are persisted before it is
    /// published, so a recovered / orphan-drained slot can rebuild the dictionary
    /// its (non-self-sufficient) delta frame references. No-op in memory mode.
    fn encode_and_persist(
        &mut self,
        buffer: &QwpWsColumnarBuffer,
        max_buf_size: usize,
    ) -> crate::Result<(SymbolGlobalDictMark, Option<PersistedSymbolDictMark>)> {
        let global_dict_mark = self.global_dict.mark();
        let dict_len_before = self.global_dict.next_id();
        let pd_mark = self.persisted_symbol_dict.as_ref().map(|pd| pd.mark());
        if let Err(err) = self.encode_to_scratch(buffer) {
            self.rollback_frame(global_dict_mark, pd_mark);
            return Err(err);
        }
        let encoded_len = self.scratch.message.len();
        if encoded_len > max_buf_size {
            self.rollback_frame(global_dict_mark, pd_mark);
            return Err(qwp_ws_encoded_message_size_error(encoded_len, max_buf_size));
        }
        if let Err(err) = self.persist_new_symbols(dict_len_before) {
            self.rollback_frame(global_dict_mark, pd_mark);
            return Err(err);
        }
        Ok((global_dict_mark, pd_mark))
    }

    #[cfg(test)]
    pub(crate) fn encode_with_max_size(
        &mut self,
        buffer: &QwpWsColumnarBuffer,
        max_buf_size: usize,
    ) -> crate::Result<&[u8]> {
        self.encode_and_persist(buffer, max_buf_size)?;
        Ok(&self.scratch.message)
    }

    /// Encodes `buffer`, write-aheads its new symbols, then hands the payload to
    /// `publish`. **If `publish` fails, the connection dict and side-file are
    /// rolled back** so the aborted frame's symbol ids are freed and reused by the
    /// next frame.
    ///
    /// This rollback is load-bearing: `publish` can fail transiently and
    /// recoverably (e.g. `SubmitTimedOut` under back-pressure while the SFA queue
    /// is full), leaving the sender open for the caller to retry. Without the
    /// rollback the dict would be left one step ahead of the driver's send mirror
    /// (which only advances on a successful send), so the next frame's
    /// `delta_start` would outrun the mirror and the torn-dict guard would mark
    /// the whole slot terminal, losing all queued data. Mirrors the column
    /// backend's `SfaColumnBackend::publish_chunk_sfa`.
    pub(crate) fn encode_and_publish(
        &mut self,
        buffer: &QwpWsColumnarBuffer,
        max_buf_size: usize,
        publish: impl FnOnce(&[u8]) -> crate::Result<u64>,
    ) -> crate::Result<u64> {
        let (global_dict_mark, pd_mark) = self.encode_and_persist(buffer, max_buf_size)?;
        match publish(&self.scratch.message) {
            Ok(fsn) => Ok(fsn),
            Err(err) => {
                self.rollback_frame(global_dict_mark, pd_mark);
                Err(err)
            }
        }
    }
}

pub(crate) fn qwp_ws_encoded_message_size_error(
    encoded_len: usize,
    max_buf_size: usize,
) -> crate::Error {
    error::fmt!(
        InvalidApiCall,
        "Could not flush buffer: QWP/WebSocket encoded message size of {} exceeds maximum configured allowed size of {} bytes.",
        encoded_len,
        max_buf_size
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ErrorCode;

    fn one_symbol_buffer(symbol: &str) -> QwpWsColumnarBuffer {
        let mut buffer = QwpWsColumnarBuffer::new(127);
        buffer
            .table("trades")
            .unwrap()
            .symbol("sym", symbol)
            .unwrap()
            .at_now()
            .unwrap();
        buffer
    }

    #[test]
    fn file_mode_side_file_rollback_failure_drops_handle_and_disables_delta() {
        // When the slot's persisted side-file cannot be rolled back (a failing
        // disk), the encoder must drop the side-file handle AND disable delta so
        // subsequent frames fall back to dense (self-sufficient) encoding -- a
        // delta frame the poisoned/desynced side-file can no longer rebuild on
        // recovery would strand the queued data at the send loop's torn-dict guard.
        // Injected via the side-file's fail-next-append-cleanup hook, which poisons
        // the handle so the write-ahead append fails and the ensuing rollback fails
        // too, exercising `rollback_frame`'s truncate-failed branch. (The only other
        // publisher test runs in memory mode, so this `Some(pd_mark)` branch was
        // otherwise unexercised.)
        let dir = tempfile::tempdir().unwrap();
        let mut pd = PersistedSymbolDict::open(dir.path()).unwrap();
        pd.arm_fail_next_append_cleanup();

        let mut encoder = QwpWsReplayEncoder::new(1);
        encoder.set_delta_dict_enabled(true);
        encoder.set_persisted_symbol_dict(Some(pd));

        // The frame interns a new symbol, so write-ahead appends it -- which the
        // armed hook fails, poisoning the side-file and failing the rollback.
        let err = encoder
            .encode_and_publish(&one_symbol_buffer("alpha"), usize::MAX, |_payload| Ok(1))
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::SocketError);
        assert!(err.msg().contains("persist"), "{err}");

        assert!(
            encoder.persisted_symbol_dict.is_none(),
            "a failed side-file rollback must drop the handle"
        );
        assert!(
            !encoder.delta_dict_enabled,
            "dropping the side-file must disable delta so frames go dense"
        );
    }

    #[test]
    fn replay_encoder_max_size_accounts_for_connection_global_symbol_prefix() {
        let mut encoder = QwpWsReplayEncoder::new(1);
        for idx in 0..130 {
            let seed = one_symbol_buffer(format!("seed{idx}").as_str());
            encoder.encode_with_max_size(&seed, usize::MAX).unwrap();
        }
        let seeded_symbols = encoder.global_dict.len();

        let buffer = one_symbol_buffer("fresh");
        let local_hint = buffer.len();
        let err = encoder
            .encode_with_max_size(&buffer, local_hint)
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert!(err.msg().contains("QWP/WebSocket encoded message size"));
        assert_eq!(encoder.global_dict.len(), seeded_symbols);

        let encoded_len = encoder
            .encode_with_max_size(&buffer, usize::MAX)
            .unwrap()
            .len();
        assert!(encoded_len > local_hint);
        assert_eq!(encoder.global_dict.len(), seeded_symbols + 1);
    }

    #[test]
    fn encode_and_publish_rolls_back_dict_when_publish_fails() {
        // Regression for the delta-mode publish-failure desync: a transient,
        // recoverable publish failure (e.g. `SubmitTimedOut` back-pressure) must
        // roll the connection dict back so the aborted frame's symbol id is reused
        // by the next frame. Otherwise the dict runs one id ahead of the driver's
        // send mirror (which only advances on a successful send), and the next
        // frame's `delta_start` trips the torn-dict guard -> terminal -> all queued
        // data lost.
        let mut encoder = QwpWsReplayEncoder::new(1);
        encoder.set_delta_dict_enabled(true);

        // Frame 1 publishes successfully: interns "alpha" (id 0).
        let ok = encoder
            .encode_and_publish(&one_symbol_buffer("alpha"), usize::MAX, |_payload| Ok(7))
            .unwrap();
        assert_eq!(ok, 7);
        assert_eq!(encoder.global_dict.len(), 1);

        // Frame 2 introduces "beta" (would be id 1) but the publish fails. The dict
        // must roll back so "beta" is NOT retained.
        let err = encoder
            .encode_and_publish(&one_symbol_buffer("beta"), usize::MAX, |_payload| {
                Err(error::fmt!(SocketError, "simulated back-pressure timeout"))
            })
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::SocketError);
        assert_eq!(
            encoder.global_dict.len(),
            1,
            "a failed publish must roll the dict back so ids are reused, not skipped"
        );

        // The retry re-interns "beta" at the reused id 1 (no phantom gap), so the
        // next frame's delta stays in lockstep with the send mirror.
        encoder
            .encode_and_publish(&one_symbol_buffer("beta"), usize::MAX, |_payload| Ok(8))
            .unwrap();
        assert_eq!(encoder.global_dict.len(), 2);
    }

    #[test]
    fn release_dormant_dict_frees_the_seeded_connection_dictionary() {
        // A column sender forces async connect, which seeds the recovered dictionary
        // into this (row) encoder as a synchronous validator -- but the column
        // backend uses its own dictionary and never touches this encoder, so the
        // seeded copy is dead weight. release_dormant_dict frees it.
        let mut encoder = QwpWsReplayEncoder::new(1);
        encoder.set_delta_dict_enabled(true);
        // Two recovered entries: [len=3]"abc", [len=2]"xy".
        encoder
            .seed_global_dict(&[3, b'a', b'b', b'c', 2, b'x', b'y'], 2)
            .unwrap();
        assert_eq!(encoder.global_dict.len(), 2);

        encoder.release_dormant_dict();
        assert_eq!(
            encoder.global_dict.len(),
            0,
            "the dormant encoder's seeded dictionary must be freed"
        );
    }
}
