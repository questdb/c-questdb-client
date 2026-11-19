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
    QwpWsColumnarBuffer, QwpWsEncodeScratch, QwpWsFrameBlock, SymbolGlobalDict,
    SymbolGlobalDictMark,
};

pub(crate) struct QwpWsReplayEncoder {
    payload: Vec<u8>,
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
            payload: Vec::with_capacity(16 * 1024),
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

    /// Appends the symbols the side-file is still missing -- `[pd.size(),
    /// next_id)` -- to it. No-op in memory mode (no side-file).
    ///
    /// The start id comes from the SIDE-FILE's own tip rather than from the
    /// producer's id before this frame. The two are normally equal, but not
    /// after a recovery whose dictionary was rebuilt from the stored frames
    /// (`SfaFrameQueue::rebuild_recovered_dict_from_frames`): the producer
    /// resumes at `K'` while the file holds only its intact prefix `K < K'`.
    /// Anchoring to the producer would write id `K'` at file position `K` and
    /// permanently break the file's dense `id == position` invariant. See the
    /// twin note on `SymbolPublishState::persist_new_symbols`, which also argues
    /// why `frame_base_id` splits the write into two chunks rather than one.
    fn persist_new_symbols(&mut self, frame_base_id: u64) -> crate::Result<()> {
        let Self {
            global_dict,
            persisted_symbol_dict,
            ..
        } = self;
        let Some(pd) = persisted_symbol_dict.as_mut() else {
            return Ok(());
        };
        let file_tip = u64::from(pd.size());
        let next_id = global_dict.next_id();
        // Backfill first (empty on the steady state), then this frame's own
        // symbols -- two appends, so this frame's `delta_start` stays on a chunk
        // boundary. Clamped so a stray `frame_base_id` cannot reverse a range.
        let split = frame_base_id.clamp(file_tip, next_id);
        // Gather each run, then write it ahead in one batched write_all rather
        // than one alloc + one write() syscall per symbol.
        let mut new_symbols: Vec<&[u8]> = Vec::new();
        for (from, to) in [(file_tip, split), (split, next_id)] {
            if from >= to {
                continue;
            }
            new_symbols.clear();
            for id in from..to {
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
        }
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
            &mut self.payload,
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
        Ok(&self.payload)
    }

    /// Rolls the connection dict and its persisted side-file back to the marks
    /// taken before a frame was encoded, discarding any symbols that frame
    /// introduced. If the side-file truncate fails (a failing disk),
    /// [`PersistedSymbolDict::rollback`] poisons the on-disk file (recovery
    /// starts fresh) and the handle is dropped so this slot stops persisting --
    /// the side-file must never linger ahead of the in-memory dictionary and the
    /// driver's send mirror. Dropping the handle also disables delta encoding
    /// (falls back to dense, self-sufficient frames) so subsequent frames stay
    /// crash-recoverable without the side-file.
    ///
    /// The driver's send mirror lives on the I/O thread and cannot be reached from
    /// here, so it stays enabled while the foreground goes dense. That is safe: the
    /// dense frames this fallback emits base at id 0 and re-ship the whole dictionary,
    /// which the torn-dict guard accepts as an idempotent overlap of the mirrored
    /// prefix (see `guard_dict_not_torn` in `qwp_ws_driver`) and `accumulate` folds
    /// back into lockstep. Mirrors `SfaColumnBackend::rollback_frame`.
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
        // This frame's `delta_start`: the boundary that keeps its symbols in a
        // chunk of their own, distinct from the write-ahead anchor (the file tip).
        let frame_base_id = self.global_dict.next_id();
        let pd_mark = self.persisted_symbol_dict.as_ref().map(|pd| pd.mark());
        if let Err(err) = self.encode_to_scratch(buffer) {
            self.rollback_frame(global_dict_mark, pd_mark);
            return Err(err);
        }
        let encoded_len = self.payload.len();
        if encoded_len > max_buf_size {
            self.rollback_frame(global_dict_mark, pd_mark);
            return Err(qwp_ws_encoded_message_size_error(encoded_len, max_buf_size));
        }
        if let Err(err) = self.persist_new_symbols(frame_base_id) {
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
        Ok(&self.payload)
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
        match publish(&self.payload) {
            Ok(fsn) => Ok(fsn),
            Err(err) => {
                self.rollback_frame(global_dict_mark, pd_mark);
                Err(err)
            }
        }
    }

    /// Encodes one frame of a plan into the scratch message, refuses it when
    /// it is larger than `frame_cap`, and hands it to `publish`. The frames
    /// of a flush come in the order of the plan.
    ///
    /// The frame brings the symbols that its blocks use first, which enter
    /// the connection dictionary. **When the frame is not published, they
    /// are taken out again**, as [`Self::encode_and_publish`] does it and
    /// for its reason: a flush whose first frame finds no room leaves the
    /// sender open, and its dictionary must not be ahead of what was sent.
    ///
    /// Only for a sender in delta mode without a side-file, whose frames
    /// start their dictionary section at the connection dictionary's size.
    pub(crate) fn encode_and_publish_frame(
        &mut self,
        buffer: &QwpWsColumnarBuffer,
        blocks: &[QwpWsFrameBlock],
        defer_commit: bool,
        frame_cap: usize,
        publish: impl FnOnce(&[u8]) -> crate::Result<u64>,
    ) -> crate::Result<u64> {
        debug_assert!(self.delta_dict_enabled && self.persisted_symbol_dict.is_none());
        let global_dict_mark = self.global_dict.mark();
        let published = buffer
            .encode_ws_frame(
                blocks,
                &mut self.payload,
                &mut self.scratch,
                &mut self.global_dict,
                self.version,
                defer_commit,
            )
            .and_then(|()| {
                let encoded_len = self.payload.len();
                if encoded_len > frame_cap {
                    return Err(qwp_ws_encoded_message_size_error(encoded_len, frame_cap));
                }
                publish(&self.payload)
            });
        if published.is_err() {
            self.global_dict.rollback(global_dict_mark);
        }
        published
    }
}

pub(crate) fn qwp_ws_encoded_message_size_error(
    encoded_len: usize,
    max_buf_size: usize,
) -> crate::Error {
    error::fmt!(
        BatchTooLarge,
        "Could not flush buffer: QWP/WebSocket encoded message size of {} bytes exceeds the per-frame cap of {} bytes.",
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
    fn file_mode_write_ahead_heals_a_side_file_short_of_the_seeded_dictionary() {
        // The standalone row sender reaches the same frame-rebuilt recovery the
        // pooled core does -- `connect_qwp_ws_background_state` seeds this encoder
        // from `SfaFrameQueue::recovered_symbol_dict_entries` (which is the
        // side-file's prefix EXTENDED by the surviving frames' own delta sections)
        // and `connect_qwp_ws` then hands it the side-file handle, still at the
        // shorter prefix. So this path needs the same write-ahead anchoring as
        // `SymbolPublishState::persist_new_symbols`, and gets its own test because
        // it is a separate implementation.
        //
        // Anchoring to the producer's pre-frame id would append `bravo` (id 1) at
        // file position 0, aliasing id 0 onto it and losing `alpha` for good.
        let dir = tempfile::tempdir().unwrap();
        {
            let mut seed_file = PersistedSymbolDict::open(dir.path()).unwrap();
            seed_file.append_symbol(b"alpha").unwrap();
        }
        let pd = PersistedSymbolDict::open(dir.path()).unwrap();
        assert_eq!(pd.size(), 1, "the file holds the intact prefix only");

        let mut encoder = QwpWsReplayEncoder::new(1);
        encoder.set_delta_dict_enabled(true);
        // Seeded with TWO ids -- the frame-derived rebuild recovered `bravo` from a
        // surviving frame -- while the handle above is still at one.
        encoder
            .seed_global_dict(
                &[
                    5, b'a', b'l', b'p', b'h', b'a', 5, b'b', b'r', b'a', b'v', b'o',
                ],
                2,
            )
            .unwrap();
        encoder.set_persisted_symbol_dict(Some(pd));

        encoder
            .encode_and_publish(&one_symbol_buffer("charlie"), usize::MAX, |_payload| Ok(1))
            .unwrap();

        let pd = encoder.persisted_symbol_dict.take().expect("handle kept");
        assert_eq!(
            pd.size(),
            3,
            "the write-ahead must re-persist the rebuilt id 1 alongside the new id 2"
        );
        drop(pd);
        let reopened = PersistedSymbolDict::open(dir.path()).unwrap();
        assert_eq!(
            reopened.read_loaded_symbols(),
            vec![b"alpha".to_vec(), b"bravo".to_vec(), b"charlie".to_vec()],
            "entry i must be symbol id i"
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
        assert_eq!(err.code(), ErrorCode::BatchTooLarge);
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

    /// Encodes a frame of a plan as a flush does, and takes it in place of
    /// the queue.
    fn encode_frame(
        encoder: &mut QwpWsReplayEncoder,
        buffer: &QwpWsColumnarBuffer,
        blocks: &[QwpWsFrameBlock],
        defer_commit: bool,
        frame_cap: usize,
    ) -> crate::Result<Vec<u8>> {
        let mut frame = Vec::new();
        encoder.encode_and_publish_frame(buffer, blocks, defer_commit, frame_cap, |payload| {
            frame = payload.to_vec();
            Ok(0)
        })?;
        Ok(frame)
    }

    /// Rows without symbols, enough of them for several small frames.
    fn rows_without_symbols() -> QwpWsColumnarBuffer {
        let mut buffer = QwpWsColumnarBuffer::new(127);
        for id in 0..40 {
            buffer
                .table("readings")
                .unwrap()
                .column_i64("id", id)
                .unwrap()
                .at_now()
                .unwrap();
        }
        buffer
    }

    #[test]
    fn encode_frame_writes_a_frame_of_the_plan_for_its_connection() {
        // A connection of version 3 that has registered one symbol.
        let mut encoder = QwpWsReplayEncoder::new(3);
        encoder.set_delta_dict_enabled(true);
        encoder.encode(&one_symbol_buffer("a")).unwrap();

        let buffer = rows_without_symbols();
        let plan = buffer.plan_frames(128, 128).unwrap();
        assert!(plan.frames().count() > 2);
        let mut expected = Vec::new();
        let mut scratch = QwpWsEncodeScratch::new();
        for defer_commit in [true, false] {
            for blocks in plan.frames() {
                // The same frame for a connection of version 1 without symbols.
                buffer
                    .encode_ws_frame(
                        blocks,
                        &mut expected,
                        &mut scratch,
                        &mut SymbolGlobalDict::new(),
                        1,
                        defer_commit,
                    )
                    .unwrap();
                let frame =
                    encode_frame(&mut encoder, &buffer, blocks, defer_commit, usize::MAX).unwrap();
                assert_eq!(frame[..4], expected[..4]);
                assert_eq!((frame[4], expected[4]), (3, 1), "the version");
                assert_eq!(
                    frame[5..12],
                    expected[5..12],
                    "the flags, the table count and the payload length"
                );
                assert_eq!(
                    (&frame[12..14], &expected[12..14]),
                    (&[1, 0][..], &[0, 0][..]),
                    "the dictionary section: where it starts, and no new symbol"
                );
                assert_eq!(frame[14..], expected[14..], "the table blocks");
            }
        }
    }

    /// Rows with a new symbol each, enough of them for several small frames.
    fn rows_with_symbols() -> QwpWsColumnarBuffer {
        let mut buffer = QwpWsColumnarBuffer::new(127);
        for id in 0..40 {
            buffer
                .table("readings")
                .unwrap()
                .symbol("sym", format!("s{id}").as_str())
                .unwrap()
                .column_i64("id", id)
                .unwrap()
                .at_now()
                .unwrap();
        }
        buffer
    }

    #[test]
    fn a_frame_that_is_not_published_gives_its_symbols_back() {
        // A connection that has registered one symbol.
        let mut encoder = QwpWsReplayEncoder::new(1);
        encoder.set_delta_dict_enabled(true);
        encoder.encode(&one_symbol_buffer("known")).unwrap();
        let buffer = rows_with_symbols();
        let plan = buffer.plan_frames(128, 128).unwrap();
        let frames: Vec<&[QwpWsFrameBlock]> = plan.frames().collect();
        assert!(frames.len() > 2);

        // The queue does not take the frame.
        let err = encoder
            .encode_and_publish_frame(&buffer, frames[0], true, usize::MAX, |_payload| {
                Err(error::fmt!(SocketError, "no room"))
            })
            .unwrap_err();
        assert_eq!((err.code(), err.msg()), (ErrorCode::SocketError, "no room"));
        assert_eq!(encoder.global_dict.len(), 1);
        // The frame is above the cap.
        let err = encode_frame(&mut encoder, &buffer, frames[0], true, 20).unwrap_err();
        assert_eq!(err.code(), ErrorCode::BatchTooLarge);
        assert_eq!(encoder.global_dict.len(), 1);

        // A frame that is published keeps its symbols, and the next one
        // starts behind them.
        let first = encode_frame(&mut encoder, &buffer, frames[0], true, usize::MAX).unwrap();
        let brought = encoder.global_dict.len() - 1;
        assert!(brought > 0);
        assert_eq!((first[12], u64::from(first[13])), (1, brought));
        let second = encode_frame(&mut encoder, &buffer, frames[1], true, usize::MAX).unwrap();
        assert_eq!(u64::from(second[12]), 1 + brought);
        assert!(second[13] > 0);
        assert_eq!(
            encoder.global_dict.len(),
            1 + brought + u64::from(second[13])
        );
    }

    #[test]
    fn encode_frame_refuses_a_frame_above_the_cap() {
        let mut encoder = QwpWsReplayEncoder::new(1);
        encoder.set_delta_dict_enabled(true);
        let buffer = rows_without_symbols();
        let plan = buffer.plan_frames(128, 128).unwrap();
        let blocks = plan.frames().next().unwrap();
        let len = encode_frame(&mut encoder, &buffer, blocks, true, usize::MAX)
            .unwrap()
            .len();

        let at_the_cap = encode_frame(&mut encoder, &buffer, blocks, true, len).unwrap();
        assert_eq!(at_the_cap.len(), len);
        let err = encode_frame(&mut encoder, &buffer, blocks, true, len - 1).unwrap_err();
        assert_eq!(err.code(), ErrorCode::BatchTooLarge);
        assert_eq!(
            err.msg(),
            format!(
                "Could not flush buffer: QWP/WebSocket encoded message size of {len} bytes \
                 exceeds the per-frame cap of {} bytes.",
                len - 1
            )
        );
    }
}
