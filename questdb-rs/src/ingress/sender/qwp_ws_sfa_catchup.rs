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

//! Delta symbol-dictionary catch-up for store-and-forward replay.
//!
//! When the SFA sender delta-encodes symbol dictionaries, each stored frame
//! carries only the symbol ids it introduces — it is **not** self-sufficient.
//! On reconnect/failover the fresh server starts with an empty dictionary, so
//! before the queued delta frames replay, the whole dictionary must be
//! re-registered. [`SentDictMirror`] is the I/O-thread-local record of every
//! symbol the loop has sent, from which it builds the catch-up frame(s).
//!
//! The mirror is populated two ways, both encoder-agnostic (it parses the wire
//! bytes, never the [`SymbolGlobalDict`](crate::ingress::buffer::SymbolGlobalDict)):
//!
//! * [`accumulate`](SentDictMirror::accumulate) — after each frame is sent, its
//!   delta section is appended to the mirror if it extends the mirror's tip.
//!   Replayed or empty-delta frames are no-ops, so this is idempotent.
//! * [`seed`](SentDictMirror::seed) — on recovery/orphan-drain the mirror is
//!   seeded from the slot's [`PersistedSymbolDict`](super::qwp_ws_sfa_symbol_dict)
//!   before the first connection.
//!
//! On reconnect the driver calls [`build_catch_up_frames`](SentDictMirror::build_catch_up_frames),
//! which re-registers the whole dictionary split across as many table-less
//! frames as the server's advertised batch cap requires. Each frame carries a
//! contiguous id range `[start .. start+count)`, in order, so the server
//! accumulates them exactly as it would the original per-frame deltas.

// QWP wire constants, duplicated from the row/column encoders (see
// `buffer/qwp.rs` and `column_sender/wire.rs`, which likewise duplicate them to
// keep hot paths free of cross-module hops). These are protocol-stable.
// The one shared LEB128 decoder (with the >=10-byte overflow guard), so the
// catch-up mirror, the persisted side-file, and `SymbolGlobalDict::seed` cannot
// silently diverge. Imported under the local name for the existing call sites.
use crate::ingress::buffer::decode_qwp_varint as decode_varint;

const QWP_HEADER_SIZE: usize = 12;
const QWP_MAGIC: [u8; 4] = *b"QWP1";
const HEADER_OFFSET_FLAGS: usize = 5;
const QWP_FLAG_DELTA_SYMBOL_DICT: u8 = 0x08;

/// Headroom, beyond the 12-byte header, reserved in a catch-up frame's byte
/// budget for the two delta-section varints (`delta_start`, `delta_count`). Ten
/// bytes each maximum; 16 is a safe round bound.
const CATCH_UP_VARINT_HEADROOM: usize = 16;

/// A single symbol dictionary entry did not fit a catch-up frame even alone,
/// because the server's advertised batch cap is smaller than the entry plus
/// framing overhead. Surfaced as a terminal error: the entry cannot be
/// re-registered, so replay would dangle a reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CatchUpEntryTooLarge {
    pub(crate) entry_bytes: usize,
    pub(crate) budget: usize,
}

/// I/O-thread-local mirror of every symbol dictionary entry the send loop has
/// transmitted, in ascending global-id order, held as the concatenated
/// `[len varint][utf8]` bytes exactly as a delta section carries them. Inert
/// (all operations no-ops / empty) when delta mode is disabled.
///
/// # Memory
///
/// The mirror keeps the whole sent dictionary resident for the send core's life
/// (it survives reconnects — it is the source the reconnect catch-up rebuilds
/// from). Its footprint is O(distinct symbols), bounded by the same connection
/// dictionary cap the producer enforces (`MAX_CONN_SYMBOL_DICT_SIZE`), so it
/// cannot grow without bound; it is a second in-RAM copy of the dictionary
/// alongside the foreground [`SymbolGlobalDict`](crate::ingress::buffer::SymbolGlobalDict).
/// In file mode it also duplicates the on-disk side-file in RAM: a deliberate
/// trade-off, since the I/O thread does not own the side-file handle (it is moved
/// to the foreground for write-ahead) and so keeps its own copy to build catch-up
/// frames on reconnect without touching the disk. Eliminating that file-mode copy
/// (reloading from the side-file on the cold reconnect path instead) is a possible
/// future optimisation.
#[derive(Debug, Default)]
pub(crate) struct SentDictMirror {
    bytes: Vec<u8>,
    count: u32,
    enabled: bool,
}

impl SentDictMirror {
    pub(crate) fn new(enabled: bool) -> Self {
        Self {
            bytes: Vec::new(),
            count: 0,
            enabled,
        }
    }

    pub(crate) fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Number of symbols mirrored so far (== the next unmirrored id).
    pub(crate) fn count(&self) -> u32 {
        self.count
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Seeds the mirror from a recovered [`PersistedSymbolDict`]'s loaded entry
    /// region (`[len][utf8]...` in id order) and its entry count. Called once,
    /// before the first connection, on recovery / orphan-drain. No-op when
    /// disabled or given nothing.
    ///
    /// [`PersistedSymbolDict`]: super::qwp_ws_sfa_symbol_dict::PersistedSymbolDict
    pub(crate) fn seed(&mut self, entries: &[u8], count: u32) {
        if !self.enabled || count == 0 {
            return;
        }
        self.bytes.clear();
        // Fallible: a very large recovered dictionary (~2 GiB) must not abort the
        // host via an infallible copy. On OOM, disable the mirror instead -- the
        // send loop's torn-dict guard then rejects the recovered delta frames
        // (`StoreResendRequired`, resend from source), a graceful degrade rather
        // than a crash.
        if self.bytes.try_reserve(entries.len()).is_err() {
            self.enabled = false;
            self.count = 0;
            return;
        }
        self.bytes.extend_from_slice(entries);
        self.count = count;
    }

    /// Copies the symbol-dictionary delta that a just-sent `frame` carries into
    /// the mirror, so a future reconnect can re-register it. Frames are sent in
    /// FSN order carrying monotonically extending deltas, so only a frame whose
    /// delta starts exactly at [`count`](Self::count) extends the mirror; a
    /// replayed or empty-delta frame (nothing new) is skipped. Idempotent on
    /// replay. No-op when disabled.
    ///
    /// `frame` is the whole QWP message (12-byte header first).
    pub(crate) fn accumulate(&mut self, frame: &[u8]) {
        if !self.enabled {
            return;
        }
        let Some(section) = parse_delta_section(frame) else {
            return;
        };
        if section.delta_count == 0 {
            return;
        }
        let tip = u64::from(self.count);
        let frame_end = section
            .delta_start
            .saturating_add(u64::from(section.delta_count));
        // A frame extends the mirror only if it covers the current tip and reaches
        // past it. `frame_end <= tip` is a pure replay/overlap we already hold;
        // `delta_start > tip` is a gap the torn-dict guard rejects before send. The
        // OVERLAP case (`delta_start < tip < frame_end`) matters on recovery from a
        // short/torn side-file: an earlier queued frame that re-registers ids the
        // mirror seed missed must still extend the mirror — folding in only the
        // suffix beyond the tip — or a later frame's guard would false-fire even
        // though this re-registration already covers its base.
        if section.delta_start > tip || frame_end <= tip {
            return;
        }
        // Append only the suffix beyond the tip: skip the `tip - delta_start`
        // already-mirrored entries at the head of this frame's region (0 in the
        // common exactly-contiguous case, so it appends the whole region).
        let skip = (tip - section.delta_start) as usize;
        let suffix_off = skip_entries(section.entries, skip);
        self.bytes.extend_from_slice(&section.entries[suffix_off..]);
        self.count = frame_end as u32;
    }

    /// Returns `true` when `frame`'s delta section redefines an already-mirrored
    /// symbol id to a **different** symbol.
    ///
    /// The foreground [`SymbolGlobalDict`](crate::ingress::buffer::SymbolGlobalDict)
    /// is append-only, so an id the mirror already holds can legitimately be
    /// re-registered only with the *same* bytes (a benign replay of history, e.g.
    /// an earlier queued frame re-registering ids a short recovery seed missed —
    /// see [`accumulate`](Self::accumulate)). A *differing* redefinition means the
    /// recovered history and the queued frames disagree: a host/power crash tore
    /// the side-file so its recovered entries desynced from a later frame that
    /// reused those ids. `accumulate` folds in only the suffix beyond the tip and
    /// drops fully-overlapping regions, so it would silently keep the stale mapping
    /// and the reconnect catch-up would re-register the wrong symbol. The send loop
    /// calls this before sending so `guard_dict_not_torn` can reject such a frame
    /// as torn ("resend required") instead of corrupting the server dictionary.
    ///
    /// Only the overlap prefix `[delta_start, min(frame_end, count))` is compared
    /// (verbatim, since both sides are `[len][utf8]` for the same ids); the suffix
    /// beyond the tip is genuinely new, and a `delta_start > count` gap is the
    /// separate torn case `guard_dict_not_torn` already rejects. No-op (false) when
    /// disabled, for a non-delta frame, or when there is no overlap.
    pub(crate) fn conflicts_with(&self, frame: &[u8]) -> bool {
        if !self.enabled {
            return false;
        }
        let Some(section) = parse_delta_section(frame) else {
            return false;
        };
        let tip = u64::from(self.count);
        // No already-held ids: an empty delta, a gap, or an exactly-contiguous
        // extension (`delta_start == tip`) introduces nothing the mirror holds.
        if section.delta_count == 0 || section.delta_start >= tip {
            return false;
        }
        let frame_end = section
            .delta_start
            .saturating_add(u64::from(section.delta_count));
        let overlap_end = frame_end.min(tip);
        let overlap_entries = (overlap_end - section.delta_start) as usize;
        // Byte ranges of the overlapping entries in the mirror and in the frame.
        let mirror_lo = skip_entries(&self.bytes, section.delta_start as usize);
        let mirror_hi = skip_entries(&self.bytes, overlap_end as usize);
        let frame_hi = skip_entries(section.entries, overlap_entries);
        self.bytes[mirror_lo..mirror_hi] != section.entries[..frame_hi]
    }

    /// Streams the table-less catch-up frame(s) that re-register the whole
    /// mirrored dictionary on a fresh connection, split so no frame exceeds
    /// `server_max_batch_size` (0 = server advertised no cap → a single frame).
    /// Each frame is built into a fresh buffer, handed to `emit`, then dropped
    /// before the next is built — so only one frame is resident at a time rather
    /// than a second copy of the whole dictionary, even on a flapping connection
    /// that repeats the catch-up on every reconnect. Frames carry contiguous id
    /// ranges in order and use `version` in their header. Returns the number
    /// emitted (0 when the mirror is empty). Errors if a single entry cannot fit
    /// the cap, or propagates an `emit` error (after which no further frames are
    /// built).
    pub(crate) fn for_each_catch_up_frame<E>(
        &self,
        server_max_batch_size: usize,
        version: u8,
        mut emit: impl FnMut(&[u8]) -> Result<(), E>,
    ) -> Result<u64, CatchUpStreamError<E>> {
        if self.count == 0 {
            return Ok(0);
        }
        let budget = if server_max_batch_size > 0 {
            server_max_batch_size
                .saturating_sub(QWP_HEADER_SIZE + CATCH_UP_VARINT_HEADROOM)
                .max(1)
        } else {
            // No server-advertised cap: still bound each frame by the QWP header's
            // u32 payload-length field so a huge recovered dictionary splits into
            // u32-sized frames rather than one frame whose length would wrap mod
            // 2^32 in `build_catch_up_frame`. The wire format's own limit is the
            // natural bound.
            (u32::MAX as usize).saturating_sub(QWP_HEADER_SIZE + CATCH_UP_VARINT_HEADROOM)
        };

        let mut emitted: u64 = 0;
        let mut chunk_start_id: u32 = 0;
        let mut chunk_start_off: usize = 0;
        let mut chunk_symbols: u32 = 0;
        let mut chunk_bytes: usize = 0;

        let mut p = 0usize;
        while p < self.bytes.len() {
            let entry_start = p;
            // Entry = [len varint][utf8]; advance past it. A malformed / overrunning
            // entry is unreachable given the mirror invariant (`accumulate` and
            // `seed` only ever append complete entries), but decode it gracefully
            // rather than `expect` — a panic here is a process abort under the FFI
            // `panic = "abort"` profile. On a (future) invariant break, stop at the
            // valid prefix: the catch-up then re-registers only the ids emitted so
            // far, and any stored frame referencing a dropped id fails loudly at the
            // torn-dict guard instead of aborting the host.
            let Some((len, after_len)) = decode_varint(&self.bytes, p) else {
                break;
            };
            let Some(entry_end) = after_len
                .checked_add(len as usize)
                .filter(|end| *end <= self.bytes.len())
            else {
                break;
            };
            p = entry_end;
            let entry_bytes = p - entry_start;

            if entry_bytes > budget {
                return Err(CatchUpStreamError::EntryTooLarge(CatchUpEntryTooLarge {
                    entry_bytes,
                    budget,
                }));
            }
            if chunk_symbols > 0 && chunk_bytes + entry_bytes > budget {
                let frame = build_catch_up_frame(
                    chunk_start_id,
                    chunk_symbols,
                    &self.bytes[chunk_start_off..entry_start],
                    version,
                )
                .ok_or(CatchUpStreamError::FrameBuildFailed)?;
                emit(&frame).map_err(CatchUpStreamError::Emit)?;
                emitted += 1;
                chunk_start_id += chunk_symbols;
                chunk_start_off = entry_start;
                chunk_symbols = 0;
                chunk_bytes = 0;
            }
            chunk_symbols += 1;
            chunk_bytes += entry_bytes;
        }
        if chunk_symbols > 0 {
            // `p` is the end of the last accepted entry: `self.bytes.len()` on a
            // clean walk, or the valid-prefix boundary on an early break above.
            let frame = build_catch_up_frame(
                chunk_start_id,
                chunk_symbols,
                &self.bytes[chunk_start_off..p],
                version,
            )
            .ok_or(CatchUpStreamError::FrameBuildFailed)?;
            emit(&frame).map_err(CatchUpStreamError::Emit)?;
            emitted += 1;
        }
        Ok(emitted)
    }

    /// Collects [`for_each_catch_up_frame`] into a `Vec` for tests that inspect the
    /// frames. Production streams them one at a time via `for_each_catch_up_frame`.
    ///
    /// [`for_each_catch_up_frame`]: SentDictMirror::for_each_catch_up_frame
    #[cfg(test)]
    pub(crate) fn build_catch_up_frames(
        &self,
        server_max_batch_size: usize,
        version: u8,
    ) -> Result<Vec<Vec<u8>>, CatchUpEntryTooLarge> {
        let mut frames = Vec::new();
        match self.for_each_catch_up_frame::<std::convert::Infallible>(
            server_max_batch_size,
            version,
            |frame| {
                frames.push(frame.to_vec());
                Ok(())
            },
        ) {
            Ok(_) => Ok(frames),
            Err(CatchUpStreamError::EntryTooLarge(e)) => Err(e),
            Err(CatchUpStreamError::FrameBuildFailed) => {
                unreachable!("catch-up frame build cannot fail at test scale")
            }
            Err(CatchUpStreamError::Emit(never)) => match never {},
        }
    }
}

/// Error from [`SentDictMirror::for_each_catch_up_frame`]: a single dictionary
/// entry too large for the server's batch cap (terminal — the entry cannot be
/// re-registered), a catch-up frame that could not be built (allocation failed,
/// or its payload would overflow the QWP `u32` length field), or a failure
/// returned by the caller's `emit` (e.g. the transport dropped mid-catch-up,
/// which recovers by reconnecting again).
pub(crate) enum CatchUpStreamError<E> {
    EntryTooLarge(CatchUpEntryTooLarge),
    /// A catch-up frame could not be allocated (fallible `try_reserve` failed) or
    /// its payload would exceed the QWP `u32` payload-length field. Recoverable:
    /// nothing was sent, and the queued data stays persisted for a later retry /
    /// drain.
    FrameBuildFailed,
    Emit(E),
}

/// The `delta_start` a `frame` carries, or `None` when the frame has no delta
/// symbol-dict section (not a QWP frame, or the flag is clear). Used by the
/// pre-send torn-dictionary guard: a `delta_start` above the mirror's coverage
/// means the persisted dictionary was torn.
pub(crate) fn frame_delta_start(frame: &[u8]) -> Option<u64> {
    if !is_delta_frame(frame) {
        return None;
    }
    decode_varint(frame, QWP_HEADER_SIZE).map(|(v, _)| v)
}

/// True only for a well-formed QWP frame carrying a delta symbol-dict section.
/// The magic check keeps the dict logic from misreading non-QWP payloads whose
/// bytes happen to set the delta flag.
fn is_delta_frame(frame: &[u8]) -> bool {
    frame.len() >= QWP_HEADER_SIZE
        && frame[0..4] == QWP_MAGIC
        && frame[HEADER_OFFSET_FLAGS] & QWP_FLAG_DELTA_SYMBOL_DICT != 0
}

struct DeltaSection<'a> {
    delta_start: u64,
    delta_count: u32,
    /// The `[len][utf8]...` bytes covering exactly `delta_count` entries.
    entries: &'a [u8],
}

/// Parses the delta symbol-dict section at the head of a frame's payload.
/// Returns `None` for a non-delta frame or a malformed/truncated section (never
/// produced by our encoders).
fn parse_delta_section(frame: &[u8]) -> Option<DeltaSection<'_>> {
    if !is_delta_frame(frame) {
        return None;
    }
    let (delta_start, p) = decode_varint(frame, QWP_HEADER_SIZE)?;
    let (delta_count, mut p) = decode_varint(frame, p)?;
    let delta_count = u32::try_from(delta_count).ok()?;
    let region_start = p;
    for _ in 0..delta_count {
        let (len, after_len) = decode_varint(frame, p)?;
        p = after_len.checked_add(len as usize)?;
        if p > frame.len() {
            return None;
        }
    }
    Some(DeltaSection {
        delta_start,
        delta_count,
        entries: &frame[region_start..p],
    })
}

/// Builds one table-less catch-up frame carrying dictionary ids
/// `[delta_start .. delta_start+delta_count)` whose `[len][utf8]` bytes are
/// `entries`. Returns `None` when the frame cannot be built:
///
/// * the allocation cannot be reserved — fallible `try_reserve` (rather than an
///   infallible `Vec::with_capacity`) so a huge recovered dictionary degrades to
///   a recoverable error instead of aborting the FFI crate's `panic = "abort"`
///   profile on OOM, and
/// * the payload would overflow the QWP header's `u32` length field — a checked
///   conversion instead of a truncating `as u32`. The frame-size budget in
///   [`SentDictMirror::for_each_catch_up_frame`] already keeps the payload under
///   `u32::MAX`, so this is defence in depth.
///
/// The caller surfaces `None` as a recoverable `FrameBuildFailed`: nothing is
/// sent and the queued data stays persisted for a later retry / drain.
fn build_catch_up_frame(
    delta_start: u32,
    delta_count: u32,
    entries: &[u8],
    version: u8,
) -> Option<Vec<u8>> {
    let mut payload = Vec::new();
    payload
        .try_reserve(CATCH_UP_VARINT_HEADROOM + entries.len())
        .ok()?;
    write_varint(&mut payload, u64::from(delta_start));
    write_varint(&mut payload, u64::from(delta_count));
    payload.extend_from_slice(entries);
    let payload_len = u32::try_from(payload.len()).ok()?;

    let mut frame = Vec::new();
    frame.try_reserve(QWP_HEADER_SIZE + payload.len()).ok()?;
    frame.extend_from_slice(&QWP_MAGIC);
    frame.push(version);
    // Table-less: DELTA_SYMBOL_DICT only. No DEFER_COMMIT — the catch-up runs on
    // a fresh connection with nothing deferred, so committing zero rows is a
    // no-op; and no rows means the flag is otherwise irrelevant.
    frame.push(QWP_FLAG_DELTA_SYMBOL_DICT);
    frame.extend_from_slice(&0u16.to_le_bytes()); // table_count = 0
    frame.extend_from_slice(&payload_len.to_le_bytes());
    frame.extend_from_slice(&payload);
    Some(frame)
}

/// Byte offset in `entries` (a `[len][utf8]...` region) just past the first `n`
/// complete entries. Stops early (returning the offset reached) on a
/// malformed/overrunning entry — unreachable for a section already validated by
/// [`parse_delta_section`], but keeps the walk panic-free under the FFI
/// `panic = "abort"` profile.
fn skip_entries(entries: &[u8], n: usize) -> usize {
    let mut p = 0usize;
    for _ in 0..n {
        let Some((len, after_len)) = decode_varint(entries, p) else {
            return p;
        };
        match after_len.checked_add(len as usize) {
            Some(end) if end <= entries.len() => p = end,
            _ => return p,
        }
    }
    p
}

/// Appends `value` to `out` as an unsigned LEB128 varint (matches
/// `write_qwp_varint`).
fn write_varint(out: &mut Vec<u8>, mut value: u64) {
    while value > 0x7F {
        out.push(((value & 0x7F) as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a synthetic delta frame: header + `[delta_start][count]` + entries,
    /// with optional trailing `table_junk` to prove the parser ignores the
    /// (table) bytes past the dict section.
    fn make_frame(delta_start: u64, entries: &[&[u8]], table_junk: &[u8]) -> Vec<u8> {
        let mut payload = Vec::new();
        write_varint(&mut payload, delta_start);
        write_varint(&mut payload, entries.len() as u64);
        for e in entries {
            write_varint(&mut payload, e.len() as u64);
            payload.extend_from_slice(e);
        }
        payload.extend_from_slice(table_junk);
        let mut frame = Vec::new();
        frame.extend_from_slice(&QWP_MAGIC);
        frame.push(1);
        frame.push(QWP_FLAG_DELTA_SYMBOL_DICT);
        frame.extend_from_slice(&1u16.to_le_bytes());
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(&payload);
        frame
    }

    /// Symbols reconstructed from a mirror's would-be catch-up frames.
    fn symbols_from_catch_up(frames: &[Vec<u8>]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut expected_start = 0u64;
        for f in frames {
            let s = parse_delta_section(f).expect("catch-up frame parses");
            assert_eq!(
                s.delta_start, expected_start,
                "catch-up ranges are contiguous"
            );
            expected_start += u64::from(s.delta_count);
            // walk the entries region
            let mut p = 0usize;
            for _ in 0..s.delta_count {
                let (len, after) = decode_varint(s.entries, p).unwrap();
                out.push(s.entries[after..after + len as usize].to_vec());
                p = after + len as usize;
            }
        }
        out
    }

    #[test]
    fn accumulate_extends_on_contiguous_delta() {
        let mut m = SentDictMirror::new(true);
        m.accumulate(&make_frame(0, &[b"AAPL", b"GOOG"], b"tabledata"));
        assert_eq!(m.count(), 2);
        m.accumulate(&make_frame(2, &[b"MSFT"], b"more"));
        assert_eq!(m.count(), 3);
        let frames = m.build_catch_up_frames(0, 1).unwrap();
        assert_eq!(
            symbols_from_catch_up(&frames),
            vec![b"AAPL".to_vec(), b"GOOG".to_vec(), b"MSFT".to_vec()]
        );
    }

    #[test]
    fn accumulate_skips_replay_overlap_and_empty() {
        let mut m = SentDictMirror::new(true);
        m.accumulate(&make_frame(0, &[b"A", b"B"], b""));
        assert_eq!(m.count(), 2);
        // Replay of an already-held prefix (delta_start < count): ignored.
        m.accumulate(&make_frame(0, &[b"A", b"B"], b""));
        assert_eq!(m.count(), 2);
        // Empty delta (a commit frame): ignored.
        m.accumulate(&make_frame(2, &[], b""));
        assert_eq!(m.count(), 2);
        // A gap (delta_start > count) must NOT silently extend — it is the torn
        // case the driver guards before send; accumulate leaves the mirror intact.
        m.accumulate(&make_frame(5, &[b"X"], b""));
        assert_eq!(m.count(), 2);
    }

    #[test]
    fn accumulate_folds_an_overlapping_frame_that_extends_past_a_short_seed() {
        // Recovery from a short/torn side-file: the mirror seeds to a count SHORTER
        // than an earlier queued frame's re-registration. That frame (delta_start
        // below the tip, extending past it) must still extend the mirror — folding
        // in only the suffix beyond the tip — so a later frame's torn-dict guard
        // does not false-fire even though the re-registration covers its base.
        let mut m = SentDictMirror::new(true);
        // Seed short: only id 0 = "a" recovered, though the queued frame below
        // re-registers ids 0,1,2.
        m.seed(&[1, b'a'], 1);
        assert_eq!(m.count(), 1);

        m.accumulate(&make_frame(0, &[b"a", b"b", b"c"], b"table"));
        assert_eq!(
            m.count(),
            3,
            "an overlapping frame that reaches past the seed extends the mirror"
        );
        // The mirror now holds a,b,c, so the catch-up re-registers all three and a
        // later frame basing at id 2 or 3 passes the torn-dict guard.
        let frames = m.build_catch_up_frames(0, 1).unwrap();
        assert_eq!(
            symbols_from_catch_up(&frames),
            vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]
        );
    }

    #[test]
    fn conflicts_with_flags_a_differing_redefinition_but_not_a_matching_one() {
        // Torn recovery: the seed recovered only id0 = A; an older queued frame
        // re-registers id1 = B; then a fresh foreground frame reuses id1 for a
        // DIFFERENT symbol C (the append-only foreground was seeded with the short
        // recovered count). `accumulate` would drop that fully-overlapping frame and
        // keep B, so the reconnect catch-up would re-register the wrong symbol.
        // `conflicts_with` must flag it so the send loop rejects it as torn.
        let mut m = SentDictMirror::new(true);
        m.seed(&[1, b'A'], 1); // id0 = A
        m.accumulate(&make_frame(1, &[b"B"], b"")); // id1 = B
        assert_eq!(m.count(), 2);

        // Fresh frame redefines id1 = C (different) -> conflict.
        assert!(m.conflicts_with(&make_frame(1, &[b"C"], b"")));
        // Partial overlap: id1 differs (C), id2 is new -> still a conflict.
        assert!(m.conflicts_with(&make_frame(1, &[b"C", b"D"], b"")));

        // Re-registering id1 = B (same symbol) is a benign replay -> no conflict.
        assert!(!m.conflicts_with(&make_frame(1, &[b"B"], b"")));
        // Replay of the whole held prefix, verbatim -> no conflict.
        assert!(!m.conflicts_with(&make_frame(0, &[b"A", b"B"], b"")));
        // Matching prefix that extends past the tip (the legitimate fold case
        // `accumulate` handles) -> no conflict.
        assert!(!m.conflicts_with(&make_frame(1, &[b"B", b"D"], b"")));
        // Exactly-contiguous extension (no overlap) -> no conflict.
        assert!(!m.conflicts_with(&make_frame(2, &[b"C"], b"")));
        // A gap (delta_start > count) is the separate torn case the driver already
        // guards, not a redefinition -> no conflict here.
        assert!(!m.conflicts_with(&make_frame(5, &[b"X"], b"")));
        // Empty delta (a commit frame) -> no conflict.
        assert!(!m.conflicts_with(&make_frame(2, &[], b"")));

        // A disabled mirror never conflicts.
        let disabled = SentDictMirror::new(false);
        assert!(!disabled.conflicts_with(&make_frame(1, &[b"C"], b"")));
    }

    #[test]
    fn disabled_mirror_is_inert() {
        let mut m = SentDictMirror::new(false);
        m.accumulate(&make_frame(0, &[b"A"], b""));
        m.seed(&[1, b'z'], 1);
        assert_eq!(m.count(), 0);
        assert!(m.build_catch_up_frames(0, 1).unwrap().is_empty());
    }

    #[test]
    fn seed_from_persisted_then_extend() {
        let mut m = SentDictMirror::new(true);
        // [len=1]['a'][len=1]['b'] == two entries
        m.seed(&[1, b'a', 1, b'b'], 2);
        assert_eq!(m.count(), 2);
        m.accumulate(&make_frame(2, &[b"c"], b""));
        assert_eq!(m.count(), 3);
        let frames = m.build_catch_up_frames(0, 1).unwrap();
        assert_eq!(
            symbols_from_catch_up(&frames),
            vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]
        );
    }

    #[test]
    fn recovered_side_file_rebuilds_the_catch_up_dictionary() {
        use crate::ingress::sender::qwp_ws_sfa_symbol_dict::PersistedSymbolDict;

        // A previous session's foreground write-ahead persisted two symbols.
        let dir = tempfile::tempdir().unwrap();
        {
            let mut pd = PersistedSymbolDict::open(dir.path()).unwrap();
            pd.append_symbol(b"alpha").unwrap();
            pd.append_symbol(b"bravo").unwrap();
        }
        // Crash recovery: reopen the side-file and seed a fresh connection's mirror
        // straight from its raw region, exactly as the driver does when a recovered
        // slot reconnects.
        let pd = PersistedSymbolDict::open(dir.path()).unwrap();
        let mut mirror = SentDictMirror::new(true);
        mirror.seed(pd.loaded_entries(), pd.size());
        assert_eq!(mirror.count(), 2);
        // The catch-up frame re-registers the whole recovered dictionary from id 0,
        // so the stored delta frames replay gap-free against a server that never
        // saw the original dictionary.
        let frames = mirror.build_catch_up_frames(0, 1).unwrap();
        assert_eq!(
            symbols_from_catch_up(&frames),
            vec![b"alpha".to_vec(), b"bravo".to_vec()]
        );
    }

    #[test]
    fn catch_up_single_frame_when_uncapped() {
        let mut m = SentDictMirror::new(true);
        m.accumulate(&make_frame(0, &[b"AAPL", b"GOOG", b"MSFT"], b""));
        let frames = m.build_catch_up_frames(0, 7).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frame_delta_start(&frames[0]), Some(0));
    }

    #[test]
    fn catch_up_splits_by_cap_and_reassembles_gap_free() {
        let mut m = SentDictMirror::new(true);
        // Ten 4-byte symbols → each entry is 5 bytes ([len=4]+4).
        let syms: Vec<Vec<u8>> = (0..10).map(|i| format!("sy{i:02}").into_bytes()).collect();
        let refs: Vec<&[u8]> = syms.iter().map(|s| s.as_slice()).collect();
        m.accumulate(&make_frame(0, &refs, b""));
        assert_eq!(m.count(), 10);

        // Cap that fits ~3 entries per frame: budget = cap-12-16, want ~15 bytes.
        let cap = 12 + 16 + 15;
        let frames = m.build_catch_up_frames(cap, 3).unwrap();
        assert!(
            frames.len() > 1,
            "expected a multi-frame split, got {}",
            frames.len()
        );
        for f in &frames {
            assert!(f.len() <= cap, "frame {} exceeds cap {}", f.len(), cap);
            assert_eq!(f[4], 3, "catch-up frames carry the negotiated version");
        }
        assert_eq!(symbols_from_catch_up(&frames), syms);
    }

    #[test]
    fn catch_up_errors_when_entry_exceeds_cap() {
        let mut m = SentDictMirror::new(true);
        m.accumulate(&make_frame(0, &[b"a_very_long_symbol_value"], b""));
        // Tiny cap: even one entry cannot fit.
        let err = m.build_catch_up_frames(20, 1).unwrap_err();
        assert!(err.entry_bytes > err.budget);
    }

    #[test]
    fn catch_up_degrades_on_a_torn_mirror_instead_of_aborting() {
        // The mirror invariant guarantees well-formed entries, so a torn region is
        // unreachable in practice -- but if one ever arose it must degrade to the
        // valid prefix, not panic (a panic is a process abort under the FFI
        // `panic = "abort"` profile). Truncate mid-entry so the second entry's
        // `[len][utf8]` is torn.
        let mut m = SentDictMirror::new(true);
        m.accumulate(&make_frame(0, &[b"AAPL", b"GOOG"], b""));
        assert_eq!(m.count(), 2);
        m.bytes.truncate(m.bytes.len() - 2);

        let frames = m.build_catch_up_frames(0, 1).unwrap();
        assert_eq!(
            symbols_from_catch_up(&frames),
            vec![b"AAPL".to_vec()],
            "catch-up re-registers the valid prefix and stops at the tear"
        );
    }

    #[test]
    fn round_trip_accumulate_catch_up_reaccumulate() {
        // Simulate: send several delta frames, build catch-up, then a fresh
        // server-side mirror re-accumulating the catch-up reconstructs identically.
        let mut sender = SentDictMirror::new(true);
        sender.accumulate(&make_frame(0, &[b"one", b"two"], b"t"));
        sender.accumulate(&make_frame(2, &[b"three"], b"t"));
        sender.accumulate(&make_frame(3, &[b"four", b"five"], b"t"));
        let frames = sender.build_catch_up_frames(12 + 16 + 8, 1).unwrap();

        let mut replayed = SentDictMirror::new(true);
        for f in &frames {
            replayed.accumulate(f);
        }
        assert_eq!(replayed.count(), sender.count());
        assert_eq!(
            symbols_from_catch_up(&replayed.build_catch_up_frames(0, 1).unwrap()),
            vec![
                b"one".to_vec(),
                b"two".to_vec(),
                b"three".to_vec(),
                b"four".to_vec(),
                b"five".to_vec()
            ]
        );
    }

    #[test]
    fn frame_delta_start_ignores_non_delta_frames() {
        // A frame without the delta flag.
        let mut frame = make_frame(3, &[b"x"], b"");
        frame[HEADER_OFFSET_FLAGS] = 0;
        assert_eq!(frame_delta_start(&frame), None);
        // Non-QWP bytes that happen to set the flag.
        let junk = vec![0u8; 20];
        assert_eq!(frame_delta_start(&junk), None);
        // A real delta frame.
        assert_eq!(frame_delta_start(&make_frame(7, &[b"x"], b"")), Some(7));
    }
}
