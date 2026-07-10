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

//! Append-only, per-slot persistence of the global symbol dictionary a
//! store-and-forward sender ships to the server with delta encoding. Lives at
//! `<slot_dir>/.symbol-dict` alongside the segment files and the slot lock.
//!
//! Delta-encoded SFA frames are **not** self-sufficient: a frame carries only
//! the symbols it introduces, so recovering (process restart) or draining
//! (orphan adoption) a slot requires re-registering the whole dictionary on the
//! fresh server before those frames replay. This file is that dictionary. Unlike
//! the ack watermark — a discardable optimization — this file is *load-bearing*:
//! a surviving frame that references an id missing from it is unrecoverable, so
//! it is held to a stronger durability contract (write-ahead of the referencing
//! frame; see [`super::qwp_ws_driver`]).
//!
//! # Layout (little-endian)
//!
//! ```text
//!   offset 0: u32 magic = 'SYD2'
//!   offset 4: u8  version = 2
//!   offset 5: 3 bytes reserved (zero)
//!   offset 8: records, each written by one write-ahead append
//!               [payload_len: u32]
//!               [payload: entries, each [len: varint][utf8 bytes], ascending id]
//!               [crc32c: u32 over (payload_len || payload)]
//! ```
//!
//! Symbol id `i` is the `i`-th entry across all record payloads (ids are dense
//! and assigned sequentially from 0), so no id needs to be stored. Each record
//! carries the symbols one write-ahead batch (a frame) introduced, committed by a
//! trailing CRC32C exactly as the segment records are (see
//! [`super::qwp_ws_sfa_segment`]): a bit-flip in a length or a symbol byte is
//! caught on recovery instead of silently mis-registering a symbol. The
//! concatenated record *payloads* (framing stripped) are byte-for-byte the shape a
//! QWP delta-dict section carries, so a recovered region can be spliced into a
//! catch-up frame verbatim.
//!
//! # Durability / write-ahead ordering
//!
//! The producer appends the symbols a frame introduces **before** that frame is
//! published to the ring, but does **not** fsync — matching the rest of
//! store-and-forward, which is page-cache (not disk) durable. This ordering is
//! sufficient for a **process/JVM crash**: the page cache survives, so both the
//! dictionary and the frames survive and the dictionary is a superset of every
//! recoverable frame's references. It is **not** sufficient for a **host/power
//! crash**, where unflushed pages can be lost out of order and the dictionary
//! may end up torn relative to the frames it serves — exactly as the segment
//! frames themselves may be lost on a host crash. A torn dictionary is caught at
//! replay by the send loop's guard, which fails loudly (the unreplayable data
//! must be resent) rather than corrupting the target table.
//!
//! A torn trailing record from a crash mid-append is self-healing: [`open`] stops
//! parsing at the first incomplete or CRC-failed record and truncates the file
//! there, so the
//! next append overwrites it.
//!
//! # Lifecycle
//!
//! Single-writer (the producer / user thread). Read once at [`open`] to seed
//! in-memory state on recovery or orphan-drain. The owner closes it (dropping the
//! value closes the file). Not safe for concurrent writers.
//!
//! [`open`]: PersistedSymbolDict::open

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

// The one shared LEB128 decoder (with the >=10-byte overflow guard), so this
// side-file reader, the catch-up mirror, and `SymbolGlobalDict::seed` cannot
// silently diverge. Imported under the local name for the existing call sites.
use crate::ingress::buffer::decode_qwp_varint as decode_varint;
// One shared per-entry length cap for ingestion, recovery validation, and this
// side-file's reader/writer, so a symbol the writer accepts can never be one the
// reader rejects (which would strand a queued frame). Aliased to the local name.
use crate::ingress::buffer::MAX_PERSISTED_SYMBOL_ENTRY_LEN as MAX_ENTRY_LEN;

/// Filename within the slot directory. Dot-prefixed so directory enumerators
/// that filter by the `.sfa` suffix (segment recovery, orphan scan, trim) skip
/// it automatically, exactly like `.lock` and `.ack-watermark`.
pub(crate) const FILE_NAME: &str = ".symbol-dict";

/// `'SYD2'` little-endian. Bumped from `'SYD1'` when per-record CRC32C framing was
/// added: an old unframed file has a different magic, so [`open`] rejects it as
/// bad-magic and recovers fresh rather than misparsing it.
///
/// [`open`]: PersistedSymbolDict::open
const FILE_MAGIC: u32 = 0x3244_5953;
const HEADER_SIZE: u64 = 8;
const VERSION: u8 = 2;

/// Bytes of framing each record adds around its payload: a `u32` payload length
/// prefix and a trailing `u32` CRC32C.
const RECORD_LEN_PREFIX: usize = 4;
const RECORD_CRC_LEN: usize = 4;

/// Upper bound on the side-file size accepted at [`open`](PersistedSymbolDict::open) /
/// [`open_recovered`](PersistedSymbolDict::open_recovered). A legitimate dictionary's
/// UTF-8 bytes are bounded writer-side by the connection heap cap
/// (`MAX_CONN_SYMBOL_DICT_HEAP_BYTES`, 256 MiB, enforced at `intern`); adding the
/// per-entry length prefixes and per-record framing keeps a legitimate file well
/// under this ceiling, so a larger file is corrupt. Capping `file_len` before
/// reading keeps a corrupt/oversized file from driving `read_to_end` to an OOM
/// abort — its allocation is infallible and aborts the host regardless of the
/// panic setting. Deliberately generous defence-in-depth (~2 GiB, ~8x the
/// legitimate maximum); exceeding it degrades to a fresh/dense recovery rather
/// than loading the file.
const MAX_FILE_LEN: u64 = HEADER_SIZE + (8 * 1024 * 1024) * 256;

/// A point in the persisted dictionary's append history, taken before a frame's
/// symbols are written ahead so the file can be rolled back to it if that frame
/// fails to publish. See [`PersistedSymbolDict::mark`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct PersistedSymbolDictMark {
    append_offset: u64,
    size: u32,
}

/// Append-only, single-writer persisted symbol dictionary. See the module docs.
#[derive(Debug)]
pub(crate) struct PersistedSymbolDict {
    file: File,
    /// Byte offset one past the last complete entry — where the next append
    /// lands. Starts at [`HEADER_SIZE`].
    append_offset: u64,
    /// Number of symbols held (highest id + 1).
    size: u32,
    /// The concatenated `[len][utf8]...` bytes of every entry recovered at
    /// [`open`] time, exactly as on disk and as a delta section carries them.
    /// Empty for a freshly created file. Consumed once to seed the send loop's
    /// catch-up mirror and the producer's id map.
    loaded_entries: Vec<u8>,
    /// Reused scratch for [`append_symbols`]: a frame's new symbols are encoded
    /// into it and written in one `write_all`, so a wide flush interning many
    /// symbols does not re-allocate per symbol on the caller's flush path.
    ///
    /// [`append_symbols`]: PersistedSymbolDict::append_symbols
    append_scratch: Vec<u8>,
    /// Latched when a partial-write cleanup (`set_len`/`seek` back to the pre-write
    /// tip) itself fails, leaving the OS file cursor stranded past the logical tip.
    /// The handle can no longer be written or rolled back safely, so [`rollback`]
    /// and [`append_symbols`] both fail once set -- forcing the caller to drop the
    /// handle and fall back to dense (self-sufficient) frames. Set even when the
    /// best-effort on-disk [`poison`] cannot reach a dying disk, so the in-memory
    /// latch alone protects the live connection.
    ///
    /// [`rollback`]: PersistedSymbolDict::rollback
    /// [`poison`]: PersistedSymbolDict::poison
    poisoned: bool,
    /// Test-only: force the next [`append_symbols`] down the failed-partial-write
    /// cleanup path (write fails and the restore cannot be completed), so the
    /// poison + latch behaviour can be exercised without a real disk fault.
    #[cfg(test)]
    fail_next_append_cleanup: bool,
}

impl PersistedSymbolDict {
    /// Opens (creating if absent) the dictionary file in `slot_dir`. An existing,
    /// readable file is parsed and its complete entries are loaded into memory (see
    /// [`loaded_entries`]); a missing file, or a present file with a bad-magic
    /// (proven-corrupt) header, is (re)created with a fresh header.
    ///
    /// Returns `Err` on a *transient* I/O failure against an existing file (a
    /// failed open/read/seek/truncate, an inconsistent read, or a `stat` error):
    /// the file is left untouched, so a recovered slot's load-bearing dictionary is
    /// never destroyed by a hiccup that merely prevented reading it this time. The
    /// caller decides whether that is fatal (recovered slot — fail loudly and retry
    /// with the data intact) or ignorable (fresh slot — degrade to full-dictionary
    /// frames). Only bad magic — proven local corruption — discards recovered
    /// entries.
    ///
    /// [`loaded_entries`]: PersistedSymbolDict::loaded_entries
    pub(crate) fn open(slot_dir: &Path) -> io::Result<Self> {
        let path = slot_dir.join(FILE_NAME);
        let existing_len = match fs::metadata(&path) {
            Ok(meta) => meta.len(),
            Err(e) if e.kind() == io::ErrorKind::NotFound => 0,
            // A transient `stat` failure must NOT masquerade as an absent file
            // (`len == 0`), or a recovered slot's load-bearing dictionary would be
            // silently re-created empty below. Surface it so the caller can retry.
            Err(e) => return Err(e),
        };
        // Only a present, readable, bad-magic file (proven-corrupt) falls through to
        // a fresh re-create; a transient I/O error opening/reading an existing file
        // propagates instead, so recovery never truncates a dictionary it merely
        // failed to read this time.
        if existing_len >= HEADER_SIZE
            && let Some(d) = Self::open_existing(&path, existing_len)?
        {
            return Ok(d);
        }
        Self::open_fresh(&path)
    }

    /// Opens the dictionary file for a **recovered** slot — one whose segments
    /// already exist — WITHOUT ever fabricating a fresh file. Returns:
    ///
    /// * `Ok(Some(dict))` — an existing, valid dictionary loaded. Its recovered
    ///   entries seed the producer dict + catch-up mirror and the slot
    ///   delta-encodes.
    /// * `Ok(None)` — no valid dictionary is present (absent, header too short,
    ///   or bad/poisoned magic). The recovered segments reference symbol ids
    ///   `[0, K)` that a fabricated *empty* delta dictionary would NOT mirror,
    ///   so the caller must keep full-dictionary (self-sufficient) frames rather
    ///   than delta-encode: a surviving dense frame then replays on its own, and
    ///   a surviving delta frame is rejected loudly by the send loop's
    ///   torn-dictionary guard (the mirror stays disabled, so a `delta_start > 0`
    ///   frame cannot be re-registered). Seeding an empty delta dictionary here
    ///   instead would let a later delta frame resolve those stale ids to the
    ///   wrong symbols on a fresh server — silent data corruption.
    /// * `Err` — a *transient* I/O failure (stat/open/read/seek/truncate): the
    ///   file is left untouched so the caller can fail this attempt and retry
    ///   with the on-disk data intact, never destroying a dictionary it merely
    ///   failed to read this time.
    ///
    /// Unlike [`open`](Self::open), the absent / bad-magic cases return `None`
    /// (dense fallback) instead of re-creating a fresh empty file.
    pub(crate) fn open_recovered(slot_dir: &Path) -> io::Result<Option<Self>> {
        let path = slot_dir.join(FILE_NAME);
        let existing_len = match fs::metadata(&path) {
            Ok(meta) => meta.len(),
            // Absent: no persisted dictionary mirrors the segments -> dense.
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            // Transient stat failure: surface it (retryable, data intact).
            Err(e) => return Err(e),
        };
        if existing_len < HEADER_SIZE {
            // Present but too short to even hold a header -> no valid dictionary.
            return Ok(None);
        }
        // `Ok(Some)` valid, `Ok(None)` bad-magic (dense fallback), `Err`
        // transient. Never re-creates a fresh file on the `None` path.
        Self::open_existing(&path, existing_len)
    }

    /// Best-effort removal of a stale dictionary file. Used at fresh-start (a
    /// stale dict with no segments behind it is meaningless) and at fully-drained
    /// close (the slot is empty, nothing references the dictionary any more),
    /// mirroring the ack-watermark's `remove_orphan`.
    pub(crate) fn remove_orphan(slot_dir: &Path) {
        let _ = fs::remove_file(slot_dir.join(FILE_NAME));
    }

    /// Appends one symbol. Thin wrapper over [`append_symbols`] used by tests; the
    /// write-ahead path calls the batch form directly (one write per frame).
    ///
    /// [`append_symbols`]: PersistedSymbolDict::append_symbols
    #[cfg(test)]
    pub(crate) fn append_symbol(&mut self, symbol: &[u8]) -> io::Result<()> {
        self.append_symbols(&[symbol])
    }

    /// Test-only: arm the failed-partial-write-cleanup path so the next
    /// [`append_symbols`](Self::append_symbols) poisons the handle (and a later
    /// [`rollback`](Self::rollback) fails). Lets other modules' tests (e.g. the
    /// replay encoder / column backend) drive the drop-handle / disable-delta
    /// fallback without a real disk fault.
    #[cfg(test)]
    pub(crate) fn arm_fail_next_append_cleanup(&mut self) {
        self.fail_next_append_cleanup = true;
    }

    /// Appends `symbols` in id order in a **single** buffered `write_all`, each
    /// taking the next dense id implicitly (its position). The write-ahead path
    /// calls this once per frame with the symbols that frame introduced; batching
    /// keeps a wide first flush (which can intern thousands of symbols at once)
    /// from doing one allocation + one `write()` syscall per symbol on the
    /// caller's flush. The caller write-aheads a frame's symbols **before**
    /// publishing it, so the ordering (entries before referencing frame) holds; no
    /// fsync is performed (see the module durability note).
    ///
    /// On a partial write the file is restored to the pre-write tip so the
    /// in-memory `append_offset`/`size` stay authoritative and the caller's
    /// rollback-to-mark is a clean no-op. If even that restore fails the disk is
    /// failing and the OS file cursor is stranded past the logical tip: the
    /// side-file is [`poison`]ed and the handle latched so this and every later
    /// [`rollback`] fail, forcing the caller to drop the handle and fall back to
    /// dense frames. [`open`]'s torn-tail healer trims any on-disk residue on the
    /// next recovery.
    ///
    /// [`rollback`]: PersistedSymbolDict::rollback
    /// [`poison`]: PersistedSymbolDict::poison
    /// [`open`]: PersistedSymbolDict::open
    pub(crate) fn append_symbols(&mut self, symbols: &[&[u8]]) -> io::Result<()> {
        if self.poisoned {
            return Err(io::Error::other(
                "persisted symbol dictionary poisoned by a failed partial-write cleanup",
            ));
        }
        if symbols.is_empty() {
            return Ok(());
        }
        // Test-only: exercise the failed-cleanup path without a real disk fault.
        #[cfg(test)]
        if self.fail_next_append_cleanup {
            self.fail_next_append_cleanup = false;
            self.poison();
            self.poisoned = true;
            return Err(io::Error::other("injected partial-write cleanup failure"));
        }
        let start = self.append_offset;
        // One CRC-committed record: [payload_len u32][payload][crc32c u32]. The
        // payload is the frame's `[len][utf8]...` symbols; the CRC covers the length
        // prefix + payload (mirroring the segment codec) so a bit-flip in either is
        // caught on recovery instead of silently mis-registering a symbol. Built in
        // scratch and written in one `write_all` so a wide flush does not do a
        // syscall per symbol.
        self.append_scratch.clear();
        self.append_scratch
            .extend_from_slice(&[0u8; RECORD_LEN_PREFIX]); // reserved; filled below
        for symbol in symbols {
            write_varint(&mut self.append_scratch, symbol.len() as u64);
            self.append_scratch.extend_from_slice(symbol);
        }
        let payload_len = (self.append_scratch.len() - RECORD_LEN_PREFIX) as u32;
        self.append_scratch[..RECORD_LEN_PREFIX].copy_from_slice(&payload_len.to_le_bytes());
        let crc = crc32c::crc32c_append(0, &self.append_scratch);
        self.append_scratch.extend_from_slice(&crc.to_le_bytes());
        let rec_len = self.append_scratch.len() as u64;
        // Disjoint field borrows: write the scratch (shared) into the file (mut).
        if let Err(e) = self.file.write_all(&self.append_scratch) {
            // Restore the file to the pre-write tip. `set_len` (ftruncate) does not
            // move the cursor, so the `seek` is required to keep the OS cursor in
            // lockstep with `append_offset`. If EITHER restore fails, the cursor is
            // stranded past the tip -- a later append would write at the wrong
            // offset and a torn partial record could be misread -- so poison the
            // side-file and latch the handle (unconditionally, even if the poison
            // write cannot reach a dying disk) so the caller's rollback fails and
            // delta is disabled on this connection.
            let truncated = self.file.set_len(start).is_ok();
            let seeked = self.file.seek(SeekFrom::Start(start)).is_ok();
            if !(truncated && seeked) {
                self.poison();
                self.poisoned = true;
            }
            return Err(e);
        }
        self.append_offset = start + rec_len;
        self.size += symbols.len() as u32;
        Ok(())
    }

    /// The concatenated `[len][utf8]` bytes of every recovered symbol in id
    /// order, exactly as a delta section carries them. Empty when nothing was
    /// recovered. Used once on recovery to seed the driver's catch-up mirror.
    pub(crate) fn loaded_entries(&self) -> &[u8] {
        &self.loaded_entries
    }

    /// Frees the recovered entry region once it has been copied out for seeding
    /// (via [`loaded_entries`]). The write-ahead handle the foreground keeps for
    /// the whole connection only needs the `file` / `append_offset` / `size`, so
    /// retaining this (up to ~2 GiB) region for the connection lifetime is pure
    /// dead weight. `Vec::new` (not `clear`) so the backing capacity is released.
    ///
    /// [`loaded_entries`]: PersistedSymbolDict::loaded_entries
    pub(crate) fn clear_loaded_entries(&mut self) {
        self.loaded_entries = Vec::new();
    }

    /// Materialises the loaded entries as symbol byte strings in ascending-id
    /// order (entry `i` is symbol id `i`). Production recovery seeds directly from
    /// the raw [`loaded_entries`] region (via `SymbolGlobalDict::seed`), so this
    /// materialising form is used only by tests for readable assertions.
    ///
    /// [`loaded_entries`]: PersistedSymbolDict::loaded_entries
    #[cfg(test)]
    pub(crate) fn read_loaded_symbols(&self) -> Vec<Vec<u8>> {
        let mut out = Vec::with_capacity(self.size as usize);
        let buf = &self.loaded_entries;
        let mut pos = 0usize;
        while pos < buf.len() {
            let Some((len, next)) = decode_varint(buf, pos) else {
                break;
            };
            let len = len as usize;
            if next + len > buf.len() {
                break; // defensive: torn tail (should not survive open())
            }
            out.push(buf[next..next + len].to_vec());
            pos = next + len;
        }
        out
    }

    /// Number of symbols the dictionary holds (highest id + 1).
    pub(crate) fn size(&self) -> u32 {
        self.size
    }

    /// Snapshots the current append tip so a frame's write-ahead symbols can be
    /// undone with [`rollback`] if that frame's publish fails.
    ///
    /// [`rollback`]: PersistedSymbolDict::rollback
    pub(crate) fn mark(&self) -> PersistedSymbolDictMark {
        PersistedSymbolDictMark {
            append_offset: self.append_offset,
            size: self.size,
        }
    }

    /// Rolls the on-disk dictionary back to `mark`, discarding every symbol
    /// appended since. The column foreground writes a frame's new symbols ahead
    /// of publishing it, then rolls its in-memory dictionary back and reuses those
    /// ids for the next frame when the append fails (see the SFA append-timeout
    /// path); the side-file must roll back in lockstep, or recovery would map the
    /// reused ids to the abandoned symbols. Never extends the file (a
    /// forward/equal mark is a no-op).
    ///
    /// If the truncate itself fails (a failing/read-only disk), the abandoned
    /// entries cannot be removed and the next frame's reuse of their ids would
    /// leave the file a *distinct*-symbol superset of the live dictionary —
    /// which recovery does NOT fold away (`SymbolGlobalDict::seed` interns every
    /// stored entry, so the extra symbol shifts every later id up by one and
    /// aliases the reused id onto the wrong symbol, and the torn-dict guard
    /// misses it because the recovered count is inflated, not short). Rather
    /// than risk that silent corruption, [`poison`] the header so a later
    /// [`open`] rejects the file and starts fresh — the torn-dict guard then
    /// fails loudly on the un-re-registered ids — and return the error so the
    /// caller stops persisting on this slot.
    ///
    /// [`poison`]: PersistedSymbolDict::poison
    /// [`open`]: PersistedSymbolDict::open
    pub(crate) fn rollback(&mut self, mark: PersistedSymbolDictMark) -> io::Result<()> {
        // A poisoned handle (a partial-write cleanup failed, stranding the cursor)
        // cannot be truncated to a trustworthy offset. Fail so the caller drops the
        // handle and disables delta, rather than silently returning Ok and reusing a
        // desynced file. Checked before the no-op fast path below, which would
        // otherwise mask the poison after a failed append left `append_offset`
        // unchanged.
        if self.poisoned {
            return Err(io::Error::other(
                "persisted symbol dictionary poisoned by a failed partial-write cleanup",
            ));
        }
        if mark.append_offset >= self.append_offset {
            return Ok(());
        }
        if let Err(e) = self.file.set_len(mark.append_offset) {
            // Truncation failed: the abandoned tail cannot be removed, so poison
            // the on-disk magic (recovery starts fresh) AND latch in memory --
            // matching `append_symbols`' cleanup path -- so this handle rejects
            // every later `append_symbols` / `rollback` regardless of caller
            // discipline, not just because the caller happens to drop it.
            self.poison();
            self.poisoned = true;
            return Err(e);
        }
        self.file.seek(SeekFrom::Start(mark.append_offset))?;
        self.append_offset = mark.append_offset;
        self.size = mark.size;
        Ok(())
    }

    /// Best-effort invalidation of the on-disk side-file: overwrites the header
    /// magic so a later [`open`] rejects the file and re-creates it fresh
    /// (empty). Used when [`rollback`] cannot truncate an abandoned tail, so
    /// recovery cannot rebuild a corrupt dictionary from a file that no longer
    /// mirrors the live dictionary. Best-effort because the disk is already
    /// failing.
    ///
    /// # Residual double-failure window
    ///
    /// If *both* the [`rollback`] truncate and this header overwrite fail (a dying
    /// disk failing two writes in a row on the same handle), the abandoned
    /// complete-entry tail survives with still-valid magic, and a later recovery
    /// reads those stale entries as real symbols — the silent id-aliasing the
    /// write-ahead design otherwise guards against (see [`rollback`]). The window
    /// is narrow (two consecutive write failures) and is the residual cost of not
    /// `fsync`-ing; a host that can still write anything closes it. Nothing more
    /// can be done here without a working disk.
    ///
    /// [`open`]: PersistedSymbolDict::open
    /// [`rollback`]: PersistedSymbolDict::rollback
    fn poison(&mut self) {
        if self.file.seek(SeekFrom::Start(0)).is_ok() {
            let _ = self.file.write_all(&[0u8; 4]);
        }
    }

    /// Opens and parses an existing side-file. `Ok(Some)` = a valid dictionary was
    /// loaded; `Ok(None)` = the file is present but has a bad-magic header (proven
    /// corrupt), so the caller may safely re-create it fresh; `Err` = a transient
    /// I/O error (open/read/seek/truncate) or an inconsistent read — the on-disk
    /// file may still be intact, so the caller must NOT truncate/re-create it.
    fn open_existing(path: &Path, file_len: u64) -> io::Result<Option<Self>> {
        if file_len > MAX_FILE_LEN {
            // Implausibly large for a dictionary bounded by the connection
            // symbol-dict cap: treat as proven-corrupt (like bad magic) rather than
            // feed `read_to_end` a huge length whose infallible allocation would
            // abort the host on OOM.
            return Ok(None);
        }
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        // Reserve fallibly so even an under-cap file that cannot be allocated
        // surfaces a transient error instead of aborting; `read_to_end` then fills
        // the reservation without growing it.
        let mut buf = Vec::new();
        buf.try_reserve(file_len as usize)
            .map_err(|_| io::Error::other("persisted symbol dictionary: allocation too large"))?;
        file.read_to_end(&mut buf)?;
        if buf.len() as u64 != file_len || buf.len() < HEADER_SIZE as usize {
            // Short / interrupted read, or the file changed under us: the bytes we
            // have cannot be trusted, but the file on disk may be fine. Treat as
            // transient (do NOT re-create/truncate) rather than as corruption.
            return Err(io::Error::other(
                "persisted symbol dictionary: short or inconsistent read",
            ));
        }
        // buf.len() >= HEADER_SIZE (== 8) is guaranteed above, so the first four
        // bytes are always present — index directly rather than risk a panic.
        if u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) != FILE_MAGIC {
            return Ok(None); // proven-corrupt header -> caller re-creates fresh
        }

        // Parse CRC-committed records after the header; stop at the first torn,
        // incomplete, or CRC-failed record (self-healing tail). `loaded_entries` is
        // rebuilt from the record payloads only (framing stripped) so it stays the
        // byte-for-byte shape a delta section carries.
        let mut pos = HEADER_SIZE as usize;
        let mut count: u32 = 0;
        // Fallible up-front reservation, upper-bounded by the file (itself capped at
        // MAX_FILE_LEN): the `extend_from_slice` in the loop below then fills it
        // without re-allocating, so a ~2 GiB recovery surfaces a transient error
        // rather than defeating `buf`'s OOM guard with a second infallible ~2 GiB
        // allocation.
        let mut loaded_entries: Vec<u8> = Vec::new();
        loaded_entries
            .try_reserve(buf.len())
            .map_err(|_| io::Error::other("persisted symbol dictionary: allocation too large"))?;
        while pos < buf.len() {
            // [payload_len: u32][payload][crc32c: u32]
            let Some(payload_start) = pos.checked_add(RECORD_LEN_PREFIX) else {
                break;
            };
            if payload_start > buf.len() {
                break; // torn length prefix
            }
            let payload_len =
                u32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]) as usize;
            let Some(crc_start) = payload_start.checked_add(payload_len) else {
                break;
            };
            let Some(record_end) = crc_start.checked_add(RECORD_CRC_LEN) else {
                break;
            };
            if record_end > buf.len() {
                break; // payload / crc overruns the buffer -> torn tail
            }
            let crc_read = u32::from_le_bytes([
                buf[crc_start],
                buf[crc_start + 1],
                buf[crc_start + 2],
                buf[crc_start + 3],
            ]);
            // CRC covers the length prefix + payload.
            if crc32c::crc32c_append(0, &buf[pos..crc_start]) != crc_read {
                break; // corrupt / half-committed record -> torn tail
            }
            // Count the verified payload's entries and enforce the per-entry cap
            // (defence in depth: `intern` already rejects oversized symbols before
            // they are written). A malformed entry inside a CRC-valid payload would
            // be a writer bug, so stop before adopting the record.
            let payload = &buf[payload_start..crc_start];
            let Some(record_count) = count_payload_entries(payload) else {
                break;
            };
            let Some(new_count) = count.checked_add(record_count) else {
                break;
            };
            loaded_entries.extend_from_slice(payload);
            count = new_count;
            pos = record_end;
        }

        let append_offset = pos as u64;

        // Physically drop any torn trailing bytes so the next append lands
        // immediately after the last complete entry rather than after the tear.
        if append_offset != file_len {
            file.set_len(append_offset)?;
        }
        file.seek(SeekFrom::Start(append_offset))?;

        Ok(Some(Self {
            file,
            append_offset,
            size: count,
            loaded_entries,
            append_scratch: Vec::new(),
            poisoned: false,
            #[cfg(test)]
            fail_next_append_cleanup: false,
        }))
    }

    fn open_fresh(path: &Path) -> io::Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        let mut header = [0u8; HEADER_SIZE as usize];
        header[0..4].copy_from_slice(&FILE_MAGIC.to_le_bytes());
        header[4] = VERSION;
        // bytes 5..8 stay zero (reserved)
        if let Err(e) = file.write_all(&header) {
            let _ = fs::remove_file(path);
            return Err(e);
        }
        Ok(Self {
            file,
            append_offset: HEADER_SIZE,
            size: 0,
            loaded_entries: Vec::new(),
            append_scratch: Vec::new(),
            poisoned: false,
            #[cfg(test)]
            fail_next_append_cleanup: false,
        })
    }
}

/// Appends `value` to `out` as an unsigned LEB128 varint.
fn write_varint(out: &mut Vec<u8>, mut value: u64) {
    while value > 0x7F {
        out.push(((value & 0x7F) as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

/// Walks a CRC-verified record payload's `[len varint][utf8]` entries, returning
/// the entry count when every entry is well-formed and within [`MAX_ENTRY_LEN`],
/// or `None` when the payload is malformed (a torn varint, an entry that overruns
/// the payload, or one exceeding the cap). The CRC has already proven the payload
/// intact, so `None` indicates a writer bug rather than corruption; either way the
/// record is not adopted. Never panics on malformed input.
fn count_payload_entries(payload: &[u8]) -> Option<u32> {
    let mut pos = 0usize;
    let mut count: u32 = 0;
    while pos < payload.len() {
        let (len, next) = decode_varint(payload, pos)?;
        if len > MAX_ENTRY_LEN {
            return None;
        }
        let end = next.checked_add(len as usize)?;
        if end > payload.len() {
            return None;
        }
        pos = end;
        count = count.checked_add(1)?;
    }
    Some(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_slot() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn fresh_open_is_empty_and_writes_header() {
        let dir = tmp_slot();
        let d = PersistedSymbolDict::open(dir.path()).unwrap();
        assert_eq!(d.size(), 0);
        assert!(d.loaded_entries().is_empty());
        assert!(d.read_loaded_symbols().is_empty());

        let bytes = fs::read(dir.path().join(FILE_NAME)).unwrap();
        assert_eq!(bytes.len(), HEADER_SIZE as usize);
        assert_eq!(
            u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            FILE_MAGIC
        );
        assert_eq!(bytes[4], VERSION);
    }

    #[test]
    fn append_then_reopen_round_trips_entries() {
        let dir = tmp_slot();
        {
            let mut d = PersistedSymbolDict::open(dir.path()).unwrap();
            d.append_symbol(b"AAPL").unwrap();
            d.append_symbol(b"GOOG").unwrap();
            d.append_symbol(b"").unwrap(); // empty symbol is a valid entry
            d.append_symbol("béta".as_bytes()).unwrap();
            assert_eq!(d.size(), 4);
        }
        let d = PersistedSymbolDict::open(dir.path()).unwrap();
        assert_eq!(d.size(), 4);
        let symbols = d.read_loaded_symbols();
        assert_eq!(
            symbols,
            vec![
                b"AAPL".to_vec(),
                b"GOOG".to_vec(),
                b"".to_vec(),
                "béta".as_bytes().to_vec(),
            ]
        );
    }

    #[test]
    fn append_symbols_batches_multiple_in_one_write_and_round_trips() {
        // The write-ahead path persists a frame's new symbols in one batched call
        // (one alloc + one write_all) rather than per symbol. The on-disk result
        // must be identical to per-symbol appends: entries in id order, empty
        // symbols preserved, and ids continuing across successive batches.
        let dir = tmp_slot();
        {
            let mut d = PersistedSymbolDict::open(dir.path()).unwrap();
            d.append_symbols(&[b"AAPL", b"", b"GOOG"]).unwrap();
            assert_eq!(d.size(), 3);
            d.append_symbols(&[b"MSFT"]).unwrap(); // a later frame continues ids
            assert_eq!(d.size(), 4);
            d.append_symbols(&[]).unwrap(); // an empty batch is a no-op
            assert_eq!(d.size(), 4);
        }
        let d = PersistedSymbolDict::open(dir.path()).unwrap();
        assert_eq!(
            d.read_loaded_symbols(),
            vec![
                b"AAPL".to_vec(),
                b"".to_vec(),
                b"GOOG".to_vec(),
                b"MSFT".to_vec(),
            ]
        );
    }

    #[test]
    fn reopen_appends_after_recovered_tail() {
        let dir = tmp_slot();
        {
            let mut d = PersistedSymbolDict::open(dir.path()).unwrap();
            d.append_symbol(b"one").unwrap();
        }
        {
            let mut d = PersistedSymbolDict::open(dir.path()).unwrap();
            assert_eq!(d.size(), 1);
            d.append_symbol(b"two").unwrap();
        }
        let d = PersistedSymbolDict::open(dir.path()).unwrap();
        assert_eq!(
            d.read_loaded_symbols(),
            vec![b"one".to_vec(), b"two".to_vec()]
        );
    }

    #[test]
    fn loaded_entries_match_wire_delta_shape() {
        let dir = tmp_slot();
        {
            let mut d = PersistedSymbolDict::open(dir.path()).unwrap();
            d.append_symbol(b"a").unwrap();
            d.append_symbol(b"bb").unwrap();
        }
        let d = PersistedSymbolDict::open(dir.path()).unwrap();
        // [len=1]['a'][len=2]['b']['b']
        assert_eq!(d.loaded_entries(), &[1, b'a', 2, b'b', b'b']);
    }

    #[test]
    fn clear_loaded_entries_frees_the_region_but_keeps_size_and_appends() {
        // After the recovered entries are copied out for seeding, the write-ahead
        // handle no longer needs them; clear_loaded_entries frees the (up to ~2 GiB)
        // region without disturbing the append tip (size) or further write-ahead
        // appends.
        let dir = tmp_slot();
        {
            let mut d = PersistedSymbolDict::open(dir.path()).unwrap();
            d.append_symbol(b"alpha").unwrap();
            d.append_symbol(b"bravo").unwrap();
        }
        let mut d = PersistedSymbolDict::open(dir.path()).unwrap();
        assert!(!d.loaded_entries().is_empty());
        assert_eq!(d.size(), 2);

        d.clear_loaded_entries();
        assert!(
            d.loaded_entries().is_empty(),
            "the recovered region is freed"
        );
        assert_eq!(d.size(), 2, "the append tip is unchanged");

        // Write-ahead still works: a new symbol continues at the recovered tip.
        d.append_symbol(b"charlie").unwrap();
        assert_eq!(d.size(), 3);
        drop(d);
        let d = PersistedSymbolDict::open(dir.path()).unwrap();
        assert_eq!(
            d.read_loaded_symbols(),
            vec![b"alpha".to_vec(), b"bravo".to_vec(), b"charlie".to_vec()]
        );
    }

    #[test]
    fn recovered_side_file_seeds_producer_dict_and_continues_ids() {
        use crate::ingress::buffer::SymbolGlobalDict;
        // A previous session persisted two symbols. Recovery seeds the PRODUCER
        // dictionary (the one the encoder assigns ids from) straight from the
        // reopened side-file's raw region -- exactly as `new_store_and_forward` /
        // `QwpWsReplayEncoder::seed_global_dict` do -- so newly ingested symbols
        // continue above the recovered ids instead of colliding at 0. Companion
        // to `recovered_side_file_rebuilds_the_catch_up_dictionary`, which covers
        // the driver's mirror; this covers the producer dict.
        let dir = tmp_slot();
        {
            let mut pd = PersistedSymbolDict::open(dir.path()).unwrap();
            pd.append_symbol(b"alpha").unwrap();
            pd.append_symbol(b"bravo").unwrap();
        }
        let pd = PersistedSymbolDict::open(dir.path()).unwrap();

        let mut dict = SymbolGlobalDict::new();
        dict.seed(pd.loaded_entries(), pd.size()).unwrap();
        assert_eq!(dict.next_id(), 2, "recovered ids 0,1 -> next id is 2");
        // Recovered symbols re-intern to their recovered ids...
        assert_eq!(dict.intern(b"alpha").unwrap(), (0, false));
        assert_eq!(dict.intern(b"bravo").unwrap(), (1, false));
        // ...and a new symbol continues at the recovered watermark.
        assert_eq!(dict.intern(b"charlie").unwrap(), (2, true));
    }

    #[test]
    fn torn_trailing_entry_is_healed_on_open() {
        let dir = tmp_slot();
        {
            let mut d = PersistedSymbolDict::open(dir.path()).unwrap();
            d.append_symbol(b"complete").unwrap();
        }
        // Simulate a crash mid-append: a length prefix claiming more bytes than
        // are present.
        {
            let mut f = OpenOptions::new()
                .append(true)
                .open(dir.path().join(FILE_NAME))
                .unwrap();
            f.write_all(&[9, b'x', b'y']).unwrap(); // says 9 bytes, only 2 follow
        }
        // open() must stop at the torn entry, keep the complete one, and truncate.
        let mut d = PersistedSymbolDict::open(dir.path()).unwrap();
        assert_eq!(d.size(), 1);
        assert_eq!(d.read_loaded_symbols(), vec![b"complete".to_vec()]);
        // The next append overwrites the torn bytes cleanly.
        d.append_symbol(b"next").unwrap();
        drop(d);
        let d = PersistedSymbolDict::open(dir.path()).unwrap();
        assert_eq!(
            d.read_loaded_symbols(),
            vec![b"complete".to_vec(), b"next".to_vec()]
        );
    }

    #[test]
    fn bad_magic_is_recreated_fresh() {
        let dir = tmp_slot();
        fs::write(dir.path().join(FILE_NAME), b"NOPEnope-garbage-content").unwrap();
        let d = PersistedSymbolDict::open(dir.path()).unwrap();
        assert_eq!(d.size(), 0);
        assert!(d.read_loaded_symbols().is_empty());
        // Header was rewritten.
        let bytes = fs::read(dir.path().join(FILE_NAME)).unwrap();
        assert_eq!(
            u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            FILE_MAGIC
        );
    }

    #[test]
    fn open_recovered_returns_none_for_an_absent_or_invalid_dictionary() {
        // A recovered slot must NOT fabricate a fresh empty dictionary: absent,
        // too-short, and bad-magic all yield None so the caller keeps dense
        // (self-sufficient) frames rather than seeding an empty delta dict next to
        // segments that already reference ids [0, K) (which would misresolve those
        // ids to the wrong symbols on the server).
        let dir = tmp_slot();

        // Absent: None, and the file is NOT created.
        assert!(
            PersistedSymbolDict::open_recovered(dir.path())
                .unwrap()
                .is_none()
        );
        assert!(
            !dir.path().join(FILE_NAME).exists(),
            "recovery must not create a side-file"
        );

        // Bad magic: None, and (unlike `open`) the file is left as-is, not rewritten.
        fs::write(dir.path().join(FILE_NAME), b"NOPEnope-garbage-content").unwrap();
        assert!(
            PersistedSymbolDict::open_recovered(dir.path())
                .unwrap()
                .is_none()
        );
        assert_eq!(
            fs::read(dir.path().join(FILE_NAME)).unwrap(),
            b"NOPEnope-garbage-content",
            "recovery must not rewrite a bad-magic file"
        );

        // Present but too short to hold a header: None.
        fs::write(dir.path().join(FILE_NAME), b"SY").unwrap();
        assert!(
            PersistedSymbolDict::open_recovered(dir.path())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn open_recovered_loads_an_existing_valid_dictionary() {
        let dir = tmp_slot();
        {
            let mut d = PersistedSymbolDict::open(dir.path()).unwrap();
            d.append_symbol(b"alpha").unwrap();
            d.append_symbol(b"bravo").unwrap();
        }
        let d = PersistedSymbolDict::open_recovered(dir.path())
            .unwrap()
            .expect("a valid existing dictionary must load for delta recovery");
        assert_eq!(d.size(), 2);
        assert_eq!(
            d.read_loaded_symbols(),
            vec![b"alpha".to_vec(), b"bravo".to_vec()]
        );
    }

    #[test]
    fn zero_extended_tail_is_healed_at_open_by_the_record_crc() {
        // A host/power crash can zero-extend the append-only side-file. Pre-CRC the
        // trailing `0x00` bytes parsed as valid empty `[len=0]` entries that
        // inflated the recovered count (a hazard the orphan drainer's seed gate had
        // to catch later). With the per-record CRC, a zero run cannot form a valid
        // record -- it overruns as a torn record or fails the CRC -- so `open` heals
        // it at recovery and the recovered dictionary stays exactly the real
        // symbols, never inflated.
        let dir = tmp_slot();
        {
            let mut d = PersistedSymbolDict::open(dir.path()).unwrap();
            d.append_symbol(b"old").unwrap();
        }
        {
            let mut f = OpenOptions::new()
                .append(true)
                .open(dir.path().join(FILE_NAME))
                .unwrap();
            // A structurally-complete zero record ([len=0][crc=0]) whose CRC is
            // wrong, plus extra zeros -- all healed.
            f.write_all(&[0u8; 12]).unwrap();
        }

        let d = PersistedSymbolDict::open(dir.path()).unwrap();
        assert_eq!(
            d.size(),
            1,
            "the zero tail is healed at open, not counted as phantom entries"
        );
        assert_eq!(d.read_loaded_symbols(), vec![b"old".to_vec()]);
    }

    #[test]
    fn same_length_value_flip_fails_the_record_crc_and_is_healed() {
        // The Issue-4 corruption: a bit-flip that changes a symbol's VALUE but not
        // its length. Pre-CRC it parsed as a valid (wrong) symbol and seeded the
        // dictionary silently; now the record CRC catches it and `open` heals to the
        // records before it, so recovery never registers the wrong symbol. A queued
        // frame that referenced the dropped id then fails loudly at the send loop's
        // torn-dict guard (StoreResendRequired) rather than corrupting the table.
        let dir = tmp_slot();
        {
            let mut d = PersistedSymbolDict::open(dir.path()).unwrap();
            d.append_symbol(b"alpha").unwrap(); // record 0
            d.append_symbol(b"bravo").unwrap(); // record 1
        }
        let path = dir.path().join(FILE_NAME);
        let mut bytes = fs::read(&path).unwrap();
        // Flip one byte of "bravo" in record 1's payload (record 0 stays intact).
        let idx = bytes
            .windows(5)
            .position(|w| w == b"bravo")
            .expect("bravo payload present");
        bytes[idx] = b'X'; // same length, different value
        fs::write(&path, &bytes).unwrap();

        let d = PersistedSymbolDict::open(dir.path()).unwrap();
        assert_eq!(
            d.read_loaded_symbols(),
            vec![b"alpha".to_vec()],
            "the CRC-failed record is dropped; the corrupt symbol is never recovered"
        );
        assert_eq!(d.size(), 1);
    }

    #[test]
    fn oversized_side_file_is_rejected_without_an_unbounded_read() {
        // A file larger than MAX_FILE_LEN is treated as proven-corrupt (None)
        // BEFORE read_to_end, so a corrupt/oversized `.symbol-dict` cannot drive an
        // OOM abort (read_to_end's allocation is infallible). The cap precedes
        // opening the file, so the real file need not be that large to exercise it.
        let dir = tmp_slot();
        let path = dir.path().join(FILE_NAME);
        assert!(
            PersistedSymbolDict::open_existing(&path, MAX_FILE_LEN + 1)
                .unwrap()
                .is_none(),
            "an over-cap file_len must be rejected as corrupt, not read"
        );

        // A normal-sized existing file still loads at its true (under-cap) length.
        {
            let mut d = PersistedSymbolDict::open(dir.path()).unwrap();
            d.append_symbol(b"ok").unwrap();
        }
        let meta_len = fs::metadata(&path).unwrap().len();
        assert!(meta_len <= MAX_FILE_LEN);
        assert!(
            PersistedSymbolDict::open_existing(&path, meta_len)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn open_does_not_destroy_an_unreadable_side_file() {
        // Unlike a bad-magic file (proven corrupt -> recreated fresh above), a
        // present side-file that cannot be opened/read is a *transient* condition:
        // `open` must surface `Err` and leave the path untouched, never truncate or
        // re-create it. Here the I/O error is forced by putting a directory where
        // the file is expected. On a recovered slot the caller turns this Err into a
        // loud, retryable failure, so a transient hiccup never destroys the
        // load-bearing dictionary and strands all the slot's queued data.
        let dir = tmp_slot();
        let side = dir.path().join(FILE_NAME);
        fs::create_dir(&side).unwrap();
        fs::write(side.join("marker"), b"keep").unwrap();

        assert!(
            PersistedSymbolDict::open(dir.path()).is_err(),
            "an unreadable side-file must yield Err, not a truncating re-create"
        );
        assert!(side.is_dir(), "the side-file path must be left untouched");
        assert_eq!(fs::read(side.join("marker")).unwrap(), b"keep");
    }

    #[test]
    fn remove_orphan_deletes_the_file() {
        let dir = tmp_slot();
        {
            let mut d = PersistedSymbolDict::open(dir.path()).unwrap();
            d.append_symbol(b"x").unwrap();
        }
        assert!(dir.path().join(FILE_NAME).exists());
        PersistedSymbolDict::remove_orphan(dir.path());
        assert!(!dir.path().join(FILE_NAME).exists());
        // Idempotent.
        PersistedSymbolDict::remove_orphan(dir.path());
    }

    #[test]
    fn rollback_discards_symbols_appended_since_mark() {
        let dir = tmp_slot();
        {
            let mut d = PersistedSymbolDict::open(dir.path()).unwrap();
            d.append_symbol(b"alpha").unwrap();
            let mark = d.mark();
            d.append_symbol(b"beta").unwrap();
            assert_eq!(d.size(), 2);
            // Publish failed: undo beta, then the next frame reuses beta's id.
            d.rollback(mark).unwrap();
            assert_eq!(d.size(), 1);
            d.append_symbol(b"gamma").unwrap();
            assert_eq!(d.size(), 2);
        }
        // The reopened file mirrors [alpha, gamma] with no trace of beta.
        let d = PersistedSymbolDict::open(dir.path()).unwrap();
        assert_eq!(
            d.read_loaded_symbols(),
            vec![b"alpha".to_vec(), b"gamma".to_vec()]
        );
    }

    #[test]
    fn rollback_to_current_or_forward_mark_never_extends() {
        let dir = tmp_slot();
        let mut d = PersistedSymbolDict::open(dir.path()).unwrap();
        d.append_symbol(b"one").unwrap();
        let mark1 = d.mark();
        d.append_symbol(b"two").unwrap();
        let mark2 = d.mark();
        // Rollback to the current tip is a no-op.
        d.rollback(mark2).unwrap();
        assert_eq!(d.size(), 2);
        // Roll back past mark2 down to mark1...
        d.rollback(mark1).unwrap();
        assert_eq!(d.size(), 1);
        // ...then replaying the now-stale forward mark2 must not re-extend.
        d.rollback(mark2).unwrap();
        assert_eq!(d.size(), 1);
        drop(d);
        let d = PersistedSymbolDict::open(dir.path()).unwrap();
        assert_eq!(d.read_loaded_symbols(), vec![b"one".to_vec()]);
    }

    #[test]
    fn failed_partial_write_cleanup_poisons_the_handle_and_fails_rollback() {
        // When a partial write's cleanup (set_len/seek back to the tip) fails, the
        // OS cursor is stranded past the logical tip, so the handle must poison
        // itself: a later rollback must FAIL (so the caller drops the handle and
        // disables delta) rather than silently no-op, a later append must fail, and
        // a fresh open must recover clean (the poisoned magic reads as bad-magic).
        let dir = tmp_slot();
        let mut d = PersistedSymbolDict::open(dir.path()).unwrap();
        d.append_symbol(b"alpha").unwrap();
        let mark = d.mark();

        // Force the next append down the failed-partial-write-cleanup path.
        d.fail_next_append_cleanup = true;
        let err = d.append_symbol(b"bravo").unwrap_err();
        assert!(err.to_string().contains("cleanup"), "{err}");

        // Poisoned: rollback fails (not a silent Ok no-op), and further appends fail.
        assert!(
            d.rollback(mark).is_err(),
            "a poisoned handle must fail rollback, not silently no-op -- otherwise \
             the caller never disables delta"
        );
        assert!(
            d.append_symbol(b"charlie").is_err(),
            "a poisoned handle must reject further appends"
        );
        drop(d);

        // The on-disk magic was poisoned, so a fresh open recovers empty.
        let reopened = PersistedSymbolDict::open(dir.path()).unwrap();
        assert_eq!(reopened.size(), 0, "a poisoned side-file recovers fresh");
        assert!(reopened.read_loaded_symbols().is_empty());
    }

    #[test]
    fn varint_round_trip_across_widths() {
        for v in [
            0u64,
            1,
            127,
            128,
            300,
            16_383,
            16_384,
            1 << 20,
            u32::MAX as u64,
        ] {
            let mut out = Vec::new();
            write_varint(&mut out, v);
            let (decoded, pos) = decode_varint(&out, 0).unwrap();
            assert_eq!(decoded, v);
            assert_eq!(pos, out.len());
        }
    }

    #[test]
    fn count_payload_entries_rejects_malformed_payloads_without_panicking() {
        // The per-record CRC only proves the bytes are intact, not that the
        // payload is well-formed; a malformed entry inside a CRC-valid record is a
        // writer bug that must be rejected (record dropped) rather than adopted or
        // panicked on. This pins the module's "Never panics on malformed input"
        // contract.

        // Well-formed: [len=1]['a'][len=2]['b']['c'] -> 2 entries.
        assert_eq!(count_payload_entries(&[1, b'a', 2, b'b', b'c']), Some(2));
        // Empty payload -> 0 entries.
        assert_eq!(count_payload_entries(&[]), Some(0));
        // A single empty ([len=0]) entry.
        assert_eq!(count_payload_entries(&[0]), Some(1));
        // Torn length varint: a lone continuation byte with nothing after it.
        assert_eq!(count_payload_entries(&[0x80]), None);
        // Entry length overruns the payload: claims 5 bytes, only 1 present.
        assert_eq!(count_payload_entries(&[5, b'a']), None);
        // Entry length exceeds the per-entry cap (checked before the body, so no
        // 1 MiB body is needed to reject it).
        let mut over_cap = Vec::new();
        write_varint(&mut over_cap, MAX_ENTRY_LEN + 1);
        over_cap.push(b'x');
        assert_eq!(count_payload_entries(&over_cap), None);
    }

    #[test]
    fn crc_valid_record_with_malformed_payload_is_dropped_at_open() {
        // A CRC-valid record whose payload is malformed (a length varint that
        // overruns the payload) must be dropped at `open` -- `count_payload_entries`
        // rejects it, so `open_existing` stops before adopting it and heals the
        // file -- keeping the earlier valid records and never mis-registering a
        // symbol or panicking.
        let dir = tmp_slot();
        {
            let mut d = PersistedSymbolDict::open(dir.path()).unwrap();
            d.append_symbol(b"good").unwrap(); // record 0: well-formed
        }
        // Append a hand-built record whose CRC is VALID but whose payload is
        // malformed: [payload_len u32][payload][crc32c u32], payload = [len=5]['a']
        // (claims a 5-byte entry, only 1 byte follows).
        {
            let payload = [5u8, b'a'];
            let mut rec = Vec::new();
            rec.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            rec.extend_from_slice(&payload);
            let crc = crc32c::crc32c_append(0, &rec); // over [len_prefix][payload]
            rec.extend_from_slice(&crc.to_le_bytes());
            let mut f = OpenOptions::new()
                .append(true)
                .open(dir.path().join(FILE_NAME))
                .unwrap();
            f.write_all(&rec).unwrap();
        }

        let d = PersistedSymbolDict::open(dir.path()).unwrap();
        assert_eq!(
            d.size(),
            1,
            "the CRC-valid-but-malformed record is dropped, not adopted"
        );
        assert_eq!(d.read_loaded_symbols(), vec![b"good".to_vec()]);
    }
}
