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
//!   offset 0: u32 magic = 'SYD1'
//!   offset 4: u8  version = 1
//!   offset 5: 3 bytes reserved (zero)
//!   offset 8: chunks, each
//!             [entryCount: varint][entryBytes: varint][entries][crc32c: u32]
//!             where entries = [len: varint][utf8] repeated entryCount times,
//!             occupying exactly entryBytes bytes, and the CRC32C covers the two
//!             header varints AND the entry region.
//! ```
//!
//! A *chunk* is one append — exactly the symbols one frame introduces, since the
//! producer persists a frame's new symbols in a single call before publishing it.
//! Symbol id `i` is the `i`-th entry across all chunks (ids are dense and assigned
//! sequentially from 0), so no id needs to be stored. The concatenated entry *wire*
//! bytes (chunk headers and CRCs stripped) are byte-for-byte the shape a QWP
//! delta-dict section carries, so a recovered region can be spliced into a catch-up
//! frame verbatim.
//!
//! The CRC32C is **per chunk, not per entry** — byte-for-byte the layout the Java
//! reference client's `.symbol-dict` uses (`PersistedSymbolDict`), so the two
//! clients stay format-compatible. Per-chunk granularity loses no recoverable
//! prefix: every recoverable frame's `delta_start` falls on a chunk boundary
//! (chunks and frame deltas are written one-for-one), so a tear inside a chunk
//! invalidates exactly the frames a per-entry checksum would have. The same
//! checksum the SF segment frames use (see [`super::qwp_ws_sfa_segment`]) catches a
//! torn, zero-page or stale chunk on recovery and stops the parse there, instead of
//! silently mis-registering a symbol and shifting the dense id->symbol map.
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
//! frames themselves may be lost on a host crash. Two layers keep a host-crash
//! tear from silently corrupting data: the per-chunk CRC32C makes [`open`] stop at
//! the first chunk whose checksum fails — an interior page lost out of order
//! (reading back as zeroes) or a stale chunk left past the end is detected and the
//! trusted region ends before it, so recovery never mis-parses a corrupt chunk nor
//! shifts the dense id->symbol map — and the send loop's replay guard then fails
//! loudly on any surviving frame whose delta start id exceeds that trusted prefix
//! (the unreplayable data must be resent) rather than corrupting the target table.
//! A tear that happens to leave bytes whose CRC still matches is a 1-in-2^32
//! collision per chunk, no weaker than the frames' own checksum.
//!
//! A torn trailing chunk from a crash mid-append is self-healing: [`open`] stops
//! parsing at the first incomplete or CRC-failed chunk and truncates the file
//! there, so the next append overwrites it.
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
// One shared per-entry length cap for ingestion (`SymbolGlobalDict::intern`),
// recovery validation (`SymbolGlobalDict::seed`), and this side-file's
// reader/writer, so all three enforce one bound and cannot diverge. Aliased to
// the local name.
use crate::ingress::buffer::MAX_PERSISTED_SYMBOL_ENTRY_LEN as MAX_ENTRY_LEN;

/// Filename within the slot directory. Dot-prefixed so directory enumerators
/// that filter by the `.sfa` suffix (segment recovery, orphan scan, trim) skip
/// it automatically, exactly like `.lock` and `.ack-watermark`.
pub(crate) const FILE_NAME: &str = ".symbol-dict";

/// `'SYD1'` little-endian, matching the Java reference client's `.symbol-dict`.
/// [`VERSION`] `1` is the per-chunk `[entryCount][entryBytes][entries][crc32c]`
/// framing (see the module docs). [`open`] checks BOTH the magic and the version,
/// so a file with any other magic or version — including this client's superseded
/// per-entry-CRC `v2` — is rejected as proven-incompatible and recovered fresh
/// rather than misparsed.
///
/// [`open`]: PersistedSymbolDict::open
const FILE_MAGIC: u32 = 0x3144_5953;
const HEADER_SIZE: u64 = 8;
const VERSION: u8 = 1;

/// Bytes of the CRC32C trailing every chunk on disk.
const CRC_SIZE: usize = 4;

/// Upper bound on a chunk's two header varints (`entryCount` and `entryBytes`):
/// each is at most 5 bytes for the 32-bit-bounded values this side-file holds
/// (entry count <= `MAX_CONN_SYMBOL_DICT_SIZE`, entry bytes <= the connection
/// heap cap). [`append_symbols_iter`](PersistedSymbolDict::append_symbols_iter)
/// reserves this much in front of the entry region so the header can be back-filled
/// once the region's exact size is known, keeping header, entries and CRC one
/// contiguous run. Matches the Java client's `MAX_CHUNK_HEADER_SIZE`.
const MAX_CHUNK_HEADER_LEN: usize = 10;

/// Upper bound on the side-file size accepted at [`open`](PersistedSymbolDict::open) /
/// [`open_recovered`](PersistedSymbolDict::open_recovered). A legitimate dictionary's
/// UTF-8 bytes are bounded writer-side by the connection heap cap
/// (`MAX_CONN_SYMBOL_DICT_HEAP_BYTES`, 256 MiB, enforced at `intern`); adding the
/// per-entry length prefixes and the per-chunk headers and CRC32Cs keeps a
/// legitimate file well under this ceiling, so a larger file is corrupt. Capping `file_len` before
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
    /// Test-only: fail the next append before writing any byte. This models a
    /// clean write-ahead rejection whose rollback must leave the live handle,
    /// cursor, and on-disk prefix unchanged.
    #[cfg(test)]
    fail_next_append: bool,
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

    /// Test-only: fail the next [`append_symbols`](Self::append_symbols) before
    /// it writes anything, leaving the side-file at its current mark.
    #[cfg(test)]
    pub(crate) fn arm_fail_next_append(&mut self) {
        self.fail_next_append = true;
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
        self.append_symbols_iter(symbols.iter().copied())
    }

    /// Iterator form used by the pooled foreground to stream entries directly
    /// from its global dictionary without allocating an intermediate
    /// `Vec<&[u8]>`. Entries are still batched in the retained append scratch.
    pub(crate) fn append_symbols_iter<'a>(
        &mut self,
        symbols: impl IntoIterator<Item = &'a [u8]>,
    ) -> io::Result<()> {
        if self.poisoned {
            return Err(io::Error::other(
                "persisted symbol dictionary poisoned by a failed partial-write cleanup",
            ));
        }
        let mut symbols = symbols.into_iter().peekable();
        if symbols.peek().is_none() {
            return Ok(());
        }
        #[cfg(test)]
        if self.fail_next_append {
            self.fail_next_append = false;
            return Err(io::Error::other("injected clean append failure"));
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
        // Encode the frame's new symbols as ONE chunk
        // [entryCount varint][entryBytes varint][entries][crc32c], entries =
        // [len varint][utf8] per symbol in id order, the CRC covering the two header
        // varints AND the entry region (matching the Java client and the segment
        // codec) so a torn/stale chunk is caught on recovery instead of silently
        // mis-registering a symbol. Reserve MAX_CHUNK_HEADER_LEN in front so the
        // header can be back-filled once the entry region's size is known, keeping
        // header, entries and CRC one contiguous run written in a single `write_all`
        // (a wide flush does not do a syscall per symbol).
        self.append_scratch.clear();
        self.append_scratch.resize(MAX_CHUNK_HEADER_LEN, 0);
        let mut entry_count = 0u64;
        for symbol in symbols {
            write_varint(&mut self.append_scratch, symbol.len() as u64);
            self.append_scratch.extend_from_slice(symbol);
            entry_count += 1;
        }
        let entry_bytes = (self.append_scratch.len() - MAX_CHUNK_HEADER_LEN) as u64;
        // Back-fill the two header varints immediately before the entry region. The
        // 32-bit-bounded values (entry count <= MAX_CONN_SYMBOL_DICT_SIZE, entry
        // bytes <= the connection heap cap) never fill MAX_CHUNK_HEADER_LEN.
        let mut count_buf = [0u8; MAX_CHUNK_HEADER_LEN];
        let count_len = encode_varint(&mut count_buf, entry_count);
        let mut bytes_buf = [0u8; MAX_CHUNK_HEADER_LEN];
        let bytes_len = encode_varint(&mut bytes_buf, entry_bytes);
        let header_len = count_len + bytes_len;
        debug_assert!(header_len <= MAX_CHUNK_HEADER_LEN);
        let header_start = MAX_CHUNK_HEADER_LEN - header_len;
        self.append_scratch[header_start..header_start + count_len]
            .copy_from_slice(&count_buf[..count_len]);
        self.append_scratch[header_start + count_len..MAX_CHUNK_HEADER_LEN]
            .copy_from_slice(&bytes_buf[..bytes_len]);
        // CRC over the header varints + entry region; appended little-endian.
        let crc = crc32c::crc32c_append(0, &self.append_scratch[header_start..]);
        self.append_scratch.extend_from_slice(&crc.to_le_bytes());
        let batch_len = (self.append_scratch.len() - header_start) as u64;
        // Disjoint field borrows: write the scratch (shared) into the file (mut).
        if let Err(e) = self.file.write_all(&self.append_scratch[header_start..]) {
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
        self.append_offset = start + batch_len;
        self.size += entry_count as u32;
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

    /// Moves the recovered entry region out, leaving the handle with an empty one
    /// (as [`clear_loaded_entries`] would). For a caller that wants to OWN the
    /// region rather than borrow it: a `to_vec` of this region is an infallible
    /// allocation of up to [`MAX_FILE_LEN`] bytes, and Rust's allocator aborts the
    /// host process on OOM -- which the whole reader is written to avoid (it
    /// `try_reserve`s every buffer it builds). Moving costs nothing and cannot
    /// fail.
    ///
    /// [`clear_loaded_entries`]: PersistedSymbolDict::clear_loaded_entries
    pub(crate) fn take_loaded_entries(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.loaded_entries)
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
        // buf.len() >= HEADER_SIZE (== 8) is guaranteed above, so the magic and
        // version bytes are always present — index directly rather than risk a panic.
        if u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) != FILE_MAGIC || buf[4] != VERSION {
            // Proven-corrupt or unknown-version header -> caller re-creates fresh.
            return Ok(None);
        }

        // Parse `[entryCount varint][entryBytes varint][entries][crc32c]` chunks
        // after the header; stop at the first torn/incomplete OR crc-mismatched
        // chunk (self-healing tail). The per-chunk CRC turns an interior tear or a
        // stale post-end chunk into a clean stop point, so recovery trusts only the
        // intact prefix instead of silently mis-parsing a corrupt chunk and shifting
        // the dense id->symbol map. `loaded_entries` is rebuilt as WIRE bytes
        // (`[len][utf8]...`, chunk headers and CRCs stripped) so it stays the
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
            let chunk_start = pos;
            let Some((entry_count, after_count)) = decode_varint(&buf, chunk_start) else {
                break; // torn entryCount varint
            };
            let Some((entry_bytes, entries_start)) = decode_varint(&buf, after_count) else {
                break; // torn entryBytes varint
            };
            // A chunk carries at least one entry occupying at least one byte; a zero
            // count or zero-byte region is a torn/zero-page tail (or corruption).
            if entry_count == 0 || entry_bytes == 0 {
                break;
            }
            let Some(chunk_end) = entries_start.checked_add(entry_bytes as usize) else {
                break;
            };
            let Some(chunk_end_crc) = chunk_end.checked_add(CRC_SIZE) else {
                break;
            };
            if chunk_end_crc > buf.len() {
                break; // torn/incomplete trailing chunk (entries or CRC do not fit)
            }
            let crc_read = u32::from_le_bytes([
                buf[chunk_end],
                buf[chunk_end + 1],
                buf[chunk_end + 2],
                buf[chunk_end + 3],
            ]);
            // CRC covers the two header varints AND the entry region.
            if crc32c::crc32c_append(0, &buf[chunk_start..chunk_end]) != crc_read {
                break; // corrupt / stale chunk -> stop before it (fail-clean)
            }
            // The CRC proves the bytes are what was written, not that the header
            // triple is self-consistent: a producer bug or a torn write that
            // re-checksummed could record a chunk whose entryCount disagrees with
            // its entries, shifting the dense id->symbol map. Verify the region
            // holds exactly entryCount well-formed [len][utf8] entries and is
            // consumed exactly, mirroring the Java client's isConsistentEntryRegion.
            if !is_consistent_entry_region(&buf, entries_start, entry_bytes as usize, entry_count) {
                break;
            }
            let entry_count_u32 = match u32::try_from(entry_count) {
                Ok(c) => c,
                // More entries than a MAX_FILE_LEN-bounded file can hold: corrupt.
                Err(_) => break,
            };
            let Some(new_count) = count.checked_add(entry_count_u32) else {
                break;
            };
            // Wire bytes only: strip the chunk header and CRC so `loaded_entries`
            // stays the shape a delta section / catch-up frame carries.
            loaded_entries.extend_from_slice(&buf[entries_start..chunk_end]);
            count = new_count;
            pos = chunk_end_crc;
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
            #[cfg(test)]
            fail_next_append: false,
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
            #[cfg(test)]
            fail_next_append: false,
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

/// Encodes `value` as an unsigned LEB128 varint into the front of `out`, returning
/// the number of bytes written. `out` must hold at least 10 bytes (the widest a
/// `u64` varint can be); the chunk-header back-fill passes a [`MAX_CHUNK_HEADER_LEN`]
/// buffer.
fn encode_varint(out: &mut [u8], mut value: u64) -> usize {
    let mut i = 0;
    while value > 0x7F {
        out[i] = ((value & 0x7F) as u8) | 0x80;
        value >>= 7;
        i += 1;
    }
    out[i] = value as u8;
    i + 1
}

/// Whether `buf[start .. start + bytes]` holds exactly `count` well-formed
/// `[len varint][utf8]` entries, each within [`MAX_ENTRY_LEN`], and is consumed
/// exactly. Mirrors the Java client's `isConsistentEntryRegion`: the chunk CRC
/// proves the bytes are what was written, not that the header's `entryCount`
/// agrees with the entries it frames, so without this a torn write that happened
/// to re-checksum could shift the dense id->symbol map for every id above it.
///
/// The per-entry cap is checked here rather than left to the caller because this
/// is the only walk that sees individual entry lengths. Enforcing it makes a
/// rejected chunk stop the parse (the same treatment a CRC failure gets), so the
/// intact prefix is kept and `open` truncates the rest -- self-healing. Without
/// it an over-cap entry parses fine here and is instead rejected downstream by
/// `SymbolGlobalDict::seed`, which fails the WHOLE recovered region and leaves
/// the offending bytes on disk for every later open to re-read and re-reject.
/// `intern` caps ingestion at the same bound, so no legitimate writer -- this
/// client's or the Java client's, whose dictionary the server bounds identically
/// -- can produce an entry this rejects.
fn is_consistent_entry_region(buf: &[u8], start: usize, bytes: usize, count: u64) -> bool {
    let mut p = start;
    let limit = start + bytes;
    for _ in 0..count {
        let Some((len, after_len)) = decode_varint(buf, p) else {
            return false;
        };
        // Defence in depth: `intern` rejects oversized symbols before they are
        // written, so a longer length on disk is corrupt.
        if len > MAX_ENTRY_LEN {
            return false;
        }
        let Some(end) = after_len.checked_add(len as usize) else {
            return false;
        };
        if end > limit {
            return false;
        }
        p = end;
    }
    p == limit
}

/// Splits a side-file into its chunks, each as the list of symbols it carries,
/// so a test can assert on chunk *framing* -- how many appends the file holds
/// and what each one carried -- rather than only on the flat entry list
/// [`read_loaded_symbols`](PersistedSymbolDict::read_loaded_symbols) returns.
/// That distinction is what pins the one-chunk-per-frame invariant the
/// per-chunk blast-radius argument rests on (see the module docs); assertions
/// over the flat list stay green if the writer coalesces or splits chunks.
///
/// Mirrors [`open_existing`](PersistedSymbolDict::open_existing)'s walk and
/// panics on a malformed file -- callers are asserting on a file a correct
/// writer produced.
///
/// The header is VALIDATED, not merely stepped over. Callers assert
/// `parse_chunks(..).is_empty()` to mean "a valid, untorn, zero-chunk
/// dictionary" -- the empty-vs-corrupt distinction the delta-armed recovery
/// tests exist to pin -- but every file `open_existing` rejects outright
/// (shorter than the header, bad magic, unknown version) carries no parsable
/// chunk either and would satisfy a bare `is_empty()` just as well. Rejecting
/// those here is what makes "no chunks" mean an empty dictionary rather than
/// only "nothing was parsed".
#[cfg(test)]
pub(crate) fn parse_chunks(path: &Path) -> Vec<Vec<Vec<u8>>> {
    let buf = fs::read(path).unwrap();
    assert!(
        buf.len() >= HEADER_SIZE as usize,
        "side-file holds {} bytes, short of the {HEADER_SIZE}-byte header",
        buf.len()
    );
    assert_eq!(
        u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
        FILE_MAGIC,
        "side-file magic"
    );
    assert_eq!(buf[4], VERSION, "side-file version");
    let mut pos = HEADER_SIZE as usize;
    let mut chunks = Vec::new();
    while pos < buf.len() {
        let (entry_count, after_count) = decode_varint(&buf, pos).expect("entryCount varint");
        let (entry_bytes, entries_start) = decode_varint(&buf, after_count).expect("entryBytes");
        let chunk_end = entries_start + entry_bytes as usize;
        let mut entries = Vec::new();
        let mut p = entries_start;
        for _ in 0..entry_count {
            let (len, after_len) = decode_varint(&buf, p).expect("entry length varint");
            let end = after_len + len as usize;
            entries.push(buf[after_len..end].to_vec());
            p = end;
        }
        assert_eq!(p, chunk_end, "entry region consumed exactly");
        chunks.push(entries);
        pos = chunk_end + CRC_SIZE;
    }
    chunks
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::path::PathBuf;
    use std::process::Command;

    use super::*;

    /// Bytes written by the Java reference client's `PersistedSymbolDict` (see
    /// `src/tests/interop/qwp-ws-sfa/README.md` for provenance and how to
    /// regenerate). Two chunks: `["one"]` then `["two", "three"]` -- a
    /// single-entry chunk and a multi-entry one, so the fixture pins the framing
    /// the per-chunk CRC exists for, not just the degenerate one-symbol case.
    const JAVA_SYMBOL_DICT_FIXTURE_HEX: &str =
        include_str!("../../tests/interop/qwp-ws-sfa/java-two-chunk.symbol-dict.hex");
    /// The same Java bytes with one value byte flipped inside chunk 1 (`'t'` of
    /// `"two"` -> `'u'`): same length, so only that chunk's stored CRC goes stale.
    const JAVA_SYMBOL_DICT_TORN_FIXTURE_HEX: &str =
        include_str!("../../tests/interop/qwp-ws-sfa/java-two-chunk-torn-tail.symbol-dict.hex");

    /// Offset of the byte the torn fixture flips, and the offset recovery must
    /// truncate back to once chunk 1 is rejected (= the end of chunk 0).
    const TORN_BYTE_OFFSET: usize = 21;
    const TORN_TRUNCATED_LEN: u64 = 18;

    fn tmp_slot() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn java_symbol_dict_fixture() -> Vec<u8> {
        decode_hex_fixture(JAVA_SYMBOL_DICT_FIXTURE_HEX)
    }

    fn java_symbol_dict_torn_fixture() -> Vec<u8> {
        decode_hex_fixture(JAVA_SYMBOL_DICT_TORN_FIXTURE_HEX)
    }

    fn decode_hex_fixture(hex: &str) -> Vec<u8> {
        let mut nibbles = Vec::new();
        for byte in hex.bytes() {
            let value = match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                b' ' | b'\n' | b'\r' | b'\t' => continue,
                other => panic!("invalid hex byte {other:?} in fixture"),
            };
            nibbles.push(value);
        }
        assert!(nibbles.len().is_multiple_of(2), "odd hex nibble count");
        nibbles
            .chunks(2)
            .map(|pair| (pair[0] << 4) | pair[1])
            .collect()
    }

    fn format_hex_fixture(bytes: &[u8]) -> String {
        let mut output = String::new();
        for (index, byte) in bytes.iter().enumerate() {
            if index > 0 && index.is_multiple_of(24) {
                output.push('\n');
            }
            output.push_str(&format!("{byte:02x}"));
        }
        output
    }

    /// Writes the fixture's two chunks through the Rust writer, exactly as a
    /// producer does: one `append` per frame, carrying that frame's new symbols.
    fn write_fixture_chunks(dict: &mut PersistedSymbolDict) {
        dict.append_symbol(b"one").unwrap();
        dict.append_symbols(&[b"two".as_slice(), b"three".as_slice()])
            .unwrap();
    }

    #[test]
    fn reads_java_symbol_dict_golden_bytes() {
        // The module docs claim this side-file is "byte-for-byte the layout the
        // Java reference client's `.symbol-dict` uses". Round-trip tests cannot
        // check that -- they stay green while both ends of this client drift
        // together -- so the claim rests on bytes the Java client actually wrote.
        // Read half: the Rust reader must recover Java's dictionary exactly,
        // including the chunk boundaries, since a `delta_start` lands on each one.
        let dir = tmp_slot();
        let path = dir.path().join(FILE_NAME);
        fs::write(&path, java_symbol_dict_fixture()).unwrap();

        let dict = PersistedSymbolDict::open_recovered(dir.path())
            .unwrap()
            .expect("the Java-written side-file must open, not be rejected");

        assert_eq!(dict.size(), 3);
        assert_eq!(
            dict.read_loaded_symbols(),
            vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec()]
        );
        assert_eq!(
            parse_chunks(&path),
            vec![
                vec![b"one".to_vec()],
                vec![b"two".to_vec(), b"three".to_vec()],
            ],
            "chunk boundaries must survive the read: every recoverable frame's \
             delta_start falls on one"
        );
        // The concatenated entry region is spliced verbatim into a catch-up
        // frame, so it too must match Java's wire shape.
        assert_eq!(
            dict.loaded_entries(),
            &[
                3, b'o', b'n', b'e', 3, b't', b'w', b'o', 5, b't', b'h', b'r', b'e', b'e'
            ][..]
        );
    }

    #[test]
    fn writes_java_compatible_symbol_dict_bytes() {
        // Write half of the parity claim: the same two appends a Java producer
        // makes must leave byte-identical bytes on disk -- header, varint
        // encoding, chunk framing and CRC32C alike. Java truncates its mmap
        // reserve to the logical length on close, so the lengths are comparable
        // with no normalization (unlike the `.sfa` fixtures' `createdMicros`).
        let dir = tmp_slot();
        {
            let mut dict = PersistedSymbolDict::open(dir.path()).unwrap();
            write_fixture_chunks(&mut dict);
        }

        let bytes = fs::read(dir.path().join(FILE_NAME)).unwrap();
        assert_eq!(
            format_hex_fixture(&bytes),
            format_hex_fixture(&java_symbol_dict_fixture()),
            "Rust-written side-file diverged from the Java golden bytes"
        );
    }

    #[test]
    fn recovers_the_intact_prefix_of_a_torn_java_symbol_dict() {
        // Cross-client agreement on the failure path, which is the one that
        // decides how much data is recoverable: a flipped byte inside Java's
        // second chunk must cost exactly that chunk. Rust stops at the first
        // CRC failure, keeps chunk 0, and truncates the torn tail so the next
        // append overwrites it.
        let dir = tmp_slot();
        let path = dir.path().join(FILE_NAME);
        fs::write(&path, java_symbol_dict_torn_fixture()).unwrap();

        let dict = PersistedSymbolDict::open_recovered(dir.path())
            .unwrap()
            .expect("a torn tail is healed, not rejected outright");

        assert_eq!(dict.size(), 1);
        assert_eq!(dict.read_loaded_symbols(), vec![b"one".to_vec()]);
        drop(dict);
        assert_eq!(
            fs::metadata(&path).unwrap().len(),
            TORN_TRUNCATED_LEN,
            "the torn chunk must be truncated away, back to the end of chunk 0"
        );
    }

    #[test]
    #[ignore = "requires QDB_JAVA_CLIENT_CORE or the local Java client checkout"]
    fn java_and_rust_read_each_others_symbol_dicts() {
        // Proves the committed fixtures against the Java source, both directions.
        // Mirrors `qwp_ws_sfa_segment::java_and_rust_read_each_others_segments`.
        let fixture = JavaSymbolDictFixture::compile();

        // Java writes -> Rust reads, and the bytes are the committed fixture.
        let java_dir = tmp_slot();
        fixture.run(&["write", java_dir.path().to_str().unwrap()]);
        let java_bytes = fs::read(java_dir.path().join(FILE_NAME)).unwrap();
        assert_eq!(java_bytes, java_symbol_dict_fixture());
        let dict = PersistedSymbolDict::open_recovered(java_dir.path())
            .unwrap()
            .unwrap();
        assert_eq!(
            dict.read_loaded_symbols(),
            vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec()]
        );
        drop(dict);

        // Rust writes -> Java reads.
        let rust_dir = tmp_slot();
        {
            let mut dict = PersistedSymbolDict::open(rust_dir.path()).unwrap();
            write_fixture_chunks(&mut dict);
        }
        let report = fixture.run(&["read", rust_dir.path().to_str().unwrap()]);
        assert_report_contains(&report, "size=3");
        assert_report_contains(&report, "symbol.0=one");
        assert_report_contains(&report, "symbol.1=two");
        assert_report_contains(&report, "symbol.2=three");

        // Torn agreement: Java's own bytes with the fixture's flip must leave
        // Java recovering the same single-symbol prefix Rust does.
        let torn_dir = tmp_slot();
        fixture.run(&["write", torn_dir.path().to_str().unwrap()]);
        let torn_path = torn_dir.path().join(FILE_NAME);
        let mut torn = fs::read(&torn_path).unwrap();
        torn[TORN_BYTE_OFFSET] ^= 0x01;
        assert_eq!(torn, java_symbol_dict_torn_fixture());
        fs::write(&torn_path, &torn).unwrap();
        let report = fixture.run(&["read", torn_dir.path().to_str().unwrap()]);
        assert_report_contains(&report, "size=1");
        assert_report_contains(&report, "symbol.0=one");
    }

    #[test]
    #[ignore = "prints regenerated Java .symbol-dict fixture hex"]
    fn print_java_symbol_dict_fixture_hex() {
        let fixture = JavaSymbolDictFixture::compile();
        let dir = tmp_slot();
        fixture.run(&["write", dir.path().to_str().unwrap()]);

        let bytes = fs::read(dir.path().join(FILE_NAME)).unwrap();
        println!(
            "java-two-chunk.symbol-dict.hex:\n{}",
            format_hex_fixture(&bytes)
        );

        let mut torn = bytes.clone();
        torn[TORN_BYTE_OFFSET] ^= 0x01;
        println!(
            "java-two-chunk-torn-tail.symbol-dict.hex:\n{}",
            format_hex_fixture(&torn)
        );
    }

    fn assert_report_contains(report: &str, expected: &str) {
        assert!(
            report.lines().any(|line| line == expected),
            "missing Java report line {expected:?} in:\n{report}"
        );
    }

    struct JavaSymbolDictFixture {
        _work_dir: tempfile::TempDir,
        classpath: String,
    }

    impl JavaSymbolDictFixture {
        fn compile() -> Self {
            let core_dir = java_client_core_dir();
            let work_dir = tmp_slot();
            let source_path = work_dir.path().join("SymbolDictInteropHelper.java");
            fs::write(&source_path, JAVA_HELPER_SOURCE).unwrap();
            let classes_dir = work_dir.path().join("classes");
            fs::create_dir(&classes_dir).unwrap();

            let classpath = java_client_classpath(&core_dir, work_dir.path());
            run_command(
                Command::new("javac")
                    .arg("-d")
                    .arg(&classes_dir)
                    .arg("-cp")
                    .arg(&classpath)
                    .arg(&source_path),
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
            command.arg("SymbolDictInteropHelper");
            command.args(args);
            run_command(&mut command)
        }
    }

    fn java_client_core_dir() -> PathBuf {
        env::var_os("QDB_JAVA_CLIENT_CORE")
            .map(PathBuf::from)
            .expect(
                "set QDB_JAVA_CLIENT_CORE to the Java client's `core` directory \
                 (the one holding pom.xml and target/classes)",
            )
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

    /// Writes the two-chunk fixture through the Java client's real
    /// `PersistedSymbolDict`: `appendSymbol` for the single-entry chunk, then
    /// `appendSymbols` over a `GlobalSymbolDictionary` range for the multi-entry
    /// one -- the two append shapes a Java producer actually uses.
    const JAVA_HELPER_SOURCE: &str = r#"
import io.questdb.client.cutlass.qwp.client.GlobalSymbolDictionary;
import io.questdb.client.cutlass.qwp.client.sf.cursor.PersistedSymbolDict;
import io.questdb.client.std.ObjList;

public final class SymbolDictInteropHelper {
    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            throw new IllegalArgumentException("usage: SymbolDictInteropHelper <write|read> <slotDir>");
        }
        if ("write".equals(args[0])) {
            write(args[1]);
        } else if ("read".equals(args[0])) {
            read(args[1]);
        } else {
            throw new IllegalArgumentException("unknown command: " + args[0]);
        }
    }

    private static void write(String slotDir) {
        PersistedSymbolDict dict = PersistedSymbolDict.openClean(slotDir);
        try {
            dict.appendSymbol("one");
            GlobalSymbolDictionary global = new GlobalSymbolDictionary();
            global.getOrAddSymbol("one");
            global.getOrAddSymbol("two");
            global.getOrAddSymbol("three");
            dict.appendSymbols(global, 1, 2);
            System.out.println("size=" + dict.size());
        } finally {
            dict.close();
        }
    }

    private static void read(String slotDir) {
        PersistedSymbolDict dict = PersistedSymbolDict.open(slotDir);
        if (dict == null) {
            System.out.println("dict=null");
            return;
        }
        try {
            System.out.println("size=" + dict.size());
            System.out.println("recoveredSize=" + dict.recoveredSize());
            ObjList<String> symbols = dict.readLoadedSymbols();
            for (int i = 0, n = symbols.size(); i < n; i++) {
                System.out.println("symbol." + i + "=" + symbols.getQuick(i));
            }
        } finally {
            dict.close();
        }
    }
}
"#;

    /// Builds a CRC-valid chunk from a raw entry region and an `entryCount` that
    /// need not agree with it, so a test can pin what the reader does with a
    /// header no correct writer would emit.
    fn crafted_chunk(entry_count: u64, entries: &[u8]) -> Vec<u8> {
        let mut chunk = Vec::new();
        write_varint(&mut chunk, entry_count);
        write_varint(&mut chunk, entries.len() as u64);
        chunk.extend_from_slice(entries);
        let crc = crc32c::crc32c_append(0, &chunk);
        chunk.extend_from_slice(&crc.to_le_bytes());
        chunk
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
        // The write-ahead path streams a frame's new symbols into retained scratch
        // and persists them with one write_all. The on-disk result must be identical
        // to per-symbol appends: entries in id order, empty symbols preserved, and
        // ids continuing across successive batches.
        let dir = tmp_slot();
        {
            let mut d = PersistedSymbolDict::open(dir.path()).unwrap();
            let first: [&[u8]; 3] = [b"AAPL", b"", b"GOOG"];
            d.append_symbols_iter(first).unwrap();
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
        // Simulate a crash mid-append: a chunk header claiming an entry region
        // larger than the bytes actually present.
        {
            let mut f = OpenOptions::new()
                .append(true)
                .open(dir.path().join(FILE_NAME))
                .unwrap();
            f.write_all(&[1, 9, b'x']).unwrap(); // entryCount=1, entryBytes=9, only 1 byte follows
        }
        // open() must stop at the torn chunk, keep the complete one, and truncate.
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
    fn zero_extended_tail_is_healed_at_open() {
        // A host/power crash can zero-extend the append-only side-file. A zero run
        // cannot form a valid chunk: its leading `entryCount` varint decodes to 0,
        // which `open` rejects outright (and even a non-zero count would fail the
        // per-chunk CRC, whose all-zero trailing bytes never match a real chunk). So
        // `open` heals the tail at recovery and the recovered dictionary stays
        // exactly the real symbols, never inflated with phantom entries.
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
    fn same_length_value_flip_fails_the_per_chunk_crc_and_is_healed() {
        // The Issue-4 corruption: a bit-flip that changes a symbol's VALUE but not
        // its length. Without a CRC it parsed as a valid (wrong) symbol and seeded
        // the dictionary silently; now the per-chunk CRC catches it and `open` heals
        // to the chunks before it, so recovery never registers the wrong symbol. A
        // queued frame that referenced the dropped id then fails loudly at the send
        // loop's torn-dict guard (StoreResendRequired) rather than corrupting the
        // table.
        let dir = tmp_slot();
        {
            let mut d = PersistedSymbolDict::open(dir.path()).unwrap();
            d.append_symbol(b"alpha").unwrap(); // chunk 0 (entry 0)
            d.append_symbol(b"bravo").unwrap(); // chunk 1 (entry 1)
        }
        let path = dir.path().join(FILE_NAME);
        let mut bytes = fs::read(&path).unwrap();
        // Flip one byte of "bravo" (chunk 1's utf8); chunk 0 stays intact.
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
            "the CRC-failed chunk is dropped; the corrupt symbol is never recovered"
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
    fn over_cap_entry_len_is_rejected_at_open() {
        // Defence in depth: `intern` caps a symbol at MAX_ENTRY_LEN before it is
        // written, so a longer length on disk is corrupt and must be stopped at
        // `open` -- keeping the intact prefix and truncating the rest. Left to
        // `SymbolGlobalDict::seed` instead, the over-cap entry would fail the WHOLE
        // recovered region (not just the frames above it) AND stay on disk, so every
        // later open re-reads and re-rejects it and the slot never drains.
        //
        // The chunk below is deliberately self-CONSISTENT -- its region really does
        // hold the bytes its length claims -- so the CRC, the entry-region walk and
        // the file-size cap all pass it. Only the per-entry cap rejects it; without
        // that check this test adopts the entry and fails.
        let dir = tmp_slot();
        {
            let mut d = PersistedSymbolDict::open(dir.path()).unwrap();
            d.append_symbol(b"good").unwrap(); // chunk 0: well-formed
        }
        let good_len = fs::metadata(dir.path().join(FILE_NAME)).unwrap().len();
        {
            let over = MAX_ENTRY_LEN + 1;
            let mut entries = Vec::new();
            write_varint(&mut entries, over);
            entries.resize(entries.len() + over as usize, b'x');
            let mut chunk = Vec::new();
            write_varint(&mut chunk, 1); // entryCount
            write_varint(&mut chunk, entries.len() as u64); // entryBytes
            chunk.extend_from_slice(&entries);
            let crc = crc32c::crc32c_append(0, &chunk);
            chunk.extend_from_slice(&crc.to_le_bytes());
            let mut f = OpenOptions::new()
                .append(true)
                .open(dir.path().join(FILE_NAME))
                .unwrap();
            f.write_all(&chunk).unwrap();
        }

        let d = PersistedSymbolDict::open(dir.path()).unwrap();
        assert_eq!(d.size(), 1, "the over-cap entry is stopped, not adopted");
        assert_eq!(d.read_loaded_symbols(), vec![b"good".to_vec()]);
        // Self-healing: the rejected chunk is physically gone, so a later open does
        // not re-read it and the slot can keep appending.
        assert_eq!(
            fs::metadata(dir.path().join(FILE_NAME)).unwrap().len(),
            good_len,
            "the over-cap chunk is truncated away, leaving only the good chunk"
        );
    }

    #[test]
    fn inconsistent_chunk_header_is_rejected_not_misattributed() {
        // A chunk whose header claims more entries than its region holds -- a
        // producer bug or a torn write that happened to re-checksum -- must be
        // stopped at `open` (the same treatment a CRC failure gets) rather than
        // shifting the dense id->symbol map. The chunk CRC alone cannot catch this:
        // it proves the bytes are what was written, not that entryCount agrees with
        // the entries. Mirrors the Java client's isConsistentEntryRegion guard.
        let dir = tmp_slot();
        {
            let mut d = PersistedSymbolDict::open(dir.path()).unwrap();
            d.append_symbol(b"good").unwrap(); // chunk 0: well-formed
        }
        // Hand-append a CRC-valid chunk that claims entryCount=2 but whose region
        // holds exactly ONE [len][utf8] entry, so the consistency walk rejects it.
        {
            let entries: &[u8] = &[1, b'x']; // one entry: [len=1]['x']
            let mut chunk = Vec::new();
            write_varint(&mut chunk, 2); // entryCount (claims two)
            write_varint(&mut chunk, entries.len() as u64); // entryBytes
            chunk.extend_from_slice(entries);
            let crc = crc32c::crc32c_append(0, &chunk);
            chunk.extend_from_slice(&crc.to_le_bytes());
            let mut f = OpenOptions::new()
                .append(true)
                .open(dir.path().join(FILE_NAME))
                .unwrap();
            f.write_all(&chunk).unwrap();
        }

        let d = PersistedSymbolDict::open(dir.path()).unwrap();
        assert_eq!(
            d.size(),
            1,
            "the inconsistent chunk is stopped, not adopted"
        );
        assert_eq!(d.read_loaded_symbols(), vec![b"good".to_vec()]);
    }

    #[test]
    fn interior_corruption_is_caught_not_silently_misattributed() {
        // A host-crash interior tear (a lost page reading back as zeroes) or a stale
        // chunk left past the end can change the bytes of a NON-trailing chunk.
        // Without the per-chunk CRC the parse would accept those bytes, shifting the
        // dense id->symbol map and silently misattributing symbol-column values on
        // replay. With the CRC the corrupt chunk fails verification and the parse
        // stops there, so recovery trusts only the intact prefix (fail-clean: the
        // send loop's torn-dict guard then forces a resend of the rest). Mirrors the
        // Java client's testInteriorCorruptionIsCaughtNotSilentlyMisattributed.
        let dir = tmp_slot();
        {
            let mut d = PersistedSymbolDict::open(dir.path()).unwrap();
            for s in [b"s0", b"s1", b"s2", b"s3", b"s4"] {
                d.append_symbol(s).unwrap();
            }
            assert_eq!(d.size(), 5);
        }

        // Each append is its own chunk; flip a byte of "s2"'s utf8 (located via its
        // on-wire `[len=2]"s2"` entry) so chunk 2's stored CRC goes stale while the
        // chunks before it stay intact.
        let path = dir.path().join(FILE_NAME);
        let mut bytes = fs::read(&path).unwrap();
        let idx = bytes
            .windows(3)
            .position(|w| w == b"\x02s2")
            .expect("s2 entry present");
        bytes[idx + 1] ^= 0x7F; // flip the 's' of "s2"
        fs::write(&path, &bytes).unwrap();

        let d = PersistedSymbolDict::open(dir.path()).unwrap();
        // Only the intact prefix [s0, s1] is trusted; the corrupt chunk 2 and
        // everything after it are dropped. No recovered symbol is the corrupted string.
        assert_eq!(d.size(), 2, "parse must stop at the corrupt interior chunk");
        assert_eq!(
            d.read_loaded_symbols(),
            vec![b"s0".to_vec(), b"s1".to_vec()]
        );
    }

    #[test]
    fn a_torn_multi_symbol_chunk_drops_every_entry_it_carries() {
        // The per-chunk CRC's blast radius is a whole chunk, and a chunk is one
        // frame's new symbols -- so corrupting the LAST entry of a multi-symbol
        // chunk drops every entry in it, including the intact ones before it. The
        // superseded per-entry CRC would have kept those. Every other corruption
        // test here appends one symbol per chunk, which makes chunk boundaries
        // coincide with entry boundaries and hides this entirely.
        //
        // This is safe -- not merely tolerated -- precisely because chunks and
        // frame deltas are written one-for-one (`append_symbols*` is called once
        // per frame with exactly that frame's new symbols). The trusted prefix
        // therefore always ends on a chunk boundary, which is always some frame's
        // `delta_start`, so a tear invalidates exactly the frames a per-entry
        // checksum would have. This test pins both halves: the whole torn chunk
        // goes, and the chunk before it is kept whole.
        let dir = tmp_slot();
        let path = dir.path().join(FILE_NAME);
        let after_first_chunk;
        {
            let mut d = PersistedSymbolDict::open(dir.path()).unwrap();
            // Frame 1 -> chunk 0, three entries in ONE append.
            d.append_symbols(&[b"alpha", b"bravo", b"charlie"]).unwrap();
            after_first_chunk = fs::metadata(&path).unwrap().len();
            // Frame 2 -> chunk 1, two entries in ONE append.
            d.append_symbols(&[b"delta", b"echo"]).unwrap();
            assert_eq!(d.size(), 5);
        }

        // Flip a byte of "echo" -- the LAST entry of chunk 1 -- so chunk 1's CRC
        // goes stale while chunk 0 stays intact. Located via its on-wire
        // `[len=4]"echo"` entry so the search cannot hit a header varint.
        let mut bytes = fs::read(&path).unwrap();
        let idx = bytes
            .windows(5)
            .position(|w| w == b"\x04echo")
            .expect("echo entry present");
        bytes[idx + 1] = b'X'; // same length, different value
        fs::write(&path, &bytes).unwrap();

        let d = PersistedSymbolDict::open(dir.path()).unwrap();
        assert_eq!(
            d.read_loaded_symbols(),
            vec![b"alpha".to_vec(), b"bravo".to_vec(), b"charlie".to_vec()],
            "the torn chunk is dropped WHOLE -- `delta` was intact and precedes the \
             corrupted `echo` in the same chunk, and is still lost; chunk 0 is kept \
             entire"
        );
        assert_eq!(d.size(), 3);
        assert_eq!(
            fs::metadata(&path).unwrap().len(),
            after_first_chunk,
            "the torn chunk is truncated away, leaving exactly the intact prefix chunk"
        );
    }

    #[test]
    fn a_crc_valid_empty_chunk_stops_the_parse() {
        // The `entry_count == 0 || entry_bytes == 0` guard earns its place on
        // exactly one shape: a CRC-valid chunk claiming ZERO entries in a
        // ZERO-byte region. `is_consistent_entry_region` cannot catch that one --
        // zero entries really do consume exactly zero bytes, so the walk returns
        // true -- and without the guard the chunk is silently SKIPPED, the parse
        // continuing past it to adopt whatever follows as if the dense
        // id->symbol map were unbroken. That is what this test pins.
        //
        // Every other zero-ish shape the walk rejects on its own, so the guard's
        // two halves are redundant with EACH OTHER here rather than each covering
        // a distinct case: (count 0, bytes > 0) and (count > 0, bytes 0) both fail
        // the walk (see `a_chunk_claiming_entries_in_a_zero_byte_region_is_rejected`).
        // Mutation-checked: deleting the guard entirely fails this test; deleting
        // either half alone does not.
        let dir = tmp_slot();
        let path = dir.path().join(FILE_NAME);
        {
            let mut d = PersistedSymbolDict::open(dir.path()).unwrap();
            d.append_symbol(b"good").unwrap(); // chunk 0: well-formed
        }
        let good_len = fs::metadata(&path).unwrap().len();

        // Chunk 1: CRC-valid but empty (entryCount = 0, entryBytes = 0).
        // Chunk 2: a well-formed entry the parse must NOT reach.
        {
            let mut tail = Vec::new();
            let mut empty = Vec::new();
            write_varint(&mut empty, 0); // entryCount
            write_varint(&mut empty, 0); // entryBytes
            let crc = crc32c::crc32c_append(0, &empty);
            empty.extend_from_slice(&crc.to_le_bytes());
            tail.extend_from_slice(&empty);

            let entries: &[u8] = &[4, b'l', b'a', b't', b'e']; // [len=4]"late"
            let mut late = Vec::new();
            write_varint(&mut late, 1);
            write_varint(&mut late, entries.len() as u64);
            late.extend_from_slice(entries);
            let crc = crc32c::crc32c_append(0, &late);
            late.extend_from_slice(&crc.to_le_bytes());
            tail.extend_from_slice(&late);

            let mut f = OpenOptions::new().append(true).open(&path).unwrap();
            f.write_all(&tail).unwrap();
        }

        let d = PersistedSymbolDict::open(dir.path()).unwrap();
        assert_eq!(
            d.read_loaded_symbols(),
            vec![b"good".to_vec()],
            "the parse must stop AT the empty chunk, not skip it and adopt `late`"
        );
        assert_eq!(d.size(), 1);
        assert_eq!(
            fs::metadata(&path).unwrap().len(),
            good_len,
            "the empty chunk and everything after it is truncated away"
        );
    }

    #[test]
    fn a_chunk_claiming_entries_in_a_zero_byte_region_is_rejected() {
        // The complementary shape: a non-zero entryCount over a zero-byte region.
        // The header guard rejects it first, but `is_consistent_entry_region`
        // would too -- a 0-byte region cannot hold the >=1 entry the header claims
        // -- so this pins the outcome rather than gating the guard.
        // Mutation-checked: deleting the guard entirely leaves this test passing.
        // Kept because a parser for crash-torn input should not depend on that
        // redundancy holding as the walk evolves.
        let dir = tmp_slot();
        let path = dir.path().join(FILE_NAME);
        {
            let mut d = PersistedSymbolDict::open(dir.path()).unwrap();
            d.append_symbol(b"good").unwrap();
        }
        let good_len = fs::metadata(&path).unwrap().len();
        {
            let mut chunk = Vec::new();
            write_varint(&mut chunk, 3); // entryCount claims three...
            write_varint(&mut chunk, 0); // ...in a zero-byte region
            let crc = crc32c::crc32c_append(0, &chunk);
            chunk.extend_from_slice(&crc.to_le_bytes());
            let mut f = OpenOptions::new().append(true).open(&path).unwrap();
            f.write_all(&chunk).unwrap();
        }

        let d = PersistedSymbolDict::open(dir.path()).unwrap();
        assert_eq!(d.read_loaded_symbols(), vec![b"good".to_vec()]);
        assert_eq!(d.size(), 1);
        assert_eq!(fs::metadata(&path).unwrap().len(), good_len);
    }

    #[test]
    fn unknown_version_is_recreated_fresh() {
        // A file with the right magic but an unrecognised version byte (e.g. this
        // client's superseded per-entry v2 file, or a future format) is
        // proven-incompatible: `open` checks magic AND version and recreates fresh
        // rather than misparsing.
        let dir = tmp_slot();
        let path = dir.path().join(FILE_NAME);
        // Valid magic, header-only, but version 2 (the superseded per-entry layout).
        let mut header = [0u8; HEADER_SIZE as usize];
        header[0..4].copy_from_slice(&FILE_MAGIC.to_le_bytes());
        header[4] = 2;
        fs::write(&path, header).unwrap();

        let d = PersistedSymbolDict::open(dir.path()).unwrap();
        assert_eq!(d.size(), 0, "an unknown-version file recovers fresh");
        assert!(d.read_loaded_symbols().is_empty());
        // The header was rewritten to the current version.
        let bytes = fs::read(&path).unwrap();
        assert_eq!(bytes[4], VERSION);
    }

    #[test]
    fn open_recovered_rejects_an_unknown_version_without_touching_the_file() {
        // `unknown_version_is_recreated_fresh` covers `open` (fresh re-create).
        // The RECOVERED path is the one the format switch makes live: every
        // pre-existing v2 side-file takes it on the first run after the change,
        // beside segments that already reference ids [0, K). It must report "no
        // usable dictionary" so the caller falls back to dense, and -- like the
        // bad-magic case -- leave the bytes alone rather than rewriting a file
        // whose contents it could not interpret.
        let dir = tmp_slot();
        let path = dir.path().join(FILE_NAME);
        // Valid magic, superseded per-entry v2 layout, with a v2-shaped body.
        let mut file = Vec::new();
        file.extend_from_slice(&FILE_MAGIC.to_le_bytes());
        file.push(2); // version
        file.extend_from_slice(&[0, 0, 0]); // reserved
        let mut entry = Vec::new();
        write_varint(&mut entry, 5);
        entry.extend_from_slice(b"alpha");
        let crc = crc32c::crc32c_append(0, &entry);
        entry.extend_from_slice(&crc.to_le_bytes());
        file.extend_from_slice(&entry);
        fs::write(&path, &file).unwrap();

        assert!(
            PersistedSymbolDict::open_recovered(dir.path())
                .unwrap()
                .is_none(),
            "an unknown-version file yields no dictionary on the recovered path"
        );
        assert_eq!(
            fs::read(&path).unwrap(),
            file,
            "recovery must not rewrite a file it rejected"
        );
    }

    #[test]
    fn a_chunk_whose_entries_leave_trailing_slack_is_rejected() {
        // `is_consistent_entry_region` requires the region be consumed EXACTLY,
        // not merely that entryCount entries fit. This is the complementary shape
        // to `inconsistent_chunk_header_is_rejected_not_misattributed` (which
        // claims MORE entries than it holds): here entryCount entries consume
        // FEWER bytes than entryBytes, leaving slack that the walk's `end > limit`
        // branch never sees. Only the final `p == limit` rejects it.
        //
        // Adopting it would be silent id-map corruption, not a cosmetic slip:
        // `open` copies `buf[entries_start..chunk_end]` into `loaded_entries`
        // verbatim, slack included, and `SentDictMirror::for_each_catch_up_frame`
        // walks that region to its END rather than by entry count -- so the slack
        // parses as phantom entries and shifts every id above it.
        // Mutation-checked: replacing `p == limit` with `true` fails this test.
        let dir = tmp_slot();
        let path = dir.path().join(FILE_NAME);
        {
            let mut d = PersistedSymbolDict::open(dir.path()).unwrap();
            d.append_symbol(b"good").unwrap();
        }
        let good_len = fs::metadata(&path).unwrap().len();
        {
            // One well-formed entry (`[len=1]'x'`, 2 bytes) in a 5-byte region.
            let mut f = OpenOptions::new().append(true).open(&path).unwrap();
            f.write_all(&crafted_chunk(1, &[1, b'x', 0xAA, 0xBB, 0xCC]))
                .unwrap();
        }

        let d = PersistedSymbolDict::open(dir.path()).unwrap();
        assert_eq!(d.read_loaded_symbols(), vec![b"good".to_vec()]);
        assert_eq!(d.size(), 1);
        assert_eq!(
            d.loaded_entries(),
            &b"\x04good"[..],
            "no slack byte reaches the recovered entry region"
        );
        assert_eq!(
            fs::metadata(&path).unwrap().len(),
            good_len,
            "the slack chunk is truncated away"
        );
    }

    #[test]
    fn a_chunk_whose_entry_bytes_would_overflow_is_rejected_without_panicking() {
        // A crafted `entryBytes` near u64::MAX is a legal 10-byte LEB128 that
        // `decode_varint` accepts, so only the two `checked_add`s stand between it
        // and `&buf[chunk_start..chunk_end]`. Without them the wrapped end slices
        // backwards and panics -- a process abort driven purely by on-disk state,
        // since questdb-rs-ffi builds with `panic = "abort"` and release leaves
        // `overflow-checks` off so the add itself would not trap.
        //
        // Both arms are covered: `u64::MAX` overflows `entries_start +
        // entry_bytes`, while `u64::MAX - entries_start` passes that and overflows
        // only the later `+ CRC_SIZE`.
        // Mutation-checked: either `checked_add` -> `wrapping_add` fails this test.
        let dir = tmp_slot();
        let path = dir.path().join(FILE_NAME);
        {
            let mut d = PersistedSymbolDict::open(dir.path()).unwrap();
            d.append_symbol(b"good").unwrap();
        }
        let good_len = fs::metadata(&path).unwrap().len();
        // entryCount varint (1 byte) + a 10-byte entryBytes varint.
        let entries_start = good_len + 1 + 10;

        for entry_bytes in [u64::MAX, u64::MAX - entries_start] {
            let mut chunk = Vec::new();
            write_varint(&mut chunk, 1); // entryCount
            write_varint(&mut chunk, entry_bytes); // absurd entryBytes
            let crc = crc32c::crc32c_append(0, &chunk);
            chunk.extend_from_slice(&crc.to_le_bytes());
            {
                let mut f = OpenOptions::new().append(true).open(&path).unwrap();
                f.write_all(&chunk).unwrap();
            }

            let d = PersistedSymbolDict::open(dir.path()).unwrap();
            assert_eq!(d.read_loaded_symbols(), vec![b"good".to_vec()]);
            assert_eq!(d.size(), 1);
            assert_eq!(
                fs::metadata(&path).unwrap().len(),
                good_len,
                "the overflowing chunk is truncated away, leaving the good prefix"
            );
        }
    }

    #[test]
    fn a_symbol_of_exactly_the_per_entry_cap_round_trips() {
        // The reader rejects `len > MAX_ENTRY_LEN`; `intern` accepts a symbol of
        // exactly that length (`symbol_dict_intern_rejects_symbols_above_the_
        // persisted_entry_cap` pins "exactly at the cap is accepted"). Only this
        // test pins the boundary on the READER side --
        // `over_cap_entry_len_is_rejected_at_open` pins MAX_ENTRY_LEN + 1 as
        // rejected, so `>` could silently become `>=` with the suite still green.
        // Writer and reader would then disagree at exactly 1 MiB: a legitimately
        // written symbol is dropped at recovery, the file truncated there, and
        // every frame above it stranded at the torn-dict guard.
        let dir = tmp_slot();
        let at_cap = vec![b'q'; MAX_ENTRY_LEN as usize];
        {
            let mut d = PersistedSymbolDict::open(dir.path()).unwrap();
            d.append_symbols(&[b"pre".as_slice(), at_cap.as_slice()])
                .unwrap();
            assert_eq!(d.size(), 2);
        }

        let d = PersistedSymbolDict::open(dir.path()).unwrap();
        assert_eq!(d.size(), 2, "a symbol at exactly the cap survives recovery");
        assert_eq!(d.read_loaded_symbols(), vec![b"pre".to_vec(), at_cap]);
    }

    #[test]
    fn a_chunk_with_multi_byte_header_varints_round_trips() {
        // The header back-fill right-aligns two varints inside
        // MAX_CHUNK_HEADER_LEN and writes from `header_start`, so every offset it
        // computes depends on both varints' widths. Every other writer test in
        // this module produces a 1+1-byte header (`header_start == 8`), which
        // makes that arithmetic a constant and leaves `encode_varint`'s
        // continuation loop unexercised -- yet production crosses into a 2-byte
        // entryBytes at a mere 128 bytes of entries, i.e. an ordinary flush.
        //
        // 200 entries of 100 bytes: entryCount 200 (2-byte varint) and entryBytes
        // 20_200 (3-byte varint), so header_len == 5.
        // Mutation-checked: hardcoding `header_start = MAX_CHUNK_HEADER_LEN - 2`
        // fails this test.
        let dir = tmp_slot();
        let path = dir.path().join(FILE_NAME);
        let symbols: Vec<Vec<u8>> = (0..200u32)
            .map(|i| {
                let mut s = format!("sym-{i:03}-").into_bytes();
                s.resize(100, b'p');
                s
            })
            .collect();
        {
            let mut d = PersistedSymbolDict::open(dir.path()).unwrap();
            let refs: Vec<&[u8]> = symbols.iter().map(|s| s.as_slice()).collect();
            d.append_symbols(&refs).unwrap();
            assert_eq!(d.size(), 200);
        }

        // Pin that this really is the multi-byte-header case, so a later change to
        // the symbol count or width cannot silently turn it back into 1+1.
        let bytes = fs::read(&path).unwrap();
        let (entry_count, after_count) = decode_varint(&bytes, HEADER_SIZE as usize).unwrap();
        let (entry_bytes, entries_start) = decode_varint(&bytes, after_count).unwrap();
        assert_eq!(entry_count, 200);
        assert_eq!(entry_bytes, 200 * 101);
        assert_eq!(
            entries_start - HEADER_SIZE as usize,
            5,
            "a 2-byte entryCount followed by a 3-byte entryBytes"
        );

        let d = PersistedSymbolDict::open(dir.path()).unwrap();
        assert_eq!(d.size(), 200);
        assert_eq!(d.read_loaded_symbols(), symbols);
        assert_eq!(parse_chunks(&path).len(), 1, "one append is one chunk");
    }

    #[test]
    fn encode_varint_matches_write_varint_across_widths() {
        // `encode_varint` is the chunk-header back-fill's encoder: it writes into
        // a fixed buffer and returns the width the back-fill uses as an offset, so
        // a wrong width silently misplaces the header. `varint_round_trip_across_
        // widths` exercises `write_varint` (the Vec form the entry region uses),
        // not this one. Pin the two against each other, and against the decoder,
        // at every continuation boundary -- including u64::MAX, which is exactly
        // the 10 bytes MAX_CHUNK_HEADER_LEN reserves.
        for value in [
            0u64,
            1,
            0x7F,
            0x80,
            300,
            16_383,
            16_384,
            2_097_151,
            2_097_152,
            u32::MAX as u64,
            u64::MAX,
        ] {
            let mut buf = [0u8; MAX_CHUNK_HEADER_LEN];
            let len = encode_varint(&mut buf, value);

            let mut expected = Vec::new();
            write_varint(&mut expected, value);
            assert_eq!(len, expected.len(), "width differs for {value}");
            assert_eq!(&buf[..len], &expected[..], "encoding differs for {value}");

            let (decoded, next) = decode_varint(&buf, 0).expect("decodes");
            assert_eq!(decoded, value);
            assert_eq!(next, len);
        }
    }

    #[test]
    fn each_append_is_exactly_one_chunk() {
        // The per-chunk blast-radius argument rests on chunks and frame deltas
        // being written one-for-one: the producer calls `append_symbols*` once per
        // frame with exactly that frame's new symbols, so every chunk boundary is
        // some frame's `delta_start`. Nothing pinned the writer half of that --
        // regressing to one chunk per symbol, or coalescing two appends into one
        // chunk, left every test in this module green because they all assert only
        // the flat, concatenated entry list.
        //
        // The empty append is load-bearing too: `open`'s `entry_count == 0` guard
        // is a hard stop that truncates, so if the writer ever emitted a `[0][0]`
        // chunk for a frame that interns nothing, every side-file would be
        // truncated at the second flush of almost any workload.
        let dir = tmp_slot();
        let path = dir.path().join(FILE_NAME);
        {
            let mut d = PersistedSymbolDict::open(dir.path()).unwrap();
            d.append_symbols(&[b"alpha".as_slice(), b"bravo".as_slice()])
                .unwrap();
            d.append_symbol(b"charlie").unwrap();
            let len_before_empty = fs::metadata(&path).unwrap().len();
            d.append_symbols(&[]).unwrap(); // a frame introducing no symbols
            assert_eq!(
                fs::metadata(&path).unwrap().len(),
                len_before_empty,
                "an empty append must write no chunk at all"
            );
            d.append_symbols(&[b"delta".as_slice()]).unwrap();
        }

        assert_eq!(
            parse_chunks(&path),
            vec![
                vec![b"alpha".to_vec(), b"bravo".to_vec()],
                vec![b"charlie".to_vec()],
                vec![b"delta".to_vec()],
            ],
            "one chunk per non-empty append, carrying exactly that append's symbols"
        );
    }

    #[test]
    fn parse_chunks_rejects_every_header_open_rejects() {
        // `parse_chunks(..).is_empty()` is how the recovery tests state "a valid,
        // untorn, EMPTY dictionary" -- the empty-vs-corrupt distinction the
        // delta-armed decision turns on. Every header `open_existing` refuses
        // carries no parsable chunk either, so without a header check here those
        // assertions would hold on exactly the corruption they claim to rule out.
        let dir = tmp_slot();
        let path = dir.path().join(FILE_NAME);

        let mut valid_empty = [0u8; HEADER_SIZE as usize];
        valid_empty[0..4].copy_from_slice(&FILE_MAGIC.to_le_bytes());
        valid_empty[4] = VERSION;

        let mut bad_magic = valid_empty;
        bad_magic[0] ^= 0xFF;
        let mut bad_version = valid_empty;
        bad_version[4] = VERSION + 1;
        for (label, bytes) in [
            ("truncated header", &valid_empty[..HEADER_SIZE as usize - 1]),
            ("bad magic", &bad_magic[..]),
            ("unknown version", &bad_version[..]),
        ] {
            fs::write(&path, bytes).unwrap();
            assert!(
                std::panic::catch_unwind(|| parse_chunks(&path)).is_err(),
                "a {label} must not read as an empty dictionary"
            );
        }

        // ... while the file a symbol-free session really does leave behind -- a
        // bare, well-formed header -- still parses, as zero chunks.
        fs::write(&path, valid_empty).unwrap();
        assert!(
            parse_chunks(&path).is_empty(),
            "a valid header with no chunks appended is an empty dictionary"
        );
    }
}
