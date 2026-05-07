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

//! Connection-scoped symbol dictionary.
//!
//! Each `RESULT_BATCH` carrying `FLAG_DELTA_SYMBOL_DICT` appends entries
//! to the dictionary; `SYMBOL` columns transmit only integer codes that
//! index into it. The dictionary persists across queries on the same
//! connection until a `CACHE_RESET` with the dict bit clears it.
//!
//! Wire format of the delta section (when `FLAG_DELTA_SYMBOL_DICT` is set):
//!
//! ```text
//! delta_start: varint     first conn-id assigned in this batch
//! delta_count: varint     number of new entries
//! repeat delta_count times:
//!   entry_len: varint
//!   entry:     bytes      UTF-8 symbol string
//! ```
//!
//! `delta_start` MUST equal the dictionary's current length; after a
//! reset, the next delta MUST start at 0.

use crate::egress::error::{Result, fmt};
use crate::egress::wire::varint;

/// Hard cap on the connection-scoped SYMBOL dict's UTF-8 heap size in
/// bytes. Mirrors `MAX_CONN_DICT_HEAP_BYTES` in the Java reference
/// client. Well-behaved servers approaching this cap are expected to
/// emit `CACHE_RESET(RESET_MASK_DICT)`; crossing it without a reset is
/// a protocol violation and we error rather than grow without bound.
pub(crate) const MAX_CONN_DICT_HEAP_BYTES: usize = 256 * 1024 * 1024;

/// Hard cap on the connection-scoped SYMBOL dict entry count. Mirrors
/// `MAX_CONN_DICT_SIZE` in the Java reference client.
pub(crate) const MAX_CONN_DICT_SIZE: usize = 8_388_608;

#[derive(Debug, Clone, Copy)]
struct Entry {
    offset: u32,
    len: u32,
}

/// Connection-scoped symbol dictionary.
#[derive(Debug, Default, Clone)]
pub struct SymbolDict {
    arena: Vec<u8>,
    entries: Vec<Entry>,
}

impl SymbolDict {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of entries currently stored. Also the next conn-id to assign.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// UTF-8 bytes currently held in the arena.
    pub fn heap_bytes(&self) -> usize {
        self.arena.len()
    }

    /// Resolve a connection-scoped symbol id to its UTF-8 string.
    pub fn get(&self, id: u32) -> Option<&str> {
        let entry = self.entries.get(id as usize)?;
        let start = entry.offset as usize;
        let end = start + entry.len as usize;
        // Safety: every byte slice that reaches the arena was UTF-8 validated
        // by `apply_delta` before being copied in.
        Some(unsafe { std::str::from_utf8_unchecked(&self.arena[start..end]) })
    }

    /// Clear all state. Triggered by a `CACHE_RESET` with the dict bit.
    pub fn reset(&mut self) {
        self.entries.clear();
        self.arena.clear();
    }

    /// Apply a delta whose first new id is `delta_start` and whose entries
    /// are produced in order. Validates UTF-8 and the sequencing invariant.
    pub fn apply_delta<'a, I>(&mut self, delta_start: u64, entries: I) -> Result<()>
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        let expected = self.entries.len() as u64;
        if delta_start != expected {
            return Err(fmt!(
                ProtocolError,
                "symbol dict delta_start={} but registry len={}",
                delta_start,
                expected
            ));
        }
        for bytes in entries {
            self.push_one(bytes)?;
        }
        Ok(())
    }

    /// Decode + apply a delta directly from the wire bytes. Returns the
    /// number of bytes consumed.
    ///
    /// All-or-nothing: if any entry in the delta is malformed, the dict
    /// is rolled back to its pre-call state. Without this, a partial
    /// failure would leave `self.entries.len()` between the old and new
    /// expected values, and every subsequent delta would mismatch the
    /// `delta_start` check above and break the connection until reset.
    pub fn apply_delta_from_bytes(&mut self, bytes: &[u8]) -> Result<usize> {
        let mut cursor = 0usize;
        let (delta_start, n) = varint::decode_u64(&bytes[cursor..])?;
        cursor += n;
        let (delta_count, n) = varint::decode_u64(&bytes[cursor..])?;
        cursor += n;

        let expected = self.entries.len() as u64;
        if delta_start != expected {
            return Err(fmt!(
                ProtocolError,
                "symbol dict delta_start={} but registry len={}",
                delta_start,
                expected
            ));
        }

        // Upfront cap on delta_count: a corrupt batch with delta_count
        // = u64::MAX would otherwise iterate up to MAX_CONN_DICT_SIZE
        // (8M) times — burning real CPU on per-entry varint decode +
        // UTF-8 validation + heap-size checks — before push_one finally
        // refuses to grow past the soft cap. Reject the malformed
        // count up front against the headroom remaining in the dict.
        let headroom = (MAX_CONN_DICT_SIZE - self.entries.len()) as u64;
        if delta_count > headroom {
            return Err(fmt!(
                ProtocolError,
                "symbol dict delta_count={} exceeds remaining capacity {} \
                 (current entries={}, max={})",
                delta_count,
                headroom,
                self.entries.len(),
                MAX_CONN_DICT_SIZE
            ));
        }

        let snapshot_entries = self.entries.len();
        let snapshot_arena = self.arena.len();
        let result: Result<usize> = (|| {
            for i in 0..delta_count {
                let (entry_len, n) = varint::decode_usize(&bytes[cursor..])?;
                cursor += n;
                let end = cursor.checked_add(entry_len).ok_or_else(|| {
                    fmt!(
                        ProtocolError,
                        "symbol dict entry length overflow at i={}",
                        i
                    )
                })?;
                if end > bytes.len() {
                    return Err(fmt!(
                        ProtocolError,
                        "symbol dict truncated at entry {}: need {} bytes, have {}",
                        i,
                        entry_len,
                        bytes.len() - cursor
                    ));
                }
                self.push_one(&bytes[cursor..end])?;
                cursor = end;
            }
            Ok(cursor)
        })();
        if result.is_err() {
            self.entries.truncate(snapshot_entries);
            self.arena.truncate(snapshot_arena);
        }
        result
    }

    fn push_one(&mut self, bytes: &[u8]) -> Result<()> {
        let s = std::str::from_utf8(bytes).map_err(|e| {
            fmt!(
                InvalidUtf8,
                "symbol dict entry {} is not valid UTF-8: {}",
                self.entries.len(),
                e
            )
        })?;
        if self.entries.len() >= MAX_CONN_DICT_SIZE {
            return Err(fmt!(
                ProtocolError,
                "symbol dict full: {} entries (max {}); server must emit \
                 CACHE_RESET(dict) before adding more",
                self.entries.len(),
                MAX_CONN_DICT_SIZE
            ));
        }
        let new_heap = self
            .arena
            .len()
            .checked_add(s.len())
            .ok_or_else(|| fmt!(ProtocolError, "symbol dict heap overflow"))?;
        if new_heap > MAX_CONN_DICT_HEAP_BYTES {
            return Err(fmt!(
                ProtocolError,
                "symbol dict heap would reach {} bytes (max {}); server \
                 must emit CACHE_RESET(dict) before adding more",
                new_heap,
                MAX_CONN_DICT_HEAP_BYTES
            ));
        }
        let offset = u32::try_from(self.arena.len())
            .map_err(|_| fmt!(ProtocolError, "symbol dict arena exceeds u32"))?;
        let len = u32::try_from(s.len())
            .map_err(|_| fmt!(ProtocolError, "symbol dict entry exceeds u32 length"))?;
        self.arena.extend_from_slice(s.as_bytes());
        self.entries.push(Entry { offset, len });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress::error::ErrorCode;
    use crate::egress::wire::varint::encode_u64;

    fn build_delta(start: u64, entries: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        encode_u64(start, &mut out);
        encode_u64(entries.len() as u64, &mut out);
        for e in entries {
            encode_u64(e.len() as u64, &mut out);
            out.extend_from_slice(e.as_bytes());
        }
        out
    }

    #[test]
    fn empty_dict() {
        let d = SymbolDict::new();
        assert_eq!(d.len(), 0);
        assert!(d.is_empty());
        assert_eq!(d.heap_bytes(), 0);
        assert!(d.get(0).is_none());
    }

    #[test]
    fn apply_first_delta_via_iter() {
        let mut d = SymbolDict::new();
        let entries: Vec<&[u8]> = vec![b"AAPL", b"MSFT", b"GOOG"];
        d.apply_delta(0, entries).unwrap();
        assert_eq!(d.len(), 3);
        assert_eq!(d.get(0), Some("AAPL"));
        assert_eq!(d.get(1), Some("MSFT"));
        assert_eq!(d.get(2), Some("GOOG"));
        assert_eq!(d.get(3), None);
        assert_eq!(d.heap_bytes(), 4 + 4 + 4);
    }

    #[test]
    fn second_delta_appends() {
        let mut d = SymbolDict::new();
        d.apply_delta(0, [b"a".as_slice()]).unwrap();
        d.apply_delta(1, [b"bb".as_slice(), b"ccc".as_slice()])
            .unwrap();
        assert_eq!(d.len(), 3);
        assert_eq!(d.get(2), Some("ccc"));
    }

    #[test]
    fn delta_start_mismatch_rejected() {
        let mut d = SymbolDict::new();
        d.apply_delta(0, [b"x".as_slice()]).unwrap();
        // Server claims new entries start at 5, but we have only 1.
        let err = d.apply_delta(5, [b"y".as_slice()]).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProtocolError);
    }

    #[test]
    fn from_bytes_roundtrip() {
        let mut d = SymbolDict::new();
        let bytes = build_delta(0, &["AAPL", "MSFT"]);
        let consumed = d.apply_delta_from_bytes(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(d.get(0), Some("AAPL"));
        assert_eq!(d.get(1), Some("MSFT"));

        let bytes2 = build_delta(2, &["GOOG"]);
        d.apply_delta_from_bytes(&bytes2).unwrap();
        assert_eq!(d.get(2), Some("GOOG"));
    }

    #[test]
    fn from_bytes_partial_failure_rolls_back() {
        // Build a delta where the first entry is fine and the second is
        // truncated. Without rollback, the dict would commit the first
        // entry and the delta_start of every subsequent batch would
        // mismatch.
        let mut d = SymbolDict::new();
        d.apply_delta(0, [b"first".as_slice()]).unwrap();
        let snapshot_len = d.len();
        let snapshot_heap = d.heap_bytes();

        let mut bytes = Vec::new();
        encode_u64(snapshot_len as u64, &mut bytes); // delta_start
        encode_u64(2, &mut bytes); // delta_count
        encode_u64(2, &mut bytes); // entry 0 len
        bytes.extend_from_slice(b"ok");
        encode_u64(10, &mut bytes); // entry 1 claims 10 bytes
        bytes.extend_from_slice(b"abc"); // only 3 follow → truncated

        let err = d.apply_delta_from_bytes(&bytes).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProtocolError);
        // Dict reverted to snapshot: subsequent delta_start check uses
        // the original length.
        assert_eq!(d.len(), snapshot_len);
        assert_eq!(d.heap_bytes(), snapshot_heap);
        let next = build_delta(snapshot_len as u64, &["recovered"]);
        d.apply_delta_from_bytes(&next).unwrap();
        assert_eq!(d.get(snapshot_len as u32), Some("recovered"));
    }

    #[test]
    fn from_bytes_truncated_entry_rejected() {
        let mut d = SymbolDict::new();
        let mut bytes = build_delta(0, &["hello"]);
        bytes.truncate(bytes.len() - 1); // chop one byte off the entry
        let err = d.apply_delta_from_bytes(&bytes).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProtocolError);
    }

    #[test]
    fn from_bytes_invalid_utf8_rejected() {
        let mut bytes = Vec::new();
        encode_u64(0, &mut bytes);
        encode_u64(1, &mut bytes);
        encode_u64(2, &mut bytes);
        bytes.extend_from_slice(&[0xFF, 0xFE]); // invalid UTF-8
        let mut d = SymbolDict::new();
        let err = d.apply_delta_from_bytes(&bytes).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidUtf8);
    }

    #[test]
    fn reset_clears_state() {
        let mut d = SymbolDict::new();
        d.apply_delta(0, [b"x".as_slice(), b"yy".as_slice()])
            .unwrap();
        assert_eq!(d.len(), 2);
        d.reset();
        assert_eq!(d.len(), 0);
        assert_eq!(d.heap_bytes(), 0);
        // After reset, next delta must start at 0.
        d.apply_delta(0, [b"new".as_slice()]).unwrap();
        assert_eq!(d.get(0), Some("new"));
    }

    #[test]
    fn delta_with_zero_entries_is_noop() {
        let mut d = SymbolDict::new();
        d.apply_delta(0, std::iter::empty::<&[u8]>()).unwrap();
        let bytes = build_delta(0, &[]);
        let consumed = d.apply_delta_from_bytes(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(d.len(), 0);
    }

    #[test]
    fn delta_count_exceeding_capacity_rejected_upfront() {
        // A corrupt batch with `delta_count = u64::MAX` must fail fast,
        // not iterate up to MAX_CONN_DICT_SIZE times burning CPU on
        // per-entry varint decode + UTF-8 + heap-size checks.
        let mut d = SymbolDict::new();
        let mut bytes = Vec::new();
        encode_u64(0, &mut bytes); // delta_start
        encode_u64(u64::MAX, &mut bytes); // delta_count
        // No entries follow: if the cap weren't enforced upfront, the
        // first iteration would error on truncated entry-length varint
        // — which is also a ProtocolError but only after the loop has
        // started. We can't directly observe iteration count, but we
        // can pin the error message: the upfront cap surfaces
        // "exceeds remaining capacity", the per-entry path surfaces
        // "truncated".
        let err = d.apply_delta_from_bytes(&bytes).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProtocolError);
        assert!(
            err.msg().contains("exceeds remaining capacity"),
            "expected upfront-cap rejection, got: {}",
            err.msg()
        );
        assert_eq!(d.len(), 0);
    }

    #[test]
    fn unicode_entries_preserved() {
        let mut d = SymbolDict::new();
        let bytes = build_delta(0, &["café", "日本語"]);
        d.apply_delta_from_bytes(&bytes).unwrap();
        assert_eq!(d.get(0), Some("café"));
        assert_eq!(d.get(1), Some("日本語"));
    }
}
