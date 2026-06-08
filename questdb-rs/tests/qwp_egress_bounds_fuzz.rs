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

//! Bounds-check fuzz harness for the QWP egress `RESULT_BATCH` decoder.
//!
//! Port of `QwpCursorBoundsCheckFuzzTest` from the OSS questdb repo
//! (`core/src/test/java/io/questdb/test/cutlass/qwp/`). The original
//! exercises QuestDB's shared protocol cursor; this version targets the
//! Rust egress decoder entry point [`decode_result_batch`]. Both have the
//! same shape and the same intent: generate a *valid* QWP message, then
//! either
//!
//! 1. truncate the payload at every byte offset, or
//! 2. corrupt random bytes,
//!
//! and confirm the decoder returns an `Err` (or, for corrupted-but-still-
//! parseable inputs, an `Ok` with no panic). A panic, OOB read, or
//! integer-overflow abort at any truncation/corruption point indicates a
//! missing bounds check.
//!
//! Wire layout mirrored from the encoder side in `benches/decoder.rs` so
//! the synthesised payload decodes cleanly before the fuzz loop starts.

#![cfg(feature = "sync-reader-ws")]

use proptest::prelude::*;

use questdb::egress::_bench_internals::{
    Bytes, SchemaRegistry, SymbolDict, ZstdScratch, decode_result_batch,
};
use questdb::egress::ColumnKind;

// ---------------------------------------------------------------------------
// Wire constants. Match `benches/decoder.rs` and `egress::wire::msg_kind`.
// ---------------------------------------------------------------------------

const MSG_KIND_RESULT_BATCH: u8 = 0x11;
const SCHEMA_MODE_FULL: u8 = 0x00;
const NULL_FLAG_NONE: u8 = 0x00;
const NULL_FLAG_PRESENT: u8 = 0x01;

/// Column kinds we know how to synthesise a valid body for. Mirrors the
/// Java `FUZZABLE_TYPES` set, translated to Rust `ColumnKind` variants.
/// Types whose wire layout the decoder rejects on most random inputs (e.g.
/// `LongArray`, which the bench doesn't exercise either) are omitted so
/// `sanity_check_decode` reliably succeeds before the fuzz sweep starts.
const FUZZABLE_KINDS: &[ColumnKind] = &[
    // Non-nullable fixed-width.
    ColumnKind::Boolean,
    ColumnKind::Byte,
    ColumnKind::Short,
    ColumnKind::Char,
    // Nullable fixed-width.
    ColumnKind::Int,
    ColumnKind::Long,
    ColumnKind::Float,
    ColumnKind::Double,
    ColumnKind::Date,
    ColumnKind::Uuid,
    ColumnKind::Long256,
    ColumnKind::Ipv4,
    // Temporal (no FLAG_GORILLA in this generator → same wire as nullable
    // fixed-width).
    ColumnKind::Timestamp,
    ColumnKind::TimestampNanos,
    // Var-length / structured.
    ColumnKind::Varchar,
    ColumnKind::Binary,
    ColumnKind::Symbol,
    ColumnKind::Geohash,
    ColumnKind::Decimal64,
    ColumnKind::Decimal128,
    ColumnKind::Decimal256,
    ColumnKind::DoubleArray,
];

// ---------------------------------------------------------------------------
// Deterministic PRNG. Splitmix64 keeps the test seed-stable across Rust
// `rand` minor versions without pulling `rand` in as a direct dev-dep
// (it's already transitive via `tungstenite` etc., but using it as a
// declared dep would be a churn). Same trick the criterion bench uses.
// ---------------------------------------------------------------------------

struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        // Guarantee a non-zero state; the all-zeros seed is a known-bad
        // SplitMix64 starting point that returns 0 on the first call.
        Self {
            state: seed | 0x9E37_79B9_7F4A_7C15,
        }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn next_u8(&mut self) -> u8 {
        self.next_u64() as u8
    }

    /// Uniform `[0, bound)`. `bound` must be non-zero.
    fn gen_range(&mut self, bound: usize) -> usize {
        (self.next_u64() as usize) % bound
    }

    fn gen_bool(&mut self) -> bool {
        self.next_u64() & 1 == 0
    }
}

// ---------------------------------------------------------------------------
// Wire helpers.
// ---------------------------------------------------------------------------

fn varint_u64(mut v: u64, out: &mut Vec<u8>) {
    while v & !0x7F != 0 {
        out.push(((v & 0x7F) as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn write_random_bytes(out: &mut Vec<u8>, rng: &mut SplitMix64, n: usize) {
    for _ in 0..n {
        out.push(rng.next_u8());
    }
}

/// Bitmap of `row_count` bits where `null_count` slots are marked null.
/// Returns the bitmap bytes and the actual null count (always equal to
/// the input).
fn build_null_bitmap(row_count: usize, null_count: usize, rng: &mut SplitMix64) -> Vec<u8> {
    let bitmap_len = row_count.div_ceil(8);
    let mut bitmap = vec![0u8; bitmap_len];
    let mut remaining = null_count;
    while remaining > 0 {
        let pos = rng.gen_range(row_count);
        let byte = pos / 8;
        let bit = 1u8 << (pos % 8);
        if bitmap[byte] & bit == 0 {
            bitmap[byte] |= bit;
            remaining -= 1;
        }
    }
    bitmap
}

/// Validity prefix for a nullable column: either `NULL_FLAG_NONE` and no
/// bitmap, or `NULL_FLAG_PRESENT` and a bitmap with `null_count` slots
/// set. Returns the resulting non-null count so the caller knows how many
/// compact values to write.
fn write_validity(out: &mut Vec<u8>, rng: &mut SplitMix64, row_count: usize) -> usize {
    if row_count == 0 || !rng.gen_bool() {
        out.push(NULL_FLAG_NONE);
        return row_count;
    }
    // 0..=row_count nulls; uniform over the discrete range.
    let null_count = rng.gen_range(row_count + 1);
    out.push(NULL_FLAG_PRESENT);
    let bitmap = build_null_bitmap(row_count, null_count, rng);
    out.extend_from_slice(&bitmap);
    row_count - null_count
}

// ---------------------------------------------------------------------------
// Per-column body writers.
// ---------------------------------------------------------------------------

fn write_column_data(out: &mut Vec<u8>, rng: &mut SplitMix64, kind: ColumnKind, row_count: usize) {
    use ColumnKind as K;
    match kind {
        // Non-nullable fixed-width per Rust spec (decode_fixed_non_nullable
        // rejects null_flag != 0). BOOLEAN is bit-packed; the others are
        // raw row_count * elem_size bytes.
        K::Boolean => {
            out.push(NULL_FLAG_NONE);
            write_random_bytes(out, rng, row_count.div_ceil(8));
        }
        K::Byte => {
            out.push(NULL_FLAG_NONE);
            write_random_bytes(out, rng, row_count);
        }
        K::Short | K::Char => {
            out.push(NULL_FLAG_NONE);
            write_random_bytes(out, rng, row_count * 2);
        }
        // Nullable fixed-width: validity prefix + compact value bytes.
        K::Int | K::Float | K::Ipv4 => {
            let non_null = write_validity(out, rng, row_count);
            write_random_bytes(out, rng, non_null * 4);
        }
        K::Long | K::Double | K::Date | K::Timestamp | K::TimestampNanos => {
            let non_null = write_validity(out, rng, row_count);
            write_random_bytes(out, rng, non_null * 8);
        }
        K::Uuid => {
            let non_null = write_validity(out, rng, row_count);
            write_random_bytes(out, rng, non_null * 16);
        }
        K::Long256 => {
            let non_null = write_validity(out, rng, row_count);
            write_random_bytes(out, rng, non_null * 32);
        }
        // VARCHAR / BINARY: validity prefix, then `(non_null + 1) × u32_le`
        // offsets, then concatenated data bytes. For VARCHAR the data must
        // be valid UTF-8; we use ASCII printable to keep that trivially
        // true.
        K::Varchar => write_varlen(out, rng, row_count, /*utf8=*/ true),
        K::Binary => write_varlen(out, rng, row_count, /*utf8=*/ false),
        // SYMBOL column-local (no FLAG_DELTA_SYMBOL_DICT): validity + varint
        // dict_size + dict entries + varint codes per non-null row.
        K::Symbol => write_symbol(out, rng, row_count),
        // GEOHASH: validity + varint precision (1..=60) + non_null × byte_width.
        K::Geohash => write_geohash(out, rng, row_count),
        // DECIMAL: validity + 1-byte scale + non_null × elem_size.
        K::Decimal64 => write_decimal(out, rng, row_count, 8),
        K::Decimal128 => write_decimal(out, rng, row_count, 16),
        K::Decimal256 => write_decimal(out, rng, row_count, 32),
        // DOUBLE_ARRAY / LONG_ARRAY share wire layout: validity + per non-
        // null row {1B nDims, nDims×u32_le dims, prod(dims)×8 element bytes}.
        K::DoubleArray | K::LongArray => write_array(out, rng, row_count),
        _ => unreachable!("FUZZABLE_KINDS contains an unhandled variant"),
    }
}

fn write_varlen(out: &mut Vec<u8>, rng: &mut SplitMix64, row_count: usize, utf8: bool) {
    let non_null = write_validity(out, rng, row_count);
    // Build offsets and data together so they're internally consistent.
    let mut data: Vec<u8> = Vec::new();
    let mut offsets: Vec<u32> = Vec::with_capacity(non_null + 1);
    offsets.push(0);
    for _ in 0..non_null {
        let len = rng.gen_range(20); // 0..20
        for _ in 0..len {
            data.push(if utf8 {
                // ASCII printable to keep `from_utf8` happy.
                0x20 + (rng.next_u8() % 95)
            } else {
                rng.next_u8()
            });
        }
        offsets.push(data.len() as u32);
    }
    for o in &offsets {
        out.extend_from_slice(&o.to_le_bytes());
    }
    out.extend_from_slice(&data);
}

fn write_symbol(out: &mut Vec<u8>, rng: &mut SplitMix64, row_count: usize) {
    let non_null = write_validity(out, rng, row_count);
    // Decoder enforces `dict_size <= row_count`. Non-null rows must each
    // reference a code in `0..dict_size`, so `dict_size` must be `>= 1`
    // when `non_null > 0`. When `row_count == 0`, `dict_size` must be 0
    // (the upper bound from the same check).
    let dict_size = if row_count == 0 {
        0
    } else if non_null == 0 {
        rng.gen_range(row_count + 1) // 0..=row_count
    } else {
        let max = row_count.min(5);
        1 + rng.gen_range(max) // 1..=min(row_count, 5)
    };
    varint_u64(dict_size as u64, out);
    for _ in 0..dict_size {
        let entry_len = 1 + rng.gen_range(8); // 1..=8
        varint_u64(entry_len as u64, out);
        for _ in 0..entry_len {
            out.push(0x61 + (rng.next_u8() % 26)); // 'a'..='z'
        }
    }
    if dict_size > 0 {
        for _ in 0..non_null {
            let code = rng.gen_range(dict_size);
            varint_u64(code as u64, out);
        }
    }
    // When dict_size == 0, non_null must also be 0 (decoder enforces via
    // the `code32 >= active_dict_size` check), so the codes section is
    // implicitly empty.
}

fn write_geohash(out: &mut Vec<u8>, rng: &mut SplitMix64, row_count: usize) {
    let non_null = write_validity(out, rng, row_count);
    let precision_bits = 1 + rng.gen_range(60); // 1..=60 per decoder check
    varint_u64(precision_bits as u64, out);
    let byte_width = precision_bits.div_ceil(8);
    write_random_bytes(out, rng, non_null * byte_width);
}

fn write_decimal(out: &mut Vec<u8>, rng: &mut SplitMix64, row_count: usize, elem_size: usize) {
    let non_null = write_validity(out, rng, row_count);
    let max_scale: u64 = match elem_size {
        8 => 18,
        16 => 38,
        _ => 38,
    };
    let scale: u8 = (rng.next_u64() % (max_scale + 1)) as u8;
    out.push(scale);
    write_random_bytes(out, rng, non_null * elem_size);
}

fn write_array(out: &mut Vec<u8>, rng: &mut SplitMix64, row_count: usize) {
    let non_null = write_validity(out, rng, row_count);
    for _ in 0..non_null {
        // 1D arrays with 1..=3 elements. The spec permits empty arrays
        // (dim==0), but the bounds fuzz only mutates *non-empty*
        // shapes so truncation/corruption have something to chew on —
        // dim==0 has no element bytes to truncate. The dim==0 case is
        // pinned by `array_dim_zero_is_valid_empty_array` in the
        // decoder hardening tests.
        out.push(1u8); // nDims
        let dim: u32 = (1 + rng.gen_range(3)) as u32; // 1..=3
        out.extend_from_slice(&dim.to_le_bytes());
        write_random_bytes(out, rng, dim as usize * 8);
    }
}

// ---------------------------------------------------------------------------
// Message assembly.
// ---------------------------------------------------------------------------

/// Synthesise a valid single-table `RESULT_BATCH` payload (post 12-byte
/// frame header — exactly what [`decode_result_batch`] consumes).
/// Single-table because the Rust decoder's `decode_result_batch` parses
/// one table block per call; the Java fuzz used 1..=3 tables because the
/// shared protocol cursor on the Java side iterates multiple tables, but
/// the Rust egress API normalizes that to per-batch single-table.
fn generate_valid_message(seed: u64) -> Vec<u8> {
    let mut rng = SplitMix64::new(seed);
    let row_count = rng.gen_range(20); // 0..20
    let col_count = 1 + rng.gen_range(6); // 1..=6

    let kinds: Vec<ColumnKind> = (0..col_count)
        .map(|_| FUZZABLE_KINDS[rng.gen_range(FUZZABLE_KINDS.len())])
        .collect();
    let names: Vec<String> = (0..col_count).map(|i| format!("c{}", i)).collect();

    let mut out = Vec::new();
    // Frame prefix: msg_kind + request_id + batch_seq.
    out.push(MSG_KIND_RESULT_BATCH);
    out.extend_from_slice(&1i64.to_le_bytes());
    varint_u64(0, &mut out);

    // Table block: empty table name (matches the bench and the real
    // server's "name omitted for query results" convention), row count,
    // col count.
    varint_u64(0, &mut out);
    varint_u64(row_count as u64, &mut out);
    varint_u64(col_count as u64, &mut out);

    // Schema section: Full mode, fresh id.
    out.push(SCHEMA_MODE_FULL);
    varint_u64(1, &mut out);
    for i in 0..col_count {
        varint_u64(names[i].len() as u64, &mut out);
        out.extend_from_slice(names[i].as_bytes());
        out.push(kinds[i].as_u8());
    }

    // Per-column data.
    for &kind in &kinds {
        write_column_data(&mut out, &mut rng, kind, row_count);
    }

    out
}

// ---------------------------------------------------------------------------
// Decode helpers. Each call gets a fresh `SymbolDict` / `SchemaRegistry`
// so a corrupted SYMBOL dict in one iteration can't poison the next.
// ---------------------------------------------------------------------------

fn sanity_check_decode(message: &[u8]) {
    let mut dict = SymbolDict::new();
    let mut reg = SchemaRegistry::new();
    let mut scratch = ZstdScratch::new();
    decode_result_batch(
        &Bytes::copy_from_slice(message),
        0,
        &mut dict,
        &mut reg,
        &mut scratch,
    )
    .unwrap_or_else(|e| {
        panic!(
            "generated message must decode cleanly (len={}): {:?}",
            message.len(),
            e
        )
    });
}

/// The decoder must return either Ok or Err without panicking, OOB reading,
/// or aborting on integer overflow. proptest treats a panic here as a
/// shrinkable failure.
fn attempt_decode_no_panic(bytes: &[u8]) {
    let mut dict = SymbolDict::new();
    let mut reg = SchemaRegistry::new();
    let mut scratch = ZstdScratch::new();
    let _ = decode_result_batch(
        &Bytes::copy_from_slice(bytes),
        0,
        &mut dict,
        &mut reg,
        &mut scratch,
    );
}

// ---------------------------------------------------------------------------
// proptest harnesses.
// ---------------------------------------------------------------------------

proptest! {
    // 50 iterations matches the Java reference test
    // (`QwpCursorBoundsCheckFuzzTest` uses `iterations = 50`). The
    // per-iteration sweep is exhaustive over truncation offsets / 30
    // corruption attempts, so per-seed coverage is high.
    #![proptest_config(ProptestConfig {
        cases: 50,
        max_shrink_iters: 256,
        .. ProptestConfig::default()
    })]

    /// For each seed: synthesise a valid message, then call
    /// `decode_result_batch` on every prefix `message[..trunc_len]`.
    /// Mirrors `QwpCursorBoundsCheckFuzzTest.testTruncationAtEveryBytePosition`.
    #[test]
    fn truncation_at_every_offset(seed in any::<u64>()) {
        let message = generate_valid_message(seed);
        sanity_check_decode(&message);
        for trunc_len in 0..message.len() {
            attempt_decode_no_panic(&message[..trunc_len]);
        }
    }

    /// For each seed: synthesise a valid message, then make 30 corruption
    /// attempts (each flips 1..=3 random bytes). Mirrors
    /// `QwpCursorBoundsCheckFuzzTest.testByteCorruption`.
    #[test]
    fn byte_corruption(seed in any::<u64>()) {
        let message = generate_valid_message(seed);
        sanity_check_decode(&message);

        // Derive a corruption RNG so the corruption stream is independent
        // of the message-generation stream but still reproducible from
        // the proptest seed.
        let mut rng = SplitMix64::new(seed ^ 0xDEAD_BEEF_DEAD_BEEF);
        for _ in 0..30 {
            let mut corrupted = message.clone();
            let n_corrupt = 1 + rng.gen_range(3); // 1..=3
            for _ in 0..n_corrupt {
                let pos = rng.gen_range(corrupted.len());
                corrupted[pos] = rng.next_u8();
            }
            attempt_decode_no_panic(&corrupted);
        }
    }
}
