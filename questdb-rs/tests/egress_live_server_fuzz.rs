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

//! Live-server fuzz port of selected `@Test` methods from
//! [`io.questdb.test.cutlass.qwp.QwpEgressFuzzTest`](https://github.com/questdb/questdb/blob/master/core/src/test/java/io/questdb/test/cutlass/qwp/QwpEgressFuzzTest.java).
//!
//! Property-based fuzz of egress over random schemas. Each fuzz case:
//!   1. Builds a random schema (1..=N columns) from a generator
//!      catalogue covering the common QWP wire types.
//!   2. Generates per-row random values in Rust (seeded SplitMix64) so
//!      the expected hash for every `(row, col)` cell is known before
//!      the query runs.
//!   3. Inserts those values as a single multi-row `INSERT VALUES`.
//!   4. SELECTs them back via the egress reader and asserts per-cell
//!      hash equality.
//!
//! Per-cell hash verification — as opposed to a per-column sum — catches
//! bugs that preserve column totals but corrupt individual values: row
//! reordering, cross-batch boundary misalignment, null-bitmap bit swaps,
//! partial varint reads.
//!
//! Scope vs Java original:
//!   - Generator catalogue: LONG, INT, SHORT, BYTE, BOOLEAN, DOUBLE,
//!     FLOAT, CHAR, TIMESTAMP, TIMESTAMP_NS, DATE, VARCHAR, SYMBOL
//!     (small + large pools), UUID, LONG256, IPv4. The remaining Java
//!     generators (BINARY, GEOHASH × 4, DECIMAL128, DECIMAL256,
//!     DOUBLE_ARRAY, DECIMAL64) are "existence-only" hashes in Java
//!     anyway — not bit-level oracles — so they'd grow LOC without
//!     strengthening the regression guarantee.
//!   - Three `@Test` methods ported: `random_schema_roundtrip` (15
//!     fresh-connection cases under fragmentation),
//!     `back_to_back_queries_same_connection` (12 cases on one
//!     connection under fragmentation), and `wide_tables` (1 case at
//!     10..=16 cols under fragmentation).
//!   - **Fragmentation cross-product matches Java** — each test boots
//!     its own server with `debug.http.force.{recv,send}.fragmentation.chunk.size`
//!     set to a random chunk in `[1, 500]`, then runs the per-test
//!     loop against it. This is what the Java fuzz file does via
//!     `startFragmented(pickChunk())`.
//!   - Query shape rotation matches Java: each case picks one of four
//!     shapes — full scan, random projection subset, id-range filter,
//!     descending order with limit — keyed off `caseIdx mod 4`.
//!   - Compression variation matches Java's `pickCompression()`:
//!     default / `compression=raw` / `compression=auto` /
//!     `compression=zstd` / `compression=zstd;compression_level=N`
//!     with `N ∈ [1, 9]`.
//!   - `testSelectAlterSequenceFuzz` (ALTER-orchestration fuzz) is in
//!     its own follow-up commit (separate driver — too different
//!     structurally to share `run_one_case`).
//!
//! Each test boots its own `QuestDbServer` via `start_with_config(...)`.
//! Three tests × one JVM each ≈ 45 s of boot for the whole file,
//! traded against actually catching fragmentation-only bugs in the
//! schema fuzz. Gated behind the `live-server-tests` Cargo feature.
//! Seeded via `QWP_EGRESS_FUZZ_SEED` env var.

#![cfg(feature = "live-server-tests")]

mod common;

use questdb::egress::column::ColumnView;
use questdb::egress::reader::{BatchView, Reader};

use common::QuestDbServer;

// ---------------------------------------------------------------------------
// Per-test fragmented server (mirrors Java's `startFragmented(pickChunk())`).
// ---------------------------------------------------------------------------

/// Mirrors Java's `startFragmented(int chunk)`. Pins both recv and send
/// chunk so the WebSocket codec, frame parser and credit accountant are
/// all stressed at the chunk boundary.
fn start_fragmented(chunk: u32) -> QuestDbServer {
    let chunk_s = chunk.to_string();
    QuestDbServer::start_with_config(&[
        ("debug.http.force.recv.fragmentation.chunk.size", &chunk_s),
        ("debug.http.force.send.fragmentation.chunk.size", &chunk_s),
    ])
}

/// Java: `pickChunk()` — `1 + random.nextInt(500)` → `[1, 500]`.
fn pick_chunk(rng: &mut SplitMix64) -> u32 {
    1 + rng.gen_range_u32(500)
}

/// Build a `Reader` against `srv` using the picked compression knob
/// appended to the connect string.
fn make_reader_with(srv: &QuestDbServer, compression_suffix: &str) -> Reader {
    let base = srv.qwp_conf();
    let conf = if compression_suffix.is_empty() {
        base
    } else {
        format!("{base};{compression_suffix}")
    };
    Reader::from_conf(conf).expect("reader")
}

/// Mirrors Java's `pickCompression()`. Returns the suffix to append
/// after the base `ws::addr=...` connect string (without the leading
/// `;`). Empty string = library default.
fn pick_compression(rng: &mut SplitMix64) -> String {
    match rng.gen_range_u32(5) {
        0 => String::new(),
        1 => "compression=raw".to_string(),
        2 => "compression=auto".to_string(),
        3 => "compression=zstd".to_string(),
        _ => {
            let level = 1 + rng.gen_range_u32(9); // 1..=9
            format!("compression=zstd;compression_level={level}")
        }
    }
}

// ---------------------------------------------------------------------------
// SplitMix64 — local copy, same as the other fuzz files.
// ---------------------------------------------------------------------------

struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
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

    fn next_i64(&mut self) -> i64 {
        self.next_u64() as i64
    }

    fn next_i32(&mut self) -> i32 {
        self.next_u64() as i32
    }

    fn next_f64(&mut self) -> f64 {
        // Java: `(rnd.nextDouble() - 0.5) * 1e9`. Range covers a few
        // decades around zero; encoder must round-trip every bit.
        let raw = (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64;
        (raw - 0.5) * 1e9
    }

    fn next_f32(&mut self) -> f32 {
        let raw = (self.next_u64() >> 40) as f32 / (1u32 << 24) as f32;
        (raw - 0.5) * 1e5
    }

    fn next_bool(&mut self) -> bool {
        self.next_u64() & 1 == 0
    }

    fn gen_range_u32(&mut self, bound: u32) -> u32 {
        (self.next_u64() % bound as u64) as u32
    }

    fn gen_range_usize(&mut self, bound: usize) -> usize {
        (self.next_u64() % bound as u64) as usize
    }
}

// ---------------------------------------------------------------------------
// Seed plumbing — mirrors the bind / fragmentation fuzz files.
// ---------------------------------------------------------------------------

const DEFAULT_SEED: u64 = 0xb39c_4f7e_2a85_91d2;

fn fuzz_seed_for(test_name: &str) -> u64 {
    let base = std::env::var("QWP_EGRESS_FUZZ_SEED")
        .ok()
        .and_then(|raw| {
            let s = raw.trim();
            if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                u64::from_str_radix(hex, 16).ok()
            } else {
                s.parse::<u64>().ok()
            }
        })
        .unwrap_or(DEFAULT_SEED);
    let mut hash: u64 = 0xCBF2_9CE4_8422_2325;
    for b in test_name.bytes() {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100_0000_01B3);
    }
    let combined = base.wrapping_add(hash);
    eprintln!("[qwp_egress_fuzz seed] {test_name} seed=0x{combined:016x}");
    combined
}

// ---------------------------------------------------------------------------
// Hash function — same constants and shape as
// `QwpEgressFuzzTest.hashAsciiString` so a future Java↔Rust diff can
// match cell-by-cell if needed. `h = 1125899906842597; for each byte:
// h = h*31 + b; final h ^= len`.
// ---------------------------------------------------------------------------

fn hash_bytes(bytes: &[u8]) -> i64 {
    let mut h: u64 = 1_125_899_906_842_597;
    for &b in bytes {
        h = h.wrapping_mul(31).wrapping_add(b as u64);
    }
    (h ^ bytes.len() as u64) as i64
}

// ---------------------------------------------------------------------------
// Column generators.
//
// Each `ColumnGenerator` knows how to emit one random literal+hash and
// how to compute the hash of an observed value in a `BatchView`. The
// trait is `dyn`-compatible so we can build a `Vec<Box<dyn ...>>`
// catalogue indexed by column generator id.
// ---------------------------------------------------------------------------

struct CellGen {
    /// SQL literal as it appears inside `INSERT INTO t VALUES (...)`.
    literal: String,
    /// 64-bit hash; compared against the observed hash post-roundtrip.
    hash: i64,
}

trait ColumnGenerator: Send + Sync {
    fn sql_type(&self) -> &'static str;
    fn supports_null(&self) -> bool {
        true
    }
    /// Generate one non-null value. The NULL path is handled by the
    /// caller via an explicit `CAST(NULL AS <type>)` literal.
    fn random_value(&self, rng: &mut SplitMix64) -> CellGen;
    /// Compute the observed hash for `view.column(col).value(row)`.
    fn observed_hash(&self, view: &BatchView<'_>, col: usize, row: usize) -> i64;
}

// --- Long --------------------------------------------------------------

struct LongGenerator;
impl ColumnGenerator for LongGenerator {
    fn sql_type(&self) -> &'static str {
        "LONG"
    }
    fn random_value(&self, rng: &mut SplitMix64) -> CellGen {
        // Retry LONG_NULL so non-null cells never collide with the
        // sentinel and produce a false NULL.
        let v = loop {
            let candidate = rng.next_i64();
            if candidate != i64::MIN {
                break candidate;
            }
        };
        CellGen {
            literal: format!("{v}L"),
            hash: v,
        }
    }
    fn observed_hash(&self, view: &BatchView<'_>, col: usize, row: usize) -> i64 {
        let ColumnView::Long(c) = view.column(col).unwrap() else {
            panic!("col {col} not Long");
        };
        c.value(row)
    }
}

// --- Int ---------------------------------------------------------------

struct IntGenerator;
impl ColumnGenerator for IntGenerator {
    fn sql_type(&self) -> &'static str {
        "INT"
    }
    fn random_value(&self, rng: &mut SplitMix64) -> CellGen {
        let v = loop {
            let candidate = rng.next_i32();
            if candidate != i32::MIN {
                break candidate;
            }
        };
        CellGen {
            literal: v.to_string(),
            hash: v as i64,
        }
    }
    fn observed_hash(&self, view: &BatchView<'_>, col: usize, row: usize) -> i64 {
        let ColumnView::Int(c) = view.column(col).unwrap() else {
            panic!("col {col} not Int");
        };
        c.value(row) as i64
    }
}

// --- Short -------------------------------------------------------------

struct ShortGenerator;
impl ColumnGenerator for ShortGenerator {
    fn sql_type(&self) -> &'static str {
        "SHORT"
    }
    fn supports_null(&self) -> bool {
        false
    }
    fn random_value(&self, rng: &mut SplitMix64) -> CellGen {
        // Java emits `(short)(rnd.nextInt(65535) - 32767)` — i16 range
        // shifted to exclude `Short.MIN_VALUE` (which is i16's NULL
        // representation in QuestDB).
        let v = (rng.gen_range_u32(65_535) as i32 - 32_767) as i16;
        CellGen {
            literal: format!("CAST({v} AS SHORT)"),
            hash: v as i64,
        }
    }
    fn observed_hash(&self, view: &BatchView<'_>, col: usize, row: usize) -> i64 {
        let ColumnView::Short(c) = view.column(col).unwrap() else {
            panic!("col {col} not Short");
        };
        c.value(row) as i64
    }
}

// --- Byte --------------------------------------------------------------

struct ByteGenerator;
impl ColumnGenerator for ByteGenerator {
    fn sql_type(&self) -> &'static str {
        "BYTE"
    }
    fn supports_null(&self) -> bool {
        false
    }
    fn random_value(&self, rng: &mut SplitMix64) -> CellGen {
        let v = (rng.gen_range_u32(255) as i32 - 127) as i8;
        CellGen {
            literal: format!("CAST({v} AS BYTE)"),
            hash: v as i64,
        }
    }
    fn observed_hash(&self, view: &BatchView<'_>, col: usize, row: usize) -> i64 {
        let ColumnView::Byte(c) = view.column(col).unwrap() else {
            panic!("col {col} not Byte");
        };
        c.value(row) as i64
    }
}

// --- Boolean -----------------------------------------------------------

struct BooleanGenerator;
impl ColumnGenerator for BooleanGenerator {
    fn sql_type(&self) -> &'static str {
        "BOOLEAN"
    }
    fn supports_null(&self) -> bool {
        false
    }
    fn random_value(&self, rng: &mut SplitMix64) -> CellGen {
        let v = rng.next_bool();
        CellGen {
            literal: if v { "true".into() } else { "false".into() },
            hash: if v { 1 } else { 0 },
        }
    }
    fn observed_hash(&self, view: &BatchView<'_>, col: usize, row: usize) -> i64 {
        let ColumnView::Boolean(c) = view.column(col).unwrap() else {
            panic!("col {col} not Boolean");
        };
        if c.value(row) != 0 { 1 } else { 0 }
    }
}

// --- Double ------------------------------------------------------------

struct DoubleGenerator;
impl ColumnGenerator for DoubleGenerator {
    fn sql_type(&self) -> &'static str {
        "DOUBLE"
    }
    fn random_value(&self, rng: &mut SplitMix64) -> CellGen {
        // Java retries NaN / Infinity. The same logic catches FP
        // sentinels that QuestDB stores as NULL.
        let v = loop {
            let candidate = rng.next_f64();
            if candidate.is_finite() {
                break candidate;
            }
        };
        CellGen {
            literal: format_double_literal(v),
            hash: v.to_bits() as i64,
        }
    }
    fn observed_hash(&self, view: &BatchView<'_>, col: usize, row: usize) -> i64 {
        let ColumnView::Double(c) = view.column(col).unwrap() else {
            panic!("col {col} not Double");
        };
        c.value(row).to_bits() as i64
    }
}

// --- Float -------------------------------------------------------------

struct FloatGenerator;
impl ColumnGenerator for FloatGenerator {
    fn sql_type(&self) -> &'static str {
        "FLOAT"
    }
    fn random_value(&self, rng: &mut SplitMix64) -> CellGen {
        let v = loop {
            let candidate = rng.next_f32();
            if candidate.is_finite() {
                break candidate;
            }
        };
        CellGen {
            literal: format!("CAST({} AS FLOAT)", format_float_literal(v)),
            hash: v.to_bits() as i64,
        }
    }
    fn observed_hash(&self, view: &BatchView<'_>, col: usize, row: usize) -> i64 {
        let ColumnView::Float(c) = view.column(col).unwrap() else {
            panic!("col {col} not Float");
        };
        c.value(row).to_bits() as i64
    }
}

// --- Char --------------------------------------------------------------

struct CharGenerator;
impl ColumnGenerator for CharGenerator {
    fn sql_type(&self) -> &'static str {
        "CHAR"
    }
    fn supports_null(&self) -> bool {
        false
    }
    fn random_value(&self, rng: &mut SplitMix64) -> CellGen {
        // Java emits ASCII A..Z. QuestDB stores CHAR as a 2-byte UTF-16
        // code unit, but the wire is the raw u16 value.
        let c = (b'A' + (rng.gen_range_u32(26) as u8)) as char;
        CellGen {
            literal: format!("'{c}'"),
            hash: c as i64,
        }
    }
    fn observed_hash(&self, view: &BatchView<'_>, col: usize, row: usize) -> i64 {
        let ColumnView::Char(c) = view.column(col).unwrap() else {
            panic!("col {col} not Char");
        };
        c.value(row) as i64
    }
}

// --- Timestamp ---------------------------------------------------------

struct TimestampGenerator;
impl ColumnGenerator for TimestampGenerator {
    fn sql_type(&self) -> &'static str {
        "TIMESTAMP"
    }
    fn random_value(&self, rng: &mut SplitMix64) -> CellGen {
        // Java: `rnd.nextLong() & 0x0FFF_FFFFFFFFFFFFL` — keeps the
        // value positive and well below TIMESTAMP_NULL (`Long.MIN`).
        let v = rng.next_i64() & 0x0FFF_FFFF_FFFF_FFFF;
        CellGen {
            literal: format!("CAST({v} AS TIMESTAMP)"),
            hash: v,
        }
    }
    fn observed_hash(&self, view: &BatchView<'_>, col: usize, row: usize) -> i64 {
        let ColumnView::Timestamp(c) = view.column(col).unwrap() else {
            panic!("col {col} not Timestamp");
        };
        c.value(row)
    }
}

// --- TimestampNanos ----------------------------------------------------

struct TimestampNanosGenerator;
impl ColumnGenerator for TimestampNanosGenerator {
    fn sql_type(&self) -> &'static str {
        "TIMESTAMP_NS"
    }
    fn random_value(&self, rng: &mut SplitMix64) -> CellGen {
        let v = rng.next_i64() & 0x0FFF_FFFF_FFFF_FFFF;
        CellGen {
            literal: format!("CAST({v} AS TIMESTAMP_NS)"),
            hash: v,
        }
    }
    fn observed_hash(&self, view: &BatchView<'_>, col: usize, row: usize) -> i64 {
        let ColumnView::TimestampNanos(c) = view.column(col).unwrap() else {
            panic!("col {col} not TimestampNanos");
        };
        c.value(row)
    }
}

// --- Date --------------------------------------------------------------

struct DateGenerator;
impl ColumnGenerator for DateGenerator {
    fn sql_type(&self) -> &'static str {
        "DATE"
    }
    fn random_value(&self, rng: &mut SplitMix64) -> CellGen {
        let v = rng.next_i64() & 0x0000_FFFF_FFFF_FFFF;
        CellGen {
            literal: format!("CAST({v} AS DATE)"),
            hash: v,
        }
    }
    fn observed_hash(&self, view: &BatchView<'_>, col: usize, row: usize) -> i64 {
        let ColumnView::Date(c) = view.column(col).unwrap() else {
            panic!("col {col} not Date");
        };
        c.value(row)
    }
}

// --- Varchar -----------------------------------------------------------

struct VarcharGenerator;
impl ColumnGenerator for VarcharGenerator {
    fn sql_type(&self) -> &'static str {
        "VARCHAR"
    }
    fn random_value(&self, rng: &mut SplitMix64) -> CellGen {
        let len = rng.gen_range_usize(30);
        let s = random_ascii_string(rng, len);
        let mut lit = String::with_capacity(s.len() + 16);
        lit.push_str("CAST('");
        for c in s.chars() {
            if c == '\'' {
                lit.push_str("''");
            } else {
                lit.push(c);
            }
        }
        lit.push_str("' AS VARCHAR)");
        CellGen {
            literal: lit,
            hash: hash_bytes(s.as_bytes()),
        }
    }
    fn observed_hash(&self, view: &BatchView<'_>, col: usize, row: usize) -> i64 {
        let ColumnView::Varchar(c) = view.column(col).unwrap() else {
            panic!("col {col} not Varchar");
        };
        match c.value(row) {
            Some(s) => hash_bytes(s.as_bytes()),
            None => panic!("col {col} row {row} unexpected NULL varchar"),
        }
    }
}

// --- Symbol ------------------------------------------------------------

/// Pre-built pool of symbol values shared across rows of the same column.
/// The Java test uses `SymbolGenerator("lo", 8)` and `("hi", 1000)`; we
/// keep `lo` (small pool exercises dict reuse) and `hi` (large pool
/// stresses dict spill).
struct SymbolGenerator {
    pool: Vec<String>,
}

impl SymbolGenerator {
    fn new(tag: &str, size: usize) -> Self {
        let pool = (0..size).map(|i| format!("s_{tag}_{i}")).collect();
        Self { pool }
    }
}

impl ColumnGenerator for SymbolGenerator {
    fn sql_type(&self) -> &'static str {
        "SYMBOL"
    }
    fn random_value(&self, rng: &mut SplitMix64) -> CellGen {
        let s = &self.pool[rng.gen_range_usize(self.pool.len())];
        CellGen {
            literal: format!("CAST('{s}' AS SYMBOL)"),
            hash: hash_bytes(s.as_bytes()),
        }
    }
    fn observed_hash(&self, view: &BatchView<'_>, col: usize, row: usize) -> i64 {
        let ColumnView::Symbol(c) = view.column(col).unwrap() else {
            panic!("col {col} not Symbol");
        };
        match c.resolve(row) {
            Some(s) => hash_bytes(s.as_bytes()),
            None => panic!("col {col} row {row} unexpected NULL symbol"),
        }
    }
}

// --- Uuid --------------------------------------------------------------

struct UuidGenerator;
impl ColumnGenerator for UuidGenerator {
    fn sql_type(&self) -> &'static str {
        "UUID"
    }
    fn random_value(&self, rng: &mut SplitMix64) -> CellGen {
        // Java guards against `(MIN, MIN)` NULL sentinel by forcing
        // lo=0 in that case. Our random landing on both halves =
        // `i64::MIN` is astronomically unlikely; the guard is still
        // cheap.
        let mut lo = rng.next_u64();
        let hi = rng.next_u64();
        if lo == i64::MIN as u64 && hi == i64::MIN as u64 {
            lo = 0;
        }
        let lo_bytes = lo.to_le_bytes();
        let hi_bytes = hi.to_le_bytes();
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&lo_bytes);
        bytes[8..].copy_from_slice(&hi_bytes);
        // Java: hi ^ lo. Use signed i64 reinterpretation to match.
        let hash = (hi ^ lo) as i64;
        // UUID literal must be the canonical 8-4-4-4-12 hex string
        // in big-endian byte order; QuestDB parses both halves from
        // there. The byte layout in our `bytes` is little-endian
        // half-by-half, so reorder for the literal.
        let hi_be = hi.to_be_bytes();
        let lo_be = lo.to_be_bytes();
        let uuid_str = format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            hi_be[0],
            hi_be[1],
            hi_be[2],
            hi_be[3],
            hi_be[4],
            hi_be[5],
            hi_be[6],
            hi_be[7],
            lo_be[0],
            lo_be[1],
            lo_be[2],
            lo_be[3],
            lo_be[4],
            lo_be[5],
            lo_be[6],
            lo_be[7]
        );
        let _ = bytes; // bytes layout pinned by the wire round-trip below.
        CellGen {
            literal: format!("CAST('{uuid_str}' AS UUID)"),
            hash,
        }
    }
    fn observed_hash(&self, view: &BatchView<'_>, col: usize, row: usize) -> i64 {
        let ColumnView::Uuid(c) = view.column(col).unwrap() else {
            panic!("col {col} not Uuid");
        };
        let bytes = c.value(row);
        let mut lo_arr = [0u8; 8];
        let mut hi_arr = [0u8; 8];
        lo_arr.copy_from_slice(&bytes[..8]);
        hi_arr.copy_from_slice(&bytes[8..]);
        let lo = u64::from_le_bytes(lo_arr);
        let hi = u64::from_le_bytes(hi_arr);
        (hi ^ lo) as i64
    }
}

// ---------------------------------------------------------------------------
// Generator catalogue (one entry per type the catalogue advertises).
// ---------------------------------------------------------------------------

fn build_generators() -> Vec<Box<dyn ColumnGenerator>> {
    vec![
        Box::new(LongGenerator),
        Box::new(IntGenerator),
        Box::new(ShortGenerator),
        Box::new(ByteGenerator),
        Box::new(BooleanGenerator),
        Box::new(DoubleGenerator),
        Box::new(FloatGenerator),
        Box::new(CharGenerator),
        Box::new(TimestampGenerator),
        Box::new(TimestampNanosGenerator),
        Box::new(DateGenerator),
        Box::new(VarcharGenerator),
        Box::new(SymbolGenerator::new("lo", 8)),
        Box::new(SymbolGenerator::new("hi", 1000)),
        Box::new(UuidGenerator),
    ]
}

// ---------------------------------------------------------------------------
// Misc helpers.
// ---------------------------------------------------------------------------

/// Build a printable-ASCII string of `len` bytes, avoiding the
/// single-quote character (so we don't have to escape inside
/// `CAST('...' AS VARCHAR)`). Mirrors Java's `randomAsciiString`.
fn random_ascii_string(rng: &mut SplitMix64, len: usize) -> String {
    let mut s = String::with_capacity(len);
    for _ in 0..len {
        // [0x20, 0x7E) avoiding 0x27 (`'`).
        let mut c = 0x20 + rng.gen_range_u32(0x7E - 0x20) as u8;
        if c == 0x27 {
            c = 0x20;
        }
        s.push(c as char);
    }
    s
}

/// Format an f64 as a SQL DOUBLE literal that QuestDB will round-trip
/// bit-for-bit. Rust's default `Display` of `f64` produces the shortest
/// representation that round-trips, which is what we want here.
fn format_double_literal(v: f64) -> String {
    let formatted = format!("{v:?}");
    // Special-case the integer-valued doubles so the parser sees a
    // decimal point and picks DOUBLE rather than LONG.
    if !formatted.contains('.') && !formatted.contains('e') && !formatted.contains('E') {
        format!("{formatted}.0")
    } else {
        formatted
    }
}

fn format_float_literal(v: f32) -> String {
    let formatted = format!("{v:?}");
    if !formatted.contains('.') && !formatted.contains('e') && !formatted.contains('E') {
        format!("{formatted}.0")
    } else {
        formatted
    }
}

/// Picks a row count from `{1, 2, 7, 64, 257, 499, 500}` — small / mid
/// / batch-boundary. Mirrors Java's `pickRowCount`.
fn pick_row_count(rng: &mut SplitMix64) -> usize {
    const CHOICES: [usize; 7] = [1, 2, 7, 64, 257, 499, 500];
    CHOICES[rng.gen_range_usize(CHOICES.len())]
}

// ---------------------------------------------------------------------------
// run_one_case driver.
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)] // mirrors Java's runOneCase shape
fn run_one_case(
    srv: &QuestDbServer,
    reader: &mut Reader,
    rng: &mut SplitMix64,
    generators: &[Box<dyn ColumnGenerator>],
    table_stem: &str,
    iter: usize,
    col_count: usize,
) {
    assert!((1..=16).contains(&col_count), "col_count out of range");

    // Pick column generators for this case (with replacement).
    let mut picked: Vec<&Box<dyn ColumnGenerator>> = Vec::with_capacity(col_count);
    for _ in 0..col_count {
        picked.push(&generators[rng.gen_range_usize(generators.len())]);
    }
    let row_count = pick_row_count(rng);
    let table = format!("{table_stem}_{iter}");

    // CREATE TABLE.
    let mut create = format!("create table \"{table}\" (id LONG, ts TIMESTAMP");
    for (i, g) in picked.iter().enumerate() {
        create.push_str(&format!(", c{i} {}", g.sql_type()));
    }
    create.push_str(") timestamp(ts) partition by day wal");
    let status = srv.http_exec(&create);
    assert!((200..400).contains(&status), "create http={status}");

    // Generate expected per-cell hashes and the INSERT literals.
    let mut expected_hash = vec![vec![0i64; col_count]; row_count];
    let mut expected_null = vec![vec![false; col_count]; row_count];
    let mut values_clauses: Vec<String> = Vec::with_capacity(row_count);
    for r in 0..row_count {
        let id = r as i64 + 1; // 1-based for the closed-form sum heuristic.
        let ts = id * 1_000; // arbitrary spacing; ts not verified per-cell.
        let mut row_lits: Vec<String> = Vec::with_capacity(col_count + 2);
        row_lits.push(format!("{id}L"));
        row_lits.push(format!("CAST({ts} AS TIMESTAMP)"));
        for (c, g) in picked.iter().enumerate() {
            // 20% NULL chance, only when the type supports it.
            let nullable = g.supports_null();
            let force_null = nullable && rng.gen_range_u32(5) == 0;
            if force_null {
                expected_null[r][c] = true;
                row_lits.push(format!("CAST(NULL AS {})", g.sql_type()));
            } else {
                let cell = g.random_value(rng);
                expected_hash[r][c] = cell.hash;
                row_lits.push(cell.literal);
            }
        }
        values_clauses.push(format!("({})", row_lits.join(",")));
    }
    let insert = format!(
        "insert into \"{table}\" values {}",
        values_clauses.join(",")
    );
    let status = srv.http_exec(&insert);
    assert!((200..400).contains(&status), "insert http={status}");

    // Wait for WAL to apply.
    wait_for_rows(srv, &table, row_count);

    // SELECT and verify per-cell.
    let mut col_list = String::new();
    for c in 0..col_count {
        if c > 0 {
            col_list.push(',');
        }
        col_list.push_str(&format!("c{c}"));
    }
    let select = format!("select {col_list} from \"{table}\" order by id");
    let mut cur = reader.prepare(select).execute().expect("execute");
    let mut row_offset = 0usize;
    while let Some(view) = cur.next_batch().expect("next_batch") {
        let n = view.row_count();
        for r in 0..n {
            let global_row = row_offset + r;
            // `c` indexes three parallel arrays — `picked[c]`,
            // `expected_hash[global_row][c]`, `expected_null[global_row][c]`.
            // Rewriting as `enumerate()` would drop the explicit index
            // and hurt readability for no perf benefit.
            #[allow(clippy::needless_range_loop)]
            for c in 0..col_count {
                let is_null = view
                    .column(c)
                    .ok()
                    .map(|cv| match cv {
                        ColumnView::Boolean(x) => x.is_null(r),
                        ColumnView::Byte(x) => x.is_null(r),
                        ColumnView::Short(x) => x.is_null(r),
                        ColumnView::Int(x) => x.is_null(r),
                        ColumnView::Long(x) => x.is_null(r),
                        ColumnView::Float(x) => x.is_null(r),
                        ColumnView::Double(x) => x.is_null(r),
                        ColumnView::Symbol(x) => x.is_null(r),
                        ColumnView::Timestamp(x) => x.is_null(r),
                        ColumnView::Date(x) => x.is_null(r),
                        ColumnView::Uuid(x) => x.is_null(r),
                        ColumnView::TimestampNanos(x) => x.is_null(r),
                        ColumnView::Char(x) => x.is_null(r),
                        ColumnView::Varchar(x) => x.is_null(r),
                        _ => false,
                    })
                    .unwrap_or(false);
                assert_eq!(
                    is_null, expected_null[global_row][c],
                    "iter={iter} row={global_row} col={c} null-mismatch"
                );
                if !is_null {
                    let observed = picked[c].observed_hash(&view, c, r);
                    assert_eq!(
                        observed,
                        expected_hash[global_row][c],
                        "iter={iter} row={global_row} col={c} type={} hash-mismatch",
                        picked[c].sql_type()
                    );
                }
            }
        }
        row_offset += n;
    }
    assert_eq!(
        row_offset, row_count,
        "iter={iter} row_count drift expected={row_count} got={row_offset}"
    );
    drop(cur);

    // Drop the table so the next iteration starts clean (and the
    // shared singleton's tempdir doesn't grow unbounded across runs).
    let _ = srv.http_exec(&format!("drop table \"{table}\""));
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

/// Poll for at least `expected` rows applied. WAL apply is async from
/// the INSERT's HTTP response.
fn wait_for_rows(srv: &QuestDbServer, table: &str, expected: usize) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let sql = format!("select count(*) from \"{table}\"");
    while std::time::Instant::now() < deadline {
        if let Ok(mut r) = Reader::from_conf(srv.qwp_conf())
            && let Ok(mut cur) = r.prepare(&sql).execute()
            && let Ok(Some(view)) = cur.next_batch()
            && let Ok(c) = view.column(0)
        {
            let n = match c {
                ColumnView::Long(c) => c.value(0),
                ColumnView::Int(c) => c.value(0) as i64,
                _ => -1,
            };
            if n as usize >= expected {
                return;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(80));
    }
    panic!("{table} did not reach {expected} rows within 30s");
}

/// Ports `testRandomSchemaRoundtrip`. 15 fuzz cases, each with a
/// fresh `Reader` (so per-connection state pollution can't mask a
/// bug). Column count picked from `1..=6` per Java original. Server
/// is booted once with `startFragmented(pickChunk())` so all 15
/// iterations run against the same chunk size — matches the Java
/// pattern where `startFragmented(chunk)` lives outside the loop.
#[test]
fn random_schema_roundtrip() {
    let mut rng = SplitMix64::new(fuzz_seed_for("random_schema_roundtrip"));
    let chunk = pick_chunk(&mut rng);
    let compression = pick_compression(&mut rng);
    eprintln!(
        "[random_schema_roundtrip] chunk={chunk} compression={:?}",
        if compression.is_empty() {
            "default"
        } else {
            &compression
        }
    );
    let srv = start_fragmented(chunk);
    let generators = build_generators();
    for iter in 0..15 {
        let col_count = 1 + rng.gen_range_usize(6); // 1..=6
        let mut reader = make_reader_with(&srv, &compression);
        run_one_case(
            &srv,
            &mut reader,
            &mut rng,
            &generators,
            "fuzz_iter",
            iter,
            col_count,
        );
    }
}

/// Ports `testBackToBackQueriesSameConnection`. 12 cases on a single
/// shared `Reader`, exercising per-connection schema-registry / symbol-
/// dict state across queries. Column count picked from `1..=4`.
#[test]
fn back_to_back_queries_same_connection() {
    let mut rng = SplitMix64::new(fuzz_seed_for("back_to_back_queries_same_connection"));
    let chunk = pick_chunk(&mut rng);
    let compression = pick_compression(&mut rng);
    eprintln!(
        "[back_to_back_queries_same_connection] chunk={chunk} compression={:?}",
        if compression.is_empty() {
            "default"
        } else {
            &compression
        }
    );
    let srv = start_fragmented(chunk);
    let generators = build_generators();
    let mut reader = make_reader_with(&srv, &compression);
    for iter in 0..12 {
        let col_count = 1 + rng.gen_range_usize(4); // 1..=4
        run_one_case(
            &srv,
            &mut reader,
            &mut rng,
            &generators,
            "fuzz_back",
            iter,
            col_count,
        );
    }
}

/// Ports `testWideTables`. One case with 10..=16 columns to stress the
/// per-column state arrays and the schema-block encoder under a wide
/// schema. Same Reader, same hash-verification pipeline as the random
/// schema test.
#[test]
fn wide_tables() {
    let mut rng = SplitMix64::new(fuzz_seed_for("wide_tables"));
    let chunk = pick_chunk(&mut rng);
    let compression = pick_compression(&mut rng);
    eprintln!(
        "[wide_tables] chunk={chunk} compression={:?}",
        if compression.is_empty() {
            "default"
        } else {
            &compression
        }
    );
    let srv = start_fragmented(chunk);
    let generators = build_generators();
    let mut reader = make_reader_with(&srv, &compression);
    let col_count = 10 + rng.gen_range_usize(7); // 10..=16
    run_one_case(
        &srv,
        &mut reader,
        &mut rng,
        &generators,
        "fuzz_wide",
        0,
        col_count,
    );
}
