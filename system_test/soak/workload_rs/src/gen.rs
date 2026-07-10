//! Deterministic, cross-language soak data generator — **the shared spec**.
//!
//! The soak oracle proves "no data loss, correct values for every datatype" by
//! regenerating the *expected read-back* of any row from the seed alone, then
//! comparing it against what QuestDB returns. For that to work the Rust, C, and
//! Python workloads must emit **byte-identical** values from the same
//! `(seed, worker_id, seq)`. This module is the reference implementation and
//! the contract the C / Python mirrors must reproduce exactly.
//!
//! # The contract (reimplement verbatim in every language)
//!
//! 1. **PRNG** — [`splitmix64`]. A 64-bit state-in / value-out mixer using only
//!    wrapping add/mul and xor-shift, so it is identical on every platform.
//! 2. **Field draw** — [`draw`]. Folds `(seed, worker_id, seq, col, sub)` into
//!    one `u64` then mixes it. `col` is the column index; `sub` selects
//!    independent draws for multi-part values (e.g. a varchar's length vs its
//!    bytes). Never derive two fields from the same draw.
//! 3. **Edge cadence** — [`edge_index`]. Deterministically forces NULLs and
//!    boundary values on a per-column phase so every edge is *guaranteed* hit
//!    over a run, not merely probable.
//! 4. **Canonicalisation** — each type maps its sent value to the
//!    [`Expected`] the server stores (e.g. a double `NaN` is stored as `NULL`).
//!
//! `soak-workload gen-vectors` emits golden vectors (JSON) so the C / Python
//! mirrors can assert conformance against this reference in their own tests.

use std::fmt::Write as _;

/// The 22 QWP wire types, in the canonical order of
/// `questdb-rs/src/ingress/column_sender/wire.rs`. Each ingress leg writes one
/// column per variant its route supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QwpType {
    Boolean,
    Byte,
    Short,
    Int,
    Long,
    Float,
    Double,
    Symbol,
    Timestamp,
    Date,
    Uuid,
    Long256,
    Geohash,
    Varchar,
    TimestampNanos,
    DoubleArray,
    Decimal64,
    Decimal128,
    Decimal256,
    Char,
    Binary,
    Ipv4,
}

/// Every type, in wire order. `QWP_TYPES.len() == 22`.
pub const QWP_TYPES: [QwpType; 22] = [
    QwpType::Boolean,
    QwpType::Byte,
    QwpType::Short,
    QwpType::Int,
    QwpType::Long,
    QwpType::Float,
    QwpType::Double,
    QwpType::Symbol,
    QwpType::Timestamp,
    QwpType::Date,
    QwpType::Uuid,
    QwpType::Long256,
    QwpType::Geohash,
    QwpType::Varchar,
    QwpType::TimestampNanos,
    QwpType::DoubleArray,
    QwpType::Decimal64,
    QwpType::Decimal128,
    QwpType::Decimal256,
    QwpType::Char,
    QwpType::Binary,
    QwpType::Ipv4,
];

impl QwpType {
    /// The wire type byte (mirrors the `QWP_TYPE_*` constants).
    pub fn tag(self) -> u8 {
        match self {
            QwpType::Boolean => 0x01,
            QwpType::Byte => 0x02,
            QwpType::Short => 0x03,
            QwpType::Int => 0x04,
            QwpType::Long => 0x05,
            QwpType::Float => 0x06,
            QwpType::Double => 0x07,
            QwpType::Symbol => 0x09,
            QwpType::Timestamp => 0x0A,
            QwpType::Date => 0x0B,
            QwpType::Uuid => 0x0C,
            QwpType::Long256 => 0x0D,
            QwpType::Geohash => 0x0E,
            QwpType::Varchar => 0x0F,
            QwpType::TimestampNanos => 0x10,
            QwpType::DoubleArray => 0x11,
            QwpType::Decimal64 => 0x13,
            QwpType::Decimal128 => 0x14,
            QwpType::Decimal256 => 0x15,
            QwpType::Char => 0x16,
            QwpType::Binary => 0x17,
            QwpType::Ipv4 => 0x18,
        }
    }

    /// Stable column name for this type's column in a soak table, e.g.
    /// `c_double`. Used verbatim by the DDL, the ingest legs, and the oracle's
    /// `SELECT`.
    pub fn col_name(self) -> &'static str {
        match self {
            QwpType::Boolean => "c_bool",
            QwpType::Byte => "c_byte",
            QwpType::Short => "c_short",
            QwpType::Int => "c_int",
            QwpType::Long => "c_long",
            QwpType::Float => "c_float",
            QwpType::Double => "c_double",
            QwpType::Symbol => "c_symbol",
            QwpType::Timestamp => "c_ts",
            QwpType::Date => "c_date",
            QwpType::Uuid => "c_uuid",
            QwpType::Long256 => "c_long256",
            QwpType::Geohash => "c_geohash",
            QwpType::Varchar => "c_varchar",
            QwpType::TimestampNanos => "c_ts_nanos",
            QwpType::DoubleArray => "c_dbl_arr",
            QwpType::Decimal64 => "c_dec64",
            QwpType::Decimal128 => "c_dec128",
            QwpType::Decimal256 => "c_dec256",
            QwpType::Char => "c_char",
            QwpType::Binary => "c_binary",
            QwpType::Ipv4 => "c_ipv4",
        }
    }

    /// Column index within a row: its position in [`QWP_TYPES`]. Feeds [`draw`]
    /// as `col`, so each type draws from an independent stream.
    pub fn col_index(self) -> u32 {
        QWP_TYPES
            .iter()
            .position(|&t| t == self)
            .expect("every QwpType is in QWP_TYPES") as u32
    }
}

/// SplitMix64 — the portable PRNG. State in, pseudo-random value out. Uses only
/// wrapping arithmetic and xor-shift, so it is bit-identical in Rust, C, and
/// Python. **Do not change the constants**: they are the cross-language
/// contract.
#[inline]
pub fn splitmix64(x: u64) -> u64 {
    let mut z = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

// Odd 64-bit multipliers fold each input dimension into distinct bit patterns
// before mixing. Any fixed odd constants work; these are arbitrary primes.
const K_WORKER: u64 = 0xD1B5_4A32_D192_ED03;
const K_SEQ: u64 = 0xA0761D6478BD642F_u64;
const K_COL: u64 = 0xE703_7ED1_A0B4_28DB;
const K_SUB: u64 = 0x8EBC_6AF0_9C88_C6E3;

/// Draw one `u64` for field `(col, sub)` of row `(worker_id, seq)` under
/// `seed`. Independent `sub` values give independent draws for the same field
/// (length vs bytes, array element `i`, …).
#[inline]
pub fn draw(seed: u64, worker_id: u32, seq: u64, col: u32, sub: u32) -> u64 {
    let mut h = seed;
    h ^= u64::from(worker_id).wrapping_mul(K_WORKER);
    h = splitmix64(h);
    h ^= seq.wrapping_mul(K_SEQ);
    h = splitmix64(h);
    h ^= u64::from(col).wrapping_mul(K_COL);
    h = splitmix64(h);
    h ^= u64::from(sub).wrapping_mul(K_SUB);
    splitmix64(h)
}

/// Number of distinct edge slots scheduled per column, including the "no edge,
/// use a random value" slot at index 0. Each type interprets slots `1..` as its
/// own boundary values (see [`gen_expected`]).
const EDGE_SLOTS: u64 = 12;
/// One row in every `EDGE_PERIOD` (per column phase) is an edge row. Prime so
/// edge rows do not align with batch boundaries.
const EDGE_PERIOD: u64 = 23;

/// Which edge slot column `col` takes at `seq`, or `None` for an ordinary
/// random value. Phase-shifting by `col` means different columns hit their
/// NULL / boundary rows at different `seq`, and cycling `(seq / EDGE_PERIOD)`
/// through `1..EDGE_SLOTS` guarantees every edge is exercised over a run.
#[inline]
pub fn edge_index(seq: u64, col: u32) -> Option<u32> {
    let phase = seq.wrapping_add(u64::from(col).wrapping_mul(7));
    if phase % EDGE_PERIOD != 0 {
        return None;
    }
    let slot = (phase / EDGE_PERIOD) % EDGE_SLOTS;
    if slot == 0 {
        None
    } else {
        Some(slot as u32)
    }
}

/// The value QuestDB is expected to return for a cell, in a form the oracle can
/// compare against a SQL/HTTP result. Exotic types canonicalise to the text
/// form QuestDB renders (calibrated against a live server in the oracle stage).
#[derive(Debug, Clone, PartialEq)]
pub enum Expected {
    /// SQL `NULL` — the cell is absent or was canonicalised away (e.g. NaN).
    Null,
    /// Integral types: byte/short/int/long, date & timestamps (epoch units),
    /// ipv4 (as its 32-bit value). Stored widened to `i128`.
    Int(i128),
    /// `float`/`double`. Compared bit-exactly (both sides regenerate the same
    /// value), so `-0.0` and normal values are distinct but reproducible.
    Float(f64),
    /// Boolean.
    Bool(bool),
    /// Text-rendered value: symbol, varchar, char, uuid, long256, geohash,
    /// decimals, arrays. `text` is the exact string QuestDB is expected to
    /// return for the cell.
    Text(String),
    /// Raw bytes for `binary`.
    Bytes(Vec<u8>),
}

/// One generated cell: its type and the value the server should store. The
/// Rust ingest leg maps `expected` back to the typed sender call; the oracle
/// compares `expected` against the query result. When the sent value differs
/// from the stored value (only NaN today) the leg keys off `ty` + `expected`
/// to decide what to transmit.
#[derive(Debug, Clone, PartialEq)]
pub struct Cell {
    pub ty: QwpType,
    pub expected: Expected,
}

/// Generate the full row for `(seed, worker_id, seq)`: one [`Cell`] per QWP
/// type, in [`QWP_TYPES`] order.
pub fn gen_row(seed: u64, worker_id: u32, seq: u64) -> Vec<Cell> {
    QWP_TYPES
        .iter()
        .map(|&ty| Cell {
            ty,
            expected: gen_expected(seed, worker_id, seq, ty),
        })
        .collect()
}

/// Non-ASCII sample strings, cycled for symbol/varchar edges — exercises the
/// Unicode case-folding lookup path on the server and the client.
const UNICODE_SAMPLES: [&str; 6] = ["Straße", "café", "Ω-Ω", "日本語", "naïve", "ÀÉÎ"];

/// The expected stored value for one cell. Ordinary rows draw a random value;
/// edge rows ([`edge_index`]) substitute a boundary value or NULL.
pub fn gen_expected(seed: u64, worker_id: u32, seq: u64, ty: QwpType) -> Expected {
    let col = ty.col_index();
    let edge = edge_index(seq, col);
    let d0 = draw(seed, worker_id, seq, col, 0);

    match ty {
        QwpType::Boolean => Expected::Bool(d0 & 1 == 0),

        QwpType::Byte => match edge {
            Some(1) => Expected::Int(i128::from(i8::MIN)),
            Some(2) => Expected::Int(i128::from(i8::MAX)),
            Some(3) => Expected::Int(0),
            // `byte` is not nullable in QuestDB; no NULL edge.
            _ => Expected::Int(i128::from(d0 as i8)),
        },

        QwpType::Short => match edge {
            Some(1) => Expected::Int(i128::from(i16::MIN)),
            Some(2) => Expected::Int(i128::from(i16::MAX)),
            Some(3) => Expected::Int(0),
            _ => Expected::Int(i128::from(d0 as i16)),
        },

        QwpType::Int => match edge {
            Some(1) => Expected::Null, // INT NULL sentinel exists in QuestDB
            Some(2) => Expected::Int(i128::from(i32::MAX)),
            // i32::MIN is QuestDB's INT NULL sentinel; never send it as a value.
            Some(3) => Expected::Int(i128::from(i32::MIN + 1)),
            Some(4) => Expected::Int(0),
            _ => Expected::Int(i128::from(d0 as i32)),
        },

        QwpType::Long => match edge {
            Some(1) => Expected::Null,
            Some(2) => Expected::Int(i128::from(i64::MAX)),
            Some(3) => Expected::Int(i128::from(i64::MIN + 1)),
            Some(4) => Expected::Int(0),
            _ => Expected::Int(i128::from(d0 as i64)),
        },

        // NaN canonicalises to NULL (documented). Infinity is deliberately NOT
        // emitted: QuestDB's stored form for ±Inf is not something this v1
        // asserts, so the generator only ever produces finite values or NULL.
        QwpType::Float => match edge {
            Some(1) => Expected::Null, // NaN stored as NULL
            Some(2) => Expected::Float(f64::from(f32::MAX)),
            Some(3) => Expected::Float(f64::from(f32::MIN)),
            Some(4) => Expected::Float(0.0),
            _ => Expected::Float(f64::from(f32_from(d0))),
        },

        QwpType::Double => match edge {
            Some(1) => Expected::Null, // NaN stored as NULL
            Some(2) => Expected::Float(f64::MAX),
            Some(3) => Expected::Float(f64::MIN),
            Some(4) => Expected::Float(0.0),
            _ => Expected::Float(f64_from(d0)),
        },

        QwpType::Symbol => match edge {
            Some(1) => Expected::Null,
            Some(2) => {
                Expected::Text(UNICODE_SAMPLES[(d0 as usize) % UNICODE_SAMPLES.len()].into())
            }
            Some(3) => Expected::Text("s".into()),
            // Bounded cardinality so the symbol dict interns and reuses.
            _ => Expected::Text(format!("sym_{}", d0 % 512)),
        },

        QwpType::Timestamp => match edge {
            Some(1) => Expected::Null,
            // Bounded to a sane epoch-micros window [2000-01-01, ~2065).
            _ => Expected::Int(i128::from(bounded_epoch(
                d0,
                946_684_800_000_000,
                3_000_000_000_000_000,
            ))),
        },

        QwpType::Date => match edge {
            Some(1) => Expected::Null,
            _ => Expected::Int(i128::from(bounded_epoch(
                d0,
                946_684_800_000,
                3_000_000_000_000,
            ))),
        },

        QwpType::Uuid => match edge {
            Some(1) => Expected::Null,
            Some(2) => Expected::Text(fmt_uuid(0)),
            _ => {
                let hi = d0;
                let lo = draw(seed, worker_id, seq, col, 1);
                Expected::Text(fmt_uuid((u128::from(hi) << 64) | u128::from(lo)))
            }
        },

        QwpType::Long256 => match edge {
            Some(1) => Expected::Null,
            Some(2) => Expected::Text("0x0".into()),
            _ => {
                let w = [
                    d0,
                    draw(seed, worker_id, seq, col, 1),
                    draw(seed, worker_id, seq, col, 2),
                    draw(seed, worker_id, seq, col, 3),
                ];
                Expected::Text(fmt_long256(w))
            }
        },

        // Geohash of a fixed precision; expected text is calibrated against the
        // server in the oracle stage (S4) — see the note in the module docs.
        QwpType::Geohash => match edge {
            Some(1) => Expected::Null,
            _ => Expected::Text(fmt_geohash(d0, GEOHASH_CHARS)),
        },

        QwpType::Varchar => match edge {
            Some(1) => Expected::Null,
            Some(2) => Expected::Text(String::new()), // empty string (distinct from NULL)
            Some(3) => {
                Expected::Text(UNICODE_SAMPLES[(d0 as usize) % UNICODE_SAMPLES.len()].into())
            }
            Some(4) => Expected::Text("x".repeat(4096)), // oversized
            _ => Expected::Text(gen_varchar(seed, worker_id, seq, col, d0)),
        },

        QwpType::TimestampNanos => match edge {
            Some(1) => Expected::Null,
            _ => Expected::Int(i128::from(bounded_epoch(
                d0,
                946_684_800_000_000_000,
                3_000_000_000_000_000_000,
            ))),
        },

        // Arrays and decimals: v1 canonical text; read-back format calibrated
        // in S4. Kept deterministic so the mirrors reproduce them.
        QwpType::DoubleArray => match edge {
            Some(1) => Expected::Null,
            Some(2) => Expected::Text("[]".into()), // zero-length
            _ => {
                let n = (d0 % 8) as u32 + 1;
                let mut vals = Vec::with_capacity(n as usize);
                for i in 0..n {
                    vals.push(f64_from(draw(seed, worker_id, seq, col, 10 + i)));
                }
                Expected::Text(fmt_f64_array(&vals))
            }
        },

        QwpType::Decimal64 => gen_decimal(edge, d0, 2),
        QwpType::Decimal128 => gen_decimal(edge, d0, 6),
        QwpType::Decimal256 => gen_decimal(edge, d0, 10),

        QwpType::Char => match edge {
            Some(1) => Expected::Null,
            Some(2) => Expected::Text("A".into()),
            // Printable ASCII to keep the round-trip unambiguous.
            _ => {
                let c = 0x21 + (d0 % 0x5E) as u8; // '!'..'~'
                Expected::Text((c as char).to_string())
            }
        },

        QwpType::Binary => match edge {
            Some(1) => Expected::Null,
            Some(2) => Expected::Bytes(Vec::new()), // empty
            _ => {
                let n = (d0 % 24) as u32 + 1;
                let mut b = Vec::with_capacity(n as usize);
                for i in 0..n {
                    b.push((draw(seed, worker_id, seq, col, 20 + i) & 0xFF) as u8);
                }
                Expected::Bytes(b)
            }
        },

        QwpType::Ipv4 => match edge {
            Some(1) => Expected::Null,
            Some(2) => Expected::Int(0),
            _ => Expected::Int(i128::from(d0 as u32)),
        },
    }
}

const GEOHASH_CHARS: usize = 8;
/// Geohash precision in bits: 8 base32 chars × 5 bits.
pub const GEOHASH_BITS: u32 = 40;

/// The actual `f64` elements of the `double_array` cell for `(seed, worker, seq)`
/// — what an ingest leg needs to send (the canonical [`Expected`] only carries
/// the hex-bit text form). `None` for the NULL edge, `Some(empty)` for the
/// zero-length edge. Mirrors the `DoubleArray` arm of [`gen_expected`] exactly.
pub fn double_array_values(seed: u64, worker_id: u32, seq: u64) -> Option<Vec<f64>> {
    let col = QwpType::DoubleArray.col_index();
    let d0 = draw(seed, worker_id, seq, col, 0);
    match edge_index(seq, col) {
        Some(1) => None,
        Some(2) => Some(Vec::new()),
        _ => {
            let n = (d0 % 8) as u32 + 1;
            Some(
                (0..n)
                    .map(|i| f64_from(draw(seed, worker_id, seq, col, 10 + i)))
                    .collect(),
            )
        }
    }
}

/// Raw geohash bits for `(seed, worker, seq)` — the value an ingest leg feeds
/// to `column_geohash` at [`GEOHASH_BITS`] precision. `None` for the NULL edge.
/// The stored base32 rendering is [`gen_expected`]'s `Geohash` text.
pub fn geohash_bits(seed: u64, worker_id: u32, seq: u64) -> Option<u64> {
    let col = QwpType::Geohash.col_index();
    if edge_index(seq, col) == Some(1) {
        return None;
    }
    Some(draw(seed, worker_id, seq, col, 0) & ((1u64 << GEOHASH_BITS) - 1))
}

/// Raw long256 words (little-endian, word 0 least-significant) for
/// `(seed, worker, seq)`. `None` for the NULL edge; all-zero for the `0x0`
/// edge. Mirrors the `Long256` arm of [`gen_expected`].
pub fn long256_words(seed: u64, worker_id: u32, seq: u64) -> Option<[u64; 4]> {
    let col = QwpType::Long256.col_index();
    match edge_index(seq, col) {
        Some(1) => None,
        Some(2) => Some([0, 0, 0, 0]),
        _ => Some([
            draw(seed, worker_id, seq, col, 0),
            draw(seed, worker_id, seq, col, 1),
            draw(seed, worker_id, seq, col, 2),
            draw(seed, worker_id, seq, col, 3),
        ]),
    }
}

// -------- helpers (all portable, all deterministic) --------

/// Map a `u64` draw to a **finite** `f32` (NaN and ±Inf are handled as edges /
/// canonicalised, so the random path never emits a non-finite value).
fn f32_from(d: u64) -> f32 {
    let v = f32::from_bits((d >> 32) as u32);
    if v.is_finite() {
        v
    } else {
        (d as i32) as f32 * 0.5
    }
}

/// Map a `u64` draw to a **finite** `f64`.
fn f64_from(d: u64) -> f64 {
    let v = f64::from_bits(d);
    if v.is_finite() {
        v
    } else {
        (d as i64) as f64 * 0.5
    }
}

/// A value in `[lo, hi)` derived from `d`, for bounded epoch timestamps/dates.
fn bounded_epoch(d: u64, lo: i64, hi: i64) -> i64 {
    let span = (hi - lo) as u64;
    lo + (d % span) as i64
}

fn fmt_uuid(v: u128) -> String {
    let hex = format!("{v:032x}");
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

fn fmt_long256(words: [u64; 4]) -> String {
    // Big-endian hex, most-significant word first, leading zeros trimmed to a
    // single `0x0` for the all-zero case.
    let mut s = String::from("0x");
    let mut started = false;
    for w in words.iter().rev() {
        if !started {
            if *w == 0 {
                continue;
            }
            let _ = write!(s, "{w:x}");
            started = true;
        } else {
            let _ = write!(s, "{w:016x}");
        }
    }
    if !started {
        s.push('0');
    }
    s
}

fn fmt_geohash(d: u64, chars: usize) -> String {
    const BASE32: &[u8; 32] = b"0123456789bcdefghjkmnpqrstuvwxyz";
    // Most-significant 5 bits first — QuestDB's canonical base32 rendering, so
    // the generated string matches the server's read-back of the same bits.
    let mut s = String::with_capacity(chars);
    for i in 0..chars {
        let idx = ((d >> (5 * (chars - 1 - i))) & 0x1F) as usize;
        s.push(BASE32[idx] as char);
    }
    s
}

/// Render an f64 array as bracketed, comma-separated **bit patterns**
/// (`{:016x}` of each element's bits). Decimal float text differs between
/// Rust and Python (`1` vs `1.0`, `1e30` vs `1e+30`), which would break the
/// byte-for-byte cross-language golden-vector parity; hex bits are identical
/// everywhere and still fully deterministic. The oracle maps QuestDB's
/// returned array into this same form for comparison (calibrated in S4).
fn fmt_f64_array(vals: &[f64]) -> String {
    let mut s = String::from("[");
    for (i, v) in vals.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        let _ = write!(s, "{:016x}", v.to_bits());
    }
    s.push(']');
    s
}

fn gen_varchar(seed: u64, worker_id: u32, seq: u64, col: u32, d0: u64) -> String {
    let len = (d0 % 32) as u32 + 1;
    let mut s = String::with_capacity(len as usize);
    for i in 0..len {
        let c = 0x20 + (draw(seed, worker_id, seq, col, 30 + i) % 0x5F) as u8; // ' '..'~'
        s.push(c as char);
    }
    s
}

/// Decimal unscaled magnitude cap: 18 digits, so the value fits `DECIMAL(18,2)`
/// — QuestDB's `dec64` column precision, the tightest of the three (dec128 /
/// dec256 columns are wider). Bounding here keeps the server from rejecting a
/// too-wide value with a schema mismatch.
const DEC_UNSCALED_MOD: u64 = 1_000_000_000_000_000_000;

fn gen_decimal(edge: Option<u32>, d0: u64, scale: u32) -> Expected {
    match edge {
        Some(1) => Expected::Null,
        Some(2) => Expected::Text(fmt_decimal(0, scale)),
        _ => {
            // Unsigned mod (identical in every language — signed `%` differs
            // between Rust's truncation and Python's floor) plus a sign bit.
            let mag = (d0 % DEC_UNSCALED_MOD) as i128;
            let unscaled = if d0 & (1 << 63) != 0 { -mag } else { mag };
            Expected::Text(fmt_decimal(unscaled, scale))
        }
    }
}

/// Render `unscaled * 10^-scale` as a fixed-point decimal string.
fn fmt_decimal(unscaled: i128, scale: u32) -> String {
    if scale == 0 {
        return unscaled.to_string();
    }
    let neg = unscaled < 0;
    let mag = unscaled.unsigned_abs();
    let s = mag.to_string();
    let scale = scale as usize;
    let padded = if s.len() <= scale {
        format!("{}{}", "0".repeat(scale + 1 - s.len()), s)
    } else {
        s
    };
    let dot = padded.len() - scale;
    let out = format!("{}.{}", &padded[..dot], &padded[dot..]);
    if neg {
        format!("-{out}")
    } else {
        out
    }
}

/// Emit golden vectors as JSON lines for the C / Python mirror conformance
/// tests: for each `seq` in `0..rows`, the full row's expected cells.
pub fn write_golden_vectors(out: &mut String, seed: u64, worker_id: u32, rows: u64) {
    for seq in 0..rows {
        let _ = write!(out, "{{\"seq\":{seq},\"cells\":[");
        for (i, cell) in gen_row(seed, worker_id, seq).iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            let _ = write!(
                out,
                "{{\"col\":\"{}\",\"v\":{}}}",
                cell.ty.col_name(),
                expected_json(&cell.expected)
            );
        }
        out.push_str("]}\n");
    }
}

fn expected_json(e: &Expected) -> String {
    match e {
        Expected::Null => "null".into(),
        Expected::Int(v) => format!("{{\"i\":\"{v}\"}}"),
        Expected::Float(v) => format!("{{\"f\":\"{}\"}}", v.to_bits()),
        Expected::Bool(v) => format!("{{\"b\":{v}}}"),
        Expected::Text(v) => format!("{{\"t\":{}}}", json_string(v)),
        Expected::Bytes(v) => {
            let mut hex = String::with_capacity(v.len() * 2);
            for b in v {
                let _ = write!(hex, "{b:02x}");
            }
            format!("{{\"x\":\"{hex}\"}}")
        }
    }
}

fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn all_22_types_present_and_unique_tags() {
        assert_eq!(QWP_TYPES.len(), 22);
        let tags: HashSet<u8> = QWP_TYPES.iter().map(|t| t.tag()).collect();
        assert_eq!(tags.len(), 22, "type tags must be unique");
        let names: HashSet<&str> = QWP_TYPES.iter().map(|t| t.col_name()).collect();
        assert_eq!(names.len(), 22, "column names must be unique");
    }

    #[test]
    fn splitmix64_matches_reference_vector() {
        // Golden values pin the PRNG so a C / Python mirror can verify parity.
        assert_eq!(splitmix64(0), 0xE220A8397B1DCDAF);
        assert_eq!(splitmix64(1), 0x910A2DEC89025CC1);
        assert_eq!(splitmix64(0xDEADBEEF), 0x4ADFB90F68C9EB9B);
    }

    #[test]
    fn generation_is_deterministic() {
        for seq in 0..500u64 {
            let a = gen_row(42, 7, seq);
            let b = gen_row(42, 7, seq);
            assert_eq!(a, b, "same inputs must yield identical rows");
        }
    }

    #[test]
    fn different_workers_and_seeds_diverge() {
        // Not a strict guarantee per-row, but across a window the streams must
        // differ — else the fold is collapsing dimensions.
        let w7: Vec<_> = (0..200).map(|s| gen_row(1, 7, s)).collect();
        let w8: Vec<_> = (0..200).map(|s| gen_row(1, 8, s)).collect();
        assert_ne!(w7, w8, "distinct worker_id must produce distinct data");
        let s1: Vec<_> = (0..200).map(|s| gen_row(1, 7, s)).collect();
        let s2: Vec<_> = (0..200).map(|s| gen_row(2, 7, s)).collect();
        assert_ne!(s1, s2, "distinct seed must produce distinct data");
    }

    #[test]
    fn every_edge_is_hit_within_a_run() {
        // Over a long-enough seq window each column must hit NULL (where it can)
        // and cycle through its edge slots — the whole point of the cadence.
        let mut seen_null = HashSet::new();
        let mut seen_edges: std::collections::HashMap<u32, HashSet<u32>> = Default::default();
        for seq in 0..(EDGE_PERIOD * EDGE_SLOTS * 4) {
            for ty in QWP_TYPES {
                let col = ty.col_index();
                if let Some(slot) = edge_index(seq, col) {
                    seen_edges.entry(col).or_default().insert(slot);
                }
                if gen_expected(0xABCD, 3, seq, ty) == Expected::Null {
                    seen_null.insert(col);
                }
            }
        }
        // Every column reaches all EDGE_SLOTS-1 non-zero edge slots.
        for ty in QWP_TYPES {
            let slots = seen_edges.get(&ty.col_index()).cloned().unwrap_or_default();
            assert_eq!(
                slots.len() as u64,
                EDGE_SLOTS - 1,
                "column {} must hit every edge slot",
                ty.col_name()
            );
        }
        // Nullable types must produce at least one NULL.
        for ty in [
            QwpType::Int,
            QwpType::Long,
            QwpType::Double,
            QwpType::Symbol,
            QwpType::Uuid,
            QwpType::Varchar,
            QwpType::Binary,
            QwpType::Ipv4,
        ] {
            assert!(
                seen_null.contains(&ty.col_index()),
                "nullable {} must produce a NULL over the window",
                ty.col_name()
            );
        }
    }

    #[test]
    fn no_nan_or_int_null_sentinel_leaks() {
        // NaN must be canonicalised to Null; i32::MIN / i64::MIN are QuestDB
        // NULL sentinels and must never appear as a stored INT/LONG value.
        for seq in 0..2000u64 {
            for ty in [QwpType::Float, QwpType::Double] {
                if let Expected::Float(v) = gen_expected(9, 1, seq, ty) {
                    assert!(!v.is_nan(), "{}: NaN must be Null", ty.col_name());
                }
            }
            if let Expected::Int(v) = gen_expected(9, 1, seq, QwpType::Int) {
                assert_ne!(v, i128::from(i32::MIN), "INT NULL sentinel leaked");
            }
            if let Expected::Int(v) = gen_expected(9, 1, seq, QwpType::Long) {
                assert_ne!(v, i128::from(i64::MIN), "LONG NULL sentinel leaked");
            }
        }
    }

    #[test]
    fn decimal_formatting_is_fixed_point() {
        assert_eq!(fmt_decimal(0, 2), "0.00");
        assert_eq!(fmt_decimal(5, 2), "0.05");
        assert_eq!(fmt_decimal(123, 2), "1.23");
        assert_eq!(fmt_decimal(-123, 2), "-1.23");
        assert_eq!(fmt_decimal(100, 0), "100");
    }

    #[test]
    fn uuid_and_long256_formats() {
        assert_eq!(fmt_uuid(0), "00000000-0000-0000-0000-000000000000");
        assert_eq!(fmt_long256([0, 0, 0, 0]), "0x0");
        assert_eq!(fmt_long256([1, 0, 0, 0]), "0x1");
        assert_eq!(fmt_long256([0, 1, 0, 0]), "0x10000000000000000");
    }

    #[test]
    fn golden_vectors_are_stable_json() {
        let mut out = String::new();
        write_golden_vectors(&mut out, 7, 0, 3);
        // Three rows, each a JSON object line.
        assert_eq!(out.lines().count(), 3);
        for line in out.lines() {
            assert!(line.starts_with("{\"seq\":"));
            assert!(line.ends_with("]}"));
        }
    }
}
