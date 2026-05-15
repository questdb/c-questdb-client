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

//! Bind-parameter wire encoding for `QUERY_REQUEST`.
//!
//! Each bind serialises as a single-row column body: type code, null
//! section, column-level type args (if any), then the per-row value(s).
//!
//! ```text
//! type_code:  u8
//! null_flag:  u8                0x00 = no bitmap; 0x01 = bitmap follows
//! [bitmap]:   u8                present iff null_flag == 0x01; LSB-first, 1 = NULL
//! column args:                  per type, present per the rules below:
//!   DECIMAL64/128/256:          1 B scale (always present, including nulls)
//!   GEOHASH:                    varint precision_bits (1..=60; always present)
//!   VARCHAR/BINARY:             (non_null + 1) × u32_le offsets — non-null only
//!   everything else:            (no args)
//! values × non_null:            type-specific layout (see per-type docs below)
//! ```
//!
//! Multi-byte numeric values are little-endian. For null binds,
//! `non_null = 0`, so:
//! - simple types emit `[type, 0x01, 0x01]`
//! - DECIMAL\* emit `[type, 0x01, 0x01, scale]`
//! - GEOHASH emits `[type, 0x01, 0x01, varint(precision_bits)]`
//! - VARCHAR/BINARY emit `[type, 0x01, 0x01]` (the server's bind decoder
//!   skips the offsets array on the null branch — emitting them would
//!   poison the next bind in a multi-bind QUERY_REQUEST)

use std::net::Ipv4Addr;

use crate::egress::column_kind::ColumnKind;
use crate::egress::error::{Result, fmt};
use crate::egress::wire::varint;

// ============================================================================
// PHASE 1 SERVER COMPATIBILITY — bind-type gap
// ============================================================================
//
// Single source of truth for the bind types the Phase 1 server doesn't
// accept. Every client-side rejection / encoder note in this file
// references this block by the literal marker `PHASE 1 SERVER
// COMPATIBILITY` so enabling a type later is one grep.
//
// TODO(phase-1-binds): link tracking issue.
//
// Reference: `core/src/main/java/io/questdb/cutlass/qwp/server/egress/QwpEgressRequestDecoder.java`
// `decodeBind` switch.
//
// - **BINARY (0x17), IPv4 (0x18)** — no decoder case on the server;
//   fall into `default ->` with "unsupported wire type". Client rejects
//   in `check_bindable` so the user sees a typed `InvalidBind` instead
//   of an out-of-band `QUERY_ERROR` that arrives with `request_id=0`
//   and breaks correlation.
// - **DOUBLE_ARRAY (0x11), LONG_ARRAY (0x12)** — explicit server case
//   throwing "ARRAY bind parameters not yet supported in Phase 1
//   egress". The QWP spec (§6 "Bind parameters") describes the
//   eventual array bind encoding (per-row dimension header), so this
//   is a Phase 1 limitation that may be lifted server-side.
// - **SYMBOL (0x09)** — defensive. The Phase 1 server currently
//   accepts SYMBOL bind type codes leniently, dispatching them to
//   `BindVariableService.setStr` (spec §6 "Server leniency note"). The
//   spec instructs compliant clients to send STRING / VARCHAR for
//   symbol binds, and a future server revision may tighten this. The
//   Rust `Bind` enum has no `Symbol(_)` value variant and
//   `SimpleNullKind` excludes `Symbol`, so this arm is unreachable
//   through the typed API; it stays as a defense against any future
//   code path that synthesises a SYMBOL-kinded `Bind`.
//
// Encoder arms for IPv4 / Binary remain wired for forward
// compatibility — when the server lifts a restriction the bytes are
// already correct and only `check_bindable` needs editing.
// ============================================================================

/// Inclusive upper bound on a DECIMAL column's scale, matching the
/// server's `Decimals.MAX_SCALE`. Negative scales and scales above
/// this bound are rejected client-side at encode time so the user
/// gets `InvalidBind` immediately rather than a generic `QUERY_ERROR`
/// from the server.
pub const MAX_DECIMAL_SCALE: i8 = 38;

/// Column kinds whose null wire encoding is the simple no-args form
/// `[type_code, null_flag=0x01, bitmap=0x01]` — no column-level
/// metadata, no offsets array. Acts as the type-system constraint on
/// [`Bind::Null`]: kinds excluded here either need extra metadata
/// (DECIMAL\* scale, GEOHASH precision_bits) or have a different null
/// layout (VARCHAR, BINARY) and use a dedicated `Null*` variant.
///
/// SYMBOL, DOUBLE_ARRAY, LONG_ARRAY are excluded — see `PHASE 1 SERVER
/// COMPATIBILITY` block at the top of this module for the server-side
/// rationale and the conditions under which each may be re-enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SimpleNullKind {
    Boolean,
    Byte,
    Short,
    Int,
    Long,
    Float,
    Double,
    Timestamp,
    TimestampNanos,
    Date,
    Uuid,
    Long256,
    Char,
    Ipv4,
}

impl SimpleNullKind {
    /// The corresponding [`ColumnKind`].
    pub fn as_column_kind(self) -> ColumnKind {
        match self {
            SimpleNullKind::Boolean => ColumnKind::Boolean,
            SimpleNullKind::Byte => ColumnKind::Byte,
            SimpleNullKind::Short => ColumnKind::Short,
            SimpleNullKind::Int => ColumnKind::Int,
            SimpleNullKind::Long => ColumnKind::Long,
            SimpleNullKind::Float => ColumnKind::Float,
            SimpleNullKind::Double => ColumnKind::Double,
            SimpleNullKind::Timestamp => ColumnKind::Timestamp,
            SimpleNullKind::TimestampNanos => ColumnKind::TimestampNanos,
            SimpleNullKind::Date => ColumnKind::Date,
            SimpleNullKind::Uuid => ColumnKind::Uuid,
            SimpleNullKind::Long256 => ColumnKind::Long256,
            SimpleNullKind::Char => ColumnKind::Char,
            SimpleNullKind::Ipv4 => ColumnKind::Ipv4,
        }
    }
}

impl TryFrom<ColumnKind> for SimpleNullKind {
    type Error = ColumnKind;

    /// Returns the input kind in `Err` when it's not a simple-null kind, so
    /// the caller can build a context-rich error message pointing at the
    /// dedicated variant the user needed.
    fn try_from(k: ColumnKind) -> std::result::Result<Self, Self::Error> {
        Ok(match k {
            ColumnKind::Boolean => SimpleNullKind::Boolean,
            ColumnKind::Byte => SimpleNullKind::Byte,
            ColumnKind::Short => SimpleNullKind::Short,
            ColumnKind::Int => SimpleNullKind::Int,
            ColumnKind::Long => SimpleNullKind::Long,
            ColumnKind::Float => SimpleNullKind::Float,
            ColumnKind::Double => SimpleNullKind::Double,
            ColumnKind::Timestamp => SimpleNullKind::Timestamp,
            ColumnKind::TimestampNanos => SimpleNullKind::TimestampNanos,
            ColumnKind::Date => SimpleNullKind::Date,
            ColumnKind::Uuid => SimpleNullKind::Uuid,
            ColumnKind::Long256 => SimpleNullKind::Long256,
            ColumnKind::Char => SimpleNullKind::Char,
            ColumnKind::Ipv4 => SimpleNullKind::Ipv4,
            other => return Err(other),
        })
    }
}

/// Typed bind value.
///
/// Position is implicit in the order binds are emitted into a `QUERY_REQUEST`
/// (`$1`, `$2`, …). Types whose null wire encoding carries column-level
/// metadata have dedicated `Null*` variants; everything else uses
/// [`Bind::Null`].
///
/// `#[non_exhaustive]` so future bind types (e.g. when the server
/// lifts the array-bind restriction documented in the `PHASE 1 SERVER
/// COMPATIBILITY` block at module top) can be added without breaking
/// exhaustive matches in user code.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Bind {
    // --- Simple typed-NULL (column body is just the null section) ----------
    /// Typed NULL for any simple-null kind. The [`SimpleNullKind`] type
    /// statically excludes kinds (VARCHAR / BINARY / DECIMAL\* / GEOHASH)
    /// whose null wire encoding requires column-level metadata, so an
    /// invalid `Bind::Null` is unrepresentable.
    Null(SimpleNullKind),
    /// Typed NULL for VARCHAR (offsets array length-1 even with no values).
    NullVarchar,
    /// Typed NULL for BINARY (same offsets-array reason).
    NullBinary,
    /// Typed NULL for DECIMAL64 (scale must be on the wire).
    NullDecimal64 {
        scale: i8,
    },
    /// Typed NULL for DECIMAL128.
    NullDecimal128 {
        scale: i8,
    },
    /// Typed NULL for DECIMAL256.
    NullDecimal256 {
        scale: i8,
    },
    /// Typed NULL for GEOHASH (precision must be on the wire).
    NullGeohash {
        precision_bits: u8,
    },

    // --- Value binds -------------------------------------------------------
    Bool(bool),
    /// Maps to QWP `BYTE` (signed 8-bit).
    I8(i8),
    /// Maps to QWP `SHORT` (signed 16-bit).
    I16(i16),
    /// Maps to QWP `INT` (signed 32-bit).
    I32(i32),
    /// Maps to QWP `LONG` (signed 64-bit).
    I64(i64),
    F32(f32),
    F64(f64),
    Varchar(String),
    Binary(Vec<u8>),
    /// QWP `TIMESTAMP` (microseconds since epoch).
    TimestampMicros(i64),
    /// QWP `TIMESTAMP_NANOS` (nanoseconds since epoch).
    TimestampNanos(i64),
    /// QWP `DATE` (milliseconds since epoch).
    DateMillis(i64),
    /// 16 raw bytes; high/low long ordering is the caller's responsibility.
    Uuid([u8; 16]),
    /// 32 raw bytes; LONG256 is opaque on the wire.
    Long256([u8; 32]),
    /// 2-byte UTF-16 code unit (CHAR).
    Char(u16),
    Ipv4(Ipv4Addr),
    /// QWP `DECIMAL64`: i64 mantissa + scale.
    Decimal64 {
        value: i64,
        scale: i8,
    },
    /// QWP `DECIMAL128`: i128 mantissa + scale.
    Decimal128 {
        value: i128,
        scale: i8,
    },
    /// QWP `DECIMAL256`: 32-byte LE mantissa + scale.
    Decimal256 {
        bytes: [u8; 32],
        scale: i8,
    },
    /// QWP `GEOHASH`: zero-extended u64 + precision_bits (1..=60). The
    /// least-significant `ceil(precision_bits/8)` bytes are written.
    Geohash {
        value: u64,
        precision_bits: u8,
    },
}

impl Bind {
    /// QWP type code this bind serializes to.
    pub fn kind(&self) -> ColumnKind {
        match self {
            Bind::Null(s) => s.as_column_kind(),
            Bind::NullVarchar => ColumnKind::Varchar,
            Bind::NullBinary => ColumnKind::Binary,
            Bind::NullDecimal64 { .. } => ColumnKind::Decimal64,
            Bind::NullDecimal128 { .. } => ColumnKind::Decimal128,
            Bind::NullDecimal256 { .. } => ColumnKind::Decimal256,
            Bind::NullGeohash { .. } => ColumnKind::Geohash,
            Bind::Bool(_) => ColumnKind::Boolean,
            Bind::I8(_) => ColumnKind::Byte,
            Bind::I16(_) => ColumnKind::Short,
            Bind::I32(_) => ColumnKind::Int,
            Bind::I64(_) => ColumnKind::Long,
            Bind::F32(_) => ColumnKind::Float,
            Bind::F64(_) => ColumnKind::Double,
            Bind::Varchar(_) => ColumnKind::Varchar,
            Bind::Binary(_) => ColumnKind::Binary,
            Bind::TimestampMicros(_) => ColumnKind::Timestamp,
            Bind::TimestampNanos(_) => ColumnKind::TimestampNanos,
            Bind::DateMillis(_) => ColumnKind::Date,
            Bind::Uuid(_) => ColumnKind::Uuid,
            Bind::Long256(_) => ColumnKind::Long256,
            Bind::Char(_) => ColumnKind::Char,
            Bind::Ipv4(_) => ColumnKind::Ipv4,
            Bind::Decimal64 { .. } => ColumnKind::Decimal64,
            Bind::Decimal128 { .. } => ColumnKind::Decimal128,
            Bind::Decimal256 { .. } => ColumnKind::Decimal256,
            Bind::Geohash { .. } => ColumnKind::Geohash,
        }
    }

    fn is_null(&self) -> bool {
        matches!(
            self,
            Bind::Null(_)
                | Bind::NullVarchar
                | Bind::NullBinary
                | Bind::NullDecimal64 { .. }
                | Bind::NullDecimal128 { .. }
                | Bind::NullDecimal256 { .. }
                | Bind::NullGeohash { .. }
        )
    }
}

/// Append the wire encoding of `bind` to `out`.
pub fn encode_bind(bind: &Bind, out: &mut Vec<u8>) -> Result<()> {
    // `Bind::Null(SimpleNullKind)` only encodes the simple no-args null body
    // `[type, null_flag=0x01, bitmap=0x01]`. The `SimpleNullKind` enum
    // statically excludes kinds whose null wire encoding requires
    // column-level metadata (DECIMAL\* scale, GEOHASH precision_bits) or
    // whose null layout differs from a bare null section (VARCHAR /
    // BINARY) — those route through dedicated `Null*` variants.
    out.push(bind.kind().as_u8());

    let null = bind.is_null();
    if null {
        out.push(0x01); // null_flag
        out.push(0x01); // bitmap: bit 0 set -> row 0 is NULL
    } else {
        out.push(0x00);
    }

    // Column-level type args (always present; type-specific count of values
    // comes after).
    match bind {
        // DECIMAL: column-level scale.
        Bind::Decimal64 { scale, .. }
        | Bind::Decimal128 { scale, .. }
        | Bind::Decimal256 { scale, .. }
        | Bind::NullDecimal64 { scale }
        | Bind::NullDecimal128 { scale }
        | Bind::NullDecimal256 { scale } => {
            if *scale < 0 || *scale > MAX_DECIMAL_SCALE {
                return Err(fmt!(
                    InvalidBind,
                    "decimal scale {} outside 0..={}",
                    scale,
                    MAX_DECIMAL_SCALE
                ));
            }
            out.push(*scale as u8);
        }
        // GEOHASH: column-level varint precision_bits.
        Bind::Geohash { precision_bits, .. } | Bind::NullGeohash { precision_bits } => {
            if *precision_bits == 0 || *precision_bits > 60 {
                return Err(fmt!(
                    InvalidBind,
                    "geohash precision_bits {} outside 1..=60",
                    precision_bits
                ));
            }
            if let Bind::Geohash {
                value,
                precision_bits,
            } = bind
            {
                // `precision_bits` is in 1..=60, so the shift is always
                // well-defined; reject any high bits that would be
                // silently dropped by the wire encoding below.
                if value >> precision_bits != 0 {
                    return Err(fmt!(
                        InvalidBind,
                        "geohash value 0x{:X} has bits set above precision_bits {}",
                        value,
                        precision_bits
                    ));
                }
            }
            varint::encode_u64(*precision_bits as u64, out);
        }
        // VARCHAR/BINARY: (non_null + 1) × u32_le offsets array — only
        // emitted on the non-null branch. Java's QwpEgressRequestDecoder
        // (TYPE_VARCHAR) reads these 8 bytes only when isNull == false; on
        // the null branch it advances p by zero, so emitting an empty
        // offsets array here would be re-read as part of the *next* bind.
        Bind::Varchar(s) => write_varlen_offsets(&[s.len()], out)?,
        Bind::Binary(b) => write_varlen_offsets(&[b.len()], out)?,
        _ => {}
    }

    if null {
        return Ok(());
    }

    // Value bytes (non_null × per-type size).
    match bind {
        Bind::Null(_)
        | Bind::NullVarchar
        | Bind::NullBinary
        | Bind::NullDecimal64 { .. }
        | Bind::NullDecimal128 { .. }
        | Bind::NullDecimal256 { .. }
        | Bind::NullGeohash { .. } => unreachable!("handled above"),

        // BOOLEAN is bit-packed: 1 row → 1 byte holding bit 0.
        Bind::Bool(v) => out.push(if *v { 0x01 } else { 0x00 }),
        Bind::I8(v) => out.push(*v as u8),
        Bind::I16(v) => out.extend_from_slice(&v.to_le_bytes()),
        Bind::I32(v) => out.extend_from_slice(&v.to_le_bytes()),
        Bind::I64(v) => out.extend_from_slice(&v.to_le_bytes()),
        Bind::F32(v) => out.extend_from_slice(&v.to_le_bytes()),
        Bind::F64(v) => out.extend_from_slice(&v.to_le_bytes()),
        Bind::Char(v) => out.extend_from_slice(&v.to_le_bytes()),
        Bind::TimestampMicros(v) | Bind::TimestampNanos(v) | Bind::DateMillis(v) => {
            out.extend_from_slice(&v.to_le_bytes());
        }
        Bind::Uuid(b) => out.extend_from_slice(b),
        Bind::Long256(b) => out.extend_from_slice(b),
        // `Bind::Ipv4` / `Bind::Binary` are normally rejected client-side
        // by `check_bindable` — see `PHASE 1 SERVER COMPATIBILITY` at
        // module top. The encoder arms stay wired for forward
        // compatibility and to handle bind-sets encoded without going
        // through `QueryRequestBuilder::build`.
        Bind::Ipv4(addr) => out.extend_from_slice(&u32::from(*addr).to_le_bytes()),
        Bind::Decimal64 { value, .. } => out.extend_from_slice(&value.to_le_bytes()),
        Bind::Decimal128 { value, .. } => out.extend_from_slice(&value.to_le_bytes()),
        Bind::Decimal256 { bytes, .. } => out.extend_from_slice(bytes),
        Bind::Geohash {
            value,
            precision_bits,
        } => {
            let bw = (*precision_bits as usize).div_ceil(8);
            let bytes = value.to_le_bytes();
            out.extend_from_slice(&bytes[..bw]);
        }
        Bind::Varchar(s) => out.extend_from_slice(s.as_bytes()),
        Bind::Binary(b) => out.extend_from_slice(b),
    }

    Ok(())
}

fn write_varlen_offsets(byte_lens: &[usize], out: &mut Vec<u8>) -> Result<()> {
    let mut total: u32 = 0;
    out.extend_from_slice(&total.to_le_bytes());
    for &len in byte_lens {
        let len32 = u32::try_from(len)
            .map_err(|_| fmt!(InvalidBind, "varlen bind value too large: {} bytes", len))?;
        total = total
            .checked_add(len32)
            .ok_or_else(|| fmt!(InvalidBind, "varlen bind offsets overflow u32"))?;
        out.extend_from_slice(&total.to_le_bytes());
    }
    Ok(())
}

/// Reject bind kinds the Phase 1 server doesn't decode, so the user
/// sees a typed `InvalidBind` instead of a server `QUERY_ERROR` whose
/// `request_id=0` breaks correlation.
///
/// Set membership (Symbol, Binary, Ipv4, DoubleArray, LongArray) and
/// the per-kind server-side rationale are documented once in the
/// `PHASE 1 SERVER COMPATIBILITY` block at the top of this module —
/// keep that block in sync if this match list changes.
pub fn check_bindable(kind: ColumnKind) -> Result<()> {
    match kind {
        ColumnKind::Symbol
        | ColumnKind::Binary
        | ColumnKind::Ipv4
        | ColumnKind::DoubleArray
        | ColumnKind::LongArray => Err(fmt!(
            InvalidBind,
            "bind not supported for type {} (0x{:02X})",
            kind.name(),
            kind.as_u8()
        )),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(b: Bind) -> Vec<u8> {
        let mut out = Vec::new();
        encode_bind(&b, &mut out).unwrap();
        out
    }

    // --- Simple null + value paths -----------------------------------------

    #[test]
    fn simple_null_layout() {
        // type_code=Long(0x05), null_flag=0x01, bitmap=0x01
        assert_eq!(
            enc(Bind::Null(SimpleNullKind::Long)),
            vec![0x05, 0x01, 0x01]
        );
    }

    #[test]
    fn bool_layout() {
        assert_eq!(enc(Bind::Bool(true)), vec![0x01, 0x00, 0x01]);
        assert_eq!(enc(Bind::Bool(false)), vec![0x01, 0x00, 0x00]);
    }

    #[test]
    fn i32_le() {
        assert_eq!(
            enc(Bind::I32(0x01020304)),
            vec![0x04, 0x00, 0x04, 0x03, 0x02, 0x01]
        );
    }

    #[test]
    fn i64_le() {
        assert_eq!(
            enc(Bind::I64(0x0102_0304_0506_0708)),
            vec![0x05, 0x00, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );
    }

    #[test]
    fn f64_le() {
        let mut expected = vec![0x07, 0x00];
        expected.extend_from_slice(&1.0f64.to_le_bytes());
        assert_eq!(enc(Bind::F64(1.0)), expected);
    }

    #[test]
    fn ipv4_le() {
        let bytes = enc(Bind::Ipv4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(bytes, vec![0x18, 0x00, 0x01, 0x01, 0xA8, 0xC0]);
    }

    #[test]
    fn uuid_passthrough() {
        let raw = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];
        let bytes = enc(Bind::Uuid(raw));
        assert_eq!(bytes[0], 0x0C);
        assert_eq!(bytes[1], 0x00);
        assert_eq!(&bytes[2..], &raw);
    }

    #[test]
    fn long256_passthrough() {
        let raw: [u8; 32] = std::array::from_fn(|i| i as u8);
        let bytes = enc(Bind::Long256(raw));
        assert_eq!(bytes[0], 0x0D);
        assert_eq!(bytes[1], 0x00);
        assert_eq!(&bytes[2..], &raw);
    }

    #[test]
    fn char_layout() {
        // CHAR (0x16), 'A' = 0x0041 LE
        assert_eq!(enc(Bind::Char(b'A' as u16)), vec![0x16, 0x00, 0x41, 0x00]);
    }

    // --- Decimal -----------------------------------------------------------

    #[test]
    fn decimal64_value_layout() {
        let bytes = enc(Bind::Decimal64 {
            value: 12345,
            scale: 2,
        });
        assert_eq!(bytes[0], 0x13);
        assert_eq!(bytes[1], 0x00);
        assert_eq!(bytes[2], 0x02);
        assert_eq!(&bytes[3..], &12345i64.to_le_bytes());
    }

    #[test]
    fn decimal64_null_carries_scale() {
        // type=0x13, null_flag=0x01, bitmap=0x01, scale=4
        assert_eq!(
            enc(Bind::NullDecimal64 { scale: 4 }),
            vec![0x13, 0x01, 0x01, 0x04]
        );
    }

    #[test]
    fn decimal_scale_negative_rejected() {
        // Encode-time check: scale must be 0..=MAX_DECIMAL_SCALE.
        // Without this guard, `*scale as u8` would emit 0xFF and the
        // server would later return a generic QUERY_ERROR.
        for bind in [
            Bind::Decimal64 {
                value: 0,
                scale: -1,
            },
            Bind::Decimal128 {
                value: 0,
                scale: -1,
            },
            Bind::Decimal256 {
                bytes: [0; 32],
                scale: -1,
            },
            Bind::NullDecimal64 { scale: -1 },
            Bind::NullDecimal128 { scale: -1 },
            Bind::NullDecimal256 { scale: -1 },
        ] {
            let mut out = Vec::new();
            let err = encode_bind(&bind, &mut out).unwrap_err();
            assert_eq!(err.code(), crate::egress::ErrorCode::InvalidBind);
            assert!(
                err.msg().contains("decimal scale"),
                "expected scale error msg, got: {}",
                err.msg()
            );
        }
    }

    #[test]
    fn decimal_scale_above_max_rejected() {
        // 39 is the smallest positive value above MAX_DECIMAL_SCALE.
        for bind in [
            Bind::Decimal64 {
                value: 0,
                scale: 39,
            },
            Bind::NullDecimal128 { scale: 39 },
            Bind::NullDecimal256 { scale: i8::MAX },
        ] {
            let mut out = Vec::new();
            let err = encode_bind(&bind, &mut out).unwrap_err();
            assert_eq!(err.code(), crate::egress::ErrorCode::InvalidBind);
        }
    }

    #[test]
    fn decimal_scale_at_boundaries_accepted() {
        // 0 and MAX_DECIMAL_SCALE must encode cleanly.
        for scale in [0i8, MAX_DECIMAL_SCALE] {
            let mut out = Vec::new();
            encode_bind(&Bind::NullDecimal64 { scale }, &mut out).unwrap();
            assert_eq!(out.last().copied(), Some(scale as u8));
        }
    }

    #[test]
    fn decimal128_value_layout() {
        let bytes = enc(Bind::Decimal128 {
            value: -42,
            scale: 6,
        });
        assert_eq!(bytes[0], 0x14);
        assert_eq!(bytes[1], 0x00);
        assert_eq!(bytes[2], 0x06);
        assert_eq!(&bytes[3..], &(-42i128).to_le_bytes());
    }

    #[test]
    fn decimal128_null_carries_scale() {
        assert_eq!(
            enc(Bind::NullDecimal128 { scale: 8 }),
            vec![0x14, 0x01, 0x01, 0x08]
        );
    }

    #[test]
    fn decimal256_value_layout() {
        let raw: [u8; 32] = std::array::from_fn(|i| (i + 1) as u8);
        let bytes = enc(Bind::Decimal256 {
            bytes: raw,
            scale: 12,
        });
        assert_eq!(bytes[0], 0x15);
        assert_eq!(bytes[1], 0x00);
        assert_eq!(bytes[2], 0x0C);
        assert_eq!(&bytes[3..], &raw);
    }

    #[test]
    fn decimal256_null_carries_scale() {
        assert_eq!(
            enc(Bind::NullDecimal256 { scale: 18 }),
            vec![0x15, 0x01, 0x01, 0x12]
        );
    }

    // --- Geohash -----------------------------------------------------------

    #[test]
    fn geohash_value_layout() {
        // 8 bits → 1 byte; varint(8) = 0x08
        let bytes = enc(Bind::Geohash {
            value: 0xAB,
            precision_bits: 8,
        });
        assert_eq!(bytes, vec![0x0E, 0x00, 0x08, 0xAB]);
    }

    #[test]
    fn geohash_60_bits_writes_8_bytes() {
        let bytes = enc(Bind::Geohash {
            value: 0x0102_0304_0506_0708,
            precision_bits: 60,
        });
        // varint(60) = 0x3C
        let mut expected = vec![0x0E, 0x00, 0x3C];
        expected.extend_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
        assert_eq!(bytes, expected);
    }

    #[test]
    fn geohash_null_carries_precision() {
        // varint(20) = 0x14
        assert_eq!(
            enc(Bind::NullGeohash { precision_bits: 20 }),
            vec![0x0E, 0x01, 0x01, 0x14]
        );
    }

    #[test]
    fn geohash_invalid_precision_rejected() {
        let mut out = Vec::new();
        let err = encode_bind(
            &Bind::Geohash {
                value: 0,
                precision_bits: 0,
            },
            &mut out,
        )
        .unwrap_err();
        assert_eq!(err.code(), crate::egress::ErrorCode::InvalidBind);
    }

    #[test]
    fn geohash_value_above_precision_rejected() {
        let mut out = Vec::new();
        let err = encode_bind(
            &Bind::Geohash {
                value: u64::MAX,
                precision_bits: 8,
            },
            &mut out,
        )
        .unwrap_err();
        assert_eq!(err.code(), crate::egress::ErrorCode::InvalidBind);
    }

    // --- Varchar / Binary --------------------------------------------------

    #[test]
    fn varchar_value_layout() {
        let bytes = enc(Bind::Varchar("hi".into()));
        // 0x0F, 0x00, offsets [0, 2] (8 bytes), then "hi"
        let expected = vec![0x0F, 0x00, 0, 0, 0, 0, 2, 0, 0, 0, b'h', b'i'];
        assert_eq!(bytes, expected);
    }

    #[test]
    fn varchar_null_emits_no_offsets_array() {
        // 0x0F, 0x01, 0x01 — no trailing offsets. Java's TYPE_VARCHAR
        // bind decoder skips offsets on the null branch; emitting them
        // would corrupt any following bind in the same QUERY_REQUEST.
        assert_eq!(enc(Bind::NullVarchar), vec![0x0F, 0x01, 0x01]);
    }

    #[test]
    fn binary_value_layout() {
        let bytes = enc(Bind::Binary(vec![0xDE, 0xAD]));
        // 0x17, 0x00, [0, 2] offsets, then 0xDE 0xAD
        let expected = vec![0x17, 0x00, 0, 0, 0, 0, 2, 0, 0, 0, 0xDE, 0xAD];
        assert_eq!(bytes, expected);
    }

    #[test]
    fn binary_null_emits_no_offsets_array() {
        // Mirrors NullVarchar: no trailing offsets on the null branch.
        assert_eq!(enc(Bind::NullBinary), vec![0x17, 0x01, 0x01]);
    }

    #[test]
    fn null_varchar_then_i32_concatenates_cleanly() {
        // Regression: previously NullVarchar emitted 4 trailing zero offset
        // bytes that the server's bind decoder did NOT consume, so the next
        // bind's leading bytes were misread.
        let mut out = Vec::new();
        encode_bind(&Bind::NullVarchar, &mut out).unwrap();
        encode_bind(&Bind::I32(7), &mut out).unwrap();
        // [type=Varchar, null_flag, bitmap] || [type=Int, null_flag, 4 LE bytes]
        assert_eq!(
            out,
            vec![0x0F, 0x01, 0x01, 0x04, 0x00, 0x07, 0x00, 0x00, 0x00]
        );
    }

    // --- check_bindable ----------------------------------------------------

    #[test]
    fn check_bindable_rejects_server_unsupported() {
        // Per the Java client, server doesn't accept these as binds.
        assert!(check_bindable(ColumnKind::Symbol).is_err());
        assert!(check_bindable(ColumnKind::Binary).is_err());
        assert!(check_bindable(ColumnKind::Ipv4).is_err());
        assert!(check_bindable(ColumnKind::DoubleArray).is_err());
        assert!(check_bindable(ColumnKind::LongArray).is_err());
    }

    #[test]
    fn check_bindable_accepts_remaining_types() {
        for k in [
            ColumnKind::Boolean,
            ColumnKind::Byte,
            ColumnKind::Short,
            ColumnKind::Int,
            ColumnKind::Long,
            ColumnKind::Float,
            ColumnKind::Double,
            ColumnKind::Timestamp,
            ColumnKind::TimestampNanos,
            ColumnKind::Date,
            ColumnKind::Uuid,
            ColumnKind::Long256,
            ColumnKind::Char,
            ColumnKind::Varchar,
            ColumnKind::Decimal64,
            ColumnKind::Decimal128,
            ColumnKind::Decimal256,
            ColumnKind::Geohash,
        ] {
            check_bindable(k).unwrap_or_else(|_| panic!("{}", k.name()));
        }
    }

    #[test]
    fn simple_null_kind_try_from_rejects_kinds_with_column_args() {
        // Each of these kinds requires column-level metadata in its null wire
        // body (DECIMAL\* scale, GEOHASH precision_bits) or a different null
        // layout (VARCHAR / BINARY skip the offsets array on null) — they
        // route through dedicated `Null*` variants and must NOT be
        // representable as `Bind::Null(SimpleNullKind)`. Same for SYMBOL /
        // DOUBLE_ARRAY / LONG_ARRAY which the server rejects entirely as
        // bind values.
        for kind in [
            ColumnKind::Varchar,
            ColumnKind::Binary,
            ColumnKind::Decimal64,
            ColumnKind::Decimal128,
            ColumnKind::Decimal256,
            ColumnKind::Geohash,
            ColumnKind::Symbol,
            ColumnKind::DoubleArray,
            ColumnKind::LongArray,
        ] {
            let r = SimpleNullKind::try_from(kind);
            assert!(
                r.is_err(),
                "{} must not convert to SimpleNullKind",
                kind.name()
            );
        }
    }

    #[test]
    fn null_bind_accepts_simple_kinds() {
        for kind in [
            SimpleNullKind::Boolean,
            SimpleNullKind::Byte,
            SimpleNullKind::Short,
            SimpleNullKind::Int,
            SimpleNullKind::Long,
            SimpleNullKind::Float,
            SimpleNullKind::Double,
            SimpleNullKind::Timestamp,
            SimpleNullKind::TimestampNanos,
            SimpleNullKind::Date,
            SimpleNullKind::Uuid,
            SimpleNullKind::Long256,
            SimpleNullKind::Char,
            SimpleNullKind::Ipv4,
        ] {
            let mut out = Vec::new();
            encode_bind(&Bind::Null(kind), &mut out).unwrap_or_else(|_| {
                panic!("Bind::Null({}) should encode", kind.as_column_kind().name())
            });
            // Simple null layout: [type, null_flag=0x01, bitmap=0x01]
            assert_eq!(out, vec![kind.as_column_kind().as_u8(), 0x01, 0x01]);
        }
    }

    #[test]
    fn null_bind_kind_preserved() {
        assert_eq!(
            Bind::NullDecimal64 { scale: 0 }.kind(),
            ColumnKind::Decimal64
        );
        assert_eq!(Bind::NullVarchar.kind(), ColumnKind::Varchar);
        assert_eq!(
            Bind::NullGeohash { precision_bits: 8 }.kind(),
            ColumnKind::Geohash
        );
    }

    // -----------------------------------------------------------------------
    // Property-based fuzz: random value → encode → manually parse the wire
    // bytes → assert the round-trip matches the input bit-for-bit. Ports
    // `core/.../QwpEgressBindFuzzTest.java` from the OSS questdb repo. The
    // Java original drives a live `TestServerMain` so the server does the
    // decode; here we re-implement the per-type wire reader inline because
    // the Rust crate ships only the encoder (the server is the canonical
    // decoder in production). The reader mirrors the layout documented at
    // the top of this file so any encoder change that drifts from the spec
    // surfaces here as a fuzz failure.
    // -----------------------------------------------------------------------
    mod fuzz {
        use super::*;
        use proptest::prelude::*;

        /// Strip the `[type_code, null_flag=0x00]` prefix from a non-null
        /// value bind, returning the remaining payload bytes. Panics —
        /// which proptest reports as a shrinkable failure — if the prefix
        /// doesn't match.
        fn body_of_non_null(expected_kind: ColumnKind, encoded: &[u8]) -> &[u8] {
            assert!(encoded.len() >= 2, "encoded bind too short");
            assert_eq!(
                encoded[0],
                expected_kind.as_u8(),
                "type code mismatch: encoded={:02x} expected={:02x} ({})",
                encoded[0],
                expected_kind.as_u8(),
                expected_kind.name()
            );
            assert_eq!(encoded[1], 0x00, "null_flag must be 0x00 for non-null bind");
            &encoded[2..]
        }

        // ---- Scalar round-trips (Java's testFuzzIntegralBindsProjection
        // territory: long, int, short, byte, bool) ----------------------

        proptest! {
            #![proptest_config(ProptestConfig {
                cases: 200,
                .. ProptestConfig::default()
            })]

            #[test]
            fn fuzz_bool(v: bool) {
                let bytes = enc(Bind::Bool(v));
                let body = body_of_non_null(ColumnKind::Boolean, &bytes);
                prop_assert_eq!(body, &[v as u8][..]);
            }

            #[test]
            fn fuzz_i8(v: i8) {
                let bytes = enc(Bind::I8(v));
                let body = body_of_non_null(ColumnKind::Byte, &bytes);
                prop_assert_eq!(body, &[v as u8][..]);
            }

            #[test]
            fn fuzz_i16(v: i16) {
                let bytes = enc(Bind::I16(v));
                let body = body_of_non_null(ColumnKind::Short, &bytes);
                prop_assert_eq!(body.len(), 2);
                let got = i16::from_le_bytes(body.try_into().unwrap());
                prop_assert_eq!(got, v);
            }

            #[test]
            fn fuzz_i32(v: i32) {
                let bytes = enc(Bind::I32(v));
                let body = body_of_non_null(ColumnKind::Int, &bytes);
                prop_assert_eq!(body.len(), 4);
                let got = i32::from_le_bytes(body.try_into().unwrap());
                prop_assert_eq!(got, v);
            }

            #[test]
            fn fuzz_i64(v: i64) {
                let bytes = enc(Bind::I64(v));
                let body = body_of_non_null(ColumnKind::Long, &bytes);
                prop_assert_eq!(body.len(), 8);
                let got = i64::from_le_bytes(body.try_into().unwrap());
                prop_assert_eq!(got, v);
            }

            // -- Floats: compare by raw bits so NaN round-trips. The Java
            // reference test uses `Double.isNaN(d)` plus `==` for finite
            // values; raw-bits is equivalent and also catches -0.0 vs 0.0
            // (the encoder must not normalise — that's the server's job).

            #[test]
            fn fuzz_f32_bits(bits: u32) {
                let v = f32::from_bits(bits);
                let bytes = enc(Bind::F32(v));
                let body = body_of_non_null(ColumnKind::Float, &bytes);
                prop_assert_eq!(body.len(), 4);
                let got = f32::from_le_bytes(body.try_into().unwrap());
                prop_assert_eq!(got.to_bits(), v.to_bits());
            }

            #[test]
            fn fuzz_f64_bits(bits: u64) {
                let v = f64::from_bits(bits);
                let bytes = enc(Bind::F64(v));
                let body = body_of_non_null(ColumnKind::Double, &bytes);
                prop_assert_eq!(body.len(), 8);
                let got = f64::from_le_bytes(body.try_into().unwrap());
                prop_assert_eq!(got.to_bits(), v.to_bits());
            }

            // -- Temporal scalars: same wire as I64 but typed differently.

            #[test]
            fn fuzz_timestamp_micros(v: i64) {
                let bytes = enc(Bind::TimestampMicros(v));
                let body = body_of_non_null(ColumnKind::Timestamp, &bytes);
                prop_assert_eq!(i64::from_le_bytes(body.try_into().unwrap()), v);
            }

            #[test]
            fn fuzz_timestamp_nanos(v: i64) {
                let bytes = enc(Bind::TimestampNanos(v));
                let body = body_of_non_null(ColumnKind::TimestampNanos, &bytes);
                prop_assert_eq!(i64::from_le_bytes(body.try_into().unwrap()), v);
            }

            #[test]
            fn fuzz_date_millis(v: i64) {
                let bytes = enc(Bind::DateMillis(v));
                let body = body_of_non_null(ColumnKind::Date, &bytes);
                prop_assert_eq!(i64::from_le_bytes(body.try_into().unwrap()), v);
            }

            // -- 16-bit Char: u16 LE.

            #[test]
            fn fuzz_char(v: u16) {
                let bytes = enc(Bind::Char(v));
                let body = body_of_non_null(ColumnKind::Char, &bytes);
                prop_assert_eq!(body.len(), 2);
                let got = u16::from_le_bytes(body.try_into().unwrap());
                prop_assert_eq!(got, v);
            }

            // -- IPv4: 4 bytes LE.

            #[test]
            fn fuzz_ipv4(octets: [u8; 4]) {
                let addr = Ipv4Addr::from(u32::from_be_bytes(octets));
                let bytes = enc(Bind::Ipv4(addr));
                let body = body_of_non_null(ColumnKind::Ipv4, &bytes);
                prop_assert_eq!(body.len(), 4);
                let got = Ipv4Addr::from(u32::from_le_bytes(body.try_into().unwrap()));
                prop_assert_eq!(got, addr);
            }

            // -- Wide raw blobs: 16-byte UUID + 32-byte LONG256.

            #[test]
            fn fuzz_uuid(raw in proptest::array::uniform16(any::<u8>())) {
                let bytes = enc(Bind::Uuid(raw));
                let body = body_of_non_null(ColumnKind::Uuid, &bytes);
                prop_assert_eq!(body, &raw[..]);
            }

            #[test]
            fn fuzz_long256(raw in proptest::array::uniform32(any::<u8>())) {
                let bytes = enc(Bind::Long256(raw));
                let body = body_of_non_null(ColumnKind::Long256, &bytes);
                prop_assert_eq!(body, &raw[..]);
            }

            // -- DECIMAL64 / DECIMAL128 / DECIMAL256: scale (i8 0..=38) + LE
            // mantissa bytes. Scale comes first on the wire per the docs at
            // the top of this file.

            #[test]
            fn fuzz_decimal64(value: i64, scale in 0i8..=MAX_DECIMAL_SCALE) {
                let bytes = enc(Bind::Decimal64 { value, scale });
                let body = body_of_non_null(ColumnKind::Decimal64, &bytes);
                prop_assert_eq!(body.len(), 1 + 8);
                prop_assert_eq!(body[0] as i8, scale);
                prop_assert_eq!(i64::from_le_bytes(body[1..].try_into().unwrap()), value);
            }

            #[test]
            fn fuzz_decimal128(value: i128, scale in 0i8..=MAX_DECIMAL_SCALE) {
                let bytes = enc(Bind::Decimal128 { value, scale });
                let body = body_of_non_null(ColumnKind::Decimal128, &bytes);
                prop_assert_eq!(body.len(), 1 + 16);
                prop_assert_eq!(body[0] as i8, scale);
                prop_assert_eq!(i128::from_le_bytes(body[1..].try_into().unwrap()), value);
            }

            #[test]
            fn fuzz_decimal256(
                raw in proptest::array::uniform32(any::<u8>()),
                scale in 0i8..=MAX_DECIMAL_SCALE,
            ) {
                let bytes = enc(Bind::Decimal256 { bytes: raw, scale });
                let body = body_of_non_null(ColumnKind::Decimal256, &bytes);
                prop_assert_eq!(body.len(), 1 + 32);
                prop_assert_eq!(body[0] as i8, scale);
                prop_assert_eq!(&body[1..], &raw[..]);
            }

            // -- GEOHASH: varint precision (1..=60) + ceil(precision/8) bytes.

            #[test]
            fn fuzz_geohash(raw_value: u64, precision_bits in 1u8..=60) {
                // The encoder rejects values with bits set above
                // `precision_bits` (see check_bindable + encode_geohash). The
                // Java reference test routes geohash binds through SQL, where
                // the server normalises; here we mask upfront so the fuzz
                // exercises the encoder's value-shaping rather than its
                // out-of-range rejection (already covered by the unit tests
                // above).
                let mask = if precision_bits == 64 {
                    !0u64
                } else {
                    (1u64 << precision_bits) - 1
                };
                let value = raw_value & mask;
                let bytes = enc(Bind::Geohash { value, precision_bits });
                let body = body_of_non_null(ColumnKind::Geohash, &bytes);
                // Precision is a varint; for the 1..=60 range it always fits
                // in a single byte (high bit clear), so the layout is
                // `precision_byte || ceil(precision_bits/8) value bytes`.
                prop_assert_eq!(body[0], precision_bits);
                let byte_width = (precision_bits as usize).div_ceil(8);
                prop_assert_eq!(body.len(), 1 + byte_width);
                let mut buf = [0u8; 8];
                buf[..byte_width].copy_from_slice(&body[1..]);
                let got = u64::from_le_bytes(buf);
                prop_assert_eq!(got, value);
            }

            // -- VARCHAR / BINARY: offsets array (2 × u32_le for one row:
            // `[0, byte_len]`) + concatenated bytes. UTF-8 validity for
            // VARCHAR is the spec's responsibility; we run it through with
            // arbitrary `String`s — proptest's default `String` strategy
            // covers a mix of ASCII and multibyte codepoints.

            #[test]
            fn fuzz_varchar(s in ".{0,32}") {
                let bytes = enc(Bind::Varchar(s.clone()));
                let body = body_of_non_null(ColumnKind::Varchar, &bytes);
                let utf8_bytes = s.as_bytes();
                prop_assert_eq!(body.len(), 8 + utf8_bytes.len());
                let offset0 = u32::from_le_bytes(body[0..4].try_into().unwrap());
                let offset1 = u32::from_le_bytes(body[4..8].try_into().unwrap());
                prop_assert_eq!(offset0, 0);
                prop_assert_eq!(offset1 as usize, utf8_bytes.len());
                prop_assert_eq!(&body[8..], utf8_bytes);
            }

            #[test]
            fn fuzz_binary(buf in proptest::collection::vec(any::<u8>(), 0..32)) {
                let bytes = enc(Bind::Binary(buf.clone()));
                let body = body_of_non_null(ColumnKind::Binary, &bytes);
                prop_assert_eq!(body.len(), 8 + buf.len());
                let offset0 = u32::from_le_bytes(body[0..4].try_into().unwrap());
                let offset1 = u32::from_le_bytes(body[4..8].try_into().unwrap());
                prop_assert_eq!(offset0, 0);
                prop_assert_eq!(offset1 as usize, buf.len());
                prop_assert_eq!(&body[8..], &buf[..]);
            }
        }
    }
}
