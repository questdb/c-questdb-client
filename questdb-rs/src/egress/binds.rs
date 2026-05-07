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
/// SYMBOL is also excluded: per the QWP egress spec (§6 "Bind
/// parameters"), compliant clients send symbol binds as STRING /
/// VARCHAR — there is no need for a SYMBOL wire type code on the bind
/// path (the server is lenient and accepts it for now, but the spec
/// instructs clients not to emit it). DOUBLE_ARRAY / LONG_ARRAY are
/// excluded because the Phase 1 server rejects array binds with "not
/// yet supported"; the spec describes the eventual encoding (per-row
/// dimension header), so this exclusion may be lifted when the server
/// implements them.
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
/// `#[non_exhaustive]` so future bind types (e.g. when array binds are
/// promoted out of the Phase 1 limitation) can be added without
/// breaking exhaustive matches in user code.
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
        // The Phase 1 server rejects IPv4 and BINARY bind type codes
        // outright (no decoder case → "unsupported wire type"), and
        // rejects array binds with "not yet supported in Phase 1". The
        // server accepts SYMBOL leniently (spec §6) but compliant
        // clients send STRING / VARCHAR. `check_bindable` surfaces all
        // of these client-side. The `Bind::Ipv4` / `Bind::Binary` arms
        // below are reachable only if the bind-set is encoded without
        // going through `QueryRequestBuilder::build` — we keep the wire
        // encoding for completeness and forward compatibility, so when
        // the server lifts a restriction the encoder is already
        // correct.
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

/// Reject bind kinds whose wire type code the Phase 1 server doesn't
/// decode. Surfacing the rejection client-side avoids ambiguous server
/// errors (the server's QUERY_ERROR for these arrives with
/// `request_id=0`, breaking correlation).
///
/// Reference: `core/src/main/java/io/questdb/cutlass/qwp/server/egress/QwpEgressRequestDecoder.java`
/// `decodeBind` switch.
///
/// - **BINARY (0x17), IPv4 (0x18)**: no decoder case — fall into the
///   `default ->` arm with "unsupported wire type".
/// - **DOUBLE_ARRAY (0x11), LONG_ARRAY (0x12)**: explicit case throwing
///   "ARRAY bind parameters not yet supported in Phase 1 egress". The
///   QWP spec (§6 "Bind parameters") describes the eventual array bind
///   encoding (per-row dimension header), so this is a Phase 1
///   limitation that may be lifted server-side.
/// - **SYMBOL (0x09)** is listed defensively. The Phase 1 server
///   currently accepts SYMBOL bind type codes leniently, dispatching
///   them to `BindVariableService.setStr` (spec §6 "Server leniency
///   note"). However, the spec instructs compliant clients to send
///   STRING / VARCHAR for symbol binds — and a future server revision
///   may tighten this to reject SYMBOL bind type codes. The Rust
///   `Bind` enum has no `Symbol(_)` value variant, and
///   [`SimpleNullKind`] excludes Symbol, so this arm is unreachable
///   through the typed API; it stays here as a defense against any
///   future code path that might synthesise a SYMBOL-kinded `Bind`.
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
        assert_eq!(enc(Bind::Null(SimpleNullKind::Long)), vec![0x05, 0x01, 0x01]);
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
}
