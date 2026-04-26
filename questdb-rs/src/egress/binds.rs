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
//! Per spec each bind is encoded as a 1-row column:
//!
//! ```text
//! type_code: u8
//! null_flag: u8           0x00 = value follows; 0x01 = null bitmap follows, no value
//! [bitmap]:  u8           present iff null_flag != 0; 0x01 = single null row
//! [value]:   bytes        present iff null_flag == 0; layout per type
//! ```
//!
//! Multi-byte numeric values are little-endian.

use std::net::Ipv4Addr;

use crate::egress::column_kind::ColumnKind;
use crate::egress::error::{Result, fmt};
use crate::egress::wire::varint;

/// Typed bind value.
///
/// Position is implicit in the order binds are emitted into a `QUERY_REQUEST`
/// (`$1`, `$2`, …). Use [`Bind::Null`] with the placeholder's expected type
/// for typed-NULL binds.
#[derive(Debug, Clone, PartialEq)]
pub enum Bind {
    Null(ColumnKind),
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
    /// QWP `TIMESTAMP` (microseconds since epoch).
    TimestampMicros(i64),
    /// QWP `TIMESTAMP_NANOS` (nanoseconds since epoch).
    TimestampNanos(i64),
    /// QWP `DATE` (milliseconds since epoch).
    DateMillis(i64),
    /// 16 raw bytes; high/low long ordering is the caller's responsibility.
    Uuid([u8; 16]),
    Ipv4(Ipv4Addr),
    /// QWP `DECIMAL64`: signed mantissa + scale (number of fractional digits).
    Decimal64 { value: i64, scale: i8 },
    Binary(Vec<u8>),
}

impl Bind {
    /// QWP type code this bind serializes to.
    pub fn kind(&self) -> ColumnKind {
        match self {
            Bind::Null(k) => *k,
            Bind::Bool(_) => ColumnKind::Boolean,
            Bind::I8(_) => ColumnKind::Byte,
            Bind::I16(_) => ColumnKind::Short,
            Bind::I32(_) => ColumnKind::Int,
            Bind::I64(_) => ColumnKind::Long,
            Bind::F32(_) => ColumnKind::Float,
            Bind::F64(_) => ColumnKind::Double,
            Bind::Varchar(_) => ColumnKind::Varchar,
            Bind::TimestampMicros(_) => ColumnKind::Timestamp,
            Bind::TimestampNanos(_) => ColumnKind::TimestampNanos,
            Bind::DateMillis(_) => ColumnKind::Date,
            Bind::Uuid(_) => ColumnKind::Uuid,
            Bind::Ipv4(_) => ColumnKind::Ipv4,
            Bind::Decimal64 { .. } => ColumnKind::Decimal64,
            Bind::Binary(_) => ColumnKind::Binary,
        }
    }
}

/// Append the wire encoding of `bind` to `out`.
pub fn encode_bind(bind: &Bind, out: &mut Vec<u8>) -> Result<()> {
    out.push(bind.kind().as_u8());

    if let Bind::Null(_) = bind {
        out.push(0x01); // null_flag: bitmap follows
        out.push(0x01); // bitmap: bit 0 set = row 0 is NULL
        return Ok(());
    }

    out.push(0x00); // null_flag: value follows

    match bind {
        Bind::Null(_) => unreachable!(),
        Bind::Bool(v) => out.push(if *v { 0x01 } else { 0x00 }),
        Bind::I8(v) => out.push(*v as u8),
        Bind::I16(v) => out.extend_from_slice(&v.to_le_bytes()),
        Bind::I32(v) => out.extend_from_slice(&v.to_le_bytes()),
        Bind::I64(v) => out.extend_from_slice(&v.to_le_bytes()),
        Bind::F32(v) => out.extend_from_slice(&v.to_le_bytes()),
        Bind::F64(v) => out.extend_from_slice(&v.to_le_bytes()),
        Bind::TimestampMicros(v) | Bind::TimestampNanos(v) | Bind::DateMillis(v) => {
            out.extend_from_slice(&v.to_le_bytes())
        }
        Bind::Uuid(bytes) => out.extend_from_slice(bytes),
        Bind::Ipv4(addr) => {
            // QuestDB treats IPv4 as a uint32. Octets are big-endian network
            // order; we serialize the host-order integer LE on the wire.
            let v: u32 = u32::from(*addr);
            out.extend_from_slice(&v.to_le_bytes());
        }
        Bind::Decimal64 { value, scale } => {
            out.push(*scale as u8);
            out.extend_from_slice(&value.to_le_bytes());
        }
        Bind::Varchar(s) => {
            // TODO(qwp): confirm against ingress spec. Best fit for a 1-row
            // bind is varint(byte_len) + UTF-8 bytes; the ingress section
            // referenced by the egress spec was not available at write time.
            varint::encode_u64(s.len() as u64, out);
            out.extend_from_slice(s.as_bytes());
        }
        Bind::Binary(b) => {
            // TODO(qwp): same caveat as Varchar — confirm encoding.
            varint::encode_u64(b.len() as u64, out);
            out.extend_from_slice(b);
        }
    }

    Ok(())
}

/// Reject bind kinds we don't yet support encoding for.
///
/// Used by builders so the failure surfaces at `bind_*` call site, not at
/// `encode_bind` time. Currently rejects QWP types whose wire format we
/// haven't implemented (SYMBOL, GEOHASH, CHAR, LONG256, DECIMAL128/256,
/// arrays). Server-side these can still arrive in `RESULT_BATCH`.
pub fn check_bindable(kind: ColumnKind) -> Result<()> {
    match kind {
        ColumnKind::Boolean
        | ColumnKind::Byte
        | ColumnKind::Short
        | ColumnKind::Int
        | ColumnKind::Long
        | ColumnKind::Float
        | ColumnKind::Double
        | ColumnKind::Varchar
        | ColumnKind::Timestamp
        | ColumnKind::TimestampNanos
        | ColumnKind::Date
        | ColumnKind::Uuid
        | ColumnKind::Ipv4
        | ColumnKind::Decimal64
        | ColumnKind::Binary => Ok(()),
        other => Err(fmt!(
            InvalidBind,
            "bind not supported for type {} (0x{:02X})",
            other.name(),
            other.as_u8()
        )),
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

    #[test]
    fn null_bind_layout() {
        // type_code=Long(0x05), null_flag=0x01, bitmap=0x01
        assert_eq!(enc(Bind::Null(ColumnKind::Long)), vec![0x05, 0x01, 0x01]);
    }

    #[test]
    fn bool_bind_layout() {
        assert_eq!(enc(Bind::Bool(true)), vec![0x01, 0x00, 0x01]);
        assert_eq!(enc(Bind::Bool(false)), vec![0x01, 0x00, 0x00]);
    }

    #[test]
    fn i32_bind_le() {
        // INT (0x04), value 0x01020304
        assert_eq!(
            enc(Bind::I32(0x01020304)),
            vec![0x04, 0x00, 0x04, 0x03, 0x02, 0x01]
        );
    }

    #[test]
    fn i64_bind_le() {
        assert_eq!(
            enc(Bind::I64(0x0102_0304_0506_0708)),
            vec![0x05, 0x00, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );
    }

    #[test]
    fn f64_bind_le() {
        let v = 1.0f64;
        let mut expected = vec![0x07, 0x00];
        expected.extend_from_slice(&v.to_le_bytes());
        assert_eq!(enc(Bind::F64(v)), expected);
    }

    #[test]
    fn decimal64_bind_layout() {
        // type=0x13, null_flag=0x00, scale=0x02, value LE
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
    fn varchar_bind_layout() {
        let bytes = enc(Bind::Varchar("hi".into()));
        // 0x0F, 0x00, varint(2) = 0x02, 'h', 'i'
        assert_eq!(bytes, vec![0x0F, 0x00, 0x02, b'h', b'i']);
    }

    #[test]
    fn varchar_bind_long_uses_multibyte_varint() {
        let s = "a".repeat(200);
        let bytes = enc(Bind::Varchar(s.clone()));
        // varint(200) = 0xC8 0x01
        assert_eq!(&bytes[..4], &[0x0F, 0x00, 0xC8, 0x01]);
        assert_eq!(&bytes[4..], s.as_bytes());
    }

    #[test]
    fn ipv4_bind_le() {
        let bytes = enc(Bind::Ipv4(Ipv4Addr::new(192, 168, 1, 1)));
        // 192.168.1.1 -> u32 = 0xC0A80101 -> LE bytes 01 01 A8 C0
        assert_eq!(bytes, vec![0x18, 0x00, 0x01, 0x01, 0xA8, 0xC0]);
    }

    #[test]
    fn uuid_bind_passthrough() {
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
    fn binary_bind_layout() {
        let bytes = enc(Bind::Binary(vec![0xDE, 0xAD]));
        assert_eq!(bytes, vec![0x17, 0x00, 0x02, 0xDE, 0xAD]);
    }

    #[test]
    fn check_bindable_rejects_unsupported() {
        assert!(check_bindable(ColumnKind::Symbol).is_err());
        assert!(check_bindable(ColumnKind::Geohash).is_err());
        assert!(check_bindable(ColumnKind::DoubleArray).is_err());
        assert!(check_bindable(ColumnKind::Decimal128).is_err());
        assert!(check_bindable(ColumnKind::Char).is_err());
        assert!(check_bindable(ColumnKind::Long256).is_err());
    }

    #[test]
    fn check_bindable_accepts_supported() {
        for k in [
            ColumnKind::Boolean,
            ColumnKind::Long,
            ColumnKind::Double,
            ColumnKind::Varchar,
            ColumnKind::TimestampNanos,
            ColumnKind::Decimal64,
            ColumnKind::Ipv4,
            ColumnKind::Uuid,
            ColumnKind::Binary,
        ] {
            check_bindable(k).expect(k.name());
        }
    }

    #[test]
    fn null_bind_kind_preserved() {
        let b = Bind::Null(ColumnKind::Decimal64);
        assert_eq!(b.kind(), ColumnKind::Decimal64);
        assert_eq!(enc(b), vec![0x13, 0x01, 0x01]);
    }
}
