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

//! QWP column type codes.
//!
//! ABI-stable: variants append-only, never reorder. `0x08` is reserved
//! (formerly `STRING`, removed); senders use [`Varchar`](ColumnKind::Varchar).

use crate::egress::error::{Result, fmt};

/// QWP wire type code.
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ColumnKind {
    Boolean = 0x01,
    Byte = 0x02,
    Short = 0x03,
    Int = 0x04,
    Long = 0x05,
    Float = 0x06,
    Double = 0x07,
    // 0x08 reserved (formerly STRING)
    Symbol = 0x09,
    /// Microsecond-precision timestamp.
    Timestamp = 0x0A,
    Date = 0x0B,
    Uuid = 0x0C,
    Long256 = 0x0D,
    Geohash = 0x0E,
    Varchar = 0x0F,
    /// Nanosecond-precision timestamp.
    TimestampNanos = 0x10,
    DoubleArray = 0x11,
    LongArray = 0x12,
    Decimal64 = 0x13,
    Decimal128 = 0x14,
    Decimal256 = 0x15,
    Char = 0x16,
    Binary = 0x17,
    Ipv4 = 0x18,
}

impl ColumnKind {
    /// Parse a wire byte into a known column kind.
    pub fn from_u8(byte: u8) -> Result<Self> {
        Ok(match byte {
            0x01 => ColumnKind::Boolean,
            0x02 => ColumnKind::Byte,
            0x03 => ColumnKind::Short,
            0x04 => ColumnKind::Int,
            0x05 => ColumnKind::Long,
            0x06 => ColumnKind::Float,
            0x07 => ColumnKind::Double,
            0x09 => ColumnKind::Symbol,
            0x0A => ColumnKind::Timestamp,
            0x0B => ColumnKind::Date,
            0x0C => ColumnKind::Uuid,
            0x0D => ColumnKind::Long256,
            0x0E => ColumnKind::Geohash,
            0x0F => ColumnKind::Varchar,
            0x10 => ColumnKind::TimestampNanos,
            0x11 => ColumnKind::DoubleArray,
            0x12 => ColumnKind::LongArray,
            0x13 => ColumnKind::Decimal64,
            0x14 => ColumnKind::Decimal128,
            0x15 => ColumnKind::Decimal256,
            0x16 => ColumnKind::Char,
            0x17 => ColumnKind::Binary,
            0x18 => ColumnKind::Ipv4,
            0x08 => {
                return Err(fmt!(
                    ProtocolError,
                    "type code 0x08 is reserved (was STRING)"
                ));
            }
            other => {
                return Err(fmt!(
                    ProtocolError,
                    "unknown column type code 0x{:02X}",
                    other
                ));
            }
        })
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Stable, lower-case name for diagnostics.
    pub fn name(self) -> &'static str {
        match self {
            ColumnKind::Boolean => "boolean",
            ColumnKind::Byte => "byte",
            ColumnKind::Short => "short",
            ColumnKind::Int => "int",
            ColumnKind::Long => "long",
            ColumnKind::Float => "float",
            ColumnKind::Double => "double",
            ColumnKind::Symbol => "symbol",
            ColumnKind::Timestamp => "timestamp",
            ColumnKind::Date => "date",
            ColumnKind::Uuid => "uuid",
            ColumnKind::Long256 => "long256",
            ColumnKind::Geohash => "geohash",
            ColumnKind::Varchar => "varchar",
            ColumnKind::TimestampNanos => "timestamp_nanos",
            ColumnKind::DoubleArray => "double_array",
            ColumnKind::LongArray => "long_array",
            ColumnKind::Decimal64 => "decimal64",
            ColumnKind::Decimal128 => "decimal128",
            ColumnKind::Decimal256 => "decimal256",
            ColumnKind::Char => "char",
            ColumnKind::Binary => "binary",
            ColumnKind::Ipv4 => "ipv4",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: &[ColumnKind] = &[
        ColumnKind::Boolean,
        ColumnKind::Byte,
        ColumnKind::Short,
        ColumnKind::Int,
        ColumnKind::Long,
        ColumnKind::Float,
        ColumnKind::Double,
        ColumnKind::Symbol,
        ColumnKind::Timestamp,
        ColumnKind::Date,
        ColumnKind::Uuid,
        ColumnKind::Long256,
        ColumnKind::Geohash,
        ColumnKind::Varchar,
        ColumnKind::TimestampNanos,
        ColumnKind::DoubleArray,
        ColumnKind::LongArray,
        ColumnKind::Decimal64,
        ColumnKind::Decimal128,
        ColumnKind::Decimal256,
        ColumnKind::Char,
        ColumnKind::Binary,
        ColumnKind::Ipv4,
    ];

    #[test]
    fn roundtrip_all_known_codes() {
        for &k in ALL {
            assert_eq!(ColumnKind::from_u8(k.as_u8()).unwrap(), k, "{}", k.name());
        }
    }

    #[test]
    fn reserved_string_code_rejected() {
        assert!(ColumnKind::from_u8(0x08).is_err());
    }

    #[test]
    fn unknown_codes_rejected() {
        assert!(ColumnKind::from_u8(0x00).is_err());
        assert!(ColumnKind::from_u8(0x19).is_err());
        assert!(ColumnKind::from_u8(0xFF).is_err());
    }

    #[test]
    fn names_unique() {
        let names: Vec<_> = ALL.iter().map(|k| k.name()).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(names.len(), sorted.len());
    }
}
