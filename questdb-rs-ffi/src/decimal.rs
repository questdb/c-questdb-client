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

//! FFI-specific decimal number serialization for QuestDB ILP.
//!
//! This module provides decimal serialization support for the C FFI bindings.
//! Decimals are represented as arbitrary-precision numbers with a scale factor,
//! encoded in a binary format for transmission over the InfluxDB Line Protocol (ILP).

use questdb::{
    Result,
    ingress::{DECIMAL_BINARY_FORMAT_TYPE, DecimalSerializer},
};

use crate::fmt_error;

/// Represents a decimal number for binary serialization to QuestDB.
///
/// A decimal consists of:
/// - An unscaled integer value (the mantissa), represented as raw bytes in big-endian format
/// - A scale indicating how many decimal places to shift (e.g., scale=2 means value/100)
///
/// # Wire Format
///
/// The binary serialization format is:
/// ```text
/// '=' marker (1 byte) + type ID (1 byte) + length (1 byte) + value bytes + scale (1 byte)
/// ```
///
/// # Constraints
///
/// - Maximum scale: 76 (QuestDB server limitation)
/// - Maximum value size: 127 bytes (i8::MAX limitation from length field)
///
/// # Example
///
/// To represent the decimal `123.45` with scale 2:
/// - scale = 2
/// - value = 12345 encoded as bytes [0x30, 0x39] (big-endian)
pub(super) struct Decimal<'a> {
    /// The number of decimal places to shift.
    /// For example, scale=2 means the value represents hundredths (divide by 100).
    scale: u32,

    /// The unscaled integer value as raw bytes in big-endian format.
    /// This represents the mantissa of the decimal number.
    value: &'a [u8],
}

impl<'a> Decimal<'a> {
    /// Creates a new decimal number.
    ///
    /// # Arguments
    ///
    /// * `scale` - The number of decimal places (must be ≤ 76)
    /// * `value` - The unscaled value as bytes in big-endian format (must be ≤ 127 bytes)
    pub(super) fn new(scale: u32, value: &'a [u8]) -> Self {
        Self { scale, value }
    }
}

impl<'a> DecimalSerializer for Decimal<'a> {
    /// Serializes the decimal value into the QuestDB ILP binary format.
    ///
    /// # Wire Format Layout
    ///
    /// The serialization produces the following byte sequence:
    /// 1. `'='` (0x3D) - Binary encoding marker
    /// 2. Type ID (23) - Identifies this as a decimal type
    /// 3. Scale byte - Number of decimal places
    /// 4. Length byte - Number of bytes in the value (max 127)
    /// 5. Value bytes - The unscaled integer in big-endian format
    ///
    /// # Arguments
    ///
    /// * `out` - The output buffer to write the serialized decimal to
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Scale exceeds 76 (QuestDB server maximum)
    /// - Value size exceeds 127 bytes (protocol limitation)
    fn serialize(self, out: &mut Vec<u8>) -> Result<()> {
        // Validate scale constraint (QuestDB server limitation)
        // The server's decimal implementation supports a maximum scale of 76
        if self.scale > 76 {
            return Err(fmt_error!(
                InvalidDecimal,
                "QuestDB ILP does not support scale greater than 76, got {}",
                self.scale
            ));
        }

        // Write binary format header
        out.push(b'='); // Binary encoding marker
        out.push(DECIMAL_BINARY_FORMAT_TYPE); // Type ID = 23

        // Validate value size constraint (protocol limitation)
        // The length field is a single byte (i8), limiting value size to 127 bytes
        if self.value.len() > i8::MAX as usize {
            return Err(fmt_error!(
                InvalidDecimal,
                "QuestDB ILP does not support values greater than {} bytes, got {}",
                i8::MAX,
                self.value.len()
            ));
        }

        out.push(self.scale as u8);
        out.push(self.value.len() as u8);
        out.extend_from_slice(self.value);

        Ok(())
    }
}
