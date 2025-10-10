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

use crate::{error, ingress::must_escape_unquoted, Result};

/// Trait for types that can be serialized as decimal values in the InfluxDB Line Protocol (ILP).
///
/// Decimal values can be serialized in two formats:
///
/// # Text Format
/// The decimal is written as a string representation followed by a `'d'` suffix.
///
/// Example: `"123.45d"` or `"1.5e-3d"`
///
/// Implementers must:
/// - Write the decimal's text representation to the output buffer
/// - Append the `'d'` suffix
/// - Ensure no ILP reserved characters are present (space, comma, equals, newline, carriage return, backslash)
///
/// # Binary Format
/// A more compact binary encoding consisting of:
///
/// 1. Binary format marker: `'='` (0x3D)
/// 2. Type identifier: [`DECIMAL_BINARY_FORMAT_TYPE`](crate::ingress::DECIMAL_BINARY_FORMAT_TYPE) byte
/// 3. Scale: 1 byte (0-76 inclusive) - number of decimal places
/// 4. Length: 1 byte - number of bytes in the unscaled value
/// 5. Unscaled value: variable-length byte array in two's complement format, big-endian
///
/// Example: For decimal `123.45` with scale 2 and unscaled value 12345:
/// ```text
/// = [DECIMAL_BINARY_FORMAT_TYPE] [2] [2] [0x30] [0x39]
/// ```
///
/// # Binary Format Notes
/// - Binary format is only supported when `support_binary` is `true` (Protocol V2)
/// - The unscaled value must be encoded in two's complement big-endian format
/// - Maximum scale is 76
/// - Length byte indicates how many bytes follow for the unscaled value
pub trait DecimalSerializer {
    /// Serialize this value as a decimal in ILP format.
    ///
    /// # Parameters
    ///
    /// * `out` - The output buffer to write the serialized decimal to
    /// * `support_binary` - If `true`, binary format may be used (Protocol V2).
    ///   If `false`, text format must be used (Protocol V1).
    fn serialize(self, out: &mut Vec<u8>, support_binary: bool) -> Result<()>;
}

/// Implementation for string slices containing decimal representations.
///
/// This implementation always uses the text format, regardless of the `support_binary` parameter,
/// as it cannot parse the string to extract scale and unscaled value needed for binary encoding.
///
/// # Format
/// The string is validated and written as-is, followed by the 'd' suffix.
///
/// # Validation
/// The implementation performs **partial validation only**:
/// - Rejects ILP reserved characters (space, comma, equals, newline, carriage return, backslash)
/// - Does NOT validate the actual decimal syntax (e.g., "not-a-number" would pass)
///
/// This is intentional: full parsing would add overhead. The QuestDB server performs complete
/// validation and will reject malformed decimals.
///
/// # Examples
/// - `"123.45"` → `"123.45d"`
/// - `"1.5e-3"` → `"1.5e-3d"`
/// - `"-0.001"` → `"-0.001d"`
///
/// # Errors
/// Returns [`Error`] with [`ErrorCode::InvalidDecimal`](crate::error::ErrorCode::InvalidDecimal)
/// if the string contains ILP reserved characters.
impl DecimalSerializer for &str {
    fn serialize(self, out: &mut Vec<u8>, _support_binary: bool) -> Result<()> {
        // Pre-allocate space for the string content plus the 'd' suffix
        out.reserve(self.len() + 1);

        // Validate and copy each byte, rejecting ILP reserved characters
        // that would break the protocol (space, comma, equals, newline, etc.)
        for b in self.bytes() {
            if must_escape_unquoted(b) {
                return Err(error::fmt!(
                    InvalidDecimal,
                    "Unexpected character {:?} in decimal str",
                    b
                ));
            }
            out.push(b);
        }

        // Append the 'd' suffix to mark this as a decimal value
        out.push(b'd');

        Ok(())
    }
}

use crate::ingress::DECIMAL_BINARY_FORMAT_TYPE;

/// Helper to format decimal values directly to a byte buffer without heap allocation.
#[cfg(any(feature = "rust_decimal", feature = "bigdecimal"))]
struct DecimalWriter<'a> {
    buf: &'a mut Vec<u8>,
}

#[cfg(any(feature = "rust_decimal", feature = "bigdecimal"))]
impl<'a> std::fmt::Write for DecimalWriter<'a> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        self.buf.extend_from_slice(s.as_bytes());
        Ok(())
    }
}

#[cfg(feature = "rust_decimal")]
impl DecimalSerializer for &rust_decimal::Decimal {
    fn serialize(self, out: &mut Vec<u8>, support_binary: bool) -> Result<()> {
        if !support_binary {
            // Text format
            use std::fmt::Write;
            write!(DecimalWriter { buf: out }, "{}", self)
                .map_err(|_| error::fmt!(InvalidDecimal, "Failed to format decimal value"))?;
            out.push(b'd');
            return Ok(());
        }

        // Binary format: '=' marker + type + scale + length + mantissa bytes
        out.push(b'=');
        out.push(DECIMAL_BINARY_FORMAT_TYPE);

        // rust_decimal::Decimal guarantees:
        // - MAX_SCALE is 28, which is within QuestDB's limit of 76
        // - Mantissa is always 96 bits (12 bytes), never exceeds this size
        debug_assert!(rust_decimal::Decimal::MAX_SCALE <= 76);
        debug_assert!(
            rust_decimal::Decimal::MAX.mantissa() & 0x7FFF_FFFF_0000_0000_0000_0000_0000_0000i128
                == 0
        );

        out.push(self.scale() as u8);

        // We skip the upper 3 bytes (which are sign-extended) and write the lower 13 bytes
        let mantissa = self.mantissa();
        out.push(13);
        out.extend_from_slice(&mantissa.to_be_bytes()[3..]); // Skip upper 4 bytes, write lower 12

        Ok(())
    }
}

#[cfg(feature = "bigdecimal")]
impl DecimalSerializer for &bigdecimal::BigDecimal {
    fn serialize(self, out: &mut Vec<u8>, support_binary: bool) -> Result<()> {
        if !support_binary {
            // Text format
            use std::fmt::Write;
            write!(DecimalWriter { buf: out }, "{}", self)
                .map_err(|_| error::fmt!(InvalidDecimal, "Failed to format decimal value"))?;
            out.push(b'd');
            return Ok(());
        }

        // Binary format: '=' marker + type + scale + length + mantissa bytes
        out.push(b'=');
        out.push(DECIMAL_BINARY_FORMAT_TYPE);

        let (unscaled, mut scale) = self.as_bigint_and_scale();
        if scale > 76 {
            return Err(error::fmt!(
                InvalidDecimal,
                "QuestDB ILP does not support scale greater than 76, got {}",
                scale
            ));
        }

        // QuestDB binary ILP doesn't support negative scale, we need to upscale the
        // unscaled value to be compliant
        let bytes = if scale < 0 {
            use bigdecimal::num_bigint;
            let unscaled =
                unscaled.into_owned() * num_bigint::BigInt::from(10).pow((-scale) as u32);
            scale = 0;
            unscaled.to_signed_bytes_be()
        } else {
            unscaled.to_signed_bytes_be()
        };

        if bytes.len() > i8::MAX as usize {
            return Err(error::fmt!(
                InvalidDecimal,
                "QuestDB ILP does not support values greater than {} bytes, got {}",
                i8::MAX,
                bytes.len()
            ));
        }

        out.push(scale as u8);

        // Write length byte and mantissa bytes
        out.push(bytes.len() as u8);
        out.extend_from_slice(&bytes);

        Ok(())
    }
}
