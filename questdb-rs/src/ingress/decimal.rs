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

use crate::{Result, error};
use std::borrow::Cow;

/// A decimal value backed by either a string representation or a scaled mantissa.
///
/// Decimal values can be serialized in two formats:
///
/// ### Text Format
/// The decimal is written as a string representation followed by a `'d'` suffix.
///
/// Example: `"123.45d"` or `"1.5e-3d"`
///
/// ### Binary Format
/// A more compact binary encoding consisting of:
///
/// 1. Binary format marker: `'='` (0x3D)
/// 2. Type identifier: [`DECIMAL_BINARY_FORMAT_TYPE`](crate::ingress::DECIMAL_BINARY_FORMAT_TYPE) byte
/// 3. Scale: 1 byte (0-76 inclusive) - number of decimal places
/// 4. Length: 1 byte - number of bytes in the unscaled value
/// 5. Unscaled value: variable-length byte array in two's complement format, big-endian
///
/// Example: For decimal `123.45` with scale 2:
/// ```text
/// Unscaled value: 12345
/// Binary representation:
///   = [23] [2] [2] [0x30] [0x39]
///   │  │    │   │  └───────────┘
///   │  │    │   │        └─ Mantissa bytes (12345 in big-endian)
///   │  │    │   └─ Length: 2 bytes
///   │  │    └─ Scale: 2
///   │  └─ Type: DECIMAL_BINARY_FORMAT_TYPE (23)
///   └─ Binary marker: '='
/// ```
///
/// #### Binary Format Notes
/// - The unscaled value must be encoded in two's complement big-endian format
/// - Maximum scale is 76
/// - Length byte indicates how many bytes follow for the unscaled value
#[derive(Debug)]
pub enum DecimalView<'a> {
    String { value: &'a str },
    Scaled { scale: u8, value: Cow<'a, [u8]> },
}

impl<'a> DecimalView<'a> {
    /// Creates a [`DecimalView::Scaled`] from a mantissa buffer and scale.
    ///
    /// Validates that:
    /// - `scale` does not exceed the QuestDB maximum of 76 decimal places.
    /// - The mantissa fits into at most 32 bytes (ILP binary limit).
    ///
    /// Returns an [`error::ErrorCode::InvalidDecimal`](crate::error::ErrorCode::InvalidDecimal)
    /// error if either constraint is violated.
    pub fn try_new_scaled<T>(scale: u32, value: T) -> Result<Self>
    where
        T: Into<Cow<'a, [u8]>>,
    {
        if scale > 76 {
            return Err(error::fmt!(
                InvalidDecimal,
                "QuestDB ILP does not support decimal scale greater than 76, got {}",
                scale
            ));
        }
        let value: Cow<'a, [u8]> = value.into();
        if value.len() > 32 as usize {
            return Err(error::fmt!(
                InvalidDecimal,
                "QuestDB ILP does not support decimal longer than 32 bytes, got {}",
                value.len()
            ));
        }
        Ok(DecimalView::Scaled {
            scale: scale as u8,
            value,
        })
    }

    /// Creates a [`DecimalView::String`] from a textual decimal representation.
    ///
    /// Thousand separators (commas) are not allowed and the decimal point must be a dot (`.`).
    ///
    /// Performs lightweight validation and rejects values containing ILP-reserved characters.
    /// Accepts plain decimals, optional `+/-` prefixes, `NaN`, `Infinity`, and scientific
    /// notation (`e`/`E`).
    ///
    /// Returns [`error::ErrorCode::InvalidDecimal`](crate::error::ErrorCode::InvalidDecimal)
    /// if disallowed characters are encountered.
    pub fn try_new_string(value: &'a str) -> Result<Self> {
        // Basic validation: ensure only numerical characters are present (accepts NaN, Inf[inity], and e-notation)
        for b in value.chars() {
            match b {
                '0'..='9'
                | '.'
                | '-'
                | '+'
                | 'e'
                | 'E'
                | 'N'
                | 'a'
                | 'I'
                | 'n'
                | 'f'
                | 'i'
                | 't'
                | 'y' => {}
                _ => {
                    return Err(error::fmt!(
                        InvalidDecimal,
                        "Decimal string contains ILP reserved character {:?}",
                        b
                    ));
                }
            }
        }
        Ok(DecimalView::String { value })
    }

    /// Serializes the decimal view into the provided output buffer using the ILP encoding.
    ///
    /// Delegates to [`serialize_string`] for textual representations and [`serialize_scaled`] for
    /// the compact binary format.
    pub(crate) fn serialize(&self, out: &mut Vec<u8>) {
        match self {
            DecimalView::String { value } => Self::serialize_string(value, out),
            DecimalView::Scaled { scale, value } => {
                Self::serialize_scaled(*scale, value.as_ref(), out)
            }
        }
    }

    /// Serializes a textual decimal by copying the string and appending the `d` suffix.
    fn serialize_string(value: &str, out: &mut Vec<u8>) {
        // Pre-allocate space for the string content plus the 'd' suffix
        out.reserve(value.len() + 1);

        out.extend_from_slice(value.as_bytes());

        // Append the 'd' suffix to mark this as a decimal value
        out.push(b'd');
    }

    /// Serializes a scaled decimal into the binary ILP format, writing the marker, type tag,
    /// scale, mantissa length, and mantissa bytes.
    fn serialize_scaled(scale: u8, value: &[u8], out: &mut Vec<u8>) {
        // Write binary format: '=' marker + type + scale + length + mantissa bytes
        out.push(b'=');
        out.push(crate::ingress::DECIMAL_BINARY_FORMAT_TYPE);
        out.push(scale);
        out.push(value.len() as u8);
        out.extend_from_slice(value);
    }
}

/// Implementation for string slices containing decimal representations.
///
/// This implementation uses the text format.
///
/// # Format
/// The string is validated and written as-is, followed by the 'd' suffix. Thousand separators
/// (commas) are not allowed and the decimal point must be a dot (`.`).
///
/// # Validation
/// The implementation performs **partial validation only**:
/// - Rejects non-numerical characters (not -/+, 0-9, ., Infinity, NaN, e/E)
/// - Does NOT validate the actual decimal syntax (e.g., "e2e" would pass)
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
/// if the string contains non-numerical characters.
impl<'a> TryInto<DecimalView<'a>> for &'a str {
    type Error = crate::Error;

    fn try_into(self) -> Result<DecimalView<'a>> {
        DecimalView::try_new_string(self)
    }
}

#[cfg(feature = "rust_decimal")]
impl<'a> TryInto<DecimalView<'a>> for &'a rust_decimal::Decimal {
    type Error = crate::Error;

    fn try_into(self) -> Result<DecimalView<'a>> {
        let raw = self.mantissa().to_be_bytes();
        let bytes = trim_leading_sign_bytes(&raw);
        DecimalView::try_new_scaled(self.scale(), bytes)
    }
}

#[cfg(feature = "bigdecimal")]
impl<'a> TryInto<DecimalView<'a>> for &'a bigdecimal::BigDecimal {
    type Error = crate::Error;

    fn try_into(self) -> Result<DecimalView<'a>> {
        let (unscaled, mut scale) = self.as_bigint_and_scale();

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

        let bytes = trim_leading_sign_bytes(&bytes);

        DecimalView::try_new_scaled(scale as u32, bytes)
    }
}

#[cfg(any(feature = "rust_decimal", feature = "bigdecimal"))]
fn trim_leading_sign_bytes(bytes: &[u8]) -> Vec<u8> {
    if bytes.is_empty() {
        return vec![0];
    }

    let negative = bytes[0] & 0x80 != 0;
    let mut keep_from = 0usize;

    while keep_from < bytes.len() - 1 {
        let current = bytes[keep_from];
        let next = bytes[keep_from + 1];

        let should_trim = if negative {
            current == 0xFF && (next & 0x80) == 0x80
        } else {
            current == 0x00 && (next & 0x80) == 0x00
        };

        if should_trim {
            keep_from += 1;
        } else {
            break;
        }
    }

    bytes[keep_from..].to_vec()
}
