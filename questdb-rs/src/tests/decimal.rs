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

use crate::ingress::{Buffer, DecimalSerializer, ProtocolVersion};
use crate::tests::{assert_err_contains, TestResult};
use crate::ErrorCode;
use rstest::rstest;

// Helper function to serialize a decimal value and return the bytes
fn serialize_decimal<D: DecimalSerializer>(value: D) -> crate::Result<Vec<u8>> {
    let mut out = Vec::new();
    value.serialize(&mut out)?;
    Ok(out)
}

// ============================================================================
// Tests for &str implementation
// ============================================================================

#[test]
fn test_str_positive_decimal() -> TestResult {
    let result = serialize_decimal("123.45")?;
    assert_eq!(result, b"123.45d");
    Ok(())
}

#[test]
fn test_str_negative_decimal() -> TestResult {
    let result = serialize_decimal("-123.45")?;
    assert_eq!(result, b"-123.45d");
    Ok(())
}

#[test]
fn test_str_zero() -> TestResult {
    let result = serialize_decimal("0")?;
    assert_eq!(result, b"0d");
    Ok(())
}

#[test]
fn test_str_scientific_notation() -> TestResult {
    let result = serialize_decimal("1.5e-3")?;
    assert_eq!(result, b"1.5e-3d");
    Ok(())
}

#[test]
fn test_str_large_decimal() -> TestResult {
    let result = serialize_decimal("999999999999999999.123456789")?;
    assert_eq!(result, b"999999999999999999.123456789d");
    Ok(())
}

#[test]
fn test_str_with_leading_zero() -> TestResult {
    let result = serialize_decimal("0.001")?;
    assert_eq!(result, b"0.001d");
    Ok(())
}

#[test]
fn test_str_rejects_space() -> TestResult {
    let result = serialize_decimal("12 3.45");
    assert_err_contains(result, ErrorCode::InvalidDecimal, "Invalid character");
    Ok(())
}

#[test]
fn test_str_rejects_comma() -> TestResult {
    let result = serialize_decimal("1,234.56");
    assert_err_contains(result, ErrorCode::InvalidDecimal, "Invalid character");
    Ok(())
}

#[test]
fn test_str_rejects_equals() -> TestResult {
    let result = serialize_decimal("123=45");
    assert_err_contains(result, ErrorCode::InvalidDecimal, "Invalid character");
    Ok(())
}

#[test]
fn test_str_rejects_newline() -> TestResult {
    let result = serialize_decimal("123\n45");
    assert_err_contains(result, ErrorCode::InvalidDecimal, "Invalid character");
    Ok(())
}

#[test]
fn test_str_rejects_backslash() -> TestResult {
    let result = serialize_decimal("123\\45");
    assert_err_contains(result, ErrorCode::InvalidDecimal, "Invalid character");
    Ok(())
}

/// Validates the binary format structure and extracts the components.
#[cfg(any(feature = "rust_decimal", feature = "bigdecimal"))]
fn parse_binary_decimal(bytes: &[u8]) -> (u8, i128) {
    // Validate format markers

    use crate::ingress::DECIMAL_BINARY_FORMAT_TYPE;
    assert_eq!(bytes[0], b'=', "Missing binary format marker");
    assert_eq!(
        bytes[1], DECIMAL_BINARY_FORMAT_TYPE,
        "Invalid decimal type byte"
    );

    let scale = bytes[2];
    let length = bytes[3] as usize;

    assert!(scale <= 76, "Scale {} exceeds maximum of 76", scale);
    assert_eq!(
        bytes.len(),
        4 + length,
        "Binary data length mismatch: expected {} bytes, got {}",
        4 + length,
        bytes.len()
    );

    // Parse mantissa bytes as big-endian two's complement
    let mantissa_bytes = &bytes[4..];

    // Convert from big-endian bytes to i128
    // We need to sign-extend if the value is negative (high bit set)
    let mut i128_bytes = [0u8; 16];
    let offset = 16 - length;

    // Copy mantissa bytes to the lower part of i128_bytes
    i128_bytes[offset..].copy_from_slice(mantissa_bytes);

    // Sign extend if negative (check if high bit of mantissa is set)
    if mantissa_bytes[0] & 0x80 != 0 {
        // Fill upper bytes with 0xFF for negative numbers
        i128_bytes[..offset].fill(0xFF);
    }

    let unscaled = i128::from_be_bytes(i128_bytes);

    (scale, unscaled)
}

// ============================================================================
// Tests for rust_decimal::Decimal implementation
// ============================================================================

#[cfg(feature = "rust_decimal")]
mod rust_decimal_tests {
    use super::*;
    use rust_decimal::Decimal;
    use std::str::FromStr;

    #[test]
    fn test_decimal_binary_format_zero() -> TestResult {
        let dec = Decimal::ZERO;
        let result = serialize_decimal(&dec)?;

        let (scale, unscaled) = parse_binary_decimal(&result);
        assert_eq!(scale, 0, "Zero should have scale 0");
        assert_eq!(unscaled, 0, "Zero should have unscaled value 0");
        Ok(())
    }

    #[test]
    fn test_decimal_binary_format_positive() -> TestResult {
        let dec = Decimal::from_str("123.45")?;
        let result = serialize_decimal(&dec)?;

        let (scale, unscaled) = parse_binary_decimal(&result);
        assert_eq!(scale, 2, "123.45 should have scale 2");
        assert_eq!(unscaled, 12345, "123.45 should have unscaled value 12345");
        Ok(())
    }

    #[test]
    fn test_decimal_binary_format_negative() -> TestResult {
        let dec = Decimal::from_str("-123.45")?;
        let result = serialize_decimal(&dec)?;

        let (scale, unscaled) = parse_binary_decimal(&result);
        assert_eq!(scale, 2, "-123.45 should have scale 2");
        assert_eq!(
            unscaled, -12345,
            "-123.45 should have unscaled value -12345"
        );
        Ok(())
    }

    #[test]
    fn test_decimal_binary_format_one() -> TestResult {
        let dec = Decimal::ONE;
        let result = serialize_decimal(&dec)?;

        let (scale, unscaled) = parse_binary_decimal(&result);
        assert_eq!(scale, 0, "One should have scale 0");
        assert_eq!(unscaled, 1, "One should have unscaled value 1");
        Ok(())
    }

    #[test]
    fn test_decimal_binary_format_max_scale() -> TestResult {
        // Create a decimal with maximum scale (28 for rust_decimal)
        let dec = Decimal::from_str("0.0000000000000000000000000001")?;
        let result = serialize_decimal(&dec)?;

        let (scale, unscaled) = parse_binary_decimal(&result);
        assert_eq!(scale, 28, "Should have maximum scale of 28");
        assert_eq!(unscaled, 1, "Should have unscaled value 1");
        Ok(())
    }

    #[test]
    fn test_decimal_binary_format_large_value() -> TestResult {
        let dec = Decimal::MAX;
        let result = serialize_decimal(&dec)?;

        let (scale, unscaled) = parse_binary_decimal(&result);
        assert_eq!(scale, 0, "Large integer should have scale 0");
        assert_eq!(
            unscaled, 79228162514264337593543950335i128,
            "Should have correct unscaled value"
        );
        Ok(())
    }

    #[test]
    fn test_decimal_binary_format_large_value2() -> TestResult {
        let dec = Decimal::MIN;
        let result = serialize_decimal(&dec)?;

        let (scale, unscaled) = parse_binary_decimal(&result);
        assert_eq!(scale, 0, "Large integer should have scale 0");
        assert_eq!(
            unscaled, -79228162514264337593543950335i128,
            "Should have correct unscaled value"
        );
        Ok(())
    }

    #[test]
    fn test_decimal_binary_format_small_negative() -> TestResult {
        let dec = Decimal::from_str("-0.01")?;
        let result = serialize_decimal(&dec)?;

        let (scale, unscaled) = parse_binary_decimal(&result);
        assert_eq!(scale, 2, "-0.01 should have scale 2");
        assert_eq!(unscaled, -1, "-0.01 should have unscaled value -1");
        Ok(())
    }

    #[test]
    fn test_decimal_binary_format_trailing_zeros() -> TestResult {
        let dec = Decimal::from_str("1.00")?;
        let result = serialize_decimal(&dec)?;

        let (scale, unscaled) = parse_binary_decimal(&result);
        // rust_decimal normalizes trailing zeros
        assert_eq!(scale, 2, "1.00 should have scale 2");
        assert_eq!(unscaled, 100, "1.00 should have unscaled value 100");
        Ok(())
    }
}

// ============================================================================
// Tests for bigdecimal::BigDecimal implementation
// ============================================================================

#[cfg(feature = "bigdecimal")]
mod bigdecimal_tests {
    use super::*;
    use bigdecimal::BigDecimal;
    use std::str::FromStr;

    #[test]
    fn test_bigdecimal_binary_format_zero() -> TestResult {
        let dec = BigDecimal::from_str("0")?;
        let result = serialize_decimal(&dec)?;

        let (scale, unscaled) = parse_binary_decimal(&result);
        assert_eq!(scale, 0, "Zero should have scale 0");
        assert_eq!(unscaled, 0, "Zero should have unscaled value 0");
        Ok(())
    }

    #[test]
    fn test_bigdecimal_binary_format_positive() -> TestResult {
        let dec = BigDecimal::from_str("123.45")?;
        let result = serialize_decimal(&dec)?;

        let (scale, unscaled) = parse_binary_decimal(&result);
        assert_eq!(scale, 2, "123.45 should have scale 2");
        assert_eq!(unscaled, 12345, "123.45 should have unscaled value 12345");
        Ok(())
    }

    #[test]
    fn test_bigdecimal_binary_format_negative() -> TestResult {
        let dec = BigDecimal::from_str("-123.45")?;
        let result = serialize_decimal(&dec)?;

        let (scale, unscaled) = parse_binary_decimal(&result);
        assert_eq!(scale, 2, "-123.45 should have scale 2");
        assert_eq!(
            unscaled, -12345,
            "-123.45 should have unscaled value -12345"
        );
        Ok(())
    }

    #[test]
    fn test_bigdecimal_binary_format_one() -> TestResult {
        let dec = BigDecimal::from_str("1")?;
        let result = serialize_decimal(&dec)?;

        let (scale, unscaled) = parse_binary_decimal(&result);
        assert_eq!(scale, 0, "One should have scale 0");
        assert_eq!(unscaled, 1, "One should have unscaled value 1");
        Ok(())
    }

    #[test]
    fn test_bigdecimal_binary_format_high_precision() -> TestResult {
        // BigDecimal can handle arbitrary precision, test a value with many decimal places
        let dec = BigDecimal::from_str("0.123456789012345678901234567890")?;
        let result = serialize_decimal(&dec)?;

        let (scale, unscaled) = parse_binary_decimal(&result);
        assert_eq!(scale, 30, "Should preserve high precision scale");
        assert_eq!(
            unscaled, 123456789012345678901234567890i128,
            "Should have correct unscaled value"
        );
        Ok(())
    }

    #[test]
    fn test_bigdecimal_binary_format_large_value() -> TestResult {
        // Test a very large value that BigDecimal can represent
        let dec = BigDecimal::from_str("79228162514264337593543950335")?;
        let result = serialize_decimal(&dec)?;

        let (scale, unscaled) = parse_binary_decimal(&result);
        assert_eq!(scale, 0, "Large integer should have scale 0");
        assert_eq!(
            unscaled, 79228162514264337593543950335i128,
            "Should have correct unscaled value"
        );
        Ok(())
    }

    #[test]
    fn test_bigdecimal_binary_format_large_negative() -> TestResult {
        let dec = BigDecimal::from_str("-79228162514264337593543950335")?;
        let result = serialize_decimal(&dec)?;

        let (scale, unscaled) = parse_binary_decimal(&result);
        assert_eq!(scale, 0, "Large negative integer should have scale 0");
        assert_eq!(
            unscaled, -79228162514264337593543950335i128,
            "Should have correct unscaled value"
        );
        Ok(())
    }

    #[test]
    fn test_bigdecimal_binary_format_small_negative() -> TestResult {
        let dec = BigDecimal::from_str("-0.01")?;
        let result = serialize_decimal(&dec)?;

        let (scale, unscaled) = parse_binary_decimal(&result);
        assert_eq!(scale, 2, "-0.01 should have scale 2");
        assert_eq!(unscaled, -1, "-0.01 should have unscaled value -1");
        Ok(())
    }

    #[test]
    fn test_bigdecimal_binary_format_trailing_zeros() -> TestResult {
        let dec = BigDecimal::from_str("1.00")?;
        let result = serialize_decimal(&dec)?;

        let (scale, unscaled) = parse_binary_decimal(&result);
        // BigDecimal may normalize trailing zeros differently than rust_decimal
        assert_eq!(scale, 2, "1.00 should have scale 2");
        assert_eq!(unscaled, 100, "1.00 should have unscaled value 100");
        Ok(())
    }

    #[test]
    fn test_bigdecimal_binary_format_max_scale() -> TestResult {
        // Test with scale at QuestDB's limit of 76
        let dec = BigDecimal::from_str(
            "0.0000000000000000000000000000000000000000000000000000000000000000000000000001",
        )?;
        let result = serialize_decimal(&dec)?;

        let (scale, unscaled) = parse_binary_decimal(&result);
        assert_eq!(scale, 76, "Should have maximum scale of 76");
        assert_eq!(unscaled, 1, "Should have unscaled value 1");
        Ok(())
    }

    #[test]
    fn test_bigdecimal_binary_format_exceeds_max_scale() -> TestResult {
        // Test that exceeding scale 76 returns an error
        let dec = BigDecimal::from_str(
            "0.00000000000000000000000000000000000000000000000000000000000000000000000000001",
        )?;
        let result = serialize_decimal(&dec);
        assert_err_contains(result, ErrorCode::InvalidDecimal, "scale greater than 76");
        Ok(())
    }

    #[test]
    fn test_bigdecimal_binary_negative_scale() -> TestResult {
        // Test with a negative scale
        let dec = BigDecimal::from_str("1.23e12")?;
        let result = serialize_decimal(&dec)?;

        let (scale, unscaled) = parse_binary_decimal(&result);
        // QuestDB does not support negative scale, instead the value should be
        // scaled properly
        assert_eq!(scale, 0, "Should have scale of 0");
        assert_eq!(
            unscaled, 1230000000000,
            "Should have unscaled value 1230000000000"
        );
        Ok(())
    }

    #[test]
    fn test_bigdecimal_binary_value_too_large() -> TestResult {
        // QuestDB cannot accept arrays that are larger than what an i8 can fit
        let dec = BigDecimal::from_str("1e1000")?;
        let result = serialize_decimal(&dec);
        assert_err_contains(
            result,
            ErrorCode::InvalidDecimal,
            "does not support values greater",
        );
        Ok(())
    }
}

// ============================================================================
// Buffer integration tests
// ============================================================================

#[rstest]
fn test_buffer_column_decimal_str(
    #[values(ProtocolVersion::V3)] version: ProtocolVersion,
) -> TestResult {
    let mut buffer = Buffer::new(version);
    buffer
        .table("test")?
        .symbol("sym", "val")?
        .column_dec("dec", "123.45")?
        .at_now()?;

    let output = std::str::from_utf8(buffer.as_bytes())?;
    assert!(output.starts_with("test,sym=val dec=123.45d"));
    Ok(())
}

#[rstest]
fn test_buffer_column_decimal_str_unsupported(
    #[values(ProtocolVersion::V1, ProtocolVersion::V2)] version: ProtocolVersion,
) -> TestResult {
    let mut buffer = Buffer::new(version);
    let result = buffer
        .table("test")?
        .symbol("sym", "val")?
        .column_dec("dec", "123.45");
    assert_err_contains(
        result,
        ErrorCode::ProtocolVersionError,
        "does not support the decimal datatype",
    );
    Ok(())
}

#[cfg(feature = "rust_decimal")]
#[test]
fn test_buffer_column_decimal_rust_decimal() -> TestResult {
    use rust_decimal::Decimal;
    use std::str::FromStr;

    let mut buffer = Buffer::new(ProtocolVersion::V3);
    let dec = Decimal::from_str("123.45")?;
    buffer
        .table("test")?
        .symbol("sym", "val")?
        .column_dec("dec", &dec)?
        .at_now()?;

    let bytes = buffer.as_bytes();
    // Should start with table name and symbol
    assert!(bytes.starts_with(b"test,sym=val dec="));
    assert!(bytes.ends_with(b"\n"));

    // Skip the prefix and \n suffix
    let dec_binary = &bytes[17..bytes.len() - 1];
    let (scale, unscaled) = parse_binary_decimal(dec_binary);
    assert_eq!(scale, 2, "123.45 should have scale 2");
    assert_eq!(unscaled, 12345, "123.45 should have unscaled value 12345");
    Ok(())
}

#[test]
fn test_buffer_multiple_decimals() -> TestResult {
    let mut buffer = Buffer::new(ProtocolVersion::V3);
    buffer
        .table("test")?
        .column_dec("dec1", "123.45")?
        .column_dec("dec2", "-67.89")?
        .column_dec("dec3", "0.001")?
        .at_now()?;

    let output = std::str::from_utf8(buffer.as_bytes())?;
    assert!(output.contains("dec1=123.45d"));
    assert!(output.contains("dec2=-67.89d"));
    assert!(output.contains("dec3=0.001d"));
    Ok(())
}

#[test]
fn test_decimal_column_name_too_long() -> TestResult {
    let mut buffer = Buffer::with_max_name_len(ProtocolVersion::V3, 4);
    let name = "a name too long";
    let err = buffer.table("tbl")?.column_dec(name, "123.45").unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidName);
    assert_eq!(
        err.msg(),
        r#"Bad name: "a name too long": Too long (max 4 characters)"#
    );
    Ok(())
}

#[cfg(feature = "bigdecimal")]
#[test]
fn test_buffer_column_decimal_bigdecimal() -> TestResult {
    use bigdecimal::BigDecimal;
    use std::str::FromStr;

    let mut buffer = Buffer::new(ProtocolVersion::V3);
    let dec = BigDecimal::from_str("123.45")?;
    buffer
        .table("test")?
        .symbol("sym", "val")?
        .column_dec("dec", &dec)?
        .at_now()?;

    let bytes = buffer.as_bytes();
    // Should start with table name and symbol
    assert!(bytes.starts_with(b"test,sym=val dec="));
    assert!(bytes.ends_with(b"\n"));

    // Skip the prefix and \n suffix
    let dec_binary = &bytes[17..bytes.len() - 1];
    let (scale, unscaled) = parse_binary_decimal(dec_binary);
    assert_eq!(scale, 2, "123.45 should have scale 2");
    assert_eq!(unscaled, 12345, "123.45 should have unscaled value 12345");
    Ok(())
}
