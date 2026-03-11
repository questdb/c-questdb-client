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

use std::f64::consts::PI;

use crate::ingress::{Buffer, DecimalView, ProtocolVersion, TimestampMicros};
use crate::tests::TestResult;
use rstest::rstest;

// ============================================================================
// Buffer Option (_opt) integration tests
// ============================================================================

#[rstest]
fn test_buffer_opt_some_matches_standard(
    // We use V3 because it supports all datatypes, including arrays and decimals
    #[values(ProtocolVersion::V3)] version: ProtocolVersion,
) -> TestResult {
    let mut opt_buf = Buffer::new(version);

    // Shared data
    let arr = vec![1.0f64, 2.0, 3.0];
    // We MUST use a hardcoded timestamp, otherwise `.now()` might differ
    // by a microsecond between the two buffer initializations, failing the test!
    let ts = TimestampMicros::new(1659548204354448);

    // 1. Build a buffer using ONLY our new `_opt` methods
    opt_buf
        .table("test")?
        .symbol_opt("sym", Some("val"))?
        .column_bool_opt("c_bool", Some(true))?
        .column_i64_opt("c_i64", Some(42))?
        .column_f64_opt("c_f64", Some(PI))?
        .column_str_opt("c_str", Some("text"))?
        .column_dec_opt("c_dec", Some(DecimalView::try_new_string("123.45")?))?
        .column_arr_opt("c_arr", Some(&arr))?
        .column_ts_opt("c_ts", Some(ts))?
        .at_now()?;

    // 2. Build a buffer using ONLY the standard methods
    let mut std_buf = Buffer::new(version);
    std_buf
        .table("test")?
        .symbol("sym", "val")?
        .column_bool("c_bool", true)?
        .column_i64("c_i64", 42)?
        .column_f64("c_f64", PI)?
        .column_str("c_str", "text")?
        .column_dec("c_dec", DecimalView::try_new_string("123.45")?)?
        .column_arr("c_arr", &arr)?
        .column_ts("c_ts", ts)?
        .at_now()?;

    // 3. The raw binary output should be byte-for-byte identical.
    // This perfectly tests strings, numbers, AND the complex V3 binary array/decimal formats.
    assert_eq!(opt_buf.as_bytes(), std_buf.as_bytes());

    Ok(())
}

#[rstest]
fn test_buffer_opt_none_skips_columns(
    #[values(ProtocolVersion::V3)] version: ProtocolVersion,
) -> TestResult {
    let mut buffer = Buffer::new(version);

    // Explicitly typed None values to satisfy the compiler
    let no_sym: Option<&str> = None;
    let no_bool: Option<bool> = None;
    let no_i64: Option<i64> = None;
    let no_f64: Option<f64> = None;
    let no_str: Option<&str> = None;
    let no_dec: Option<DecimalView> = None;
    let no_arr: Option<&Vec<f64>> = None; // Uses Vec to satisfy Sized bounds
    let no_ts: Option<TimestampMicros> = None;

    buffer
        .table("test")?
        .symbol_opt("sym", no_sym)?
        .column_bool_opt("c_bool", no_bool)?
        .column_i64_opt("c_i64", no_i64)?
        .column_f64_opt("c_f64", no_f64)?
        .column_str_opt("c_str", no_str)?
        .column_dec_opt("c_dec", no_dec)?
        .column_arr_opt("c_arr", no_arr)?
        .column_ts_opt("c_ts", no_ts)?
        // We MUST include at least one valid column to form a legal ILP row
        .column_i64("always_there", 100)?
        .at_now()?;

    let output = std::str::from_utf8(buffer.as_bytes())?;

    // Prove that NONE of the skipped columns appear in the final ILP string.
    // Note the space after "test": In ILP, if there are no symbols, the separator
    // between the table name and the first column is a space, not a comma.
    assert_eq!(output, "test always_there=100i\n");

    Ok(())
}

#[test]
fn test_buffer_opt_array_some_binary_match() -> TestResult {
    let arr = [1.0f64, 2.0, 3.0];

    // Arrays require Protocol V2 or higher
    let mut opt_buf = Buffer::new(ProtocolVersion::V2);
    opt_buf.table("my_test")?;
    opt_buf.column_arr_opt("temperature", Some(&arr))?;

    let mut std_buf = Buffer::new(ProtocolVersion::V2);
    std_buf.table("my_test")?;
    std_buf.column_arr("temperature", &arr)?;

    // We do a raw byte comparison here because Protocol V2 encodes arrays as binary
    assert_eq!(opt_buf.as_bytes(), std_buf.as_bytes());

    Ok(())
}

#[rstest]
fn test_buffer_opt_decimal_some_matches_standard(
    #[values(ProtocolVersion::V3)] version: ProtocolVersion, // Decimals require V3
) -> TestResult {
    let mut opt_buf = Buffer::new(version);
    opt_buf
        .table("test")?
        .column_dec_opt("dec", Some("123.45"))?;

    let mut std_buf = Buffer::new(version);
    std_buf.table("test")?.column_dec("dec", "123.45")?;

    assert_eq!(
        std::str::from_utf8(opt_buf.as_bytes())?,
        std::str::from_utf8(std_buf.as_bytes())?
    );

    Ok(())
}
