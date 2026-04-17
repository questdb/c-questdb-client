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

use crate::ErrorCode;
use crate::ingress::{Buffer, DecimalView, ProtocolVersion, TimestampMicros, TimestampNanos};
#[cfg(feature = "sync-sender-tcp")]
use crate::tests::mock::MockServer;
use crate::tests::qwp_decode::{DecodedValue, decode_datagram};
use crate::tests::{TestResult, assert_err_contains, qwp_mock::QwpUdpMock};

const DECIMAL256_MAX_POS_STR: &str =
    "57896044618658097711785492504343953926634992332820282019728792003956564819967";
const DECIMAL256_MIN_NEG_STR: &str =
    "-57896044618658097711785492504343953926634992332820282019728792003956564819968";
const DECIMAL256_POSITIVE_OVERFLOW_STR: &str =
    "57896044618658097711785492504343953926634992332820282019728792003956564819968";
const DECIMAL256_SIGNED_RESCALE_OVERFLOW_BASE_STR: &str =
    "5789604461865809771178549250434395392663499233282028201972879200395656481997";

fn trim_signed_be(bytes: &[u8]) -> Vec<u8> {
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

fn expected_decimal_bytes(scale: u8, unscaled_be: &[u8]) -> DecodedValue {
    DecodedValue::Decimal {
        scale,
        unscaled_be: trim_signed_be(unscaled_be),
    }
}

fn expected_decimal(scale: u8, unscaled: i128) -> DecodedValue {
    expected_decimal_bytes(scale, &unscaled.to_be_bytes())
}

#[test]
fn qwp_udp_flushes_supported_rows_to_mock_receiver() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let mut sender = mock.sender_builder().build()?;
    let mut buffer = sender.new_buffer();

    buffer
        .table("trades")?
        .symbol("sym", "ETH-USD")?
        .column_bool("active", true)?
        .column_str("venue", "binance")?
        .column_i64("qty", 4)?
        .column_f64("px", 2711.5)?
        .column_ts("event_ts", TimestampMicros::new(123_456))?
        .at(TimestampNanos::new(42))?;
    buffer
        .table("trades")?
        .symbol("sym", "BTC-USD")?
        .column_bool("active", false)?
        .column_f64("px", 1999.0)?
        .at_now()?;
    buffer
        .table("quotes")?
        .symbol("sym", "BTC-USD")?
        .column_bool("open", false)?
        .column_str("src", "feed-a")?
        .column_i64("bid_qty", 7)?
        .at_now()?;

    assert_eq!(buffer.row_count(), 3);
    assert!(!buffer.transactional());

    sender.flush(&mut buffer)?;
    assert!(buffer.is_empty());
    assert_eq!(buffer.row_count(), 0);

    let datagrams = mock.recv_datagrams(2)?;
    let first = decode_datagram(&datagrams[0]).expect("first datagram should decode");
    let second = decode_datagram(&datagrams[1]).expect("second datagram should decode");

    assert_eq!(first.table.name, "trades");
    assert_eq!(first.table.row_count, 2);
    assert_eq!(
        first
            .table
            .columns
            .iter()
            .map(|column| column.name.as_str())
            .collect::<Vec<_>>(),
        vec!["sym", "active", "venue", "qty", "px", "event_ts", ""]
    );
    assert_eq!(
        first.table.rows,
        vec![
            vec![
                DecodedValue::Symbol("ETH-USD".to_owned()),
                DecodedValue::Bool(true),
                DecodedValue::String("binance".to_owned()),
                DecodedValue::I64(4),
                DecodedValue::F64(2711.5),
                DecodedValue::TimestampMicros(123_456),
                DecodedValue::TimestampNanos(42),
            ],
            vec![
                DecodedValue::Symbol("BTC-USD".to_owned()),
                DecodedValue::Bool(false),
                DecodedValue::Null,
                DecodedValue::I64(i64::MIN),
                DecodedValue::F64(1999.0),
                DecodedValue::Null,
                DecodedValue::Null,
            ],
        ]
    );

    assert_eq!(second.table.name, "quotes");
    assert_eq!(second.table.row_count, 1);
    assert_eq!(
        second
            .table
            .columns
            .iter()
            .map(|column| column.name.as_str())
            .collect::<Vec<_>>(),
        vec!["sym", "open", "src", "bid_qty"]
    );
    assert_eq!(
        second.table.rows,
        vec![vec![
            DecodedValue::Symbol("BTC-USD".to_owned()),
            DecodedValue::Bool(false),
            DecodedValue::String("feed-a".to_owned()),
            DecodedValue::I64(7),
        ],]
    );

    Ok(())
}

#[test]
fn qwp_udp_preserves_table_switch_order_for_batched_datagrams() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let mut sender = mock.sender_builder().build()?;
    let mut buffer = sender.new_buffer();

    buffer
        .table("trades")?
        .symbol("sym", "ETH-USD")?
        .column_i64("qty", 1)?
        .at_now()?;
    buffer
        .table("quotes")?
        .symbol("sym", "BTC-USD")?
        .column_i64("qty", 2)?
        .at_now()?;
    buffer
        .table("trades")?
        .symbol("sym", "SOL-USD")?
        .column_i64("qty", 3)?
        .at_now()?;

    sender.flush(&mut buffer)?;
    let datagrams = mock.recv_datagrams(3)?;
    let tables = datagrams
        .iter()
        .map(|bytes| decode_datagram(bytes).unwrap().table.name)
        .collect::<Vec<_>>();
    assert_eq!(tables, vec!["trades", "quotes", "trades"]);

    Ok(())
}

#[test]
fn qwp_udp_splits_batched_rows_when_datagram_size_is_too_small() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let mut sender = mock.sender_builder().max_datagram_size(55)?.build()?;
    let mut buffer = sender.new_buffer();

    buffer
        .table("trades")?
        .symbol("sym", "ETH-USD")?
        .column_i64("qty", 1)?
        .at_now()?;
    buffer
        .table("trades")?
        .symbol("sym", "BTC-USD")?
        .column_i64("qty", 2)?
        .at_now()?;

    sender.flush(&mut buffer)?;
    let datagrams = mock.recv_datagrams(2)?;
    let decoded = datagrams
        .iter()
        .map(|bytes| decode_datagram(bytes).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(decoded[0].table.row_count, 1);
    assert_eq!(decoded[1].table.row_count, 1);
    assert_eq!(
        decoded[0].table.rows[0][0],
        DecodedValue::Symbol("ETH-USD".to_owned())
    );
    assert_eq!(
        decoded[1].table.rows[0][0],
        DecodedValue::Symbol("BTC-USD".to_owned())
    );

    Ok(())
}

#[test]
fn qwp_udp_markers_rewind_rows() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let sender = mock.sender_builder().build()?;
    let mut buffer = sender.new_buffer();

    buffer
        .table("trades")?
        .symbol("sym", "ETH-USD")?
        .column_i64("qty", 1)?
        .at_now()?;
    assert_eq!(buffer.row_count(), 1);
    assert!(!buffer.transactional());

    buffer.set_marker()?;
    buffer
        .table("quotes")?
        .symbol("sym", "BTC-USD")?
        .column_i64("qty", 2)?
        .at_now()?;
    assert_eq!(buffer.row_count(), 2);
    assert!(!buffer.transactional());

    buffer.rewind_to_marker()?;
    assert_eq!(buffer.row_count(), 1);
    assert!(!buffer.transactional());

    buffer
        .table("trades")?
        .symbol("sym", "SOL-USD")?
        .column_i64("qty", 3)?
        .at_now()?;
    assert_eq!(buffer.row_count(), 2);
    assert!(!buffer.transactional());

    Ok(())
}

#[test]
fn qwp_udp_marker_rewind_discards_in_progress_row() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let mut sender = mock.sender_builder().build()?;
    let mut buffer = sender.new_buffer();

    buffer
        .table("trades")?
        .symbol("sym", "ETH-USD")?
        .column_i64("qty", 1)?
        .at_now()?;
    buffer.set_marker()?;

    buffer.table("quotes")?.symbol("sym", "BTC-USD")?;
    buffer.rewind_to_marker()?;

    assert_eq!(buffer.row_count(), 1);
    assert!(!buffer.transactional());

    sender.flush(&mut buffer)?;
    let datagram = mock.recv_datagram()?;
    let decoded = decode_datagram(&datagram).expect("datagram should decode");
    assert_eq!(decoded.table.name, "trades");
    assert_eq!(decoded.table.row_count, 1);

    Ok(())
}

#[test]
fn qwp_udp_bookmarks_rewind_rows() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let sender = mock.sender_builder().build()?;
    let mut buffer = sender.new_buffer();

    buffer
        .table("trades")?
        .symbol("sym", "ETH-USD")?
        .column_i64("qty", 1)?
        .at_now()?;
    assert_eq!(buffer.row_count(), 1);
    assert!(!buffer.transactional());

    let bookmark = buffer.bookmark()?;
    buffer
        .table("quotes")?
        .symbol("sym", "BTC-USD")?
        .column_i64("qty", 2)?
        .at_now()?;
    assert_eq!(buffer.row_count(), 2);
    assert!(!buffer.transactional());

    buffer.rewind_to_bookmark(bookmark)?;
    assert_eq!(buffer.row_count(), 1);
    assert!(!buffer.transactional());

    buffer
        .table("trades")?
        .symbol("sym", "SOL-USD")?
        .column_i64("qty", 3)?
        .at_now()?;
    assert_eq!(buffer.row_count(), 2);
    assert!(!buffer.transactional());

    Ok(())
}

#[test]
fn qwp_udp_bookmark_and_marker_share_one_rewind_point() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let sender = mock.sender_builder().build()?;
    let mut buffer = sender.new_buffer();

    buffer
        .table("trades")?
        .symbol("sym", "ETH-USD")?
        .column_i64("qty", 1)?
        .at_now()?;

    let first = buffer.bookmark()?;
    buffer
        .table("trades")?
        .symbol("sym", "BTC-USD")?
        .column_i64("qty", 2)?
        .at_now()?;
    let second = buffer.bookmark()?;
    buffer
        .table("trades")?
        .symbol("sym", "SOL-USD")?
        .column_i64("qty", 3)?
        .at_now()?;

    let err = buffer.rewind_to_bookmark(first).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidApiCall);
    assert_eq!(
        err.msg(),
        "Can't rewind to the bookmark: Bookmark is stale."
    );

    buffer.rewind_to_bookmark(second)?;
    assert_eq!(buffer.row_count(), 2);

    let third = buffer.bookmark()?;
    buffer
        .table("trades")?
        .symbol("sym", "XRP-USD")?
        .column_i64("qty", 4)?
        .at_now()?;
    buffer.set_marker()?;

    let err = buffer.rewind_to_bookmark(third).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidApiCall);
    assert_eq!(
        err.msg(),
        "Can't rewind to the bookmark: Bookmark is stale."
    );

    buffer
        .table("trades")?
        .symbol("sym", "ADA-USD")?
        .column_i64("qty", 5)?
        .at_now()?;
    buffer.rewind_to_marker()?;
    assert_eq!(buffer.row_count(), 3);

    let fourth = buffer.bookmark()?;
    buffer
        .table("trades")?
        .symbol("sym", "DOT-USD")?
        .column_i64("qty", 6)?
        .at_now()?;
    buffer.clear_marker();
    let err = buffer.rewind_to_bookmark(fourth).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidApiCall);
    assert_eq!(
        err.msg(),
        "Can't rewind to the bookmark: Bookmark is stale."
    );

    Ok(())
}

#[test]
fn qwp_udp_bookmark_rejects_cross_buffer_use_after_clone() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let sender = mock.sender_builder().build()?;
    let mut original = sender.new_buffer();

    original
        .table("trades")?
        .symbol("sym", "ETH-USD")?
        .column_i64("qty", 1)?
        .at_now()?;

    let original_bookmark = original.bookmark()?;
    let mut cloned = original.clone();

    let err = cloned.rewind_to_bookmark(original_bookmark).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidApiCall);
    assert_eq!(
        err.msg(),
        "Can't rewind to the bookmark: Bookmark does not belong to this buffer."
    );

    original
        .table("trades")?
        .symbol("sym", "BTC-USD")?
        .column_i64("qty", 2)?
        .at_now()?;
    original.rewind_to_bookmark(original_bookmark)?;
    assert_eq!(original.row_count(), 1);

    let clone_bookmark = cloned.bookmark()?;
    cloned
        .table("trades")?
        .symbol("sym", "SOL-USD")?
        .column_i64("qty", 3)?
        .at_now()?;
    cloned.rewind_to_bookmark(clone_bookmark)?;
    assert_eq!(cloned.row_count(), 1);

    Ok(())
}

#[test]
fn qwp_udp_clone_preserves_marker_rewind_state() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let sender = mock.sender_builder().build()?;
    let mut original = sender.new_buffer();

    original
        .table("trades")?
        .symbol("sym", "ETH-USD")?
        .column_i64("qty", 1)?
        .at_now()?;
    original.set_marker()?;
    original
        .table("trades")?
        .symbol("sym", "BTC-USD")?
        .column_i64("qty", 2)?
        .at_now()?;

    let mut cloned = original.clone();
    cloned
        .table("trades")?
        .symbol("sym", "SOL-USD")?
        .column_i64("qty", 3)?
        .at_now()?;
    cloned.rewind_to_marker()?;

    assert_eq!(cloned.row_count(), 1);
    assert_eq!(original.row_count(), 2);

    Ok(())
}

#[test]
fn qwp_udp_clear_bookmark_is_idempotent() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let sender = mock.sender_builder().build()?;
    let mut buffer = sender.new_buffer();

    buffer
        .table("trades")?
        .symbol("sym", "ETH-USD")?
        .column_i64("qty", 1)?
        .at_now()?;
    let cleared = buffer.bookmark()?;
    buffer.clear_bookmark(cleared);
    buffer.clear_bookmark(cleared);
    let err = buffer.rewind_to_bookmark(cleared).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidApiCall);
    assert_eq!(
        err.msg(),
        "Can't rewind to the bookmark: Bookmark is stale."
    );

    let rewound = buffer.bookmark()?;
    buffer
        .table("trades")?
        .symbol("sym", "BTC-USD")?
        .column_i64("qty", 2)?
        .at_now()?;
    buffer.rewind_to_bookmark(rewound)?;
    buffer.clear_bookmark(rewound);
    buffer.clear_bookmark(rewound);
    let err = buffer.rewind_to_bookmark(rewound).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidApiCall);
    assert_eq!(
        err.msg(),
        "Can't rewind to the bookmark: Bookmark is stale."
    );

    Ok(())
}

#[test]
fn qwp_udp_rejects_marker_set_mid_row() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let sender = mock.sender_builder().build()?;
    let mut buffer = sender.new_buffer();

    buffer.table("trades")?.symbol("sym", "ETH-USD")?;
    assert_err_contains(
        buffer.set_marker(),
        ErrorCode::InvalidApiCall,
        "Can't set the marker whilst constructing a line.",
    );

    Ok(())
}

#[test]
fn qwp_udp_rejects_bookmark_set_mid_row() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let sender = mock.sender_builder().build()?;
    let mut buffer = sender.new_buffer();

    buffer.table("trades")?.symbol("sym", "ETH-USD")?;
    let err = buffer.bookmark().unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidApiCall);
    assert_eq!(
        err.msg(),
        "Can't set the bookmark whilst constructing a line. A bookmark may only be set on an empty buffer or after `at` or `at_now` is called."
    );

    Ok(())
}

#[test]
fn qwp_udp_successful_flush_invalidates_bookmark() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let mut sender = mock.sender_builder().build()?;
    let mut buffer = sender.new_buffer();

    buffer
        .table("trades")?
        .symbol("sym", "ETH-USD")?
        .column_i64("qty", 1)?
        .at_now()?;
    let bookmark = buffer.bookmark()?;
    buffer
        .table("trades")?
        .symbol("sym", "BTC-USD")?
        .column_i64("qty", 2)?
        .at_now()?;

    sender.flush(&mut buffer)?;
    assert!(buffer.is_empty());

    let err = buffer.rewind_to_bookmark(bookmark).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidApiCall);
    assert_eq!(
        err.msg(),
        "Can't rewind to the bookmark: Bookmark is stale."
    );

    Ok(())
}

#[test]
fn qwp_udp_flush_and_keep_resends_rows() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let mut sender = mock.sender_builder().build()?;
    let mut buffer = sender.new_buffer();

    buffer
        .table("trades")?
        .symbol("sym", "ETH-USD")?
        .column_i64("qty", 4)?
        .at_now()?;

    sender.flush_and_keep(&buffer)?;
    let first = mock.recv_datagram()?;
    assert_eq!(buffer.row_count(), 1);
    assert!(!buffer.is_empty());

    sender.flush(&mut buffer)?;
    let second = mock.recv_datagram()?;
    assert_eq!(first, second);
    assert!(buffer.is_empty());

    Ok(())
}

#[test]
fn qwp_udp_failed_flush_preserves_bookmark() -> TestResult {
    let max = 1024;
    let mock = QwpUdpMock::new()?;
    let mut sender = mock.sender_builder().max_buf_size(max)?.build()?;
    let mut buffer = sender.new_buffer();

    buffer
        .table("trades")?
        .symbol("sym", "ETH-USD")?
        .column_i64("qty", 1)?
        .at_now()?;
    let bookmark = buffer.bookmark()?;

    while buffer.len() < max {
        buffer
            .table("trades")?
            .symbol("sym", "BTC-USD")?
            .column_i64("qty", 2)?
            .at_now()?;
    }

    let err = sender.flush(&mut buffer).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidApiCall);
    assert!(
        err.msg()
            .contains("Could not flush buffer: QWP buffer size hint")
    );

    buffer.rewind_to_bookmark(bookmark)?;
    assert_eq!(buffer.row_count(), 1);
    assert!(!buffer.transactional());

    Ok(())
}

#[cfg(feature = "sync-sender-http")]
#[test]
fn qwp_udp_rejects_transactional_flush_flag() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let mut sender = mock.sender_builder().build()?;
    let mut buffer = sender.new_buffer();

    buffer
        .table("trades")?
        .symbol("sym", "ETH-USD")?
        .column_i64("qty", 4)?
        .at_now()?;

    assert_err_contains(
        sender.flush_and_keep_with_flags(&buffer, true),
        ErrorCode::InvalidApiCall,
        "Transactional flushes are not supported for QWP/UDP.",
    );

    Ok(())
}

#[test]
fn qwp_udp_rejects_duplicate_entry_names_within_row() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let sender = mock.sender_builder().build()?;
    let mut buffer = sender.new_buffer();

    buffer.table("trades")?.symbol("sym", "ETH-USD")?;
    assert_err_contains(
        buffer.column_i64("sym", 4),
        ErrorCode::InvalidApiCall,
        "column 'sym' already set for current row",
    );

    Ok(())
}

#[test]
fn qwp_udp_rejects_ilp_buffer_with_qwp_sender() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let mut sender = mock.sender_builder().build()?;
    let buffer = Buffer::new(crate::ingress::ProtocolVersion::V1);

    assert_err_contains(
        sender.flush_and_keep(&buffer),
        ErrorCode::InvalidApiCall,
        "QWP/UDP sender requires a QWP buffer created by `Sender::new_buffer()`.",
    );

    Ok(())
}

#[test]
fn qwp_udp_rejects_rows_exceeding_datagram_limit() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let mut sender = mock.sender_builder().max_datagram_size(24)?.build()?;
    let mut buffer = sender.new_buffer();

    buffer
        .table("trades")?
        .symbol("sym", "ETH-USD")?
        .column_i64("qty", 4)?
        .at_now()?;

    assert_err_contains(
        sender.flush_and_keep(&buffer),
        ErrorCode::InvalidApiCall,
        "single row exceeds maximum datagram size",
    );

    Ok(())
}

#[test]
fn qwp_udp_respects_max_buf_size_hint_limit() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let max = 1024usize;
    let mut sender = mock.sender_builder().max_buf_size(max)?.build()?;
    let mut buffer = sender.new_buffer();

    while buffer.len() <= max {
        let row = buffer.row_count();
        buffer
            .table("trades")?
            .symbol("sym", format!("ETH-{row}"))?
            .column_i64("qty", row as i64)?
            .column_str("venue", "binance")?
            .at_now()?;
    }

    let size_hint = buffer.len();
    assert!(size_hint > max);

    let err = sender.flush_and_keep(&buffer).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidApiCall);
    assert!(err.msg().contains("QWP buffer size hint"));
    assert_eq!(
        err.msg(),
        format!(
            "Could not flush buffer: QWP buffer size hint of {} exceeds maximum configured allowed size of {} bytes.",
            size_hint, max
        )
    );

    Ok(())
}

#[test]
fn qwp_udp_long_names_do_not_bypass_max_buf_size_hint_limit() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let max = 1400usize;
    let long_name = "c".repeat(u16::MAX as usize + 1);
    let mut sender = mock
        .sender_builder()
        .max_buf_size(max)?
        .max_name_len(long_name.len())?
        .build()?;
    let mut buffer = sender.new_buffer();

    buffer
        .table("trades")?
        .column_i64(long_name.as_str(), 1)?
        .at_now()?;

    assert!(buffer.len() > max);

    let err = sender.flush_and_keep(&buffer).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidApiCall);
    assert!(err.msg().contains("QWP buffer size hint"));

    Ok(())
}

#[test]
fn qwp_udp_encodes_sparse_boolean_columns_as_false_not_null() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let mut sender = mock.sender_builder().build()?;
    let mut buffer = sender.new_buffer();

    buffer.table("trades")?.symbol("sym", "r1")?.at_now()?;
    buffer
        .table("trades")?
        .symbol("sym", "r2")?
        .column_bool("active", true)?
        .at_now()?;
    buffer
        .table("trades")?
        .symbol("sym", "r3")?
        .column_bool("active", false)?
        .at_now()?;

    sender.flush(&mut buffer)?;
    let decoded = decode_datagram(&mock.recv_datagram()?).expect("datagram should decode");
    assert_eq!(decoded.table.name, "trades");
    assert_eq!(
        decoded
            .table
            .columns
            .iter()
            .map(|column| (column.name.as_str(), column.nullable))
            .collect::<Vec<_>>(),
        vec![("sym", true), ("active", false)]
    );
    assert_eq!(
        decoded.table.rows,
        vec![
            vec![
                DecodedValue::Symbol("r1".to_owned()),
                DecodedValue::Bool(false),
            ],
            vec![
                DecodedValue::Symbol("r2".to_owned()),
                DecodedValue::Bool(true),
            ],
            vec![
                DecodedValue::Symbol("r3".to_owned()),
                DecodedValue::Bool(false),
            ],
        ]
    );

    Ok(())
}

#[test]
fn qwp_udp_encodes_sparse_long_and_double_columns_as_non_nullable_sentinels() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let mut sender = mock.sender_builder().build()?;
    let mut buffer = sender.new_buffer();

    buffer.table("trades")?.symbol("sym", "r1")?.at_now()?;
    buffer
        .table("trades")?
        .symbol("sym", "r2")?
        .column_i64("qty", 2)?
        .at_now()?;
    buffer
        .table("trades")?
        .symbol("sym", "r3")?
        .column_f64("px", 33.5)?
        .at_now()?;
    buffer
        .table("trades")?
        .symbol("sym", "r4")?
        .column_i64("qty", 4)?
        .column_f64("px", 44.5)?
        .at_now()?;

    sender.flush(&mut buffer)?;
    let decoded = decode_datagram(&mock.recv_datagram()?).expect("datagram should decode");
    assert_eq!(decoded.table.name, "trades");
    assert_eq!(
        decoded
            .table
            .columns
            .iter()
            .map(|column| (column.name.as_str(), column.nullable))
            .collect::<Vec<_>>(),
        vec![("sym", true), ("qty", false), ("px", false)]
    );
    assert_eq!(
        decoded.table.rows[0][0],
        DecodedValue::Symbol("r1".to_owned())
    );
    assert_eq!(decoded.table.rows[0][1], DecodedValue::I64(i64::MIN));
    match &decoded.table.rows[0][2] {
        DecodedValue::F64(value) => assert!(value.is_nan()),
        other => panic!("expected NaN sentinel for sparse double column, got {other:?}"),
    }
    assert_eq!(
        decoded.table.rows[1][0],
        DecodedValue::Symbol("r2".to_owned())
    );
    assert_eq!(decoded.table.rows[1][1], DecodedValue::I64(2));
    match &decoded.table.rows[1][2] {
        DecodedValue::F64(value) => assert!(value.is_nan()),
        other => panic!("expected NaN sentinel for sparse double column, got {other:?}"),
    }
    assert_eq!(
        decoded.table.rows[2][0],
        DecodedValue::Symbol("r3".to_owned())
    );
    assert_eq!(decoded.table.rows[2][1], DecodedValue::I64(i64::MIN));
    assert_eq!(decoded.table.rows[2][2], DecodedValue::F64(33.5));
    assert_eq!(
        decoded.table.rows[3][0],
        DecodedValue::Symbol("r4".to_owned())
    );
    assert_eq!(decoded.table.rows[3][1], DecodedValue::I64(4));
    assert_eq!(decoded.table.rows[3][2], DecodedValue::F64(44.5));

    Ok(())
}

#[test]
fn qwp_udp_round_trips_user_supplied_special_f64_values() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let mut sender = mock.sender_builder().build()?;
    let mut buffer = sender.new_buffer();

    buffer
        .table("trades")?
        .column_f64("px", f64::NAN)?
        .at_now()?;
    buffer
        .table("trades")?
        .column_f64("px", f64::INFINITY)?
        .at_now()?;
    buffer
        .table("trades")?
        .column_f64("px", f64::NEG_INFINITY)?
        .at_now()?;

    sender.flush(&mut buffer)?;
    let decoded = decode_datagram(&mock.recv_datagram()?).expect("datagram should decode");

    assert_eq!(decoded.table.name, "trades");
    assert_eq!(decoded.table.row_count, 3);
    assert_eq!(
        decoded
            .table
            .columns
            .iter()
            .map(|column| (column.name.as_str(), column.type_code, column.nullable))
            .collect::<Vec<_>>(),
        vec![("px", 0x07, false)]
    );
    match decoded.table.rows[0][0] {
        DecodedValue::F64(value) => assert!(value.is_nan()),
        ref other => panic!("expected user-supplied NaN, got {other:?}"),
    }
    assert_eq!(
        decoded.table.rows[1],
        vec![DecodedValue::F64(f64::INFINITY)]
    );
    assert_eq!(
        decoded.table.rows[2],
        vec![DecodedValue::F64(f64::NEG_INFINITY)]
    );

    Ok(())
}

#[test]
fn qwp_udp_bool_i64_f64_are_never_nullable_with_various_gap_patterns() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let mut sender = mock.sender_builder().build()?;
    let mut buffer = sender.new_buffer();

    // Row 0: only bool
    buffer.table("t")?.column_bool("b", true)?.at_now()?;
    // Row 1: only i64
    buffer.table("t")?.column_i64("n", 42)?.at_now()?;
    // Row 2: only f64
    buffer.table("t")?.column_f64("d", 1.23)?.at_now()?;
    // Row 3: all three present
    buffer
        .table("t")?
        .column_bool("b", false)?
        .column_i64("n", -1)?
        .column_f64("d", 2.72)?
        .at_now()?;

    sender.flush(&mut buffer)?;
    let decoded = decode_datagram(&mock.recv_datagram()?).expect("decode");

    // All three columns must be non-nullable (gap-filled with sentinels).
    for col in &decoded.table.columns {
        match col.name.as_str() {
            "b" | "n" | "d" => assert!(
                !col.nullable,
                "column {:?} must be non-nullable, got nullable",
                col.name
            ),
            _ => {}
        }
    }

    // Row 0: b=true, n=MIN (gap), d=NaN (gap)
    assert_eq!(decoded.table.rows[0][0], DecodedValue::Bool(true));
    assert_eq!(decoded.table.rows[0][1], DecodedValue::I64(i64::MIN));
    match &decoded.table.rows[0][2] {
        DecodedValue::F64(v) => assert!(v.is_nan(), "expected NaN gap-fill"),
        other => panic!("expected F64, got {other:?}"),
    }

    // Row 1: b=false (gap), n=42, d=NaN (gap)
    assert_eq!(decoded.table.rows[1][0], DecodedValue::Bool(false));
    assert_eq!(decoded.table.rows[1][1], DecodedValue::I64(42));
    match &decoded.table.rows[1][2] {
        DecodedValue::F64(v) => assert!(v.is_nan(), "expected NaN gap-fill"),
        other => panic!("expected F64, got {other:?}"),
    }

    // Row 2: b=false (gap), n=MIN (gap), d=1.23
    assert_eq!(decoded.table.rows[2][0], DecodedValue::Bool(false));
    assert_eq!(decoded.table.rows[2][1], DecodedValue::I64(i64::MIN));
    assert_eq!(decoded.table.rows[2][2], DecodedValue::F64(1.23));

    // Row 3: b=false, n=-1, d=2.72
    assert_eq!(decoded.table.rows[3][0], DecodedValue::Bool(false));
    assert_eq!(decoded.table.rows[3][1], DecodedValue::I64(-1));
    assert_eq!(decoded.table.rows[3][2], DecodedValue::F64(2.72));

    Ok(())
}

#[test]
fn qwp_udp_dense_bool_i64_f64_columns_encode_all_values() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let mut sender = mock.sender_builder().build()?;
    let mut buffer = sender.new_buffer();

    // All rows have all three columns — no gaps at all.
    for i in 0..5 {
        buffer
            .table("t")?
            .column_bool("flag", i % 2 == 0)?
            .column_i64("count", i)?
            .column_f64("price", i as f64 * 1.5)?
            .at_now()?;
    }

    sender.flush(&mut buffer)?;
    let decoded = decode_datagram(&mock.recv_datagram()?).expect("decode");

    for col in &decoded.table.columns {
        assert!(
            !col.nullable,
            "dense column {:?} must be non-nullable",
            col.name
        );
    }

    for i in 0..5i64 {
        let row = &decoded.table.rows[i as usize];
        assert_eq!(row[0], DecodedValue::Bool(i % 2 == 0));
        assert_eq!(row[1], DecodedValue::I64(i));
        assert_eq!(row[2], DecodedValue::F64(i as f64 * 1.5));
    }

    Ok(())
}

#[test]
fn qwp_udp_encodes_sparse_timestamp_columns_as_nullable_nulls() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let mut sender = mock.sender_builder().build()?;
    let mut buffer = sender.new_buffer();

    buffer.table("trades")?.symbol("sym", "r1")?.at_now()?;
    buffer
        .table("trades")?
        .symbol("sym", "r2")?
        .column_ts("event_ts", TimestampMicros::new(123_456))?
        .at_now()?;
    buffer.table("trades")?.symbol("sym", "r3")?.at_now()?;

    sender.flush(&mut buffer)?;
    let decoded = decode_datagram(&mock.recv_datagram()?).expect("datagram should decode");
    assert_eq!(decoded.table.name, "trades");
    assert_eq!(
        decoded
            .table
            .columns
            .iter()
            .map(|column| (column.name.as_str(), column.nullable))
            .collect::<Vec<_>>(),
        vec![("sym", true), ("event_ts", true)]
    );
    assert_eq!(
        decoded.table.rows,
        vec![
            vec![DecodedValue::Symbol("r1".to_owned()), DecodedValue::Null,],
            vec![
                DecodedValue::Symbol("r2".to_owned()),
                DecodedValue::TimestampMicros(123_456),
            ],
            vec![DecodedValue::Symbol("r3".to_owned()), DecodedValue::Null,],
        ]
    );

    Ok(())
}

#[test]
fn qwp_udp_encodes_sparse_symbol_columns_as_nullable_nulls() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let mut sender = mock.sender_builder().build()?;
    let mut buffer = sender.new_buffer();

    buffer
        .table("trades")?
        .symbol("sym", "r1")?
        .symbol("venue", "A")?
        .at_now()?;
    buffer.table("trades")?.symbol("sym", "r2")?.at_now()?;
    buffer
        .table("trades")?
        .symbol("sym", "r3")?
        .symbol("venue", "B")?
        .at_now()?;

    sender.flush(&mut buffer)?;
    let decoded = decode_datagram(&mock.recv_datagram()?).expect("datagram should decode");
    assert_eq!(decoded.table.name, "trades");
    assert_eq!(
        decoded
            .table
            .columns
            .iter()
            .map(|column| (column.name.as_str(), column.nullable))
            .collect::<Vec<_>>(),
        vec![("sym", true), ("venue", true)]
    );
    assert_eq!(
        decoded.table.rows,
        vec![
            vec![
                DecodedValue::Symbol("r1".to_owned()),
                DecodedValue::Symbol("A".to_owned()),
            ],
            vec![DecodedValue::Symbol("r2".to_owned()), DecodedValue::Null],
            vec![
                DecodedValue::Symbol("r3".to_owned()),
                DecodedValue::Symbol("B".to_owned()),
            ],
        ]
    );

    Ok(())
}

#[test]
fn qwp_udp_encodes_sparse_string_columns_as_nullable_nulls() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let mut sender = mock.sender_builder().build()?;
    let mut buffer = sender.new_buffer();

    buffer
        .table("trades")?
        .column_i64("seq", 1)?
        .column_str("note", "alpha")?
        .at_now()?;
    buffer.table("trades")?.column_i64("seq", 2)?.at_now()?;
    buffer
        .table("trades")?
        .column_i64("seq", 3)?
        .column_str("note", "beta")?
        .at_now()?;

    sender.flush(&mut buffer)?;
    let decoded = decode_datagram(&mock.recv_datagram()?).expect("datagram should decode");
    assert_eq!(decoded.table.name, "trades");
    assert_eq!(
        decoded
            .table
            .columns
            .iter()
            .map(|column| (column.name.as_str(), column.nullable))
            .collect::<Vec<_>>(),
        vec![("seq", false), ("note", true)]
    );
    assert_eq!(
        decoded.table.rows,
        vec![
            vec![
                DecodedValue::I64(1),
                DecodedValue::String("alpha".to_owned())
            ],
            vec![DecodedValue::I64(2), DecodedValue::Null],
            vec![
                DecodedValue::I64(3),
                DecodedValue::String("beta".to_owned())
            ],
        ]
    );

    Ok(())
}

#[test]
fn qwp_udp_round_trips_empty_and_utf8_strings() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let mut sender = mock.sender_builder().build()?;
    let mut buffer = sender.new_buffer();

    buffer
        .table("trades")?
        .column_i64("seq", 1)?
        .column_str("note", "")?
        .at_now()?;
    buffer
        .table("trades")?
        .column_i64("seq", 2)?
        .column_str("note", "naive cafe")?
        .at_now()?;
    buffer
        .table("trades")?
        .column_i64("seq", 3)?
        .column_str("note", "hello 🌍 東京")?
        .at_now()?;

    sender.flush(&mut buffer)?;
    let decoded = decode_datagram(&mock.recv_datagram()?).expect("datagram should decode");
    assert_eq!(decoded.table.name, "trades");
    assert_eq!(
        decoded.table.rows,
        vec![
            vec![DecodedValue::I64(1), DecodedValue::String("".to_owned())],
            vec![
                DecodedValue::I64(2),
                DecodedValue::String("naive cafe".to_owned()),
            ],
            vec![
                DecodedValue::I64(3),
                DecodedValue::String("hello 🌍 東京".to_owned()),
            ],
        ]
    );

    Ok(())
}

#[test]
fn qwp_udp_round_trips_empty_and_utf8_symbols() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let mut sender = mock.sender_builder().build()?;
    let mut buffer = sender.new_buffer();

    buffer
        .table("trades")?
        .symbol("label", "")?
        .column_i64("seq", 1)?
        .at_now()?;
    buffer
        .table("trades")?
        .symbol("label", "münchen")?
        .column_i64("seq", 2)?
        .at_now()?;
    buffer
        .table("trades")?
        .symbol("label", "🚀 東京")?
        .column_i64("seq", 3)?
        .at_now()?;

    sender.flush(&mut buffer)?;
    let decoded = decode_datagram(&mock.recv_datagram()?).expect("datagram should decode");
    assert_eq!(decoded.table.name, "trades");
    assert_eq!(
        decoded.table.rows,
        vec![
            vec![DecodedValue::Symbol("".to_owned()), DecodedValue::I64(1)],
            vec![
                DecodedValue::Symbol("münchen".to_owned()),
                DecodedValue::I64(2),
            ],
            vec![
                DecodedValue::Symbol("🚀 東京".to_owned()),
                DecodedValue::I64(3),
            ],
        ]
    );

    Ok(())
}

#[test]
fn qwp_udp_rejects_mixed_designated_timestamp_precisions_within_table_batch() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let sender = mock.sender_builder().build()?;
    let mut buffer = sender.new_buffer();

    buffer
        .table("trades")?
        .symbol("sym", "ETH-USD")?
        .column_i64("qty", 1)?
        .at(TimestampMicros::new(123_456))?;
    let size_hint = buffer.len();
    assert!(size_hint > 0);

    buffer
        .table("trades")?
        .symbol("sym", "BTC-USD")?
        .column_i64("qty", 2)?;

    assert_err_contains(
        buffer.at(TimestampNanos::new(789_000)),
        ErrorCode::InvalidApiCall,
        "QWP/UDP designated timestamp changes type within a batched table",
    );
    assert_eq!(buffer.row_count(), 1);
    assert_eq!(buffer.len(), size_hint);

    Ok(())
}

#[test]
fn qwp_udp_recovers_after_failed_designated_timestamp_commit() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let mut sender = mock.sender_builder().build()?;
    let mut buffer = sender.new_buffer();
    let mut expected = sender.new_buffer();

    buffer
        .table("trades")?
        .symbol("sym", "ETH-USD")?
        .column_i64("qty", 1)?
        .at(TimestampMicros::new(123_456))?;
    expected
        .table("trades")?
        .symbol("sym", "ETH-USD")?
        .column_i64("qty", 1)?
        .at(TimestampMicros::new(123_456))?;
    let size_hint = buffer.len();

    buffer
        .table("trades")?
        .symbol("sym", "BTC-USD")?
        .column_i64("qty", 2)?;
    assert_err_contains(
        buffer.at(TimestampNanos::new(789_000)),
        ErrorCode::InvalidApiCall,
        "QWP/UDP designated timestamp changes type within a batched table",
    );

    assert_eq!(buffer.row_count(), 1);
    assert_eq!(buffer.len(), size_hint);

    buffer
        .table("trades")?
        .symbol("sym", "SOL-USD")?
        .column_i64("qty", 3)?
        .at(TimestampMicros::new(999_000))?;
    expected
        .table("trades")?
        .symbol("sym", "SOL-USD")?
        .column_i64("qty", 3)?
        .at(TimestampMicros::new(999_000))?;

    assert_eq!(buffer.len(), expected.len());

    sender.flush(&mut buffer)?;
    let decoded = decode_datagram(&mock.recv_datagram()?).expect("datagram should decode");
    assert_eq!(decoded.table.name, "trades");
    assert_eq!(decoded.table.row_count, 2);
    assert_eq!(
        decoded.table.rows,
        vec![
            vec![
                DecodedValue::Symbol("ETH-USD".to_owned()),
                DecodedValue::I64(1),
                DecodedValue::TimestampMicros(123_456),
            ],
            vec![
                DecodedValue::Symbol("SOL-USD".to_owned()),
                DecodedValue::I64(3),
                DecodedValue::TimestampMicros(999_000),
            ],
        ]
    );

    Ok(())
}

#[test]
fn qwp_udp_rejects_mixed_timestamp_column_precisions_within_table_batch() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let sender = mock.sender_builder().build()?;
    let mut buffer = sender.new_buffer();

    buffer
        .table("trades")?
        .symbol("sym", "ETH-USD")?
        .column_ts("event_ts", TimestampMicros::new(123_456))?
        .at_now()?;
    let size_hint = buffer.len();
    assert!(size_hint > 0);

    buffer
        .table("trades")?
        .symbol("sym", "BTC-USD")?
        .column_ts("event_ts", TimestampNanos::new(789_000))?;

    assert_err_contains(
        buffer.at_now(),
        ErrorCode::InvalidApiCall,
        r#"QWP/UDP column "event_ts" changes type within a batched table"#,
    );
    assert_eq!(buffer.row_count(), 1);
    assert_eq!(buffer.len(), size_hint);

    Ok(())
}

#[test]
fn qwp_udp_round_trips_timestamp_nanos_columns() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let mut sender = mock.sender_builder().build()?;
    let mut buffer = sender.new_buffer();

    buffer
        .table("trades")?
        .symbol("sym", "ETH-USD")?
        .column_ts("event_ts", TimestampNanos::new(789_000))?
        .at_now()?;

    sender.flush(&mut buffer)?;

    let decoded = decode_datagram(&mock.recv_datagram()?).expect("datagram should decode");
    assert_eq!(decoded.table.name, "trades");
    assert_eq!(decoded.table.row_count, 1);
    assert_eq!(
        decoded
            .table
            .columns
            .iter()
            .map(|column| column.name.as_str())
            .collect::<Vec<_>>(),
        vec!["sym", "event_ts"]
    );
    assert_eq!(
        decoded.table.rows,
        vec![vec![
            DecodedValue::Symbol("ETH-USD".to_owned()),
            DecodedValue::TimestampNanos(789_000),
        ]]
    );

    Ok(())
}

#[test]
fn qwp_udp_round_trips_decimal_columns() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let mut sender = mock.sender_builder().build()?;
    let mut buffer = sender.new_buffer();

    let neg_345 = DecimalView::try_new_scaled(2, &[0xFE, 0xA7][..])?;

    buffer
        .table("trades")?
        .column_dec("price", "1.2")?
        .at_now()?;
    buffer
        .table("trades")?
        .column_dec("price", "NaN")?
        .at_now()?;
    buffer
        .table("trades")?
        .column_dec("price", neg_345)?
        .at_now()?;
    buffer
        .table("trades")?
        .column_dec("price", "1.5e-3")?
        .at_now()?;

    sender.flush(&mut buffer)?;
    let decoded = decode_datagram(&mock.recv_datagram()?).expect("datagram should decode");

    assert_eq!(decoded.table.name, "trades");
    assert_eq!(decoded.table.row_count, 4);
    assert_eq!(
        decoded
            .table
            .columns
            .iter()
            .map(|column| (column.name.as_str(), column.type_code, column.nullable))
            .collect::<Vec<_>>(),
        vec![("price", 0x15, true)]
    );
    assert_eq!(
        decoded.table.rows,
        vec![
            vec![expected_decimal(4, 12_000)],
            vec![DecodedValue::Null],
            vec![expected_decimal(4, -34_500)],
            vec![expected_decimal(4, 15)],
        ]
    );

    Ok(())
}

#[test]
fn qwp_udp_decimal_infinities_are_encoded_as_nulls() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let mut sender = mock.sender_builder().build()?;
    let mut buffer = sender.new_buffer();

    buffer
        .table("trades")?
        .column_dec("price", "Infinity")?
        .at_now()?;
    buffer
        .table("trades")?
        .column_dec("price", "-Infinity")?
        .at_now()?;

    sender.flush(&mut buffer)?;
    let decoded = decode_datagram(&mock.recv_datagram()?).expect("datagram should decode");

    assert_eq!(decoded.table.name, "trades");
    assert_eq!(decoded.table.row_count, 2);
    assert_eq!(
        decoded
            .table
            .columns
            .iter()
            .map(|column| (column.name.as_str(), column.type_code, column.nullable))
            .collect::<Vec<_>>(),
        vec![("price", 0x15, true)]
    );
    assert_eq!(
        decoded.table.rows,
        vec![vec![DecodedValue::Null], vec![DecodedValue::Null]]
    );

    Ok(())
}

#[test]
fn qwp_udp_round_trips_zero_decimal_with_large_positive_exponent() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let mut sender = mock.sender_builder().build()?;
    let mut buffer = sender.new_buffer();

    buffer
        .table("trades")?
        .column_dec("price", "0e999999999")?
        .at_now()?;

    sender.flush(&mut buffer)?;
    let decoded = decode_datagram(&mock.recv_datagram()?).expect("datagram should decode");

    assert_eq!(decoded.table.name, "trades");
    assert_eq!(decoded.table.row_count, 1);
    assert_eq!(decoded.table.rows, vec![vec![expected_decimal(0, 0)]]);

    Ok(())
}

#[test]
fn qwp_udp_round_trips_decimal256_signed_boundaries() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let mut sender = mock.sender_builder().build()?;
    let mut buffer = sender.new_buffer();

    buffer
        .table("trades")?
        .column_dec("price", DECIMAL256_MAX_POS_STR)?
        .at_now()?;
    buffer
        .table("trades")?
        .column_dec("price", DECIMAL256_MIN_NEG_STR)?
        .at_now()?;

    sender.flush(&mut buffer)?;
    let decoded = decode_datagram(&mock.recv_datagram()?).expect("datagram should decode");

    let mut max_positive = vec![0x7f];
    max_positive.extend([0xff; 31]);
    let mut min_negative = vec![0x80];
    min_negative.extend([0x00; 31]);

    assert_eq!(decoded.table.name, "trades");
    assert_eq!(decoded.table.row_count, 2);
    assert_eq!(
        decoded.table.rows,
        vec![
            vec![expected_decimal_bytes(0, &max_positive)],
            vec![expected_decimal_bytes(0, &min_negative)],
        ]
    );

    Ok(())
}

#[test]
fn qwp_udp_round_trips_negative_zero_decimal_as_zero() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let mut sender = mock.sender_builder().build()?;
    let mut buffer = sender.new_buffer();

    buffer
        .table("trades")?
        .column_dec("price", "-0.0")?
        .at_now()?;

    sender.flush(&mut buffer)?;
    let decoded = decode_datagram(&mock.recv_datagram()?).expect("datagram should decode");

    assert_eq!(decoded.table.row_count, 1);
    assert_eq!(decoded.table.rows, vec![vec![expected_decimal(1, 0)]]);

    Ok(())
}

#[test]
fn qwp_udp_rejects_positive_decimal_above_signed_256_limit() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let mut sender = mock.sender_builder().build()?;
    let mut buffer = sender.new_buffer();

    buffer
        .table("trades")?
        .column_dec("price", DECIMAL256_POSITIVE_OVERFLOW_STR)?
        .at_now()?;

    assert_err_contains(
        sender.flush(&mut buffer),
        ErrorCode::InvalidDecimal,
        "signed DECIMAL256 range",
    );
    assert_eq!(buffer.row_count(), 1);

    Ok(())
}

#[test]
fn qwp_udp_rejects_signed_decimal_overflow_after_scale_unification() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let mut sender = mock.sender_builder().build()?;
    let mut buffer = sender.new_buffer();

    buffer
        .table("trades")?
        .column_dec("price", DECIMAL256_SIGNED_RESCALE_OVERFLOW_BASE_STR)?
        .at_now()?;
    buffer
        .table("trades")?
        .column_dec("price", "0.1")?
        .at_now()?;

    assert_err_contains(
        sender.flush(&mut buffer),
        ErrorCode::InvalidDecimal,
        "signed DECIMAL256 range",
    );
    assert_eq!(buffer.row_count(), 2);

    Ok(())
}

#[test]
fn qwp_udp_marker_rewind_restores_decimal_scale() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let mut sender = mock.sender_builder().build()?;
    let mut buffer = sender.new_buffer();

    buffer
        .table("trades")?
        .column_dec("price", "1.2")?
        .at_now()?;
    buffer.set_marker()?;
    buffer
        .table("trades")?
        .column_dec("price", "1.5e-3")?
        .at_now()?;

    buffer.rewind_to_marker()?;
    sender.flush(&mut buffer)?;
    let decoded = decode_datagram(&mock.recv_datagram()?).expect("datagram should decode");

    assert_eq!(decoded.table.row_count, 1);
    assert_eq!(decoded.table.rows, vec![vec![expected_decimal(1, 12)]]);

    Ok(())
}

#[test]
fn qwp_udp_rejects_scaled_decimal_with_scale_above_limit() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let sender = mock.sender_builder().build()?;
    let mut buffer = sender.new_buffer();

    buffer.table("trades")?;
    assert_err_contains(
        buffer.column_dec(
            "price",
            DecimalView::Scaled {
                scale: 255,
                value: vec![1].into(),
            },
        ),
        ErrorCode::InvalidDecimal,
        "scale cannot exceed 76",
    );

    Ok(())
}

#[test]
fn qwp_udp_rejects_invalid_decimal_text() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let sender = mock.sender_builder().build()?;
    let mut buffer = sender.new_buffer();

    buffer.table("trades")?;
    assert_err_contains(
        buffer.column_dec("price", "1.2.3"),
        ErrorCode::InvalidDecimal,
        "invalid decimal",
    );

    Ok(())
}

#[test]
fn qwp_udp_rejects_decimal_text_edge_cases() -> TestResult {
    for (value, expected_msg) in [
        ("", "empty decimal value"),
        ("+", "missing decimal digits"),
        ("-", "missing decimal digits"),
    ] {
        let mock = QwpUdpMock::new()?;
        let sender = mock.sender_builder().build()?;
        let mut buffer = sender.new_buffer();
        buffer.table("trades")?;

        assert_err_contains(
            buffer.column_dec("price", value),
            ErrorCode::InvalidDecimal,
            expected_msg,
        );
    }

    Ok(())
}

#[test]
fn qwp_udp_flush_empty_buffer_is_noop() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let mut sender = mock.sender_builder().build()?;
    let mut buffer = sender.new_buffer();

    // Flushing an empty buffer should be a no-op, not an error.
    sender.flush(&mut buffer)?;
    mock.assert_no_datagram()?;

    Ok(())
}

#[test]
fn qwp_buffer_check_can_flush_tracks_public_state_machine() -> TestResult {
    let mut buffer = Buffer::new_qwp();

    // Flush is allowed on an empty buffer (no-op).
    buffer.check_can_flush().unwrap();

    buffer.table("trades")?;
    let err = buffer.check_can_flush().unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidApiCall);
    assert_eq!(
        err.msg(),
        "State error: Bad call to `flush`, should have called `symbol` or `column` instead."
    );

    buffer.symbol("sym", "ETH-USD")?;
    let err = buffer.check_can_flush().unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidApiCall);
    assert_eq!(
        err.msg(),
        "State error: Bad call to `flush`, should have called `symbol`, `column` or `at` instead."
    );

    buffer.column_i64("qty", 4)?;
    let err = buffer.check_can_flush().unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidApiCall);
    assert_eq!(
        err.msg(),
        "State error: Bad call to `flush`, should have called `column` or `at` instead."
    );

    buffer.at_now()?;
    buffer.check_can_flush()?;

    Ok(())
}

#[test]
fn qwp_udp_rejects_flushing_incomplete_row() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let mut sender = mock.sender_builder().build()?;
    let mut buffer = sender.new_buffer();

    buffer.table("trades")?.symbol("sym", "ETH-USD")?;
    assert_err_contains(
        sender.flush(&mut buffer),
        ErrorCode::InvalidApiCall,
        "State error: Bad call to `flush`",
    );

    Ok(())
}

#[test]
fn qwp_udp_round_trips_f64_array_columns() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let mut sender = mock.sender_builder().build()?;
    let mut buffer = sender.new_buffer();
    let contiguous = [1.0f64, 2.0, 3.0];
    let empty: [f64; 0] = [];
    let non_contiguous = vec![vec![4.0f64, 5.0], vec![6.0, 7.0]];

    buffer
        .table("trades")?
        .column_i64("seq", 1)?
        .column_arr("samples", &contiguous)?
        .at_now()?;
    buffer.table("trades")?.column_i64("seq", 2)?.at_now()?;
    buffer
        .table("trades")?
        .column_i64("seq", 3)?
        .column_arr("samples", &non_contiguous)?
        .at_now()?;
    buffer
        .table("trades")?
        .column_i64("seq", 4)?
        .column_arr("samples", &empty)?
        .at_now()?;

    sender.flush(&mut buffer)?;
    let decoded = decode_datagram(&mock.recv_datagram()?).expect("datagram should decode");
    assert_eq!(decoded.table.name, "trades");
    assert_eq!(
        decoded
            .table
            .columns
            .iter()
            .map(|column| (column.name.as_str(), column.type_code, column.nullable))
            .collect::<Vec<_>>(),
        vec![("seq", 0x05, false), ("samples", 0x11, true)]
    );
    assert_eq!(
        decoded.table.rows,
        vec![
            vec![
                DecodedValue::I64(1),
                DecodedValue::F64Array {
                    shape: vec![3],
                    values: vec![1.0, 2.0, 3.0],
                },
            ],
            vec![DecodedValue::I64(2), DecodedValue::Null],
            vec![
                DecodedValue::I64(3),
                DecodedValue::F64Array {
                    shape: vec![2, 2],
                    values: vec![4.0, 5.0, 6.0, 7.0],
                },
            ],
            vec![
                DecodedValue::I64(4),
                DecodedValue::F64Array {
                    shape: vec![0],
                    values: vec![],
                },
            ],
        ]
    );

    Ok(())
}

#[cfg(feature = "sync-sender-tcp")]
#[test]
fn ilp_sender_rejects_qwp_buffer() -> TestResult {
    let mut server = MockServer::new()?;
    let mut sender = server.lsb_tcp().build()?;
    server.accept()?;

    let buffer = Buffer::new_qwp();
    assert_err_contains(
        sender.flush_and_keep(&buffer),
        ErrorCode::InvalidApiCall,
        "ILP sender requires an ILP buffer. QWP buffers must be flushed with a QWP/UDP sender.",
    );

    Ok(())
}

#[test]
fn qwp_udp_clear_then_reuse_flushes_only_new_rows() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let mut sender = mock.sender_builder().build()?;
    let mut buffer = sender.new_buffer();

    buffer
        .table("stale_rows")?
        .symbol("sym", "drop-me")?
        .column_i64("qty", 1)?
        .at_now()?;
    buffer.clear();
    assert!(buffer.is_empty());

    buffer
        .table("fresh_rows")?
        .symbol("sym", "keep-me")?
        .column_i64("qty", 2)?
        .at_now()?;

    sender.flush(&mut buffer)?;
    let decoded = decode_datagram(&mock.recv_datagram()?).expect("datagram should decode");
    assert_eq!(decoded.table.name, "fresh_rows");
    assert_eq!(decoded.table.row_count, 1);
    assert_eq!(
        decoded.table.rows,
        vec![vec![
            DecodedValue::Symbol("keep-me".to_owned()),
            DecodedValue::I64(2),
        ]]
    );

    Ok(())
}

#[test]
fn qwp_udp_allows_micros_and_nanos_designated_timestamps_in_separate_batches() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let mut sender = mock.sender_builder().build()?;
    let mut buffer = sender.new_buffer();

    buffer
        .table("trades")?
        .symbol("sym", "micros-row")?
        .column_i64("qty", 1)?
        .at(TimestampMicros::new(123_456))?;
    sender.flush(&mut buffer)?;

    buffer
        .table("trades")?
        .symbol("sym", "nanos-row")?
        .column_i64("qty", 2)?
        .at(TimestampNanos::new(789_000))?;
    sender.flush(&mut buffer)?;

    let micros = decode_datagram(&mock.recv_datagram()?).expect("micros datagram should decode");
    let nanos = decode_datagram(&mock.recv_datagram()?).expect("nanos datagram should decode");

    assert_eq!(
        micros.table.rows,
        vec![vec![
            DecodedValue::Symbol("micros-row".to_owned()),
            DecodedValue::I64(1),
            DecodedValue::TimestampMicros(123_456),
        ]]
    );
    assert_eq!(
        nanos.table.rows,
        vec![vec![
            DecodedValue::Symbol("nanos-row".to_owned()),
            DecodedValue::I64(2),
            DecodedValue::TimestampNanos(789_000),
        ]]
    );

    Ok(())
}

#[test]
fn qwp_udp_allows_mixed_at_and_at_now_within_same_table_batch() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let mut sender = mock.sender_builder().build()?;
    let mut buffer = sender.new_buffer();

    buffer
        .table("trades")?
        .symbol("sym", "explicit-a")?
        .column_i64("qty", 1)?
        .at(TimestampMicros::new(123_456))?;
    buffer
        .table("trades")?
        .symbol("sym", "server-now")?
        .column_i64("qty", 2)?
        .at_now()?;
    buffer
        .table("trades")?
        .symbol("sym", "explicit-b")?
        .column_i64("qty", 3)?
        .at(TimestampMicros::new(789_000))?;

    sender.flush(&mut buffer)?;
    let decoded = decode_datagram(&mock.recv_datagram()?).expect("datagram should decode");
    assert_eq!(decoded.table.name, "trades");
    assert_eq!(decoded.table.row_count, 3);
    assert_eq!(
        decoded.table.rows,
        vec![
            vec![
                DecodedValue::Symbol("explicit-a".to_owned()),
                DecodedValue::I64(1),
                DecodedValue::TimestampMicros(123_456),
            ],
            vec![
                DecodedValue::Symbol("server-now".to_owned()),
                DecodedValue::I64(2),
                DecodedValue::Null,
            ],
            vec![
                DecodedValue::Symbol("explicit-b".to_owned()),
                DecodedValue::I64(3),
                DecodedValue::TimestampMicros(789_000),
            ],
        ]
    );

    Ok(())
}

#[test]
fn qwp_udp_clone_produces_identical_datagrams() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let mut sender = mock.sender_builder().build()?;
    let mut buffer = sender.new_buffer();

    buffer
        .table("trades")?
        .symbol("sym", "ETH-USD")?
        .column_i64("qty", 4)?
        .column_str("venue", "binance")?
        .at(TimestampMicros::new(123_456))?;

    let cloned = buffer.clone();
    sender.flush_and_keep(&buffer)?;
    sender.flush_and_keep(&cloned)?;

    let first = mock.recv_datagram()?;
    let second = mock.recv_datagram()?;
    assert_eq!(first, second);

    Ok(())
}

#[test]
fn qwp_buffer_reports_protocol_version_v1() {
    let buffer = Buffer::new_qwp();
    assert_eq!(buffer.protocol_version(), ProtocolVersion::V1);
}

#[test]
fn qwp_udp_sparse_micros_and_nanos_timestamps_in_same_batch() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let mut sender = mock.sender_builder().build()?;
    let mut buffer = sender.new_buffer();

    buffer
        .table("t")?
        .column_ts("ts_us", TimestampMicros::new(100))?
        .at_now()?;
    buffer
        .table("t")?
        .column_ts("ts_ns", TimestampNanos::new(200))?
        .at_now()?;
    buffer
        .table("t")?
        .column_ts("ts_us", TimestampMicros::new(300))?
        .column_ts("ts_ns", TimestampNanos::new(400))?
        .at_now()?;

    sender.flush(&mut buffer)?;
    let decoded = decode_datagram(&mock.recv_datagram()?).expect("decode");

    // Both timestamp columns must be nullable (they have gaps).
    assert_eq!(
        decoded
            .table
            .columns
            .iter()
            .map(|c| (c.name.as_str(), c.nullable))
            .collect::<Vec<_>>(),
        vec![("ts_us", true), ("ts_ns", true)]
    );

    // Row 0: ts_us=100, ts_ns=null
    assert_eq!(
        decoded.table.rows[0],
        vec![DecodedValue::TimestampMicros(100), DecodedValue::Null]
    );
    // Row 1: ts_us=null, ts_ns=200
    assert_eq!(
        decoded.table.rows[1],
        vec![DecodedValue::Null, DecodedValue::TimestampNanos(200)]
    );
    // Row 2: ts_us=300, ts_ns=400
    assert_eq!(
        decoded.table.rows[2],
        vec![
            DecodedValue::TimestampMicros(300),
            DecodedValue::TimestampNanos(400)
        ]
    );

    Ok(())
}

#[test]
fn qwp_buffer_rejects_name_exceeding_max_name_len() -> TestResult {
    let mut buffer = Buffer::qwp_with_max_name_len(10);

    let long_name = "x".repeat(11);
    let ok_name = "a".repeat(10);
    let long_col = "y".repeat(11);
    let ok_col = "b".repeat(10);

    // Table name too long.
    assert_err_contains(
        buffer.table(long_name.as_str()),
        ErrorCode::InvalidName,
        "Too long",
    );

    // Table name within limit works.
    buffer.table(ok_name.as_str())?;

    // Column name too long.
    assert_err_contains(
        buffer.column_i64(long_col.as_str(), 1),
        ErrorCode::InvalidName,
        "Too long",
    );

    // Column name within limit works.
    buffer.column_i64(ok_col.as_str(), 1)?;
    buffer.at_now()?;

    Ok(())
}

#[test]
fn qwp_buffer_rejects_bad_character_column_name() -> TestResult {
    let mut buffer = Buffer::new_qwp();

    buffer.table("trades")?;
    assert_err_contains(
        buffer.column_i64("bad?name", 1),
        ErrorCode::InvalidName,
        "can't contain",
    );

    Ok(())
}

#[test]
fn qwp_buffer_rejects_negative_designated_timestamp() -> TestResult {
    let mut buffer = Buffer::new_qwp();

    buffer.table("t")?.column_i64("x", 1)?;
    assert_err_contains(
        buffer.at(TimestampNanos::new(-1)),
        ErrorCode::InvalidTimestamp,
        "negative",
    );

    // Buffer should still be usable after the error.
    buffer.at(TimestampNanos::new(42))?;
    assert_eq!(buffer.row_count(), 1);

    Ok(())
}

#[test]
fn qwp_buffer_rejects_flush_with_incomplete_row() -> TestResult {
    let mut buffer = Buffer::new_qwp();

    buffer.table("t")?.column_i64("x", 1)?;
    // Row not completed (no at/at_now call).
    assert_err_contains(
        buffer.check_can_flush(),
        ErrorCode::InvalidApiCall,
        "should have called `column` or `at` instead",
    );

    // Complete the row — flush should now be allowed.
    buffer.at_now()?;
    buffer.check_can_flush()?;

    Ok(())
}

#[test]
fn qwp_buffer_rejects_at_without_columns() -> TestResult {
    let mut buffer = Buffer::new_qwp();

    buffer.table("t")?;
    assert_err_contains(
        buffer.at_now(),
        ErrorCode::InvalidApiCall,
        "should have called `symbol` or `column` instead",
    );

    Ok(())
}
