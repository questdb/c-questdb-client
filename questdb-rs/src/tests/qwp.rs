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
use crate::ingress::{Buffer, ProtocolVersion, TimestampMicros, TimestampNanos};
#[cfg(feature = "sync-sender-tcp")]
use crate::tests::mock::MockServer;
use crate::tests::qwp_decode::{DecodedValue, decode_datagram};
use crate::tests::{TestResult, assert_err_contains, qwp_mock::QwpUdpMock};

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
fn qwp_udp_markers_rewind_rows_and_transactional_state() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let sender = mock.sender_builder().build()?;
    let mut buffer = sender.new_buffer();

    buffer
        .table("trades")?
        .symbol("sym", "ETH-USD")?
        .column_i64("qty", 1)?
        .at_now()?;
    assert_eq!(buffer.row_count(), 1);
    assert!(buffer.transactional());

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
    assert!(buffer.transactional());

    buffer
        .table("trades")?
        .symbol("sym", "SOL-USD")?
        .column_i64("qty", 3)?
        .at_now()?;
    assert_eq!(buffer.row_count(), 2);
    assert!(buffer.transactional());

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
    assert!(buffer.transactional());

    sender.flush(&mut buffer)?;
    let datagram = mock.recv_datagram()?;
    let decoded = decode_datagram(&datagram).expect("datagram should decode");
    assert_eq!(decoded.table.name, "trades");
    assert_eq!(decoded.table.row_count, 1);

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
fn qwp_udp_rejects_not_yet_supported_column_types() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let sender = mock.sender_builder().build()?;
    let mut buffer = sender.new_buffer();

    buffer.table("trades")?;
    buffer.column_bool("active", true)?;
    buffer.column_str("venue", "binance")?;
    buffer.column_ts("event_ts", TimestampMicros::new(55))?;
    assert_err_contains(
        buffer.column_dec("price_dec", "12.34"),
        ErrorCode::InvalidApiCall,
        "QWP/UDP support for `column_dec` is not implemented yet.",
    );

    Ok(())
}

#[test]
fn qwp_udp_rejects_flushing_empty_buffer() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let mut sender = mock.sender_builder().build()?;
    let mut buffer = sender.new_buffer();

    assert_err_contains(
        sender.flush(&mut buffer),
        ErrorCode::InvalidApiCall,
        "State error: Bad call to `flush`",
    );

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
fn qwp_udp_rejects_column_arr() -> TestResult {
    let mock = QwpUdpMock::new()?;
    let sender = mock.sender_builder().build()?;
    let mut buffer = sender.new_buffer();

    buffer.table("trades")?;
    assert_err_contains(
        buffer.column_arr("samples", &[1.0f64, 2.0, 3.0]),
        ErrorCode::InvalidApiCall,
        "QWP/UDP support for `column_arr` is not implemented yet.",
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
