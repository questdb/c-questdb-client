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

//! `Sender::flush` of a row buffer that does not fit one frame.
//!
//! Such a buffer goes out in several frames that the server commits together
//! when all of this holds: the sender makes its progress in the background
//! and keeps its queue in memory, the server has told its frame limit, the
//! buffer is within `max_buf_size` and holds no column the planner cannot
//! size, and the queue has room for all the frames. The buffer may hold rows
//! of several tables: the server commits each of them once.
//! Any other flush goes out as one frame, as before: a buffer that is too
//! large for one frame is refused, nothing of it is published and it keeps
//! its rows.
//!
//! The server is the model of [`crate::tests::qwp_ws_server_model`] behind a
//! socket: it holds the rows of a frame with the defer flag and commits at
//! every frame without it, so the number of its commits tells how the frames
//! of a flush were flagged.

use std::time::Duration;

use crate::ErrorCode;
use crate::ingress::{AckLevel, Buffer, Sender, SenderBuilder, TimestampMicros, TimestampNanos};
use crate::tests::qwp_ws::spawn_max_batch_size_upgrade_only_server;
use crate::tests::qwp_ws_server_model::{
    QwpWsModelServer, add_rows, buffer_of, frames_of_a_flush, rows_of,
};

const TABLE: &str = "flush_rows";
/// The tables of a flush over several tables, in the order of its buffer.
const FIRST: &str = "first_rows";
const SECOND: &str = "second_rows";
const THIRD: &str = "third_rows";
/// The frame limit the server tells, where a test names no other.
const FRAME_LIMIT: usize = 1024;
const WAIT: Duration = Duration::from_secs(10);
/// What the refusal of a frame says of a cap that is the server's frame limit.
const SET_BY_SERVER: &str = "the server's advertised X-QWP-Max-Batch-Size";
/// The same for a cap that is what a segment of the queue holds.
const SET_BY_SEGMENT: &str = "the sf_max_segment_bytes segment payload capacity";

fn sender_with(port: u16, settings: &str) -> Sender {
    SenderBuilder::from_conf(format!("ws::addr=127.0.0.1:{port};{settings}"))
        .unwrap()
        .build()
        .unwrap()
}

fn add_row(buffer: &mut Buffer, id: i64, txt: &str) {
    buffer
        .table(TABLE)
        .unwrap()
        .column_i64("id", id)
        .unwrap()
        .column_str("txt", txt)
        .unwrap()
        .at(TimestampNanos::new(1_700_000_000_000_000_000 + id))
        .unwrap();
}

/// Rows like those of [`buffer_of`], from `first_id` on, in a buffer whose
/// `len()` is exactly `len`: the text of the last row is as long as it takes.
fn buffer_of_len(first_id: i64, len: usize) -> Buffer {
    let mut buffer = Buffer::new_qwp_ws();
    let mut id = first_id;
    while buffer.len() + 64 < len {
        add_row(&mut buffer, id, &format!("row {id}"));
        id += 1;
    }
    let mut with_empty_text = buffer.clone();
    add_row(&mut with_empty_text, id, "");
    // A byte of text is a byte of the buffer.
    add_row(&mut buffer, id, &" ".repeat(len - with_empty_text.len()));
    assert_eq!(buffer.len(), len);
    buffer
}

fn rows_of_all(buffers: &[&Buffer]) -> Vec<String> {
    buffers
        .iter()
        .flat_map(|buffer| rows_of(TABLE, buffer))
        .collect()
}

/// Rows of three tables: 700 of the first, 5 of the second and 1,000 of the
/// third, each with an id of its own from `first_id` on. Cut for frames of
/// [`FRAME_LIMIT`] bytes, the second table lies whole in one frame, between
/// the last rows of the first table and the first rows of the third.
fn buffer_of_three_tables(first_id: i64) -> Buffer {
    let mut buffer = buffer_of(FIRST, first_id..first_id + 700);
    add_rows(&mut buffer, SECOND, first_id + 700..first_id + 705);
    add_rows(&mut buffer, THIRD, first_id + 705..first_id + 1705);
    buffer
}

/// Adds row `id` of a table that has a column of every kind but a symbol.
/// Each column but `id` is left out of some rows, some decimal values are
/// explicit nulls, and every seventh row has no designated timestamp.
fn add_row_of_every_kind(buffer: &mut Buffer, table: &str, id: i64) {
    let decimal_or_null = |value: String| {
        if id % 5 == 0 { "NaN".to_owned() } else { value }
    };
    buffer.table(table).unwrap().column_i64("id", id).unwrap();
    if id % 4 != 1 {
        buffer.column_bool("flag", id % 3 == 0).unwrap();
        buffer.column_i8("i8", id as i8).unwrap();
        buffer.column_i16("i16", (id * 301) as i16).unwrap();
    }
    if id % 5 != 2 {
        buffer.column_i32("i32", (id * 70_001) as i32).unwrap();
        buffer.column_f32("f32", id as f32 + 0.25).unwrap();
        buffer.column_f64("f64", id as f64 + 0.5).unwrap();
    }
    if id % 3 != 1 {
        buffer.column_str("str", format!("row {id}")).unwrap();
        buffer
            .column_binary("bin", &[id as u8; 3][..(id % 4) as usize])
            .unwrap();
    }
    if id % 4 != 2 {
        buffer
            .column_dec("dec", decimal_or_null(format!("{id}.25")).as_str())
            .unwrap();
        buffer
            .column_dec64("dec64", decimal_or_null(format!("-{id}.5")).as_str())
            .unwrap();
    }
    buffer
        .column_dec128("dec128", format!("{id}.125").as_str())
        .unwrap();
    if id % 5 != 4 {
        buffer.column_uuid("uuid", id as u64, 7).unwrap();
        buffer.column_long256("l256", &[id as u8; 32]).unwrap();
    }
    if id % 3 != 0 {
        let ip = std::net::Ipv4Addr::from(0x0a00_0000 + id as u32);
        buffer.column_ipv4("ip", ip).unwrap();
        buffer.column_date("day", 86_400_000 * id).unwrap();
        buffer
            .column_char("ch", b'a' as u16 + (id % 26) as u16)
            .unwrap();
    }
    if id % 4 != 0 {
        buffer.column_geohash("geo", id as u64, 20).unwrap();
        buffer
            .column_arr("doubles", &vec![0.5_f64, id as f64])
            .unwrap();
    }
    buffer
        .column_geohash("geo16", 0xffff - id as u64, 16)
        .unwrap();
    if id % 5 != 1 {
        buffer
            .column_arr("longs", &vec![id; (id % 3) as usize + 1])
            .unwrap();
        buffer
            .column_ts("micros", TimestampMicros::new(id))
            .unwrap();
    }
    if id % 2 == 1 {
        buffer
            .column_ts("nanos", TimestampNanos::new(id * 1_000))
            .unwrap();
    }
    if id % 7 == 3 {
        buffer.at_now().unwrap();
    } else {
        buffer
            .at(TimestampNanos::new(1_700_000_000_000_000_000 + id))
            .unwrap();
    }
}

/// Rows `ids` of a table with one DECIMAL64 column, whose first value has
/// one digit after the point. So has every other value but that of row
/// `two_digits`, which has two: a value the encoder refuses.
fn buffer_of_decimals(ids: std::ops::Range<i64>, two_digits: Option<i64>) -> Buffer {
    let mut buffer = Buffer::new_qwp_ws();
    for id in ids {
        let price = if Some(id) == two_digits {
            format!("{id}.25")
        } else {
            format!("{id}.5")
        };
        buffer
            .table(TABLE)
            .unwrap()
            .column_i64("id", id)
            .unwrap()
            .column_dec64("price", price.as_str())
            .unwrap()
            .at(TimestampNanos::new(1_700_000_000_000_000_000 + id))
            .unwrap();
    }
    buffer
}

/// How many table blocks each frame of `frames` holds.
fn blocks_per_frame(frames: &[Vec<u8>]) -> Vec<u16> {
    frames
        .iter()
        .map(|frame| u16::from_le_bytes([frame[6], frame[7]]))
        .collect()
}

/// Checks what the server holds of `table`: the number of its commits, and
/// the rows that `buffers` hold of it, in their order.
fn assert_table_holds(server: &QwpWsModelServer, table: &str, commits: u64, buffers: &[&Buffer]) {
    let held = server.model.table(table).unwrap();
    assert_eq!(held.commits, commits, "commits of {table}");
    let rows: Vec<String> = buffers
        .iter()
        .flat_map(|buffer| rows_of(table, buffer))
        .collect();
    assert_eq!(held.rows_as_text(), rows, "rows of {table}");
}

/// Flushes a buffer that is too large for one frame and that is not sent in
/// frames either. The refusal is the one such a buffer got before: it names
/// the frame cap and what sets it, nothing is published, the buffer keeps
/// its rows and the sender stays usable.
fn assert_refused_as_one_frame(sender: &mut Sender, buffer: &mut Buffer, cap: usize, set_by: &str) {
    let published = sender.published_fsn().unwrap();
    let (rows, len) = (buffer.row_count(), buffer.len());

    let err = sender.flush(buffer).unwrap_err();
    assert_eq!(err.code(), ErrorCode::BatchTooLarge, "{}", err.msg());
    let end =
        format!(" bytes exceeds the per-frame cap of {cap} bytes. The cap is set by {set_by}.");
    assert!(
        err.msg()
            .starts_with("Could not flush buffer: QWP/WebSocket encoded message size of ")
            && err.msg().ends_with(&end),
        "got: {}",
        err.msg()
    );
    assert_eq!(
        sender.published_fsn().unwrap(),
        published,
        "nothing is published"
    );
    assert_eq!(
        (buffer.row_count(), buffer.len()),
        (rows, len),
        "the buffer keeps its rows"
    );
    assert!(!sender.must_close());
}

#[test]
fn a_flush_above_the_frame_cap_is_one_commit() {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let mut sender = sender_with(server.port, "");
    assert_eq!(sender.effective_frame_cap().unwrap(), (FRAME_LIMIT, true));
    let before = buffer_of(TABLE, 0..3);
    let large = buffer_of(TABLE, 3..2003);
    let after = buffer_of(TABLE, 2003..2006);
    let frame_count = frames_of_a_flush(&large, FRAME_LIMIT).len() as u64;
    assert!(frame_count > 40, "{frame_count} frames");

    assert_eq!(sender.flush_and_keep_and_get_fsn(&before).unwrap(), Some(0));
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_eq!(server.model.table(TABLE).unwrap().commits, 1);

    // Frame 0 is the flush before: the frames of this one are 1 to
    // `frame_count`.
    let mut flushed = large.clone();
    assert_eq!(
        sender.flush_and_get_fsn(&mut flushed).unwrap(),
        Some(frame_count)
    );
    assert!(flushed.is_empty());
    assert_eq!(sender.published_fsn().unwrap(), Some(frame_count));
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_eq!(
        sender.completed_fsn(AckLevel::Ok).unwrap(),
        Some(frame_count)
    );
    let table = server.model.table(TABLE).unwrap();
    assert_eq!(table.commits, 2, "the frames of the flush are one commit");
    assert_eq!(table.blocks.len() as u64, 1 + frame_count);

    assert_eq!(
        sender.flush_and_keep_and_get_fsn(&after).unwrap(),
        Some(frame_count + 1)
    );
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    let table = server.model.table(TABLE).unwrap();
    assert_eq!(table.commits, 3);
    assert_eq!(
        table.rows_as_text(),
        rows_of_all(&[&before, &large, &after])
    );
    assert!(!sender.must_close());
    drop(sender);
    server.finish();
}

#[test]
fn a_flush_that_loses_its_connection_part_way_is_sent_again_whole() {
    // The server takes the flush before and five frames of the large flush,
    // and ends the connection.
    const CUT_AFTER_FRAMES: usize = 6;
    let server = QwpWsModelServer::start_cutting_first_connection(FRAME_LIMIT, CUT_AFTER_FRAMES);
    let mut sender = sender_with(server.port, "");
    let before = buffer_of(TABLE, 0..3);
    let large = buffer_of(TABLE, 3..2003);
    let frame_count = frames_of_a_flush(&large, FRAME_LIMIT).len() as u64;
    assert!(frame_count > 40, "{frame_count} frames");

    // Confirmed while the first connection lives, so it is not sent again.
    assert_eq!(sender.flush_and_keep_and_get_fsn(&before).unwrap(), Some(0));
    sender.wait(AckLevel::Ok, WAIT).unwrap();

    assert_eq!(
        sender.flush_and_keep_and_get_fsn(&large).unwrap(),
        Some(frame_count)
    );
    sender.wait(AckLevel::Ok, WAIT).unwrap();

    let totals = sender.qwp_ws_totals().unwrap();
    assert_eq!(totals.reconnects_succeeded, 1);
    assert!(
        totals.frames_replayed >= CUT_AFTER_FRAMES as u64 - 1,
        "{} frames sent again",
        totals.frames_replayed
    );
    // The rows that the first connection held are gone with it. The second
    // one brought every frame of the flush, and committed them once.
    let table = server.model.table(TABLE).unwrap();
    assert_eq!(table.commits, 2);
    assert_eq!(table.blocks.len() as u64, 1 + frame_count);
    assert_eq!(table.rows_as_text(), rows_of_all(&[&before, &large]));
    assert!(!sender.must_close());
    drop(sender);
    server.finish();
}

#[test]
fn a_flush_of_several_tables_above_the_frame_cap_is_one_commit_of_each_table() {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let mut sender = sender_with(server.port, "");
    // A flush of one frame that holds the first and the third table.
    let mut before = buffer_of(FIRST, 0..3);
    add_rows(&mut before, THIRD, 3..6);
    let large = buffer_of_three_tables(10);
    // A flush of one frame that holds the second table alone.
    let after = buffer_of(SECOND, 5000..5003);

    let blocks = blocks_per_frame(&frames_of_a_flush(&large, FRAME_LIMIT));
    let frame_count = blocks.len() as u64;
    assert!(frame_count > 40, "{frame_count} frames");
    // One frame holds rows of all three tables, and the last frame holds
    // rows of the third table alone: it commits the other two as well.
    assert_eq!(blocks.iter().filter(|blocks| **blocks == 3).count(), 1);
    assert_eq!(
        blocks.iter().filter(|blocks| **blocks == 1).count(),
        blocks.len() - 1
    );
    assert_eq!(blocks.last(), Some(&1));

    assert_eq!(sender.flush_and_keep_and_get_fsn(&before).unwrap(), Some(0));
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_table_holds(&server, FIRST, 1, &[&before]);
    assert_table_holds(&server, THIRD, 1, &[&before]);
    assert!(server.model.table(SECOND).is_none());

    // Frame 0 is the flush before: the frames of this one are 1 to
    // `frame_count`.
    let mut flushed = large.clone();
    assert_eq!(
        sender.flush_and_get_fsn(&mut flushed).unwrap(),
        Some(frame_count)
    );
    assert!(flushed.is_empty());
    assert_eq!(sender.published_fsn().unwrap(), Some(frame_count));
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_eq!(
        sender.completed_fsn(AckLevel::Ok).unwrap(),
        Some(frame_count)
    );
    assert_table_holds(&server, FIRST, 2, &[&before, &large]);
    assert_table_holds(&server, SECOND, 1, &[&large]);
    assert_table_holds(&server, THIRD, 2, &[&before, &large]);
    // The server holds the two blocks of the flush before, and the blocks
    // of every frame of this one.
    let block_count = |table| server.model.table(table).unwrap().blocks.len();
    let blocks_of_the_flush: usize = blocks.iter().map(|blocks| usize::from(*blocks)).sum();
    assert_eq!(
        block_count(FIRST) + block_count(SECOND) + block_count(THIRD),
        2 + blocks_of_the_flush
    );

    assert_eq!(
        sender.flush_and_keep_and_get_fsn(&after).unwrap(),
        Some(frame_count + 1)
    );
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_table_holds(&server, FIRST, 2, &[&before, &large]);
    assert_table_holds(&server, SECOND, 2, &[&large, &after]);
    assert_table_holds(&server, THIRD, 2, &[&before, &large]);
    assert!(!sender.must_close());
    drop(sender);
    server.finish();
}

#[test]
fn a_flush_of_several_tables_that_loses_its_connection_part_way_is_sent_again_whole() {
    let before = buffer_of(FIRST, 0..3);
    let large = buffer_of_three_tables(10);
    let blocks = blocks_per_frame(&frames_of_a_flush(&large, FRAME_LIMIT));
    let frame_count = blocks.len() as u64;
    // The server takes the flush before and the frames of the large flush
    // up to the third one that holds rows of the third table alone, and ends
    // the connection. It then holds rows of all three tables.
    let frame_of_three_tables = blocks.iter().position(|blocks| *blocks == 3).unwrap();
    let cut_after_frames = 1 + frame_of_three_tables + 1 + 3;
    assert!((cut_after_frames as u64) < frame_count);
    let server = QwpWsModelServer::start_cutting_first_connection(FRAME_LIMIT, cut_after_frames);
    let mut sender = sender_with(server.port, "");

    // Confirmed while the first connection lives, so it is not sent again.
    assert_eq!(sender.flush_and_keep_and_get_fsn(&before).unwrap(), Some(0));
    sender.wait(AckLevel::Ok, WAIT).unwrap();

    assert_eq!(
        sender.flush_and_keep_and_get_fsn(&large).unwrap(),
        Some(frame_count)
    );
    sender.wait(AckLevel::Ok, WAIT).unwrap();

    let totals = sender.qwp_ws_totals().unwrap();
    assert_eq!(totals.reconnects_succeeded, 1);
    assert!(
        totals.frames_replayed >= cut_after_frames as u64 - 1,
        "{} frames sent again",
        totals.frames_replayed
    );
    // The rows that the first connection held are gone with it, of every
    // table. The second one brought every frame of the flush, and committed
    // each table once.
    assert_table_holds(&server, FIRST, 2, &[&before, &large]);
    assert_table_holds(&server, SECOND, 1, &[&large]);
    assert_table_holds(&server, THIRD, 1, &[&large]);
    assert!(!sender.must_close());
    drop(sender);
    server.finish();
}

#[test]
fn a_flush_with_a_column_of_every_kind_above_the_frame_cap_is_one_commit() {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let mut sender = sender_with(server.port, "");
    let row_of_every_kind = |ids: std::ops::Range<i64>| {
        let mut buffer = Buffer::new_qwp_ws();
        for id in ids {
            add_row_of_every_kind(&mut buffer, TABLE, id);
        }
        buffer
    };
    let before = row_of_every_kind(0..3);
    let large = row_of_every_kind(3..303);
    let after = row_of_every_kind(303..306);
    assert!(before.len() < FRAME_LIMIT && after.len() < FRAME_LIMIT);
    let frames = frames_of_a_flush(&large, FRAME_LIMIT);
    let frame_count = frames.len() as u64;
    assert!(frame_count > 40, "{frame_count} frames");
    // The decimal columns hold nulls, so the frames are cut by a size that
    // is above what they take: none is above the frame limit.
    assert!(frames.iter().all(|frame| frame.len() <= FRAME_LIMIT));

    assert_eq!(sender.flush_and_keep_and_get_fsn(&before).unwrap(), Some(0));
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_table_holds(&server, TABLE, 1, &[&before]);

    let mut flushed = large.clone();
    assert_eq!(
        sender.flush_and_get_fsn(&mut flushed).unwrap(),
        Some(frame_count)
    );
    assert!(flushed.is_empty());
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_eq!(
        sender.completed_fsn(AckLevel::Ok).unwrap(),
        Some(frame_count)
    );
    let table = server.model.table(TABLE).unwrap();
    assert_eq!(table.blocks.len() as u64, 1 + frame_count);
    assert_table_holds(&server, TABLE, 2, &[&before, &large]);

    assert_eq!(
        sender.flush_and_keep_and_get_fsn(&after).unwrap(),
        Some(frame_count + 1)
    );
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_table_holds(&server, TABLE, 3, &[&before, &large, &after]);
    assert!(!sender.must_close());
    drop(sender);
    server.finish();
}

#[test]
fn a_buffer_with_a_decimal_that_cannot_be_written_is_refused_before_its_first_frame() {
    const TWO_DIGITS: &str = "cannot rescale decimal from scale 2 to 1 without precision loss";
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let mut sender = sender_with(server.port, "");
    let before = buffer_of(FIRST, 0..3);
    assert_eq!(sender.flush_and_keep_and_get_fsn(&before).unwrap(), Some(0));
    sender.wait(AckLevel::Ok, WAIT).unwrap();

    // The value is far behind the first frame of the flush, and in a buffer
    // of one frame: both are refused in the same way, and nothing is sent.
    let good = buffer_of_decimals(0..2000, None);
    let frame_count = frames_of_a_flush(&good, FRAME_LIMIT).len() as u64;
    assert!(frame_count > 40, "{frame_count} frames");
    for mut refused in [
        buffer_of_decimals(0..2000, Some(1500)),
        buffer_of_decimals(0..20, Some(15)),
    ] {
        let (rows, len) = (refused.row_count(), refused.len());
        assert_eq!(len > FRAME_LIMIT, rows == 2000);
        let err = sender.flush(&mut refused).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall, "{}", err.msg());
        assert_eq!(err.msg(), TWO_DIGITS);
        assert_eq!(sender.published_fsn().unwrap(), Some(0));
        assert_eq!((refused.row_count(), refused.len()), (rows, len));
        assert!(!sender.must_close());
    }

    // The sender goes on: the same rows without that value are one commit.
    assert_eq!(
        sender.flush_and_keep_and_get_fsn(&good).unwrap(),
        Some(frame_count)
    );
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_table_holds(&server, TABLE, 1, &[&good]);
    assert_eq!(
        server.model.table(TABLE).unwrap().blocks.len() as u64,
        frame_count
    );
    assert_table_holds(&server, FIRST, 1, &[&before]);
    drop(sender);
    server.finish();
}

#[test]
fn a_sender_in_manual_progress_mode_refuses_a_buffer_above_the_frame_cap() {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let mut sender = sender_with(server.port, "qwp_ws_progress=manual;");
    assert_eq!(sender.effective_frame_cap().unwrap(), (FRAME_LIMIT, true));
    let mut large = buffer_of(TABLE, 0..2000);

    assert_refused_as_one_frame(&mut sender, &mut large, FRAME_LIMIT, SET_BY_SERVER);
    drop(sender);
    server.finish();
}

#[test]
fn a_sender_with_sf_dir_refuses_a_buffer_above_the_frame_cap() {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let sf_dir = tempfile::TempDir::new().unwrap();
    let settings = format!(
        "sf_dir={};sender_id=large;sf_max_segment_bytes=65536;",
        sf_dir.path().display()
    );
    let mut sender = sender_with(server.port, &settings);
    assert_eq!(sender.effective_frame_cap().unwrap(), (FRAME_LIMIT, true));
    let mut large = buffer_of(TABLE, 0..2000);

    assert_refused_as_one_frame(&mut sender, &mut large, FRAME_LIMIT, SET_BY_SERVER);
    drop(sender);
    server.finish();
}

#[test]
fn a_sender_whose_server_tells_no_frame_limit_refuses_a_buffer_above_the_frame_cap() {
    let port = spawn_max_batch_size_upgrade_only_server(None);
    // The cap is then what a segment of the queue holds: its 4,096 bytes
    // less the headers of the segment and of a frame, 24 and 8 bytes.
    let mut sender = sender_with(port, "sf_max_segment_bytes=4096;");
    assert_eq!(sender.effective_frame_cap().unwrap(), (4064, false));
    let mut large = buffer_of(TABLE, 0..2000);

    assert_refused_as_one_frame(&mut sender, &mut large, 4064, SET_BY_SEGMENT);
}

/// A segment of 4,096 bytes holds two frames of 2,028 bytes: its header of
/// 24 bytes, and twice a frame with its header of 8.
const TWO_FRAME_TARGET: usize = 2028;
/// A frame limit above [`TWO_FRAME_TARGET`] and below what a segment of
/// 4,096 bytes holds: the frame cap of a sender with such segments.
const LIMIT_ABOVE_TARGET: usize = 3000;

#[test]
fn a_buffer_of_exactly_the_frame_cap_is_one_frame_and_one_byte_more_makes_two() {
    let server = QwpWsModelServer::start(LIMIT_ABOVE_TARGET);
    let mut sender = sender_with(server.port, "sf_max_segment_bytes=4096;");
    assert_eq!(
        sender.effective_frame_cap().unwrap(),
        (LIMIT_ABOVE_TARGET, true)
    );
    let at_cap = buffer_of_len(0, LIMIT_ABOVE_TARGET);
    let above_cap = buffer_of_len(1000, LIMIT_ABOVE_TARGET + 1);

    assert_eq!(sender.flush_and_keep_and_get_fsn(&at_cap).unwrap(), Some(0));
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    let table = server.model.table(TABLE).unwrap();
    assert_eq!((table.commits, table.blocks.len()), (1, 1));

    // Cut for frames of the two-frame target, so the first of the two is
    // smaller than the buffer before.
    assert_eq!(
        sender.flush_and_keep_and_get_fsn(&above_cap).unwrap(),
        Some(2)
    );
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    let table = server.model.table(TABLE).unwrap();
    assert_eq!((table.commits, table.blocks.len()), (2, 3));
    assert!(table.blocks[1].rows.len() < table.blocks[0].rows.len());
    assert_eq!(table.rows_as_text(), rows_of_all(&[&at_cap, &above_cap]));
    drop(sender);
    server.finish();
}

#[test]
fn a_flush_is_cut_for_two_frames_a_segment_and_a_larger_row_travels_alone() {
    let server = QwpWsModelServer::start(LIMIT_ABOVE_TARGET);
    let mut sender = sender_with(server.port, "sf_max_segment_bytes=4096;");
    assert_eq!(
        sender.effective_frame_cap().unwrap(),
        (LIMIT_ABOVE_TARGET, true)
    );

    let large = buffer_of(TABLE, 0..400);
    let frame_count = frames_of_a_flush(&large, TWO_FRAME_TARGET).len();
    assert!(frame_count > frames_of_a_flush(&large, LIMIT_ABOVE_TARGET).len());
    assert_eq!(
        sender.flush_and_keep_and_get_fsn(&large).unwrap(),
        Some(frame_count as u64 - 1)
    );
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    let table = server.model.table(TABLE).unwrap();
    assert_eq!((table.commits, table.blocks.len()), (1, frame_count));

    // A row whose frame is above the target and within the frame cap.
    let mut with_large_row = buffer_of(TABLE, 400..420);
    add_row(&mut with_large_row, 420, &"x".repeat(2400));
    for id in 421..440 {
        add_row(&mut with_large_row, id, &format!("row {id}"));
    }
    sender.flush_and_keep(&with_large_row).unwrap();
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    let table = server.model.table(TABLE).unwrap();
    assert_eq!((table.commits, table.blocks.len()), (2, frame_count + 3));
    let rows_per_frame: Vec<usize> = table.blocks[frame_count..]
        .iter()
        .map(|block| block.rows.len())
        .collect();
    assert_eq!(rows_per_frame, [20, 1, 19]);
    assert_eq!(
        table.rows_as_text(),
        rows_of_all(&[&large, &with_large_row])
    );
    drop(sender);
    server.finish();
}

#[test]
fn a_buffer_of_exactly_max_buf_size_is_sent_in_frames_and_one_byte_more_is_refused() {
    const MAX_BUF_SIZE: usize = 8192;
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let mut sender = sender_with(server.port, "max_buf_size=8192;");
    assert_eq!(sender.effective_frame_cap().unwrap(), (FRAME_LIMIT, true));
    let at_max = buffer_of_len(0, MAX_BUF_SIZE);
    let mut above_max = buffer_of_len(1000, MAX_BUF_SIZE + 1);
    let frame_count = frames_of_a_flush(&at_max, FRAME_LIMIT).len() as u64;

    assert_eq!(
        sender.flush_and_keep_and_get_fsn(&at_max).unwrap(),
        Some(frame_count - 1)
    );
    assert_refused_as_one_frame(&mut sender, &mut above_max, FRAME_LIMIT, SET_BY_SERVER);

    sender.wait(AckLevel::Ok, WAIT).unwrap();
    let table = server.model.table(TABLE).unwrap();
    assert_eq!(table.commits, 1);
    assert_eq!(table.rows_as_text(), rows_of(TABLE, &at_max));
    drop(sender);
    server.finish();
}

#[test]
fn a_buffer_that_cannot_be_cut_is_refused_as_one_frame() {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let mut sender = sender_with(server.port, "");

    // Rows of two tables. The second table is why each buffer cannot be
    // cut: it has a symbol column, or a row above the frame cap.
    let mut with_symbols_in_its_last_table = buffer_of(TABLE, 0..2000);
    with_symbols_in_its_last_table
        .table("other_rows")
        .unwrap()
        .symbol("sym", "a")
        .unwrap()
        .column_i64("id", 1)
        .unwrap()
        .at_now()
        .unwrap();
    let mut with_a_row_above_the_cap_in_its_last_table = buffer_of(TABLE, 0..2000);
    with_a_row_above_the_cap_in_its_last_table
        .table("other_rows")
        .unwrap()
        .column_str("txt", "x".repeat(FRAME_LIMIT))
        .unwrap()
        .at_now()
        .unwrap();
    let mut with_symbols = Buffer::new_qwp_ws();
    for id in 0..2000 {
        with_symbols
            .table(TABLE)
            .unwrap()
            .symbol("sym", "a")
            .unwrap()
            .column_i64("id", id)
            .unwrap()
            .at_now()
            .unwrap();
    }
    let mut with_a_row_above_the_cap = buffer_of(TABLE, 0..2000);
    add_row(
        &mut with_a_row_above_the_cap,
        2000,
        &"x".repeat(FRAME_LIMIT),
    );
    for buffer in [
        &mut with_symbols_in_its_last_table,
        &mut with_a_row_above_the_cap_in_its_last_table,
        &mut with_symbols,
        &mut with_a_row_above_the_cap,
    ] {
        assert_refused_as_one_frame(&mut sender, buffer, FRAME_LIMIT, SET_BY_SERVER);
    }
    // Nothing of the refused buffers reached the server, not even a table.
    assert!(server.model.table(TABLE).is_none());
    assert!(server.model.table("other_rows").is_none());

    // The sender then takes a buffer that can be cut: the two tables, with
    // columns the planner can size and rows within the frame cap.
    let mut large = buffer_of(TABLE, 0..2000);
    large
        .table("other_rows")
        .unwrap()
        .column_i64("id", 1)
        .unwrap()
        .at_now()
        .unwrap();
    sender.flush_and_keep(&large).unwrap();
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    let table = server.model.table(TABLE).unwrap();
    assert_eq!(table.commits, 1);
    assert_eq!(table.rows_as_text(), rows_of(TABLE, &large));
    let other = server.model.table("other_rows").unwrap();
    assert_eq!(other.commits, 1);
    assert_eq!(other.rows_as_text(), rows_of("other_rows", &large));
    drop(sender);
    server.finish();
}

#[test]
fn a_flush_without_room_for_all_its_frames_is_refused_as_one_frame() {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    // A queue of four segments of 1,024 bytes. A segment holds 992 bytes of
    // one frame, which is the frame cap, or two frames of 492 bytes, which
    // is what a flush is cut for. A flush that could not queue a frame
    // would wait 200 ms for room.
    let mut sender = sender_with(
        server.port,
        "sf_max_segment_bytes=1024;sf_max_total_bytes=4096;sf_append_deadline_millis=200;",
    );
    assert_eq!(sender.effective_frame_cap().unwrap(), (992, true));
    let mut too_many_frames = buffer_of(TABLE, 0..400);
    let few_frames = buffer_of(TABLE, 400..460);
    assert!(frames_of_a_flush(&too_many_frames, 492).len() > 8);
    let few = frames_of_a_flush(&few_frames, 492).len() as u64;
    assert!((3..=6).contains(&few), "{few} frames");

    assert_refused_as_one_frame(&mut sender, &mut too_many_frames, 992, SET_BY_SEGMENT);

    assert_eq!(
        sender.flush_and_keep_and_get_fsn(&few_frames).unwrap(),
        Some(few - 1)
    );
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    let table = server.model.table(TABLE).unwrap();
    assert_eq!(table.commits, 1);
    assert_eq!(table.rows_as_text(), rows_of(TABLE, &few_frames));

    assert_refused_as_one_frame(&mut sender, &mut too_many_frames, 992, SET_BY_SEGMENT);
    drop(sender);
    server.finish();
}

#[test]
fn a_sender_that_was_closed_refuses_a_buffer_above_the_frame_cap() {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let mut sender = sender_with(server.port, "");
    let mut large = buffer_of(TABLE, 0..2000);
    sender.close_drain().unwrap();

    assert_refused_as_one_frame(&mut sender, &mut large, FRAME_LIMIT, SET_BY_SERVER);
    drop(sender);
    server.finish();
}
