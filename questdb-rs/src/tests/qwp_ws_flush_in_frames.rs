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
//! buffer is within `max_buf_size`, each of its rows fits a frame and none of
//! its values is one that cannot be sent.
//! The buffer may hold rows of several tables: the server commits each of
//! them once. Each frame brings the symbols that its rows are the first to
//! use on the connection. The flush waits until the queue has room for all
//! its frames, as long as `sf_append_deadline_millis` allows, and publishes
//! none of them before.
//! Such a sender refuses a buffer above `max_buf_size` with an error that
//! names `max_buf_size` and the size of the buffer, and a buffer whose frames
//! the queue can never hold together with one that names
//! `sf_max_total_bytes` and the value that would do.
//! Any other flush goes out as one frame, as before: a buffer that is too
//! large for one frame is refused. When a row that fits no frame is why the
//! buffer was not cut into several, the refusal names the table of the row,
//! the size of the frame it needs, and the frame cap. Nothing of a refused
//! buffer is published, and it keeps its rows.
//!
//! The server is the model of [`crate::tests::qwp_ws_server_model`] behind a
//! socket: it holds the rows of a frame with the defer flag and commits at
//! every frame without it, so the number of its commits tells how the frames
//! of a flush were flagged. A test can make it keep its answers to itself, so
//! that what was flushed stays in the queue of the sender.

use std::thread;
use std::time::{Duration, Instant};

use crate::ErrorCode;
use crate::ingress::{
    AckLevel, Buffer, Sender, SenderBuilder, SymbolGlobalDict, TimestampMicros, TimestampNanos,
    decode_qwp_varint,
};
use crate::tests::qwp_ws::spawn_max_batch_size_upgrade_only_server;
use crate::tests::qwp_ws_server_model::{
    QwpWsModelServer, QwpWsServerModel, add_rows, buffer_of, frame_of_a_sender,
    frame_of_a_whole_buffer, frames_of_a_flush, frames_of_a_sender, rows_of,
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

/// Flushes a buffer that the sender refuses for its size, and gives the text
/// of the refusal. Nothing is published, the buffer keeps its rows and the
/// sender stays usable.
fn refusal_of(sender: &mut Sender, buffer: &mut Buffer) -> String {
    let published = sender.published_fsn().unwrap();
    let (rows, len) = (buffer.row_count(), buffer.len());

    let err = sender.flush(buffer).unwrap_err();
    assert_eq!(err.code(), ErrorCode::BatchTooLarge, "{}", err.msg());
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
    err.msg().to_owned()
}

/// Flushes a buffer that is too large for one frame and that is not sent in
/// frames either. The refusal is the one such a buffer got before: it names
/// the frame cap and what sets it.
fn assert_refused_as_one_frame(sender: &mut Sender, buffer: &mut Buffer, cap: usize, set_by: &str) {
    let refusal = refusal_of(sender, buffer);
    let end =
        format!(" bytes exceeds the per-frame cap of {cap} bytes. The cap is set by {set_by}.");
    assert!(
        refusal.starts_with("Could not flush buffer: QWP/WebSocket encoded message size of ")
            && refusal.ends_with(&end),
        "got: {refusal}"
    );
}

/// Flushes a buffer that is larger than `max_buf_size`. The refusal names
/// the size of the buffer, `max_buf_size`, and the value that would do.
fn assert_refused_for_max_buf_size(sender: &mut Sender, buffer: &mut Buffer, max_buf_size: usize) {
    let len = buffer.len();
    assert_eq!(
        refusal_of(sender, buffer),
        format!(
            "Could not flush buffer: its size is {len} bytes, and max_buf_size is {max_buf_size} \
             bytes. Set max_buf_size to at least {len}, or flush more often."
        )
    );
}

/// Flushes a buffer that is too large for one frame and that is not cut
/// into several, because a row of `table` fits none. The refusal names the
/// table, the `frame_size` bytes that a frame with that row alone takes, the
/// frame cap and what sets it.
fn assert_refused_for_a_row(
    sender: &mut Sender,
    buffer: &mut Buffer,
    table: &str,
    frame_size: usize,
    cap: usize,
    set_by: &str,
) {
    assert_eq!(
        refusal_of(sender, buffer),
        format!(
            "Could not flush buffer: a row of table '{table}' needs a frame of {frame_size} \
             bytes, and the per-frame cap is {cap} bytes. Make the row smaller, or raise the \
             cap. The cap is set by {set_by}."
        )
    );
}

/// Flushes a buffer whose `frames` frames need a queue of `min_total_bytes`
/// bytes, through a sender whose queue is one of `max_total_bytes`. The
/// refusal names both.
fn assert_refused_for_the_queue(
    sender: &mut Sender,
    buffer: &mut Buffer,
    frames: usize,
    min_total_bytes: usize,
    max_total_bytes: usize,
) {
    assert_eq!(
        refusal_of(sender, buffer),
        format!(
            "Could not flush buffer: its {frames} frames need a store-and-forward queue of \
             {min_total_bytes} bytes, and sf_max_total_bytes is {max_total_bytes} bytes. Set \
             sf_max_total_bytes to at least {min_total_bytes}, or flush more often."
        )
    );
}

/// Adds row `id` of a table with three symbol columns, each left out of
/// some rows. `venue` has four symbols. Every cell of `tag` brings a new
/// one. `mixed` brings some and finds others, in no order: some of them are
/// symbols of `venue`, and some are 130 bytes long, so that their length
/// takes two bytes. A row's values depend on `id` alone, so two tables
/// share the symbols of the ids that both hold.
fn add_symbol_row(buffer: &mut Buffer, table: &str, id: i64) {
    buffer.table(table).unwrap();
    if id % 5 != 3 {
        buffer.symbol("venue", format!("v{}", id % 4)).unwrap();
    }
    if id % 3 != 1 {
        buffer.symbol("tag", format!("t{id}")).unwrap();
    }
    if id % 4 != 2 {
        let pick = id * id % 37;
        let mixed = match pick {
            0..4 => format!("v{pick}"),
            _ if pick % 5 == 0 => format!("m{pick}{}", "-".repeat(128)),
            _ => format!("m{pick}"),
        };
        buffer.symbol("mixed", mixed).unwrap();
    }
    buffer.column_i64("id", id).unwrap();
    if id % 2 == 1 {
        buffer.column_str("txt", format!("row {id}")).unwrap();
    }
    buffer
        .at(TimestampNanos::new(1_700_000_000_000_000_000 + id))
        .unwrap();
}

/// Rows `ids` of [`add_symbol_row`] in a buffer of one table.
fn buffer_of_symbols(table: &str, ids: std::ops::Range<i64>) -> Buffer {
    let mut buffer = Buffer::new_qwp_ws();
    for id in ids {
        add_symbol_row(&mut buffer, table, id);
    }
    buffer
}

/// The symbols that a frame brings: the id of the first, and their texts.
fn symbols_brought_by(frame: &[u8]) -> (u64, Vec<String>) {
    let (first_id, pos) = decode_qwp_varint(frame, 12).unwrap();
    let (count, mut pos) = decode_qwp_varint(frame, pos).unwrap();
    let mut texts = Vec::new();
    for _ in 0..count {
        let (len, start) = decode_qwp_varint(frame, pos).unwrap();
        pos = start + len as usize;
        texts.push(String::from_utf8(frame[start..pos].to_vec()).unwrap());
    }
    (first_id, texts)
}

/// The frames of a flush bring the symbols of its rows, wherever the buffer
/// is cut. For every frame limit from the smallest that the rows allow, on
/// a connection that knows some of the symbols from a flush before:
///
/// - the symbols of a frame start where those of the frame before ended;
/// - no symbol comes twice, none that the connection knew comes again, and
///   together they are the symbols of the buffer that it did not know;
/// - no frame is above the limit, which it would be if it brought a symbol
///   before the frame whose rows use it;
/// - a server holds the rows that one frame of the buffer gives, each table
///   in one commit.
///
/// Over the limits, a frame begins at nearly every row of the first table.
#[test]
fn the_frames_of_a_flush_bring_each_symbol_once_wherever_the_buffer_is_cut() {
    const FIRST_ROWS: usize = 90;
    let before = buffer_of_symbols(THIRD, 20..45);
    let mut large = buffer_of_symbols(FIRST, 0..FIRST_ROWS as i64);
    for id in 60..110 {
        add_symbol_row(&mut large, SECOND, id);
    }
    let (first_rows, second_rows) = (rows_of(FIRST, &large), rows_of(SECOND, &large));
    let texts_of = |buffer: &Buffer| -> std::collections::BTreeSet<String> {
        let frame = frame_of_a_sender(buffer, false, &mut SymbolGlobalDict::new());
        symbols_brought_by(&frame).1.into_iter().collect()
    };
    let known = texts_of(&before);
    let new: std::collections::BTreeSet<String> =
        texts_of(&large).difference(&known).cloned().collect();
    assert!(new.len() > 50 && new.len() < texts_of(&large).len());

    let rows = large.as_qwp_ws().unwrap();
    let least_limit = (64..)
        .find(|limit| rows.plan_frames(*limit, *limit).is_ok())
        .unwrap();
    let mut frame_starts = std::collections::BTreeSet::new();
    let mut frame_counts = std::collections::BTreeSet::new();
    for limit in (least_limit..least_limit + 500).chain([4096, usize::MAX]) {
        let server = QwpWsServerModel::new();
        let mut connection = server.connect();
        let mut sender_symbols = SymbolGlobalDict::new();
        let first_frame = frame_of_a_sender(&before, false, &mut sender_symbols);
        assert!(connection.receive(&first_frame).is_some());
        let mut held = known.len() as u64;
        assert_eq!(sender_symbols.next_id(), held);

        let frames = frames_of_a_sender(&large, limit, &mut sender_symbols);
        let mut brought = std::collections::BTreeSet::new();
        for (frame_idx, frame) in frames.iter().enumerate() {
            let case = format!("limit {limit} frame {frame_idx}");
            assert!(frame.len() <= limit, "{case}: {} bytes", frame.len());
            let (first_id, texts) = symbols_brought_by(frame);
            assert_eq!(first_id, held, "{case}");
            held += texts.len() as u64;
            for text in texts {
                assert!(!known.contains(&text), "{case}: {text} was known");
                assert!(brought.insert(text.clone()), "{case}: {text} again");
            }
            let answer = connection.receive(frame);
            assert_eq!(answer.is_some(), frame_idx + 1 == frames.len(), "{case}");
        }
        assert_eq!(brought, new, "limit {limit}");
        assert_eq!(sender_symbols.next_id(), held, "limit {limit}");

        let first = server.table(FIRST).unwrap();
        let second = server.table(SECOND).unwrap();
        assert_eq!((first.commits, second.commits), (1, 1), "limit {limit}");
        assert_eq!(first.rows_as_text(), first_rows, "limit {limit}");
        assert_eq!(second.rows_as_text(), second_rows, "limit {limit}");
        let mut row = 0;
        for block in &first.blocks {
            frame_starts.insert(row);
            row += block.rows.len();
        }
        frame_counts.insert(frames.len());
    }
    // The first few rows fit the smallest frame together.
    assert!(frame_starts.len() > FIRST_ROWS - 6, "{frame_starts:?}");
    assert!(frame_counts.contains(&1) && frame_counts.contains(&2));
    assert!(frame_counts.last().is_some_and(|most| *most > 20));
}

#[test]
fn a_flush_with_symbols_above_the_frame_cap_is_one_commit() {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let mut sender = sender_with(server.port, "");
    let before = buffer_of_symbols(FIRST, 0..10);
    // Two tables that share symbols with each other and with the flush
    // before. The first has more symbols than one frame holds.
    let mut large = buffer_of_symbols(FIRST, 10..1210);
    for id in 1100..1400 {
        add_symbol_row(&mut large, SECOND, id);
    }
    // It uses symbols that the large flush brought, and new ones.
    let after = buffer_of_symbols(SECOND, 1392..1400);
    assert!(before.len() < FRAME_LIMIT && after.len() < FRAME_LIMIT);

    let mut sender_symbols = SymbolGlobalDict::new();
    frame_of_a_sender(&before, false, &mut sender_symbols);
    let frames = frames_of_a_sender(&large, FRAME_LIMIT, &mut sender_symbols);
    let frame_count = frames.len() as u64;
    let bringing_symbols = frames
        .iter()
        .filter(|frame| !symbols_brought_by(frame).1.is_empty())
        .count();
    assert!(bringing_symbols > 40, "{bringing_symbols} of {frame_count}");
    assert!(frames.iter().all(|frame| frame.len() <= FRAME_LIMIT));

    assert_eq!(sender.flush_and_keep_and_get_fsn(&before).unwrap(), Some(0));
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_table_holds(&server, FIRST, 1, &[&before]);

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
    assert_table_holds(&server, FIRST, 2, &[&before, &large]);
    assert_table_holds(&server, SECOND, 1, &[&large]);

    assert_eq!(
        sender.flush_and_keep_and_get_fsn(&after).unwrap(),
        Some(frame_count + 1)
    );
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_table_holds(&server, FIRST, 2, &[&before, &large]);
    assert_table_holds(&server, SECOND, 2, &[&large, &after]);
    assert!(!sender.must_close());
    drop(sender);
    server.finish();
}

#[test]
fn a_flush_with_symbols_that_loses_its_connection_part_way_is_sent_again_whole() {
    // The server takes the flush before and eleven frames of the large
    // flush, and ends the connection.
    const CUT_AFTER_FRAMES: usize = 12;
    let server = QwpWsModelServer::start_cutting_first_connection(FRAME_LIMIT, CUT_AFTER_FRAMES);
    let mut sender = sender_with(server.port, "");
    let before = buffer_of_symbols(FIRST, 0..10);
    let large = buffer_of_symbols(FIRST, 10..1210);
    let mut sender_symbols = SymbolGlobalDict::new();
    frame_of_a_sender(&before, false, &mut sender_symbols);
    let frames = frames_of_a_sender(&large, FRAME_LIMIT, &mut sender_symbols);
    let frame_count = frames.len() as u64;
    assert!(frame_count > 40, "{frame_count} frames");
    // The frames that the first connection took brought symbols, and so do
    // frames that only the second one takes.
    for frame in [1, CUT_AFTER_FRAMES - 2, CUT_AFTER_FRAMES + 5] {
        assert!(!symbols_brought_by(&frames[frame]).1.is_empty(), "{frame}");
    }

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
    // The second connection began without a symbol. The sender brought it
    // the symbols of the first one, those of the flush before among them,
    // and then every frame of the flush, which the server committed once.
    let table = server.model.table(FIRST).unwrap();
    assert_eq!(table.blocks.len() as u64, 1 + frame_count);
    assert_table_holds(&server, FIRST, 2, &[&before, &large]);

    // The sender goes on with the symbols that both connections know.
    let after = buffer_of_symbols(FIRST, 1200..1215);
    sender.flush_and_keep(&after).unwrap();
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_table_holds(&server, FIRST, 3, &[&before, &large, &after]);
    assert!(!sender.must_close());
    drop(sender);
    server.finish();
}

#[test]
fn a_buffer_with_a_symbol_that_a_connection_refuses_is_refused_before_its_first_frame() {
    // A frame limit that a symbol of the longest size fits.
    const LIMIT: usize = 2 * 1024 * 1024;
    const LONGEST: usize = 1 << 20;
    let server = QwpWsModelServer::start(LIMIT);
    let mut sender = sender_with(server.port, "");
    let before = buffer_of_symbols(FIRST, 0..10);
    assert_eq!(sender.flush_and_keep_and_get_fsn(&before).unwrap(), Some(0));
    sender.wait(AckLevel::Ok, WAIT).unwrap();

    // 30,000 rows, in which row 20,000 has a symbol of `long` bytes.
    let rows_with = |long: usize| {
        let mut buffer = Buffer::new_qwp_ws();
        for id in 0..30_000 {
            let symbol = if id == 20_000 {
                "x".repeat(long)
            } else {
                format!("s{}", id % 50)
            };
            buffer.table(TABLE).unwrap();
            buffer.symbol("sym", symbol).unwrap();
            buffer.column_i64("id", id).unwrap();
            buffer.column_str("txt", "-".repeat(100)).unwrap();
            buffer.at_now().unwrap();
        }
        buffer
    };
    let mut refused = rows_with(LONGEST + 1);
    let (rows, len) = (refused.row_count(), refused.len());
    assert!(len > 2 * LIMIT);
    let err = sender.flush(&mut refused).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidApiCall, "{}", err.msg());
    assert_eq!(
        err.msg(),
        "QWP/WS symbol value is 1048577 bytes, exceeding the 1048576-byte per-symbol maximum"
    );
    assert_eq!(sender.published_fsn().unwrap(), Some(0));
    assert_eq!((refused.row_count(), refused.len()), (rows, len));
    assert!(!sender.must_close());
    assert!(server.model.table(TABLE).is_none());

    // The sender goes on: the same rows with the longest symbol that a
    // connection takes are one commit.
    let taken = rows_with(LONGEST);
    let frame_count = taken
        .as_qwp_ws()
        .unwrap()
        .plan_frames(LIMIT, LIMIT)
        .unwrap()
        .frames()
        .count() as u64;
    assert!(frame_count > 2, "{frame_count} frames");
    assert_eq!(
        sender.flush_and_keep_and_get_fsn(&taken).unwrap(),
        Some(frame_count)
    );
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_table_holds(&server, TABLE, 1, &[&taken]);
    assert_table_holds(&server, FIRST, 1, &[&before]);
    drop(sender);
    server.finish();
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
    assert_refused_for_max_buf_size(&mut sender, &mut above_max, MAX_BUF_SIZE);

    // The sender goes on with a buffer that is within `max_buf_size`.
    let after = buffer_of_len(2000, MAX_BUF_SIZE);
    let frames_after = frames_of_a_flush(&after, FRAME_LIMIT).len() as u64;
    assert_eq!(
        sender.flush_and_keep_and_get_fsn(&after).unwrap(),
        Some(frame_count + frames_after - 1)
    );
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    let table = server.model.table(TABLE).unwrap();
    assert_eq!(table.commits, 2);
    assert_eq!(table.rows_as_text(), rows_of_all(&[&at_max, &after]));
    drop(sender);
    server.finish();
}

#[test]
fn a_buffer_above_max_buf_size_is_refused_for_its_size_whatever_else_it_holds() {
    const MAX_BUF_SIZE: usize = 8192;
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let mut sender = sender_with(server.port, "max_buf_size=8192;");

    // Each buffer has one more thing in the way of its flush: a decimal that
    // the encoder refuses, and a row that fits no frame.
    let mut with_a_value = buffer_of_decimals(0..2000, Some(1500));
    let mut with_a_row = buffer_of(TABLE, 0..2000);
    add_row(&mut with_a_row, 2000, &"x".repeat(FRAME_LIMIT));
    for buffer in [&mut with_a_value, &mut with_a_row] {
        assert!(buffer.len() > MAX_BUF_SIZE);
        assert_refused_for_max_buf_size(&mut sender, buffer, MAX_BUF_SIZE);
    }
    assert!(server.model.table(TABLE).is_none());
    drop(sender);
    server.finish();
}

#[test]
fn a_max_buf_size_below_the_frame_limit_is_held_against_the_size_of_the_buffer() {
    const MAX_BUF_SIZE: usize = 2000;
    let server = QwpWsModelServer::start(LIMIT_ABOVE_TARGET);
    let mut sender = sender_with(server.port, "max_buf_size=2000;");
    // `max_buf_size` is the frame cap then, and no buffer goes out in frames.
    assert_eq!(sender.effective_frame_cap().unwrap(), (MAX_BUF_SIZE, true));
    let at_max = buffer_of_len(0, MAX_BUF_SIZE);
    // The frame of this buffer takes two bytes less than the size that the
    // buffer gives, which is within the frame cap: what is above
    // `max_buf_size` is the buffer.
    let mut above_max = buffer_of_len(1000, MAX_BUF_SIZE + 1);
    assert_eq!(
        frame_of_a_whole_buffer(&above_max, false).len(),
        MAX_BUF_SIZE - 1
    );

    assert_eq!(sender.flush_and_keep_and_get_fsn(&at_max).unwrap(), Some(0));
    assert_refused_for_max_buf_size(&mut sender, &mut above_max, MAX_BUF_SIZE);

    sender.wait(AckLevel::Ok, WAIT).unwrap();
    let table = server.model.table(TABLE).unwrap();
    assert_eq!((table.commits, table.blocks.len()), (1, 1));
    assert_eq!(table.rows_as_text(), rows_of(TABLE, &at_max));
    drop(sender);
    server.finish();
}

#[test]
fn a_buffer_with_a_row_that_fits_no_frame_is_refused_with_the_table_and_the_size_of_the_row() {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let mut sender = sender_with(server.port, "");

    // Three rows that fit no frame: of a table of its own, of the table of
    // the rows before it, and with a symbol that makes it so.
    let row_of_another_table = |buffer: &mut Buffer| {
        buffer
            .table("other_rows")
            .unwrap()
            .column_str("txt", "x".repeat(FRAME_LIMIT))
            .unwrap()
            .at_now()
            .unwrap();
    };
    let row_of_the_table = |buffer: &mut Buffer| add_row(buffer, 2000, &"x".repeat(FRAME_LIMIT));
    let row_with_a_symbol = |buffer: &mut Buffer| {
        buffer
            .table("other_rows")
            .unwrap()
            .symbol("sym", "x".repeat(FRAME_LIMIT))
            .unwrap()
            .at_now()
            .unwrap();
    };
    // The size of the frame that holds a row alone is the size of a buffer
    // that holds it alone, and two bytes more when the table has a symbol
    // column: a frame that may bring symbols has the room to count them.
    let mut refuse = |add_the_row: &dyn Fn(&mut Buffer), table, room_to_count_symbols| {
        let mut alone = Buffer::new_qwp_ws();
        add_the_row(&mut alone);
        let frame_size = alone.len() + room_to_count_symbols;
        assert!(frame_size > FRAME_LIMIT);

        // The row comes behind 2,000 rows that frames can hold.
        let mut buffer = buffer_of(TABLE, 0..2000);
        add_the_row(&mut buffer);
        assert_refused_for_a_row(
            &mut sender,
            &mut buffer,
            table,
            frame_size,
            FRAME_LIMIT,
            SET_BY_SERVER,
        );
    };
    refuse(&row_of_another_table, "other_rows", 0);
    refuse(&row_of_the_table, TABLE, 0);
    refuse(&row_with_a_symbol, "other_rows", 2);
    // Nothing of the refused buffers reached the server, not even a table.
    assert!(server.model.table(TABLE).is_none());
    assert!(server.model.table("other_rows").is_none());

    // The sender then takes a buffer that can be cut: the two tables, with
    // rows within the frame cap. The refused symbol left nothing behind:
    // the first symbol of this flush is the first of the connection.
    let mut large = buffer_of(TABLE, 0..2000);
    large
        .table("other_rows")
        .unwrap()
        .symbol("sym", "a")
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
fn a_row_whose_frame_is_exactly_the_frame_cap_travels_alone_and_one_byte_more_is_refused() {
    // A flush is cut for frames that are smaller than the frame cap.
    let server = QwpWsModelServer::start(LIMIT_ABOVE_TARGET);
    let mut sender = sender_with(server.port, "sf_max_segment_bytes=4096;");
    assert_eq!(
        sender.effective_frame_cap().unwrap(),
        (LIMIT_ABOVE_TARGET, true)
    );
    // A row whose frame takes `frame_size` bytes, between rows that fill
    // other frames.
    let rows_around_a_row_of = |frame_size: usize| {
        let mut alone = Buffer::new_qwp_ws();
        add_row(&mut alone, 100, "");
        // A byte of text is a byte of the frame.
        let text = "x".repeat(frame_size - alone.len());
        let mut buffer = buffer_of(TABLE, 0..100);
        add_row(&mut buffer, 100, &text);
        add_rows(&mut buffer, TABLE, 101..200);
        buffer
    };
    let at_cap = rows_around_a_row_of(LIMIT_ABOVE_TARGET);
    let mut above_cap = rows_around_a_row_of(LIMIT_ABOVE_TARGET + 1);

    sender.flush_and_keep(&at_cap).unwrap();
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    let table = server.model.table(TABLE).unwrap();
    assert_eq!(table.commits, 1);
    assert_eq!(table.rows_as_text(), rows_of(TABLE, &at_cap));
    let frames_of_one_row = table
        .blocks
        .iter()
        .filter(|block| block.rows.len() == 1)
        .count();
    assert_eq!(frames_of_one_row, 1);

    assert_refused_for_a_row(
        &mut sender,
        &mut above_cap,
        TABLE,
        LIMIT_ABOVE_TARGET + 1,
        LIMIT_ABOVE_TARGET,
        SET_BY_SERVER,
    );
    drop(sender);
    server.finish();
}

#[test]
fn a_row_that_fits_no_frame_by_its_size_bound_is_sent_when_the_buffer_fits_one_frame() {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let mut sender = sender_with(server.port, "");
    // Rows with one symbol of 600 bytes and a text of `txt` bytes.
    let add = |buffer: &mut Buffer, id: i64, txt: usize| {
        buffer
            .table(TABLE)
            .unwrap()
            .symbol("sym", "s".repeat(600))
            .unwrap()
            .column_i64("id", id)
            .unwrap()
            .column_str("txt", "x".repeat(txt))
            .unwrap()
            .at_now()
            .unwrap();
    };
    let mut first = Buffer::new_qwp_ws();
    add(&mut first, 0, 10);
    assert_eq!(sender.flush_and_keep_and_get_fsn(&first).unwrap(), Some(0));
    sender.wait(AckLevel::Ok, WAIT).unwrap();

    // The size bound of a row takes its symbols as new to the connection.
    // With its symbol this row needs a frame above the frame cap, and the
    // connection has the symbol: the buffer fits one frame, and goes out.
    let mut alone = Buffer::new_qwp_ws();
    add(&mut alone, 1, 500);
    let frame_size = alone.len() + 2;
    assert!(frame_size > FRAME_LIMIT + 100);
    assert_eq!(sender.flush_and_keep_and_get_fsn(&alone).unwrap(), Some(1));
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    let table = server.model.table(TABLE).unwrap();
    assert_eq!((table.commits, table.blocks.len()), (2, 2));

    // Ahead of rows that do not fit one frame with it, the same row is why
    // the buffer is not cut into frames. The refusal gives the size of its
    // frame by the size bound, with the symbol.
    let mut ahead_of_others = Buffer::new_qwp_ws();
    add(&mut ahead_of_others, 2, 500);
    for id in 3..60 {
        add(&mut ahead_of_others, id, 10);
    }
    assert_refused_for_a_row(
        &mut sender,
        &mut ahead_of_others,
        TABLE,
        frame_size,
        FRAME_LIMIT,
        SET_BY_SERVER,
    );

    let table = server.model.table(TABLE).unwrap();
    assert_eq!(table.commits, 2);
    assert_eq!(table.rows_as_text(), rows_of_all(&[&first, &alone]));
    drop(sender);
    server.finish();
}

#[test]
fn a_value_that_cannot_be_sent_is_named_before_a_row_that_fits_no_frame() {
    const TWO_DIGITS: &str = "cannot rescale decimal from scale 2 to 1 without precision loss";
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let mut sender = sender_with(server.port, "");
    // 2,000 rows with a decimal of one digit after the point. With
    // `two_digits`, row 1,500 has two: a value that the encoder refuses.
    let add_decimals = |buffer: &mut Buffer, table: &str, two_digits: bool| {
        for id in 0..2000 {
            let price = if two_digits && id == 1500 {
                format!("{id}.25")
            } else {
                format!("{id}.5")
            };
            buffer
                .table(table)
                .unwrap()
                .column_i64("id", id)
                .unwrap()
                .column_dec64("price", price.as_str())
                .unwrap()
                .at(TimestampNanos::new(1_700_000_000_000_000_000 + id))
                .unwrap();
        }
    };
    let add_a_row_above_the_cap = |buffer: &mut Buffer, table: &str| {
        buffer
            .table(table)
            .unwrap()
            .column_str("txt", "x".repeat(FRAME_LIMIT))
            .unwrap()
            .at_now()
            .unwrap();
    };
    // The row in the table before that of the value, in the table after it,
    // and in the same table.
    let buffers_with = |two_digits: bool| {
        let mut row_first = Buffer::new_qwp_ws();
        add_a_row_above_the_cap(&mut row_first, FIRST);
        add_decimals(&mut row_first, SECOND, two_digits);
        let mut value_first = Buffer::new_qwp_ws();
        add_decimals(&mut value_first, FIRST, two_digits);
        add_a_row_above_the_cap(&mut value_first, SECOND);
        let mut one_table = Buffer::new_qwp_ws();
        add_a_row_above_the_cap(&mut one_table, FIRST);
        add_decimals(&mut one_table, FIRST, two_digits);
        [row_first, value_first, one_table]
    };

    for mut refused in buffers_with(true) {
        let (rows, len) = (refused.row_count(), refused.len());
        let err = sender.flush(&mut refused).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall, "{}", err.msg());
        assert_eq!(err.msg(), TWO_DIGITS);
        assert_eq!(sender.published_fsn().unwrap(), None);
        assert_eq!((refused.row_count(), refused.len()), (rows, len));
        assert!(!sender.must_close());
    }
    // Without that value, the row is what each buffer is refused for.
    for (mut refused, table) in buffers_with(false).into_iter().zip([FIRST, SECOND, FIRST]) {
        let refusal = refusal_of(&mut sender, &mut refused);
        assert!(
            refusal.starts_with(&format!(
                "Could not flush buffer: a row of table '{table}' needs a frame of "
            )),
            "got: {refusal}"
        );
    }
    assert!(server.model.table(FIRST).is_none());
    assert!(server.model.table(SECOND).is_none());
    drop(sender);
    server.finish();
}

/// The byte budget that a queue of segments of 1,024 bytes needs for a
/// flush of `frames` frames that go two a segment: the segments that the
/// frames fill, and the segment in use.
fn queue_bytes_for(frames: usize) -> usize {
    (frames.div_ceil(2) + 1) * 1024
}

#[test]
fn a_flush_that_the_queue_can_never_hold_is_refused_with_the_value_that_would_do() {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    // Segments of 1,024 bytes. One holds 992 bytes of one frame, which is
    // the frame cap, or two frames of 492 bytes, which is what a flush is
    // cut for.
    const SEGMENTS: &str = "sf_max_segment_bytes=1024;";
    let before = buffer_of(TABLE, 0..3);
    let few_frames = buffer_of(TABLE, 3..63);
    let mut too_large = buffer_of(TABLE, 63..463);
    let few = frames_of_a_flush(&few_frames, 492).len();
    assert!((3..=6).contains(&few), "{few} frames");
    let frames = frames_of_a_flush(&too_large, 492).len();
    let min_total_bytes = queue_bytes_for(frames);
    assert!(min_total_bytes > 3 * 4096, "{frames} frames");

    // A queue of four segments.
    let mut sender = sender_with(server.port, &format!("{SEGMENTS}sf_max_total_bytes=4096;"));
    assert_eq!(sender.effective_frame_cap().unwrap(), (992, true));
    assert_eq!(sender.flush_and_keep_and_get_fsn(&before).unwrap(), Some(0));
    assert_refused_for_the_queue(&mut sender, &mut too_large, frames, min_total_bytes, 4096);

    // The flush before is confirmed, and the sender takes a flush that its
    // queue holds. The large one is refused again.
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_table_holds(&server, TABLE, 1, &[&before]);
    assert_eq!(
        sender.flush_and_keep_and_get_fsn(&few_frames).unwrap(),
        Some(few as u64)
    );
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_table_holds(&server, TABLE, 2, &[&before, &few_frames]);
    assert_refused_for_the_queue(&mut sender, &mut too_large, frames, min_total_bytes, 4096);
    drop(sender);

    // A byte less than the error names is not enough, also for a queue that
    // holds nothing else.
    let settings = format!("{SEGMENTS}sf_max_total_bytes={};", min_total_bytes - 1);
    let mut sender = sender_with(server.port, &settings);
    assert_refused_for_the_queue(
        &mut sender,
        &mut too_large,
        frames,
        min_total_bytes,
        min_total_bytes - 1,
    );
    drop(sender);

    // With the queue that the error names, the buffer is one commit.
    let settings = format!("{SEGMENTS}sf_max_total_bytes={min_total_bytes};");
    let mut sender = sender_with(server.port, &settings);
    assert_eq!(
        sender.flush_and_keep_and_get_fsn(&too_large).unwrap(),
        Some(frames as u64 - 1)
    );
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_table_holds(&server, TABLE, 3, &[&before, &few_frames, &too_large]);
    assert!(!sender.must_close());
    drop(sender);
    server.finish();
}

/// The settings of a sender whose queue is eight segments of 1,024 bytes,
/// for frames that go two a segment.
const EIGHT_SEGMENTS: &str = "sf_max_segment_bytes=1024;sf_max_total_bytes=8192;";

/// Two flushes for the queue of [`EIGHT_SEGMENTS`], and the number of
/// frames of each. The six frames of the first fill three segments. Next to
/// them the queue has five segments, which hold ten of the eleven frames of
/// the second: that flush lacks room for its last frame alone.
fn two_flushes_for_a_queue_that_holds_one() -> (Buffer, usize, Buffer, usize) {
    let first = buffer_of(TABLE, 0..94);
    let second = buffer_of(TABLE, 100..268);
    let first_frames = frames_of_a_flush(&first, 492).len();
    let second_frames = frames_of_a_flush(&second, 492).len();
    assert_eq!((first_frames, second_frames), (6, 11));
    assert!(queue_bytes_for(second_frames) <= 8192);
    (first, first_frames, second, second_frames)
}

/// What the segments of the queue of [`EIGHT_SEGMENTS`] take once it holds
/// a flush of `frames` frames and nothing else: the segments of the frames,
/// and the one that the runner prepares for the next frame when it gets to
/// it, which a runner that is reconnecting does not.
fn allocated_after_a_flush_of(frames: usize) -> [usize; 2] {
    let segments = frames.div_ceil(2);
    [segments * 1024, (segments + 1) * 1024]
}

/// Checks the error of a flush that waited for room in the queue of
/// [`EIGHT_SEGMENTS`] until `sf_append_deadline_millis` had passed, with the
/// connection up. What the segments of the queue take then is one of
/// `allocated`.
fn assert_timed_out_waiting_for_room(err: &crate::Error, allocated: &[usize]) {
    assert_eq!(err.code(), ErrorCode::SocketError, "{}", err.msg());
    let texts: Vec<String> = allocated
        .iter()
        .map(|allocated| {
            format!(
                "QWP/WebSocket Store-and-Forward append timed out waiting for ACK-driven \
                 segment trim; increase sf_max_total_bytes or drive pending acknowledgements \
                 [segment_size_bytes=1024, allocated_segment_bytes={allocated}, \
                 max_total_bytes=8192]"
            )
        })
        .collect();
    assert!(
        texts.iter().any(|text| text == err.msg()),
        "got: {}",
        err.msg()
    );
}

/// Waits until the server has taken `frames` frames.
fn wait_for_frames_taken(server: &QwpWsModelServer, frames: usize) {
    let deadline = Instant::now() + WAIT;
    while server.frames_taken() < frames {
        assert!(
            Instant::now() < deadline,
            "the server took {} of {frames} frames",
            server.frames_taken()
        );
        thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn a_flush_without_room_waits_until_the_server_confirms_what_the_queue_holds() {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    // The server takes what is flushed and keeps its answers to itself: what
    // is flushed stays in the queue.
    server.hold_answers();
    let mut sender = sender_with(server.port, EIGHT_SEGMENTS);
    assert_eq!(sender.effective_frame_cap().unwrap(), (992, true));
    let (first, first_frames, second, second_frames) = two_flushes_for_a_queue_that_holds_one();
    let mut too_large = buffer_of(TABLE, 340..740);
    let too_many_frames = frames_of_a_flush(&too_large, 492).len();
    assert!(queue_bytes_for(too_many_frames) > 8192);

    assert_eq!(
        sender.flush_and_keep_and_get_fsn(&first).unwrap(),
        Some(first_frames as u64 - 1)
    );

    // What the queue can never hold is refused at once, whatever it holds.
    let started = Instant::now();
    assert_refused_for_the_queue(
        &mut sender,
        &mut too_large,
        too_many_frames,
        queue_bytes_for(too_many_frames),
        8192,
    );
    assert!(started.elapsed() < Duration::from_secs(5));

    // The second flush waits for the answer to the first.
    let last_fsn = thread::scope(|scope| {
        let flush = scope.spawn(|| sender.flush_and_keep_and_get_fsn(&second));
        wait_for_frames_taken(&server, first_frames);
        thread::sleep(Duration::from_millis(200));
        assert!(!flush.is_finished(), "the flush did not wait for room");
        assert_eq!(
            server.frames_taken(),
            first_frames,
            "no frame of the flush is sent before all of them have room"
        );
        server.let_answers_go();
        flush.join().unwrap().unwrap()
    });
    assert_eq!(last_fsn, Some((first_frames + second_frames) as u64 - 1));
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_table_holds(&server, TABLE, 2, &[&first, &second]);
    assert!(!sender.must_close());
    drop(sender);
    server.finish();
}

#[test]
fn a_flush_that_waits_for_room_until_the_deadline_fails_with_nothing_sent() {
    const DEADLINE: Duration = Duration::from_millis(300);
    let settings = format!("{EIGHT_SEGMENTS}sf_append_deadline_millis=300;");
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    server.hold_answers();
    let mut sender = sender_with(server.port, &settings);
    let (first, first_frames, mut second, second_frames) = two_flushes_for_a_queue_that_holds_one();
    let (rows, len) = (second.row_count(), second.len());

    assert_eq!(
        sender.flush_and_keep_and_get_fsn(&first).unwrap(),
        Some(first_frames as u64 - 1)
    );
    let started = Instant::now();
    let err = sender.flush(&mut second).unwrap_err();
    let waited = started.elapsed();
    assert!(waited >= DEADLINE && waited < WAIT, "waited {waited:?}");
    // Half of the queue is free: enough for every frame but the last.
    let allocated = allocated_after_a_flush_of(first_frames);
    assert_eq!(allocated, [3072, 4096]);
    assert_timed_out_waiting_for_room(&err, &allocated);
    assert_eq!(
        sender.published_fsn().unwrap(),
        Some(first_frames as u64 - 1),
        "nothing is published"
    );
    assert_eq!(
        (second.row_count(), second.len()),
        (rows, len),
        "the buffer keeps its rows"
    );
    wait_for_frames_taken(&server, first_frames);
    assert_eq!(server.frames_taken(), first_frames, "nothing is sent");
    // As after a flush of one frame that waited as long, below: the sender
    // says that it must be closed, and goes on working all the same.
    assert!(sender.must_close());

    // A flush of one frame that finds the queue full fails the same way.
    let mut other = sender_with(server.port, &settings);
    let one_frame = buffer_of(FIRST, 0..10);
    assert!(one_frame.len() <= 492);
    let err = loop {
        if let Err(err) = other.flush_and_keep(&one_frame) {
            break err;
        }
        assert!(!other.must_close());
    };
    assert_timed_out_waiting_for_room(&err, &[8192]);
    assert!(other.must_close());
    drop(other);

    // The server answers, and the same flush goes through: it waits for the
    // runner to free the segments of the first flush, and is tried again
    // should that take longer than the deadline.
    server.let_answers_go();
    let retry_until = Instant::now() + WAIT;
    let last_fsn = loop {
        match sender.flush_and_keep_and_get_fsn(&second) {
            Ok(fsn) => break fsn,
            Err(err) => assert!(Instant::now() < retry_until, "{}", err.msg()),
        }
    };
    assert_eq!(last_fsn, Some((first_frames + second_frames) as u64 - 1));
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_table_holds(&server, TABLE, 2, &[&first, &second]);
    assert!(sender.must_close());
    drop(sender);
    server.finish();
}

#[test]
fn a_flush_that_waits_for_room_while_the_server_is_down_names_why_reconnecting_fails() {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    server.hold_answers();
    let mut sender = sender_with(
        server.port,
        &format!(
            "{EIGHT_SEGMENTS}sf_append_deadline_millis=300;\
             reconnect_initial_backoff_millis=10;reconnect_max_backoff_millis=20;"
        ),
    );
    let (first, first_frames, mut second, _) = two_flushes_for_a_queue_that_holds_one();
    let (rows, len) = (second.row_count(), second.len());
    assert_eq!(
        sender.flush_and_keep_and_get_fsn(&first).unwrap(),
        Some(first_frames as u64 - 1)
    );

    // The server goes down with the first flush unconfirmed, and the sender
    // has tried to reconnect and failed.
    server.go_down();
    let deadline = Instant::now() + WAIT;
    while sender.qwp_ws_totals().unwrap().reconnect_attempts < 2 {
        assert!(Instant::now() < deadline, "the sender did not reconnect");
        thread::sleep(Duration::from_millis(1));
    }

    let err = sender.flush(&mut second).unwrap_err();
    assert_eq!(err.code(), ErrorCode::SocketError, "{}", err.msg());
    let begins = allocated_after_a_flush_of(first_frames).map(|allocated| {
        format!(
            "QWP/WebSocket Store-and-Forward append timed out waiting for ACK-driven segment \
             trim [segment_size_bytes=1024, allocated_segment_bytes={allocated}, \
             max_total_bytes=8192]; the connection is down and reconnecting keeps failing: "
        )
    });
    let end = ". The frames already published remain queued and the sender keeps reconnecting: \
               retry the flush once that is resolved, or close the sender to give up.";
    assert!(
        begins.iter().any(|begin| err.msg().starts_with(begin)) && err.msg().ends_with(end),
        "got: {}",
        err.msg()
    );
    assert_eq!(
        sender.published_fsn().unwrap(),
        Some(first_frames as u64 - 1),
        "nothing is published"
    );
    assert_eq!(
        (second.row_count(), second.len()),
        (rows, len),
        "the buffer keeps its rows"
    );
    assert!(sender.must_close());
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
