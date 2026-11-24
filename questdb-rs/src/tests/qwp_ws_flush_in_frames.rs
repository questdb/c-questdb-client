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
//! when all of this holds: the server has told its frame limit, the buffer
//! is within `max_buf_size`, each of its rows fits a frame and none of its
//! values is one that cannot be sent. The sender may keep its queue in
//! memory or in a slot of its `sf_dir`. With `sf_dir` a `close_drain` after a
//! flush that stopped part way leaves the slot empty. A sender dropped without
//! it leaves the frames of that flush in the slot, and the next sender on the
//! slot removes them when it starts: it sends the flushes before that one, and
//! nothing of it, also when its segments are larger than those of the slot
//! and its frames do not fit them. It keeps the symbols of the slot, so a
//! flush that a full dictionary stopped stops the same way once more. A sender
//! that could not make the symbol file of its slot sends every buffer as one
//! frame.
//! The sender may make its progress in the background or be driven by its
//! caller (`qwp_ws_progress=manual`): every test of a sender runs with both.
//! A sender that is driven by its caller only queues the frames, and drives
//! itself where a flush has to wait for room in the queue.
//! The buffer may hold rows of several tables: the server commits each of
//! them once. Each frame brings the symbols that its rows are the first to
//! use on the connection. The flush waits until the queue has room for all
//! its frames, as long as `sf_append_deadline_millis` allows, and publishes
//! none of them before. When the queue has no room for them, a buffer whose
//! one frame fits the frame cap goes out as that frame, which waits only for
//! its own room. With `sf_dir` a frame after the first waits, beyond
//! `sf_append_deadline_millis`, for a spare segment file that the network
//! thread is making: the flush fails then when the file cannot be made or
//! that thread stops.
//! Such a sender refuses a buffer above `max_buf_size` with an error that
//! names `max_buf_size` and the size of the buffer, and a buffer whose frames
//! the queue can never hold together with one that names
//! `sf_max_total_bytes` and the value that would do. Both go by size bounds
//! that take more than the frame for symbols: such a buffer is sent as one
//! frame when that frame fits, and refused only when it does not.
//! Any other flush goes out as one frame, as before: a buffer that is too
//! large for one frame is refused. When a row that fits no frame is why the
//! buffer was not cut into several, the refusal names the table of the row,
//! the size of the frame it needs, and the frame cap. Nothing of a refused
//! buffer is published, and it keeps its rows.
//! A flush in frames that stops after its first frame was published fails
//! with `ErrorCode::FlushAborted`. Nothing of it is committed and the buffer
//! keeps its rows. The sender sends no frame of it from then on, and its
//! error is in doubt when a frame of it was sent before. The sender queues
//! nothing more: each later flush that gets as far as the queue fails with
//! the same error. It goes on delivering the flushes before the failed one:
//! `wait` and `close_drain` return once those are confirmed.
//! A frame of a flush that the server rejects leaves nothing of the flush
//! committed. A rejection for good stops the sender, which reports it at
//! `wait` and at `close_drain`. After any other the sender connects again
//! and sends the whole flush, which the server commits once.
//! A flush whose connection is lost is sent again whole on the next one,
//! wherever it was lost: the server commits it once, or a second time when
//! it had committed the flush and only its answer was lost. A server that
//! closes every connection during one flush stops the sender at the fourth
//! close. `close_drain` gives up at `close_flush_timeout`.
//!
//! The server is the model of [`crate::tests::qwp_ws_server_model`] behind a
//! socket: it holds the rows of a frame with the defer flag and commits at
//! every frame without it, so the number of its commits tells how the frames
//! of a flush were flagged. A test can make it keep its answers to itself, so
//! that what was flushed stays in the queue of the sender.

use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::ErrorCode;
use crate::ingress::sender::qwp_ws_sfa_manifest::fail_manifest_sync_after_for_test;
use crate::ingress::sender::{
    ConfirmationStoredHook, ConfirmationStoredHookGuard, HotSpareCreationHookGuard,
    LaterFrameHookGuard, before_hot_spare_creation_for_test, fail_sync_after_for_test,
};
use crate::ingress::{
    AckLevel, Buffer, QwpWsErrorCategory, QwpWsErrorPolicy, QwpWsSenderError, Sender,
    SenderBuilder, SymbolGlobalDict, TimestampMicros, TimestampNanos, decode_qwp_varint,
};
use crate::tests::qwp_ws::{
    read_frame, spawn_max_batch_size_upgrade_only_server, upgrade_mock_stream_with_max_batch_size,
    write_server_binary_frame, write_server_frame,
};
use crate::tests::qwp_ws_server_model::{
    ModelTable, QwpWsModelServer, QwpWsServerModel, add_rows, buffer_of, frame_of_a_sender,
    frame_of_a_whole_buffer, frames_of_a_flush, frames_of_a_sender, rows_of,
};

pub(super) const TABLE: &str = "flush_rows";
/// The tables of a flush over several tables, in the order of its buffer.
pub(super) const FIRST: &str = "first_rows";
pub(super) const SECOND: &str = "second_rows";
const THIRD: &str = "third_rows";
/// The frame limit the server tells, where a test names no other.
pub(super) const FRAME_LIMIT: usize = 1024;
pub(super) const WAIT: Duration = Duration::from_secs(10);
/// What the refusal of a frame says of a cap that is the server's frame limit.
const SET_BY_SERVER: &str = "the server's advertised X-QWP-Max-Batch-Size";
/// The same for a cap that is what a segment of the queue holds.
const SET_BY_SEGMENT: &str = "the sf_max_segment_bytes segment payload capacity";
/// What ends the refusal of a buffer above the frame cap that only the
/// server's silence about its frame limit keeps from going out in frames.
pub(super) const NO_FRAME_LIMIT_TOLD: &str = " It is not sent in several frames, because the \
    server has not told its frame limit: either the sender is not connected yet (flush again \
    once it is), or the server is too old to commit several frames together (upgrade it, or \
    flush smaller batches).";

/// How a sender makes its progress. Every test of a sender here runs once
/// for each: see [`in_both_progress_modes`].
#[derive(Clone, Copy)]
enum Progress {
    /// A thread of the sender sends what is queued and reads the answers.
    Background,
    /// Nobody does unless the test drives the sender: with `drive_once`, with
    /// `wait` or `close_drain`, or with a `flush` that waits for room.
    Manual,
}

thread_local! {
    /// The folder in which the senders of a test keep their queues, and how
    /// many senders the test has built: see [`on_disk`].
    static SF_DIR: std::cell::RefCell<Option<(tempfile::TempDir, usize)>> =
        const { std::cell::RefCell::new(None) };
}

/// Runs `test` with the queue of every sender it builds on disk: each
/// sender gets a slot of its own in a temporary `sf_dir`, as each has a
/// queue of its own in memory.
fn on_disk(test: fn(Progress), progress: Progress) {
    SF_DIR.with(|sf_dir| *sf_dir.borrow_mut() = Some((tempfile::TempDir::new().unwrap(), 0)));
    test(progress);
    SF_DIR.with(|sf_dir| sf_dir.borrow_mut().take());
}

fn sender_with(port: u16, progress: Progress, settings: &str) -> Sender {
    let mode = match progress {
        Progress::Background => "",
        Progress::Manual => "qwp_ws_progress=manual;",
    };
    // A test that names its `sf_dir` keeps it.
    let slot = SF_DIR
        .with(|sf_dir| {
            let mut sf_dir = sf_dir.borrow_mut();
            let (dir, senders) = sf_dir.as_mut().filter(|_| !settings.contains("sf_dir="))?;
            *senders += 1;
            Some(format!(
                "sf_dir={};sender_id=sender{senders};",
                dir.path().display()
            ))
        })
        .unwrap_or_default();
    SenderBuilder::from_conf(format!("ws::addr=127.0.0.1:{port};{mode}{slot}{settings}"))
        .unwrap()
        .build()
        .unwrap()
}

/// Gives `sender` the time to send and to read, or makes it do so.
fn let_it_work(sender: &mut Sender, progress: Progress) {
    match progress {
        Progress::Background => thread::sleep(Duration::from_millis(1)),
        Progress::Manual => {
            sender.drive_once().unwrap();
        }
    }
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
pub(super) fn buffer_of_len(first_id: i64, len: usize) -> Buffer {
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
pub(super) fn assert_table_holds(
    server: &QwpWsModelServer,
    table: &str,
    commits: u64,
    buffers: &[&Buffer],
) {
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
pub(super) fn add_symbol_row(buffer: &mut Buffer, table: &str, id: i64) {
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
pub(super) fn buffer_of_symbols(table: &str, ids: std::ops::Range<i64>) -> Buffer {
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

fn a_flush_with_symbols_above_the_frame_cap_is_one_commit(progress: Progress) {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let mut sender = sender_with(server.port, progress, "");
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

fn a_flush_with_symbols_that_loses_its_connection_part_way_is_sent_again_whole(progress: Progress) {
    // The server takes the flush before and eleven frames of the large
    // flush, and ends the connection.
    const CUT_AFTER_FRAMES: usize = 12;
    let server = QwpWsModelServer::start_cutting_first_connection(FRAME_LIMIT, CUT_AFTER_FRAMES);
    let mut sender = sender_with(server.port, progress, "");
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

fn a_buffer_with_a_symbol_that_a_connection_refuses_is_refused_before_its_first_frame(
    progress: Progress,
) {
    // A frame limit that a symbol of the longest size fits.
    const LIMIT: usize = 2 * 1024 * 1024;
    const LONGEST: usize = 1 << 20;
    let server = QwpWsModelServer::start(LIMIT);
    let mut sender = sender_with(server.port, progress, "");
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

fn a_flush_above_the_frame_cap_is_one_commit(progress: Progress) {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let mut sender = sender_with(server.port, progress, "");
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

fn a_flush_that_loses_its_connection_part_way_is_sent_again_whole(progress: Progress) {
    // The server takes the flush before and five frames of the large flush,
    // and ends the connection.
    const CUT_AFTER_FRAMES: usize = 6;
    let server = QwpWsModelServer::start_cutting_first_connection(FRAME_LIMIT, CUT_AFTER_FRAMES);
    let mut sender = sender_with(server.port, progress, "");
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

fn a_flush_of_several_tables_above_the_frame_cap_is_one_commit_of_each_table(progress: Progress) {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let mut sender = sender_with(server.port, progress, "");
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

fn a_flush_of_several_tables_that_loses_its_connection_part_way_is_sent_again_whole(
    progress: Progress,
) {
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
    let mut sender = sender_with(server.port, progress, "");

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

fn a_flush_with_a_column_of_every_kind_above_the_frame_cap_is_one_commit(progress: Progress) {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let mut sender = sender_with(server.port, progress, "");
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

fn a_buffer_with_a_decimal_that_cannot_be_written_is_refused_before_its_first_frame(
    progress: Progress,
) {
    const TWO_DIGITS: &str = "cannot rescale decimal from scale 2 to 1 without precision loss";
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let mut sender = sender_with(server.port, progress, "");
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

/// A DECIMAL64 value without digits after the point, behind the first frame
/// in a column of one such digit, is multiplied by ten when it is written.
/// The largest that stays within DECIMAL64 is sent in frames, of either sign;
/// the next one is refused before the first frame, nothing is sent and the
/// sender stays usable.
#[test]
fn a_flush_in_frames_takes_a_rescaled_decimal_up_to_the_limit_of_decimal64() {
    const PAST_THE_LIMIT: &str = "decimal value does not fit DECIMAL64 wire width";
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let mut sender = sender_with(server.port, Progress::Background, "");
    let buffer_ending_with = |value: &str| {
        let mut buffer = buffer_of_decimals(0..2000, None);
        buffer
            .table(TABLE)
            .unwrap()
            .column_i64("id", 2000)
            .unwrap()
            .column_dec64("price", value)
            .unwrap()
            .at(TimestampNanos::new(1_700_000_000_000_000_000 + 2000))
            .unwrap();
        buffer
    };

    for value in ["922337203685477581", "-922337203685477581"] {
        let mut refused = buffer_ending_with(value);
        assert!(refused.len() > FRAME_LIMIT);
        let (rows, len) = (refused.row_count(), refused.len());
        let err = sender.flush(&mut refused).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall, "{}", err.msg());
        assert_eq!(err.msg(), PAST_THE_LIMIT, "{value}");
        assert_eq!(sender.published_fsn().unwrap(), None, "{value}");
        assert_eq!((refused.row_count(), refused.len()), (rows, len));
        assert!(!sender.must_close());
    }

    let largest = buffer_ending_with("922337203685477580");
    let smallest = buffer_ending_with("-922337203685477580");
    let frame_count = frames_of_a_flush(&largest, FRAME_LIMIT).len() as u64;
    assert!(frame_count > 40, "{frame_count} frames");
    assert_eq!(
        sender.flush_and_keep_and_get_fsn(&largest).unwrap(),
        Some(frame_count - 1)
    );
    assert_eq!(
        sender.flush_and_keep_and_get_fsn(&smallest).unwrap(),
        Some(2 * frame_count - 1)
    );
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_table_holds(&server, TABLE, 2, &[&largest, &smallest]);
    let held = server.model.table(TABLE).unwrap().rows_as_text();
    // 9223372036854775800 and its negative, of scale 1.
    for (row, unscaled) in [
        (2000, "[127, 255, 255, 255, 255, 255, 255, 248]"),
        (4001, "[128, 0, 0, 0, 0, 0, 0, 8]"),
    ] {
        let decimal = format!("Decimal {{ scale: 1, unscaled_be: {unscaled} }}");
        assert!(held[row].contains(&decimal), "{}", held[row]);
    }
    drop(sender);
    server.finish();
}

/// A sender in manual progress mode queues the frames of a flush and sends
/// none of them. The server gets them when the caller drives the sender, a
/// frame a call at most, and commits them when it has the last one.
#[test]
fn a_flush_in_manual_progress_mode_is_sent_when_its_caller_drives() {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    // Segments of 1,024 bytes, two frames each: the flush fills many.
    let settings = "sf_max_segment_bytes=1024;sf_max_total_bytes=131072;";
    let mut sender = sender_with(server.port, Progress::Manual, settings);
    assert_eq!(sender.effective_frame_cap().unwrap(), (992, true));
    let large = buffer_of(TABLE, 0..2000);
    let frame_count = frames_of_a_flush(&large, 492).len();
    assert!(frame_count > 100, "{frame_count} frames");
    let last_fsn = Some(frame_count as u64 - 1);

    assert_eq!(sender.flush_and_keep_and_get_fsn(&large).unwrap(), last_fsn);
    assert_eq!(sender.published_fsn().unwrap(), last_fsn);
    thread::sleep(Duration::from_millis(100));
    assert_eq!(server.frames_taken(), 0, "the flush sends nothing");
    assert_eq!(sender.completed_fsn(AckLevel::Ok).unwrap(), None);

    // A call less than the flush has frames: the server lacks the last one,
    // holds the rows of the others and has committed none.
    for _ in 1..frame_count {
        sender.drive_once().unwrap();
    }
    let sent = sender.qwp_ws_totals().unwrap().frames_sent as usize;
    assert!((1..frame_count).contains(&sent), "{sent} frames sent");
    wait_for_frames_taken(&server, sent);
    assert_table_holds(&server, TABLE, 0, &[]);
    assert_eq!(sender.completed_fsn(AckLevel::Ok).unwrap(), None);

    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_eq!(sender.completed_fsn(AckLevel::Ok).unwrap(), last_fsn);
    assert_eq!(server.frames_taken(), frame_count);
    assert_table_holds(&server, TABLE, 1, &[&large]);
    assert!(!sender.must_close());
    drop(sender);
    server.finish();
}

/// The settings of a sender whose queue is the slot `large` of `sf_dir`, in
/// segments of 4,096 bytes: one holds three or four frames of a flush that
/// is cut for a frame limit of 1,024 bytes.
pub(super) fn slot_settings(sf_dir: &tempfile::TempDir) -> String {
    format!(
        "sf_dir={};sender_id=large;sf_max_segment_bytes=4096;",
        sf_dir.path().display()
    )
}

/// How many segment files the slot of [`slot_settings`] holds.
fn segment_files(sf_dir: &tempfile::TempDir) -> usize {
    std::fs::read_dir(sf_dir.path().join("large"))
        .unwrap()
        .flatten()
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "sfa"))
        .count()
}

/// Waits until the server has committed to `table` `commits` times.
fn wait_for_commits(
    sender: &mut Sender,
    progress: Progress,
    server: &QwpWsModelServer,
    table: &str,
    commits: u64,
) {
    let deadline = Instant::now() + WAIT;
    while server.model.table(table).map(|held| held.commits) != Some(commits) {
        assert!(
            Instant::now() < deadline,
            "the server committed to {table} {:?} times, not {commits}",
            server.model.table(table).map(|held| held.commits)
        );
        let_it_work(sender, progress);
    }
}

/// Takes the server away from a sender that has nothing to send, and waits
/// until the sender has found that out: its flush of `unsent`, which stays
/// in the queue, makes it look.
fn take_the_server_away(
    sender: &mut Sender,
    progress: Progress,
    server: &QwpWsModelServer,
    unsent: &Buffer,
) {
    server.go_down();
    sender.flush_and_keep(unsent).unwrap();
    let deadline = Instant::now() + WAIT;
    while sender.qwp_ws_totals().unwrap().reconnect_attempts < 2 {
        assert!(Instant::now() < deadline, "the sender did not reconnect");
        let_it_work(sender, progress);
    }
}

/// What makes a sender try a server that is away again soon.
pub(super) const RECONNECT_SOON: &str =
    "reconnect_initial_backoff_millis=10;reconnect_max_backoff_millis=20;";
/// What makes a sender end without waiting for what its server has not
/// confirmed. Its slot keeps its files then, whatever was confirmed.
pub(super) const NO_WAIT_AT_THE_END: &str = "close_flush_timeout_millis=0;";

fn a_flush_in_frames_with_sf_dir_leaves_no_segment_file_once_it_is_confirmed(progress: Progress) {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    // What is flushed stays in the queue until the server answers.
    server.hold_answers();
    let sf_dir = tempfile::TempDir::new().unwrap();
    let mut sender = sender_with(server.port, progress, &slot_settings(&sf_dir));
    assert_eq!(sender.effective_frame_cap().unwrap(), (FRAME_LIMIT, true));
    let large = buffer_of_symbols(TABLE, 0..600);
    let frames = frames_of_a_sender(&large, FRAME_LIMIT, &mut SymbolGlobalDict::new()).len();
    assert!(frames > 12, "{frames} frames");

    assert_eq!(
        sender.flush_and_keep_and_get_fsn(&large).unwrap(),
        Some(frames as u64 - 1)
    );
    let files = segment_files(&sf_dir);
    assert!(files >= frames / 4, "{files} files for {frames} frames");
    server.let_answers_go();
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_table_holds(&server, TABLE, 1, &[&large]);
    assert!(!sender.must_close());

    sender.close_drain().unwrap();
    assert_eq!(segment_files(&sf_dir), 0);
    drop(sender);
    server.finish();
}

/// The frames of a flush that need a new segment each, in a queue of
/// segments of `segment` bytes whose segment in use holds frames of `held`
/// bytes. A segment has a header of 24 bytes, and each frame one of 8.
fn frames_that_take_a_new_segment(
    segment: usize,
    held: &[usize],
    frames: &[Vec<u8>],
) -> Vec<usize> {
    let mut used = 24 + held.iter().map(|len| 8 + len).sum::<usize>();
    assert!(used <= segment, "{held:?}");
    let mut taking = Vec::new();
    for (index, frame) in frames.iter().enumerate() {
        if used + 8 + frame.len() > segment {
            taking.push(index);
            used = 24;
        }
        used += 8 + frame.len();
    }
    taking
}

/// What stops a flush in frames with `sf_dir` after its first frame.
#[derive(Clone, Copy)]
enum StoppedBy {
    /// A frame brings a symbol more than the dictionary of the sender takes.
    FullDictionary,
    /// A frame needs a new segment, and the manifest that names the segment
    /// cannot be synced.
    ManifestSync,
    /// With `sf_durability=periodic`: a frame needs a new segment, and the
    /// segment that it leaves cannot be synced.
    SegmentSync,
}

/// A flush that the server has confirmed, one that it has not, and a flush
/// in frames that stops part way: at frame `which(frame count)` when the
/// dictionary is full, else at the frame that takes new segment number
/// `which(count of such frames)`. The sender is dropped as it is, with the
/// frames of the stopped flush in its slot.
///
/// A new sender on the slot delivers the flush that was not confirmed and
/// nothing of the stopped one, takes the same buffer again, and then a
/// flush with symbols that the slot knows and new ones.
fn assert_a_new_sender_on_the_slot_sends_nothing_of_a_flush_that_stopped(
    progress: Progress,
    stopped_by: StoppedBy,
    which: fn(usize) -> usize,
) {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let sf_dir = tempfile::TempDir::new().unwrap();
    let durability = match stopped_by {
        StoppedBy::SegmentSync => "sf_durability=periodic;sf_sync_interval_millis=3600000;",
        _ => "",
    };
    let settings = format!("{}{RECONNECT_SOON}{durability}", slot_settings(&sf_dir));
    let dropped = format!("{settings}{NO_WAIT_AT_THE_END}");
    let before = buffer_of_symbols(TABLE, 0..10);
    let unsent = buffer_of_symbols(TABLE, 5..15);
    let mut large = buffer_of_symbols(TABLE, 10..1210);
    let (rows, len) = (large.row_count(), large.len());
    let mut sender_symbols = SymbolGlobalDict::new();
    let held = [
        frame_of_a_sender(&before, false, &mut sender_symbols).len(),
        frame_of_a_sender(&unsent, false, &mut sender_symbols).len(),
    ];
    let frames = frames_of_a_sender(&large, FRAME_LIMIT, &mut sender_symbols);
    assert!(frames.len() > 40, "{} frames", frames.len());
    let taking = frames_that_take_a_new_segment(4096, &held, &frames);
    assert!(taking.len() > 8 && taking[0] > 0, "{taking:?}");
    let (failing, cause) = match stopped_by {
        StoppedBy::FullDictionary => (which(frames.len()), "symbol dictionary reached its"),
        StoppedBy::ManifestSync => (
            taking[which(taking.len())],
            "injected SF manifest sync failure",
        ),
        StoppedBy::SegmentSync => (
            taking[which(taking.len())],
            "injected periodic SF sync failure",
        ),
    };
    assert!((1..frames.len()).contains(&failing));

    let mut sender = match stopped_by {
        StoppedBy::FullDictionary => {
            let _cap = crate::ingress::TestDictCapGuard::new(symbols_held_before(&frames[failing]));
            sender_with(server.port, progress, &dropped)
        }
        _ => sender_with(server.port, progress, &dropped),
    };
    assert_eq!(sender.flush_and_keep_and_get_fsn(&before).unwrap(), Some(0));
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    take_the_server_away(&mut sender, progress, &server, &unsent);

    // The new segments that the flush gets before the one that it does not.
    let segments_before = taking.iter().filter(|frame| **frame < failing).count();
    match stopped_by {
        StoppedBy::FullDictionary => {}
        StoppedBy::ManifestSync => fail_manifest_sync_after_for_test(segments_before),
        StoppedBy::SegmentSync => fail_sync_after_for_test(segments_before),
    }
    let err = sender.flush(&mut large).unwrap_err();
    assert_eq!(err.code(), ErrorCode::FlushAborted, "{}", err.msg());
    assert!(
        err.msg()
            .starts_with("Could not flush buffer: the flush stopped part way: ")
            && err.msg().contains(cause),
        "{}",
        err.msg()
    );
    assert!(!err.in_doubt());
    assert!(sender.must_close());
    assert_eq!(
        (large.row_count(), large.len()),
        (rows, len),
        "the buffer keeps its rows"
    );
    assert_eq!(sender.published_fsn().unwrap(), Some(1));
    assert!(segment_files(&sf_dir) > segments_before);
    drop(sender);
    assert_table_holds(&server, TABLE, 1, &[&before]);

    server.come_back();
    let mut sender = sender_with(server.port, progress, &settings);
    wait_for_commits(&mut sender, progress, &server, TABLE, 2);
    assert_table_holds(&server, TABLE, 2, &[&before, &unsent]);
    sender.flush(&mut large).unwrap();
    assert!(large.is_empty());
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    let large = buffer_of_symbols(TABLE, 10..1210);
    assert_table_holds(&server, TABLE, 3, &[&before, &unsent, &large]);
    let after = buffer_of_symbols(TABLE, 1200..1220);
    sender.flush_and_keep(&after).unwrap();
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_table_holds(&server, TABLE, 4, &[&before, &unsent, &large, &after]);
    assert!(!sender.must_close());

    sender.close_drain().unwrap();
    assert_eq!(segment_files(&sf_dir), 0);
    drop(sender);
    server.finish();
}

fn a_new_sender_on_the_slot_sends_nothing_of_a_flush_that_a_full_dictionary_stopped(
    progress: Progress,
) {
    for which in [|_| 1, |frames| frames / 2, |frames| frames - 1] {
        assert_a_new_sender_on_the_slot_sends_nothing_of_a_flush_that_stopped(
            progress,
            StoppedBy::FullDictionary,
            which,
        );
    }
}

fn a_new_sender_on_the_slot_sends_nothing_of_a_flush_that_a_manifest_sync_stopped(
    progress: Progress,
) {
    for which in [|_| 0, |segments| segments / 2, |segments| segments - 1] {
        assert_a_new_sender_on_the_slot_sends_nothing_of_a_flush_that_stopped(
            progress,
            StoppedBy::ManifestSync,
            which,
        );
    }
}

fn a_new_sender_on_the_slot_sends_nothing_of_a_flush_that_a_segment_sync_stopped(
    progress: Progress,
) {
    for which in [|_| 0, |segments| segments / 2, |segments| segments - 1] {
        assert_a_new_sender_on_the_slot_sends_nothing_of_a_flush_that_stopped(
            progress,
            StoppedBy::SegmentSync,
            which,
        );
    }
}

fn a_flush_in_frames_that_its_sender_did_not_deliver_is_one_commit_of_a_new_sender_on_the_slot(
    progress: Progress,
) {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let sf_dir = tempfile::TempDir::new().unwrap();
    let settings = format!("{}{RECONNECT_SOON}", slot_settings(&sf_dir));
    let dropped = format!("{settings}{NO_WAIT_AT_THE_END}");
    let before = buffer_of_symbols(TABLE, 0..10);
    let unsent = buffer_of_symbols(TABLE, 5..15);
    let large = buffer_of_symbols(TABLE, 10..1210);
    let mut sender_symbols = SymbolGlobalDict::new();
    frame_of_a_sender(&before, false, &mut sender_symbols);
    frame_of_a_sender(&unsent, false, &mut sender_symbols);
    let frames = frames_of_a_sender(&large, FRAME_LIMIT, &mut sender_symbols).len();

    let mut sender = sender_with(server.port, progress, &dropped);
    assert_eq!(sender.flush_and_keep_and_get_fsn(&before).unwrap(), Some(0));
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    take_the_server_away(&mut sender, progress, &server, &unsent);
    // The server told its frame limit, and the sender still goes by it.
    assert_eq!(
        sender.flush_and_keep_and_get_fsn(&large).unwrap(),
        Some(1 + frames as u64)
    );
    assert!(!sender.must_close());
    drop(sender);
    assert_table_holds(&server, TABLE, 1, &[&before]);

    server.come_back();
    let mut sender = sender_with(server.port, progress, &settings);
    wait_for_commits(&mut sender, progress, &server, TABLE, 3);
    assert_table_holds(&server, TABLE, 3, &[&before, &unsent, &large]);
    let after = buffer_of_symbols(TABLE, 1200..1220);
    sender.flush_and_keep(&after).unwrap();
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_table_holds(&server, TABLE, 4, &[&before, &unsent, &large, &after]);

    sender.close_drain().unwrap();
    assert_eq!(segment_files(&sf_dir), 0);
    drop(sender);
    server.finish();
}

fn a_flush_in_frames_with_periodic_durability_is_queued_while_the_server_is_away(
    progress: Progress,
) {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let sf_dir = tempfile::TempDir::new().unwrap();
    let settings = format!(
        "{}{RECONNECT_SOON}sf_durability=periodic;sf_append_deadline_millis=2000;",
        slot_settings(&sf_dir)
    );
    let before = buffer_of_symbols(TABLE, 0..10);
    let unsent = buffer_of_symbols(TABLE, 5..15);
    let large = buffer_of_symbols(TABLE, 10..1210);
    let mut sender_symbols = SymbolGlobalDict::new();
    frame_of_a_sender(&before, false, &mut sender_symbols);
    frame_of_a_sender(&unsent, false, &mut sender_symbols);
    let frames = frames_of_a_sender(&large, FRAME_LIMIT, &mut sender_symbols).len();

    let mut sender = sender_with(server.port, progress, &settings);
    assert_eq!(sender.flush_and_keep_and_get_fsn(&before).unwrap(), Some(0));
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    take_the_server_away(&mut sender, progress, &server, &unsent);
    // Every segment that the flush fills is synced where it is appended.
    assert_eq!(
        sender.flush_and_keep_and_get_fsn(&large).unwrap(),
        Some(1 + frames as u64)
    );
    assert!(segment_files(&sf_dir) >= frames / 4);

    // The server is back, and the same sender delivers what it queued.
    server.come_back();
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_table_holds(&server, TABLE, 3, &[&before, &unsent, &large]);
    sender.close_drain().unwrap();
    assert_eq!(segment_files(&sf_dir), 0);
    drop(sender);
    server.finish();
}

fn a_new_sender_on_the_slot_knows_the_symbols_of_a_flush_whose_segments_are_freed(
    progress: Progress,
) {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let sf_dir = tempfile::TempDir::new().unwrap();
    let settings = format!("{}{RECONNECT_SOON}", slot_settings(&sf_dir));
    let dropped = format!("{settings}{NO_WAIT_AT_THE_END}");
    let first = buffer_of_symbols(TABLE, 0..600);
    // It uses symbols that the first flush brought, and brings new ones.
    let second = buffer_of_symbols(TABLE, 590..1190);
    let mut sender_symbols = SymbolGlobalDict::new();
    let first_frames = frames_of_a_sender(&first, FRAME_LIMIT, &mut sender_symbols).len();
    let second_frames = frames_of_a_sender(&second, FRAME_LIMIT, &mut sender_symbols);
    assert!(first_frames > 12 && second_frames.len() > 12);
    assert!(symbols_held_before(&second_frames[0]) > 100);

    let mut sender = sender_with(server.port, progress, &dropped);
    sender.flush_and_keep(&first).unwrap();
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_table_holds(&server, TABLE, 1, &[&first]);
    // The sender frees the segments of the confirmed frames: the slot keeps
    // the segment in use, and a spare one.
    let deadline = Instant::now() + WAIT;
    while segment_files(&sf_dir) > 2 {
        assert!(Instant::now() < deadline, "the segments were not freed");
        let_it_work(&mut sender, progress);
    }

    // The frames of the second flush stay in the slot. They name the
    // symbols of the first by their numbers.
    server.go_down();
    sender.flush_and_keep(&second).unwrap();
    drop(sender);

    server.come_back();
    let mut sender = sender_with(server.port, progress, &settings);
    wait_for_commits(&mut sender, progress, &server, TABLE, 2);
    assert_table_holds(&server, TABLE, 2, &[&first, &second]);
    sender.close_drain().unwrap();
    drop(sender);
    server.finish();
}

fn a_flush_whose_first_frame_gets_no_segment_takes_its_symbols_out_of_the_symbol_file(
    progress: Progress,
) {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let sf_dir = tempfile::TempDir::new().unwrap();
    // Segments of 1,024 bytes: the frame cap is 992 bytes, and a flush is
    // cut for two frames a segment, of 492 bytes.
    let settings = format!(
        "sf_dir={};sender_id=large;sf_max_segment_bytes=1024;",
        sf_dir.path().display()
    );
    let symbol_file = sf_dir
        .path()
        .join("large")
        .join(crate::ingress::sender::qwp_ws_sfa_symbol_dict::FILE_NAME);
    // One frame that leaves its segment no room for a frame of the flush
    // after it.
    let before = buffer_of_symbols(TABLE, 0..16);
    let mut large = buffer_of_symbols(TABLE, 120..320);
    let (rows, len) = (large.row_count(), large.len());
    let mut sender_symbols = SymbolGlobalDict::new();
    let held = [frame_of_a_sender(&before, false, &mut sender_symbols).len()];
    let frames = frames_of_a_sender(&large, 492, &mut sender_symbols);
    assert!(held[0] <= 992 && frames.len() > 6, "{held:?}");
    assert!(!symbols_brought_by(&frames[0]).1.is_empty());
    assert_eq!(
        frames_that_take_a_new_segment(1024, &held, &frames).first(),
        Some(&0),
        "{held:?}"
    );

    let mut sender = sender_with(server.port, progress, &settings);
    assert_eq!(sender.effective_frame_cap().unwrap(), (992, true));
    assert_eq!(sender.flush_and_keep_and_get_fsn(&before).unwrap(), Some(0));
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    let symbol_bytes = std::fs::metadata(&symbol_file).unwrap().len();

    fail_manifest_sync_after_for_test(0);
    let err = sender.flush(&mut large).unwrap_err();
    assert_eq!(err.code(), ErrorCode::SocketError, "{}", err.msg());
    assert!(
        err.msg().contains("injected SF manifest sync failure"),
        "{}",
        err.msg()
    );
    assert_eq!(
        sender.published_fsn().unwrap(),
        Some(0),
        "nothing is published"
    );
    assert_eq!(
        (large.row_count(), large.len()),
        (rows, len),
        "the buffer keeps its rows"
    );
    assert_eq!(
        std::fs::metadata(&symbol_file).unwrap().len(),
        symbol_bytes,
        "the symbols of the frame that was not published stayed in the symbol file"
    );

    // The same flush goes through, and its symbols get the same numbers.
    assert_eq!(
        sender.flush_and_keep_and_get_fsn(&large).unwrap(),
        Some(frames.len() as u64)
    );
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_table_holds(&server, TABLE, 2, &[&before, &large]);
    assert!(std::fs::metadata(&symbol_file).unwrap().len() > symbol_bytes);
    drop(sender);
    server.finish();
}

fn a_sender_whose_slot_has_no_symbol_file_refuses_a_buffer_above_the_frame_cap(progress: Progress) {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let sf_dir = tempfile::TempDir::new().unwrap();
    // A folder where the symbol file of the slot belongs: the sender cannot
    // make the file, and sends every symbol with every frame.
    let symbol_file = sf_dir
        .path()
        .join("large")
        .join(crate::ingress::sender::qwp_ws_sfa_symbol_dict::FILE_NAME);
    std::fs::create_dir_all(&symbol_file).unwrap();
    let mut sender = sender_with(server.port, progress, &slot_settings(&sf_dir));
    assert_eq!(sender.effective_frame_cap().unwrap(), (FRAME_LIMIT, true));
    let mut large = buffer_of_symbols(TABLE, 0..600);

    let refusal = refusal_of(&mut sender, &mut large);
    let end = format!(
        " bytes exceeds the per-frame cap of {FRAME_LIMIT} bytes. The cap is set by \
         {SET_BY_SERVER}. It is not sent in several frames, because this sender could not \
         write the symbol file of its store-and-forward slot: flush smaller batches, or close \
         the sender, see to the disk of sf_dir, and build a new one."
    );
    assert!(
        refusal.starts_with("Could not flush buffer: QWP/WebSocket encoded message size of ")
            && refusal.ends_with(&end),
        "got: {refusal}"
    );
    // Buffers that fit one frame are sent as before.
    let small = [
        buffer_of_symbols(TABLE, 0..10),
        buffer_of_symbols(TABLE, 5..15),
    ];
    for buffer in &small {
        sender.flush_and_keep(buffer).unwrap();
    }
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_table_holds(&server, TABLE, 2, &[&small[0], &small[1]]);
    drop(sender);
    server.finish();
}

fn a_sender_whose_server_tells_no_frame_limit_refuses_a_buffer_above_the_frame_cap(
    progress: Progress,
) {
    let port = spawn_max_batch_size_upgrade_only_server(None);
    // The cap is then what a segment of the queue holds: its 4,096 bytes
    // less the headers of the segment and of a frame, 24 and 8 bytes. This
    // server answers no frame: the sender does not wait for it at its end.
    let settings = "sf_max_segment_bytes=4096;close_flush_timeout_millis=0;";
    let mut sender = sender_with(port, progress, settings);
    assert_eq!(sender.effective_frame_cap().unwrap(), (4064, false));
    let mut large = buffer_of(TABLE, 0..2000);

    // The refusal says what keeps the buffer from going out in frames.
    let refusal = refusal_of(&mut sender, &mut large);
    let end = format!(
        " bytes exceeds the per-frame cap of 4064 bytes. The cap is set by \
         {SET_BY_SEGMENT}.{NO_FRAME_LIMIT_TOLD}"
    );
    assert!(refusal.ends_with(&end), "got: {refusal}");
    // A buffer that fits one frame is sent as before.
    sender.flush(&mut buffer_of(TABLE, 0..3)).unwrap();

    // Where `max_buf_size` is the cap, no server would get the buffer in
    // frames, and the refusal says no more than before.
    let port = spawn_max_batch_size_upgrade_only_server(None);
    let mut sender = sender_with(
        port,
        progress,
        "sf_max_segment_bytes=4096;max_buf_size=3000;",
    );
    assert_eq!(sender.effective_frame_cap().unwrap(), (3000, false));
    assert_refused_as_one_frame(&mut sender, &mut large, 3000, "max_buf_size");

    // With `sf_dir` the refusal says the same.
    let port = spawn_max_batch_size_upgrade_only_server(None);
    let sf_dir = tempfile::TempDir::new().unwrap();
    let settings = format!(
        "sf_dir={};sender_id=large;sf_max_segment_bytes=4096;close_flush_timeout_millis=0;",
        sf_dir.path().display()
    );
    let mut sender = sender_with(port, progress, &settings);
    assert_eq!(sender.effective_frame_cap().unwrap(), (4064, false));
    assert!(refusal_of(&mut sender, &mut large).ends_with(&end));
}

/// A segment of 4,096 bytes holds two frames of 2,028 bytes: its header of
/// 24 bytes, and twice a frame with its header of 8.
const TWO_FRAME_TARGET: usize = 2028;
/// A frame limit above [`TWO_FRAME_TARGET`] and below what a segment of
/// 4,096 bytes holds: the frame cap of a sender with such segments.
const LIMIT_ABOVE_TARGET: usize = 3000;

/// Rows without symbols whose one frame, on a connection that holds fewer
/// than 128 symbols, takes `frame_len` bytes. The size bound of the buffer
/// takes two bytes more: it counts three for the id that the symbols of the
/// frame start at, which such a frame writes in one.
fn buffer_of_frame_len(first_id: i64, frame_len: usize) -> Buffer {
    let buffer = buffer_of_len(first_id, frame_len + 2);
    let frame = frame_of_a_sender(&buffer, false, &mut SymbolGlobalDict::new());
    assert_eq!(frame.len(), frame_len);
    buffer
}

/// The encoded frame decides whether a buffer is cut, not its size bound: a
/// buffer whose frame is exactly the frame cap is one frame, though its
/// bound is above the cap, and a frame one byte larger makes two.
fn a_buffer_whose_frame_is_exactly_the_frame_cap_is_one_frame_and_one_byte_more_makes_two(
    progress: Progress,
) {
    let server = QwpWsModelServer::start(LIMIT_ABOVE_TARGET);
    let mut sender = sender_with(server.port, progress, "sf_max_segment_bytes=4096;");
    assert_eq!(
        sender.effective_frame_cap().unwrap(),
        (LIMIT_ABOVE_TARGET, true)
    );
    let at_cap = buffer_of_frame_len(0, LIMIT_ABOVE_TARGET);
    assert!(at_cap.len() > LIMIT_ABOVE_TARGET);
    let above_cap = buffer_of_frame_len(1000, LIMIT_ABOVE_TARGET + 1);

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

fn a_flush_is_cut_for_two_frames_a_segment_and_a_larger_row_travels_alone(progress: Progress) {
    let server = QwpWsModelServer::start(LIMIT_ABOVE_TARGET);
    let mut sender = sender_with(server.port, progress, "sf_max_segment_bytes=4096;");
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

fn a_buffer_of_exactly_max_buf_size_is_sent_in_frames_and_one_byte_more_is_refused(
    progress: Progress,
) {
    const MAX_BUF_SIZE: usize = 8192;
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let mut sender = sender_with(server.port, progress, "max_buf_size=8192;");
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

fn a_buffer_above_max_buf_size_is_refused_for_its_size_or_for_a_value_that_cannot_be_sent(
    progress: Progress,
) {
    const MAX_BUF_SIZE: usize = 8192;
    const TWO_DIGITS: &str = "cannot rescale decimal from scale 2 to 1 without precision loss";
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let mut sender = sender_with(server.port, progress, "max_buf_size=8192;");

    // A buffer above `max_buf_size` goes the way of one frame, whose encoder
    // names a decimal that it refuses.
    let mut with_a_value = buffer_of_decimals(0..2000, Some(1500));
    assert!(with_a_value.len() > MAX_BUF_SIZE);
    let (rows, len) = (with_a_value.row_count(), with_a_value.len());
    let err = sender.flush(&mut with_a_value).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidApiCall, "{}", err.msg());
    assert_eq!(err.msg(), TWO_DIGITS);
    assert_eq!(sender.published_fsn().unwrap(), None);
    assert_eq!((with_a_value.row_count(), with_a_value.len()), (rows, len));

    // The buffer with a row that fits no frame is too large for one frame:
    // it is refused for its size.
    let mut with_a_row = buffer_of(TABLE, 0..2000);
    add_row(&mut with_a_row, 2000, &"x".repeat(FRAME_LIMIT));
    assert!(with_a_row.len() > MAX_BUF_SIZE);
    assert_refused_for_max_buf_size(&mut sender, &mut with_a_row, MAX_BUF_SIZE);
    assert!(server.model.table(TABLE).is_none());
    drop(sender);
    server.finish();
}

fn a_max_buf_size_below_the_frame_limit_is_held_against_the_frame_of_the_buffer(
    progress: Progress,
) {
    const MAX_BUF_SIZE: usize = 2000;
    let server = QwpWsModelServer::start(LIMIT_ABOVE_TARGET);
    let mut sender = sender_with(server.port, progress, "max_buf_size=2000;");
    // `max_buf_size` is the frame cap then, and no buffer goes out in frames.
    assert_eq!(sender.effective_frame_cap().unwrap(), (MAX_BUF_SIZE, true));
    let at_max = buffer_of_len(0, MAX_BUF_SIZE);
    // The frame of this buffer takes two bytes less than the size that the
    // buffer gives, which is within the frame cap: the buffer is above
    // `max_buf_size`, and goes out as one frame all the same.
    let above_max = buffer_of_len(1000, MAX_BUF_SIZE + 1);
    assert_eq!(
        frame_of_a_whole_buffer(&above_max, false).len(),
        MAX_BUF_SIZE - 1
    );
    // Rows with symbols, whose frame is above `max_buf_size`.
    let mut too_large = buffer_of_symbols(FIRST, 0..200);
    assert!(
        frame_of_a_sender(&too_large, false, &mut SymbolGlobalDict::new()).len() > MAX_BUF_SIZE
    );

    assert_eq!(sender.flush_and_keep_and_get_fsn(&at_max).unwrap(), Some(0));
    assert_sent_as_one_frame(&server, &mut sender, &above_max, TABLE);
    assert_refused_for_max_buf_size(&mut sender, &mut too_large, MAX_BUF_SIZE);

    // The sender goes on. The symbols of the refused buffer are not taken
    // as sent: the frame of a later buffer brings those it uses.
    let after = buffer_of_symbols(FIRST, 0..10);
    assert_sent_as_one_frame(&server, &mut sender, &after, FIRST);
    let table = server.model.table(TABLE).unwrap();
    assert_eq!((table.commits, table.blocks.len()), (2, 2));
    assert_eq!(table.rows_as_text(), rows_of_all(&[&at_max, &above_max]));
    assert_table_holds(&server, FIRST, 1, &[&after]);
    drop(sender);
    server.finish();
}

/// The frame limit that a QuestDB server tells by default.
const SERVER_DEFAULT_FRAME_LIMIT: usize = 2 * 1024 * 1024;

/// Flushes `buffer`, of one `table`, whose size bound holds it back from
/// frames while its frame fits the frame cap: it goes out as one frame,
/// which the server commits once.
fn assert_sent_as_one_frame(
    server: &QwpWsModelServer,
    sender: &mut Sender,
    buffer: &Buffer,
    table: &str,
) {
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    let frames = server.frames_taken();
    let commits = server.model.table(table).map_or(0, |held| held.commits);
    let fsn = sender.published_fsn().unwrap().map_or(0, |fsn| fsn + 1);

    assert_eq!(
        sender.flush_and_keep_and_get_fsn(buffer).unwrap(),
        Some(fsn)
    );
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_eq!(server.frames_taken(), frames + 1, "one frame");
    let held = server.model.table(table).unwrap();
    assert_eq!(held.commits, commits + 1);
    let rows: Vec<String> = held
        .blocks
        .last()
        .unwrap()
        .rows
        .iter()
        .map(|row| format!("{row:?}"))
        .collect();
    assert_eq!(rows, rows_of(table, buffer));
}

/// Rows of one symbol column whose symbols are all `a`, at the time of the
/// flush. A cell takes three bytes of the size of the buffer and one of its
/// frame.
fn buffer_of_one_symbol(table: &str, rows: usize) -> Buffer {
    let mut buffer = Buffer::new_qwp_ws();
    for _ in 0..rows {
        buffer.table(table).unwrap().symbol("s", "a").unwrap();
        buffer.at_now().unwrap();
    }
    buffer
}

/// Rows of trades, as many as make the buffer just larger than `len`: a
/// timestamp, a symbol of eight values and two doubles.
fn buffer_of_trades_above(table: &str, len: usize) -> Buffer {
    let mut buffer = Buffer::new_qwp_ws();
    let mut row = 0;
    while buffer.len() <= len {
        buffer
            .table(table)
            .unwrap()
            .symbol("sym", format!("s{}", row % 8))
            .unwrap()
            .column_f64("price", 100.0 + row as f64)
            .unwrap()
            .column_f64("qty", 1.5 * row as f64)
            .unwrap()
            .at(TimestampNanos::new(1_700_000_000_000_000_000 + row))
            .unwrap();
        row += 1;
    }
    buffer
}

/// Rows of `columns` symbol columns, each holding `a`, at the time of the
/// flush.
pub(super) fn buffer_of_symbol_columns(table: &str, rows: usize, columns: usize) -> Buffer {
    let mut buffer = Buffer::new_qwp_ws();
    for _ in 0..rows {
        buffer.table(table).unwrap();
        for column in 0..columns {
            buffer.symbol(format!("s{column}").as_str(), "a").unwrap();
        }
        buffer.at_now().unwrap();
    }
    buffer
}

/// The size of a buffer takes more for a symbol than its frame does: two
/// bytes more for each symbol cell. With `max_buf_size` at or below the
/// server's frame limit, which makes it the frame cap, a buffer of symbols
/// above `max_buf_size` can still fit one frame. It goes out as one frame.
fn a_buffer_of_symbols_above_max_buf_size_whose_frame_fits_is_one_frame(progress: Progress) {
    const MAX_BUF_SIZE: usize = 1024 * 1024;
    let server = QwpWsModelServer::start(SERVER_DEFAULT_FRAME_LIMIT);
    let mut sender = sender_with(server.port, progress, "max_buf_size=1048576;");
    assert_eq!(sender.effective_frame_cap().unwrap(), (MAX_BUF_SIZE, true));
    let fits_one_frame = |buffer: &Buffer, max_buf_size: usize| {
        let frame = frame_of_a_sender(buffer, false, &mut SymbolGlobalDict::new());
        assert!(buffer.len() > max_buf_size && frame.len() <= max_buf_size);
    };

    // A symbol column with one value.
    let one_symbol = buffer_of_one_symbol("one_symbol_rows", 400_000);
    fits_one_frame(&one_symbol, MAX_BUF_SIZE);
    assert_sent_as_one_frame(&server, &mut sender, &one_symbol, "one_symbol_rows");

    // Trades, just above `max_buf_size`.
    let trades = buffer_of_trades_above("trades", MAX_BUF_SIZE);
    fits_one_frame(&trades, MAX_BUF_SIZE);
    assert_sent_as_one_frame(&server, &mut sender, &trades, "trades");
    drop(sender);

    // Eight symbol columns, the frame a third of the buffer.
    let mut sender = sender_with(server.port, progress, "max_buf_size=2000;");
    assert_eq!(sender.effective_frame_cap().unwrap(), (2000, true));
    let symbol_columns = buffer_of_symbol_columns("symbol_columns", 200, 8);
    fits_one_frame(&symbol_columns, 2000);
    assert!(symbol_columns.len() > 2 * 2000);
    assert_sent_as_one_frame(&server, &mut sender, &symbol_columns, "symbol_columns");
    drop(sender);
    server.finish();
}

/// The size of a buffer takes the text of a symbol for each of its columns
/// and for every symbol that the connection knows, which its frame brings
/// once and not again. A buffer above `max_buf_size` for such symbols goes
/// out as one frame when that frame fits, also with `max_buf_size` above
/// the frame cap.
fn a_buffer_above_max_buf_size_for_symbols_that_its_frame_brings_once_is_one_frame(
    progress: Progress,
) {
    const MAX_BUF_SIZE: usize = 8192;
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let mut sender = sender_with(server.port, progress, "max_buf_size=8192;");
    assert_eq!(sender.effective_frame_cap().unwrap(), (FRAME_LIMIT, true));
    let symbol = |id: usize| format!("{id:0>100}");

    // One row with a symbol of 100 bytes in each of 105 columns.
    let mut in_many_columns = Buffer::new_qwp_ws();
    in_many_columns.table("many_columns").unwrap();
    for column in 0..105 {
        in_many_columns
            .symbol(format!("s{column}").as_str(), symbol(0).as_str())
            .unwrap();
    }
    in_many_columns.at_now().unwrap();
    let frame = frame_of_a_sender(&in_many_columns, false, &mut SymbolGlobalDict::new());
    assert!(in_many_columns.len() > MAX_BUF_SIZE && frame.len() <= FRAME_LIMIT);
    assert_sent_as_one_frame(&server, &mut sender, &in_many_columns, "many_columns");

    // Rows of symbols of 100 bytes that the connection knows: two flushes
    // in frames bring them first.
    let known_symbols = |ids: std::ops::Range<usize>| {
        let mut buffer = Buffer::new_qwp_ws();
        for id in ids {
            buffer
                .table("known_symbols")
                .unwrap()
                .symbol("k", symbol(id).as_str())
                .unwrap();
            buffer.at_now().unwrap();
        }
        buffer
    };
    let mut symbols = SymbolGlobalDict::new();
    for ids in [0..50, 50..100] {
        let learning = known_symbols(ids);
        assert!(learning.len() > FRAME_LIMIT && learning.len() <= MAX_BUF_SIZE);
        sender.flush_and_keep(&learning).unwrap();
        frame_of_a_sender(&learning, false, &mut symbols);
    }
    let known = known_symbols(0..100);
    let frame = frame_of_a_sender(&known, false, &mut symbols);
    assert!(known.len() > MAX_BUF_SIZE && frame.len() <= FRAME_LIMIT);
    assert_sent_as_one_frame(&server, &mut sender, &known, "known_symbols");
    assert_eq!(server.model.table("known_symbols").unwrap().commits, 3);
    drop(sender);
    server.finish();
}

/// The frames of a flush in frames, planned by their size bound, take more
/// than the frame of a buffer with symbols. A buffer whose frames the queue
/// could never hold together goes out as one frame when that frame fits.
/// When it does not, the buffer is refused for the queue, and its symbols
/// are not taken as sent.
fn a_buffer_whose_frames_the_queue_cannot_hold_is_one_frame_when_its_frame_fits(
    progress: Progress,
) {
    let server = QwpWsModelServer::start(SERVER_DEFAULT_FRAME_LIMIT);
    // A queue of the least two segments of 1,024 bytes. The frame cap is
    // what a segment holds, 992 bytes, and a flush is cut for frames of 492
    // bytes, two a segment.
    const TWO_SEGMENTS: &str = "sf_max_segment_bytes=1024;sf_max_total_bytes=2048;";
    let mut sender = sender_with(server.port, progress, TWO_SEGMENTS);
    assert_eq!(sender.effective_frame_cap().unwrap(), (992, true));
    let symbol_columns = buffer_of_symbol_columns("symbol_columns", 100, 8);
    let frames = frames_of_a_sender(&symbol_columns, 492, &mut SymbolGlobalDict::new()).len();
    assert!(queue_bytes_for(frames) > 2048, "{frames} frames");
    let frame = frame_of_a_sender(&symbol_columns, false, &mut SymbolGlobalDict::new());
    assert!(frame.len() <= 992, "{}", frame.len());
    assert_sent_as_one_frame(&server, &mut sender, &symbol_columns, "symbol_columns");

    // Rows whose frame is above the frame cap.
    let mut too_large = buffer_of_symbols(FIRST, 0..400);
    let frames = frames_of_a_sender(&too_large, 492, &mut SymbolGlobalDict::new()).len();
    assert_refused_for_the_queue(
        &mut sender,
        &mut too_large,
        frames,
        queue_bytes_for(frames),
        2048,
    );
    let after = buffer_of_symbols(FIRST, 0..10);
    assert_sent_as_one_frame(&server, &mut sender, &after, FIRST);
    drop(sender);

    // Segments of 1 MiB, in a queue of two: rows of a symbol, a long and a
    // timestamp, a little above what a segment holds.
    let settings = "sf_max_segment_bytes=1048576;sf_max_total_bytes=2097152;";
    let mut sender = sender_with(server.port, progress, settings);
    let (cap, _) = sender.effective_frame_cap().unwrap();
    let mut trades = Buffer::new_qwp_ws();
    for id in 0..58_000 {
        trades
            .table("trades")
            .unwrap()
            .symbol("sym", "a")
            .unwrap()
            .column_i64("qty", id)
            .unwrap()
            .at(TimestampNanos::new(1_700_000_000_000_000_000 + id))
            .unwrap();
    }
    let frame = frame_of_a_sender(&trades, false, &mut SymbolGlobalDict::new());
    assert!(trades.len() > cap && frame.len() <= cap);
    assert_sent_as_one_frame(&server, &mut sender, &trades, "trades");
    drop(sender);
    server.finish();
}

fn a_buffer_with_a_row_that_fits_no_frame_is_refused_with_the_table_and_the_size_of_the_row(
    progress: Progress,
) {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let mut sender = sender_with(server.port, progress, "");

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

fn a_row_whose_frame_is_exactly_the_frame_cap_travels_alone_and_one_byte_more_is_refused(
    progress: Progress,
) {
    // A flush is cut for frames that are smaller than the frame cap.
    let server = QwpWsModelServer::start(LIMIT_ABOVE_TARGET);
    let mut sender = sender_with(server.port, progress, "sf_max_segment_bytes=4096;");
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

fn a_row_that_fits_no_frame_by_its_size_bound_is_sent_when_the_buffer_fits_one_frame(
    progress: Progress,
) {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let mut sender = sender_with(server.port, progress, "");
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

fn a_value_that_cannot_be_sent_is_named_before_a_row_that_fits_no_frame(progress: Progress) {
    const TWO_DIGITS: &str = "cannot rescale decimal from scale 2 to 1 without precision loss";
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let mut sender = sender_with(server.port, progress, "");
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
pub(super) fn queue_bytes_for(frames: usize) -> usize {
    (frames.div_ceil(2) + 1) * 1024
}

fn a_flush_that_the_queue_can_never_hold_is_refused_with_the_value_that_would_do(
    progress: Progress,
) {
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
    let mut sender = sender_with(
        server.port,
        progress,
        &format!("{SEGMENTS}sf_max_total_bytes=4096;"),
    );
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
    let mut sender = sender_with(server.port, progress, &settings);
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
    let mut sender = sender_with(server.port, progress, &settings);
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
pub(super) const EIGHT_SEGMENTS: &str = "sf_max_segment_bytes=1024;sf_max_total_bytes=8192;";

/// Two flushes for the queue of [`EIGHT_SEGMENTS`], and the number of
/// frames of each. The six frames of the first fill three segments. Next to
/// them the queue has five segments, which hold ten of the eleven frames of
/// the second: that flush lacks room for its last frame alone.
pub(super) fn two_flushes_for_a_queue_that_holds_one() -> (Buffer, usize, Buffer, usize) {
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
pub(super) fn allocated_after_a_flush_of(frames: usize) -> [usize; 2] {
    let segments = frames.div_ceil(2);
    [segments * 1024, (segments + 1) * 1024]
}

/// Checks the error of a flush that waited for room in the queue of
/// [`EIGHT_SEGMENTS`] until `sf_append_deadline_millis` had passed, with the
/// connection up. What the segments of the queue take then is one of
/// `allocated`.
pub(super) fn assert_timed_out_waiting_for_room(err: &crate::Error, allocated: &[usize]) {
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

/// Waits until `done`, as long as `wait` allows.
pub(super) fn wait_until(wait: Duration, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + wait;
    while !done() {
        assert!(Instant::now() < deadline, "waited {wait:?} in vain");
        thread::sleep(Duration::from_millis(1));
    }
}

/// Waits until the server has taken `frames` frames from `sender`.
fn wait_for_frames_sent(
    sender: &mut Sender,
    progress: Progress,
    server: &QwpWsModelServer,
    frames: usize,
) {
    let deadline = Instant::now() + WAIT;
    while server.frames_taken() < frames {
        assert!(
            Instant::now() < deadline,
            "the server took {} of {frames} frames",
            server.frames_taken()
        );
        let_it_work(sender, progress);
    }
}

/// Waits until the server has taken `frames` frames, while another thread
/// holds the sender: a flush that waits for room, a `wait` or a
/// `close_drain`, each of which drives a sender in manual progress mode.
pub(super) fn wait_for_frames_taken(server: &QwpWsModelServer, frames: usize) {
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

fn a_flush_without_room_waits_until_the_server_confirms_what_the_queue_holds(progress: Progress) {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    // The server takes what is flushed and keeps its answers to itself: what
    // is flushed stays in the queue.
    server.hold_answers();
    let mut sender = sender_with(server.port, progress, EIGHT_SEGMENTS);
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

fn a_flush_that_waits_for_room_until_the_deadline_fails_with_nothing_sent(progress: Progress) {
    const DEADLINE: Duration = Duration::from_millis(300);
    let settings = format!("{EIGHT_SEGMENTS}sf_append_deadline_millis=300;");
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    server.hold_answers();
    let mut sender = sender_with(server.port, progress, &settings);
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
    wait_for_frames_sent(&mut sender, progress, &server, first_frames);
    assert_eq!(server.frames_taken(), first_frames, "nothing is sent");
    // As after a flush of one frame that waited as long, below: the sender
    // says that it must be closed, and goes on working all the same.
    assert!(sender.must_close());

    // A flush of one frame that finds the queue full fails the same way.
    let mut other = sender_with(server.port, progress, &settings);
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

fn a_flush_that_waits_for_room_while_the_server_is_down_names_why_reconnecting_fails(
    progress: Progress,
) {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    server.hold_answers();
    let mut sender = sender_with(
        server.port,
        progress,
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
        let_it_work(&mut sender, progress);
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

/// The settings of a sender whose queue is four segments of 1,024 bytes, and
/// which waits 300 ms for room in it.
pub(super) const FOUR_SEGMENTS: &str =
    "sf_max_segment_bytes=1024;sf_max_total_bytes=4096;sf_append_deadline_millis=300;";

/// A buffer of rows of [`TABLE`] whose one frame fills a segment, and a
/// buffer of the table `symbol_columns` whose size bound cuts it into six
/// frames, which take three segments, while its one frame fits one. With
/// two flushes of the first in the queue of [`FOUR_SEGMENTS`] and not
/// confirmed, the queue has room for that frame and not for the six.
pub(super) fn a_frame_that_fits_where_its_frames_do_not() -> (Buffer, Buffer) {
    let filler = buffer_of_len(0, 900);
    let symbol_columns = buffer_of_symbol_columns("symbol_columns", 100, 8);
    let frame = frame_of_a_sender(&symbol_columns, false, &mut SymbolGlobalDict::new());
    assert!(
        symbol_columns.len() > 992 && frame.len() <= 992,
        "len {}, frame {}",
        symbol_columns.len(),
        frame.len()
    );
    let frames = frames_of_a_sender(&symbol_columns, 492, &mut SymbolGlobalDict::new()).len();
    assert_eq!(frames, 6);
    assert_eq!(queue_bytes_for(frames), 4096);
    (filler, symbol_columns)
}

/// The size bound of a buffer of symbols cuts it into frames while its one
/// frame fits the frame cap. When the queue has room for that frame and not
/// for the frames, the buffer goes out as that frame at once, as a buffer
/// within the cap does, and the server commits it once.
fn a_buffer_whose_frame_fits_is_one_frame_when_the_queue_has_no_room_for_its_frames(
    progress: Progress,
) {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    server.hold_answers();
    let mut sender = sender_with(server.port, progress, FOUR_SEGMENTS);
    assert_eq!(sender.effective_frame_cap().unwrap(), (992, true));
    let (filler, symbol_columns) = a_frame_that_fits_where_its_frames_do_not();
    assert_eq!(sender.flush_and_keep_and_get_fsn(&filler).unwrap(), Some(0));
    assert_eq!(sender.flush_and_keep_and_get_fsn(&filler).unwrap(), Some(1));

    assert_eq!(
        sender.flush_and_keep_and_get_fsn(&symbol_columns).unwrap(),
        Some(2)
    );
    server.let_answers_go();
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_eq!(server.frames_taken(), 3);
    assert_table_holds(&server, TABLE, 2, &[&filler, &filler]);
    assert_table_holds(&server, "symbol_columns", 1, &[&symbol_columns]);
    assert!(!sender.must_close());
    drop(sender);
    server.finish();
}

/// The size bound of a buffer of symbols is more than twice the frame cap
/// while its one frame fits: it goes out as that frame, as a buffer within
/// the cap does, also when the queue has room for the frames that the bound
/// would cut it into. The server commits it once.
fn a_buffer_whose_frame_fits_is_one_frame_when_the_queue_has_room_for_its_frames(
    progress: Progress,
) {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let mut sender = sender_with(server.port, progress, "");
    assert_eq!(sender.effective_frame_cap().unwrap(), (FRAME_LIMIT, true));
    let symbol_columns = buffer_of_symbol_columns("symbol_columns", 100, 8);
    let frame = frame_of_a_sender(&symbol_columns, false, &mut SymbolGlobalDict::new());
    assert!(
        symbol_columns.len() > 2 * FRAME_LIMIT && frame.len() <= FRAME_LIMIT,
        "len {}, frame {}",
        symbol_columns.len(),
        frame.len()
    );

    assert_sent_as_one_frame(&server, &mut sender, &symbol_columns, "symbol_columns");
    assert!(!sender.must_close());
    drop(sender);
    server.finish();
}

/// A buffer whose one frame fits the cap brings, in its last row, a symbol
/// that the full dictionary of its connection cannot take. It is refused
/// before anything of it is sent, as a buffer within the cap is: the sender
/// stays open, and a flush of a known symbol goes on. Cut into frames by its
/// size bound, the buffer would have brought that symbol in its last frame,
/// and stopped part way.
fn a_buffer_whose_frame_fits_is_refused_whole_by_a_full_dictionary(progress: Progress) {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let mut sender = sender_with_a_dictionary_of(server.port, progress, 2);
    let mut known = Buffer::new_qwp_ws();
    known.table("known").unwrap().symbol("k", "k").unwrap();
    known.at_now().unwrap();
    // Rows of the symbol `a`, the second of the connection, and a last row
    // that brings `z`, the third.
    let mut large = buffer_of_symbol_columns("symbol_columns", 100, 8);
    large.table("symbol_columns").unwrap();
    for column in 0..8 {
        let symbol = if column == 0 { "z" } else { "a" };
        large.symbol(format!("s{column}").as_str(), symbol).unwrap();
    }
    large.at_now().unwrap();
    let mut symbols = SymbolGlobalDict::new();
    frame_of_a_sender(&known, false, &mut symbols);
    let frame = frame_of_a_sender(&large, false, &mut SymbolGlobalDict::new());
    assert!(large.len() > FRAME_LIMIT && frame.len() <= FRAME_LIMIT);
    let frames = frames_of_a_sender(&large, FRAME_LIMIT, &mut symbols);
    assert!(frames.len() > 1);
    assert_eq!(symbols_brought_by(frames.last().unwrap()).1, ["z"]);

    assert_eq!(sender.flush_and_keep_and_get_fsn(&known).unwrap(), Some(0));
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    let err = sender.flush_and_keep(&large).unwrap_err();
    assert_eq!(err.code(), ErrorCode::SymbolDictFull, "{}", err.msg());
    assert!(!sender.must_close());
    assert_eq!(sender.published_fsn().unwrap(), Some(0));

    assert_eq!(sender.flush_and_keep_and_get_fsn(&known).unwrap(), Some(1));
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_eq!(server.frames_taken(), 2);
    assert_table_holds(&server, "known", 2, &[&known, &known]);
    assert!(server.model.table("symbol_columns").is_none());
    drop(sender);
    server.finish();
}

/// The settings of a sender whose queue is eight segments of 1,024 bytes, and
/// which waits 300 ms for room in it.
pub(super) const EIGHT_SEGMENTS_SHORT_WAIT: &str =
    "sf_max_segment_bytes=1024;sf_max_total_bytes=8192;sf_append_deadline_millis=300;";

/// Rows of the table `long_symbol` whose symbol is the same text of 300
/// bytes.
fn buffer_of_a_long_symbol(rows: usize) -> Buffer {
    let mut buffer = Buffer::new_qwp_ws();
    for _ in 0..rows {
        buffer
            .table("long_symbol")
            .unwrap()
            .symbol("s", "x".repeat(300))
            .unwrap()
            .at_now()
            .unwrap();
    }
    buffer
}

/// Flushes for the queue of [`EIGHT_SEGMENTS_SHORT_WAIT`], to be flushed in
/// their order and not confirmed: a row of [`buffer_of_a_long_symbol`], and
/// five buffers of rows of [`TABLE`] whose frames fill a segment each. Then a
/// buffer of rows of that symbol whose size bound cuts it into frames for
/// which the queue has no room, while its one frame fits the frame cap and
/// the room the queue has. Only the text of the symbol, which the connection
/// holds then, keeps that frame from being above the cap.
pub(super) fn a_frame_that_fits_by_the_symbols_its_connection_holds() -> (Vec<Buffer>, Buffer) {
    let mut before = vec![buffer_of_a_long_symbol(1)];
    before.extend((0..5).map(|_| buffer_of_len(0, 900)));
    let long_symbol = buffer_of_a_long_symbol(800);
    let frames = frames_of_a_sender(&long_symbol, 492, &mut SymbolGlobalDict::new()).len();
    assert!(
        frames.div_ceil(2) > 2 && queue_bytes_for(frames) <= 8192,
        "{frames} frames"
    );
    let mut symbols = SymbolGlobalDict::new();
    frame_of_a_sender(&before[0], false, &mut symbols);
    let rows = long_symbol.as_qwp_ws().unwrap();
    let least_on_a_new_connection = rows.one_frame_min_len(0);
    let least = rows.one_frame_min_len(symbols.max_encoded_len());
    let frame = frame_of_a_sender(&long_symbol, false, &mut symbols);
    assert!(
        least <= frame.len() && frame.len() <= 992 && least_on_a_new_connection > 992,
        "{least}, {}, {least_on_a_new_connection}",
        frame.len()
    );
    (before, long_symbol)
}

/// As [`a_buffer_whose_frame_fits_is_one_frame_when_the_queue_has_no_room_for_its_frames`],
/// for a buffer whose frame fits the cap because it does not bring the
/// symbols that its connection holds.
fn a_buffer_whose_frame_fits_by_the_symbols_its_connection_holds_is_one_frame_without_room_for_its_frames(
    progress: Progress,
) {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    server.hold_answers();
    let mut sender = sender_with(server.port, progress, EIGHT_SEGMENTS_SHORT_WAIT);
    let (before, long_symbol) = a_frame_that_fits_by_the_symbols_its_connection_holds();
    for buffer in &before {
        sender.flush_and_keep(buffer).unwrap();
    }

    assert_eq!(
        sender.flush_and_keep_and_get_fsn(&long_symbol).unwrap(),
        Some(before.len() as u64)
    );
    server.let_answers_go();
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_eq!(server.frames_taken(), before.len() + 1);
    assert_table_holds(&server, "long_symbol", 2, &[&before[0], &long_symbol]);
    assert!(!sender.must_close());
    drop(sender);
    server.finish();
}

/// The least that the one frame of a buffer can take counts a byte for each
/// symbol cell, which takes two once the connection holds 128 symbols. When
/// the queue has no room for the frames of such a buffer, it is tried as one
/// frame, which is above the frame cap. It then waits for the room of its
/// frames, and goes out in them as one commit.
fn a_buffer_whose_frame_is_above_the_cap_by_its_symbol_ids_waits_for_the_room_of_its_frames(
    progress: Progress,
) {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    server.hold_answers();
    let mut sender = sender_with(server.port, progress, EIGHT_SEGMENTS);
    assert_eq!(sender.effective_frame_cap().unwrap(), (992, true));
    // Two flushes of one frame each bring 150 symbols to the connection, and
    // five more fill a segment each.
    let mut symbols = SymbolGlobalDict::new();
    let mut known = Vec::new();
    for ids in [0..75, 75..150] {
        let mut buffer = Buffer::new_qwp_ws();
        for id in ids {
            buffer
                .table("known")
                .unwrap()
                .symbol("k", format!("k{id}"))
                .unwrap()
                .at_now()
                .unwrap();
        }
        assert!(buffer.len() <= 992);
        frame_of_a_sender(&buffer, false, &mut symbols);
        known.push(buffer);
    }
    let filler = buffer_of_len(0, 900);
    let symbol_columns = buffer_of_symbol_columns("symbol_columns", 100, 8);
    let frames = frames_of_a_sender(&symbol_columns, 492, &mut SymbolGlobalDict::new()).len();
    let least = symbol_columns
        .as_qwp_ws()
        .unwrap()
        .one_frame_min_len(symbols.max_encoded_len());
    let frame = frame_of_a_sender(&symbol_columns, false, &mut symbols);
    assert!(
        least <= 992 && frame.len() > 992,
        "{least}, {}",
        frame.len()
    );
    for buffer in known.iter().chain([&filler; 5]) {
        sender.flush_and_keep(buffer).unwrap();
    }
    let before = 7;
    assert_eq!(sender.published_fsn().unwrap(), Some(before - 1));

    let last_fsn = thread::scope(|scope| {
        let flush = scope.spawn(|| sender.flush_and_keep_and_get_fsn(&symbol_columns));
        wait_for_frames_taken(&server, before as usize);
        thread::sleep(Duration::from_millis(200));
        assert!(!flush.is_finished(), "the flush did not wait for room");
        assert_eq!(
            server.frames_taken(),
            before as usize,
            "no frame of the flush is sent before all of them have room"
        );
        server.let_answers_go();
        flush.join().unwrap().unwrap()
    });
    assert_eq!(last_fsn, Some(before + frames as u64 - 1));
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_eq!(server.frames_taken(), before as usize + frames);
    assert_table_holds(&server, "symbol_columns", 1, &[&symbol_columns]);
    assert!(!sender.must_close());
    drop(sender);
    server.finish();
}

/// The settings of a sender whose queue is the slot `reopened` of `sf_dir`,
/// in segments of `segment_size_bytes`, and `more`. Its drop does not wait
/// for the server, so that the next sender on the slot can come at once.
fn reopened_slot_settings(
    sf_dir: &tempfile::TempDir,
    segment_size_bytes: u64,
    more: &str,
) -> String {
    format!(
        "sf_dir={};sender_id=reopened;sf_max_segment_bytes={segment_size_bytes};\
         close_flush_timeout_millis=0;{more}",
        sf_dir.path().display()
    )
}

/// The sizes of the segment files in the slot of [`reopened_slot_settings`].
fn reopened_segment_sizes(sf_dir: &tempfile::TempDir) -> Vec<u64> {
    let mut sizes: Vec<u64> = std::fs::read_dir(sf_dir.path().join("reopened"))
        .unwrap()
        .flatten()
        .filter(|entry| entry.file_name().to_string_lossy().ends_with(".sfa"))
        .map(|entry| entry.metadata().unwrap().len())
        .collect();
    sizes.sort();
    sizes
}

/// A slot made with segments of 1,024 bytes is reopened with segments of
/// 2,048 bytes, and goes on with the segment it had in use. The flush in
/// frames that comes then waits for room, which is counted for the segment
/// in use at its own size: with the server silent it waits in vain and
/// sends nothing, and it goes through once the server answers.
fn a_flush_on_a_slot_reopened_with_larger_segments_counts_the_segment_in_use_at_its_size(
    progress: Progress,
) {
    const DEADLINE: Duration = Duration::from_millis(400);
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    server.hold_answers();
    let sf_dir = tempfile::TempDir::new().unwrap();
    // Three flushes of one frame of over 600 bytes: each takes a segment of
    // 1,024 bytes.
    let earlier = [
        buffer_of(TABLE, 0..22),
        buffer_of(TABLE, 100..121),
        buffer_of(TABLE, 200..221),
    ];
    for buffer in &earlier {
        assert!(frame_of_a_whole_buffer(buffer, false).len() > 600);
    }
    {
        let settings = reopened_slot_settings(&sf_dir, 1024, "sf_max_total_bytes=8192;");
        let mut sender = sender_with(server.port, progress, &settings);
        for (fsn, buffer) in earlier.iter().enumerate() {
            assert_eq!(
                sender.flush_and_keep_and_get_fsn(buffer).unwrap(),
                Some(fsn as u64)
            );
        }
        wait_for_frames_sent(&mut sender, progress, &server, 3);
    }
    // The three segments of the frames, and the spare.
    assert_eq!(reopened_segment_sizes(&sf_dir), [1024; 4]);

    // Next to the three segments of 1,024 bytes and a new spare of 2,048,
    // the budget has no room for another segment: the flush has the spare.
    // Its frames take 999, 999 and 327 bytes by their size bounds. The
    // first does not fit the segment in use, the third does not fit the
    // spare after the first two: the flush needs two new segments.
    let settings = reopened_slot_settings(
        &sf_dir,
        2048,
        "sf_max_total_bytes=6144;sf_append_deadline_millis=400;",
    );
    let mut sender = sender_with(server.port, progress, &settings);
    wait_for_frames_sent(&mut sender, progress, &server, 6);
    let mut large = buffer_of(TABLE, 1000..1078);
    let frames = frames_of_a_flush(&large, 1004).len();
    assert_eq!(frames, 3);
    let (rows, len) = (large.row_count(), large.len());

    let started = Instant::now();
    let err = sender.flush(&mut large).unwrap_err();
    let waited = started.elapsed();
    assert_eq!(err.code(), ErrorCode::SocketError, "{}", err.msg());
    assert!(
        err.msg().starts_with(
            "QWP/WebSocket Store-and-Forward append timed out waiting for ACK-driven segment \
             trim; increase sf_max_total_bytes or drive pending acknowledgements \
             [segment_size_bytes=2048, "
        ),
        "{}",
        err.msg()
    );
    assert!(waited >= DEADLINE && waited < WAIT, "waited {waited:?}");
    assert_eq!(
        sender.published_fsn().unwrap(),
        Some(2),
        "nothing is published"
    );
    assert_eq!((large.row_count(), large.len()), (rows, len));
    for _ in 0..50 {
        let_it_work(&mut sender, progress);
    }
    assert_eq!(server.frames_taken(), 6, "nothing is sent");

    server.let_answers_go();
    let retry_until = Instant::now() + WAIT;
    let last_fsn = loop {
        match sender.flush_and_keep_and_get_fsn(&large) {
            Ok(fsn) => break fsn,
            Err(err) => assert!(Instant::now() < retry_until, "{}", err.msg()),
        }
    };
    assert_eq!(last_fsn, Some(2 + frames as u64));
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    // The server committed the earlier flushes on the first connection, and
    // again when the reopened slot sent them.
    let [first, second, third] = &earlier;
    assert_table_holds(
        &server,
        TABLE,
        7,
        &[first, second, third, first, second, third, &large],
    );
    drop(sender);
    server.finish();
}

/// A slot made with segments of 2,048 bytes is reopened with segments of
/// 1,024 bytes, and goes on with the larger segment it had in use. A flush
/// in frames that the queue can hold next to a segment of 1,024 bytes, and
/// not next to that one, is refused at once with the budget it needs.
fn a_flush_on_a_slot_reopened_with_smaller_segments_is_refused_for_the_segment_in_use(
    progress: Progress,
) {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    server.hold_answers();
    let sf_dir = tempfile::TempDir::new().unwrap();
    // Two flushes of one frame of over 800 bytes fill the first segment
    // so far that no frame of the flush below fits it.
    let earlier = [buffer_of(TABLE, 0..30), buffer_of(TABLE, 100..128)];
    for buffer in &earlier {
        assert!(frame_of_a_whole_buffer(buffer, false).len() > 800);
    }
    {
        let settings = reopened_slot_settings(&sf_dir, 2048, "");
        let mut sender = sender_with(server.port, progress, &settings);
        for (fsn, buffer) in earlier.iter().enumerate() {
            assert_eq!(
                sender.flush_and_keep_and_get_fsn(buffer).unwrap(),
                Some(fsn as u64)
            );
        }
        wait_for_frames_sent(&mut sender, progress, &server, 2);
    }
    server.let_answers_go();

    // Next to a segment in use of 1,024 bytes, the frames fit the budget
    // that the error of a flush on a fresh slot names.
    let mut too_large = buffer_of(TABLE, 300..700);
    let frames = frames_of_a_flush(&too_large, 492).len();
    let max_total_bytes = queue_bytes_for(frames);
    let settings = reopened_slot_settings(
        &sf_dir,
        1024,
        &format!("sf_max_total_bytes={max_total_bytes};sf_append_deadline_millis=400;"),
    );
    let mut sender = sender_with(server.port, progress, &settings);
    sender.wait(AckLevel::Ok, WAIT).unwrap();

    let started = Instant::now();
    assert_refused_for_the_queue(
        &mut sender,
        &mut too_large,
        frames,
        max_total_bytes + 1024,
        max_total_bytes,
    );
    assert!(started.elapsed() < Duration::from_millis(400));
    assert_eq!(
        sender.published_fsn().unwrap(),
        Some(1),
        "nothing is published"
    );

    // The sender goes on.
    let after = buffer_of(TABLE, 700..703);
    assert_eq!(sender.flush_and_keep_and_get_fsn(&after).unwrap(), Some(2));
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    let [first, second] = &earlier;
    assert_table_holds(&server, TABLE, 5, &[first, second, first, second, &after]);
    assert!(!sender.must_close());
    drop(sender);
    server.finish();
}

/// A slot made with segments of 2,048 bytes is reopened with segments of
/// 1,024 bytes, and goes on with the larger segment it had in use, which
/// holds one small frame. A flush in frames that fits the rest of that
/// segment needs no more of the budget, and goes through.
fn a_flush_on_a_slot_reopened_with_smaller_segments_that_fits_the_segment_in_use_is_sent(
    progress: Progress,
) {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    server.hold_answers();
    let sf_dir = tempfile::TempDir::new().unwrap();
    let before = buffer_of(TABLE, 0..3);
    {
        let settings = reopened_slot_settings(&sf_dir, 2048, "");
        let mut sender = sender_with(server.port, progress, &settings);
        assert_eq!(sender.flush_and_keep_and_get_fsn(&before).unwrap(), Some(0));
        wait_for_frames_sent(&mut sender, progress, &server, 1);
    }
    server.let_answers_go();

    // Three frames of 1,192 bytes in all fit the segment in use. On a fresh
    // slot of segments of 1,024 bytes they need a queue of 3,072 bytes.
    let large = buffer_of(TABLE, 3..43);
    let frames = frames_of_a_flush(&large, 492).len();
    assert_eq!(frames, 3);
    let settings = reopened_slot_settings(&sf_dir, 1024, "sf_max_total_bytes=3072;");
    let mut sender = sender_with(server.port, progress, &settings);
    sender.wait(AckLevel::Ok, WAIT).unwrap();

    assert_eq!(
        sender.flush_and_keep_and_get_fsn(&large).unwrap(),
        Some(frames as u64)
    );
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_eq!(server.frames_taken(), 2 + frames);
    // The server committed the earlier flush on the first connection, and
    // again when the reopened slot sent it.
    assert_table_holds(&server, TABLE, 3, &[&before, &before, &large]);
    assert!(!sender.must_close());
    drop(sender);
    server.finish();
}

/// A flush in frames stops part way on a slot of segments of 512 bytes, and
/// its sender is dropped. Its first frame began a segment: the first of the
/// slot, or the one after the segment of a flush before it. The next sender
/// on the slot removes the frames of the stopped flush, which leaves that
/// segment empty. That sender has segments of 4,096 bytes, and sends the
/// buffer of the stopped flush in frames that a segment of 512 bytes cannot
/// hold, and then a buffer of one such frame. The server commits each of
/// them once, and nothing of the stopped flush.
fn assert_a_slot_reopened_with_larger_segments_takes_larger_frames_after_a_flush_that_stopped(
    progress: Progress,
    with_a_flush_before: bool,
) {
    // What a segment of 512 bytes holds: a header of 24 bytes, and one of
    // 8 for the frame.
    const OLD_CAPACITY: usize = 512 - 24 - 8;
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    server.hold_answers();
    let sf_dir = tempfile::TempDir::new().unwrap();
    let before = buffer_of(TABLE, 0..12);
    let mut large = buffer_of(TABLE, 100..400);
    let (rows, len) = (large.row_count(), large.len());
    {
        let settings = reopened_slot_settings(&sf_dir, 512, "");
        let mut sender = sender_with(server.port, progress, &settings);
        let mut held = Vec::new();
        if with_a_flush_before {
            held.push(frame_of_a_whole_buffer(&before, false).len());
            assert_eq!(sender.flush_and_keep_and_get_fsn(&before).unwrap(), Some(0));
            wait_for_frames_sent(&mut sender, progress, &server, 1);
        }
        // Segments of 512 bytes are cut for two frames of 236 bytes each.
        let frames = frames_of_a_flush(&large, 236);
        let taking = frames_that_take_a_new_segment(512, &held, &frames);
        // The first frame of the flush begins a segment, and the flush stops
        // at the next frame that needs a new segment.
        let new_segments_before = usize::from(with_a_flush_before);
        assert_eq!(taking[0] == 0, with_a_flush_before, "{taking:?}");
        assert!(taking[new_segments_before] > 0, "{taking:?}");
        fail_manifest_sync_after_for_test(new_segments_before);
        let err = sender.flush(&mut large).unwrap_err();
        assert_eq!(err.code(), ErrorCode::FlushAborted, "{}", err.msg());
        assert_eq!(
            sender.published_fsn().unwrap(),
            with_a_flush_before.then_some(0)
        );
        assert_eq!((large.row_count(), large.len()), (rows, len));
    }
    server.let_answers_go();

    let settings = reopened_slot_settings(&sf_dir, 4096, "");
    let mut sender = sender_with(server.port, progress, &settings);
    assert_eq!(sender.effective_frame_cap().unwrap(), (FRAME_LIMIT, true));
    let frames = frames_of_a_flush(&large, FRAME_LIMIT);
    assert!(frames.len() > 1 && frames[0].len() > OLD_CAPACITY);
    let one_frame = buffer_of(TABLE, 400..420);
    let one_frame_len = frame_of_a_whole_buffer(&one_frame, false).len();
    assert!(
        one_frame_len > OLD_CAPACITY && one_frame_len <= FRAME_LIMIT,
        "{one_frame_len}"
    );
    let first_fsn = u64::from(with_a_flush_before);
    let last_fsn = first_fsn + frames.len() as u64 - 1;
    assert_eq!(
        sender.flush_and_keep_and_get_fsn(&large).unwrap(),
        Some(last_fsn)
    );
    assert_eq!(
        sender.flush_and_keep_and_get_fsn(&one_frame).unwrap(),
        Some(last_fsn + 1)
    );
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    if with_a_flush_before {
        // The server committed the flush before on the first connection,
        // and again when the reopened slot sent it.
        assert_table_holds(&server, TABLE, 4, &[&before, &before, &large, &one_frame]);
    } else {
        assert_table_holds(&server, TABLE, 2, &[&large, &one_frame]);
    }
    assert!(!sender.must_close());
    drop(sender);
    server.finish();
}

fn a_slot_reopened_with_larger_segments_takes_larger_frames_after_a_flush_that_stopped(
    progress: Progress,
) {
    for with_a_flush_before in [false, true] {
        assert_a_slot_reopened_with_larger_segments_takes_larger_frames_after_a_flush_that_stopped(
            progress,
            with_a_flush_before,
        );
    }
}

fn a_sender_that_was_closed_refuses_a_buffer_above_the_frame_cap(progress: Progress) {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let mut sender = sender_with(server.port, progress, "");
    let mut large = buffer_of(TABLE, 0..2000);
    sender.close_drain().unwrap();

    assert_refused_as_one_frame(&mut sender, &mut large, FRAME_LIMIT, SET_BY_SERVER);
    drop(sender);
    server.finish();
}

/// A sender whose connection takes `symbols` symbols and no more.
fn sender_with_a_dictionary_of(port: u16, progress: Progress, symbols: usize) -> Sender {
    // The dictionary of a sender is made when the sender is built.
    let _cap = crate::ingress::TestDictCapGuard::new(symbols);
    sender_with(port, progress, "")
}

/// The error of a flush in frames that stopped part way because the
/// dictionary of its sender was full with `symbols` symbols: `sent` when a
/// frame of it may have been handed to the transport before it stopped,
/// which is when the error is in doubt.
pub(super) fn stopped_by_a_full_dictionary(symbols: usize, sent: bool) -> String {
    let what_was_sent = if sent {
        "Some of its frames were sent: the server commits none of their rows unless one table \
         had more rows than its qwp.max.uncommitted.rows, and then may have committed a part of \
         them by itself, which flushing the buffer again stores twice unless the table has DEDUP \
         keys. The buffer still holds its rows."
    } else {
        "None of its frames reached the server, nothing of it is committed, and the buffer still \
         holds its rows."
    };
    format!(
        "Could not flush buffer: the flush stopped part way: QWP/WS connection-scoped symbol \
         dictionary reached its {symbols}-entry cap; retire this connection and continue on a \
         fresh one (returning it to a pool recycles its dictionary). {what_was_sent} This \
         sender takes no more flushes and still delivers the flushes before this one: once \
         they are confirmed, close it or return it to its pool, and flush the buffer again \
         through a new sender."
    )
}

/// Checks the error of a flush that stopped part way because the dictionary
/// of its sender was full with `symbols` symbols, and what the sender says
/// of itself right after it. The error tells whether a frame of the flush
/// may have been sent. A sender in manual progress mode drives nothing
/// during a flush that has room, so none was.
fn assert_stopped_by_a_full_dictionary(
    sender: &Sender,
    progress: Progress,
    err: &crate::Error,
    symbols: usize,
) {
    assert_eq!(err.code(), ErrorCode::FlushAborted, "{}", err.msg());
    assert_eq!(
        err.msg(),
        stopped_by_a_full_dictionary(symbols, err.in_doubt())
    );
    if matches!(progress, Progress::Manual) {
        assert!(!err.in_doubt());
    }
    assert!(sender.must_close());
}

/// Checks how many frames of a flush in frames that failed part way with
/// `err` the server took: `taken` of the `queued` frames that the flush had
/// queued, counted once the connection that took them has ended. The sender
/// sends no frame of a flush after the flush has failed, so the server
/// takes only frames handed to the transport before, and the error is in
/// doubt then. A sender in manual progress mode drives nothing during a
/// flush that has room, so the server takes none.
fn assert_taken_of_the_failed_flush(
    err: &crate::Error,
    progress: Progress,
    taken: usize,
    queued: usize,
) {
    assert!(
        taken <= queued,
        "the server took {taken} of {queued} frames"
    );
    assert!(
        taken == 0 || err.in_doubt(),
        "the server took {taken} frames of a flush whose error is not in doubt"
    );
    if matches!(progress, Progress::Manual) {
        assert_eq!(taken, 0);
    }
}

/// How many symbols the connection of a sender holds when it comes to
/// `frame`, which must bring at least one more.
pub(super) fn symbols_held_before(frame: &[u8]) -> usize {
    let (held, brought) = symbols_brought_by(frame);
    assert!(!brought.is_empty());
    held as usize
}

/// Waits until the server has seen the end of every connection.
pub(super) fn wait_for_no_connection(server: &QwpWsModelServer) {
    let deadline = Instant::now() + WAIT;
    while server.open_connections() > 0 {
        assert!(Instant::now() < deadline, "a connection stayed open");
        thread::sleep(Duration::from_millis(1));
    }
}

/// How a test waits for the flushes before the failed one.
#[derive(Clone, Copy)]
enum WaitsBy {
    Wait,
    CloseDrain,
}

/// A flush before, which the server commits without telling, and a flush in
/// frames whose frame `failing_frame(frame count)` finds the dictionary of
/// the sender full. Checks the error of that flush and what the sender does
/// after it, to the new sender that flushes the same buffer.
fn assert_a_flush_that_fails_part_way_leaves_the_flushes_before_it(
    progress: Progress,
    failing_frame: fn(usize) -> usize,
    waits_by: WaitsBy,
) {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    // The server takes what is flushed and keeps its answers to itself.
    server.hold_answers();
    let before = buffer_of_symbols(TABLE, 0..10);
    let mut large = buffer_of_symbols(TABLE, 10..1210);
    let (rows, len) = (large.row_count(), large.len());
    let mut sender_symbols = SymbolGlobalDict::new();
    frame_of_a_sender(&before, false, &mut sender_symbols);
    let frames = frames_of_a_sender(&large, FRAME_LIMIT, &mut sender_symbols);
    assert!(frames.len() > 40, "{} frames", frames.len());
    // The frames before this one are queued, and this one brings a symbol
    // more than the connection takes.
    let failing = failing_frame(frames.len());
    assert!((1..frames.len()).contains(&failing));
    let symbols = symbols_held_before(&frames[failing]);
    let mut sender = sender_with_a_dictionary_of(server.port, progress, symbols);

    assert_eq!(sender.flush_and_keep_and_get_fsn(&before).unwrap(), Some(0));
    let err = sender.flush(&mut large).unwrap_err();
    assert_stopped_by_a_full_dictionary(&sender, progress, &err, symbols);
    assert_eq!(
        (large.row_count(), large.len()),
        (rows, len),
        "the buffer keeps its rows"
    );
    // The sender has published the flush before, and says no more.
    assert_eq!(sender.published_fsn().unwrap(), Some(0));
    // It sends the flush before.
    wait_for_frames_sent(&mut sender, progress, &server, 1);

    // Every later flush gets the same error, of one frame and in frames.
    for later in [&buffer_of(TABLE, 0..3), &large] {
        let refused = sender.flush_and_keep(later).unwrap_err();
        assert_eq!((refused.code(), refused.msg()), (err.code(), err.msg()));
        assert_eq!(refused.in_doubt(), err.in_doubt());
    }
    // A buffer with a symbol that is new to the full dictionary cannot be
    // encoded, which the sender finds before it comes to its state.
    let refused = sender
        .flush_and_keep(&buffer_of_symbols(TABLE, 5000..5001))
        .unwrap_err();
    assert_eq!(
        refused.code(),
        ErrorCode::SymbolDictFull,
        "{}",
        refused.msg()
    );
    assert!(sender.must_close());
    assert_eq!(sender.published_fsn().unwrap(), Some(0));

    // The sender waits for the answer to the flush before, and for nothing
    // else: the server answers no frame of the failed flush.
    thread::scope(|scope| {
        let waiting = scope.spawn(|| match waits_by {
            WaitsBy::Wait => sender.wait(AckLevel::Ok, WAIT),
            WaitsBy::CloseDrain => sender.close_drain(),
        });
        thread::sleep(Duration::from_millis(200));
        assert!(
            !waiting.is_finished(),
            "the sender did not wait for the flush before"
        );
        assert!(
            server.frames_taken() <= 1 + failing,
            "no later flush is queued"
        );
        server.let_answers_go();
        waiting.join().unwrap().unwrap();
    });
    if matches!(waits_by, WaitsBy::Wait) {
        assert_eq!(sender.completed_fsn(AckLevel::Ok).unwrap(), Some(0));
        assert_eq!(sender.published_fsn().unwrap(), Some(0));
        sender.close_drain().unwrap();
    }
    assert!(sender.must_close());
    // The server has committed the flush before, and holds the rows of the
    // frames of the failed flush that were sent before it failed, for a
    // frame that never comes.
    assert_table_holds(&server, TABLE, 1, &[&before]);

    // What the error says to do: close the sender, and flush the buffer
    // through a new one. The rows that the server held go with the
    // connection, and every row of the buffer is committed once.
    drop(sender);
    wait_for_no_connection(&server);
    assert_taken_of_the_failed_flush(&err, progress, server.frames_taken() - 1, failing);
    let mut sender = sender_with(server.port, progress, "");
    sender.flush(&mut large).unwrap();
    assert!(large.is_empty());
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    let large = buffer_of_symbols(TABLE, 10..1210);
    assert_table_holds(&server, TABLE, 2, &[&before, &large]);
    assert!(!sender.must_close());
    drop(sender);
    server.finish();
}

fn a_flush_that_fails_at_its_second_frame_is_aborted_and_the_flush_before_it_is_delivered(
    progress: Progress,
) {
    assert_a_flush_that_fails_part_way_leaves_the_flushes_before_it(progress, |_| 1, WaitsBy::Wait);
}

fn a_flush_that_fails_at_a_middle_frame_is_aborted_and_the_flush_before_it_is_delivered(
    progress: Progress,
) {
    assert_a_flush_that_fails_part_way_leaves_the_flushes_before_it(
        progress,
        |frames| frames / 2,
        WaitsBy::CloseDrain,
    );
}

fn a_flush_that_fails_at_its_last_frame_is_aborted_and_the_flush_before_it_is_delivered(
    progress: Progress,
) {
    assert_a_flush_that_fails_part_way_leaves_the_flushes_before_it(
        progress,
        |frames| frames - 1,
        WaitsBy::Wait,
    );
}

fn a_flush_that_fails_part_way_as_the_first_of_its_sender_leaves_nothing_to_wait_for(
    progress: Progress,
) {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let large = buffer_of_symbols(TABLE, 10..1210);
    let frames = frames_of_a_sender(&large, FRAME_LIMIT, &mut SymbolGlobalDict::new());
    let failing = frames.len() / 2;
    let symbols = symbols_held_before(&frames[failing]);
    let mut sender = sender_with_a_dictionary_of(server.port, progress, symbols);

    let err = sender.flush_and_keep(&large).unwrap_err();
    assert_stopped_by_a_full_dictionary(&sender, progress, &err, symbols);
    assert_eq!(sender.published_fsn().unwrap(), None);

    // The server answers none of the frames it took, and the sender waits
    // for none of them.
    let started = Instant::now();
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_eq!(sender.completed_fsn(AckLevel::Ok).unwrap(), None);
    sender.close_drain().unwrap();
    let waited = started.elapsed();
    assert!(waited < Duration::from_secs(2), "waited {waited:?}");

    drop(sender);
    wait_for_no_connection(&server);
    assert_taken_of_the_failed_flush(&err, progress, server.frames_taken(), failing);
    // The server made the table if it took a frame for it, and commits
    // nothing of it.
    let held = server.model.table(TABLE).unwrap_or_default();
    assert_eq!((held.commits, held.row_count()), (0, 0));
    let mut sender = sender_with(server.port, progress, "");
    sender.flush_and_keep(&large).unwrap();
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_table_holds(&server, TABLE, 1, &[&large]);
    drop(sender);
    server.finish();
}

/// A server of one connection that answers each frame without the defer
/// flag with an OK, and frame `deferred_answered` too, which has the flag:
/// as a QuestDB server answers the frame that brings a table to its
/// `qwp.max.uncommitted.rows`, when it commits the table by itself. The
/// model of a server refuses that commit, so this one stands in for it.
/// Returns its port, and the sequences of the frames it has answered.
fn start_server_that_answers_a_deferred_frame(
    deferred_answered: u64,
) -> (u16, Arc<Mutex<Vec<u64>>>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let answered = Arc::new(Mutex::new(Vec::new()));
    thread::spawn({
        let answered = Arc::clone(&answered);
        move || {
            let (mut stream, _) = listener.accept().unwrap();
            upgrade_mock_stream_with_max_batch_size(&mut stream, Some(FRAME_LIMIT));
            let (mut sequence, mut commits) = (0u64, 0i64);
            while let Ok((_, opcode, payload)) = read_frame(&mut stream) {
                match opcode {
                    0x2 => {
                        if payload[5] & 0x01 == 0 || sequence == deferred_answered {
                            commits += 1;
                            // An OK: the status, the sequence, and the table
                            // with the number of its commit.
                            let mut ok = vec![0u8];
                            ok.extend_from_slice(&sequence.to_le_bytes());
                            ok.extend_from_slice(&1u16.to_le_bytes());
                            ok.extend_from_slice(&(TABLE.len() as u16).to_le_bytes());
                            ok.extend_from_slice(TABLE.as_bytes());
                            ok.extend_from_slice(&commits.to_le_bytes());
                            // Recorded before the answer goes out: the test
                            // reads the record as soon as its sender has the
                            // answer.
                            answered.lock().unwrap().push(sequence);
                            if write_server_binary_frame(&mut stream, &ok).is_err() {
                                break;
                            }
                        }
                        sequence += 1;
                    }
                    0x9 => {
                        let _ = write_server_frame(&mut stream, 0xA, &payload, false);
                    }
                    0x8 => break,
                    _ => {}
                }
            }
        }
    });
    (port, answered)
}

/// A flush in frames fails part way, and the server confirms one of the
/// frames of it that were sent, as it does when it commits a part of a
/// flush with more rows of one table than its `qwp.max.uncommitted.rows`.
/// The error is in doubt. The sender reports no confirmed position above
/// the last frame before the failed flush, which is where `published_fsn`
/// stays: `published_fsn` less a confirmed position is never below zero.
///
/// The flush cuts its failing frame only once the server has answered the
/// frame before it, which the network thread sent. A sender in manual
/// progress mode sends nothing during a flush that has room, so only one in
/// background progress mode can have a frame of the flush confirmed.
fn a_frame_of_a_failed_flush_that_the_server_confirms_is_not_reported_as_confirmed(
    progress: Progress,
) {
    let before = buffer_of_symbols(TABLE, 0..10);
    let mut large = buffer_of_symbols(TABLE, 10..1210);
    let mut sender_symbols = SymbolGlobalDict::new();
    frame_of_a_sender(&before, false, &mut sender_symbols);
    let frames = frames_of_a_sender(&large, FRAME_LIMIT, &mut sender_symbols);
    let failing = frames.len() / 2;
    assert!(failing >= 2, "{} frames", frames.len());
    // The frame before the failing one, which has the defer flag. The
    // sequences of the connection are the frame numbers: the flush before
    // is frame 0, and frame `i` of the flush is frame `1 + i`.
    let confirmed = failing as u64;
    let (port, answered) = start_server_that_answers_a_deferred_frame(confirmed);
    let symbols = symbols_held_before(&frames[failing]);
    let mut sender = {
        let _cap = crate::ingress::TestDictCapGuard::new(symbols);
        sender_with(port, progress, NO_WAIT_AT_THE_END)
    };

    assert_eq!(sender.flush_and_keep_and_get_fsn(&before).unwrap(), Some(0));
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    let err = {
        let (answered, mut later_frames) = (Arc::clone(&answered), 0);
        let _hook = LaterFrameHookGuard::new(Box::new(move || {
            later_frames += 1;
            if later_frames == failing {
                wait_until(WAIT, || answered.lock().unwrap().contains(&confirmed));
            }
        }));
        sender.flush(&mut large).unwrap_err()
    };
    assert_eq!(err.code(), ErrorCode::FlushAborted, "{}", err.msg());
    assert!(err.in_doubt());
    assert_eq!(err.msg(), stopped_by_a_full_dictionary(symbols, true));
    // The queue takes the answer of the frame.
    let deadline = Instant::now() + WAIT;
    while sender.qwp_ws_queue_completed_fsn() != Some(confirmed) {
        assert!(
            Instant::now() < deadline,
            "the server answered {:?}, the queue confirmed {:?}",
            answered.lock().unwrap(),
            sender.qwp_ws_queue_completed_fsn()
        );
        let_it_work(&mut sender, progress);
    }
    assert_eq!(*answered.lock().unwrap(), [0, confirmed]);

    assert_eq!(sender.published_fsn().unwrap(), Some(0));
    assert_eq!(sender.acked_fsn().unwrap(), Some(0));
    assert_eq!(sender.completed_fsn(AckLevel::Ok).unwrap(), Some(0));
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert!(sender.must_close());
    drop(sender);
}

fn a_later_flush_without_room_in_the_queue_gets_the_error_of_the_failed_flush(progress: Progress) {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let large = buffer_of_symbols(TABLE, 10..160);
    let frames = frames_of_a_sender(&large, 492, &mut SymbolGlobalDict::new());
    // The queue of eight segments holds the flush, two frames a segment.
    assert!((10..=14).contains(&frames.len()), "{} frames", frames.len());
    let failing = frames.len() - 1;
    let symbols = symbols_held_before(&frames[failing]);
    let settings = format!("{EIGHT_SEGMENTS}sf_append_deadline_millis=1000;");
    let mut sender = {
        let _cap = crate::ingress::TestDictCapGuard::new(symbols);
        sender_with(server.port, progress, &settings)
    };

    let err = sender.flush_and_keep(&large).unwrap_err();
    assert_stopped_by_a_full_dictionary(&sender, progress, &err, symbols);
    // The frames of the failed flush stay in the queue, which has no room
    // for as many again, and gets none: the server confirms none of them.
    // The sender does not wait for it.
    let refused = sender.flush_and_keep(&large).unwrap_err();
    assert_eq!((refused.code(), refused.msg()), (err.code(), err.msg()));
    assert_eq!(sender.published_fsn().unwrap(), None);
    sender.close_drain().unwrap();
    drop(sender);
    server.finish();
}

fn a_sender_whose_flush_failed_part_way_delivers_the_flush_before_it_on_a_new_connection(
    progress: Progress,
) {
    // The server takes five frames of the flush before, and ends the
    // connection: the rows it held are gone, and nothing is committed.
    const CUT_AFTER_FRAMES: usize = 5;
    let server = QwpWsModelServer::start_cutting_first_connection(FRAME_LIMIT, CUT_AFTER_FRAMES);
    let before = buffer_of_symbols(TABLE, 2000..2300);
    let large = buffer_of_symbols(FIRST, 10..1210);
    let mut sender_symbols = SymbolGlobalDict::new();
    let before_frames = frames_of_a_sender(&before, FRAME_LIMIT, &mut sender_symbols).len();
    assert!(before_frames > CUT_AFTER_FRAMES, "{before_frames} frames");
    let last_before = before_frames as u64 - 1;
    let frames = frames_of_a_sender(&large, FRAME_LIMIT, &mut sender_symbols);
    let failing = frames.len() / 2;
    let symbols = symbols_held_before(&frames[failing]);
    let mut sender = sender_with_a_dictionary_of(server.port, progress, symbols);

    assert_eq!(
        sender.flush_and_keep_and_get_fsn(&before).unwrap(),
        Some(last_before)
    );
    let err = sender.flush_and_keep(&large).unwrap_err();
    assert_stopped_by_a_full_dictionary(&sender, progress, &err, symbols);
    assert_eq!(sender.published_fsn().unwrap(), Some(last_before));

    // On its second connection the sender sends the symbols it had sent and
    // the flush before, which the server commits and confirms, and no frame
    // of the failed flush that it had not sent before the flush failed.
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_eq!(
        sender.completed_fsn(AckLevel::Ok).unwrap(),
        Some(last_before)
    );
    assert_eq!(sender.published_fsn().unwrap(), Some(last_before));
    let totals = sender.qwp_ws_totals().unwrap();
    assert_eq!(totals.reconnects_succeeded, 1);
    let refused = sender.flush_and_keep(&large).unwrap_err();
    assert_eq!((refused.code(), refused.msg()), (err.code(), err.msg()));
    sender.close_drain().unwrap();
    assert_table_holds(&server, TABLE, 1, &[&before]);
    let held = server.model.table(FIRST).unwrap_or_default();
    assert_eq!((held.commits, held.row_count()), (0, 0));

    drop(sender);
    wait_for_no_connection(&server);
    // The rows of the failed flush are all of its table, which the server
    // makes when it takes the first frame for it: it took a frame of the
    // flush only if the error is in doubt.
    assert!(server.model.table(FIRST).is_none() || err.in_doubt());
    let mut sender = sender_with(server.port, progress, "");
    sender.flush_and_keep(&large).unwrap();
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_table_holds(&server, TABLE, 1, &[&before]);
    assert_table_holds(&server, FIRST, 1, &[&large]);
    drop(sender);
    server.finish();
}

/// The files in the slot of [`slot_settings`], but the lock files, which
/// stay for the next sender.
/// The files in the slots of the senders that [`on_disk`] gives a slot, as
/// `<slot>/<file>`, but their lock files. None with the queues in memory.
fn files_in_the_slots() -> Vec<String> {
    SF_DIR.with(|sf_dir| {
        let sf_dir = sf_dir.borrow();
        let Some((dir, _)) = sf_dir.as_ref() else {
            return Vec::new();
        };
        let mut files = Vec::new();
        for slot in std::fs::read_dir(dir.path()).unwrap().flatten() {
            if !slot.path().is_dir() {
                continue;
            }
            for file in std::fs::read_dir(slot.path()).unwrap().flatten() {
                let name = file.file_name().to_string_lossy().into_owned();
                if !name.starts_with(".lock") {
                    files.push(format!("{}/{name}", slot.file_name().to_string_lossy()));
                }
            }
        }
        files.sort();
        files
    })
}

fn files_in_the_slot(sf_dir: &tempfile::TempDir) -> Vec<String> {
    let mut files: Vec<String> = std::fs::read_dir(sf_dir.path().join("large"))
        .unwrap()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| !name.starts_with(".lock"))
        .collect();
    files.sort();
    files
}

/// A flush before, of one frame, and a buffer whose flush in frames stops at
/// a middle frame, for a sender that has flushed the one before: the frames
/// queued when it stops, and the size of the dictionary that is full then.
fn a_flush_before_and_one_that_stops_part_way() -> (Buffer, Buffer, usize, usize) {
    let before = buffer_of_symbols(TABLE, 0..10);
    let large = buffer_of_symbols(TABLE, 10..1210);
    let mut sender_symbols = SymbolGlobalDict::new();
    frame_of_a_sender(&before, false, &mut sender_symbols);
    let frames = frames_of_a_sender(&large, FRAME_LIMIT, &mut sender_symbols);
    assert!(frames.len() > 40, "{} frames", frames.len());
    let failing = frames.len() / 2;
    let symbols = symbols_held_before(&frames[failing]);
    (before, large, failing, symbols)
}

/// With `sf_dir`: once the flush before the failed one is confirmed,
/// `close_drain` closes the slot as after a complete drain. Nothing of the
/// failed flush is left in it, and no symbol: the next sender on the slot
/// sends nothing, and starts with an empty dictionary.
fn a_close_drain_after_a_flush_that_failed_part_way_leaves_an_empty_slot(progress: Progress) {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    server.hold_answers();
    let sf_dir = tempfile::TempDir::new().unwrap();
    let settings = slot_settings(&sf_dir);
    let (before, mut large, failing, symbols) = a_flush_before_and_one_that_stops_part_way();
    // Every sender of the test has a dictionary of this size.
    let _cap = crate::ingress::TestDictCapGuard::new(symbols);
    let mut sender = sender_with(server.port, progress, &settings);

    assert_eq!(sender.flush_and_keep_and_get_fsn(&before).unwrap(), Some(0));
    let err = sender.flush(&mut large).unwrap_err();
    assert_stopped_by_a_full_dictionary(&sender, progress, &err, symbols);
    wait_for_frames_sent(&mut sender, progress, &server, 1);
    assert!(segment_files(&sf_dir) > 0);
    server.let_answers_go();
    sender.close_drain().unwrap();
    assert_eq!(files_in_the_slot(&sf_dir), Vec::<String>::new());
    assert_table_holds(&server, TABLE, 1, &[&before]);
    drop(sender);
    wait_for_no_connection(&server);
    assert_taken_of_the_failed_flush(&err, progress, server.frames_taken() - 1, failing);

    // With a dictionary of the same size, the next sender takes as many
    // symbols that are new to it.
    let taken = server.frames_taken();
    let mut sender = sender_with(server.port, progress, &settings);
    assert_eq!(sender.published_fsn().unwrap(), None);
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    let new_symbols = buffer_of_symbols(TABLE, 5000..5000 + symbols as i64);
    let frames = frames_of_a_sender(&new_symbols, FRAME_LIMIT, &mut SymbolGlobalDict::new());
    sender.flush_and_keep(&new_symbols).unwrap();
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_eq!(server.frames_taken(), taken + frames.len());
    assert_table_holds(&server, TABLE, 2, &[&before, &new_symbols]);
    drop(sender);
    server.finish();
}

/// Parks the network thread of a sender once at its
/// [`ConfirmationStoredHook`], with the confirmation stored in the queue and
/// not yet written to the watermark, until the test lets it go.
#[derive(Default)]
struct ConfirmationHold {
    state: Mutex<ConfirmationHoldState>,
    changed: Condvar,
}

#[derive(Default)]
struct ConfirmationHoldState {
    armed: bool,
    /// The confirmed position that the queue held when the thread parked.
    parked_at: Option<Option<u64>>,
    released: bool,
}

impl ConfirmationHold {
    fn hook(self: &Arc<Self>) -> ConfirmationStoredHook {
        let hold = Arc::clone(self);
        Arc::new(move |completed_fsn| hold.park(completed_fsn))
    }

    fn park(&self, completed_fsn: Option<u64>) {
        let mut state = self.state.lock().unwrap();
        if !state.armed {
            return;
        }
        state.armed = false;
        state.parked_at = Some(completed_fsn);
        self.changed.notify_all();
        let deadline = Instant::now() + WAIT;
        while !state.released {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            state = self.changed.wait_timeout(state, deadline - now).unwrap().0;
        }
    }

    /// The next confirmation that the thread stores parks it.
    fn arm(&self) {
        self.state.lock().unwrap().armed = true;
    }

    /// Waits until the thread has parked, and gives the confirmed position
    /// that the queue held then.
    fn wait_until_parked(&self) -> Option<u64> {
        let deadline = Instant::now() + WAIT;
        let mut state = self.state.lock().unwrap();
        loop {
            if let Some(parked_at) = state.parked_at {
                return parked_at;
            }
            let now = Instant::now();
            assert!(now < deadline, "the network thread did not park");
            state = self.changed.wait_timeout(state, deadline - now).unwrap().0;
        }
    }

    fn release(&self) {
        self.state.lock().unwrap().released = true;
        self.changed.notify_all();
    }
}

/// The confirmation of the flush before the failed one comes as
/// `close_drain` starts: the network thread has stored it in the queue and
/// not yet written it to the watermark of the slot. The close keeps it, and
/// the next sender on the slot sends nothing again.
#[test]
fn a_confirmation_that_comes_as_close_drain_starts_after_a_flush_that_failed_part_way_is_kept() {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    server.hold_answers();
    let sf_dir = tempfile::TempDir::new().unwrap();
    let settings = slot_settings(&sf_dir);
    let (before, mut large, failing, symbols) = a_flush_before_and_one_that_stops_part_way();
    let hold = Arc::new(ConfirmationHold::default());
    let _hook = ConfirmationStoredHookGuard::new(hold.hook());
    let mut sender = {
        let _cap = crate::ingress::TestDictCapGuard::new(symbols);
        sender_with(server.port, Progress::Background, &settings)
    };

    assert_eq!(sender.flush_and_keep_and_get_fsn(&before).unwrap(), Some(0));
    let err = sender.flush(&mut large).unwrap_err();
    assert_stopped_by_a_full_dictionary(&sender, Progress::Background, &err, symbols);
    wait_for_frames_taken(&server, 1);
    hold.arm();
    server.let_answers_go();
    assert_eq!(hold.wait_until_parked(), Some(0));
    thread::scope(|scope| {
        scope.spawn(|| {
            thread::sleep(Duration::from_millis(200));
            hold.release();
        });
        sender.close_drain().unwrap();
    });
    drop(sender);
    wait_for_no_connection(&server);
    assert_table_holds(&server, TABLE, 1, &[&before]);
    let taken = server.frames_taken();
    assert_taken_of_the_failed_flush(&err, Progress::Background, taken - 1, failing);

    let mut sender = sender_with(server.port, Progress::Background, &settings);
    assert_eq!(sender.published_fsn().unwrap(), None);
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    // Time for a frame sent again to reach the server.
    thread::sleep(Duration::from_millis(200));
    assert_eq!(server.frames_taken(), taken);
    assert_table_holds(&server, TABLE, 1, &[&before]);
    drop(sender);
    server.finish();
}

/// After a flush that failed part way, the network thread is slow to stop
/// when `close_drain` comes: it is parked with the confirmation of the flush
/// before stored in the queue. `close_drain` gives up at its timeout and
/// closes nothing. The drop of the sender stops the thread, and the next
/// sender on the slot commits nothing again.
#[test]
fn a_close_drain_after_a_flush_that_failed_part_way_gives_up_at_its_timeout_while_the_network_thread_stops()
 {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    server.hold_answers();
    let sf_dir = tempfile::TempDir::new().unwrap();
    let settings = format!("{}{CLOSE_FLUSH_TIMEOUT_SETTING}", slot_settings(&sf_dir));
    let (before, mut large, failing, symbols) = a_flush_before_and_one_that_stops_part_way();
    let hold = Arc::new(ConfirmationHold::default());
    let _hook = ConfirmationStoredHookGuard::new(hold.hook());
    let mut sender = {
        let _cap = crate::ingress::TestDictCapGuard::new(symbols);
        sender_with(server.port, Progress::Background, &settings)
    };

    assert_eq!(sender.flush_and_keep_and_get_fsn(&before).unwrap(), Some(0));
    let aborted = sender.flush(&mut large).unwrap_err();
    assert_stopped_by_a_full_dictionary(&sender, Progress::Background, &aborted, symbols);
    wait_for_frames_taken(&server, 1);
    hold.arm();
    server.let_answers_go();
    assert_eq!(hold.wait_until_parked(), Some(0));
    let started = Instant::now();
    let err = sender.close_drain().unwrap_err();
    let took = started.elapsed();
    hold.release();
    assert!(
        took >= CLOSE_FLUSH_TIMEOUT && took < CLOSE_FLUSH_TIMEOUT + Duration::from_secs(2),
        "close_drain took {took:?}"
    );
    assert_eq!(err.code(), ErrorCode::SocketError, "{}", err.msg());
    assert_eq!(
        err.msg(),
        "QWP/WebSocket close drain timed out while the sender was closing its connection after \
         the flush that stopped part way. The flushes before it are confirmed, and nothing of \
         that flush is committed: only a flush with more rows of one table than the server's \
         qwp.max.uncommitted.rows may be committed in part. Drop the sender: the next sender on \
         the slot under sf_dir removes that flush."
    );
    assert!(segment_files(&sf_dir) > 0, "the slot is not closed");
    drop(sender);
    wait_for_no_connection(&server);
    assert_table_holds(&server, TABLE, 1, &[&before]);
    assert_taken_of_the_failed_flush(
        &aborted,
        Progress::Background,
        server.frames_taken() - 1,
        failing,
    );

    // The next sender on the slot holds the flush before, confirmed, and
    // nothing of the failed one. It sends neither again.
    let mut sender = sender_with(server.port, Progress::Background, &settings);
    assert_eq!(sender.published_fsn().unwrap(), Some(0));
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    // Time for a frame sent again to reach the server.
    thread::sleep(Duration::from_millis(200));
    assert_table_holds(&server, TABLE, 1, &[&before]);
    drop(sender);
    server.finish();
}

/// `close_drain` after a flush that failed part way stops the network thread
/// of the sender, and with it the connection, before it gives the slot up. A
/// second sender on the slot, opened while the first one is still there, is
/// the only one that sends.
#[test]
fn a_second_sender_on_the_slot_of_a_sender_closed_after_a_flush_that_failed_part_way_sends_alone() {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let sf_dir = tempfile::TempDir::new().unwrap();
    let settings = slot_settings(&sf_dir);
    let mut large = buffer_of_symbols(TABLE, 10..1210);
    let frames = frames_of_a_sender(&large, FRAME_LIMIT, &mut SymbolGlobalDict::new());
    let failing = frames.len() / 2;
    let symbols = symbols_held_before(&frames[failing]);
    let mut first = {
        let _cap = crate::ingress::TestDictCapGuard::new(symbols);
        sender_with(server.port, Progress::Background, &settings)
    };

    let err = first.flush(&mut large).unwrap_err();
    assert_stopped_by_a_full_dictionary(&first, Progress::Background, &err, symbols);
    // There is nothing before the failed flush to wait for, and the network
    // thread may still be sending the frames of the failed one.
    first.close_drain().unwrap();
    // The connection has ended, and with it the rows that the server held.
    wait_for_no_connection(&server);
    let taken = server.frames_taken();
    assert_taken_of_the_failed_flush(&err, Progress::Background, taken, failing);

    let mut second = sender_with(server.port, Progress::Background, &settings);
    assert_eq!(second.published_fsn().unwrap(), None);
    second.flush(&mut large).unwrap();
    second.wait(AckLevel::Ok, WAIT).unwrap();
    assert_eq!(server.frames_taken(), taken + frames.len());
    let large = buffer_of_symbols(TABLE, 10..1210);
    assert_table_holds(&server, TABLE, 1, &[&large]);
    drop(first);
    drop(second);
    server.finish();
}

/// A flush of symbols, and a buffer whose flush in frames after it stops at
/// frame `which(frame count)` because the dictionary of the sender is full:
/// the size of that dictionary. A dictionary of that size takes the symbols
/// of the buffer alone, and not those of both: a slot whose dictionary grew
/// over earlier flushes.
fn a_flush_of_symbols_and_one_that_fills_the_dictionary_after_it(
    which: fn(usize) -> usize,
) -> (Buffer, Buffer, usize) {
    let prior = buffer_of_symbols(TABLE, 100_000..102_000);
    let large = buffer_of_symbols(TABLE, 10..1210);
    let mut symbols_of_large = SymbolGlobalDict::new();
    frames_of_a_sender(&large, FRAME_LIMIT, &mut symbols_of_large);
    let mut sender_symbols = SymbolGlobalDict::new();
    frames_of_a_sender(&prior, FRAME_LIMIT, &mut sender_symbols);
    let frames = frames_of_a_sender(&large, FRAME_LIMIT, &mut sender_symbols);
    assert!(frames.len() > 40, "{} frames", frames.len());
    let failing = which(frames.len());
    assert!((1..frames.len()).contains(&failing));
    let symbols = symbols_held_before(&frames[failing]);
    assert!(
        symbols_of_large.len() as usize <= symbols,
        "{} symbols of the buffer alone, a dictionary of {symbols}",
        symbols_of_large.len()
    );
    (prior, large, symbols)
}

/// Flushes `prior` through `sender` and waits until the server confirms it,
/// then flushes `large`, which stops part way because the dictionary of the
/// sender is full with `symbols` symbols.
fn flush_until_the_dictionary_is_full(
    sender: &mut Sender,
    progress: Progress,
    prior: &Buffer,
    large: &mut Buffer,
    symbols: usize,
) {
    let (rows, len) = (large.row_count(), large.len());
    sender.flush_and_keep(prior).unwrap();
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    let err = sender.flush(large).unwrap_err();
    assert_stopped_by_a_full_dictionary(sender, progress, &err, symbols);
    assert_eq!(
        (large.row_count(), large.len()),
        (rows, len),
        "the buffer keeps its rows"
    );
}

/// With `sf_dir`: a flush in frames brings symbols to a slot that holds
/// those of a confirmed flush before it, and stops part way because the
/// dictionary is full. Once `close_drain` succeeded, a new sender on the
/// slot, whose dictionary takes as many symbols, flushes the same buffer.
/// The server holds each flush once.
fn a_new_sender_on_the_slot_flushes_a_buffer_that_a_full_dictionary_stopped_after_close_drain(
    progress: Progress,
) {
    for which in [|_| 1, |frames| frames / 2, |frames| frames - 1] {
        let server = QwpWsModelServer::start(FRAME_LIMIT);
        let sf_dir = tempfile::TempDir::new().unwrap();
        let settings = slot_settings(&sf_dir);
        let (prior, mut large, symbols) =
            a_flush_of_symbols_and_one_that_fills_the_dictionary_after_it(which);
        // Every sender of the test has a dictionary of this size, as every
        // sender has the same cap.
        let _cap = crate::ingress::TestDictCapGuard::new(symbols);
        let mut sender = sender_with(server.port, progress, &settings);
        flush_until_the_dictionary_is_full(&mut sender, progress, &prior, &mut large, symbols);
        sender.close_drain().unwrap();
        drop(sender);
        assert_table_holds(&server, TABLE, 1, &[&prior]);

        let mut sender = sender_with(server.port, progress, &settings);
        let flushed = sender.flush(&mut large);
        assert!(
            flushed.is_ok(),
            "{:?}",
            flushed.map_err(|err| err.msg().to_string())
        );
        assert!(large.is_empty());
        sender.wait(AckLevel::Ok, WAIT).unwrap();
        let large = buffer_of_symbols(TABLE, 10..1210);
        assert_table_holds(&server, TABLE, 2, &[&prior, &large]);
        assert!(!sender.must_close());
        sender.close_drain().unwrap();
        drop(sender);
        server.finish();
    }
}

/// With `sf_dir`: the same flush stops part way, and its sender is dropped
/// without a `close_drain` that waits, as when the process dies. The next
/// sender on the slot starts with the symbols of the slot, so its flush of
/// the same buffer stops the same way, and commits nothing. Its
/// `close_drain` empties the slot, and the sender after it flushes the
/// buffer.
fn a_full_dictionary_stops_the_flush_once_more_on_the_slot_of_a_sender_dropped_without_close_drain(
    progress: Progress,
) {
    for which in [|_| 1, |frames| frames / 2, |frames| frames - 1] {
        let server = QwpWsModelServer::start(FRAME_LIMIT);
        let sf_dir = tempfile::TempDir::new().unwrap();
        let settings = slot_settings(&sf_dir);
        let dropped = format!("{settings}{NO_WAIT_AT_THE_END}");
        let (prior, mut large, symbols) =
            a_flush_of_symbols_and_one_that_fills_the_dictionary_after_it(which);
        // Every sender of the test has a dictionary of this size, as every
        // sender has the same cap.
        let _cap = crate::ingress::TestDictCapGuard::new(symbols);
        let mut sender = sender_with(server.port, progress, &dropped);
        flush_until_the_dictionary_is_full(&mut sender, progress, &prior, &mut large, symbols);
        drop(sender);
        assert!(segment_files(&sf_dir) > 0);

        let mut sender = sender_with(server.port, progress, &settings);
        let err = sender.flush(&mut large).unwrap_err();
        assert_stopped_by_a_full_dictionary(&sender, progress, &err, symbols);
        sender.close_drain().unwrap();
        assert_eq!(files_in_the_slot(&sf_dir), Vec::<String>::new());
        drop(sender);
        assert_table_holds(&server, TABLE, 1, &[&prior]);

        let mut sender = sender_with(server.port, progress, &settings);
        sender.flush(&mut large).unwrap();
        assert!(large.is_empty());
        sender.wait(AckLevel::Ok, WAIT).unwrap();
        let large = buffer_of_symbols(TABLE, 10..1210);
        assert_table_holds(&server, TABLE, 2, &[&prior, &large]);
        sender.close_drain().unwrap();
        drop(sender);
        server.finish();
    }
}

/// What a server answers a frame whose columns disagree with the table. A
/// sender that gets it stops for good.
pub(super) const SCHEMA_MISMATCH: u8 = 0x03;
/// What a server answers a frame that it could not write. A sender that gets
/// it connects again and sends every frame that is not confirmed.
const WRITE_ERROR: u8 = 0x09;
/// What a primary answers once an in-place role switch has made it a
/// replica. A sender that gets it connects again, to this server or another,
/// and sends every frame that is not confirmed.
const NOT_WRITABLE: u8 = 0x0C;

/// The first error of a server that `sender` reads, once it has read it.
fn the_server_error_read_by(sender: &mut Sender, progress: Progress) -> QwpWsSenderError {
    let deadline = Instant::now() + WAIT;
    loop {
        match progress {
            Progress::Background => thread::sleep(Duration::from_millis(1)),
            Progress::Manual => {
                sender.drive_once().unwrap();
            }
        }
        if let Some(rejection) = sender.poll_qwp_ws_error().unwrap() {
            return rejection;
        }
        assert!(Instant::now() < deadline, "the sender read no error");
    }
}

/// Checks that `err` is the rejection for good of frame `fsn` of the sender.
fn assert_rejected_for_good(err: &crate::Error, fsn: u64) {
    assert_eq!(err.code(), ErrorCode::ServerRejection, "{}", err.msg());
    assert_rejection_for_good(
        err.qwp_ws_rejection().expect("what the server rejected"),
        fsn,
    );
}

/// Checks that `rejection` is the rejection for good of frame `fsn` of the
/// sender.
fn assert_rejection_for_good(rejection: &QwpWsSenderError, fsn: u64) {
    assert_eq!(rejection.category, QwpWsErrorCategory::SchemaMismatch);
    assert_eq!(rejection.applied_policy, QwpWsErrorPolicy::Terminal);
    assert_eq!(rejection.status, Some(SCHEMA_MISMATCH));
    assert_eq!((rejection.from_fsn, rejection.to_fsn), (fsn, fsn));
}

/// The server rejects a middle frame of a flush in frames for good, and the
/// sender learns of it after `flush` returned: `wait` and `close_drain`
/// report the rejection, which names that frame, and the sender takes no
/// more flushes. Nothing of the flush is committed, the flush before it
/// stays, and the same rows through a new sender are one commit.
fn a_flush_with_a_frame_that_the_server_rejects_for_good_stops_the_sender_and_commits_nothing(
    progress: Progress,
) {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let mut sender = sender_with(server.port, progress, "");
    let before = buffer_of(TABLE, 0..3);
    let large = buffer_of(TABLE, 3..2003);
    let frame_count = frames_of_a_flush(&large, FRAME_LIMIT).len();
    assert!(frame_count > 40, "{frame_count} frames");
    // Of the frames of the flush, counted from 0.
    let rejected = frame_count / 2;

    assert_eq!(sender.flush_and_keep_and_get_fsn(&before).unwrap(), Some(0));
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    // The flush before is the first frame that the server takes and frame 0
    // of the sender, so the frames of the flush are 2 and up for the server
    // and 1 and up for the sender. The answer waits until `flush` returned.
    server.reject_frame(2 + rejected, SCHEMA_MISMATCH);
    server.hold_answers();
    let mut flushed = large.clone();
    let last = sender.flush_and_get_fsn(&mut flushed).unwrap();
    assert_eq!(last, Some(frame_count as u64));
    assert!(flushed.is_empty());
    wait_for_frames_sent(&mut sender, progress, &server, 1 + frame_count);
    assert!(!sender.must_close());
    server.let_answers_go();

    // The rejected frame belongs to the flush whose number is the first at
    // or above it.
    let fsn = 1 + rejected as u64;
    assert!(Some(0) < Some(fsn) && Some(fsn) < last);
    assert_rejected_for_good(&sender.wait(AckLevel::Ok, WAIT).unwrap_err(), fsn);
    assert!(sender.must_close());
    assert_rejected_for_good(&sender.flush_and_keep(&before).unwrap_err(), fsn);
    assert_rejected_for_good(&sender.close_drain().unwrap_err(), fsn);
    // The server has read every frame of the flush, and committed none.
    assert_eq!(server.frames_taken(), 1 + frame_count);
    assert_table_holds(&server, TABLE, 1, &[&before]);

    drop(sender);
    wait_for_no_connection(&server);
    let mut sender = sender_with(server.port, progress, "");
    sender.flush_and_keep(&large).unwrap();
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_table_holds(&server, TABLE, 2, &[&before, &large]);
    drop(sender);
    server.finish();
}

/// The server rejects a middle frame of a flush in frames with an error
/// that a sender answers by connecting again. The rows that the first
/// connection held are gone with the rejection. The sender sends the whole
/// flush again, and the server commits it once. In the background the
/// rejection may come while `flush` still publishes.
fn a_flush_with_a_frame_that_the_server_rejects_once_is_sent_again_whole(progress: Progress) {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let mut sender = sender_with(server.port, progress, "");
    let before = buffer_of(TABLE, 0..3);
    let large = buffer_of(TABLE, 3..2003);
    let after = buffer_of(TABLE, 2003..2006);
    let frame_count = frames_of_a_flush(&large, FRAME_LIMIT).len() as u64;
    assert!(frame_count > 40, "{frame_count} frames");
    let rejected = frame_count / 2;

    // Confirmed while the first connection lives, so it is not sent again.
    assert_eq!(sender.flush_and_keep_and_get_fsn(&before).unwrap(), Some(0));
    sender.wait(AckLevel::Ok, WAIT).unwrap();

    server.reject_frame(2 + rejected as usize, WRITE_ERROR);
    assert_eq!(
        sender.flush_and_keep_and_get_fsn(&large).unwrap(),
        Some(frame_count)
    );
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_eq!(
        sender.completed_fsn(AckLevel::Ok).unwrap(),
        Some(frame_count)
    );

    let totals = sender.qwp_ws_totals().unwrap();
    assert_eq!(
        (totals.server_errors, totals.reconnects_succeeded),
        (1, 1),
        "{totals:?}"
    );
    // The first connection took the frames up to the rejected one at least.
    assert!(
        totals.frames_replayed > rejected,
        "{} frames sent again",
        totals.frames_replayed
    );
    let table = server.model.table(TABLE).unwrap();
    assert_eq!(table.commits, 2);
    assert_eq!(table.blocks.len() as u64, 1 + frame_count);
    assert_eq!(table.rows_as_text(), rows_of_all(&[&before, &large]));
    assert!(!sender.must_close());

    // The sender goes on.
    sender.flush_and_keep(&after).unwrap();
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_table_holds(&server, TABLE, 3, &[&before, &large, &after]);
    drop(sender);
    server.finish();
}

/// An in-place role switch makes the server a replica while it holds the
/// rows of a flush in frames: it rejects a middle frame as not writable, and
/// the rows it held are gone with the rejection. The sender takes that as a
/// state of the server, not a fault of the frame: it connects again and
/// sends the whole flush, which the server, a primary again, commits once.
fn a_flush_with_a_frame_that_a_demoted_server_rejects_is_sent_again_whole(progress: Progress) {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let mut sender = sender_with(server.port, progress, "");
    let before = buffer_of(TABLE, 0..3);
    let large = buffer_of(TABLE, 3..2003);
    let frame_count = frames_of_a_flush(&large, FRAME_LIMIT).len() as u64;
    assert!(frame_count > 40, "{frame_count} frames");
    let rejected = frame_count / 2;

    assert_eq!(sender.flush_and_keep_and_get_fsn(&before).unwrap(), Some(0));
    sender.wait(AckLevel::Ok, WAIT).unwrap();

    server.reject_frame(2 + rejected as usize, NOT_WRITABLE);
    assert_eq!(
        sender.flush_and_keep_and_get_fsn(&large).unwrap(),
        Some(frame_count)
    );
    sender.wait(AckLevel::Ok, WAIT).unwrap();

    let rejection = sender.poll_qwp_ws_error().unwrap().expect("the rejection");
    assert_eq!(rejection.category, QwpWsErrorCategory::NotWritable);
    assert_eq!(rejection.applied_policy, QwpWsErrorPolicy::RetriableOther);
    assert_eq!(rejection.from_fsn, 1 + rejected);
    assert_eq!(sender.poll_qwp_ws_error().unwrap(), None);
    let totals = sender.qwp_ws_totals().unwrap();
    assert_eq!(
        (totals.server_errors, totals.reconnects_succeeded),
        (1, 1),
        "{totals:?}"
    );
    let table = server.model.table(TABLE).unwrap();
    assert_eq!(table.commits, 2);
    assert_eq!(table.blocks.len() as u64, 1 + frame_count);
    assert_eq!(table.rows_as_text(), rows_of_all(&[&before, &large]));
    assert!(!sender.must_close());
    drop(sender);
    server.finish();
}

/// The server rejects for good a frame of a flush that failed part way, and
/// tells so after the flush has failed. The rejection is about the failed
/// flush, whose error already says what of it may be committed. So the
/// calls about the flush before it, which is confirmed, do not fail on it,
/// and a later flush still gets the error of the failed flush. The sender
/// reports the rejection as an error of the server, and a close drain
/// empties its slot.
///
/// In background progress mode the flush cuts its failing frame only once
/// the server has taken the rejected one: its error is in doubt. A sender in
/// manual progress mode drives nothing during a flush that has room, and
/// sends no frame of the flush once it has failed: the server takes none,
/// and has nothing to reject.
fn a_rejection_of_a_frame_of_a_flush_that_failed_part_way_leaves_the_flush_before_it_confirmed(
    progress: Progress,
) {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let before = buffer_of_symbols(TABLE, 0..10);
    let large = buffer_of_symbols(TABLE, 10..1210);
    let mut sender_symbols = SymbolGlobalDict::new();
    frame_of_a_sender(&before, false, &mut sender_symbols);
    let frames = frames_of_a_sender(&large, FRAME_LIMIT, &mut sender_symbols);
    let failing = frames.len() / 2;
    assert!(failing > 2, "{} frames", frames.len());
    let symbols = symbols_held_before(&frames[failing]);
    let mut sender = sender_with_a_dictionary_of(server.port, progress, symbols);

    assert_eq!(sender.flush_and_keep_and_get_fsn(&before).unwrap(), Some(0));
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    // The server takes the flush before as its first frame. It rejects the
    // second frame of the failed flush, which is frame 2 of the sender, and
    // tells so when the flush has failed.
    server.reject_frame(3, SCHEMA_MISMATCH);
    server.hold_answers();
    let err = {
        let (frames_taken, mut later_frames) = (server.frames_taken_reader(), 0);
        let _hook = matches!(progress, Progress::Background).then(|| {
            LaterFrameHookGuard::new(Box::new(move || {
                later_frames += 1;
                if later_frames == failing {
                    wait_until(WAIT, || frames_taken() >= 3);
                }
            }))
        });
        sender.flush_and_keep(&large).unwrap_err()
    };
    assert_stopped_by_a_full_dictionary(&sender, progress, &err, symbols);
    assert_eq!(err.in_doubt(), matches!(progress, Progress::Background));
    server.let_answers_go();

    match progress {
        Progress::Background => {
            assert_rejection_for_good(&the_server_error_read_by(&mut sender, progress), 2);
            assert_eq!(sender.poll_qwp_ws_error().unwrap(), None);
        }
        Progress::Manual => {
            for _ in 0..10 {
                sender.drive_once().unwrap();
            }
            assert_eq!(sender.poll_qwp_ws_error().unwrap(), None);
            assert_eq!(server.frames_taken(), 1);
        }
    }
    assert_eq!(sender.published_fsn().unwrap(), Some(0));
    assert_eq!(sender.acked_fsn().unwrap(), Some(0));
    assert_eq!(sender.completed_fsn(AckLevel::Ok).unwrap(), Some(0));
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    let err = sender.flush_and_keep(&before).unwrap_err();
    assert_stopped_by_a_full_dictionary(&sender, progress, &err, symbols);
    sender.close_drain().unwrap();
    assert_eq!(files_in_the_slots(), Vec::<String>::new());
    assert_table_holds(&server, TABLE, 1, &[&before]);
    drop(sender);
    server.finish();
}

/// Flushes a few rows, which the server confirms, and then a buffer of
/// several frames through a sender whose first connection the server ends
/// when it has taken the flush before and `taken` frames of the large one.
/// The sender connects again. Returns what the table holds when `wait` has
/// returned, and both buffers.
fn flush_through_a_connection_that_is_lost(
    progress: Progress,
    taken: usize,
) -> (ModelTable, Buffer, Buffer) {
    let server = QwpWsModelServer::start_cutting_first_connection(FRAME_LIMIT, 1 + taken);
    let mut sender = sender_with(server.port, progress, "");
    let before = buffer_of(TABLE, 0..3);
    let large = buffer_of(TABLE, 3..403);
    let frame_count = frames_of_a_flush(&large, FRAME_LIMIT).len() as u64;

    assert_eq!(sender.flush_and_keep_and_get_fsn(&before).unwrap(), Some(0));
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_eq!(
        sender.flush_and_keep_and_get_fsn(&large).unwrap(),
        Some(frame_count)
    );
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_eq!(
        sender.completed_fsn(AckLevel::Ok).unwrap(),
        Some(frame_count)
    );
    let totals = sender.qwp_ws_totals().unwrap();
    assert_eq!(totals.reconnects_succeeded, 1, "{taken} frames taken");
    assert!(!sender.must_close());
    drop(sender);
    let table = server.model.table(TABLE).unwrap();
    server.finish();
    (table, before, large)
}

/// The connection is lost when the server has taken some frames of a flush
/// and not its last: after one frame, after two, and so on to all but the
/// last. Each time the rows that the server held are gone, the sender sends
/// the whole flush again, and the server commits it once. In the background
/// the connection may be lost while `flush` still publishes.
fn a_flush_is_committed_once_wherever_its_connection_is_lost_before_the_commit(progress: Progress) {
    let frame_count = frames_of_a_flush(&buffer_of(TABLE, 3..403), FRAME_LIMIT).len();
    assert!(frame_count >= 8, "{frame_count} frames");
    for taken in 1..frame_count {
        let (table, before, large) = flush_through_a_connection_that_is_lost(progress, taken);
        assert_eq!(table.commits, 2, "{taken} frames taken");
        assert_eq!(table.blocks.len(), 1 + frame_count);
        assert_eq!(
            table.rows_as_text(),
            rows_of_all(&[&before, &large]),
            "{taken} frames taken"
        );
    }
}

/// The connection is lost when the server has taken every frame of a flush
/// and committed it, before the sender has the answer. The sender cannot
/// tell this from a flush that was not committed: it sends the flush again,
/// and the server commits it a second time. The table holds every row of
/// the flush twice, each time as one commit.
fn a_flush_whose_connection_is_lost_after_the_commit_and_before_its_answer_is_committed_again(
    progress: Progress,
) {
    let frame_count = frames_of_a_flush(&buffer_of(TABLE, 3..403), FRAME_LIMIT).len();
    let (table, before, large) = flush_through_a_connection_that_is_lost(progress, frame_count);
    assert_eq!(table.commits, 3);
    assert_eq!(table.blocks.len(), 1 + 2 * frame_count);
    assert_eq!(
        table.rows_as_text(),
        rows_of_all(&[&before, &large, &large])
    );
}

/// The server closes every connection when it has taken a few frames of
/// it, so a flush of more frames never reaches its last one. No frame of
/// a flush is confirmed before the last, so each close finds the same frame
/// as the oldest that is not confirmed: at the fourth close
/// (`max_frame_rejections`) the sender stops for good. Nothing of the flush
/// is committed, and the flush before it stays.
fn a_flush_whose_every_connection_the_server_closes_stops_the_sender_at_the_fourth_close(
    progress: Progress,
) {
    const CLOSED_AFTER_FRAMES: usize = 6;
    let server = QwpWsModelServer::start_closing_every_connection(FRAME_LIMIT, CLOSED_AFTER_FRAMES);
    // Closes count at once, not only those of five seconds and more.
    let mut sender = sender_with(
        server.port,
        progress,
        "poison_min_escalation_window_millis=0;",
    );
    let before = buffer_of(TABLE, 0..3);
    let large = buffer_of(TABLE, 3..2003);
    let frame_count = frames_of_a_flush(&large, FRAME_LIMIT).len() as u64;
    assert!(frame_count > 40, "{frame_count} frames");

    assert_eq!(sender.flush_and_keep_and_get_fsn(&before).unwrap(), Some(0));
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_eq!(
        sender.flush_and_keep_and_get_fsn(&large).unwrap(),
        Some(frame_count)
    );

    // Frame 1 of the sender is the first of the flush.
    const STOPPED: &str = "QWP/WebSocket frame fsn 1 was closed 4 times without ACK progress";
    let err = sender.wait(AckLevel::Ok, WAIT).unwrap_err();
    assert!(err.msg().contains(STOPPED), "{}", err.msg());
    assert!(sender.must_close());
    let refused = sender.flush_and_keep(&before).unwrap_err();
    assert!(refused.msg().contains(STOPPED), "{}", refused.msg());
    let closed = sender.close_drain().unwrap_err();
    assert!(closed.msg().contains(STOPPED), "{}", closed.msg());

    // Four connections, each closed at its sixth frame. The first one took
    // the flush before as its first frame.
    assert_eq!(server.frames_taken(), 4 * CLOSED_AFTER_FRAMES);
    assert_table_holds(&server, TABLE, 1, &[&before]);
    drop(sender);
    server.finish();
}

/// What `close_drain` says when its time is up before the server has
/// confirmed `frames` of the frames that the sender published: with
/// `sf_dir` ([`on_disk`]) those frames stay in the slot.
fn close_drain_timed_out(frames: usize) -> String {
    let what_to_do = if SF_DIR.with(|sf_dir| sf_dir.borrow().is_some()) {
        "They stay in the slot under sf_dir and the next sender on the slot sends them: to \
         deliver them with this sender, call wait before closing or raise \
         close_flush_timeout_millis."
    } else {
        "Without sf_dir they are dropped with the sender: call wait before closing, raise \
         close_flush_timeout_millis, or use sf_dir."
    };
    format!(
        "QWP/WebSocket close drain timed out before all published frames were acknowledged: \
         {frames} of them are not confirmed. {what_to_do}"
    )
}

const CLOSE_FLUSH_TIMEOUT: Duration = Duration::from_millis(200);
const CLOSE_FLUSH_TIMEOUT_SETTING: &str = "close_flush_timeout_millis=200;";

/// Closes `sender`, whose `close_drain` fails when `close_flush_timeout` is
/// over, and gives the text of the error.
fn close_drain_that_times_out(sender: &mut Sender) -> String {
    let started = Instant::now();
    let err = sender.close_drain().unwrap_err();
    assert!(
        started.elapsed() >= CLOSE_FLUSH_TIMEOUT,
        "gave up after {:?}",
        started.elapsed()
    );
    assert_eq!(err.code(), ErrorCode::SocketError, "{}", err.msg());
    err.msg().to_string()
}

/// `close_drain` right after a flush in frames whose answer does not come:
/// it sends what is queued, waits as long as `close_flush_timeout` says and
/// fails. The error says how many frames are not confirmed, which are those
/// of the flush and not the one of the flush before, and what to do.
fn a_close_drain_after_a_flush_in_frames_that_is_not_confirmed_in_time_fails(progress: Progress) {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let mut sender = sender_with(server.port, progress, CLOSE_FLUSH_TIMEOUT_SETTING);
    let before = buffer_of(TABLE, 0..3);
    let large = buffer_of(TABLE, 3..2003);
    let frame_count = frames_of_a_flush(&large, FRAME_LIMIT).len();
    assert!(frame_count > 40, "{frame_count} frames");

    assert_eq!(sender.flush_and_keep_and_get_fsn(&before).unwrap(), Some(0));
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    // The server takes the flush, commits it and keeps the answer to itself.
    server.hold_answers();
    assert_eq!(
        sender.flush_and_keep_and_get_fsn(&large).unwrap(),
        Some(frame_count as u64)
    );
    assert_eq!(
        close_drain_that_times_out(&mut sender),
        close_drain_timed_out(frame_count)
    );
    // It had sent every frame: the server commits the flush.
    wait_for_frames_taken(&server, 1 + frame_count);
    assert_table_holds(&server, TABLE, 2, &[&before, &large]);
    drop(sender);
    server.finish();
}

/// `close_drain` of a sender whose flush failed part way, while the server
/// has not confirmed the flush before it. The sender waits for that flush
/// alone, so the error counts its frames and none of the failed flush.
fn a_close_drain_that_times_out_after_a_failed_flush_counts_the_frames_before_it(
    progress: Progress,
) {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    server.hold_answers();
    let before = buffer_of_symbols(TABLE, 2000..2100);
    let large = buffer_of_symbols(TABLE, 10..1210);
    let mut sender_symbols = SymbolGlobalDict::new();
    let before_frames = frames_of_a_sender(&before, FRAME_LIMIT, &mut sender_symbols).len();
    assert!(before_frames > 2, "{before_frames} frames");
    let frames = frames_of_a_sender(&large, FRAME_LIMIT, &mut sender_symbols);
    let failing = frames.len() / 2;
    let symbols = symbols_held_before(&frames[failing]);
    let mut sender = {
        let _cap = crate::ingress::TestDictCapGuard::new(symbols);
        sender_with(server.port, progress, CLOSE_FLUSH_TIMEOUT_SETTING)
    };

    assert_eq!(
        sender.flush_and_keep_and_get_fsn(&before).unwrap(),
        Some(before_frames as u64 - 1)
    );
    let err = sender.flush_and_keep(&large).unwrap_err();
    assert_stopped_by_a_full_dictionary(&sender, progress, &err, symbols);
    assert_eq!(
        close_drain_that_times_out(&mut sender),
        close_drain_timed_out(before_frames)
    );
    drop(sender);
    server.finish();
}

/// How long the network thread of a sender takes to make each spare segment
/// file after its first one, with [`HeldSpares`]: far longer than an append
/// deadline of 1 millisecond.
const SPARE_DELAY: Duration = Duration::from_millis(100);

/// How a creation of a spare segment file ends once [`HeldSpares`] lets it
/// go.
#[derive(Clone, Copy, Default)]
enum SpareEnd {
    #[default]
    Made,
    /// It fails as one that the disk refuses.
    Failed,
    /// The thread that makes it panics.
    Panicked,
}

/// The spare segment files that the network thread of a sender makes for
/// the slots under an `sf_dir`, as a test holds them back: not the one that
/// a slot makes when it is opened. Each one after the first takes
/// [`SPARE_DELAY`]. A creation of a held one then waits until the test lets
/// it go.
///
/// The test holds them by their numbers: a new slot numbers its segment
/// files in the order that it makes them, 0 for the first one in use and 1
/// for the spare that it makes when it is opened. A frame that needs a new
/// segment while no spare is being made makes that segment itself, so the
/// network thread may make none of some numbers.
#[derive(Default)]
struct HeldSpares {
    state: Mutex<HeldSparesState>,
    changed: Condvar,
}

#[derive(Default)]
struct HeldSparesState {
    begun: usize,
    /// The number of the first spare segment file that is held: those from
    /// it on wait for the test to let them go.
    held_from: u64,
    /// The number that `held_from` becomes when the test next lets the held
    /// ones go, if any: see [`HeldSpares::hold_again_from`].
    held_again_from: Option<u64>,
    /// How many creations wait for the test to let them go.
    waiting: usize,
    end: SpareEnd,
}

impl HeldSpares {
    /// Holds the spare segment files made under `sf_dir` from the first on,
    /// as long as the guard lives.
    fn hold(sf_dir: &tempfile::TempDir) -> (Arc<Self>, HotSpareCreationHookGuard) {
        let spares = Arc::new(Self::default());
        let making = Arc::clone(&spares);
        let guard = before_hot_spare_creation_for_test(
            sf_dir.path(),
            Arc::new(move |path: &std::path::Path| making.make(segment_number(path))),
        );
        (spares, guard)
    }

    /// Makes the spare segment file numbered `number`.
    fn make(&self, number: u64) -> std::io::Result<()> {
        let delayed = {
            let mut state = self.state.lock().unwrap();
            state.begun += 1;
            state.begun > 1
        };
        if delayed {
            thread::sleep(SPARE_DELAY);
        }
        let mut state = self.state.lock().unwrap();
        if number >= state.held_from {
            state.waiting += 1;
            self.changed.notify_all();
            // A test that fails to let it go must not hang.
            let deadline = Instant::now() + WAIT;
            while number >= state.held_from && Instant::now() < deadline {
                let wait_for = deadline.saturating_duration_since(Instant::now());
                state = self.changed.wait_timeout(state, wait_for).unwrap().0;
            }
            state.waiting -= 1;
        }
        let end = state.end;
        drop(state);
        match end {
            SpareEnd::Made => Ok(()),
            SpareEnd::Failed => Err(std::io::Error::other(
                "injected failure of a spare segment file",
            )),
            SpareEnd::Panicked => panic!("injected panic while making a spare segment file"),
        }
    }

    /// Has the next [`Self::let_go`] go on holding the spare segment files
    /// numbered from `number` on: the one after it lets them go.
    fn hold_again_from(&self, number: u64) {
        self.state.lock().unwrap().held_again_from = Some(number);
    }

    /// Waits until a creation waits for the test to let it go: the network
    /// thread is making a spare, and the queue has none.
    fn wait_for_a_held_spare(&self) {
        let deadline = Instant::now() + WAIT;
        let mut state = self.state.lock().unwrap();
        while state.waiting == 0 {
            assert!(Instant::now() < deadline, "no spare segment file is made");
            state = self
                .changed
                .wait_timeout(state, Duration::from_millis(10))
                .unwrap()
                .0;
        }
    }

    /// Lets every creation go, now and from now on, to end as `end` says:
    /// after [`Self::hold_again_from`], every one but those of the numbers
    /// that it holds.
    fn let_go(&self, end: SpareEnd) {
        let mut state = self.state.lock().unwrap();
        state.held_from = state.held_again_from.take().unwrap_or(u64::MAX);
        state.end = end;
        self.changed.notify_all();
    }
}

/// The number of the segment file of a slot at `path`, from its name:
/// `sf-<the number in 16 hex digits>.sfa`.
fn segment_number(path: &std::path::Path) -> u64 {
    path.file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_prefix("sf-")?.strip_suffix(".sfa"))
        .and_then(|hex| u64::from_str_radix(hex, 16).ok())
        .unwrap_or_else(|| panic!("not a segment file of a slot: {}", path.display()))
}

/// The settings of a sender whose queue is a slot of `sf_dir` in segments of
/// 1,024 bytes, which hold two frames each of a flush that is cut for them,
/// with an append deadline that is over long before the network thread has
/// made a spare segment file.
fn held_spares_settings(sf_dir: &tempfile::TempDir, durability: &str) -> String {
    format!(
        "sf_dir={};sender_id=spares;sf_max_segment_bytes=1024;sf_append_deadline_millis=1;\
         {durability}",
        sf_dir.path().display()
    )
}

const MEMORY_DURABILITY: &str = "sf_durability=memory;";
/// Periodic durability whose cadence never comes in a test: a segment is
/// synced when a frame leaves it for a new one.
const PERIODIC_DURABILITY: &str = "sf_durability=periodic;sf_sync_interval_millis=3600000;";

/// The first flush of a sender with [`HeldSpares`]: three frames, the last
/// of which takes the spare that the slot made when it was opened, and
/// leaves room in that segment for a frame of the next flush.
fn buffer_that_takes_the_spare_of_the_open() -> Buffer {
    buffer_of(TABLE, 0..40)
}

/// Flushes [`buffer_that_takes_the_spare_of_the_open`], and then `buffer` on
/// another thread while the network thread makes the next spare, which
/// `spares` holds. Once a frame of `buffer` after its first one has waited
/// for that spare, lets the spare go, to end as `end` says, and returns what
/// the flush of `buffer` returns.
fn flush_while_a_spare_is_held(
    sender: &mut Sender,
    spares: &HeldSpares,
    buffer: &mut Buffer,
    end: SpareEnd,
) -> crate::Result<Option<u64>> {
    let before = buffer_that_takes_the_spare_of_the_open();
    let before_frames = frames_of_a_flush(&before, 492);
    let frames = [before_frames.clone(), frames_of_a_flush(buffer, 492)].concat();
    let taking = frames_that_take_a_new_segment(1024, &[], &frames);
    assert!(
        taking[0] == before_frames.len() - 1 && taking[1] > before_frames.len(),
        "{taking:?}"
    );
    assert_eq!(
        sender.flush_and_keep_and_get_fsn(&before).unwrap(),
        Some(before_frames.len() as u64 - 1)
    );
    spares.wait_for_a_held_spare();
    thread::scope(|scope| {
        let flush = scope.spawn(|| sender.flush_and_get_fsn(buffer));
        // The network thread sends nothing while it makes the spare: give
        // the flush the time to get to the frame that waits, and that frame
        // far more than the deadline.
        thread::sleep(SPARE_DELAY);
        spares.let_go(end);
        flush.join().unwrap()
    })
}

/// Checks that the server holds no row of the flush after
/// [`buffer_that_takes_the_spare_of_the_open`]. It may hold the rows of that
/// one: its last frame may still be unsent when the network thread stops
/// while it makes the spare.
fn assert_nothing_committed_after_the_spare_of_the_open(server: &QwpWsModelServer) {
    let held = server.model.table(TABLE).unwrap_or_default();
    let before = rows_of(TABLE, &buffer_that_takes_the_spare_of_the_open());
    assert!(
        (held.commits, held.rows_as_text()) == (0, Vec::new())
            || (held.commits, held.rows_as_text()) == (1, before),
        "{} commits: {:?}",
        held.commits,
        held.rows_as_text()
    );
}

/// A flush in frames whose later frames need spare segment files that the
/// network thread makes long after `sf_append_deadline_millis`: they wait
/// for them, and the flush is one commit. With `sf_durability=memory` such a
/// frame waits while the spare is being made; with `periodic` while any
/// storage work of the network thread is under way.
///
/// The first frame of a flush still waits only up to the deadline: a flush
/// whose first frame needs a spare that is being made fails with nothing
/// queued, and goes through once the spare is there.
fn a_flush_in_frames_waits_for_the_spares_of_its_later_frames_beyond_the_append_deadline(
    durability: &str,
) {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let sf_dir = tempfile::TempDir::new().unwrap();
    let (spares, _hook) = HeldSpares::hold(&sf_dir);
    let mut sender = sender_with(
        server.port,
        Progress::Background,
        &held_spares_settings(&sf_dir, durability),
    );
    assert_eq!(sender.effective_frame_cap().unwrap(), (992, true));
    let before = buffer_that_takes_the_spare_of_the_open();
    let first = buffer_of(TABLE, 40..205);
    let mut second = buffer_of(TABLE, 205..355);
    let before_frames = frames_of_a_flush(&before, 492);
    let first_end = before_frames.len() + frames_of_a_flush(&first, 492).len();
    let second_end = first_end + frames_of_a_flush(&second, 492).len();
    let taking = frames_that_take_a_new_segment(
        1024,
        &[],
        &[
            before_frames,
            frames_of_a_flush(&first, 492),
            frames_of_a_flush(&second, 492),
        ]
        .concat(),
    );
    // The first flush takes several new segments, and the first frame of the
    // second one does not fit the segment that the first one leaves.
    assert!(
        taking.iter().filter(|frame| **frame < first_end).count() >= 4
            && taking.contains(&first_end),
        "{taking:?}"
    );
    // The frame `taking[i]` takes the segment numbered `i + 1`. The spare
    // that the first frame of the second flush needs stays held after the
    // first flush, however late this thread is to look at it.
    let spare_of_the_second = taking.iter().position(|frame| *frame == first_end).unwrap() + 1;
    spares.hold_again_from(spare_of_the_second as u64);

    let mut flushed = first.clone();
    let last_fsn =
        flush_while_a_spare_is_held(&mut sender, &spares, &mut flushed, SpareEnd::Made).unwrap();
    assert_eq!(last_fsn, Some(first_end as u64 - 1));
    assert!(flushed.is_empty());

    // The network thread is making the next spare, which the first frame of
    // the second flush needs.
    spares.wait_for_a_held_spare();
    let (rows, len) = (second.row_count(), second.len());
    let err = sender.flush(&mut second).unwrap_err();
    assert_eq!(err.code(), ErrorCode::SocketError, "{}", err.msg());
    assert!(
        err.msg()
            .contains("timed out waiting for a prepared segment spare"),
        "{}",
        err.msg()
    );
    assert_eq!(
        sender.published_fsn().unwrap(),
        Some(first_end as u64 - 1),
        "nothing is published"
    );
    assert_eq!(
        (second.row_count(), second.len()),
        (rows, len),
        "the buffer keeps its rows"
    );
    // As after any flush that waited out its deadline: the sender says that
    // it must be closed, and goes on working all the same.
    assert!(sender.must_close());

    spares.let_go(SpareEnd::Made);
    let retry_until = Instant::now() + WAIT;
    let last_fsn = loop {
        match sender.flush_and_get_fsn(&mut second) {
            Ok(fsn) => break fsn,
            Err(err) => {
                assert!(
                    err.msg()
                        .contains("timed out waiting for a prepared segment spare")
                        && Instant::now() < retry_until,
                    "{}",
                    err.msg()
                );
            }
        }
    };
    assert_eq!(last_fsn, Some(second_end as u64 - 1));
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    let second = buffer_of(TABLE, 205..355);
    assert_table_holds(&server, TABLE, 3, &[&before, &first, &second]);
    drop(sender);
    server.finish();
}

mod a_flush_in_frames_waits_for_the_spares_of_its_later_frames_beyond_the_append_deadline {
    #[test]
    fn memory() {
        super::a_flush_in_frames_waits_for_the_spares_of_its_later_frames_beyond_the_append_deadline(
            super::MEMORY_DURABILITY,
        );
    }

    #[test]
    fn periodic() {
        super::a_flush_in_frames_waits_for_the_spares_of_its_later_frames_beyond_the_append_deadline(
            super::PERIODIC_DURABILITY,
        );
    }
}

/// A spare segment file that cannot be made while a later frame of a flush
/// in frames waits for it stops the sender: the flush fails within moments
/// with the error of the sender, and nothing of it is committed.
#[test]
fn a_flush_in_frames_whose_spare_cannot_be_made_stops_the_sender_and_commits_nothing() {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let sf_dir = tempfile::TempDir::new().unwrap();
    let (spares, _hook) = HeldSpares::hold(&sf_dir);
    let mut sender = sender_with(
        server.port,
        Progress::Background,
        &held_spares_settings(&sf_dir, MEMORY_DURABILITY),
    );
    let mut large = buffer_of(TABLE, 40..205);
    let (rows, len) = (large.row_count(), large.len());

    let started = Instant::now();
    let err = flush_while_a_spare_is_held(&mut sender, &spares, &mut large, SpareEnd::Failed)
        .unwrap_err();
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "failed after {:?}",
        started.elapsed()
    );
    assert_eq!(err.code(), ErrorCode::SocketError, "{}", err.msg());
    assert!(
        err.msg()
            .starts_with("QWP/WebSocket store-and-forward queue error: ")
            && err
                .msg()
                .contains("injected failure of a spare segment file"),
        "{}",
        err.msg()
    );
    assert!(sender.must_close());
    assert_eq!(
        (large.row_count(), large.len()),
        (rows, len),
        "the buffer keeps its rows"
    );
    drop(sender);
    assert_nothing_committed_after_the_spare_of_the_open(&server);
    server.finish();
}

/// The network thread of a sender that panics while a later frame of a
/// flush in frames waits for the spare that it makes: the flush fails
/// within moments, nothing of it is committed, and the sender can be
/// dropped. The message of the panic shows in the output of the test.
#[test]
fn a_flush_in_frames_whose_network_thread_dies_while_a_frame_waits_for_a_spare_fails() {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let sf_dir = tempfile::TempDir::new().unwrap();
    let (spares, _hook) = HeldSpares::hold(&sf_dir);
    let mut sender = sender_with(
        server.port,
        Progress::Background,
        &held_spares_settings(&sf_dir, MEMORY_DURABILITY),
    );
    let mut large = buffer_of(TABLE, 40..205);
    let (rows, len) = (large.row_count(), large.len());

    let started = Instant::now();
    let err = flush_while_a_spare_is_held(&mut sender, &spares, &mut large, SpareEnd::Panicked)
        .unwrap_err();
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "failed after {:?}",
        started.elapsed()
    );
    assert_eq!(err.code(), ErrorCode::FlushAborted, "{}", err.msg());
    assert!(
        err.msg().starts_with(
            "Could not flush buffer: the flush stopped part way: QWP/WebSocket \
             Store-and-Forward append failed: the network thread of the sender has stopped. \
             None of its frames reached the server, nothing of it is committed"
        ),
        "{}",
        err.msg()
    );
    // The network thread died while it made the spare, before it could
    // take the first frame of the flush.
    assert!(!err.in_doubt());
    assert!(sender.must_close());
    assert_eq!(
        (large.row_count(), large.len()),
        (rows, len),
        "the buffer keeps its rows"
    );
    drop(sender);
    assert_nothing_committed_after_the_spare_of_the_open(&server);
    server.finish();
}

mod a_frame_of_a_failed_flush_that_the_server_confirms_is_not_reported_as_confirmed {
    use super::a_frame_of_a_failed_flush_that_the_server_confirms_is_not_reported_as_confirmed as test;
    use super::{Progress, on_disk};

    #[test]
    fn background() {
        test(Progress::Background);
    }

    #[test]
    fn on_disk_background() {
        on_disk(test, Progress::Background);
    }
}

/// Makes two tests of each test that takes the progress mode of its senders:
/// `<test>::background` and `<test>::manual`.
macro_rules! in_both_progress_modes {
    ($($test:ident)*) => {$(
        mod $test {
            #[test]
            fn background() {
                super::$test(super::Progress::Background);
            }

            #[test]
            fn manual() {
                super::$test(super::Progress::Manual);
            }
        }
    )*};
}

/// Makes two more tests of a test of senders, with their queues on disk:
/// `on_disk::<test>::background` and `on_disk::<test>::manual`.
macro_rules! on_disk_in_both_progress_modes {
    ($($test:ident)*) => {
        mod on_disk {
            $(
                mod $test {
                    use super::super::{Progress, on_disk};

                    #[test]
                    fn background() {
                        on_disk(super::super::$test, Progress::Background);
                    }

                    #[test]
                    fn manual() {
                        on_disk(super::super::$test, Progress::Manual);
                    }
                }
            )*
        }
    };
}

in_both_progress_modes! {
    a_flush_with_symbols_above_the_frame_cap_is_one_commit
    a_flush_with_symbols_that_loses_its_connection_part_way_is_sent_again_whole
    a_buffer_with_a_symbol_that_a_connection_refuses_is_refused_before_its_first_frame
    a_flush_above_the_frame_cap_is_one_commit
    a_flush_that_loses_its_connection_part_way_is_sent_again_whole
    a_flush_of_several_tables_above_the_frame_cap_is_one_commit_of_each_table
    a_flush_of_several_tables_that_loses_its_connection_part_way_is_sent_again_whole
    a_flush_with_a_column_of_every_kind_above_the_frame_cap_is_one_commit
    a_buffer_with_a_decimal_that_cannot_be_written_is_refused_before_its_first_frame
    a_flush_in_frames_with_sf_dir_leaves_no_segment_file_once_it_is_confirmed
    a_new_sender_on_the_slot_sends_nothing_of_a_flush_that_a_full_dictionary_stopped
    a_new_sender_on_the_slot_sends_nothing_of_a_flush_that_a_manifest_sync_stopped
    a_new_sender_on_the_slot_sends_nothing_of_a_flush_that_a_segment_sync_stopped
    a_flush_in_frames_that_its_sender_did_not_deliver_is_one_commit_of_a_new_sender_on_the_slot
    a_flush_in_frames_with_periodic_durability_is_queued_while_the_server_is_away
    a_new_sender_on_the_slot_knows_the_symbols_of_a_flush_whose_segments_are_freed
    a_flush_whose_first_frame_gets_no_segment_takes_its_symbols_out_of_the_symbol_file
    a_sender_whose_slot_has_no_symbol_file_refuses_a_buffer_above_the_frame_cap
    a_sender_whose_server_tells_no_frame_limit_refuses_a_buffer_above_the_frame_cap
    a_buffer_whose_frame_is_exactly_the_frame_cap_is_one_frame_and_one_byte_more_makes_two
    a_flush_is_cut_for_two_frames_a_segment_and_a_larger_row_travels_alone
    a_buffer_of_exactly_max_buf_size_is_sent_in_frames_and_one_byte_more_is_refused
    a_buffer_above_max_buf_size_is_refused_for_its_size_or_for_a_value_that_cannot_be_sent
    a_max_buf_size_below_the_frame_limit_is_held_against_the_frame_of_the_buffer
    a_buffer_of_symbols_above_max_buf_size_whose_frame_fits_is_one_frame
    a_buffer_above_max_buf_size_for_symbols_that_its_frame_brings_once_is_one_frame
    a_buffer_whose_frames_the_queue_cannot_hold_is_one_frame_when_its_frame_fits
    a_buffer_with_a_row_that_fits_no_frame_is_refused_with_the_table_and_the_size_of_the_row
    a_row_whose_frame_is_exactly_the_frame_cap_travels_alone_and_one_byte_more_is_refused
    a_row_that_fits_no_frame_by_its_size_bound_is_sent_when_the_buffer_fits_one_frame
    a_value_that_cannot_be_sent_is_named_before_a_row_that_fits_no_frame
    a_flush_that_the_queue_can_never_hold_is_refused_with_the_value_that_would_do
    a_flush_without_room_waits_until_the_server_confirms_what_the_queue_holds
    a_flush_that_waits_for_room_until_the_deadline_fails_with_nothing_sent
    a_flush_that_waits_for_room_while_the_server_is_down_names_why_reconnecting_fails
    a_buffer_whose_frame_fits_is_one_frame_when_the_queue_has_no_room_for_its_frames
    a_buffer_whose_frame_fits_is_one_frame_when_the_queue_has_room_for_its_frames
    a_buffer_whose_frame_fits_is_refused_whole_by_a_full_dictionary
    a_buffer_whose_frame_fits_by_the_symbols_its_connection_holds_is_one_frame_without_room_for_its_frames
    a_buffer_whose_frame_is_above_the_cap_by_its_symbol_ids_waits_for_the_room_of_its_frames
    a_flush_on_a_slot_reopened_with_larger_segments_counts_the_segment_in_use_at_its_size
    a_flush_on_a_slot_reopened_with_smaller_segments_is_refused_for_the_segment_in_use
    a_flush_on_a_slot_reopened_with_smaller_segments_that_fits_the_segment_in_use_is_sent
    a_slot_reopened_with_larger_segments_takes_larger_frames_after_a_flush_that_stopped
    a_sender_that_was_closed_refuses_a_buffer_above_the_frame_cap
    a_flush_that_fails_at_its_second_frame_is_aborted_and_the_flush_before_it_is_delivered
    a_flush_that_fails_at_a_middle_frame_is_aborted_and_the_flush_before_it_is_delivered
    a_flush_that_fails_at_its_last_frame_is_aborted_and_the_flush_before_it_is_delivered
    a_flush_that_fails_part_way_as_the_first_of_its_sender_leaves_nothing_to_wait_for
    a_later_flush_without_room_in_the_queue_gets_the_error_of_the_failed_flush
    a_sender_whose_flush_failed_part_way_delivers_the_flush_before_it_on_a_new_connection
    a_close_drain_after_a_flush_that_failed_part_way_leaves_an_empty_slot
    a_new_sender_on_the_slot_flushes_a_buffer_that_a_full_dictionary_stopped_after_close_drain
    a_full_dictionary_stops_the_flush_once_more_on_the_slot_of_a_sender_dropped_without_close_drain
    a_flush_with_a_frame_that_the_server_rejects_for_good_stops_the_sender_and_commits_nothing
    a_flush_with_a_frame_that_the_server_rejects_once_is_sent_again_whole
    a_flush_with_a_frame_that_a_demoted_server_rejects_is_sent_again_whole
    a_rejection_of_a_frame_of_a_flush_that_failed_part_way_leaves_the_flush_before_it_confirmed
    a_flush_is_committed_once_wherever_its_connection_is_lost_before_the_commit
    a_flush_whose_connection_is_lost_after_the_commit_and_before_its_answer_is_committed_again
    a_flush_whose_every_connection_the_server_closes_stops_the_sender_at_the_fourth_close
    a_close_drain_after_a_flush_in_frames_that_is_not_confirmed_in_time_fails
    a_close_drain_that_times_out_after_a_failed_flush_counts_the_frames_before_it
}

// What a sender does with a buffer above the frame cap does not depend on
// where it keeps its queue. These tests run once more with `sf_dir`: the ones
// in which frames reach the queue.
on_disk_in_both_progress_modes! {
    a_flush_with_symbols_above_the_frame_cap_is_one_commit
    a_flush_with_symbols_that_loses_its_connection_part_way_is_sent_again_whole
    a_buffer_with_a_symbol_that_a_connection_refuses_is_refused_before_its_first_frame
    a_flush_above_the_frame_cap_is_one_commit
    a_flush_that_loses_its_connection_part_way_is_sent_again_whole
    a_flush_of_several_tables_above_the_frame_cap_is_one_commit_of_each_table
    a_flush_of_several_tables_that_loses_its_connection_part_way_is_sent_again_whole
    a_flush_with_a_column_of_every_kind_above_the_frame_cap_is_one_commit
    a_buffer_whose_frame_is_exactly_the_frame_cap_is_one_frame_and_one_byte_more_makes_two
    a_flush_is_cut_for_two_frames_a_segment_and_a_larger_row_travels_alone
    a_buffer_of_exactly_max_buf_size_is_sent_in_frames_and_one_byte_more_is_refused
    a_buffer_of_symbols_above_max_buf_size_whose_frame_fits_is_one_frame
    a_buffer_whose_frames_the_queue_cannot_hold_is_one_frame_when_its_frame_fits
    a_flush_that_the_queue_can_never_hold_is_refused_with_the_value_that_would_do
    a_flush_without_room_waits_until_the_server_confirms_what_the_queue_holds
    a_flush_that_waits_for_room_until_the_deadline_fails_with_nothing_sent
    a_flush_that_waits_for_room_while_the_server_is_down_names_why_reconnecting_fails
    a_buffer_whose_frame_fits_is_one_frame_when_the_queue_has_no_room_for_its_frames
    a_buffer_whose_frame_fits_is_one_frame_when_the_queue_has_room_for_its_frames
    a_buffer_whose_frame_fits_is_refused_whole_by_a_full_dictionary
    a_buffer_whose_frame_fits_by_the_symbols_its_connection_holds_is_one_frame_without_room_for_its_frames
    a_buffer_whose_frame_is_above_the_cap_by_its_symbol_ids_waits_for_the_room_of_its_frames
    a_flush_that_fails_at_its_second_frame_is_aborted_and_the_flush_before_it_is_delivered
    a_flush_that_fails_at_a_middle_frame_is_aborted_and_the_flush_before_it_is_delivered
    a_flush_that_fails_at_its_last_frame_is_aborted_and_the_flush_before_it_is_delivered
    a_flush_that_fails_part_way_as_the_first_of_its_sender_leaves_nothing_to_wait_for
    a_later_flush_without_room_in_the_queue_gets_the_error_of_the_failed_flush
    a_sender_whose_flush_failed_part_way_delivers_the_flush_before_it_on_a_new_connection
    a_flush_with_a_frame_that_the_server_rejects_for_good_stops_the_sender_and_commits_nothing
    a_flush_with_a_frame_that_the_server_rejects_once_is_sent_again_whole
    a_flush_with_a_frame_that_a_demoted_server_rejects_is_sent_again_whole
    a_rejection_of_a_frame_of_a_flush_that_failed_part_way_leaves_the_flush_before_it_confirmed
    a_flush_is_committed_once_wherever_its_connection_is_lost_before_the_commit
    a_flush_whose_connection_is_lost_after_the_commit_and_before_its_answer_is_committed_again
    a_close_drain_after_a_flush_in_frames_that_is_not_confirmed_in_time_fails
    a_close_drain_that_times_out_after_a_failed_flush_counts_the_frames_before_it
}

mod after_abort_answers;
