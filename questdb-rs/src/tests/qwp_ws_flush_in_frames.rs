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
//! buffer is within `max_buf_size` and holds rows of one table without a
//! column the planner cannot size, and the queue has room for all the frames.
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
use crate::ingress::{AckLevel, Buffer, Sender, SenderBuilder, TimestampNanos};
use crate::tests::qwp_ws::spawn_max_batch_size_upgrade_only_server;
use crate::tests::qwp_ws_server_model::{QwpWsModelServer, buffer_of, frames_of_a_flush, rows_of};

const TABLE: &str = "flush_rows";
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

    let mut two_tables = buffer_of(TABLE, 0..2000);
    two_tables
        .table("other_rows")
        .unwrap()
        .column_i64("id", 1)
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
        &mut two_tables,
        &mut with_symbols,
        &mut with_a_row_above_the_cap,
    ] {
        assert_refused_as_one_frame(&mut sender, buffer, FRAME_LIMIT, SET_BY_SERVER);
    }

    // The sender then takes a buffer that can be cut.
    let large = buffer_of(TABLE, 0..2000);
    sender.flush_and_keep(&large).unwrap();
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    let table = server.model.table(TABLE).unwrap();
    assert_eq!(table.commits, 1);
    assert_eq!(table.rows_as_text(), rows_of(TABLE, &large));
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
