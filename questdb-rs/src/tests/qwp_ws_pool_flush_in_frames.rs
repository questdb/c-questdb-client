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

//! A row buffer that does not fit one frame, flushed through a sender that
//! is borrowed from the pool of a [`QuestDb`].
//!
//! Such a sender sends the buffer as a `Sender` does, which
//! `qwp_ws_flush_in_frames` tests in full: in frames that the server commits
//! together, when the pool keeps its queues in memory and the server has
//! told its frame limit; with the same refusals before the first frame, the
//! same wait for room in the queue, and the same error of a flush that stops
//! part way. The tests here show that each of these holds for a pooled
//! sender, and what is the pool's own:
//!
//! - a buffer is flushed in five ways, and each sends it in frames;
//! - the row and column flushes of a pooled sender share one dictionary of
//!   symbols, which the next sender that the pool gives the connection to
//!   goes on with: the frames of a flush bring what the connection does not
//!   know;
//! - a sender whose flush stopped part way refuses every later flush, of
//!   rows and of columns, and says that it must be closed: the pool does not
//!   hand its connection out again;
//! - the pool closes such a sender when it is returned. It waits for the
//!   answers to the flushes before the failed one and for nothing else, it
//!   sends nothing more, and nothing of the failed flush is committed;
//! - any other buffer that is too large for one frame gets the refusal that
//!   a pooled sender gave before.
//!
//! The server is the model of [`crate::tests::qwp_ws_server_model`] behind a
//! socket, as in `qwp_ws_flush_in_frames`.

use std::thread;
use std::time::{Duration, Instant};

use crate::ingress::column_sender::Chunk;
use crate::ingress::{AckLevel, Buffer, SymbolGlobalDict, TestDictCapGuard};
use crate::tests::qwp_ws::spawn_max_batch_size_upgrade_only_server;
use crate::tests::qwp_ws_flush_in_frames::{
    EIGHT_SEGMENTS, FIRST, FRAME_LIMIT, NO_FRAME_LIMIT_TOLD, SECOND, TABLE, WAIT, add_symbol_row,
    allocated_after_a_flush_of, assert_table_holds, assert_timed_out_waiting_for_room,
    buffer_of_len, buffer_of_symbols, queue_bytes_for, stopped_by_a_full_dictionary,
    symbols_held_before, two_flushes_for_a_queue_that_holds_one, wait_for_frames_taken,
    wait_for_no_connection,
};
use crate::tests::qwp_ws_server_model::{
    QwpWsModelServer, buffer_of, frame_of_a_sender, frames_of_a_flush, frames_of_a_sender,
};
use crate::{BorrowedSender, ErrorCode, QuestDb};

/// How long a test makes the server hold its answers back, where a call of
/// the sender must wait for them.
const HELD: Duration = Duration::from_millis(200);

/// A `close_flush_timeout` that no test here lives to see. A pool that
/// closes a sender waits that long for what the server never confirms, so a
/// return that ends within [`WAIT`] did not wait for it.
const LONG_CLOSE_FLUSH: &str = "close_flush_timeout_millis=30000;";

/// A pool whose senders connect to the server on `port`, the first of them
/// before this returns. It opens no connection for queries, which the test
/// servers do not answer.
fn pool_with(port: u16, settings: &str) -> QuestDb {
    let conf = format!("ws::addr=127.0.0.1:{port};query_pool_min=0;{settings}");
    QuestDb::connect(&conf).unwrap()
}

/// Flushes a buffer that the sender refuses, and gives the refusal. Nothing
/// is published, the buffer keeps its rows, and the sender stays usable.
fn refusal_of(sender: &mut BorrowedSender<'_>, buffer: &mut Buffer) -> crate::Error {
    let published = sender.published_fsn().unwrap();
    let (rows, len) = (buffer.row_count(), buffer.len());

    let err = sender.flush_buffer(buffer).unwrap_err();
    assert!(!err.in_doubt());
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
    assert!(!sender.must_close_for_test());
    err
}

/// The same for a buffer that is refused for its size: the text of the
/// refusal.
fn size_refusal_of(sender: &mut BorrowedSender<'_>, buffer: &mut Buffer) -> String {
    let err = refusal_of(sender, buffer);
    assert_eq!(err.code(), ErrorCode::BatchTooLarge, "{}", err.msg());
    err.msg().to_owned()
}

/// Flushes a buffer that is too large for one frame and that is not sent in
/// frames either. The refusal is the one that a pooled sender gave such a
/// buffer before.
fn assert_refused_as_one_frame(sender: &mut BorrowedSender<'_>, buffer: &mut Buffer, cap: usize) {
    let refusal = size_refusal_of(sender, buffer);
    let end = format!(
        " bytes) exceeds the store-and-forward per-frame cap ({cap} bytes, the smaller of \
         max_buf_size and the sf_max_segment_bytes segment payload capacity)"
    );
    assert!(
        refusal.starts_with("QWP frame (") && refusal.ends_with(&end),
        "got: {refusal}"
    );
}

#[test]
fn a_pooled_sender_sends_a_buffer_above_the_frame_cap_in_frames_whichever_way_it_is_flushed() {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let db = pool_with(server.port, "");
    let mut sender = db.borrow_sender().unwrap();
    assert_eq!(sender.effective_frame_cap_for_test(), (FRAME_LIMIT, true));
    let before = buffer_of(TABLE, 0..3);
    assert_eq!(
        sender.flush_buffer_and_keep_and_get_fsn(&before).unwrap(),
        Some(0)
    );
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_table_holds(&server, TABLE, 1, &[&before]);

    // The five ways to flush a buffer, each with a buffer of its own.
    let buffers: Vec<Buffer> = (0..5)
        .map(|way| buffer_of(TABLE, 1000 * way + 3..1000 * way + 803))
        .collect();
    let mut held = vec![&before];
    let mut last_fsn = 0;
    for (way, buffer) in buffers.iter().enumerate() {
        let frame_count = frames_of_a_flush(buffer, FRAME_LIMIT).len() as u64;
        assert!(frame_count > 15, "{frame_count} frames");
        let mut flushed = buffer.clone();
        let (fsn, cleared) = match way {
            0 => (sender.flush_buffer_and_get_fsn(&mut flushed).unwrap(), true),
            1 => (
                sender.flush_buffer_and_keep_and_get_fsn(&flushed).unwrap(),
                false,
            ),
            2 => {
                sender.flush_buffer(&mut flushed).unwrap();
                (sender.published_fsn().unwrap(), true)
            }
            3 => {
                sender.flush_buffer_and_keep(&flushed).unwrap();
                (sender.published_fsn().unwrap(), false)
            }
            _ => {
                // This one returns when the server has confirmed the flush.
                sender
                    .flush_buffer_and_wait(&mut flushed, AckLevel::Ok)
                    .unwrap();
                let commits = server.model.table(TABLE).unwrap().commits;
                assert_eq!(commits, 2 + way as u64, "the flush was not waited for");
                (sender.published_fsn().unwrap(), true)
            }
        };
        // The frames of a flush follow those of the flush before, and the
        // flush gives the number of its last frame.
        last_fsn += frame_count;
        assert_eq!(fsn, Some(last_fsn), "way {way}");
        assert_eq!(flushed.is_empty(), cleared, "way {way}");
        sender.wait(AckLevel::Ok, WAIT).unwrap();
        held.push(buffer);
        // The frames of the flush are one commit.
        assert_table_holds(&server, TABLE, 2 + way as u64, &held);
    }
    assert_eq!(server.frames_taken() as u64, 1 + last_fsn);
    assert!(!sender.must_close_for_test());
    drop(sender);
    db.close();
    server.finish();
}

/// A flush of two tables with symbols, after a flush that brought some of
/// them, and again through the next sender of the pool, which gets the same
/// connection: then its frames bring no symbol. The server reads every
/// symbol of a row by its number on the connection, so the rows that it
/// holds show that each frame brought what the connection did not know.
#[test]
fn the_frames_of_a_pooled_flush_bring_the_symbols_that_the_connection_does_not_know() {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let db = pool_with(server.port, "");
    let before = buffer_of_symbols(FIRST, 0..10);
    let mut large = buffer_of_symbols(FIRST, 5..605);
    for id in 600..1200 {
        add_symbol_row(&mut large, SECOND, id);
    }
    let after = buffer_of_symbols(SECOND, 1195..1200);
    // What a sender makes of these buffers, one after the other.
    let mut sender_symbols = SymbolGlobalDict::new();
    frame_of_a_sender(&before, false, &mut sender_symbols);
    let frames = frames_of_a_sender(&large, FRAME_LIMIT, &mut sender_symbols).len() as u64;
    let frames_again = frames_of_a_sender(&large, FRAME_LIMIT, &mut sender_symbols).len() as u64;
    assert!(frames > 40, "{frames} frames");

    let mut sender = db.borrow_sender().unwrap();
    assert_eq!(
        sender.flush_buffer_and_keep_and_get_fsn(&before).unwrap(),
        Some(0)
    );
    assert_eq!(
        sender.flush_buffer_and_keep_and_get_fsn(&large).unwrap(),
        Some(frames)
    );
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_table_holds(&server, FIRST, 2, &[&before, &large]);
    assert_table_holds(&server, SECOND, 1, &[&large]);
    assert!(!sender.must_close_for_test());
    drop(sender);

    let mut sender = db.borrow_sender().unwrap();
    assert_eq!(
        sender.flush_buffer_and_keep_and_get_fsn(&large).unwrap(),
        Some(frames + frames_again),
        "the connection of the sender before, with the symbols that it knows"
    );
    assert_eq!(
        sender.flush_buffer_and_keep_and_get_fsn(&after).unwrap(),
        Some(frames + frames_again + 1)
    );
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_table_holds(&server, FIRST, 3, &[&before, &large, &large]);
    assert_table_holds(&server, SECOND, 3, &[&large, &large, &after]);
    drop(sender);
    db.close();
    server.finish();
}

/// A flush of columns brings a symbol, and the frames of the flush of rows
/// after it start their symbols behind that one: the two kinds of flush
/// share the dictionary of the sender.
#[test]
fn a_pooled_flush_in_frames_shares_its_symbols_with_the_flushes_of_columns() {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let db = pool_with(server.port, "");
    let mut sender = db.borrow_sender().unwrap();
    let large = buffer_of_symbols(TABLE, 0..600);
    let frames = frames_of_a_sender(&large, FRAME_LIMIT, &mut SymbolGlobalDict::new());
    assert!(frames.len() > 20, "{} frames", frames.len());

    let (codes, offsets, ts) = ([0_i32], [0_i32, 9], [1_i64]);
    let mut chunk = Chunk::new("column_rows");
    chunk
        .symbol_i32("sym", &codes, &offsets, b"of-column", None)
        .unwrap();
    chunk.at_nanos(&ts).unwrap();
    assert_eq!(sender.flush_and_get_fsn(&mut chunk).unwrap(), Some(0));
    assert_eq!(
        sender.flush_buffer_and_keep_and_get_fsn(&large).unwrap(),
        Some(frames.len() as u64)
    );
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    // The server reads every symbol of the rows by its number on the
    // connection: one that is off by the symbol of the columns is another
    // symbol, or none.
    assert_table_holds(&server, TABLE, 1, &[&large]);
    assert_eq!(server.model.table("column_rows").unwrap().commits, 1);

    // And the other way: a symbol that the rows brought is known to the
    // flush of columns, whose frame brings it no more.
    let mut chunk = Chunk::new("column_rows");
    chunk
        .symbol_i32("sym", &codes, &[0, 2], b"v1", None)
        .unwrap();
    chunk.at_nanos(&ts).unwrap();
    sender.flush_and_wait(&mut chunk, AckLevel::Ok).unwrap();
    assert_eq!(server.model.table("column_rows").unwrap().commits, 2);
    assert!(!sender.must_close_for_test());
    drop(sender);
    db.close();
    server.finish();
}

#[test]
fn a_pooled_sender_refuses_a_buffer_above_max_buf_size_for_its_size() {
    const MAX_BUF_SIZE: usize = 8192;
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let db = pool_with(server.port, "max_buf_size=8192;");
    let mut sender = db.borrow_sender().unwrap();
    assert_eq!(sender.effective_frame_cap_for_test(), (FRAME_LIMIT, true));
    let at_max = buffer_of_len(0, MAX_BUF_SIZE);
    let mut above_max = buffer_of_len(1000, MAX_BUF_SIZE + 1);
    let frame_count = frames_of_a_flush(&at_max, FRAME_LIMIT).len() as u64;

    assert_eq!(
        sender.flush_buffer_and_keep_and_get_fsn(&at_max).unwrap(),
        Some(frame_count - 1)
    );
    let len = above_max.len();
    assert_eq!(
        size_refusal_of(&mut sender, &mut above_max),
        format!(
            "Could not flush buffer: its size is {len} bytes, and max_buf_size is {MAX_BUF_SIZE} \
             bytes. Set max_buf_size to at least {len}, or flush more often."
        )
    );
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_table_holds(&server, TABLE, 1, &[&at_max]);
    drop(sender);
    db.close();
    server.finish();
}

#[test]
fn a_pooled_sender_names_the_row_that_fits_no_frame() {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let db = pool_with(server.port, "");
    let mut sender = db.borrow_sender().unwrap();
    let mut buffer = buffer_of(TABLE, 0..2000);
    buffer
        .table("other_rows")
        .unwrap()
        .column_str("txt", "x".repeat(FRAME_LIMIT))
        .unwrap()
        .at_now()
        .unwrap();

    let refusal = size_refusal_of(&mut sender, &mut buffer);
    let end = format!(
        " bytes, and the per-frame cap is {FRAME_LIMIT} bytes. Make the row smaller, or raise \
         the cap."
    );
    assert!(
        refusal
            .starts_with("Could not flush buffer: a row of table 'other_rows' needs a frame of ")
            && refusal.ends_with(&end),
        "got: {refusal}"
    );
    assert_eq!(server.frames_taken(), 0);
    drop(sender);
    db.close();
    server.finish();
}

/// A row that is not finished makes a buffer of any size one that cannot be
/// flushed: a buffer above the frame cap gets the error of a small one.
#[test]
fn a_pooled_sender_refuses_a_buffer_above_the_frame_cap_whose_last_row_is_not_finished() {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let db = pool_with(server.port, "");
    let mut sender = db.borrow_sender().unwrap();
    let unfinished = |mut buffer: Buffer| {
        buffer.table(TABLE).unwrap().column_i64("id", 5000).unwrap();
        buffer
    };
    let mut small = unfinished(buffer_of(TABLE, 0..3));
    let mut large = unfinished(buffer_of(TABLE, 3..2003));

    let of_small = refusal_of(&mut sender, &mut small);
    assert_eq!(
        of_small.code(),
        ErrorCode::InvalidApiCall,
        "{}",
        of_small.msg()
    );
    let of_large = refusal_of(&mut sender, &mut large);
    assert_eq!(
        (of_large.code(), of_large.msg()),
        (of_small.code(), of_small.msg())
    );
    assert_eq!(server.frames_taken(), 0);
    drop(sender);
    db.close();
    server.finish();
}

#[test]
fn a_pooled_flush_that_the_queue_can_never_hold_is_refused_and_one_without_room_waits() {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    // The server takes what is flushed and keeps its answers to itself: what
    // is flushed stays in the queue.
    server.hold_answers();
    let db = pool_with(server.port, EIGHT_SEGMENTS);
    let mut sender = db.borrow_sender().unwrap();
    assert_eq!(sender.effective_frame_cap_for_test(), (992, true));
    let (first, first_frames, second, second_frames) = two_flushes_for_a_queue_that_holds_one();
    let mut too_large = buffer_of(TABLE, 340..740);
    let too_many_frames = frames_of_a_flush(&too_large, 492).len();
    let min_total_bytes = queue_bytes_for(too_many_frames);
    assert!(min_total_bytes > 8192);

    assert_eq!(
        sender.flush_buffer_and_keep_and_get_fsn(&first).unwrap(),
        Some(first_frames as u64 - 1)
    );

    // What the queue can never hold is refused at once, whatever it holds.
    let started = Instant::now();
    assert_eq!(
        size_refusal_of(&mut sender, &mut too_large),
        format!(
            "Could not flush buffer: its {too_many_frames} frames need a store-and-forward \
             queue of {min_total_bytes} bytes, and sf_max_total_bytes is 8192 bytes. Set \
             sf_max_total_bytes to at least {min_total_bytes}, or flush more often."
        )
    );
    assert!(started.elapsed() < Duration::from_secs(5));

    // The second flush waits for the answer to the first, which the server
    // lets go a while after it has taken the frames of the first. A borrowed
    // sender stays on its thread, so another one watches the server.
    let (last_fsn, waited, taken) = thread::scope(|scope| {
        let server = &server;
        let started = Instant::now();
        let watching = scope.spawn(move || {
            wait_for_frames_taken(server, first_frames);
            thread::sleep(HELD);
            let taken = server.frames_taken();
            server.let_answers_go();
            taken
        });
        let last_fsn = sender.flush_buffer_and_keep_and_get_fsn(&second).unwrap();
        (last_fsn, started.elapsed(), watching.join().unwrap())
    });
    assert!(waited >= HELD, "the flush did not wait for room");
    assert_eq!(
        taken, first_frames,
        "no frame of the flush is sent before all of them have room"
    );
    assert_eq!(last_fsn, Some((first_frames + second_frames) as u64 - 1));
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_table_holds(&server, TABLE, 2, &[&first, &second]);
    assert!(!sender.must_close_for_test());
    drop(sender);
    db.close();
    server.finish();
}

#[test]
fn a_pooled_flush_that_waits_for_room_until_the_deadline_fails_with_nothing_sent() {
    const DEADLINE: Duration = Duration::from_millis(300);
    let settings = format!("{EIGHT_SEGMENTS}sf_append_deadline_millis=300;");
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    server.hold_answers();
    let db = pool_with(server.port, &settings);
    let mut sender = db.borrow_sender().unwrap();
    let (first, first_frames, mut second, second_frames) = two_flushes_for_a_queue_that_holds_one();

    assert_eq!(
        sender.flush_buffer_and_keep_and_get_fsn(&first).unwrap(),
        Some(first_frames as u64 - 1)
    );
    let started = Instant::now();
    let err = refusal_of(&mut sender, &mut second);
    let waited = started.elapsed();
    assert!(waited >= DEADLINE && waited < WAIT, "waited {waited:?}");
    assert_timed_out_waiting_for_room(&err, &allocated_after_a_flush_of(first_frames));
    wait_for_frames_taken(&server, first_frames);
    assert_eq!(server.frames_taken(), first_frames, "nothing is sent");

    // The server answers, and the same flush goes through: it is tried
    // again should the room take longer to come than the deadline.
    server.let_answers_go();
    let retry_until = Instant::now() + WAIT;
    let last_fsn = loop {
        match sender.flush_buffer_and_keep_and_get_fsn(&second) {
            Ok(fsn) => break fsn,
            Err(err) => assert!(Instant::now() < retry_until, "{}", err.msg()),
        }
    };
    assert_eq!(last_fsn, Some((first_frames + second_frames) as u64 - 1));
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_table_holds(&server, TABLE, 2, &[&first, &second]);
    drop(sender);
    db.close();
    server.finish();
}

/// A buffer whose flush in frames stops at a middle frame: its sender has
/// flushed `before`, if there is one, and has a dictionary that is full
/// when the flush comes to that frame. Gives the buffer, how many of its
/// frames are queued when the flush stops, and the size of that dictionary.
fn a_buffer_whose_flush_stops_part_way(before: Option<&Buffer>) -> (Buffer, usize, usize) {
    let large = buffer_of_symbols(TABLE, 10..1210);
    let mut sender_symbols = SymbolGlobalDict::new();
    if let Some(before) = before {
        frame_of_a_sender(before, false, &mut sender_symbols);
    }
    let frames = frames_of_a_sender(&large, FRAME_LIMIT, &mut sender_symbols);
    assert!(frames.len() > 40, "{} frames", frames.len());
    // The frames before this one are queued, and this one brings a symbol
    // more than the connection takes.
    let failing = frames.len() / 2;
    let symbols = symbols_held_before(&frames[failing]);
    (large, failing, symbols)
}

/// Flushes `before`, if there is one, and then `large`, whose flush stops
/// when `queued` of its frames are queued. Returns when the server has
/// taken every frame that the sender queued.
fn stop_a_flush_part_way(
    sender: &mut BorrowedSender<'_>,
    server: &QwpWsModelServer,
    before: Option<&Buffer>,
    large: &Buffer,
    queued: usize,
) {
    if let Some(before) = before {
        assert_eq!(
            sender.flush_buffer_and_keep_and_get_fsn(before).unwrap(),
            Some(0)
        );
    }
    let err = sender.flush_buffer_and_keep(large).unwrap_err();
    assert_eq!(err.code(), ErrorCode::FlushAborted, "{}", err.msg());
    assert!(sender.must_close_for_test());
    wait_for_frames_taken(server, before.iter().len() + queued);
}

/// Checks how long a pool with [`LONG_CLOSE_FLUSH`] took to close a sender
/// that had nothing left that the server would confirm.
fn assert_did_not_wait_for_close_flush_timeout(took: Duration) {
    assert!(
        took < WAIT,
        "the pool waited {took:?}, for frames that the server never confirms"
    );
}

/// Gives a sender back to its pool, by `give_back`, while the server holds
/// its answers back, and lets the answers go a while later. Gives how long
/// the return took, and what the server had when it let its answers go: the
/// frames taken, and the connections.
fn give_back_while_answers_are_held(
    server: &QwpWsModelServer,
    give_back: impl FnOnce(),
) -> (Duration, usize, usize) {
    thread::scope(|scope| {
        let started = Instant::now();
        let watching = scope.spawn(move || {
            thread::sleep(HELD);
            let (taken, open) = (server.frames_taken(), server.open_connections());
            server.let_answers_go();
            (taken, open)
        });
        give_back();
        let took = started.elapsed();
        let (taken, open) = watching.join().unwrap();
        (took, taken, open)
    })
}

/// A flush before, which the server commits without telling, and a flush in
/// frames whose middle frame finds the dictionary of the sender full.
#[test]
fn a_pooled_flush_that_fails_part_way_is_aborted_and_its_connection_is_not_handed_out_again() {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    server.hold_answers();
    let before = buffer_of_symbols(TABLE, 0..10);
    let (mut large, failing, symbols) = a_buffer_whose_flush_stops_part_way(Some(&before));
    let (rows, len) = (large.row_count(), large.len());
    // The dictionary of a pooled sender is made with its connection.
    let cap = TestDictCapGuard::new(symbols);
    let db = pool_with(server.port, LONG_CLOSE_FLUSH);
    let mut sender = db.borrow_sender().unwrap();
    drop(cap);

    assert_eq!(
        sender.flush_buffer_and_keep_and_get_fsn(&before).unwrap(),
        Some(0)
    );
    let err = sender.flush_buffer(&mut large).unwrap_err();
    assert_eq!(err.code(), ErrorCode::FlushAborted, "{}", err.msg());
    assert_eq!(err.msg(), stopped_by_a_full_dictionary(symbols));
    assert!(!err.in_doubt());
    assert!(sender.must_close_for_test());
    assert_eq!(
        (large.row_count(), large.len()),
        (rows, len),
        "the buffer keeps its rows"
    );
    // The sender has published the flush before, and says no more. It sends
    // the frames of the failed flush that it had queued.
    assert_eq!(sender.published_fsn().unwrap(), Some(0));
    wait_for_frames_taken(&server, 1 + failing);

    // Every later flush gets the same error: of rows, in one frame and in
    // frames, and of columns.
    for later in [&buffer_of(TABLE, 0..3), &large] {
        let refused = sender.flush_buffer_and_keep(later).unwrap_err();
        assert_eq!((refused.code(), refused.msg()), (err.code(), err.msg()));
        assert!(!refused.in_doubt());
    }
    let (ids, ts) = ([1_i64], [1_i64]);
    let mut chunk = Chunk::new(TABLE);
    chunk.column_i64("id", &ids, None).unwrap();
    chunk.at_nanos(&ts).unwrap();
    let refused = sender.flush(&mut chunk).unwrap_err();
    assert_eq!((refused.code(), refused.msg()), (err.code(), err.msg()));
    assert!(!refused.in_doubt());
    assert_eq!(sender.published_fsn().unwrap(), Some(0));

    // The sender waits for the answer to the flush before, and for nothing
    // else: the server answers no frame of the failed flush.
    let (waited, taken) = thread::scope(|scope| {
        let server = &server;
        let started = Instant::now();
        let watching = scope.spawn(move || {
            thread::sleep(HELD);
            let taken = server.frames_taken();
            server.let_answers_go();
            taken
        });
        sender.wait(AckLevel::Ok, WAIT).unwrap();
        (started.elapsed(), watching.join().unwrap())
    });
    assert!(
        waited >= HELD,
        "the sender did not wait for the flush before"
    );
    assert_eq!(taken, 1 + failing, "no later flush is queued");
    assert!(sender.must_close_for_test());
    // The server has committed the flush before, and holds the rows of the
    // failed flush for a frame that never comes.
    assert_table_holds(&server, TABLE, 1, &[&before]);

    // The pool closes the connection of a sender that must be closed, and
    // the rows that the server held go with it. It has nothing to wait for.
    // The next sender has a new connection, through which every row of the
    // buffer is committed once.
    let started = Instant::now();
    drop(sender);
    assert_did_not_wait_for_close_flush_timeout(started.elapsed());
    wait_for_no_connection(&server);
    let mut sender = db.borrow_sender().unwrap();
    assert!(!sender.must_close_for_test());
    assert_eq!(sender.published_fsn().unwrap(), None);
    sender
        .flush_buffer_and_wait(&mut large, AckLevel::Ok)
        .unwrap();
    assert!(large.is_empty());
    let large = buffer_of_symbols(TABLE, 10..1210);
    assert_table_holds(&server, TABLE, 2, &[&before, &large]);
    drop(sender);
    db.close();
    server.finish();
}

/// The sender is given back while the server has not answered the flush
/// before the failed one.
#[test]
fn the_pool_closes_a_sender_whose_flush_failed_part_way_when_the_flush_before_it_is_confirmed() {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    server.hold_answers();
    let before = buffer_of_symbols(TABLE, 0..10);
    let (large, queued, symbols) = a_buffer_whose_flush_stops_part_way(Some(&before));
    let cap = TestDictCapGuard::new(symbols);
    // A pool of one sender: the next one needs the place of this one.
    let settings = format!("sender_pool_max=1;{LONG_CLOSE_FLUSH}");
    let db = pool_with(server.port, &settings);
    let mut sender = db.borrow_sender().unwrap();
    drop(cap);
    stop_a_flush_part_way(&mut sender, &server, Some(&before), &large, queued);

    // The pool waits for the answer to the flush before, with the
    // connection open, and for nothing else: the server answers no frame of
    // the failed flush.
    let (took, taken, open) = give_back_while_answers_are_held(&server, || drop(sender));
    assert!(took >= HELD, "the pool did not wait for the flush before");
    assert_did_not_wait_for_close_flush_timeout(took);
    assert_eq!((taken, open), (1 + queued, 1));

    // The connection is closed, and the rows that the server held go with
    // it. The pool has sent nothing more: no frame that would commit them.
    wait_for_no_connection(&server);
    assert_eq!(server.frames_taken(), 1 + queued);
    assert_table_holds(&server, TABLE, 1, &[&before]);
    // The pool keeps nothing of the sender: none that is idle, none to reap.
    assert_eq!((db.free_count(), db.in_use_count()), (0, 0));
    assert_eq!(db.reap_idle(), 0);

    // Its place is free: the next sender has a new connection, through
    // which every row of the buffer is committed once.
    let mut sender = db.borrow_sender().unwrap();
    assert!(!sender.must_close_for_test());
    assert_eq!(sender.published_fsn().unwrap(), None);
    sender.flush_buffer_and_keep(&large).unwrap();
    sender.wait(AckLevel::Ok, WAIT).unwrap();
    assert_table_holds(&server, TABLE, 2, &[&before, &large]);
    drop(sender);
    db.close();
    server.finish();
}

/// Nothing of the sender is left that the server would answer: the failed
/// flush was its first.
#[test]
fn the_pool_closes_a_sender_whose_first_flush_failed_part_way_without_waiting() {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    server.hold_answers();
    let (large, queued, symbols) = a_buffer_whose_flush_stops_part_way(None);
    let cap = TestDictCapGuard::new(symbols);
    let db = pool_with(server.port, LONG_CLOSE_FLUSH);
    let mut sender = db.borrow_sender().unwrap();
    drop(cap);
    stop_a_flush_part_way(&mut sender, &server, None, &large, queued);
    assert_eq!(sender.published_fsn().unwrap(), None);

    // Neither the return of the sender nor the close of the pool waits.
    let started = Instant::now();
    drop(sender);
    assert_eq!((db.free_count(), db.in_use_count()), (0, 0));
    db.close();
    assert_did_not_wait_for_close_flush_timeout(started.elapsed());

    wait_for_no_connection(&server);
    assert_eq!(server.frames_taken(), queued);
    // The server made the table when it took the first frame for it.
    assert_table_holds(&server, TABLE, 0, &[]);
    server.finish();
}

/// A pool with `close_flush_timeout` 0 waits for no answer when it closes a
/// sender: here the server never answers the flush before the failed one.
#[test]
fn a_pool_that_waits_for_nothing_at_close_gives_up_a_sender_whose_flush_failed_part_way_at_once() {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    server.hold_answers();
    let before = buffer_of_symbols(TABLE, 0..10);
    let (large, queued, symbols) = a_buffer_whose_flush_stops_part_way(Some(&before));
    let cap = TestDictCapGuard::new(symbols);
    let db = pool_with(server.port, "close_flush_timeout_millis=0;");
    let mut sender = db.borrow_sender().unwrap();
    drop(cap);
    stop_a_flush_part_way(&mut sender, &server, Some(&before), &large, queued);

    // Less than the `close_flush_timeout` of a pool that is told none.
    let started = Instant::now();
    drop(sender);
    let took = started.elapsed();
    assert!(took < Duration::from_secs(2), "the pool waited {took:?}");

    wait_for_no_connection(&server);
    assert_eq!(server.frames_taken(), 1 + queued);
    // The server had committed the flush before when it took its frame.
    assert_table_holds(&server, TABLE, 1, &[&before]);
    db.close();
    server.finish();
}

/// The pool is closed while the sender is out, which the lifetime of a
/// borrowed sender rules out and a sender that owns its place allows: the
/// kind that the C and the Python client hold.
#[cfg(feature = "ffi-support")]
#[test]
fn a_closed_pool_closes_a_sender_whose_flush_failed_part_way_when_it_comes_back() {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    server.hold_answers();
    let before = buffer_of_symbols(TABLE, 0..10);
    let (large, queued, symbols) = a_buffer_whose_flush_stops_part_way(Some(&before));
    let cap = TestDictCapGuard::new(symbols);
    let db = pool_with(server.port, LONG_CLOSE_FLUSH);
    let mut sender = db.borrow_sender_owned().unwrap();
    drop(cap);
    assert_eq!(
        sender
            .get_mut()
            .flush_buffer_and_keep_and_get_fsn(&before)
            .unwrap(),
        Some(0)
    );
    let err = sender.get_mut().flush_buffer_and_keep(&large).unwrap_err();
    assert_eq!(err.code(), ErrorCode::FlushAborted, "{}", err.msg());
    wait_for_frames_taken(&server, 1 + queued);

    // The close of the pool does not wait for a sender that is out, and
    // leaves its connection alone.
    let started = Instant::now();
    db.close();
    assert_did_not_wait_for_close_flush_timeout(started.elapsed());
    assert!(sender.must_close());
    assert_eq!(server.open_connections(), 1);

    // The sender comes back as to an open pool.
    let (took, taken, open) = give_back_while_answers_are_held(&server, || drop(sender));
    assert!(took >= HELD, "the pool did not wait for the flush before");
    assert_did_not_wait_for_close_flush_timeout(took);
    assert_eq!((taken, open), (1 + queued, 1));
    wait_for_no_connection(&server);
    assert_eq!(server.frames_taken(), 1 + queued);
    assert_table_holds(&server, TABLE, 1, &[&before]);
    server.finish();
}

#[test]
fn a_pooled_sender_with_sf_dir_refuses_a_buffer_above_the_frame_cap() {
    let server = QwpWsModelServer::start(FRAME_LIMIT);
    let sf_dir = tempfile::TempDir::new().unwrap();
    let settings = format!(
        "sf_dir={};sender_id=large;sf_max_segment_bytes=65536;",
        sf_dir.path().display()
    );
    let db = pool_with(server.port, &settings);
    let mut sender = db.borrow_sender().unwrap();
    assert_eq!(sender.effective_frame_cap_for_test(), (FRAME_LIMIT, true));
    let mut large = buffer_of(TABLE, 0..2000);

    assert_refused_as_one_frame(&mut sender, &mut large, FRAME_LIMIT);
    assert_eq!(server.frames_taken(), 0);
    drop(sender);
    db.close();
    server.finish();
}

#[test]
fn a_pooled_sender_whose_server_tells_no_frame_limit_refuses_a_buffer_above_the_frame_cap() {
    let port = spawn_max_batch_size_upgrade_only_server(None);
    // The cap is then what a segment of the queue holds: its 4,096 bytes
    // less the headers of the segment and of a frame, 24 and 8 bytes. This
    // server answers no frame: the pool does not wait for it.
    let db = pool_with(
        port,
        "sf_max_segment_bytes=4096;close_flush_timeout_millis=0;",
    );
    let mut sender = db.borrow_sender().unwrap();
    assert_eq!(sender.effective_frame_cap_for_test(), (4064, false));
    let mut large = buffer_of(TABLE, 0..2000);

    // The refusal says what keeps the buffer from going out in frames.
    let refusal = size_refusal_of(&mut sender, &mut large);
    let end = format!(
        " bytes) exceeds the store-and-forward per-frame cap (4064 bytes, the smaller of \
         max_buf_size and the sf_max_segment_bytes segment payload capacity)\
         {NO_FRAME_LIMIT_TOLD}"
    );
    assert!(
        refusal.starts_with("QWP frame (") && refusal.ends_with(&end),
        "got: {refusal}"
    );
    // A buffer that fits one frame is sent as before.
    sender.flush_buffer(&mut buffer_of(TABLE, 0..3)).unwrap();
    drop(sender);

    // Where `max_buf_size` is the cap, no server would get the buffer in
    // frames, and the refusal says no more than before.
    let port = spawn_max_batch_size_upgrade_only_server(None);
    let db = pool_with(port, "sf_max_segment_bytes=4096;max_buf_size=3000;");
    let mut sender = db.borrow_sender().unwrap();
    assert_eq!(sender.effective_frame_cap_for_test(), (3000, false));
    assert_refused_as_one_frame(&mut sender, &mut large, 3000);
    drop(sender);

    // The same with `sf_dir`, where no buffer goes out in frames whatever
    // the server tells.
    let port = spawn_max_batch_size_upgrade_only_server(None);
    let sf_dir = tempfile::TempDir::new().unwrap();
    let settings = format!(
        "sf_dir={};sender_id=large;sf_max_segment_bytes=4096;",
        sf_dir.path().display()
    );
    let db = pool_with(port, &settings);
    let mut sender = db.borrow_sender().unwrap();
    assert_eq!(sender.effective_frame_cap_for_test(), (4064, false));
    assert_refused_as_one_frame(&mut sender, &mut large, 4064);
}

/// A pool that connects when its first sender is used: that sender does not
/// know its server yet.
#[test]
fn a_pooled_sender_that_is_not_connected_yet_refuses_a_buffer_above_the_frame_cap() {
    // No server ever answers on this port.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let db = pool_with(port, "lazy_connect=true;sf_max_segment_bytes=4096;");
    let mut sender = db.borrow_sender().unwrap();
    assert_eq!(sender.effective_frame_cap_for_test(), (4064, false));
    let mut large = buffer_of(TABLE, 0..2000);

    let refusal = size_refusal_of(&mut sender, &mut large);
    assert!(refusal.ends_with(NO_FRAME_LIMIT_TOLD), "got: {refusal}");
}
