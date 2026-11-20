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

//! One flush of a row buffer that is far larger than a frame, through the
//! public `Sender`, against a real QuestDB server: the server commits the
//! flush as one transaction of each table, which holds exactly the rows.
//!
//! The rows and the checks of the tables are those of `qwp_ws_defer_probe`,
//! which writes such frames to a raw WebSocket. Here the sender cuts the
//! buffer and sends the frames. There are six tests:
//!
//! - a flush of one table without symbols into a table that the flush
//!   creates, so the time until the server confirms includes the time it
//!   takes to create one;
//! - a flush of two tables with symbols, one of them with more symbols than
//!   a frame holds, into tables that exist. The buffer is flushed twice:
//!   the first time its frames bring the symbols, the second time the
//!   connection knows them;
//! - two flushes of one table, one right after the other, through a sender
//!   whose queue takes one of them at a time: the second `flush` waits
//!   until the server has confirmed the first;
//! - a flush with symbols that fails part way, after a small flush of the
//!   same sender: the server commits the small flush and no row of the
//!   failed one, and the same buffer through a new sender is one
//!   transaction;
//! - a flush of a sender in manual progress mode, which sends nothing until
//!   the caller drives the connection, and then two flushes of such a
//!   sender through a queue that takes one of them at a time: the second
//!   `flush` drives the connection itself until the server has confirmed
//!   the first;
//! - a flush over three tables with a frame in its middle that the server
//!   rejects for good, after a small flush of the same sender, in both
//!   progress modes: the sender stops with the server's rejection, the
//!   server commits the small flush and no row of the rejected one, and
//!   the rows without the fault are one transaction of each table through
//!   a new sender.
//!
//! Each test also prints how long a flush took; the first two, how much
//! memory the process held; the second one, how many frames its flushes
//! took. For these numbers run one test at a time, from a release build.
//! This runs all six; the whole name of a test runs that one:
//!
//! `QDB_QWP_WS_LARGE_FLUSH_PROBE=1 QDB_QWP_WS_PORT=9000 cargo test --release --manifest-path questdb-rs/Cargo.toml --lib qwp_ws_real_server_large_flush -- --ignored --nocapture`
//!
//! `QDB_QWP_WS_LARGE_FLUSH_PROBE_MIB` is the size of the buffer in MiB: 20
//! when it is not set, and no more than 100, the most that a sender takes in
//! one flush (`max_buf_size`).

use std::time::{Duration, Instant};

use crate::ErrorCode;
use crate::ingress::{
    AckLevel, Buffer, QwpWsErrorCategory, QwpWsErrorPolicy, Sender, SenderBuilder,
    SymbolGlobalDict, TestDictCapGuard,
};

use super::TestResult;
use super::qwp_ws_defer_probe::{
    Digest, Group, SERVER_MAX_UNCOMMITTED_ROWS, Server, TagOf, push_row,
    push_row_with_a_text_for_a_number, rows_from, symbols_brought, tag_of, text_len_of,
};
use super::qwp_ws_protocol_probe::{ProbeConfig, ProbeResult, query_build};
use super::qwp_ws_server_model::{frame_of_a_sender, frames_of_a_flush, frames_of_a_sender};

/// More than 16 MiB, the largest message the protocol has.
const DEFAULT_MIB: usize = 20;
/// A row of the group takes less than this in a buffer.
const ROW_ROOM: usize = 256;
/// A row with symbols takes less than this in a buffer, a tag of its own
/// included.
const SYMBOL_ROW_ROOM: usize = 512;
/// How many rows of each table the flush that creates the tables has.
const CREATING_ROWS: usize = 20;
/// How long the server may stay silent before the flush counts as lost. It
/// answers a flush once, at the end.
const WAIT: Duration = Duration::from_secs(30);
/// A queue of 8 MiB, which is two of its segments: too small for a buffer
/// of more than a few frames, whatever the server confirms.
const QUEUE_TOO_SMALL: u64 = 8 * 1024 * 1024;
/// How long a server is given to see that a connection went away. Its log
/// shows that it takes a few milliseconds.
const DROP_SETTLE: Duration = Duration::from_secs(1);

#[test]
#[ignore = "requires a real QuestDB server and QDB_QWP_WS_LARGE_FLUSH_PROBE=1"]
fn qwp_ws_real_server_large_flush_is_one_transaction() -> TestResult {
    let Some((config, mib)) = probe_settings()? else {
        return Ok(());
    };
    let server = Server::Live(&config);
    let (table, _cleanup) = server.new_table("qwp_large_flush");

    // A sender as its defaults make it: it sends in the background and keeps
    // its queue in memory.
    let conf = format!("ws::addr={}:{};", config.host, config.qwp_ws_port);
    let mut sender = SenderBuilder::from_conf(conf)?.build()?;
    let (frame_cap, told_by_server) = sender.effective_frame_cap()?;
    assert!(told_by_server, "the server told no frame limit");
    let resident_with_sender = resident_mib("VmRSS");

    // A group ends with the row that reaches the size it is given: a row
    // less keeps the buffer within the size asked for, which may be all
    // that a sender takes. The group's list of its rows ends with this
    // block, so the process then holds the buffer and what the sender
    // takes, and little else.
    let (expected, mut buffer) = {
        let bytes = (mib * 1024 * 1024).saturating_sub(ROW_ROOM);
        let group = Group::of_bytes(&table, 0, bytes)?;
        (group.digest(), group.buffer)
    };
    let (rows, len) = (buffer.row_count(), buffer.len());
    assert!(
        len > frame_cap,
        "a buffer of {len} bytes fits one frame of {frame_cap}"
    );
    let resident_with_buffer = resident_mib("VmRSS");

    let started = Instant::now();
    let fsn = sender.flush_and_get_fsn(&mut buffer)?;
    let flush_took = started.elapsed();
    sender.wait(AckLevel::Ok, WAIT)?;
    let confirmed_after = started.elapsed();
    let resident_at_most = resident_mib("VmHWM");

    // The frames of the flush are the first of this sender.
    let frames = fsn.expect("a flush of rows publishes frames") + 1;
    assert!(buffer.is_empty());
    assert!(
        frames >= len.div_ceil(frame_cap) as u64,
        "{frames} frames for {len} bytes"
    );
    assert_eq!(sender.completed_fsn(AckLevel::Ok)?, fsn);
    // Every frame went out once, on the first connection, and the server
    // refused none.
    let totals = sender.qwp_ws_totals()?;
    assert_eq!(
        (
            totals.frames_sent,
            totals.frames_replayed,
            totals.reconnect_attempts,
            totals.server_errors
        ),
        (frames, 0, 0, 0),
        "{totals:?}"
    );

    server.wait_for_rows(&table, rows)?;
    assert_eq!(server.digest(&table)?, Some(expected));
    assert_eq!(server.transactions(&table)?, Some(1));

    eprintln!(
        "large flush: {rows} rows, {len} bytes in the buffer, {frames} frames of at most \
         {frame_cap} bytes; flush returned after {flush_took:?}, and the server had confirmed \
         the rows {confirmed_after:?} after the call began"
    );
    eprintln!(
        "resident memory of the process, in MiB: {resident_with_sender} with the sender \
         connected, {resident_with_buffer} with the buffer filled, at most {resident_at_most} \
         until the server had confirmed"
    );
    Ok(())
}

/// One flush of two tables with symbols, far larger than a frame, into
/// tables that exist. The rows of the first table have the symbols of the
/// script: ten rows share a tag. Every row of the second table has a tag of
/// its own, and together these tags are more than a frame holds, so the
/// frames must bring them as they go. The server commits the flush as one
/// transaction of each table.
///
/// The same buffer is then flushed again. Now the connection knows every
/// symbol and the frames bring none. Each table gets one more transaction
/// and holds every row of the buffer twice, each with its symbols.
///
/// A server is slow to add very many new symbols to a symbol column that it
/// created itself: the rows of the second table show a second after the
/// server confirmed them at 20 MiB, and half a minute after at 100 MiB.
#[test]
#[ignore = "requires a real QuestDB server and QDB_QWP_WS_LARGE_FLUSH_PROBE=1"]
fn qwp_ws_real_server_large_flush_with_symbols_is_one_transaction_of_each_table() -> TestResult {
    let Some((config, mib)) = probe_settings()? else {
        return Ok(());
    };
    let server = Server::Live(&config);
    let (few, _cleanup_few) = server.new_table("qwp_large_flush_few_symbols");
    let (many, _cleanup_many) = server.new_table("qwp_large_flush_many_symbols");
    // Per table: its name, the id of its first row, and the tags of its rows.
    let tables: [(&str, i64, TagOf); 2] = [(&few, 0, tag_of), (&many, 5_000_000, own_tag_of)];

    let conf = format!("ws::addr={}:{};", config.host, config.qwp_ws_port);
    let mut sender = SenderBuilder::from_conf(conf)?.build()?;
    let (frame_cap, told_by_server) = sender.effective_frame_cap()?;
    assert!(told_by_server, "the server told no frame limit");

    // A flush of a few rows creates the tables, so that the large flush does
    // not wait for that. It brings the venues, which every later row has.
    let mut creating = Buffer::new_qwp_ws();
    for (table, first_id, tag_of) in tables {
        for (id, text_len) in rows_from(first_id, CREATING_ROWS) {
            push_row(&mut creating, table, id, text_len, Some(tag_of))?;
        }
    }
    assert_eq!(sender.flush_and_keep_and_get_fsn(&creating)?, Some(0));
    sender.wait(AckLevel::Ok, WAIT)?;
    for (table, ..) in tables {
        assert_eq!(server.transactions(table)?, Some(1));
    }
    let resident_with_sender = resident_mib("VmRSS");

    // The large buffer. The test keeps no list of its rows: the process then
    // holds the buffer and what the sender takes, and little else.
    let bytes = (mib * 1024 * 1024).saturating_sub(SYMBOL_ROW_ROOM);
    let mut buffer = Buffer::new_qwp_ws();
    let mut row_counts = [0; 2];
    for (table_idx, (table, first_id, tag_of)) in tables.into_iter().enumerate() {
        // Two fifths of the buffer are rows of the first table.
        let until = if table_idx == 0 { bytes * 2 / 5 } else { bytes };
        let mut id = first_id + CREATING_ROWS as i64;
        while buffer.len() < until {
            push_row(&mut buffer, table, id, text_len_of(id), Some(tag_of))?;
            id += 1;
            row_counts[table_idx] += 1;
        }
    }
    let [few_rows, many_rows] = row_counts;
    let len = buffer.len();
    assert!(
        len > frame_cap,
        "a buffer of {len} bytes fits one frame of {frame_cap}"
    );
    assert!(
        few_rows.max(many_rows) < SERVER_MAX_UNCOMMITTED_ROWS,
        "a server commits a flush of {few_rows} and {many_rows} rows in parts"
    );
    // What the tags of the second table take in the frames that bring them:
    // a byte for its length and the text, each.
    let own_tag_len = own_tag_of(0).map_or(0, |tag| tag.len());
    let many_tag_bytes = many_rows * (1 + own_tag_len);
    assert!(
        many_tag_bytes > frame_cap,
        "one frame of {frame_cap} bytes holds the {many_tag_bytes} bytes of the tags"
    );
    let resident_with_buffer = resident_mib("VmRSS");

    // The first flush: its frames bring the symbols. Each table then holds
    // the rows that created it and the rows of the buffer.
    let with_new_symbols = flush_and_wait(&mut sender, &buffer)?;
    for ((table, first_id, _), rows) in tables.into_iter().zip(row_counts) {
        let held = rows_from(first_id, CREATING_ROWS + rows);
        server.wait_for_rows(table, held.len())?;
        assert_eq!(server.digest(table)?, Some(Digest::of(&held)));
        assert_eq!(server.transactions(table)?, Some(2));
    }

    // The second flush of the same rows: the connection knows the symbols.
    // The symbols of both flushes are checked here, row by row.
    let with_known_symbols = flush_and_wait(&mut sender, &buffer)?;
    for ((table, first_id, tag_of), rows) in tables.into_iter().zip(row_counts) {
        let held = [
            rows_from(first_id, CREATING_ROWS + rows),
            rows_from(first_id + CREATING_ROWS as i64, rows),
        ]
        .concat();
        server.wait_for_rows(table, held.len())?;
        server.expect_rows_with_tags(table, &held, tag_of)?;
        assert_eq!(server.transactions(table)?, Some(3));
    }

    // Every frame went out once, on the first connection, and the server
    // refused none. The flush that created the tables was one frame.
    let totals = sender.qwp_ws_totals()?;
    assert_eq!(
        (
            totals.frames_sent,
            totals.frames_replayed,
            totals.reconnect_attempts,
            totals.server_errors
        ),
        (with_known_symbols.fsn + 1, 0, 0, 0),
        "{totals:?}"
    );

    // How full the frames were: the bytes that the flush takes as one
    // message, with the symbols that the connection did not know, against
    // the bytes that its frames may hold. The dictionary here is what that
    // of the sender was.
    let mut symbols = SymbolGlobalDict::new();
    frame_of_a_sender(&creating, false, &mut symbols);
    let known_before = symbols.next_id();
    let new_bytes = frame_of_a_sender(&buffer, false, &mut symbols).len();
    let brought = symbols.next_id() - known_before;
    let known_bytes = frame_of_a_sender(&buffer, false, &mut symbols).len();
    assert_eq!(symbols.next_id(), known_before + brought);
    assert!(brought as usize > many_rows, "{brought} symbols");
    eprintln!(
        "large flush with symbols: {few_rows} and {many_rows} rows, {len} bytes in the buffer, \
         {brought} symbols that the connection did not know, the tags of the second table \
         {many_tag_bytes} bytes; frames of at most {frame_cap} bytes"
    );
    for (symbols, flushed, frames, bytes) in [
        ("new", &with_new_symbols, with_new_symbols.fsn, new_bytes),
        (
            "known",
            &with_known_symbols,
            with_known_symbols.fsn - with_new_symbols.fsn,
            known_bytes,
        ),
    ] {
        let frames = frames as usize;
        let enough = bytes.div_ceil(frame_cap);
        assert!(frames >= enough, "{frames} frames for {bytes} bytes");
        eprintln!(
            "symbols {symbols}: {frames} frames, where {enough} could hold the {bytes} bytes that \
             the flush takes as one message; flush returned after {:?}, and the server had \
             confirmed the rows {:?} after the call began",
            flushed.flush_took, flushed.confirmed_after,
        );
    }
    eprintln!(
        "resident memory of the process, in MiB: {resident_with_sender} with the sender \
         connected, {resident_with_buffer} with the buffer filled, at most {} until the server \
         had confirmed the first flush and {} until the second",
        with_new_symbols.resident_at_most, with_known_symbols.resident_at_most
    );
    Ok(())
}

/// Two flushes far larger than a frame, one right after the other, through a
/// sender whose queue takes one of them at a time. The second `flush` is
/// called while the queue holds the first. It waits until the server has
/// confirmed the first, then queues its own frames and returns. The server
/// commits each flush as one transaction.
///
/// The sender itself tells how large that queue is: with a queue that can
/// never take such a buffer, it refuses the buffer at once, and the error
/// names the size of a queue that takes it.
#[test]
#[ignore = "requires a real QuestDB server and QDB_QWP_WS_LARGE_FLUSH_PROBE=1"]
fn qwp_ws_real_server_large_flush_waits_for_room_in_the_queue() -> TestResult {
    let Some((config, mib)) = probe_settings()? else {
        return Ok(());
    };
    let server = Server::Live(&config);
    let (table, _cleanup) = server.new_table("qwp_large_flush_waits");
    let addr = format!("ws::addr={}:{};", config.host, config.qwp_ws_port);

    // A few rows that create the table, then the rows of the two large
    // flushes: each flush has rows of its own.
    let mut creating = Buffer::new_qwp_ws();
    for (id, text_len) in rows_from(0, CREATING_ROWS) {
        push_row(&mut creating, &table, id, text_len, None)?;
    }
    let bytes = (mib * 1024 * 1024).saturating_sub(ROW_ROOM);
    let mut first = Group::of_bytes(&table, CREATING_ROWS as i64, bytes)?.buffer;
    let (first_rows, first_len) = (first.row_count(), first.len());
    let second_from = (CREATING_ROWS + first_rows) as i64;
    let mut second = Group::of_bytes(&table, second_from, bytes)?.buffer;
    let (second_rows, second_len) = (second.row_count(), second.len());

    // A queue that is too small for such a buffer: the sender refuses the
    // buffer at once, queues nothing of it, and names the queue that it
    // needs.
    let conf = format!("{addr}sf_max_total_bytes={QUEUE_TOO_SMALL};");
    let mut small = SenderBuilder::from_conf(conf)?.build()?;
    let (frame_cap, told_by_server) = small.effective_frame_cap()?;
    assert!(told_by_server, "the server told no frame limit");
    assert!(
        first_len > frame_cap,
        "a buffer of {first_len} bytes fits one frame of {frame_cap}"
    );
    let started = Instant::now();
    let refusal = match small.flush(&mut first) {
        Err(refusal) => refusal,
        Ok(()) => panic!("a queue of {QUEUE_TOO_SMALL} bytes took a buffer of {first_len} bytes"),
    };
    let refused_after = started.elapsed();
    assert_eq!(
        refusal.code(),
        ErrorCode::BatchTooLarge,
        "{}",
        refusal.msg()
    );
    assert_eq!(
        (first.row_count(), first.len()),
        (first_rows, first_len),
        "the buffer keeps its rows"
    );
    assert_eq!(small.published_fsn()?, None, "nothing is queued");
    assert!(!small.must_close());
    drop(small);
    let queue_bytes = queue_bytes_named_by(&refusal)?;
    // That queue is too small for the two flushes together.
    assert!(
        queue_bytes < (first_len + second_len) as u64,
        "a queue of {queue_bytes} bytes may take buffers of {first_len} and {second_len} bytes \
         together, and then the second flush has nothing to wait for: use larger buffers"
    );

    // A sender with the queue that the error names. A flush of a few rows
    // creates the table, so that the large flushes do not wait for that.
    let conf = format!("{addr}sf_max_total_bytes={queue_bytes};");
    let mut sender = SenderBuilder::from_conf(conf)?.build()?;
    assert_eq!(sender.effective_frame_cap()?, (frame_cap, true));
    assert_eq!(sender.flush_and_keep_and_get_fsn(&creating)?, Some(0));
    sender.wait(AckLevel::Ok, WAIT)?;
    assert_eq!(server.transactions(&table)?, Some(1));

    // The two flushes, with no wait for the server between them: only a
    // look at what it has confirmed so far.
    let started = Instant::now();
    let first_fsn = sender.flush_and_get_fsn(&mut first)?;
    let first_took = started.elapsed();
    let confirmed_between = sender.completed_fsn(AckLevel::Ok)?;
    let second_started = Instant::now();
    let second_fsn = sender.flush_and_get_fsn(&mut second)?;
    let second_took = second_started.elapsed();
    let confirmed_at_return = sender.completed_fsn(AckLevel::Ok)?;
    sender.wait(AckLevel::Ok, WAIT)?;
    let confirmed_after = started.elapsed();

    assert!(first.is_empty() && second.is_empty());
    let first_fsn = first_fsn.expect("a flush of rows publishes frames");
    let second_fsn = second_fsn.expect("a flush of rows publishes frames");
    // The second flush was called while the queue held the first, whose
    // frames stay there until the server confirms them, and the queue is
    // too small for both. So it had no room, and got it when the server
    // confirmed the first.
    assert!(
        confirmed_between < Some(first_fsn),
        "the server had confirmed the first flush before the second was called, which then had \
         nothing to wait for"
    );
    assert!(
        confirmed_at_return >= Some(first_fsn),
        "the second flush returned before the server had confirmed the first: a queue of \
         {queue_bytes} bytes held both"
    );
    assert_eq!(sender.completed_fsn(AckLevel::Ok)?, Some(second_fsn));
    // The frame that created the table is the first of this sender.
    let (first_frames, second_frames) = (first_fsn, second_fsn - first_fsn);
    for (frames, len) in [(first_frames, first_len), (second_frames, second_len)] {
        assert!(
            frames >= len.div_ceil(frame_cap) as u64,
            "{frames} frames for {len} bytes"
        );
    }
    // Every frame went out once, on the first connection, and the server
    // refused none.
    let totals = sender.qwp_ws_totals()?;
    assert_eq!(
        (
            totals.frames_sent,
            totals.frames_replayed,
            totals.reconnect_attempts,
            totals.server_errors
        ),
        (second_fsn + 1, 0, 0, 0),
        "{totals:?}"
    );
    assert!(!sender.must_close());

    // A transaction for each flush, and the table holds the rows of all
    // three, each row once.
    let rows = CREATING_ROWS + first_rows + second_rows;
    server.wait_for_rows(&table, rows)?;
    assert_eq!(
        server.digest(&table)?,
        Some(Digest::of(&rows_from(0, rows)))
    );
    assert_eq!(server.transactions(&table)?, Some(3));

    eprintln!(
        "large flush that waits: two flushes of {first_rows} and {second_rows} rows, {first_len} \
         and {second_len} bytes in the buffer, {first_frames} and {second_frames} frames of at \
         most {frame_cap} bytes, through a queue of {queue_bytes} bytes; the first flush \
         returned after {first_took:?}; the second, called while the queue held the first, \
         returned after {second_took:?}; the server had confirmed both {confirmed_after:?} \
         after the first call began"
    );
    eprintln!(
        "a queue of {QUEUE_TOO_SMALL} bytes refused the buffer after {refused_after:?}: {}",
        refusal.msg()
    );
    Ok(())
}

/// A flush far larger than a frame that fails part way, after a small flush
/// of the same sender. The rows of both have the symbols of the script. The
/// test makes the symbol dictionary of the sender so small that it is full
/// when the first half of the frames of the large flush is queued: the next
/// frame brings a symbol more, and the flush fails there.
///
/// The large flush fails with `FlushAborted` and its buffer keeps its rows.
/// The sender sends the frames that it had queued, which the server holds
/// without committing them, and takes no more flushes. Its `wait` returns
/// when the server has confirmed the small flush, and so does its
/// `close_drain`. The table then holds the rows of the small flush, in one
/// transaction, and still does when the sender is gone: the server drops
/// the rows it held with the connection.
///
/// The same buffer through a new sender is one more transaction, and the
/// table holds every row once.
#[test]
#[ignore = "requires a real QuestDB server and QDB_QWP_WS_LARGE_FLUSH_PROBE=1"]
fn qwp_ws_real_server_large_flush_that_fails_part_way_commits_none_of_its_rows() -> TestResult {
    let Some((config, mib)) = probe_settings()? else {
        return Ok(());
    };
    let server = Server::Live(&config);
    let (table, _cleanup) = server.new_table("qwp_large_flush_aborted");
    let conf = format!("ws::addr={}:{};", config.host, config.qwp_ws_port);
    // A sender that is only asked what the server takes in a frame.
    let frame_cap = {
        let sender = SenderBuilder::from_conf(&conf)?.build()?;
        let (frame_cap, told_by_server) = sender.effective_frame_cap()?;
        assert!(told_by_server, "the server told no frame limit");
        frame_cap
    };

    // The small flush, which creates the table, and the large one. Ten rows
    // share a tag, so every frame of the large one brings new symbols.
    let small_rows = rows_from(0, CREATING_ROWS);
    let mut small = Buffer::new_qwp_ws();
    for (id, text_len) in &small_rows {
        push_row(&mut small, &table, *id, *text_len, Some(tag_of))?;
    }
    let bytes = (mib * 1024 * 1024).saturating_sub(SYMBOL_ROW_ROOM);
    let mut large = Buffer::new_qwp_ws();
    let mut id = CREATING_ROWS as i64;
    while large.len() < bytes {
        push_row(&mut large, &table, id, text_len_of(id), Some(tag_of))?;
        id += 1;
    }
    let (rows, len) = (large.row_count(), large.len());
    // Fewer rows than a server holds before it commits by itself: it would
    // commit a part of the failed flush.
    assert!(
        rows < SERVER_MAX_UNCOMMITTED_ROWS,
        "a server commits a flush of {rows} rows in parts"
    );

    // The frames that a sender makes of the large buffer after the small
    // one. The flush is to fail at the frame in the middle: the connection
    // takes the symbols that it holds before that frame, and no more.
    let (frame_count, failing, symbol_cap, all_symbols) = {
        let mut symbols = SymbolGlobalDict::new();
        frame_of_a_sender(&small, false, &mut symbols);
        let frames = frames_of_a_sender(&large, frame_cap, &mut symbols);
        let failing = frames.len() / 2;
        assert!(failing >= 1, "{} frames: use a larger buffer", frames.len());
        let (held_before, brought) = symbols_brought(&frames[failing..=failing])[0];
        assert!(brought > 0, "frame {failing} brings no symbol");
        (
            frames.len(),
            failing,
            held_before as usize,
            symbols.next_id(),
        )
    };
    let mut sender = {
        // The dictionary of a sender is made when the sender is built.
        let _cap = TestDictCapGuard::new(symbol_cap);
        SenderBuilder::from_conf(&conf)?.build()?
    };
    assert_eq!(sender.effective_frame_cap()?, (frame_cap, true));

    // The two flushes, with no wait for the server between them.
    assert_eq!(sender.flush_and_keep_and_get_fsn(&small)?, Some(0));
    let started = Instant::now();
    let err = match sender.flush(&mut large) {
        Err(err) => err,
        Ok(()) => panic!(
            "a connection that takes {symbol_cap} symbols took a buffer that brings \
             {all_symbols}"
        ),
    };
    let failed_after = started.elapsed();
    assert_eq!(err.code(), ErrorCode::FlushAborted, "{}", err.msg());
    let cause = format!("dictionary reached its {symbol_cap}-entry cap");
    assert!(err.msg().contains(&cause), "{}", err.msg());
    assert!(!err.in_doubt());
    assert!(sender.must_close());
    assert_eq!(
        (large.row_count(), large.len()),
        (rows, len),
        "the buffer keeps its rows"
    );
    // The sender has published the small flush, and says no more.
    assert_eq!(sender.published_fsn()?, Some(0));

    // It waits for the answer to the small flush and for no other: the
    // server answers no frame of the failed flush.
    let confirmed_at_failure = sender.completed_fsn(AckLevel::Ok)?;
    let wait_started = Instant::now();
    sender.wait(AckLevel::Ok, WAIT)?;
    let waited = wait_started.elapsed();
    assert_eq!(sender.completed_fsn(AckLevel::Ok)?, Some(0));
    assert_eq!(sender.published_fsn()?, Some(0));

    // It sends the frames of the failed flush that it had queued, which are
    // those before the failing one, each once.
    let queued = 1 + failing as u64;
    let deadline = Instant::now() + WAIT;
    while sender.qwp_ws_totals()?.frames_sent < queued {
        assert!(
            Instant::now() < deadline,
            "{:?}: the frames of the failed flush did not go out",
            sender.qwp_ws_totals()?
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    // A later flush gets the same error, and nothing of it is queued.
    let refused = match sender.flush_and_keep(&small) {
        Err(refused) => refused,
        Ok(()) => panic!("the sender took a flush after the one that failed part way"),
    };
    assert_eq!((refused.code(), refused.msg()), (err.code(), err.msg()));
    assert_eq!(sender.published_fsn()?, Some(0));
    let totals = sender.qwp_ws_totals()?;
    assert_eq!(
        (
            totals.frames_sent,
            totals.frames_replayed,
            totals.reconnect_attempts,
            totals.server_errors
        ),
        (queued, 0, 0, 0),
        "{totals:?}"
    );

    // The server has committed the small flush and nothing else.
    server.wait_for_rows(&table, small_rows.len())?;
    assert_eq!(server.digest(&table)?, Some(Digest::of(&small_rows)));
    assert_eq!(server.transactions(&table)?, Some(1));

    // What the error says to do: close the sender, and flush the buffer
    // through a new one. The close has nothing left to wait for.
    let close_started = Instant::now();
    sender.close_drain()?;
    let closed_after = close_started.elapsed();
    assert!(sender.must_close());
    drop(sender);
    // The rows that the server held go with the connection.
    server.wait_for_the_drop(DROP_SETTLE);
    assert_eq!(server.digest(&table)?, Some(Digest::of(&small_rows)));
    assert_eq!(server.transactions(&table)?, Some(1));

    let mut sender = SenderBuilder::from_conf(&conf)?.build()?;
    let again = flush_and_wait(&mut sender, &large)?;
    let frames_again = again.fsn + 1;
    assert!(
        frames_again >= len.div_ceil(frame_cap) as u64,
        "{frames_again} frames for {len} bytes"
    );
    let totals = sender.qwp_ws_totals()?;
    assert_eq!(
        (
            totals.frames_sent,
            totals.frames_replayed,
            totals.reconnect_attempts,
            totals.server_errors
        ),
        (frames_again, 0, 0, 0),
        "{totals:?}"
    );
    assert!(!sender.must_close());

    // One more transaction, and the table holds every row once, each with
    // its symbols.
    let held = rows_from(0, CREATING_ROWS + rows);
    server.wait_for_rows(&table, held.len())?;
    server.expect_rows_with_tags(&table, &held, tag_of)?;
    assert_eq!(server.transactions(&table)?, Some(2));

    eprintln!(
        "large flush that fails part way: {rows} rows, {len} bytes in the buffer, \
         {frame_count} frames of at most {frame_cap} bytes, {all_symbols} symbols with those \
         of the small flush before it; a connection that takes {symbol_cap} symbols failed \
         the flush at frame {failing} after {failed_after:?}, with the {failing} frames \
         before it queued; the server had confirmed {confirmed_at_failure:?} by then; wait \
         returned after {waited:?}, close_drain after {closed_after:?}"
    );
    eprintln!("the error: {}", err.msg());
    eprintln!(
        "the same buffer through a new sender: {frames_again} frames; flush returned after \
         {:?}, and the server had confirmed the rows {:?} after the call began",
        again.flush_took, again.confirmed_after
    );
    Ok(())
}

/// Flushes far larger than a frame through senders in manual progress mode,
/// where nobody sends frames or reads the server's answers unless the
/// caller drives the connection.
///
/// The first sender has the queue of its defaults. Its flush only queues
/// the frames, and none goes out. `wait` drives the connection, and the
/// server commits the flush as one transaction, which creates the table.
///
/// The second sender has a queue that takes one such flush at a time, and
/// flushes twice with nothing in between. The second `flush` finds the
/// queue full of the frames of the first, which nobody has sent. It drives
/// the connection itself until the server has confirmed the first flush,
/// queues its own frames in the room that this gives, and sends none of
/// them: they go out with the `wait` that follows.
#[test]
#[ignore = "requires a real QuestDB server and QDB_QWP_WS_LARGE_FLUSH_PROBE=1"]
fn qwp_ws_real_server_large_flush_in_manual_progress_mode_is_one_transaction() -> TestResult {
    let Some((config, mib)) = probe_settings()? else {
        return Ok(());
    };
    let server = Server::Live(&config);
    let (table, _cleanup) = server.new_table("qwp_large_flush_manual");
    let addr = format!(
        "ws::addr={}:{};qwp_ws_progress=manual;",
        config.host, config.qwp_ws_port
    );

    // Three flushes, each with rows of its own.
    let bytes = (mib * 1024 * 1024).saturating_sub(ROW_ROOM);
    let mut alone = Group::of_bytes(&table, 0, bytes)?.buffer;
    let (alone_rows, alone_len) = (alone.row_count(), alone.len());
    let mut first = Group::of_bytes(&table, alone_rows as i64, bytes)?.buffer;
    let (first_rows, first_len) = (first.row_count(), first.len());
    let second_from = (alone_rows + first_rows) as i64;
    let mut second = Group::of_bytes(&table, second_from, bytes)?.buffer;
    let (second_rows, second_len) = (second.row_count(), second.len());

    // A sender as its defaults make it, but for the progress mode.
    let mut sender = SenderBuilder::from_conf(&addr)?.build()?;
    let (frame_cap, told_by_server) = sender.effective_frame_cap()?;
    assert!(told_by_server, "the server told no frame limit");
    assert!(
        alone_len > frame_cap,
        "a buffer of {alone_len} bytes fits one frame of {frame_cap}"
    );
    let started = Instant::now();
    let alone_fsn = sender.flush_and_get_fsn(&mut alone)?;
    let alone_took = started.elapsed();
    // The frames of the flush are the first of this sender.
    let alone_fsn = alone_fsn.expect("a flush of rows publishes frames");
    let alone_frames = alone_fsn + 1;
    assert!(alone.is_empty());
    assert!(
        alone_frames >= alone_len.div_ceil(frame_cap) as u64,
        "{alone_frames} frames for {alone_len} bytes"
    );
    // The flush had room, so it drove nothing: every frame is queued, and
    // none went out.
    assert_eq!(sender.published_fsn()?, Some(alone_fsn));
    assert_eq!(
        sender.qwp_ws_totals()?.frames_sent,
        0,
        "a flush that had room sent frames"
    );
    assert_eq!(sender.completed_fsn(AckLevel::Ok)?, None);
    // `wait` drives: it sends the frames and reads the server's answer.
    sender.wait(AckLevel::Ok, WAIT)?;
    let alone_confirmed_after = started.elapsed();
    assert_eq!(sender.completed_fsn(AckLevel::Ok)?, Some(alone_fsn));
    // Every frame went out once, on the first connection, and the server
    // refused none.
    let totals = sender.qwp_ws_totals()?;
    assert_eq!(
        (
            totals.frames_sent,
            totals.frames_replayed,
            totals.reconnect_attempts,
            totals.server_errors
        ),
        (alone_frames, 0, 0, 0),
        "{totals:?}"
    );
    assert!(!sender.must_close());
    drop(sender);
    server.wait_for_rows(&table, alone_rows)?;
    assert_eq!(
        server.digest(&table)?,
        Some(Digest::of(&rows_from(0, alone_rows)))
    );
    assert_eq!(server.transactions(&table)?, Some(1));

    // A queue that is too small for such a buffer: the sender refuses the
    // buffer at once and names the queue that it needs.
    let conf = format!("{addr}sf_max_total_bytes={QUEUE_TOO_SMALL};");
    let mut small = SenderBuilder::from_conf(conf)?.build()?;
    let refusal = match small.flush(&mut first) {
        Err(refusal) => refusal,
        Ok(()) => panic!("a queue of {QUEUE_TOO_SMALL} bytes took a buffer of {first_len} bytes"),
    };
    assert_eq!(
        refusal.code(),
        ErrorCode::BatchTooLarge,
        "{}",
        refusal.msg()
    );
    assert_eq!(small.published_fsn()?, None, "nothing is queued");
    drop(small);
    let queue_bytes = queue_bytes_named_by(&refusal)?;
    // That queue is too small for the two flushes together.
    assert!(
        queue_bytes < (first_len + second_len) as u64,
        "a queue of {queue_bytes} bytes may take buffers of {first_len} and {second_len} bytes \
         together, and then the second flush has nothing to wait for: use larger buffers"
    );

    // A sender with the queue that the error names, and the two flushes with
    // nothing between them that drives the connection.
    let conf = format!("{addr}sf_max_total_bytes={queue_bytes};");
    let mut sender = SenderBuilder::from_conf(conf)?.build()?;
    assert_eq!(sender.effective_frame_cap()?, (frame_cap, true));
    let started = Instant::now();
    let first_fsn = sender.flush_and_get_fsn(&mut first)?;
    let first_took = started.elapsed();
    let first_fsn = first_fsn.expect("a flush of rows publishes frames");
    assert_eq!(
        sender.qwp_ws_totals()?.frames_sent,
        0,
        "a flush that had room sent frames"
    );
    let second_started = Instant::now();
    let second_fsn = sender.flush_and_get_fsn(&mut second)?;
    let second_took = second_started.elapsed();
    let second_fsn = second_fsn.expect("a flush of rows publishes frames");
    assert!(first.is_empty() && second.is_empty());
    let (first_frames, second_frames) = (first_fsn + 1, second_fsn - first_fsn);
    for (frames, len) in [(first_frames, first_len), (second_frames, second_len)] {
        assert!(
            frames >= len.div_ceil(frame_cap) as u64,
            "{frames} frames for {len} bytes"
        );
    }
    // The second flush was called while the queue held the frames of the
    // first, and the queue is too small for both. Nobody else drives this
    // sender, so the flush itself sent the frames of the first and read
    // the server's answer to them. Then it had room: its own frames are
    // queued, and none of them went out.
    assert_eq!(sender.published_fsn()?, Some(second_fsn));
    assert_eq!(
        sender.completed_fsn(AckLevel::Ok)?,
        Some(first_fsn),
        "the second flush returned, and the server has not confirmed exactly the first: a \
         queue of {queue_bytes} bytes held both, or frames of the second went out"
    );
    assert_eq!(
        sender.qwp_ws_totals()?.frames_sent,
        first_frames,
        "the second flush sent other frames than those of the first"
    );
    assert_eq!(server.transactions(&table)?, Some(2));
    sender.wait(AckLevel::Ok, WAIT)?;
    let confirmed_after = started.elapsed();
    assert_eq!(sender.completed_fsn(AckLevel::Ok)?, Some(second_fsn));
    let totals = sender.qwp_ws_totals()?;
    assert_eq!(
        (
            totals.frames_sent,
            totals.frames_replayed,
            totals.reconnect_attempts,
            totals.server_errors
        ),
        (first_frames + second_frames, 0, 0, 0),
        "{totals:?}"
    );
    assert!(!sender.must_close());

    // A transaction for each flush, and the table holds the rows of all
    // three, each row once.
    let rows = alone_rows + first_rows + second_rows;
    server.wait_for_rows(&table, rows)?;
    assert_eq!(
        server.digest(&table)?,
        Some(Digest::of(&rows_from(0, rows)))
    );
    assert_eq!(server.transactions(&table)?, Some(3));

    eprintln!(
        "large flush in manual progress mode: {alone_rows} rows, {alone_len} bytes in the \
         buffer, {alone_frames} frames of at most {frame_cap} bytes; flush queued them in \
         {alone_took:?} and sent none; with wait driving, the server had confirmed the rows \
         {alone_confirmed_after:?} after the call began"
    );
    eprintln!(
        "manual flush that waits: two flushes of {first_rows} and {second_rows} rows, \
         {first_len} and {second_len} bytes in the buffer, {first_frames} and {second_frames} \
         frames, through a queue of {queue_bytes} bytes; the first flush queued its frames in \
         {first_took:?}; the second, called while the queue held the first, drove the \
         connection and returned after {second_took:?}; the server had confirmed both \
         {confirmed_after:?} after the first call began"
    );
    Ok(())
}

/// A flush far larger than a frame with a frame in its middle that the
/// server rejects for good, after a small flush of the same sender, once
/// for each progress mode. The flush has rows of three tables: of the
/// first for its first half, five of the second, and of the third. The
/// rows of the second table have a text in a column that is a number in
/// the table, so the server rejects the frame that brings them, when it
/// holds rows of the first table and before the frames of the third.
///
/// The sender stops with the server's rejection, which names that frame.
/// A sender in manual progress mode sends nothing before `wait`, so `flush`
/// returns and `wait` reports the rejection. In the background the answer
/// of the server can come while `flush` still queues frames, and `flush`
/// then fails with it. `close_drain` reports it too. Each table then holds
/// the rows of the small flush, in one transaction, and still does when the
/// sender is gone.
///
/// The same rows with a number where the text was are one more transaction
/// of each table through a new sender.
#[test]
#[ignore = "requires a real QuestDB server and QDB_QWP_WS_LARGE_FLUSH_PROBE=1"]
fn qwp_ws_real_server_large_flush_with_a_frame_that_the_server_rejects_commits_none_of_its_rows()
-> TestResult {
    let Some((config, mib)) = probe_settings()? else {
        return Ok(());
    };
    let server = Server::Live(&config);
    for (mode, progress) in [("background", ""), ("manual", "qwp_ws_progress=manual;")] {
        let created = ["one", "two", "three"]
            .map(|name| server.new_table(&format!("qwp_large_flush_rejected_{name}")));
        let tables = [&created[0].0, &created[1].0, &created[2].0];
        let conf = format!("ws::addr={}:{};{progress}", config.host, config.qwp_ws_port);
        let mut sender = SenderBuilder::from_conf(&conf)?.build()?;
        let (frame_cap, told_by_server) = sender.effective_frame_cap()?;
        assert!(told_by_server, "the server told no frame limit");

        // The small flush creates the tables: `mix` is a number in each.
        let small_rows = [0, 1_000_000, 2_000_000].map(|id| rows_from(id, CREATING_ROWS));
        let mut small = Buffer::new_qwp_ws();
        for (table, rows) in tables.iter().zip(&small_rows) {
            for (id, text_len) in rows {
                push_row(&mut small, table, *id, *text_len, None)?;
            }
        }
        let bytes = (mib * 1024 * 1024).saturating_sub(ROW_ROOM);
        let (large, _) = buffer_over_three_tables(tables, bytes, true)?;
        // The frame that the server rejects is the one with the rows of the
        // second table: the only frame that holds more than one table.
        let (frame_count, rejected) = {
            let frames = frames_of_a_flush(&large, frame_cap);
            let blocks = |frame: &Vec<u8>| u16::from_le_bytes([frame[6], frame[7]]);
            let rejected = frames.iter().position(|frame| blocks(frame) > 1);
            (frames.len(), rejected.expect("a frame of several tables"))
        };
        assert!(
            rejected >= 1 && rejected + 1 < frame_count,
            "frame {rejected} of {frame_count}: use a larger buffer"
        );

        assert_eq!(sender.flush_and_keep_and_get_fsn(&small)?, Some(0));
        sender.wait(AckLevel::Ok, WAIT)?;
        let started = Instant::now();
        let flushed = sender.flush_and_keep_and_get_fsn(&large);
        let flush_took = started.elapsed();
        let (err, told_by) = match flushed {
            Ok(last) => {
                assert_eq!(last, Some(frame_count as u64));
                (sender.wait(AckLevel::Ok, WAIT).unwrap_err(), "wait")
            }
            Err(err) => {
                assert_eq!(mode, "background", "{}", err.msg());
                (err, "flush")
            }
        };
        let told_after = started.elapsed();
        assert_eq!(err.code(), ErrorCode::ServerRejection, "{}", err.msg());
        let rejection = err.qwp_ws_rejection().expect("what the server rejected");
        assert_eq!(rejection.category, QwpWsErrorCategory::SchemaMismatch);
        assert_eq!(rejection.applied_policy, QwpWsErrorPolicy::Terminal);
        // The small flush is frame 0 of the sender.
        let fsn = 1 + rejected as u64;
        assert_eq!((rejection.from_fsn, rejection.to_fsn), (fsn, fsn));
        assert!(sender.must_close());
        let closed = sender.close_drain().unwrap_err();
        assert_eq!(
            closed.code(),
            ErrorCode::ServerRejection,
            "{}",
            closed.msg()
        );

        let holds_the_small_flush = |when: &str| -> ProbeResult<()> {
            for (table, rows) in tables.iter().zip(&small_rows) {
                assert_eq!(
                    server.digest(table)?,
                    Some(Digest::of(rows)),
                    "{mode}, {when}"
                );
                assert_eq!(server.transactions(table)?, Some(1), "{mode}, {when}");
            }
            Ok(())
        };
        for table in tables {
            server.wait_for_rows(table, CREATING_ROWS)?;
        }
        holds_the_small_flush("after the rejection")?;
        drop(sender);
        std::thread::sleep(DROP_SETTLE);
        holds_the_small_flush("after the sender is gone")?;

        let (large, large_rows) = buffer_over_three_tables(tables, bytes, false)?;
        let mut sender = SenderBuilder::from_conf(&conf)?.build()?;
        sender.flush_and_keep(&large)?;
        sender.wait(AckLevel::Ok, WAIT)?;
        for ((table, small), large) in tables.iter().zip(&small_rows).zip(&large_rows) {
            let rows = [small.as_slice(), large.as_slice()].concat();
            server.wait_for_rows(table, rows.len())?;
            assert_eq!(server.digest(table)?, Some(Digest::of(&rows)), "{mode}");
            assert_eq!(server.transactions(table)?, Some(2), "{mode}");
        }
        eprintln!(
            "rejected flush, {mode}: {} bytes in the buffer, {frame_count} frames of at most \
             {frame_cap} bytes; the server rejected frame {rejected} of them; flush returned \
             after {flush_took:?} and {told_by} told of the rejection {told_after:?} after the \
             call began: {}",
            large.len(),
            err.msg()
        );
    }
    Ok(())
}

/// The rows of a table: per row its id and the length of its text.
type Rows = Vec<(i64, usize)>;

/// A buffer of about `bytes`: rows of the first table for its first half,
/// five rows of the second, and rows of the third. With
/// `text_for_a_number` the rows of the second table have a text in `mix`,
/// which is a number in the rows of the script. Returns the rows of each
/// table too.
fn buffer_over_three_tables(
    tables: [&String; 3],
    bytes: usize,
    text_for_a_number: bool,
) -> ProbeResult<(Buffer, [Rows; 3])> {
    let mut buffer = Buffer::new_qwp_ws();
    let mut rows = [Vec::new(), Vec::new(), Vec::new()];
    let mut id = 10_000_000;
    while buffer.len() < bytes / 2 {
        push_row(&mut buffer, tables[0], id, text_len_of(id), None)?;
        rows[0].push((id, text_len_of(id)));
        id += 1;
    }
    for _ in 0..5 {
        if text_for_a_number {
            push_row_with_a_text_for_a_number(&mut buffer, tables[1], id)?;
        } else {
            push_row(&mut buffer, tables[1], id, text_len_of(id), None)?;
        }
        rows[1].push((id, text_len_of(id)));
        id += 1;
    }
    while buffer.len() < bytes {
        push_row(&mut buffer, tables[2], id, text_len_of(id), None)?;
        rows[2].push((id, text_len_of(id)));
        id += 1;
    }
    Ok((buffer, rows))
}

/// The size of the queue that a sender asks for when it refuses a buffer
/// that its queue can never take.
fn queue_bytes_named_by(refusal: &crate::Error) -> ProbeResult<u64> {
    let text = refusal.msg();
    let named = text
        .split_once("Set sf_max_total_bytes to at least ")
        .and_then(|(_, rest)| rest.split_once(','))
        .map(|(bytes, _)| bytes)
        .ok_or_else(|| format!("no queue size in: {text}"))?;
    Ok(named.parse()?)
}

/// The server to test against and the size of the large buffer in MiB.
/// `None` when the probe is not switched on.
fn probe_settings() -> ProbeResult<Option<(ProbeConfig, usize)>> {
    if std::env::var("QDB_QWP_WS_LARGE_FLUSH_PROBE").as_deref() != Ok("1") {
        eprintln!("set QDB_QWP_WS_LARGE_FLUSH_PROBE=1 to run the real-server large flush probe");
        return Ok(None);
    }

    let config = ProbeConfig::from_env()?;
    if config.auth_header.is_some() {
        return Err(
            "QDB_QWP_WS_LARGE_FLUSH_PROBE does not support QDB_QWP_WS_AUTH_HEADER; use an \
             unauthenticated local QuestDB server"
                .into(),
        );
    }
    eprintln!("QuestDB build: {}", query_build(&config)?);
    let mib: usize = match std::env::var("QDB_QWP_WS_LARGE_FLUSH_PROBE_MIB") {
        Ok(value) => value.parse()?,
        Err(_) => DEFAULT_MIB,
    };
    Ok(Some((config, mib)))
}

/// A tag that no other row has, 48 bytes long.
fn own_tag_of(id: i64) -> Option<String> {
    Some(format!("tag-{id:044}"))
}

/// One flush and the wait for the server.
struct Flushed {
    /// The number of the last frame of the flush.
    fsn: u64,
    flush_took: Duration,
    /// From the start of the `flush` call until the server had confirmed.
    confirmed_after: Duration,
    /// The most memory the process had held by then, in MiB.
    resident_at_most: String,
}

/// Flushes `buffer`, which keeps its rows, and waits until the server has
/// confirmed the flush.
fn flush_and_wait(sender: &mut Sender, buffer: &Buffer) -> ProbeResult<Flushed> {
    let started = Instant::now();
    let fsn = sender.flush_and_keep_and_get_fsn(buffer)?;
    let flush_took = started.elapsed();
    sender.wait(AckLevel::Ok, WAIT)?;
    let confirmed_after = started.elapsed();
    let resident_at_most = resident_mib("VmHWM");
    assert_eq!(sender.completed_fsn(AckLevel::Ok)?, fsn);
    Ok(Flushed {
        fsn: fsn.expect("a flush of rows publishes frames"),
        flush_took,
        confirmed_after,
        resident_at_most,
    })
}

/// A size from `/proc/self/status` in MiB: `VmRSS`, what the process holds
/// in memory now, or `VmHWM`, the most it has held. `?` where there is no
/// such file.
fn resident_mib(field: &str) -> String {
    let kib = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            let line = status.lines().find_map(|line| line.strip_prefix(field))?;
            let kib = line.strip_prefix(':')?.trim().strip_suffix("kB")?;
            kib.trim().parse::<u64>().ok()
        });
    kib.map_or("?".to_string(), |kib| (kib / 1024).to_string())
}
