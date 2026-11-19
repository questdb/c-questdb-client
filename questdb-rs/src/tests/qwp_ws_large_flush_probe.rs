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
//! buffer and sends the frames. There are two tests:
//!
//! - a flush of one table without symbols into a table that the flush
//!   creates, so the time until the server confirms includes the time it
//!   takes to create one;
//! - a flush of two tables with symbols, one of them with more symbols than
//!   a frame holds, into tables that exist. The buffer is flushed twice:
//!   the first time its frames bring the symbols, the second time the
//!   connection knows them.
//!
//! Each test also prints how long a flush took and how much memory the
//! process held; the second one, how many frames its flushes took. For
//! these numbers run one test at a time, from a release build. This runs
//! both; the whole name of a test runs that one:
//!
//! `QDB_QWP_WS_LARGE_FLUSH_PROBE=1 QDB_QWP_WS_PORT=9000 cargo test --release --manifest-path questdb-rs/Cargo.toml --lib qwp_ws_real_server_large_flush -- --ignored --nocapture`
//!
//! `QDB_QWP_WS_LARGE_FLUSH_PROBE_MIB` is the size of the buffer in MiB: 20
//! when it is not set, and no more than 100, the most that a sender takes in
//! one flush (`max_buf_size`).

use std::time::{Duration, Instant};

use crate::ingress::{AckLevel, Buffer, Sender, SenderBuilder, SymbolGlobalDict};

use super::TestResult;
use super::qwp_ws_defer_probe::{
    Digest, Group, SERVER_MAX_UNCOMMITTED_ROWS, Server, TagOf, push_row, rows_from, tag_of,
    text_len_of,
};
use super::qwp_ws_protocol_probe::{ProbeConfig, ProbeResult, query_build};
use super::qwp_ws_server_model::frame_of_a_sender;

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
