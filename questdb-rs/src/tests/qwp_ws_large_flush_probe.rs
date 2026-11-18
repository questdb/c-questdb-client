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
//! flush as one transaction that holds exactly the rows.
//!
//! The rows and the checks of the table are those of `qwp_ws_defer_probe`,
//! which writes such frames to a raw WebSocket. Here the sender cuts the
//! buffer and sends the frames.
//!
//! The test also prints how long the flush took and how much memory the
//! process held. The table is new, so the time until the server confirms
//! includes the time it takes to create one. Run the test alone and from a
//! release build for these numbers:
//!
//! `QDB_QWP_WS_LARGE_FLUSH_PROBE=1 QDB_QWP_WS_PORT=9000 cargo test --release --manifest-path questdb-rs/Cargo.toml --lib qwp_ws_real_server_large_flush -- --ignored --nocapture`
//!
//! `QDB_QWP_WS_LARGE_FLUSH_PROBE_MIB` is the size of the buffer in MiB: 20
//! when it is not set, and no more than 100, the most that a sender takes in
//! one flush (`max_buf_size`).

use std::time::{Duration, Instant};

use crate::ingress::{AckLevel, SenderBuilder};

use super::TestResult;
use super::qwp_ws_defer_probe::{Group, Server};
use super::qwp_ws_protocol_probe::{ProbeConfig, query_build};

/// More than 16 MiB, the largest message the protocol has.
const DEFAULT_MIB: usize = 20;
/// A row of the group takes less than this in a buffer.
const ROW_ROOM: usize = 256;
/// How long the server may stay silent before the flush counts as lost. It
/// answers a flush once, at the end.
const WAIT: Duration = Duration::from_secs(30);

#[test]
#[ignore = "requires a real QuestDB server and QDB_QWP_WS_LARGE_FLUSH_PROBE=1"]
fn qwp_ws_real_server_large_flush_is_one_transaction() -> TestResult {
    if std::env::var("QDB_QWP_WS_LARGE_FLUSH_PROBE").as_deref() != Ok("1") {
        eprintln!("set QDB_QWP_WS_LARGE_FLUSH_PROBE=1 to run the real-server large flush probe");
        return Ok(());
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
