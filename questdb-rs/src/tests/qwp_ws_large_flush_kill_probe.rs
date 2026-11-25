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

//! A client that is killed inside a flush far larger than a frame, or right
//! after it, with its queue on disk (`sf_dir`), against a real QuestDB
//! server: what the next sender on its slot delivers.
//!
//! The client is a process of its own: this test binary, started once more
//! to run [`qwp_ws_large_flush_client_that_is_killed`]. It builds a sender
//! with `sf_dir`, flushes a few rows that create the table, waits until the
//! server has confirmed them, and flushes the large buffer. The test kills
//! the process, so nothing of the client runs after that: no `close`, no
//! drop. The slot stays as the kill found it, and the test builds a sender
//! on it. There are two tests:
//!
//! - the kill comes inside the flush, when the slot holds frames of the
//!   flush and not the last one. The server drops the rows that it held
//!   with the connection. The new sender removes the frames of the flush
//!   from the slot and sends none of them, so the table has no row of the
//!   flush. The same buffer through the new sender is one transaction, and
//!   the table holds every row once;
//! - the kill comes after `flush` returned, when the slot holds the whole
//!   flush. The server may have committed the flush by then or not, and the
//!   slot may say that it did or not. The new sender sends the flush again
//!   unless the slot says that the server confirmed it. The table holds
//!   every row of the flush once or twice, and never a part of them.
//!
//! Each test kills a client several times for `sf_durability=memory` and as
//! often for `sf_durability=periodic`, each time at another point: inside
//! the flush after another number of segment files, after the flush with
//! another delay. Half of the kills inside the flush come as soon as a new
//! segment file shows, which is while the sender makes it: the next sender
//! then often finds a file that was never written, and removes it. Each
//! test prints what it found. This runs both; the whole name of a test runs
//! that one:
//!
//! `QDB_QWP_WS_LARGE_FLUSH_PROBE=1 QDB_QWP_WS_PORT=9000 cargo test --manifest-path questdb-rs/Cargo.toml --features almost-all-features --lib qwp_ws_real_server_client_killed -- --ignored --nocapture`
//!
//! `QDB_QWP_WS_LARGE_FLUSH_PROBE_MIB` is the size of the buffer in MiB, as
//! for the tests of `qwp_ws_large_flush_probe`. A kill has to come inside
//! the flush, which takes longer with a larger buffer: 100 is the size
//! these tests were run with. `QDB_QWP_WS_LARGE_FLUSH_PROBE_KILLS` is how
//! many clients a test kills for each durability setting: 3 when it is not
//! set. The slots are under the temporary folder of the system (`TMPDIR`).

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::ingress::{AckLevel, Buffer, SenderBuilder};

use super::TestResult;
use super::qwp_ws_defer_probe::{Digest, Group, Server, push_row, rows_from};
use super::qwp_ws_large_flush_probe::{
    CREATING_ROWS, DROP_SETTLE, ROW_ROOM, WAIT, flush_and_wait, probe_settings,
};
use super::qwp_ws_protocol_probe::ProbeResult;

/// How many clients a test kills for each durability setting.
const DEFAULT_KILLS: usize = 3;
/// The size of a segment file of a sender as its defaults make it.
const SEGMENT_BYTES: usize = 4 * 1024 * 1024;
/// The length of the header of a segment file.
const SEGMENT_HEADER_BYTES: usize = 24;
/// The slot of the client and of the sender that comes after it.
const SENDER_ID: &str = "killed";
/// The test that is the client. It does not run with the others: its name
/// has to be given whole.
const CLIENT_TEST: &str = "qwp_ws_large_flush_client_that_is_killed";
/// What the test tells the client: the settings of its sender, the table,
/// the size of the large buffer in MiB, and the folder where it tells how
/// far it is.
const CLIENT_CONF: &str = "QDB_QWP_WS_KILLED_CLIENT_CONF";
const CLIENT_TABLE: &str = "QDB_QWP_WS_KILLED_CLIENT_TABLE";
const CLIENT_MIB: &str = "QDB_QWP_WS_KILLED_CLIENT_MIB";
const CLIENT_SIGNALS: &str = "QDB_QWP_WS_KILLED_CLIENT_SIGNALS";
/// The file that the client makes right before it calls `flush` with the
/// large buffer, and the one it makes right after `flush` returned.
const FLUSHING: &str = "flushing";
const FLUSHED: &str = "flushed";

/// When the kill comes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kill {
    /// While `flush` writes the frames of the large buffer to the slot.
    InsideTheFlush,
    /// When `flush` has returned.
    AfterTheFlush,
}

#[test]
#[ignore = "requires a real QuestDB server and QDB_QWP_WS_LARGE_FLUSH_PROBE=1"]
fn qwp_ws_real_server_client_killed_inside_a_large_flush_leaves_none_of_its_rows() -> TestResult {
    kill_clients(Kill::InsideTheFlush)
}

#[test]
#[ignore = "requires a real QuestDB server and QDB_QWP_WS_LARGE_FLUSH_PROBE=1"]
fn qwp_ws_real_server_client_killed_after_a_large_flush_leaves_it_whole() -> TestResult {
    kill_clients(Kill::AfterTheFlush)
}

/// The client. It runs only when a test of this file started it.
#[test]
#[ignore = "started by the tests that kill a client"]
fn qwp_ws_large_flush_client_that_is_killed() -> TestResult {
    let Ok(conf) = std::env::var(CLIENT_CONF) else {
        return Ok(());
    };
    let table = std::env::var(CLIENT_TABLE)?;
    let mib: usize = std::env::var(CLIENT_MIB)?.parse()?;
    let signals = PathBuf::from(std::env::var(CLIENT_SIGNALS)?);

    let mut sender = SenderBuilder::from_conf(conf)?.build()?;
    sender.flush_and_keep(&creating_buffer(&table)?)?;
    sender.wait(AckLevel::Ok, WAIT)?;
    // Filling the buffer takes far longer than the slot needs to note what
    // the server confirmed.
    let mut large = large_group(&table, mib)?.buffer;
    std::fs::write(signals.join(FLUSHING), [])?;
    sender.flush(&mut large)?;
    std::fs::write(signals.join(FLUSHED), [])?;
    // The kill comes here at the latest.
    std::thread::sleep(WAIT);
    Err("nobody killed the client".into())
}

/// What a test found after one kill.
struct Found {
    /// How many segment files the slot held when the client was gone.
    segment_files: usize,
    /// Whether one of them was a file that the client had not finished
    /// making.
    never_written: bool,
    /// How many frames the new sender found in the slot that the server had
    /// not confirmed, as far as the slot knew.
    unconfirmed_frames: u64,
    /// How often the table holds the rows of the flush of the client.
    times: usize,
}

fn kill_clients(kill: Kill) -> TestResult {
    let Some((config, mib)) = probe_settings()? else {
        return Ok(());
    };
    let kills: usize = match std::env::var("QDB_QWP_WS_LARGE_FLUSH_PROBE_KILLS") {
        Ok(value) => value.parse()?,
        Err(_) => DEFAULT_KILLS,
    };
    let server = Server::Live(&config);
    for durability in ["memory", "periodic"] {
        let mut found = Vec::new();
        for run in 0..kills {
            found.push(kill_a_client(&server, mib, durability, kill, run)?);
        }
        let files: Vec<usize> = found.iter().map(|found| found.segment_files).collect();
        let never_written = found.iter().filter(|found| found.never_written).count();
        match kill {
            Kill::InsideTheFlush => eprintln!(
                "sf_durability={durability}: {kills} clients killed inside a flush of {mib} MiB, \
                 with these numbers of segment files in the slot: {files:?}; {never_written} of \
                 the slots held a segment file that was never written. No row of the flush \
                 reached the table, and the same buffer through the next sender on the slot \
                 was one transaction"
            ),
            Kill::AfterTheFlush => {
                let count = |times: usize, sent_again: bool| {
                    let matches = |found: &&Found| {
                        found.times == times && (found.unconfirmed_frames > 0) == sent_again
                    };
                    found.iter().filter(matches).count()
                };
                eprintln!(
                    "sf_durability={durability}: {kills} clients killed after a flush of {mib} \
                     MiB returned. The server had confirmed the flush to {} of them, and the \
                     next sender on the slot sent nothing. It sent the flush again for the \
                     others: {} times the table then held its rows once, {} times twice",
                    count(1, false),
                    count(1, true),
                    count(2, true)
                );
            }
        }
    }
    Ok(())
}

/// Starts a client, kills it, and builds a sender on its slot.
fn kill_a_client(
    server: &Server<'_>,
    mib: usize,
    durability: &str,
    kill: Kill,
    run: usize,
) -> ProbeResult<Found> {
    let Server::Live(config) = server else {
        return Err("a client process needs a real server".into());
    };
    let (table, _cleanup) = server.new_table(&format!("qwp_large_flush_killed_{run}"));
    let sf_dir = tempfile::TempDir::new()?;
    let slot = sf_dir.path().join(SENDER_ID);
    let signals = tempfile::TempDir::new()?;
    let conf = format!(
        "ws::addr={}:{};sf_dir={};sender_id={SENDER_ID};sf_durability={durability};",
        config.host,
        config.qwp_ws_port,
        sf_dir.path().display()
    );
    // What the client flushes, built here too: the rows that create the
    // table, and the large buffer.
    let creating = rows_from(0, CREATING_ROWS);
    let large = large_group(&table, mib)?;
    let (rows, len) = (large.buffer.row_count(), large.buffer.len());
    let whole = rows_from(0, CREATING_ROWS + rows);
    // The frames of the flush fill about this many segment files.
    let segments = len / SEGMENT_BYTES;
    assert!(segments >= 4, "a buffer of {len} bytes: use a larger one");

    let mut client = Client::start(&conf, &table, mib, signals.path())?;
    let flushed = signals.path().join(FLUSHED);
    match kill {
        Kill::InsideTheFlush => {
            // A sender makes a segment file before it needs it. The file
            // that is one too many for the first frames of the flush shows
            // that the flush is under way; each run waits for another
            // number of files, up to those of half the flush.
            let files = 3 + run % (segments / 2);
            client.wait_until("its slot held the first frames of the flush", || {
                segment_files(&slot) >= files
            })?;
            // A file shows while the sender makes it, right after the
            // flush took a new segment. Every second kill comes at once
            // and may find that file without its header yet, next to a
            // segment in use without a frame. The others come up to 10 ms
            // later, at another step of the work of the sender.
            if run % 2 == 1 {
                std::thread::sleep(Duration::from_micros(run as u64 * 7_919 % 10_000));
            }
        }
        Kill::AfterTheFlush => {
            client.wait_until("its flush returned", || flushed.exists())?;
            // The server confirms such a flush some milliseconds after
            // `flush` returned. Each run gives it another time for that.
            std::thread::sleep(Duration::from_millis(run as u64 % 6 * 4));
        }
    }
    let returned_before_the_kill = flushed.exists();
    client.kill()?;
    let segment_files_found = segment_files(&slot);
    let never_written = holds_a_segment_file_that_was_never_written(&slot);
    if kill == Kill::InsideTheFlush {
        assert!(
            !returned_before_the_kill,
            "the flush returned before the kill came: use a larger buffer"
        );
        // The server drops the rows that it held when the connection ends.
        server.wait_for_the_drop(DROP_SETTLE);
        assert_eq!(server.digest(&table)?, Some(Digest::of(&creating)));
        assert_eq!(server.transactions(&table)?, Some(1));
    }

    // A new sender on the slot. Opening the slot removes a segment file
    // that was never written, and a flush that has no last frame. The
    // sender then sends what the slot holds that the server did not
    // confirm, as far as the slot knows.
    let mut sender = SenderBuilder::from_conf(&conf)?.build()?;
    let in_the_slot = sender.published_fsn()?;
    let confirmed_in_the_slot = sender.completed_fsn(AckLevel::Ok)?;
    let unconfirmed_frames = match (in_the_slot, confirmed_in_the_slot) {
        (Some(last), Some(confirmed)) => last - confirmed,
        (Some(last), None) => last + 1,
        (None, _) => 0,
    };
    if kill == Kill::InsideTheFlush {
        // The frame that created the table is the only one in the slot,
        // and the server had confirmed it.
        assert_eq!(
            (in_the_slot, unconfirmed_frames),
            (Some(0), 0),
            "the slot holds frames of the flush that the kill stopped, {segment_files_found} \
             segment files: the flush was whole when the kill came (use a larger buffer), or \
             opening the slot did not remove its frames"
        );
    }
    sender.wait(AckLevel::Ok, WAIT)?;
    let totals = sender.qwp_ws_totals()?;
    assert_eq!(
        (totals.frames_sent, totals.server_errors),
        (unconfirmed_frames, 0),
        "{totals:?}"
    );

    let times = match kill {
        Kill::InsideTheFlush => {
            // Nothing was sent, and the table is as it was.
            assert_eq!(server.digest(&table)?, Some(Digest::of(&creating)));
            assert_eq!(server.transactions(&table)?, Some(1));

            // The same buffer through the new sender: one transaction more,
            // and the table holds every row once.
            let again = flush_and_wait(&mut sender, &large.buffer)?;
            assert_eq!(
                sender.qwp_ws_totals()?.frames_sent,
                again.fsn,
                "the frames of the buffer, and no other"
            );
            server.wait_for_rows(&table, whole.len())?;
            assert_eq!(server.digest(&table)?, Some(Digest::of(&whole)));
            assert_eq!(server.transactions(&table)?, Some(2));
            0
        }
        Kill::AfterTheFlush => {
            assert!(returned_before_the_kill);
            // The slot holds the whole flush after the frame that created
            // the table.
            let last = in_the_slot.expect("a slot with the frames of the flush");
            assert!(
                last as usize >= len.div_ceil(SEGMENT_BYTES),
                "{last} frames for {len} bytes"
            );
            assert!(
                unconfirmed_frames == 0 || unconfirmed_frames == last,
                "the server confirms a flush with its last frame: {unconfirmed_frames} of \
                 {last} frames are not confirmed"
            );
            // A transaction for each time the server got the last frame of
            // the flush, after the one that created the table.
            let transactions = server.transactions(&table)?;
            let times = match transactions {
                Some(2) => 1,
                Some(3) if unconfirmed_frames > 0 => 2,
                _ => panic!(
                    "{transactions:?} transactions, and the new sender sent \
                     {unconfirmed_frames} frames"
                ),
            };
            let mut held = whole.clone();
            if times == 2 {
                held.extend(rows_from(CREATING_ROWS as i64, rows));
            }
            server.wait_for_rows(&table, held.len())?;
            assert_eq!(server.digest(&table)?, Some(Digest::of(&held)));
            assert_eq!(server.transactions(&table)?, transactions);
            times
        }
    };

    // The slot is empty when the sender is closed.
    sender.close_drain()?;
    drop(sender);
    assert_eq!(segment_files(&slot), 0);
    Ok(Found {
        segment_files: segment_files_found,
        never_written,
        unconfirmed_frames,
        times,
    })
}

/// The rows that create the table.
fn creating_buffer(table: &str) -> ProbeResult<Buffer> {
    let mut buffer = Buffer::new_qwp_ws();
    for (id, text_len) in rows_from(0, CREATING_ROWS) {
        push_row(&mut buffer, table, id, text_len, None)?;
    }
    Ok(buffer)
}

/// The rows of the large flush, which follow those that create the table.
fn large_group(table: &str, mib: usize) -> ProbeResult<Group> {
    let bytes = (mib * 1024 * 1024).saturating_sub(ROW_ROOM);
    Group::of_bytes(table, CREATING_ROWS as i64, bytes)
}

/// How many segment files a slot holds.
fn segment_files(slot: &Path) -> usize {
    std::fs::read_dir(slot).map_or(0, |entries| {
        entries
            .flatten()
            .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "sfa"))
            .count()
    })
}

/// Whether a slot holds a segment file whose sender had not finished making
/// it: one that is shorter than the header of a segment, or has zeroes
/// where that header belongs.
fn holds_a_segment_file_that_was_never_written(slot: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(slot) else {
        return false;
    };
    entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "sfa"))
        .any(|path| {
            let mut header = [0u8; SEGMENT_HEADER_BYTES];
            let read = std::fs::File::open(path)
                .and_then(|mut file| file.read_exact(&mut header))
                .is_ok();
            !read || header == [0u8; SEGMENT_HEADER_BYTES]
        })
}

/// The process of a client.
struct Client(Child);

impl Client {
    /// Starts this test binary once more, to run the test that is the
    /// client.
    fn start(conf: &str, table: &str, mib: usize, signals: &Path) -> ProbeResult<Self> {
        // The name of a test as the test binary knows it: the path of its
        // module without the name of the crate.
        let module = module_path!()
            .split_once("::")
            .map_or("", |(_, module)| module);
        let child = Command::new(std::env::current_exe()?)
            .arg(format!("{module}::{CLIENT_TEST}"))
            .args(["--exact", "--ignored", "--nocapture"])
            .env(CLIENT_CONF, conf)
            .env(CLIENT_TABLE, table)
            .env(CLIENT_MIB, mib.to_string())
            .env(CLIENT_SIGNALS, signals)
            .stdout(Stdio::null())
            .spawn()?;
        Ok(Self(child))
    }

    /// Waits until `reached` is true, which the client brings about.
    fn wait_until(&mut self, what: &str, reached: impl Fn() -> bool) -> ProbeResult<()> {
        let deadline = Instant::now() + 2 * WAIT;
        while !reached() {
            if let Some(status) = self.0.try_wait()? {
                return Err(format!("the client ended by itself before {what}: {status}").into());
            }
            if Instant::now() > deadline {
                return Err(format!("the client ran for {:?} before {what}", 2 * WAIT).into());
            }
            std::thread::sleep(Duration::from_micros(100));
        }
        Ok(())
    }

    /// Kills the process, and returns when it is gone.
    fn kill(&mut self) -> ProbeResult<()> {
        self.0.kill()?;
        self.0.wait()?;
        Ok(())
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.kill();
    }
}
