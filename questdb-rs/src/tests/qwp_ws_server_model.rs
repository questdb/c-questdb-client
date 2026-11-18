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

//! A model of what a QuestDB server does with the QWP/WebSocket frames of a
//! connection, for tests that must know what a server would hold after the
//! frames they sent: which rows, in how many commits.
//!
//! Its rules are the ones a real server showed to the script of
//! `qwp_ws_defer_probe`, which runs against this model too:
//!
//! - A frame with the defer flag gets no answer. Its rows are held for the
//!   connection, uncommitted.
//! - A frame without the flag commits what the connection holds, the frame's
//!   own rows included, as one commit per table. Its answer is one OK with
//!   the frame's sequence, which names each table it committed with the
//!   number of that table's commit. Sequences count the frames of a
//!   connection from zero, commits those of a table from one.
//! - A connection that goes away loses the rows it holds.
//! - A table exists from the first frame that names it, committed or not.
//!
//! The script sends one table per connection. That a frame without the flag
//! commits every table the connection holds rows for is read from the
//! server's code, not yet seen on a real server.
//!
//! What the model cannot do it refuses with a panic, so that no test passes
//! on behaviour the model made up: a frame that is not a QWP message, a flag
//! it does not know, symbols, several table blocks in one frame, a frame
//! above the frame limit, and the commit a server forces on a table that
//! holds 1,000,000 uncommitted rows (`qwp.max.uncommitted.rows`).
//!
//! Two things a server does are neither modelled nor refused. A server
//! rejects a frame whose column types disagree with the table; the model
//! takes any columns. And a server may commit frames without the flag
//! together, as one transaction, when they arrive in one read; the model
//! commits each on its own. So a test may count on one commit for a group,
//! never on one commit per frame without the flag.

use std::collections::BTreeMap;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use crate::ingress::{Buffer, QwpWsEncodeScratch, SymbolGlobalDict, decode_qwp_varint};
use crate::tests::qwp_decode::{DecodedTable, decode_ws_table_block};
use crate::tests::qwp_ws::{
    read_frame, upgrade_mock_stream_with_max_batch_size, write_server_binary_frame,
    write_server_frame,
};

const QWP_HEADER_SIZE: usize = 12;
const QWP_VERSION: u8 = 1;
const QWP_FLAGS_OFFSET: usize = 5;
const QWP_FLAG_DEFER_COMMIT: u8 = 0x01;
const QWP_FLAG_DELTA_SYMBOL_DICT: u8 = 0x08;
const QWP_STATUS_OK: u8 = 0x00;
/// The server's default `qwp.max.uncommitted.rows`.
const MAX_UNCOMMITTED_ROWS: usize = 1_000_000;

const WS_OPCODE_BINARY: u8 = 0x2;
const WS_OPCODE_CLOSE: u8 = 0x8;
const WS_OPCODE_PING: u8 = 0x9;
const WS_OPCODE_PONG: u8 = 0xA;

/// The frames of one flush of `buffer`, cut for frames of `target` bytes:
/// every frame but the last has the defer flag. The connection has no symbols.
pub(crate) fn frames_of_a_flush(buffer: &Buffer, target: usize) -> Vec<Vec<u8>> {
    let rows = buffer.as_qwp_ws().expect("a QWP/WebSocket buffer");
    let plan = rows
        .plan_frames(target, target)
        .expect("a buffer the planner can cut");
    let frame_count = plan.frames().count();
    let mut scratch = QwpWsEncodeScratch::new();
    let no_symbols = SymbolGlobalDict::new();
    plan.frames()
        .enumerate()
        .map(|(frame_idx, blocks)| {
            let mut frame = Vec::new();
            rows.encode_ws_frame(
                blocks,
                &mut frame,
                &mut scratch,
                &no_symbols,
                QWP_VERSION,
                frame_idx + 1 < frame_count,
            )
            .unwrap();
            frame
        })
        .collect()
}

/// What the server holds of one table.
#[derive(Clone, Debug, Default)]
pub(crate) struct ModelTable {
    /// How many commits brought rows to the table.
    pub(crate) commits: u64,
    /// The committed table blocks, in the order they arrived.
    pub(crate) blocks: Vec<DecodedTable>,
}

impl ModelTable {
    pub(crate) fn row_count(&self) -> usize {
        self.blocks.iter().map(|block| block.rows.len()).sum()
    }

    /// The committed rows, in the order they arrived. As text, because a
    /// float column that a row left out decodes to NaN, which is not equal to
    /// itself.
    pub(crate) fn rows_as_text(&self) -> Vec<String> {
        self.blocks
            .iter()
            .flat_map(|block| &block.rows)
            .map(|row| format!("{row:?}"))
            .collect()
    }
}

/// The committed state of a server. A clone is a handle on the same server.
#[derive(Clone, Default)]
pub(crate) struct QwpWsServerModel {
    tables: Arc<Mutex<BTreeMap<String, ModelTable>>>,
}

impl QwpWsServerModel {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// A new connection. It holds no rows, and its first frame has sequence 0.
    pub(crate) fn connect(&self) -> QwpWsModelConnection {
        QwpWsModelConnection {
            server: self.clone(),
            next_sequence: 0,
            held: BTreeMap::new(),
        }
    }

    /// What is committed of a table. `None` when no frame has named it.
    pub(crate) fn table(&self, name: &str) -> Option<ModelTable> {
        self.tables.lock().unwrap().get(name).cloned()
    }
}

/// One connection to the server. Dropping it is a disconnect: the rows it
/// holds are gone.
pub(crate) struct QwpWsModelConnection {
    server: QwpWsServerModel,
    next_sequence: u64,
    /// Per table, the blocks that wait for a frame without the defer flag.
    held: BTreeMap<String, Vec<DecodedTable>>,
}

impl QwpWsModelConnection {
    /// Takes the next message of the client. Returns the answer of the
    /// server, if it gives one.
    pub(crate) fn receive(&mut self, message: &[u8]) -> Option<Vec<u8>> {
        let sequence = self.next_sequence;
        self.next_sequence += 1;

        assert!(
            message.len() >= QWP_HEADER_SIZE
                && message[..4] == *b"QWP1"
                && message[4] == QWP_VERSION
                && u32::from_le_bytes(message[8..12].try_into().unwrap()) as usize
                    == message.len() - QWP_HEADER_SIZE,
            "frame {sequence} is not a QWP message of version {QWP_VERSION} that states its length"
        );
        let flags = message[QWP_FLAGS_OFFSET];
        let defer_commit = flags & QWP_FLAG_DEFER_COMMIT != 0;
        assert_eq!(
            flags & !QWP_FLAG_DEFER_COMMIT,
            QWP_FLAG_DELTA_SYMBOL_DICT,
            "frame {sequence}: the server model reads frames with the delta dictionary flag, \
             with or without the defer flag"
        );
        assert_eq!(
            u16::from_le_bytes([message[6], message[7]]),
            1,
            "frame {sequence}: the server model reads frames of one table block"
        );
        let (dict_start, pos) = decode_qwp_varint(message, QWP_HEADER_SIZE).unwrap();
        let (dict_count, pos) = decode_qwp_varint(message, pos).unwrap();
        assert_eq!(
            (dict_start, dict_count),
            (0, 0),
            "frame {sequence}: the server model holds no symbols"
        );

        let block = decode_ws_table_block(&message[pos..]);
        let name = block.name.clone();
        let held = self.held.entry(name.clone()).or_default();
        held.push(block);
        let held_rows: usize = held.iter().map(|block| block.rows.len()).sum();
        assert!(
            held_rows < MAX_UNCOMMITTED_ROWS,
            "frame {sequence}: a server commits a table by itself once it holds \
             {MAX_UNCOMMITTED_ROWS} uncommitted rows, which the server model does not do"
        );

        let mut tables = self.server.tables.lock().unwrap();
        tables.entry(name).or_default();
        if defer_commit {
            return None;
        }
        // An OK: the status, the sequence, then each committed table with
        // the number of its commit.
        let held = std::mem::take(&mut self.held);
        let mut ok = vec![QWP_STATUS_OK];
        ok.extend_from_slice(&sequence.to_le_bytes());
        ok.extend_from_slice(&(held.len() as u16).to_le_bytes());
        for (name, blocks) in held {
            let table = tables.get_mut(&name).unwrap();
            table.commits += 1;
            table.blocks.extend(blocks);
            ok.extend_from_slice(&(name.len() as u16).to_le_bytes());
            ok.extend_from_slice(name.as_bytes());
            ok.extend_from_slice(&(table.commits as i64).to_le_bytes());
        }
        Some(ok)
    }
}

/// A socket server that takes QWP/WebSocket connections and answers each as
/// the model says. Its upgrade answer advertises `max_batch_size` as the
/// frame limit.
pub(crate) struct QwpWsModelServer {
    pub(crate) port: u16,
    pub(crate) model: QwpWsServerModel,
    shared: Arc<ServerShared>,
    acceptor: Option<thread::JoinHandle<()>>,
}

struct ServerShared {
    stop: AtomicBool,
    /// The connections the server has taken and not yet seen the end of.
    open: AtomicUsize,
    /// Every connection taken so far, to end them when the server stops.
    streams: Mutex<Vec<TcpStream>>,
}

impl QwpWsModelServer {
    pub(crate) fn start(max_batch_size: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let model = QwpWsServerModel::new();
        let shared = Arc::new(ServerShared {
            stop: AtomicBool::new(false),
            open: AtomicUsize::new(0),
            streams: Mutex::new(Vec::new()),
        });

        let acceptor = thread::spawn({
            let model = model.clone();
            let shared = Arc::clone(&shared);
            move || {
                let mut connections = Vec::new();
                loop {
                    let (stream, _) = listener.accept().unwrap();
                    {
                        let mut streams = shared.streams.lock().unwrap();
                        if shared.stop.load(Ordering::SeqCst) {
                            break;
                        }
                        streams.push(stream.try_clone().unwrap());
                    }
                    let connection = model.connect();
                    shared.open.fetch_add(1, Ordering::SeqCst);
                    let open = OpenConnection(Arc::clone(&shared));
                    connections.push(thread::spawn(move || {
                        // Dropped last: the connection and its rows are gone.
                        let _open = open;
                        serve_connection(stream, connection, max_batch_size);
                    }));
                }
                // What stopped a connection stops the server.
                for connection in connections {
                    if let Err(panic) = connection.join() {
                        std::panic::resume_unwind(panic);
                    }
                }
            }
        });

        Self {
            port,
            model,
            shared,
            acceptor: Some(acceptor),
        }
    }

    /// How many connections the server has taken and not yet seen the end
    /// of. A connection that has ended has lost the rows it held.
    pub(crate) fn open_connections(&self) -> usize {
        self.shared.open.load(Ordering::SeqCst)
    }

    /// Stops the server. Panics if the model refused a frame of one of the
    /// connections.
    pub(crate) fn finish(mut self) {
        if let Err(panic) = self.stop().join() {
            std::panic::resume_unwind(panic);
        }
    }

    fn stop(&mut self) -> thread::JoinHandle<()> {
        {
            let streams = self.shared.streams.lock().unwrap();
            self.shared.stop.store(true, Ordering::SeqCst);
            for stream in streams.iter() {
                let _ = stream.shutdown(Shutdown::Both);
            }
        }
        // Wakes the thread that waits for the next connection.
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        self.acceptor.take().unwrap()
    }
}

impl Drop for QwpWsModelServer {
    fn drop(&mut self) {
        // A test that fails before `finish` still ends the threads.
        if self.acceptor.is_some() {
            let _ = self.stop().join();
        }
    }
}

/// Counts a connection as ended when its thread is done with it, also by a
/// panic.
struct OpenConnection(Arc<ServerShared>);

impl Drop for OpenConnection {
    fn drop(&mut self) {
        self.0.open.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Closes the socket when the connection ends, also by a panic: the server
/// holds a second handle on it, which would keep it open.
struct CloseOnDrop(TcpStream);

impl Drop for CloseOnDrop {
    fn drop(&mut self) {
        let _ = self.0.shutdown(Shutdown::Both);
    }
}

fn serve_connection(
    mut stream: TcpStream,
    mut connection: QwpWsModelConnection,
    max_batch_size: usize,
) {
    let _close = CloseOnDrop(stream.try_clone().unwrap());
    upgrade_mock_stream_with_max_batch_size(&mut stream, Some(max_batch_size));
    // A read fails when the client went away or the server stops.
    while let Ok((fin, opcode, payload)) = read_frame(&mut stream) {
        let answered = match opcode {
            WS_OPCODE_BINARY => {
                assert!(fin, "the server model takes whole messages");
                assert!(
                    payload.len() <= max_batch_size,
                    "a frame of {} bytes is above the frame limit of {max_batch_size}: \
                     a server closes the connection, which the server model does not do",
                    payload.len()
                );
                match connection.receive(&payload) {
                    Some(answer) => write_server_binary_frame(&mut stream, &answer),
                    None => Ok(()),
                }
            }
            WS_OPCODE_PING => write_server_frame(&mut stream, WS_OPCODE_PONG, &payload, false),
            WS_OPCODE_PONG => Ok(()),
            WS_OPCODE_CLOSE => break,
            other => panic!("the server model does not take WebSocket opcode {other:#x}"),
        };
        if answered.is_err() {
            // The client went away before it read the answer.
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;
    use crate::ingress::TimestampNanos;

    const TABLE: &str = "model_rows";

    /// Rows `ids` of a table without symbols, a few dozen bytes each.
    fn buffer_of(table: &str, ids: std::ops::Range<i64>) -> Buffer {
        let mut buffer = Buffer::new_qwp_ws();
        for id in ids {
            buffer
                .table(table)
                .unwrap()
                .column_i64("id", id)
                .unwrap()
                .column_str("txt", format!("row {id}"))
                .unwrap()
                .at(TimestampNanos::new(1_700_000_000_000_000_000 + id))
                .unwrap();
        }
        buffer
    }

    /// The rows a server holds when `buffer` reaches it as a single frame.
    fn rows_of(table: &str, buffer: &Buffer) -> Vec<String> {
        let server = QwpWsServerModel::new();
        let frames = frames_of_a_flush(buffer, usize::MAX);
        assert_eq!(frames.len(), 1);
        assert!(server.connect().receive(&frames[0]).is_some());
        server.table(table).unwrap().rows_as_text()
    }

    /// The OK of frame `sequence`, which committed `tables`: each with the
    /// number of its commit.
    fn ok(sequence: usize, tables: &[(&str, i64)]) -> Option<Vec<u8>> {
        let mut ok = vec![QWP_STATUS_OK];
        ok.extend_from_slice(&(sequence as u64).to_le_bytes());
        ok.extend_from_slice(&(tables.len() as u16).to_le_bytes());
        for (name, commit) in tables {
            ok.extend_from_slice(&(name.len() as u16).to_le_bytes());
            ok.extend_from_slice(name.as_bytes());
            ok.extend_from_slice(&commit.to_le_bytes());
        }
        Some(ok)
    }

    /// The frames of a flush cut small: several of them, all but the last
    /// with the defer flag.
    fn small_frames(buffer: &Buffer) -> Vec<Vec<u8>> {
        let frames = frames_of_a_flush(buffer, 256);
        assert!(frames.len() > 3, "{} frames", frames.len());
        let (last, deferred) = frames.split_last().unwrap();
        assert!(
            deferred
                .iter()
                .all(|frame| frame[QWP_FLAGS_OFFSET] & QWP_FLAG_DEFER_COMMIT != 0)
        );
        assert_eq!(last[QWP_FLAGS_OFFSET] & QWP_FLAG_DEFER_COMMIT, 0);
        frames
    }

    #[test]
    fn server_model_holds_deferred_rows_until_a_frame_without_the_flag() {
        let buffer = buffer_of(TABLE, 0..40);
        let frames = small_frames(&buffer);
        let last = frames.len() - 1;
        let server = QwpWsServerModel::new();
        assert!(server.table(TABLE).is_none());

        let mut connection = server.connect();
        for frame in &frames[..last] {
            assert_eq!(connection.receive(frame), None);
            // The table is there from its first frame, without rows.
            let table = server.table(TABLE).unwrap();
            assert_eq!((table.commits, table.row_count()), (0, 0));
        }
        assert_eq!(connection.receive(&frames[last]), ok(last, &[(TABLE, 1)]));

        let table = server.table(TABLE).unwrap();
        assert_eq!(table.commits, 1);
        assert_eq!(table.row_count(), 40);
        assert_eq!(table.rows_as_text(), rows_of(TABLE, &buffer));

        // The next group of the connection: the sequences go on, the rows
        // are added, and it is one more commit.
        let more = buffer_of(TABLE, 40..70);
        let frames = small_frames(&more);
        let (commit_frame, deferred) = frames.split_last().unwrap();
        for frame in deferred {
            assert_eq!(connection.receive(frame), None);
        }
        assert_eq!(
            connection.receive(commit_frame),
            ok(last + frames.len(), &[(TABLE, 2)])
        );
        let table = server.table(TABLE).unwrap();
        assert_eq!(table.commits, 2);
        assert_eq!(
            table.rows_as_text(),
            rows_of(TABLE, &buffer_of(TABLE, 0..70))
        );
    }

    #[test]
    fn server_model_commits_at_every_frame_without_the_flag() {
        let buffer = buffer_of(TABLE, 0..40);
        let mut frames = small_frames(&buffer);
        let server = QwpWsServerModel::new();
        let mut connection = server.connect();
        for (sequence, frame) in frames.iter_mut().enumerate() {
            frame[QWP_FLAGS_OFFSET] &= !QWP_FLAG_DEFER_COMMIT;
            let commit = sequence as i64 + 1;
            assert_eq!(connection.receive(frame), ok(sequence, &[(TABLE, commit)]));
            assert_eq!(server.table(TABLE).unwrap().commits, commit as u64);
        }
        assert_eq!(
            server.table(TABLE).unwrap().rows_as_text(),
            rows_of(TABLE, &buffer)
        );
    }

    #[test]
    fn server_model_drops_the_held_rows_of_a_connection_that_goes_away() {
        let lost = buffer_of(TABLE, 0..40);
        let kept = buffer_of(TABLE, 100..140);
        let server = QwpWsServerModel::new();

        let mut first = server.connect();
        let frames = small_frames(&lost);
        for frame in &frames[..frames.len() - 1] {
            assert_eq!(first.receive(frame), None);
        }

        // A second connection commits its own rows, not the ones the first
        // one holds, and its sequences start at zero.
        let mut second = server.connect();
        let frames = small_frames(&kept);
        let last = frames.len() - 1;
        for frame in &frames[..last] {
            assert_eq!(second.receive(frame), None);
        }
        assert_eq!(second.receive(&frames[last]), ok(last, &[(TABLE, 1)]));
        let table = server.table(TABLE).unwrap();
        assert_eq!(table.commits, 1);
        assert_eq!(table.rows_as_text(), rows_of(TABLE, &kept));

        drop(first);
        let table = server.table(TABLE).unwrap();
        assert_eq!(table.commits, 1);
        assert_eq!(table.rows_as_text(), rows_of(TABLE, &kept));
    }

    #[test]
    fn server_model_commits_every_table_a_connection_holds_rows_for() {
        let one = buffer_of("model_one", 0..40);
        let two = buffer_of("model_two", 0..3);
        let server = QwpWsServerModel::new();
        let mut connection = server.connect();
        let frames = small_frames(&one);
        for frame in &frames[..frames.len() - 1] {
            assert_eq!(connection.receive(frame), None);
        }
        // The commit frame is of another table: both are committed.
        let commit_frame = frames_of_a_flush(&two, usize::MAX).remove(0);
        assert_eq!(
            connection.receive(&commit_frame),
            ok(frames.len() - 1, &[("model_one", 1), ("model_two", 1)])
        );

        let table = server.table("model_one").unwrap();
        assert_eq!(table.commits, 1);
        let all_but_last_frame = table.row_count();
        assert!(all_but_last_frame > 30 && all_but_last_frame < 40);
        assert_eq!(
            table.rows_as_text(),
            rows_of("model_one", &one)[..all_but_last_frame]
        );
        let table = server.table("model_two").unwrap();
        assert_eq!(table.commits, 1);
        assert_eq!(table.rows_as_text(), rows_of("model_two", &two));
    }

    fn one_frame() -> Vec<u8> {
        frames_of_a_flush(&buffer_of(TABLE, 0..3), usize::MAX).remove(0)
    }

    #[test]
    #[should_panic(expected = "frame 0 is not a QWP message")]
    fn server_model_refuses_a_frame_with_another_magic() {
        let mut frame = one_frame();
        frame[3] = b'2';
        QwpWsServerModel::new().connect().receive(&frame);
    }

    #[test]
    #[should_panic(expected = "frame 0 is not a QWP message")]
    fn server_model_refuses_a_frame_of_another_version() {
        let mut frame = one_frame();
        frame[4] = QWP_VERSION + 1;
        QwpWsServerModel::new().connect().receive(&frame);
    }

    #[test]
    #[should_panic(expected = "frame 0 is not a QWP message")]
    fn server_model_refuses_a_frame_with_a_wrong_payload_length() {
        let mut frame = one_frame();
        frame.push(0);
        QwpWsServerModel::new().connect().receive(&frame);
    }

    #[test]
    #[should_panic(expected = "frame 0 is not a QWP message")]
    fn server_model_refuses_a_frame_shorter_than_a_header() {
        QwpWsServerModel::new().connect().receive(b"QWP1");
    }

    #[test]
    #[should_panic(expected = "with the delta dictionary flag")]
    fn server_model_refuses_a_frame_without_the_delta_flag() {
        let mut frame = one_frame();
        frame[QWP_FLAGS_OFFSET] = 0;
        QwpWsServerModel::new().connect().receive(&frame);
    }

    #[test]
    #[should_panic(expected = "with the delta dictionary flag")]
    fn server_model_refuses_a_frame_with_a_flag_it_does_not_know() {
        let mut frame = one_frame();
        frame[QWP_FLAGS_OFFSET] |= 0x04;
        QwpWsServerModel::new().connect().receive(&frame);
    }

    #[test]
    #[should_panic(expected = "frames of one table block")]
    fn server_model_refuses_a_frame_of_two_table_blocks() {
        let mut frame = one_frame();
        frame[6] = 2;
        QwpWsServerModel::new().connect().receive(&frame);
    }

    #[test]
    #[should_panic(expected = "holds no symbols")]
    fn server_model_refuses_a_frame_that_brings_symbols() {
        let mut frame = one_frame();
        // The dictionary section: the start, then the count.
        assert_eq!(frame[QWP_HEADER_SIZE..QWP_HEADER_SIZE + 2], [0, 0]);
        frame[QWP_HEADER_SIZE + 1] = 1;
        QwpWsServerModel::new().connect().receive(&frame);
    }

    #[test]
    #[should_panic(expected = "holds no symbols")]
    fn server_model_refuses_a_frame_whose_dictionary_starts_past_its_own() {
        let mut frame = one_frame();
        frame[QWP_HEADER_SIZE] = 1;
        QwpWsServerModel::new().connect().receive(&frame);
    }

    /// One row short of the server's row limit is held; the row that reaches
    /// it is refused, because a server would commit there.
    #[test]
    fn server_model_refuses_to_hold_as_many_rows_as_a_server_commits_by_itself() {
        let mut buffer = Buffer::new_qwp_ws();
        for id in 0..MAX_UNCOMMITTED_ROWS as i64 - 1 {
            buffer
                .table(TABLE)
                .unwrap()
                .column_i64("id", id)
                .unwrap()
                .at(TimestampNanos::new(id))
                .unwrap();
        }
        let mut most = frames_of_a_flush(&buffer, usize::MAX).remove(0);
        most[QWP_FLAGS_OFFSET] |= QWP_FLAG_DEFER_COMMIT;
        let mut one_more = frames_of_a_flush(&buffer_of(TABLE, 0..1), usize::MAX).remove(0);
        one_more[QWP_FLAGS_OFFSET] |= QWP_FLAG_DEFER_COMMIT;

        let server = QwpWsServerModel::new();
        let mut connection = server.connect();
        assert_eq!(connection.receive(&most), None);
        let refusal = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            connection.receive(&one_more)
        }))
        .unwrap_err();
        let refusal = refusal.downcast_ref::<String>().unwrap();
        assert!(
            refusal.contains("once it holds 1000000 uncommitted rows"),
            "{refusal}"
        );
    }

    fn client_of(server: &QwpWsModelServer) -> TcpStream {
        let mut stream = TcpStream::connect(("127.0.0.1", server.port)).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        stream
            .write_all(
                b"GET /write/v4 HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n\
                  Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                  Sec-WebSocket-Version: 13\r\n\r\n",
            )
            .unwrap();
        stream
    }

    /// Reads the upgrade answer and returns the frame limit it advertises.
    fn read_upgrade_answer(stream: &mut TcpStream) -> usize {
        let answer = crate::tests::qwp_ws::read_request_until_blank(stream).unwrap();
        let answer = String::from_utf8(answer).unwrap();
        assert!(answer.starts_with("HTTP/1.1 101 "), "{answer}");
        crate::tests::qwp_ws::parse_header(&answer, "X-QWP-Max-Batch-Size")
            .unwrap()
            .parse()
            .unwrap()
    }

    #[test]
    fn server_model_socket_answers_as_the_model_says() {
        let buffer = buffer_of(TABLE, 0..40);
        let frames = small_frames(&buffer);
        let last = frames.len() - 1;
        let server = QwpWsModelServer::start(300);
        let mut stream = client_of(&server);
        assert_eq!(read_upgrade_answer(&mut stream), 300);

        for frame in &frames[..last] {
            write_server_frame(&mut stream, WS_OPCODE_BINARY, frame, true).unwrap();
        }
        // The answer to a ping is the next thing the server sends: it did
        // not answer the deferred frames.
        write_server_frame(&mut stream, WS_OPCODE_PING, b"mark", true).unwrap();
        assert_eq!(
            read_frame(&mut stream).unwrap(),
            (true, WS_OPCODE_PONG, b"mark".to_vec())
        );
        write_server_frame(&mut stream, WS_OPCODE_BINARY, &frames[last], true).unwrap();
        assert_eq!(
            read_frame(&mut stream).unwrap(),
            (true, WS_OPCODE_BINARY, ok(last, &[(TABLE, 1)]).unwrap())
        );

        // A connection that is cut loses its rows; the server goes on.
        let mut cut = client_of(&server);
        read_upgrade_answer(&mut cut);
        assert_eq!(server.open_connections(), 2);
        let lost = small_frames(&buffer_of(TABLE, 100..140));
        write_server_frame(&mut cut, WS_OPCODE_BINARY, &lost[0], true).unwrap();
        write_server_frame(&mut cut, WS_OPCODE_PING, b"cut", true).unwrap();
        assert_eq!(
            read_frame(&mut cut).unwrap(),
            (true, WS_OPCODE_PONG, b"cut".to_vec())
        );
        drop(cut);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while server.open_connections() != 1 {
            assert!(
                std::time::Instant::now() < deadline,
                "the cut went unnoticed"
            );
            thread::yield_now();
        }

        let table = server.model.table(TABLE).unwrap();
        assert_eq!(table.commits, 1);
        assert_eq!(table.rows_as_text(), rows_of(TABLE, &buffer));
        server.finish();
    }

    #[test]
    #[should_panic(expected = "is above the frame limit of 300")]
    fn server_model_socket_refuses_a_frame_above_its_limit() {
        let server = QwpWsModelServer::start(300);
        let mut stream = client_of(&server);
        read_upgrade_answer(&mut stream);
        let frame = frames_of_a_flush(&buffer_of(TABLE, 0..40), usize::MAX).remove(0);
        assert!(frame.len() > 300);
        write_server_frame(&mut stream, WS_OPCODE_BINARY, &frame, true).unwrap();
        // The server closes the connection it failed on: the read ends
        // before its timeout.
        let end = read_frame(&mut stream).unwrap_err();
        assert!(
            !matches!(
                end.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
            "{end}"
        );
        server.finish();
    }

    #[test]
    fn server_model_socket_takes_a_frame_of_exactly_its_limit() {
        let frame = frames_of_a_flush(&buffer_of(TABLE, 0..40), usize::MAX).remove(0);
        let server = QwpWsModelServer::start(frame.len());
        let mut stream = client_of(&server);
        read_upgrade_answer(&mut stream);
        write_server_frame(&mut stream, WS_OPCODE_BINARY, &frame, true).unwrap();
        assert_eq!(
            read_frame(&mut stream).unwrap(),
            (true, WS_OPCODE_BINARY, ok(0, &[(TABLE, 1)]).unwrap())
        );
        server.finish();
    }
}
