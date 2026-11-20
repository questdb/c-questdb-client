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
//! - A frame holds one table block, or several, each of another table.
//! - A frame without the flag commits what the connection holds, the frame's
//!   own rows included, as one commit per table. It commits a table it
//!   brings no rows for too. Its answer is one OK with the frame's sequence,
//!   which names each table it committed with the number of that table's
//!   commit, and no other table. Sequences count the frames of a connection
//!   from zero, commits those of a table from one.
//! - A frame brings the symbols that are new to its connection. The
//!   connection keeps them, committed or not, and numbers them as they
//!   come. A symbol in a row is such a number: of a symbol that this frame
//!   brought or an earlier one, for this table or another.
//! - A frame without a table block and without the flag only brings
//!   symbols. Its answer is an OK that names no table. A sender begins a
//!   new connection with such frames, to bring every symbol it has sent,
//!   and then sends again the frames that were not answered. So a frame
//!   may bring symbols the connection holds, under the same numbers.
//! - A connection that goes away loses the rows it holds, of every table,
//!   and its symbols.
//! - A frame that the server rejects gets an error as its answer, which
//!   names the sequence of the frame. The rows that the connection holds
//!   are gone, of every table. The connection stays, and the server takes
//!   no later frame of it: it reads them, answers none and commits nothing.
//! - A table exists from the first frame that names it, committed or not.
//!
//! What the model cannot do it refuses with a panic, so that no test passes
//! on behaviour the model made up: a frame that is not a QWP message, a flag
//! it does not know, two blocks of one table in a frame (which no flush
//! sends), a frame above the frame limit, and the commit a server forces on
//! a table that holds 1,000,000 uncommitted rows
//! (`qwp.max.uncommitted.rows`). Of symbols it refuses: a frame whose
//! symbols leave a gap after those the connection holds (a server rejects
//! it), a held symbol that gets another text (a server takes the new text),
//! a symbol in a row that the connection does not hold, and a frame without
//! a table block that has the defer flag or comes while the connection
//! holds rows (a server takes both, the second as the commit of those rows;
//! the driver sends neither).
//!
//! Four things a server does are neither modelled nor refused. A server
//! rejects a frame whose column types disagree with the table; the model
//! takes any columns, and rejects the frame that a test tells it to
//! ([`QwpWsModelServer::reject_frame`]). A server may commit frames without
//! the flag together, as one transaction, when they arrive in one read; the
//! model commits each on its own. So a test may count on one commit for a
//! group, never on one commit per frame without the flag. A server may
//! likewise answer several frames without the flag with one OK, which
//! counts for the frames before it too; the model answers each. And a
//! server names the tables of an OK in the order the connection first named
//! them, the model in the order of their names; the script does not look at
//! the order, and the client reads each entry by itself.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use crate::ingress::{
    Buffer, QwpWsEncodeScratch, SymbolGlobalDict, TimestampNanos, decode_qwp_varint,
};
use crate::tests::qwp_decode::{DecodedTable, decode_ws_table_blocks};
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
/// every frame but the last has the defer flag. The buffer has no symbols.
pub(crate) fn frames_of_a_flush(buffer: &Buffer, target: usize) -> Vec<Vec<u8>> {
    let mut no_symbols = SymbolGlobalDict::new();
    let frames = frames_of_a_sender(buffer, target, &mut no_symbols);
    assert_eq!(
        no_symbols.next_id(),
        0,
        "a buffer with symbols needs the dictionary of its sender"
    );
    frames
}

/// As [`frames_of_a_flush`], from a sender whose symbol dictionary is
/// `symbols`: each frame brings the symbols that its rows use and the
/// dictionary does not hold yet, and the dictionary holds them afterwards.
pub(crate) fn frames_of_a_sender(
    buffer: &Buffer,
    target: usize,
    symbols: &mut SymbolGlobalDict,
) -> Vec<Vec<u8>> {
    let rows = buffer.as_qwp_ws().expect("a QWP/WebSocket buffer");
    let plan = rows
        .plan_frames(target, target)
        .expect("a buffer the planner can cut");
    let frame_count = plan.frames().count();
    let mut scratch = QwpWsEncodeScratch::new();
    plan.frames()
        .enumerate()
        .map(|(frame_idx, blocks)| {
            let mut frame = Vec::new();
            rows.encode_ws_frame(
                blocks,
                &mut frame,
                &mut scratch,
                symbols,
                QWP_VERSION,
                frame_idx + 1 < frame_count,
            )
            .unwrap();
            frame
        })
        .collect()
}

/// One frame that holds every table of `buffer` whole, a block each, as a
/// flush of a buffer within the frame cap sends it. The buffer has no
/// symbols.
pub(crate) fn frame_of_a_whole_buffer(buffer: &Buffer, defer_commit: bool) -> Vec<u8> {
    let mut no_symbols = SymbolGlobalDict::new();
    let frame = frame_of_a_sender(buffer, defer_commit, &mut no_symbols);
    assert_eq!(
        no_symbols.next_id(),
        0,
        "a buffer with symbols needs the dictionary of its sender"
    );
    frame
}

/// As [`frame_of_a_whole_buffer`], from a sender whose symbol dictionary is
/// `symbols`: the frame brings the symbols of `buffer` that the dictionary
/// does not hold yet, and the dictionary holds them afterwards. So the
/// frames of one sender, made in the order they are sent, bring each symbol
/// once.
pub(crate) fn frame_of_a_sender(
    buffer: &Buffer,
    defer_commit: bool,
    symbols: &mut SymbolGlobalDict,
) -> Vec<u8> {
    let mut frame = Vec::new();
    buffer
        .as_qwp_ws()
        .expect("a QWP/WebSocket buffer")
        .encode_ws_replay_message_with_defer(
            &mut frame,
            &mut QwpWsEncodeScratch::new(),
            symbols,
            QWP_VERSION,
            defer_commit,
            true,
        )
        .unwrap();
    frame
}

/// Rows `ids` of a table without symbols, a few dozen bytes each.
pub(crate) fn buffer_of(table: &str, ids: std::ops::Range<i64>) -> Buffer {
    let mut buffer = Buffer::new_qwp_ws();
    add_rows(&mut buffer, table, ids);
    buffer
}

/// Adds the rows [`buffer_of`] makes to a buffer, which may hold other tables.
pub(crate) fn add_rows(buffer: &mut Buffer, table: &str, ids: std::ops::Range<i64>) {
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
}

/// The rows of `table` a server holds when `buffer` reaches it as a single
/// frame. The frame is the one a flush within the frame cap sends, so that
/// the rows do not depend on how a flush is cut.
pub(crate) fn rows_of(table: &str, buffer: &Buffer) -> Vec<String> {
    let server = QwpWsServerModel::new();
    // A connection of its own: the frame brings every symbol of the buffer.
    let frame = frame_of_a_sender(buffer, false, &mut SymbolGlobalDict::new());
    assert!(server.connect().receive(&frame).is_some());
    server.table(table).unwrap().rows_as_text()
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

    /// A new connection. It holds no rows and no symbols, and its first
    /// frame has sequence 0.
    pub(crate) fn connect(&self) -> QwpWsModelConnection {
        QwpWsModelConnection {
            server: self.clone(),
            next_sequence: 0,
            symbols: Vec::new(),
            held: BTreeMap::new(),
            rejected_a_frame: false,
        }
    }

    /// What is committed of a table. `None` when no frame has named it.
    pub(crate) fn table(&self, name: &str) -> Option<ModelTable> {
        self.tables.lock().unwrap().get(name).cloned()
    }
}

/// One connection to the server. Dropping it is a disconnect: the rows it
/// holds are gone, and its symbols.
pub(crate) struct QwpWsModelConnection {
    server: QwpWsServerModel,
    next_sequence: u64,
    /// The symbols the frames of the connection brought. A symbol's id is
    /// its place here.
    symbols: Vec<String>,
    /// Per table, the blocks that wait for a frame without the defer flag.
    held: BTreeMap<String, Vec<DecodedTable>>,
    /// The connection has rejected a frame, and takes no frame since.
    rejected_a_frame: bool,
}

impl QwpWsModelConnection {
    /// Takes the next message of the client. Returns the answer of the
    /// server, if it gives one.
    pub(crate) fn receive(&mut self, message: &[u8]) -> Option<Vec<u8>> {
        if self.rejected_a_frame {
            return None;
        }
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
        let block_count = usize::from(u16::from_le_bytes([message[6], message[7]]));
        assert!(
            block_count > 0 || (!defer_commit && self.held.is_empty()),
            "frame {sequence}: the server model reads a frame without a table block only as a \
             sender brings its symbols again: without the defer flag, on a connection that \
             holds no rows"
        );
        let pos = self.take_symbols(sequence, message);

        let mut names = BTreeSet::new();
        for block in decode_ws_table_blocks(&message[pos..], block_count, &self.symbols) {
            assert!(
                names.insert(block.name.clone()),
                "frame {sequence}: two blocks of table {}, which no flush sends: the server \
                 model reads one block of a table in a frame",
                block.name
            );
            let held = self.held.entry(block.name.clone()).or_default();
            held.push(block);
            let held_rows: usize = held.iter().map(|block| block.rows.len()).sum();
            assert!(
                held_rows < MAX_UNCOMMITTED_ROWS,
                "frame {sequence}: a server commits a table by itself once it holds \
                 {MAX_UNCOMMITTED_ROWS} uncommitted rows, which the server model does not do"
            );
        }

        let mut tables = self.server.tables.lock().unwrap();
        for name in names {
            tables.entry(name).or_default();
        }
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

    /// Rejects the next message of the client with `status`, as a server
    /// rejects a frame whose column types disagree with the table. Returns
    /// the answer: an error that names the sequence of the message. The
    /// connection takes no message from now on, so the rows that it holds
    /// are never committed.
    pub(crate) fn reject(&mut self, status: u8) -> Vec<u8> {
        const TEXT: &[u8] = b"the server model was told to reject this frame";
        assert_ne!(status, QWP_STATUS_OK, "an OK rejects nothing");
        self.rejected_a_frame = true;
        // An error: the status, the sequence, then a text behind its length.
        let mut error = vec![status];
        error.extend_from_slice(&self.next_sequence.to_le_bytes());
        error.extend_from_slice(&(TEXT.len() as u16).to_le_bytes());
        error.extend_from_slice(TEXT);
        error
    }

    /// Takes the symbols a frame brings: behind the header, the id of the
    /// first, their count, and each as its length and its text. Returns
    /// where the table blocks of the frame begin.
    fn take_symbols(&mut self, sequence: u64, message: &[u8]) -> usize {
        let (first_id, pos) = decode_qwp_varint(message, QWP_HEADER_SIZE).unwrap();
        let (count, mut pos) = decode_qwp_varint(message, pos).unwrap();
        let first_id = first_id as usize;
        assert!(
            first_id <= self.symbols.len(),
            "frame {sequence}: its symbols start at id {first_id} and the connection holds \
             {}: a server rejects the frame, which the server model does not do",
            self.symbols.len()
        );
        for id in first_id..first_id + count as usize {
            let (len, start) = decode_qwp_varint(message, pos).unwrap();
            pos = start + len as usize;
            let symbol = std::str::from_utf8(&message[start..pos]).unwrap();
            match self.symbols.get(id) {
                // A frame that is sent again brings its symbols again.
                Some(held) => assert_eq!(
                    held, symbol,
                    "frame {sequence}: symbol {id} gets another text, which no sender does \
                     on its own connection"
                ),
                None => self.symbols.push(symbol.to_owned()),
            }
        }
        pos
    }
}

/// A socket server that takes QWP/WebSocket connections and answers each as
/// the model says. Its upgrade answer advertises `max_batch_size` as the
/// frame limit.
///
/// A test can make it hold its answers back, as a server does that is slow
/// to commit: see [`Self::hold_answers`].
pub(crate) struct QwpWsModelServer {
    pub(crate) port: u16,
    pub(crate) model: QwpWsServerModel,
    shared: Arc<ServerShared>,
    acceptor: Option<thread::JoinHandle<()>>,
}

struct ServerShared {
    stop: AtomicBool,
    /// The server ends every connection: see [`QwpWsModelServer::go_down`].
    down: AtomicBool,
    /// The connections the server has taken and not yet seen the end of.
    open: AtomicUsize,
    /// Every connection taken so far, to end them when the server stops.
    streams: Mutex<Vec<TcpStream>>,
    /// The frames taken so far, over all connections.
    frames: AtomicUsize,
    /// The frame to reject and the status to reject it with: see
    /// [`QwpWsModelServer::reject_frame`].
    rejection: Mutex<Option<(usize, u8)>>,
    /// Locked for every write to a client, so that an answer that was held
    /// back and one that is given at once never mix.
    answers: Mutex<Answers>,
}

#[derive(Default)]
struct Answers {
    held_back: bool,
    /// The answers held back, each with the connection that waits for it,
    /// in the order the server made them.
    waiting: Vec<(TcpStream, Vec<u8>)>,
}

impl ServerShared {
    /// The status to reject the next frame with, if it is the one that the
    /// server was told to reject.
    fn rejection_of_the_next_frame(&self) -> Option<u8> {
        let next = self.frames.load(Ordering::SeqCst) + 1;
        self.rejection
            .lock()
            .unwrap()
            .filter(|(frame, _)| *frame == next)
            .map(|(_, status)| status)
    }

    /// Gives the client its answer, or keeps it while answers are held back.
    fn answer(&self, stream: &mut TcpStream, answer: Vec<u8>) -> std::io::Result<()> {
        let mut answers = self.answers.lock().unwrap();
        if answers.held_back {
            answers.waiting.push((stream.try_clone()?, answer));
            return Ok(());
        }
        write_server_binary_frame(stream, &answer)
    }
}

impl QwpWsModelServer {
    pub(crate) fn start(max_batch_size: usize) -> Self {
        Self::start_with(max_batch_size, None)
    }

    /// A server that ends its first connection as soon as it has taken
    /// `frames` frames of it, before it answers the last of them. The rows
    /// that connection holds are gone, as after any disconnect. Every later
    /// connection is served to its end.
    pub(crate) fn start_cutting_first_connection(max_batch_size: usize, frames: usize) -> Self {
        Self::start_with(max_batch_size, Some(frames))
    }

    fn start_with(max_batch_size: usize, mut cut_after_frames: Option<usize>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let model = QwpWsServerModel::new();
        let shared = Arc::new(ServerShared {
            stop: AtomicBool::new(false),
            down: AtomicBool::new(false),
            open: AtomicUsize::new(0),
            streams: Mutex::new(Vec::new()),
            frames: AtomicUsize::new(0),
            rejection: Mutex::default(),
            answers: Mutex::default(),
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
                        if shared.down.load(Ordering::SeqCst) {
                            // Ended before the server answers anything.
                            continue;
                        }
                        streams.push(stream.try_clone().unwrap());
                    }
                    let connection = model.connect();
                    shared.open.fetch_add(1, Ordering::SeqCst);
                    let open = OpenConnection(Arc::clone(&shared));
                    // Only the first connection is cut.
                    let cut_after_frames = cut_after_frames.take();
                    connections.push(thread::spawn(move || {
                        // Dropped last: the connection and its rows are gone.
                        let open = open;
                        serve_connection(
                            stream,
                            connection,
                            max_batch_size,
                            cut_after_frames,
                            &open.0,
                        );
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

    /// How many frames the server has taken so far, over all connections.
    pub(crate) fn frames_taken(&self) -> usize {
        self.shared.frames.load(Ordering::SeqCst)
    }

    /// The server rejects one frame with `status`: the one that makes
    /// [`Self::frames_taken`] reach `frame`, so the first frame it ever
    /// takes is frame 1. It does to that frame's connection what
    /// [`QwpWsModelConnection::reject`] says. A real server finds the frame
    /// to reject by itself; the model has to be told.
    pub(crate) fn reject_frame(&self, frame: usize, status: u8) {
        assert!(
            frame > self.frames_taken(),
            "frame {frame} was taken before the server was told to reject it"
        );
        *self.shared.rejection.lock().unwrap() = Some((frame, status));
    }

    /// From now on the server keeps its answers to itself. It takes every
    /// frame as before, and commits as before: only the client does not
    /// learn of it.
    pub(crate) fn hold_answers(&self) {
        self.shared.answers.lock().unwrap().held_back = true;
    }

    /// Gives the answers that were held back, in their order, and answers
    /// every later frame at once again.
    pub(crate) fn let_answers_go(&self) {
        let mut answers = self.shared.answers.lock().unwrap();
        answers.held_back = false;
        for (mut stream, answer) in answers.waiting.drain(..) {
            // The client may have gone away meanwhile.
            let _ = write_server_binary_frame(&mut stream, &answer);
        }
    }

    /// From now on the server is down for its clients: it ends the
    /// connections it has, and every new one before it answers anything. It
    /// keeps its port, so that a client that tries again never reaches the
    /// server of another test.
    pub(crate) fn go_down(&self) {
        let streams = self.shared.streams.lock().unwrap();
        self.shared.down.store(true, Ordering::SeqCst);
        for stream in streams.iter() {
            let _ = stream.shutdown(Shutdown::Both);
        }
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
    cut_after_frames: Option<usize>,
    shared: &ServerShared,
) {
    let _close = CloseOnDrop(stream.try_clone().unwrap());
    upgrade_mock_stream_with_max_batch_size(&mut stream, Some(max_batch_size));
    let mut frames = 0;
    while wait_for_a_frame(&stream, shared) {
        // A read fails when the client went away or the server stops.
        let Ok((fin, opcode, payload)) = read_frame(&mut stream) else {
            break;
        };
        let answered = match opcode {
            WS_OPCODE_BINARY => {
                assert!(fin, "the server model takes whole messages");
                assert!(
                    payload.len() <= max_batch_size,
                    "a frame of {} bytes is above the frame limit of {max_batch_size}: \
                     a server closes the connection, which the server model does not do",
                    payload.len()
                );
                let answer = match shared.rejection_of_the_next_frame() {
                    Some(status) => Some(connection.reject(status)),
                    None => connection.receive(&payload),
                };
                frames += 1;
                shared.frames.fetch_add(1, Ordering::SeqCst);
                if cut_after_frames == Some(frames) {
                    break;
                }
                match answer {
                    Some(answer) => shared.answer(&mut stream, answer),
                    None => Ok(()),
                }
            }
            WS_OPCODE_PING => {
                let _answers = shared.answers.lock().unwrap();
                write_server_frame(&mut stream, WS_OPCODE_PONG, &payload, false)
            }
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

/// How long a connection waits for its client before it looks whether the
/// server has stopped or gone down.
const SERVER_STATE_POLL: std::time::Duration = std::time::Duration::from_millis(20);

/// Waits until the client has sent something. `false` when the client went
/// away, and when the server stopped or went down in the meantime.
///
/// A connection has to find the end of its server by itself. The server
/// shuts the socket down, which wakes a blocked read on Linux and macOS. On
/// Windows it does not: there a blocked read goes on until the client closes
/// its end, or until the system gives the half-closed connection up, which
/// takes two minutes.
fn wait_for_a_frame(stream: &TcpStream, shared: &ServerShared) -> bool {
    if stream.set_read_timeout(Some(SERVER_STATE_POLL)).is_err() {
        return false;
    }
    let ready = loop {
        match stream.peek(&mut [0u8; 1]) {
            Ok(0) => break false,
            Ok(_) => break true,
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                if shared.stop.load(Ordering::SeqCst) || shared.down.load(Ordering::SeqCst) {
                    break false;
                }
            }
            Err(_) => break false,
        }
    };
    // A frame that has begun is read to its end, however long that takes.
    stream.set_read_timeout(None).is_ok() && ready
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    use super::*;
    use crate::ingress::SentDictMirror;
    use crate::tests::qwp_decode::DecodedValue;

    const TABLE: &str = "model_rows";

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
    fn server_model_drops_the_held_rows_when_it_rejects_a_frame_and_takes_none_behind_it() {
        const STATUS: u8 = 0x03;
        let whole = |buffer: &Buffer| frames_of_a_flush(buffer, usize::MAX).remove(0);
        let kept = buffer_of("model_one", 0..3);
        let lost = buffer_of("model_one", 100..140);
        let lost_of_two = buffer_of("model_two", 0..3);
        let server = QwpWsServerModel::new();
        let mut connection = server.connect();
        assert_eq!(
            connection.receive(&whole(&kept)),
            ok(0, &[("model_one", 1)])
        );

        // The connection holds rows of two tables when it rejects a frame.
        let frames = small_frames(&lost);
        let last = frames.len() - 1;
        for frame in &frames[..last] {
            assert_eq!(connection.receive(frame), None);
        }
        let mut held_of_two = whole(&lost_of_two);
        held_of_two[QWP_FLAGS_OFFSET] |= QWP_FLAG_DEFER_COMMIT;
        assert_eq!(connection.receive(&held_of_two), None);
        // The error names the frame: frame 0 was committed, and `last` frames
        // and one more are held.
        let error = connection.reject(STATUS);
        let text = &error[11..];
        assert_eq!(error[0], STATUS);
        assert_eq!(error[1..9], (last as u64 + 2).to_le_bytes());
        assert_eq!(error[9..11], (text.len() as u16).to_le_bytes());
        assert!(!text.is_empty());

        // No frame behind it is taken: not the one that would have committed
        // the held rows, and not one that brings rows and commits them.
        assert_eq!(connection.receive(&frames[last]), None);
        assert_eq!(
            connection.receive(&whole(&buffer_of("model_one", 200..203))),
            None
        );
        let rows_of_one = |server: &QwpWsServerModel| {
            let table = server.table("model_one").unwrap();
            (table.commits, table.rows_as_text())
        };
        assert_eq!(rows_of_one(&server), (1, rows_of("model_one", &kept)));
        assert_eq!(server.table("model_two").unwrap().commits, 0);

        // A new connection commits what it brings, and nothing of what the
        // first one held.
        let mut second = server.connect();
        assert_eq!(
            second.receive(&whole(&lost_of_two)),
            ok(0, &[("model_two", 1)])
        );
        assert_eq!(rows_of_one(&server), (1, rows_of("model_one", &kept)));
        let table = server.table("model_two").unwrap();
        assert_eq!(table.rows_as_text(), rows_of("model_two", &lost_of_two));
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

    /// A buffer with the rows [`buffer_of`] makes for each of `tables`, in
    /// the order given.
    fn buffer_of_tables(tables: &[(&str, std::ops::Range<i64>)]) -> Buffer {
        let mut buffer = Buffer::new_qwp_ws();
        for (table, ids) in tables {
            add_rows(&mut buffer, table, ids.clone());
        }
        buffer
    }

    #[test]
    fn server_model_takes_each_block_of_a_frame_for_its_own_table() {
        // The frames of a flush over two tables: rows of one table, the
        // rest of them with the first rows of the other, the rest of the
        // other.
        let frames = [
            frame_of_a_whole_buffer(&buffer_of("model_one", 0..5), true),
            frame_of_a_whole_buffer(
                &buffer_of_tables(&[("model_one", 5..9), ("model_two", 100..103)]),
                true,
            ),
            frame_of_a_whole_buffer(&buffer_of("model_two", 103..110), false),
        ];
        assert_eq!([frames[0][6], frames[1][6], frames[2][6]], [1, 2, 1]);

        let server = QwpWsServerModel::new();
        let mut connection = server.connect();
        assert_eq!(connection.receive(&frames[0]), None);
        assert!(server.table("model_two").is_none());
        assert_eq!(connection.receive(&frames[1]), None);
        for name in ["model_one", "model_two"] {
            let table = server.table(name).unwrap();
            assert_eq!((table.commits, table.row_count()), (0, 0));
        }
        // The last frame holds no block of the first table, and commits it.
        assert_eq!(
            connection.receive(&frames[2]),
            ok(2, &[("model_one", 1), ("model_two", 1)])
        );
        let rows_of_ids = |table: &str, ids| rows_of(table, &buffer_of(table, ids));
        let one = server.table("model_one").unwrap();
        assert_eq!(one.commits, 1);
        assert_eq!(one.rows_as_text(), rows_of_ids("model_one", 0..9));
        let two = server.table("model_two").unwrap();
        assert_eq!(two.commits, 1);
        assert_eq!(two.rows_as_text(), rows_of_ids("model_two", 100..110));

        // The next frame commits, and names, only the table it brings rows
        // for.
        let frame = frame_of_a_whole_buffer(&buffer_of("model_two", 110..112), false);
        assert_eq!(connection.receive(&frame), ok(3, &[("model_two", 2)]));
        assert_eq!(server.table("model_one").unwrap().commits, 1);
        assert_eq!(server.table("model_two").unwrap().commits, 2);

        // A frame may list its tables in any order.
        let frame = frame_of_a_whole_buffer(
            &buffer_of_tables(&[("model_two", 112..113), ("model_one", 9..12)]),
            false,
        );
        assert_eq!(
            connection.receive(&frame),
            ok(4, &[("model_one", 2), ("model_two", 3)])
        );
        assert_eq!(
            server.table("model_one").unwrap().rows_as_text(),
            rows_of_ids("model_one", 0..12)
        );
        assert_eq!(
            server.table("model_two").unwrap().rows_as_text(),
            rows_of_ids("model_two", 100..113)
        );
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

    /// The frame without a table block that brings the symbols of
    /// `frame` again.
    fn frame_without_a_table(frame: &[u8]) -> Vec<u8> {
        let mut sent = SentDictMirror::new(true);
        assert!(sent.accumulate(frame));
        let mut frames = sent.build_catch_up_frames(0, QWP_VERSION).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(
            frames[0][QWP_FLAGS_OFFSET..8],
            [QWP_FLAG_DELTA_SYMBOL_DICT, 0, 0]
        );
        frames.remove(0)
    }

    #[test]
    #[should_panic(expected = "only as a sender brings its symbols again")]
    fn server_model_refuses_a_frame_without_a_table_block_that_has_the_defer_flag() {
        let mut frame = frame_without_a_table(&symbol_frames(&mut SymbolGlobalDict::new())[0]);
        frame[QWP_FLAGS_OFFSET] |= QWP_FLAG_DEFER_COMMIT;
        QwpWsServerModel::new().connect().receive(&frame);
    }

    #[test]
    #[should_panic(expected = "only as a sender brings its symbols again")]
    fn server_model_refuses_a_frame_without_a_table_block_while_it_holds_rows() {
        let frames = symbol_frames(&mut SymbolGlobalDict::new());
        let server = QwpWsServerModel::new();
        let mut connection = server.connect();
        assert_eq!(connection.receive(&frames[0]), None);
        connection.receive(&frame_without_a_table(&frames[0]));
    }

    #[test]
    #[should_panic(expected = "table block 1 of 2: unexpected end")]
    fn server_model_refuses_a_frame_that_states_a_block_more_than_it_holds() {
        let mut frame = one_frame();
        frame[6] = 2;
        QwpWsServerModel::new().connect().receive(&frame);
    }

    #[test]
    #[should_panic(expected = "bytes behind the last of 1 table blocks")]
    fn server_model_refuses_a_frame_that_holds_a_block_more_than_it_states() {
        let two_tables = buffer_of_tables(&[(TABLE, 0..3), ("model_other", 0..3)]);
        let mut frame = frame_of_a_whole_buffer(&two_tables, false);
        assert_eq!(frame[6], 2);
        frame[6] = 1;
        QwpWsServerModel::new().connect().receive(&frame);
    }

    #[test]
    #[should_panic(expected = "two blocks of table model_rows")]
    fn server_model_refuses_two_blocks_of_one_table_in_a_frame() {
        // No flush makes such a frame: the block of a second frame is put
        // behind the block of the first.
        let mut frame = one_frame();
        let second = frames_of_a_flush(&buffer_of(TABLE, 3..5), usize::MAX).remove(0);
        frame.extend_from_slice(&second[QWP_HEADER_SIZE + 2..]);
        frame[6] = 2;
        let payload_len = (frame.len() - QWP_HEADER_SIZE) as u32;
        frame[8..12].copy_from_slice(&payload_len.to_le_bytes());
        QwpWsServerModel::new().connect().receive(&frame);
    }

    #[test]
    #[should_panic(expected = "its symbols start at id 1 and the connection holds 0")]
    fn server_model_refuses_a_frame_whose_dictionary_starts_past_its_own() {
        let mut frame = one_frame();
        // The dictionary section: the id of the first symbol, then the count.
        assert_eq!(frame[QWP_HEADER_SIZE..QWP_HEADER_SIZE + 2], [0, 0]);
        frame[QWP_HEADER_SIZE] = 1;
        QwpWsServerModel::new().connect().receive(&frame);
    }

    /// Adds rows with two symbol columns to a buffer: per row its id, its
    /// `sym`, and its `other`, which a row may lack.
    fn add_symbol_rows(buffer: &mut Buffer, table: &str, rows: &[(i64, &str, Option<&str>)]) {
        for (id, sym, other) in rows {
            buffer
                .table(table)
                .unwrap()
                .symbol("sym", sym)
                .unwrap()
                .symbol_opt("other", *other)
                .unwrap()
                .column_i64("id", *id)
                .unwrap()
                .at(TimestampNanos::new(1_700_000_000_000_000_000 + id))
                .unwrap();
        }
    }

    fn symbol_rows(table: &str, rows: &[(i64, &str, Option<&str>)]) -> Buffer {
        let mut buffer = Buffer::new_qwp_ws();
        add_symbol_rows(&mut buffer, table, rows);
        buffer
    }

    /// The three frames of a flush over two tables, from a sender whose
    /// dictionary is `symbols`. With a new dictionary the first brings `a`,
    /// `b` and `x`, the second `y` and `z`, the third `w`. The second and
    /// the third also name symbols that an earlier frame brought, for the
    /// other column or the other table.
    fn symbol_frames(symbols: &mut SymbolGlobalDict) -> [Vec<u8>; 3] {
        let first = symbol_rows(
            "model_one",
            &[(0, "a", Some("x")), (1, "b", None), (2, "a", Some("a"))],
        );
        let mut second = symbol_rows("model_one", &[(3, "b", Some("y"))]);
        add_symbol_rows(&mut second, "model_two", &[(10, "a", Some("z"))]);
        let third = symbol_rows("model_two", &[(11, "w", Some("b"))]);
        [
            frame_of_a_sender(&first, true, symbols),
            frame_of_a_sender(&second, true, symbols),
            frame_of_a_sender(&third, false, symbols),
        ]
    }

    /// Per frame, the symbols it brings: the id of the first, and how many.
    fn brought(frames: &[Vec<u8>]) -> Vec<[u8; 2]> {
        frames
            .iter()
            .map(|frame| [frame[QWP_HEADER_SIZE], frame[QWP_HEADER_SIZE + 1]])
            .collect()
    }

    /// Per committed row of a table, the symbol it has in `column`; `-` for
    /// a row without one.
    fn symbols_in(server: &QwpWsServerModel, table: &str, column: &str) -> Vec<String> {
        let mut symbols = Vec::new();
        for block in &server.table(table).unwrap().blocks {
            let column = block
                .columns
                .iter()
                .position(|candidate| candidate.name == column)
                .unwrap();
            for row in &block.rows {
                symbols.push(match &row[column] {
                    DecodedValue::Symbol(symbol) => symbol.clone(),
                    DecodedValue::Null => "-".to_owned(),
                    other => panic!("not a symbol: {other:?}"),
                });
            }
        }
        symbols
    }

    #[test]
    fn server_model_reads_a_symbol_by_the_id_its_connection_gave_it() {
        let mut symbols = SymbolGlobalDict::new();
        let frames = symbol_frames(&mut symbols);
        assert_eq!(brought(&frames), [[0, 3], [3, 2], [5, 1]]);

        let server = QwpWsServerModel::new();
        let mut connection = server.connect();
        assert_eq!(connection.receive(&frames[0]), None);
        assert_eq!(connection.receive(&frames[1]), None);
        assert_eq!(
            connection.receive(&frames[2]),
            ok(2, &[("model_one", 1), ("model_two", 1)])
        );
        assert_eq!(
            symbols_in(&server, "model_one", "sym"),
            ["a", "b", "a", "b"]
        );
        assert_eq!(
            symbols_in(&server, "model_one", "other"),
            ["x", "-", "a", "y"]
        );
        assert_eq!(symbols_in(&server, "model_two", "sym"), ["a", "w"]);
        assert_eq!(symbols_in(&server, "model_two", "other"), ["z", "b"]);

        // The connection keeps its symbols after a commit: the next frame
        // brings one, and names one of the first frame.
        let frame = frame_of_a_sender(
            &symbol_rows("model_two", &[(12, "c", Some("x"))]),
            false,
            &mut symbols,
        );
        assert_eq!(brought(std::slice::from_ref(&frame)), [[6, 1]]);
        assert_eq!(connection.receive(&frame), ok(3, &[("model_two", 2)]));
        assert_eq!(symbols_in(&server, "model_two", "sym"), ["a", "w", "c"]);
        assert_eq!(symbols_in(&server, "model_two", "other"), ["z", "b", "x"]);
    }

    #[test]
    #[should_panic(expected = "its symbols start at id 3 and the connection holds 0")]
    fn server_model_gives_each_connection_symbols_of_its_own() {
        let frames = symbol_frames(&mut SymbolGlobalDict::new());
        let server = QwpWsServerModel::new();
        let mut first = server.connect();
        assert_eq!(first.receive(&frames[0]), None);
        assert_eq!(first.receive(&frames[1]), None);
        // A second connection has not got the symbols of the first frame.
        server.connect().receive(&frames[1]);
    }

    #[test]
    fn server_model_takes_the_symbols_again_on_a_new_connection() {
        // What a sender keeps: its dictionary, and the symbols it has sent.
        let mut symbols = SymbolGlobalDict::new();
        let mut sent = SentDictMirror::new(true);
        let server = QwpWsServerModel::new();

        // A flush that is answered, then two frames of a flush of three.
        let early = frame_of_a_sender(
            &symbol_rows("model_one", &[(20, "early", Some("a"))]),
            false,
            &mut symbols,
        );
        let frames = symbol_frames(&mut symbols);
        assert_eq!(brought(&frames), [[2, 2], [4, 2], [6, 1]]);
        let mut connection = server.connect();
        assert_eq!(connection.receive(&early), ok(0, &[("model_one", 1)]));
        assert_eq!(connection.receive(&frames[0]), None);
        assert_eq!(connection.receive(&frames[1]), None);
        for frame in [&early, &frames[0], &frames[1]] {
            assert!(sent.accumulate(frame));
        }
        drop(connection);

        // The new connection: first the six symbols, in two frames without
        // a table. Each is answered, and nothing is committed.
        let again = sent.build_catch_up_frames(36, QWP_VERSION).unwrap();
        assert_eq!(brought(&again), [[0, 2], [2, 4]]);
        let mut connection = server.connect();
        assert_eq!(connection.receive(&again[0]), ok(0, &[]));
        assert_eq!(connection.receive(&again[1]), ok(1, &[]));
        let table = server.table("model_one").unwrap();
        assert_eq!((table.commits, table.row_count()), (1, 1));
        let table = server.table("model_two").unwrap();
        assert_eq!((table.commits, table.row_count()), (0, 0));

        // Then the frames that were not answered, as they are: they bring
        // their symbols once more. The last one was never sent.
        assert_eq!(connection.receive(&frames[0]), None);
        assert_eq!(connection.receive(&frames[1]), None);
        assert_eq!(
            connection.receive(&frames[2]),
            ok(4, &[("model_one", 2), ("model_two", 1)])
        );
        assert_eq!(
            symbols_in(&server, "model_one", "sym"),
            ["early", "a", "b", "a", "b"]
        );
        assert_eq!(
            symbols_in(&server, "model_one", "other"),
            ["a", "x", "-", "a", "y"]
        );
        assert_eq!(symbols_in(&server, "model_two", "sym"), ["a", "w"]);
        assert_eq!(symbols_in(&server, "model_two", "other"), ["z", "b"]);
    }

    #[test]
    #[should_panic(expected = "symbol 0 gets another text")]
    fn server_model_refuses_another_text_for_a_symbol_it_holds() {
        let frames = symbol_frames(&mut SymbolGlobalDict::new());
        let server = QwpWsServerModel::new();
        let mut connection = server.connect();
        assert_eq!(connection.receive(&frames[0]), None);
        // The first frame of another sender: its symbols begin at 0 too.
        let other = frame_of_a_sender(
            &symbol_rows("model_one", &[(5, "q", None)]),
            false,
            &mut SymbolGlobalDict::new(),
        );
        connection.receive(&other);
    }

    #[test]
    #[should_panic(expected = "symbol index 5 out of bounds for dictionary size 4")]
    fn server_model_refuses_a_symbol_its_connection_does_not_hold() {
        let mut frames = symbol_frames(&mut SymbolGlobalDict::new());
        let server = QwpWsServerModel::new();
        let mut connection = server.connect();
        assert_eq!(connection.receive(&frames[0]), None);
        // No sender makes this frame: it brings its symbol as the fourth of
        // the connection, and its row names the sixth.
        assert_eq!(brought(&frames[2..]), [[5, 1]]);
        frames[2][QWP_HEADER_SIZE] = 3;
        connection.receive(&frames[2]);
    }

    #[test]
    #[should_panic(expected = "a buffer with symbols needs the dictionary of its sender")]
    fn a_frame_of_a_buffer_with_symbols_needs_the_dictionary_of_its_sender() {
        frame_of_a_whole_buffer(&symbol_rows(TABLE, &[(0, "a", None)]), false);
    }

    /// One row short of the server's row limit is held; the row that reaches
    /// it is refused, because a server would commit there. The limit holds
    /// for each table by itself, wherever in a frame its block is.
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
        let other = frame_of_a_whole_buffer(&buffer_of("model_other", 0..1), true);
        let one_more = frame_of_a_whole_buffer(
            &buffer_of_tables(&[("model_other", 1..2), (TABLE, 0..1)]),
            true,
        );

        let server = QwpWsServerModel::new();
        let mut connection = server.connect();
        assert_eq!(connection.receive(&most), None);
        assert_eq!(connection.receive(&other), None);
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
    fn server_model_socket_ends_its_first_connection_after_the_frames_it_was_told() {
        let buffer = buffer_of(TABLE, 0..40);
        let frames = small_frames(&buffer);
        let last = frames.len() - 1;
        let server = QwpWsModelServer::start_cutting_first_connection(300, 2);

        // The connection lives after one frame and ends with the second.
        let mut cut = client_of(&server);
        read_upgrade_answer(&mut cut);
        write_server_frame(&mut cut, WS_OPCODE_BINARY, &frames[0], true).unwrap();
        write_server_frame(&mut cut, WS_OPCODE_PING, b"alive", true).unwrap();
        assert_eq!(
            read_frame(&mut cut).unwrap(),
            (true, WS_OPCODE_PONG, b"alive".to_vec())
        );
        write_server_frame(&mut cut, WS_OPCODE_BINARY, &frames[1], true).unwrap();
        let end = read_frame(&mut cut).unwrap_err();
        assert!(
            !matches!(
                end.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
            "{end}"
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while server.open_connections() != 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "the connection stayed open"
            );
            thread::yield_now();
        }
        assert_eq!(server.model.table(TABLE).unwrap().commits, 0);

        // The next connection is served to its end.
        let mut stream = client_of(&server);
        read_upgrade_answer(&mut stream);
        for frame in &frames {
            write_server_frame(&mut stream, WS_OPCODE_BINARY, frame, true).unwrap();
        }
        assert_eq!(
            read_frame(&mut stream).unwrap(),
            (true, WS_OPCODE_BINARY, ok(last, &[(TABLE, 1)]).unwrap())
        );
        let table = server.model.table(TABLE).unwrap();
        assert_eq!(table.commits, 1);
        assert_eq!(table.rows_as_text(), rows_of(TABLE, &buffer));
        server.finish();

        // A connection that ends with a frame without the flag: the frame
        // commits, and its answer never comes.
        let server = QwpWsModelServer::start_cutting_first_connection(300, 1);
        let mut cut = client_of(&server);
        read_upgrade_answer(&mut cut);
        write_server_frame(&mut cut, WS_OPCODE_BINARY, &frames[last], true).unwrap();
        let end = read_frame(&mut cut).unwrap_err();
        assert_eq!(end.kind(), std::io::ErrorKind::UnexpectedEof, "{end}");
        assert_eq!(server.model.table(TABLE).unwrap().commits, 1);
        server.finish();
    }

    #[test]
    fn server_model_socket_rejects_the_frame_it_was_told_and_takes_none_behind_it() {
        const STATUS: u8 = 0x03;
        let buffer = buffer_of(TABLE, 0..40);
        let frames = small_frames(&buffer);
        let last = frames.len() - 1;
        assert!(last >= 2, "{} frames", frames.len());
        let server = QwpWsModelServer::start(300);
        server.reject_frame(2, STATUS);

        // One answer to all the frames: the error, which names the second.
        let mut stream = client_of(&server);
        read_upgrade_answer(&mut stream);
        for frame in &frames {
            write_server_frame(&mut stream, WS_OPCODE_BINARY, frame, true).unwrap();
        }
        let (_fin, opcode, error) = read_frame(&mut stream).unwrap();
        assert_eq!(opcode, WS_OPCODE_BINARY);
        assert_eq!((error[0], &error[1..9]), (STATUS, &1u64.to_le_bytes()[..]));
        // The connection stays, and the frame that would have committed got
        // no answer.
        write_server_frame(&mut stream, WS_OPCODE_PING, b"alive", true).unwrap();
        assert_eq!(
            read_frame(&mut stream).unwrap(),
            (true, WS_OPCODE_PONG, b"alive".to_vec())
        );
        assert_eq!(server.frames_taken(), frames.len());
        assert_eq!(server.model.table(TABLE).unwrap().commits, 0);

        // The server rejects that one frame: the same frames are a commit on
        // a new connection.
        let mut again = client_of(&server);
        read_upgrade_answer(&mut again);
        for frame in &frames {
            write_server_frame(&mut again, WS_OPCODE_BINARY, frame, true).unwrap();
        }
        assert_eq!(
            read_frame(&mut again).unwrap(),
            (true, WS_OPCODE_BINARY, ok(last, &[(TABLE, 1)]).unwrap())
        );
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

    #[test]
    fn server_model_socket_holds_its_answers_back_until_they_are_let_go() {
        let frame = |ids| frame_of_a_whole_buffer(&buffer_of(TABLE, ids), false);
        let server = QwpWsModelServer::start(300);
        let mut stream = client_of(&server);
        read_upgrade_answer(&mut stream);

        server.hold_answers();
        write_server_frame(&mut stream, WS_OPCODE_BINARY, &frame(0..1), true).unwrap();
        write_server_frame(&mut stream, WS_OPCODE_BINARY, &frame(1..2), true).unwrap();
        // The answer to a ping is the next thing the server sends: it took
        // both frames, committed each and answered neither.
        write_server_frame(&mut stream, WS_OPCODE_PING, b"mark", true).unwrap();
        assert_eq!(
            read_frame(&mut stream).unwrap(),
            (true, WS_OPCODE_PONG, b"mark".to_vec())
        );
        assert_eq!(server.frames_taken(), 2);
        assert_eq!(server.model.table(TABLE).unwrap().commits, 2);

        server.let_answers_go();
        for (sequence, commit) in [(0, 1), (1, 2)] {
            assert_eq!(
                read_frame(&mut stream).unwrap(),
                (
                    true,
                    WS_OPCODE_BINARY,
                    ok(sequence, &[(TABLE, commit)]).unwrap()
                )
            );
        }
        // A later frame is answered at once again.
        write_server_frame(&mut stream, WS_OPCODE_BINARY, &frame(2..3), true).unwrap();
        assert_eq!(
            read_frame(&mut stream).unwrap(),
            (true, WS_OPCODE_BINARY, ok(2, &[(TABLE, 3)]).unwrap())
        );
        assert_eq!(server.frames_taken(), 3);
        drop(stream);
        server.finish();
    }

    #[test]
    fn server_model_socket_ends_every_connection_once_it_is_down() {
        let server = QwpWsModelServer::start(300);
        let mut stream = client_of(&server);
        read_upgrade_answer(&mut stream);
        assert_eq!(server.open_connections(), 1);

        server.go_down();
        // A read finds the end of the connection, or fails, before its
        // timeout.
        let ends = |mut stream: TcpStream| match stream.read(&mut [0u8; 1]) {
            Ok(read) => read == 0,
            Err(err) => !matches!(
                err.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
        };
        assert!(ends(stream));
        // So does a new connection, which gets no answer to an upgrade.
        let late = TcpStream::connect(("127.0.0.1", server.port)).unwrap();
        late.set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        assert!(ends(late));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while server.open_connections() != 0 {
            assert!(std::time::Instant::now() < deadline);
            thread::sleep(std::time::Duration::from_millis(1));
        }
        server.finish();
    }

    #[test]
    fn server_model_socket_does_not_wait_for_a_client_that_stays_connected() {
        // The clients neither read nor go away until the test ends.
        let limit = std::time::Duration::from_secs(10);

        let server = QwpWsModelServer::start(300);
        let mut idle = client_of(&server);
        read_upgrade_answer(&mut idle);
        assert_eq!(server.open_connections(), 1);
        let started = std::time::Instant::now();
        server.go_down();
        while server.open_connections() != 0 {
            assert!(
                started.elapsed() < limit,
                "a server that went down waits for its client to go away"
            );
            thread::sleep(std::time::Duration::from_millis(1));
        }
        server.finish();

        let server = QwpWsModelServer::start(300);
        let mut connected = client_of(&server);
        read_upgrade_answer(&mut connected);
        let started = std::time::Instant::now();
        server.finish();
        assert!(
            started.elapsed() < limit,
            "a server that stopped waited {:?} for its client to go away",
            started.elapsed()
        );
        drop((idle, connected));
    }
}
