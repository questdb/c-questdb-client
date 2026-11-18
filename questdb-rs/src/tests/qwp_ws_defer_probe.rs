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

//! What a server does with the frames of one flush that is larger than a
//! frame: every frame but the last carries the defer flag. One script sends
//! such frames over a raw WebSocket and checks the answers and what the
//! tables hold afterwards. It runs against a real QuestDB server in an
//! ignored test, and against the server model of the tests
//! (`qwp_ws_server_model`) in a test that always runs, so the model is held
//! to what a real server showed.

use std::collections::BTreeSet;
use std::io::{Error as IoError, ErrorKind};
use std::net::{Shutdown, TcpStream};
use std::time::{Duration, Instant};

use crate::ingress::{
    Buffer, DurableAckTiers, TimestampNanos, perform_upgrade, write_binary_frame, write_ping_frame,
};
use crate::tests::qwp_decode::DecodedValue;
use crate::tests::qwp_ws::read_frame;
use crate::tests::qwp_ws_server_model::{QwpWsModelServer, frames_of_a_flush};

use super::TestResult;
use super::qwp_ws_protocol_probe::{
    ProbeConfig, ProbeResult, TableCleanup, query_build, query_json, unique_table_name,
};

const WS_OPCODE_BINARY: u8 = 0x2;
const WS_OPCODE_PONG: u8 = 0xA;
const QWP_STATUS_OK: u8 = 0x00;
const QWP_FLAGS_OFFSET: usize = 5;
const QWP_FLAG_DEFER_COMMIT: u8 = 0x01;
const BASE_TS_NANOS: i64 = 1_700_200_000_000_000_000;
/// The server commits a table by itself once it holds this many uncommitted
/// rows (`qwp.max.uncommitted.rows`). The groups of the script stay below.
const SERVER_MAX_UNCOMMITTED_ROWS: usize = 1_000_000;
/// The frame limit the model server advertises: small, for a quick test.
const MODEL_FRAME_LIMIT: usize = 16 * 1024;

#[test]
#[ignore = "requires a real QuestDB server and QDB_QWP_WS_DEFER_PROBE=1"]
fn qwp_ws_real_server_defer_rules_probe() -> TestResult {
    if std::env::var("QDB_QWP_WS_DEFER_PROBE").as_deref() != Ok("1") {
        eprintln!("set QDB_QWP_WS_DEFER_PROBE=1 to run the real-server defer rules probe");
        return Ok(());
    }

    let config = ProbeConfig::from_env()?;
    eprintln!("QuestDB build: {}", query_build(&config)?);
    // More than 16 MiB, the largest message the protocol has.
    let group_mib: usize = match std::env::var("QDB_QWP_WS_DEFER_PROBE_MIB") {
        Ok(value) => value.parse()?,
        Err(_) => 20,
    };
    run_defer_rules_script(
        &Server::Live(&config),
        &ScriptSettings {
            group_bytes: group_mib * 1024 * 1024,
            quiet: Duration::from_millis(300),
            settle: Duration::from_secs(1),
        },
    )
}

#[test]
fn qwp_ws_server_model_follows_the_defer_rules_of_a_real_server() -> TestResult {
    let server = QwpWsModelServer::start(MODEL_FRAME_LIMIT);
    run_defer_rules_script(
        &Server::Model(&server),
        &ScriptSettings {
            group_bytes: 12 * MODEL_FRAME_LIMIT,
            quiet: Duration::from_millis(20),
            settle: Duration::ZERO,
        },
    )?;
    server.finish();
    Ok(())
}

struct ScriptSettings {
    /// The least size of the buffer that is sent as the large group.
    group_bytes: usize,
    /// How long nothing may arrive for the server to count as silent.
    quiet: Duration,
    /// How long to give the server to notice a connection that went away.
    settle: Duration,
}

fn run_defer_rules_script(server: &Server<'_>, settings: &ScriptSettings) -> ProbeResult<()> {
    a_group_is_one_transaction(server, settings)?;
    the_same_frames_without_the_flag_are_a_transaction_each(server, settings)?;
    a_dropped_group_leaves_no_rows(server, settings)?;
    a_frame_of_the_advertised_limit_is_taken(server)?;
    Ok(())
}

/// No answer to a deferred frame; one OK at the commit frame, with its
/// sequence and the table's first transaction; the table then holds exactly
/// the rows, in one transaction.
fn a_group_is_one_transaction(server: &Server<'_>, settings: &ScriptSettings) -> ProbeResult<()> {
    let (table, _cleanup) = server.new_table("qwp_defer_group");
    let mut connection = server.connect()?;
    let limit = connection.frame_limit;
    let group = Group::of_bytes(&table, 0, settings.group_bytes)?;
    let frames = group.frames(limit);
    let last = frames.len() - 1;
    assert!(last >= 8, "{} frames", frames.len());

    let started = Instant::now();
    for frame in &frames[..last] {
        connection.send(frame)?;
    }
    connection.expect_no_answer_yet()?;
    let deferred_taken = started.elapsed();
    connection.expect_silence(settings.quiet)?;
    assert_eq!(server.row_count(&table)?, 0, "rows before the commit frame");

    let commit_sent = Instant::now();
    connection.send(&frames[last])?;
    assert_eq!(connection.expect_ok()?, OkAnswer::of(last, &table, 1));
    let committed = commit_sent.elapsed();
    server.wait_for_rows(&table, group.rows.len())?;
    let visible = commit_sent.elapsed();
    connection.expect_no_answer(settings.quiet)?;

    assert_eq!(server.digest(&table)?, Some(group.digest()));
    assert_eq!(server.transactions(&table)?, Some(1));
    eprintln!(
        "group: {} rows, {} bytes in the buffer, {} frames of at most {limit} bytes (largest \
         {}); the server took the deferred frames in {deferred_taken:?}, answered the commit \
         frame after {committed:?}, and showed the rows after {visible:?}",
        group.rows.len(),
        group.buffer.len(),
        frames.len(),
        frames.iter().map(Vec::len).max().unwrap(),
    );
    Ok(())
}

/// The control of [`a_group_is_one_transaction`]: the transaction count does
/// follow the flag. The next frame is sent when the last one is answered,
/// because a server may commit frames that arrive together as one
/// transaction.
fn the_same_frames_without_the_flag_are_a_transaction_each(
    server: &Server<'_>,
    settings: &ScriptSettings,
) -> ProbeResult<()> {
    let (table, _cleanup) = server.new_table("qwp_defer_control");
    let mut connection = server.connect()?;
    let group = Group::of_bytes(&table, 0, settings.group_bytes)?;
    let mut frames = group.frames(connection.frame_limit);
    for (sequence, frame) in frames.iter_mut().enumerate() {
        frame[QWP_FLAGS_OFFSET] &= !QWP_FLAG_DEFER_COMMIT;
        connection.send(frame)?;
        let transaction = sequence as i64 + 1;
        assert_eq!(
            connection.expect_ok()?,
            OkAnswer::of(sequence, &table, transaction)
        );
    }

    server.wait_for_rows(&table, group.rows.len())?;
    assert_eq!(server.digest(&table)?, Some(group.digest()));
    assert_eq!(server.transactions(&table)?, Some(frames.len() as i64));
    eprintln!("control: {} transactions", frames.len());
    Ok(())
}

/// A connection that goes away before its commit frame leaves no rows, and a
/// group on a new connection commits only itself.
fn a_dropped_group_leaves_no_rows(
    server: &Server<'_>,
    settings: &ScriptSettings,
) -> ProbeResult<()> {
    let (table, _cleanup) = server.new_table("qwp_defer_dropped");
    let mut connection = server.connect()?;
    let limit = connection.frame_limit;
    let dropped = Group::of_bytes(&table, 0, settings.group_bytes / 4)?;
    let frames = dropped.frames(limit);
    assert!(frames.len() >= 3, "{} frames", frames.len());
    for frame in &frames[..frames.len() - 1] {
        connection.send(frame)?;
    }
    // The server has taken every one of these frames when it answers the ping.
    connection.expect_no_answer(settings.quiet)?;
    connection.drop_without_close();
    server.wait_for_the_drop(settings.settle);
    assert_eq!(server.row_count(&table)?, 0, "rows of a dropped group");
    eprintln!(
        "after a dropped group: the table {}, transactions {:?}",
        if server.digest(&table)?.is_some() {
            "exists"
        } else {
            "does not exist"
        },
        server.transactions(&table)?,
    );

    // Other rows, so that a row of the dropped group would show.
    let mut connection = server.connect()?;
    let second = Group::of_bytes(&table, 1_000_000, settings.group_bytes / 4)?;
    let frames = second.frames(limit);
    let last = frames.len() - 1;
    assert!(last >= 2, "{} frames", frames.len());
    for frame in &frames[..last] {
        connection.send(frame)?;
    }
    connection.expect_no_answer(settings.quiet)?;
    connection.send(&frames[last])?;
    // The sequences of a new connection start at zero again, and the
    // dropped group took no transaction of the table.
    assert_eq!(connection.expect_ok()?, OkAnswer::of(last, &table, 1));

    server.wait_for_rows(&table, second.rows.len())?;
    assert_eq!(server.digest(&table)?, Some(second.digest()));
    assert_eq!(server.transactions(&table)?, Some(1));
    // And the rows of the dropped group do not come later.
    std::thread::sleep(settings.settle);
    assert_eq!(server.digest(&table)?, Some(second.digest()));
    assert_eq!(server.transactions(&table)?, Some(1));
    Ok(())
}

/// A frame of exactly the size the server advertised is taken.
fn a_frame_of_the_advertised_limit_is_taken(server: &Server<'_>) -> ProbeResult<()> {
    let (table, _cleanup) = server.new_table("qwp_defer_limit");
    let mut connection = server.connect()?;
    let limit = connection.frame_limit;
    // The last row is padded to fill the frame. First find by how much.
    let unpadded = Group::of_one_frame(&table, limit, 0)?;
    let padding = limit - unpadded.frames(usize::MAX)[0].len();
    let group = Group::of_one_frame(&table, limit, padding)?;
    let frames = group.frames(usize::MAX);
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].len(), limit);

    connection.send(&frames[0])?;
    assert_eq!(connection.expect_ok()?, OkAnswer::of(0, &table, 1));
    server.wait_for_rows(&table, group.rows.len())?;
    assert_eq!(server.digest(&table)?, Some(group.digest()));
    eprintln!(
        "a frame of exactly {limit} bytes ({} rows) was taken",
        group.rows.len()
    );
    Ok(())
}

/// The rows of one flush: a buffer, and what its rows are.
pub(super) struct Group {
    pub(super) buffer: Buffer,
    /// Per row its id and the length of its text.
    rows: Vec<(i64, usize)>,
}

impl Group {
    /// Rows from `first_id` on, until the buffer holds `bytes`.
    pub(super) fn of_bytes(table: &str, first_id: i64, bytes: usize) -> ProbeResult<Self> {
        let mut group = Self {
            buffer: Buffer::new_qwp_ws(),
            rows: Vec::new(),
        };
        let mut id = first_id;
        while group.buffer.len() < bytes {
            group.push(table, id, 150 + (id % 50) as usize)?;
            id += 1;
        }
        assert!(
            group.rows.len() < SERVER_MAX_UNCOMMITTED_ROWS,
            "a server commits a group of {} rows in parts",
            group.rows.len()
        );
        Ok(group)
    }

    /// Rows that fit one frame of `limit` bytes with some room to spare,
    /// then one row whose text is `last_text_len` long.
    fn of_one_frame(table: &str, limit: usize, last_text_len: usize) -> ProbeResult<Self> {
        let mut group = Self::of_bytes(table, 0, limit - 1024)?;
        group.push(table, group.rows.len() as i64, last_text_len)?;
        Ok(group)
    }

    /// One row: two numbers, a text, and its own timestamp. No symbols.
    fn push(&mut self, table: &str, id: i64, text_len: usize) -> ProbeResult<()> {
        let text = char::from(b'a' + (id % 26) as u8)
            .to_string()
            .repeat(text_len);
        self.buffer
            .table(table)?
            .column_i64("id", id)?
            .column_i64("mix", mix_of(id))?
            .column_str("txt", text)?
            .at(TimestampNanos::new(BASE_TS_NANOS + id * 1_000))?;
        self.rows.push((id, text_len));
        Ok(())
    }

    /// The frames of the flush: all but the last with the defer flag.
    fn frames(&self, target: usize) -> Vec<Vec<u8>> {
        let frames = frames_of_a_flush(&self.buffer, target);
        assert!(frames.iter().all(|frame| frame.len() <= target));
        frames
    }

    /// What a table holds when it holds exactly these rows.
    pub(super) fn digest(&self) -> Digest {
        Digest {
            rows: self.rows.len() as i64,
            ids: self.rows.len() as i64,
            min_id: self.rows.first().unwrap().0,
            max_id: self.rows.last().unwrap().0,
            mix_sum: self.rows.iter().map(|(id, _)| mix_of(*id)).sum(),
            text_bytes: self.rows.iter().map(|(_, len)| *len as i64).sum(),
            timestamps: self.rows.len() as i64,
        }
    }
}

/// A number per row that is not in step with the id.
fn mix_of(id: i64) -> i64 {
    id * 7_919 % 1_000_003
}

/// What a table holds, in numbers that change when a row is missing, there
/// twice, or altered.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Digest {
    rows: i64,
    /// Distinct ids.
    ids: i64,
    min_id: i64,
    max_id: i64,
    mix_sum: i64,
    text_bytes: i64,
    /// Distinct timestamps.
    timestamps: i64,
}

pub(super) enum Server<'a> {
    Live(&'a ProbeConfig),
    Model(&'a QwpWsModelServer),
}

impl Server<'_> {
    fn connect(&self) -> ProbeResult<Connection> {
        match self {
            Self::Live(config) => Connection::open(
                &config.host,
                config.qwp_ws_port,
                config.auth_header.as_deref(),
            ),
            Self::Model(server) => Connection::open("127.0.0.1", server.port, None),
        }
    }

    /// A table name of its own, and for a real server the drop of the table
    /// when the script is done with it.
    pub(super) fn new_table(&self, prefix: &str) -> (String, Option<TableCleanup>) {
        let table = unique_table_name(prefix);
        let cleanup = match self {
            Self::Live(config) => Some(TableCleanup::new((*config).clone(), table.clone())),
            Self::Model(_) => None,
        };
        (table, cleanup)
    }

    /// What the table holds. `None` when there is no such table.
    pub(super) fn digest(&self, table: &str) -> ProbeResult<Option<Digest>> {
        match self {
            Self::Live(config) => {
                let sql = format!(
                    "select count(), count_distinct(id), min(id), max(id), sum(mix), \
                     sum(length(txt)), count_distinct(timestamp) from '{table}'"
                );
                let Some(row) = first_row(config, &sql)? else {
                    return Ok(None);
                };
                Ok(Some(Digest {
                    rows: row[0],
                    ids: row[1],
                    min_id: row[2],
                    max_id: row[3],
                    mix_sum: row[4],
                    text_bytes: row[5],
                    timestamps: row[6],
                }))
            }
            Self::Model(server) => {
                let Some(table) = server.model.table(table) else {
                    return Ok(None);
                };
                let mut digest = Digest::default();
                let mut ids = BTreeSet::new();
                let mut timestamps = BTreeSet::new();
                for block in &table.blocks {
                    let column = |name: &str| {
                        block
                            .columns
                            .iter()
                            .position(|column| column.name == name)
                            .unwrap()
                    };
                    // The designated timestamp has no name on the wire.
                    let (id, mix, txt, timestamp) =
                        (column("id"), column("mix"), column("txt"), column(""));
                    for row in &block.rows {
                        match (&row[id], &row[mix], &row[txt], &row[timestamp]) {
                            (
                                DecodedValue::I64(id),
                                DecodedValue::I64(mix),
                                DecodedValue::String(txt),
                                DecodedValue::TimestampNanos(timestamp),
                            ) => {
                                ids.insert(*id);
                                timestamps.insert(*timestamp);
                                digest.rows += 1;
                                digest.mix_sum += mix;
                                digest.text_bytes += txt.len() as i64;
                            }
                            other => panic!("not a row of the script: {other:?}"),
                        }
                    }
                }
                digest.ids = ids.len() as i64;
                digest.min_id = ids.first().copied().unwrap_or_default();
                digest.max_id = ids.last().copied().unwrap_or_default();
                digest.timestamps = timestamps.len() as i64;
                Ok(Some(digest))
            }
        }
    }

    fn row_count(&self, table: &str) -> ProbeResult<i64> {
        Ok(self.digest(table)?.map_or(0, |digest| digest.rows))
    }

    /// How many transactions the table has. `None` when there is no such
    /// table.
    pub(super) fn transactions(&self, table: &str) -> ProbeResult<Option<i64>> {
        match self {
            Self::Live(config) => {
                let sql = format!("select count() from wal_transactions('{table}')");
                Ok(first_row(config, &sql)?.map(|row| row[0]))
            }
            Self::Model(server) => Ok(server.model.table(table).map(|table| table.commits as i64)),
        }
    }

    /// Waits until the server has seen that the last connection went away.
    /// The model server tells; a real server is given `settle`, and its log
    /// shows that it takes a few milliseconds.
    fn wait_for_the_drop(&self, settle: Duration) {
        match self {
            Self::Live(_) => std::thread::sleep(settle),
            Self::Model(server) => {
                let deadline = Instant::now() + Duration::from_secs(10);
                while server.open_connections() != 0 {
                    assert!(Instant::now() < deadline, "the drop went unnoticed");
                    std::thread::yield_now();
                }
            }
        }
    }

    /// A real server applies committed rows to the table a moment after it
    /// answered. The model has them at once.
    pub(super) fn wait_for_rows(&self, table: &str, rows: usize) -> ProbeResult<()> {
        let deadline = Instant::now() + Duration::from_secs(60);
        while matches!(self, Self::Live(_))
            && self.row_count(table)? < rows as i64
            && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(50));
        }
        Ok(())
    }
}

/// The first row of a query result as numbers, a null as zero. `None` when
/// the table of the query does not exist.
fn first_row(config: &ProbeConfig, sql: &str) -> ProbeResult<Option<Vec<i64>>> {
    let value = match query_json(config, sql) {
        Ok(value) => value,
        Err(err) if err.to_string().contains("table does not exist") => return Ok(None),
        Err(err) => return Err(err),
    };
    let row = value
        .get("dataset")
        .and_then(|dataset| dataset.as_array())
        .and_then(|rows| rows.first())
        .and_then(|row| row.as_array())
        .ok_or_else(|| invalid(format!("no row in the answer to {sql:?}: {value}")))?;
    Ok(Some(
        row.iter()
            .map(|cell| cell.as_i64().unwrap_or_default())
            .collect(),
    ))
}

fn invalid(message: String) -> IoError {
    IoError::new(ErrorKind::InvalidData, message)
}

/// A raw QWP/WebSocket connection, after the upgrade.
struct Connection {
    stream: TcpStream,
    send_buf: Vec<u8>,
    /// The frame limit the server advertised.
    frame_limit: usize,
    pings: u8,
}

#[derive(Debug, PartialEq, Eq)]
struct OkAnswer {
    sequence: u64,
    /// The tables the answer names, each with its transaction number.
    tables: Vec<(String, i64)>,
}

impl OkAnswer {
    /// The OK of frame `sequence`, which committed `table` as its
    /// transaction `transaction`.
    fn of(sequence: usize, table: &str, transaction: i64) -> Self {
        Self {
            sequence: sequence as u64,
            tables: vec![(table.to_string(), transaction)],
        }
    }
}

impl Connection {
    fn open(host: &str, port: u16, auth_header: Option<&str>) -> ProbeResult<Self> {
        let mut stream = TcpStream::connect((host, port))?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(30)))?;
        stream.set_nodelay(true)?;
        let (version, leftover, frame_limit) = perform_upgrade(
            &mut stream,
            &format!("{host}:{port}"),
            auth_header,
            1,
            Some("rust-qwp-defer-probe"),
            DurableAckTiers::Off,
        )?;
        assert_eq!(version, 1);
        assert!(leftover.is_empty(), "the server spoke first");
        assert!(frame_limit > 0, "the server advertised no frame limit");
        Ok(Self {
            stream,
            send_buf: Vec::new(),
            frame_limit,
            pings: 0,
        })
    }

    fn send(&mut self, frame: &[u8]) -> ProbeResult<()> {
        write_binary_frame(&mut self.stream, &mut self.send_buf, frame)?;
        Ok(())
    }

    /// The server has not answered a frame sent so far.
    fn expect_no_answer(&mut self, quiet: Duration) -> ProbeResult<()> {
        self.expect_no_answer_yet()?;
        self.expect_silence(quiet)
    }

    /// The server has taken every frame sent so far, and has not answered
    /// one: it answers in the order it takes frames, so an answer to an
    /// earlier frame would come before the pong of a ping sent now.
    fn expect_no_answer_yet(&mut self) -> ProbeResult<()> {
        let ping = [b'p', self.pings];
        self.pings += 1;
        write_ping_frame(&mut self.stream, &mut self.send_buf, &ping)?;
        let (_fin, opcode, payload) = read_frame(&mut self.stream)?;
        if opcode != WS_OPCODE_PONG || payload != ping {
            return Err(invalid(format!(
                "expected the pong of {ping:?}, got opcode {opcode:#x} with {} bytes: {:?}",
                payload.len(),
                &payload[..payload.len().min(64)]
            ))
            .into());
        }
        Ok(())
    }

    /// Nothing arrives for `quiet`: an answer the server still held back
    /// when it wrote a pong would follow at once.
    fn expect_silence(&mut self, quiet: Duration) -> ProbeResult<()> {
        self.stream.set_read_timeout(Some(quiet))?;
        let mut byte = [0u8; 1];
        let silent = match self.stream.peek(&mut byte) {
            Err(err) if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => Ok(()),
            Err(err) => Err(err),
            Ok(0) => Err(invalid("the server closed the connection".into())),
            Ok(_) => Err(invalid("the server sent something after the pong".into())),
        };
        self.stream
            .set_read_timeout(Some(Duration::from_secs(30)))?;
        Ok(silent?)
    }

    /// The next thing the server sends is an OK.
    fn expect_ok(&mut self) -> ProbeResult<OkAnswer> {
        let (_fin, opcode, payload) = read_frame(&mut self.stream)?;
        if opcode != WS_OPCODE_BINARY || payload.len() < 11 || payload[0] != QWP_STATUS_OK {
            return Err(invalid(format!(
                "expected an OK, got opcode {opcode:#x} with {} bytes: {:?} ({:?})",
                payload.len(),
                &payload[..payload.len().min(64)],
                String::from_utf8_lossy(&payload[payload.len().min(11)..])
            ))
            .into());
        }
        let sequence = u64::from_le_bytes(payload[1..9].try_into().unwrap());
        let table_count = u16::from_le_bytes([payload[9], payload[10]]);
        let mut tables = Vec::new();
        let mut pos = 11;
        for _ in 0..table_count {
            let name_len = usize::from(u16::from_le_bytes([payload[pos], payload[pos + 1]]));
            let name = String::from_utf8(payload[pos + 2..pos + 2 + name_len].to_vec())?;
            pos += 2 + name_len;
            tables.push((
                name,
                i64::from_le_bytes(payload[pos..pos + 8].try_into().unwrap()),
            ));
            pos += 8;
        }
        assert_eq!(pos, payload.len(), "bytes after the OK");
        Ok(OkAnswer { sequence, tables })
    }

    /// Goes away as a process that died would: no close frame.
    fn drop_without_close(self) {
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}
