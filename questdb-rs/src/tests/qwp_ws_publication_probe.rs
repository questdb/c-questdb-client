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

//! Ignored real-server probes for the Step 12 publication path.
//!
//! These exercise the prototype product path against a real QuestDB server:
//! `Buffer -> replay payload -> frame queue -> manual driver -> real WebSocket
//! transport -> queryable row`.

use std::fs;
use std::io::{Error as IoError, ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::ingress::qwp_ws_test_support::{
    CloseOutcome, DeliveryOutcome, ManualDriverPrototype, QwpWsPublicationDriver, SfaSlotOptions,
    SfaSlotQueue, VolatileFrameQueue, VolatileQueueOptions, connect_blocking_transport,
};
use crate::ingress::{Buffer, TimestampNanos};
use tempfile::TempDir;

use super::{TestError, TestResult};

type ProbeResult<T> = std::result::Result<T, TestError>;
type ProxyResult<T> = std::io::Result<T>;

const QWP_STATUS_OK: u8 = 0x00;
const QWP_STATUS_DURABLE_ACK: u8 = 0x02;

#[derive(Clone, Debug)]
struct ProbeConfig {
    host: String,
    qwp_ws_port: u16,
    http_port: u16,
    auth_header: Option<String>,
}

#[test]
#[ignore = "requires a real QuestDB server and QDB_QWP_WS_PUBLICATION_PROBE=1"]
fn qwp_ws_publication_driver_submit_waits_and_row_is_queryable() -> TestResult {
    if std::env::var("QDB_QWP_WS_PUBLICATION_PROBE").as_deref() != Ok("1") {
        eprintln!("set QDB_QWP_WS_PUBLICATION_PROBE=1 to run the real-server publication probe");
        return Ok(());
    }

    let config = ProbeConfig::from_env()?;
    let table = unique_table_name("qwp_publication_probe");
    eprintln!("QuestDB build: {}", query_build(&config)?);
    eprintln!("probe table: {table}");
    let _cleanup = TableCleanup::new(config.clone(), table.clone());

    let transport = connect_blocking_transport(
        config.host.clone(),
        config.qwp_ws_port.to_string(),
        config.auth_header.clone(),
    )?;
    let queue = VolatileFrameQueue::new(VolatileQueueOptions {
        max_frames: 8,
        max_bytes: 64 * 1024,
        max_in_flight: 4,
    })
    .map_err(proto_err)?;
    let driver = ManualDriverPrototype::from_queue(queue, transport);
    let mut publisher = QwpWsPublicationDriver::new(driver, 1);

    let mut buffer = Buffer::new_qwp();
    buffer
        .table(table.as_str())?
        .symbol("sym", "SYM_PUBLICATION")?
        .column_i64("qty", 42)?
        .column_f64("px", 123.5)?
        .at(TimestampNanos::new(1_700_000_000_000_000_042))?;

    let receipt = publisher
        .try_submit_qwp(buffer.as_qwp().unwrap())
        .map_err(proto_err)?;
    let outcome = publisher.wait_steps(receipt, 8).map_err(proto_err)?;

    assert_eq!(outcome, DeliveryOutcome::Acked);
    let count = wait_for_count(&config, &table, 1, Duration::from_secs(10))?;
    assert_eq!(count, 1);
    assert!(
        has_publication_row(&config, &table)?,
        "expected row with sym=SYM_PUBLICATION, qty=42, px=123.5"
    );

    Ok(())
}

#[test]
#[ignore = "requires a real QuestDB server and QDB_QWP_WS_RECONNECT_PROBE=1"]
fn qwp_ws_publication_driver_reconnect_replays_only_unacked_rows() -> TestResult {
    if std::env::var("QDB_QWP_WS_RECONNECT_PROBE").as_deref() != Ok("1") {
        eprintln!("set QDB_QWP_WS_RECONNECT_PROBE=1 to run the real-server reconnect probe");
        return Ok(());
    }

    let config = ProbeConfig::from_env()?;
    let table = unique_table_name("qwp_reconnect_probe");
    eprintln!("QuestDB build: {}", query_build(&config)?);
    eprintln!("probe table: {table}");
    let _cleanup = TableCleanup::new(config.clone(), table.clone());
    let proxy = FaultProxy::spawn(&config)?;

    let transport = connect_blocking_transport(
        "127.0.0.1",
        proxy.port.to_string(),
        config.auth_header.clone(),
    )?;
    let queue = VolatileFrameQueue::new(VolatileQueueOptions {
        max_frames: 8,
        max_bytes: 64 * 1024,
        max_in_flight: 4,
    })
    .map_err(proto_err)?;
    let driver = ManualDriverPrototype::from_queue(queue, transport);
    let mut publisher = QwpWsPublicationDriver::new(driver, 1);

    let first = build_row(&table, "SYM_RECONNECT_ACKED", 10, 100.5, 10)?;
    let second = build_row(&table, "SYM_RECONNECT_REPLAYED", 20, 200.5, 20)?;
    let first_receipt = publisher
        .try_submit_qwp(first.as_qwp().unwrap())
        .map_err(proto_err)?;
    let second_receipt = publisher
        .try_submit_qwp(second.as_qwp().unwrap())
        .map_err(proto_err)?;

    let second_outcome = publisher.wait_steps(second_receipt, 16).map_err(proto_err);
    let proxy_result = proxy.join();
    assert_eq!(second_outcome?, DeliveryOutcome::Acked);
    assert_eq!(
        publisher.wait_steps(first_receipt, 0).map_err(proto_err)?,
        DeliveryOutcome::Acked
    );
    proxy_result?;

    let count = wait_for_count(&config, &table, 2, Duration::from_secs(10))?;
    assert_eq!(
        count, 2,
        "reconnect replay should not duplicate the already-ACKed first row"
    );
    assert!(has_row(&config, &table, "SYM_RECONNECT_ACKED", 10, 100.5)?);
    assert!(has_row(
        &config,
        &table,
        "SYM_RECONNECT_REPLAYED",
        20,
        200.5
    )?);

    Ok(())
}

#[test]
#[ignore = "requires a real QuestDB server and QDB_QWP_WS_SFA_PROBE=1"]
fn qwp_ws_sfa_recovered_frame_is_delivered_and_cleaned_up() -> TestResult {
    if std::env::var("QDB_QWP_WS_SFA_PROBE").as_deref() != Ok("1") {
        eprintln!("set QDB_QWP_WS_SFA_PROBE=1 to run the real-server SFA replay probe");
        return Ok(());
    }

    let config = ProbeConfig::from_env()?;
    let table = unique_table_name("qwp_sfa_probe");
    eprintln!("QuestDB build: {}", query_build(&config)?);
    eprintln!("probe table: {table}");
    let _cleanup = TableCleanup::new(config.clone(), table.clone());
    let sf_dir = TempDir::new()?;

    let receipt = {
        let transport = connect_blocking_transport(
            config.host.clone(),
            config.qwp_ws_port.to_string(),
            config.auth_header.clone(),
        )?;
        let queue = SfaSlotQueue::open(sfa_options(sf_dir.path())).map_err(proto_err)?;
        let driver = ManualDriverPrototype::from_queue(queue, transport);
        let mut publisher = QwpWsPublicationDriver::new(driver, 1);
        let row = build_row(&table, "SYM_SFA_REPLAYED", 77, 777.5, 77)?;

        publisher
            .try_submit_qwp(row.as_qwp().unwrap())
            .map_err(proto_err)?
    };
    assert_eq!(
        sfa_file_count(&sfa_slot_dir(sf_dir.path()))?,
        1,
        "unacknowledged SFA frame must remain recoverable after sender drop"
    );

    let transport = connect_blocking_transport(
        config.host.clone(),
        config.qwp_ws_port.to_string(),
        config.auth_header.clone(),
    )?;
    let queue = SfaSlotQueue::open(sfa_options(sf_dir.path())).map_err(proto_err)?;
    let driver = ManualDriverPrototype::from_queue(queue, transport);
    let mut publisher = QwpWsPublicationDriver::new(driver, 1);

    assert_eq!(
        publisher.wait_steps(receipt, 8).map_err(proto_err)?,
        DeliveryOutcome::Acked
    );
    assert_eq!(
        publisher.close_drain_steps(0).map_err(proto_err)?,
        CloseOutcome::Drained
    );
    assert_eq!(
        sfa_file_count(&sfa_slot_dir(sf_dir.path()))?,
        0,
        "cleanly ACKed SFA frames must not replay on the next sender"
    );

    let count = wait_for_count(&config, &table, 1, Duration::from_secs(10))?;
    assert_eq!(count, 1);
    assert!(has_row(&config, &table, "SYM_SFA_REPLAYED", 77, 777.5)?);

    Ok(())
}

fn build_row(table: &str, sym: &str, qty: i64, px: f64, ts_offset: i64) -> ProbeResult<Buffer> {
    let mut buffer = Buffer::new_qwp();
    buffer
        .table(table)?
        .symbol("sym", sym)?
        .column_i64("qty", qty)?
        .column_f64("px", px)?
        .at(TimestampNanos::new(1_700_000_000_000_000_000 + ts_offset))?;
    Ok(buffer)
}

fn sfa_options(sf_dir: &Path) -> SfaSlotOptions {
    SfaSlotOptions {
        sf_dir: sf_dir.to_path_buf(),
        sender_id: "default".to_string(),
        segment_size_bytes: 64 * 1024,
        max_frames: 8,
        max_bytes: 64 * 1024,
        max_in_flight: 4,
    }
}

fn sfa_slot_dir(sf_dir: &Path) -> std::path::PathBuf {
    sf_dir.join("default")
}

fn sfa_file_count(dir: &Path) -> ProbeResult<usize> {
    let mut count = 0usize;
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(".sfa"))
        {
            count += 1;
        }
    }
    Ok(count)
}

struct TableCleanup {
    config: ProbeConfig,
    table: String,
    keep: bool,
}

impl TableCleanup {
    fn new(config: ProbeConfig, table: String) -> Self {
        Self {
            config,
            table,
            keep: std::env::var("QDB_QWP_WS_KEEP_TABLE").as_deref() == Ok("1"),
        }
    }
}

impl Drop for TableCleanup {
    fn drop(&mut self) {
        if self.keep {
            eprintln!(
                "keeping probe table {} because QDB_QWP_WS_KEEP_TABLE=1",
                self.table
            );
            return;
        }
        let sql = format!("drop table if exists '{}'", self.table);
        if let Err(err) = query_json(&self.config, &sql) {
            eprintln!("failed to drop probe table {}: {err}", self.table);
        }
    }
}

impl ProbeConfig {
    fn from_env() -> ProbeResult<Self> {
        let host = std::env::var("QDB_QWP_WS_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
        let qwp_ws_port = parse_port("QDB_QWP_WS_PORT", 9000)?;
        let http_port = parse_port("QDB_QWP_WS_HTTP_PORT", qwp_ws_port)?;
        let auth_header = std::env::var("QDB_QWP_WS_AUTH_HEADER").ok();
        Ok(Self {
            host,
            qwp_ws_port,
            http_port,
            auth_header,
        })
    }
}

struct FaultProxy {
    port: u16,
    handle: thread::JoinHandle<ProxyResult<()>>,
}

impl FaultProxy {
    fn spawn(config: &ProbeConfig) -> ProbeResult<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let target_host = config.host.clone();
        let target_port = config.qwp_ws_port;
        let handle =
            thread::spawn(move || run_reconnect_fault_proxy(listener, target_host, target_port));
        Ok(Self { port, handle })
    }

    fn join(self) -> ProbeResult<()> {
        match self.handle.join() {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => Err(Box::new(err)),
            Err(_) => Err(Box::new(IoError::new(
                ErrorKind::Other,
                "fault proxy thread panicked",
            ))),
        }
    }
}

fn run_reconnect_fault_proxy(
    listener: TcpListener,
    target_host: String,
    target_port: u16,
) -> ProxyResult<()> {
    let target = format!("{target_host}:{target_port}");

    let mut client = accept_with_timeout(&listener, Duration::from_secs(10))?;
    let mut upstream = TcpStream::connect(&target)?;
    configure_stream(&mut client)?;
    configure_stream(&mut upstream)?;
    proxy_handshake(&mut client, &mut upstream)?;

    let first_frame = read_ws_frame_raw(&mut client)?;
    upstream.write_all(&first_frame.raw)?;
    upstream.flush()?;
    forward_until_ok(&mut upstream, &mut client, 0)?;

    let _dropped_unacked_frame = read_ws_frame_raw(&mut client)?;
    drop(client);
    drop(upstream);

    let mut client = accept_with_timeout(&listener, Duration::from_secs(10))?;
    let mut upstream = TcpStream::connect(&target)?;
    configure_stream(&mut client)?;
    configure_stream(&mut upstream)?;
    proxy_handshake(&mut client, &mut upstream)?;

    let replayed_frame = read_ws_frame_raw(&mut client)?;
    upstream.write_all(&replayed_frame.raw)?;
    upstream.flush()?;
    forward_until_ok(&mut upstream, &mut client, 0)?;

    Ok(())
}

fn accept_with_timeout(listener: &TcpListener, timeout: Duration) -> ProxyResult<TcpStream> {
    let deadline = Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok((stream, _addr)) => return Ok(stream),
            Err(err) if err.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                return Err(IoError::new(
                    ErrorKind::TimedOut,
                    "timed out waiting for reconnect probe client",
                ));
            }
            Err(err) => return Err(err),
        }
    }
}

fn configure_stream(stream: &mut TcpStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    stream.set_nodelay(true).ok();
    Ok(())
}

fn proxy_handshake(client: &mut TcpStream, upstream: &mut TcpStream) -> ProxyResult<()> {
    let request = read_until_http_header_end(client)?;
    upstream.write_all(&request)?;
    upstream.flush()?;

    let response = read_until_http_header_end(upstream)?;
    client.write_all(&response)?;
    client.flush()?;
    Ok(())
}

fn read_until_http_header_end(stream: &mut TcpStream) -> ProxyResult<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte)?;
        bytes.push(byte[0]);
        if bytes.ends_with(b"\r\n\r\n") {
            return Ok(bytes);
        }
        if bytes.len() > 64 * 1024 {
            return Err(IoError::new(
                ErrorKind::InvalidData,
                "HTTP header exceeded 64 KiB in reconnect fault proxy",
            ));
        }
    }
}

struct RawWsFrame {
    raw: Vec<u8>,
    payload: Vec<u8>,
}

fn read_ws_frame_raw(stream: &mut TcpStream) -> ProxyResult<RawWsFrame> {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header)?;
    let mut raw = header.to_vec();
    let masked = header[1] & 0x80 != 0;
    let len_short = header[1] & 0x7f;
    let payload_len = match len_short {
        126 => {
            let mut bytes = [0u8; 2];
            stream.read_exact(&mut bytes)?;
            raw.extend_from_slice(&bytes);
            u16::from_be_bytes(bytes) as usize
        }
        127 => {
            let mut bytes = [0u8; 8];
            stream.read_exact(&mut bytes)?;
            raw.extend_from_slice(&bytes);
            u64::from_be_bytes(bytes) as usize
        }
        len => len as usize,
    };
    let mut mask = [0u8; 4];
    if masked {
        stream.read_exact(&mut mask)?;
        raw.extend_from_slice(&mask);
    }
    let mut payload = vec![0u8; payload_len];
    stream.read_exact(&mut payload)?;
    raw.extend_from_slice(&payload);
    if masked {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index & 3];
        }
    }
    Ok(RawWsFrame { raw, payload })
}

fn forward_until_ok(
    upstream: &mut TcpStream,
    client: &mut TcpStream,
    target_sequence: u64,
) -> ProxyResult<()> {
    loop {
        let frame = read_ws_frame_raw(upstream)?;
        client.write_all(&frame.raw)?;
        client.flush()?;
        match qwp_response_kind(&frame.payload)? {
            QwpResponseKind::Ok { sequence } if sequence == target_sequence => return Ok(()),
            QwpResponseKind::Ok { sequence } => {
                return Err(IoError::new(
                    ErrorKind::InvalidData,
                    format!("expected OK sequence {target_sequence}, got {sequence}"),
                ));
            }
            QwpResponseKind::DurableAck => {}
            QwpResponseKind::Other(status) => {
                return Err(IoError::new(
                    ErrorKind::InvalidData,
                    format!("unexpected QWP response status 0x{status:02x}"),
                ));
            }
        }
    }
}

enum QwpResponseKind {
    Ok { sequence: u64 },
    DurableAck,
    Other(u8),
}

fn qwp_response_kind(payload: &[u8]) -> ProxyResult<QwpResponseKind> {
    let status = *payload
        .first()
        .ok_or_else(|| IoError::new(ErrorKind::UnexpectedEof, "empty QWP response"))?;
    match status {
        QWP_STATUS_OK => {
            if payload.len() < 9 {
                return Err(IoError::new(
                    ErrorKind::UnexpectedEof,
                    "QWP OK response missing sequence",
                ));
            }
            Ok(QwpResponseKind::Ok {
                sequence: u64::from_le_bytes(payload[1..9].try_into().unwrap()),
            })
        }
        QWP_STATUS_DURABLE_ACK => Ok(QwpResponseKind::DurableAck),
        other => Ok(QwpResponseKind::Other(other)),
    }
}

fn parse_port(name: &str, default: u16) -> ProbeResult<u16> {
    match std::env::var(name) {
        Ok(value) => Ok(value.parse()?),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(err) => Err(Box::new(err)),
    }
}

fn unique_table_name(prefix: &str) -> String {
    let since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    format!("{prefix}_{}_{}", std::process::id(), since_epoch)
}

fn query_build(config: &ProbeConfig) -> ProbeResult<String> {
    let value = query_json(config, "select build")?;
    let build = value
        .get("dataset")
        .and_then(|dataset| dataset.as_array())
        .and_then(|rows| rows.first())
        .and_then(|row| row.as_array())
        .and_then(|row| row.first())
        .and_then(|build| build.as_str())
        .unwrap_or("<unknown>");
    Ok(build.to_string())
}

fn wait_for_count(
    config: &ProbeConfig,
    table: &str,
    expected: usize,
    timeout: Duration,
) -> ProbeResult<usize> {
    let deadline = Instant::now() + timeout;
    let sql = format!("select count() from '{table}'");
    let mut last_count = 0usize;
    while Instant::now() < deadline {
        match query_json(config, &sql).and_then(|value| extract_count(&value)) {
            Ok(count) if count >= expected => return Ok(count),
            Ok(count) => last_count = count,
            Err(_) => {}
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(Box::new(IoError::new(
        ErrorKind::TimedOut,
        format!("timed out waiting for {expected} rows in {table}; last count {last_count}"),
    )))
}

fn has_publication_row(config: &ProbeConfig, table: &str) -> ProbeResult<bool> {
    has_row(config, table, "SYM_PUBLICATION", 42, 123.5)
}

fn has_row(
    config: &ProbeConfig,
    table: &str,
    expected_sym: &str,
    expected_qty: i64,
    expected_px: f64,
) -> ProbeResult<bool> {
    let sql = format!("select sym, qty, px from '{table}' where qty = {expected_qty}");
    let value = query_json(config, &sql)?;
    let Some(rows) = value.get("dataset").and_then(|dataset| dataset.as_array()) else {
        return Ok(false);
    };
    Ok(rows.iter().any(|row| {
        let Some(row) = row.as_array() else {
            return false;
        };
        row.first().and_then(|value| value.as_str()) == Some(expected_sym)
            && row.get(1).and_then(|value| value.as_i64()) == Some(expected_qty)
            && row.get(2).and_then(|value| value.as_f64()) == Some(expected_px)
    }))
}

fn query_json(config: &ProbeConfig, sql: &str) -> ProbeResult<serde_json::Value> {
    let url = format!(
        "http://{}:{}/exec?query={}",
        config.host,
        config.http_port,
        url_encode(sql)
    );
    let request = ureq::get(&url)
        .config()
        .timeout_per_call(Some(Duration::from_secs(5)))
        .build();
    let request = match config.auth_header.as_ref() {
        Some(auth) => request.header("Authorization", auth),
        None => request,
    };
    let response = request.call()?;
    let body = response.into_body().read_to_vec()?;
    let value: serde_json::Value = serde_json::from_slice(&body)?;
    if let Some(error) = value.get("error").and_then(|err| err.as_str()) {
        return Err(Box::new(IoError::new(
            ErrorKind::Other,
            format!("QuestDB query failed for {sql:?}: {error}"),
        )));
    }
    Ok(value)
}

fn extract_count(value: &serde_json::Value) -> ProbeResult<usize> {
    value
        .get("dataset")
        .and_then(|dataset| dataset.as_array())
        .and_then(|rows| rows.first())
        .and_then(|row| row.as_array())
        .and_then(|row| row.first())
        .and_then(|count| count.as_u64())
        .map(|count| count as usize)
        .ok_or_else(|| {
            Box::new(IoError::new(
                ErrorKind::InvalidData,
                format!("could not read count() from query response: {value}"),
            )) as TestError
        })
}

fn url_encode(input: &str) -> String {
    let mut out = String::new();
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn proto_err(err: impl std::fmt::Debug) -> TestError {
    Box::new(IoError::new(ErrorKind::Other, format!("{err:?}")))
}
