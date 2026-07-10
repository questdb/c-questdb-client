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
//! These exercise the public product path against a real QuestDB server:
//! `Buffer -> replay payload -> frame queue -> QWP/WebSocket progress -> real WebSocket
//! transport -> queryable row`.

use std::fs;
use std::io::{Error as IoError, ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::ingress::{Buffer, QwpWsProgress, SenderBuilder, TimestampNanos};
use tempfile::TempDir;

use super::{TestError, TestResult};

type ProbeResult<T> = std::result::Result<T, TestError>;
type ProxyResult<T> = std::io::Result<T>;

#[derive(Clone, Debug)]
struct ProbeConfig {
    host: String,
    qwp_ws_port: u16,
    http_port: u16,
    auth_header: Option<String>,
}

#[test]
#[ignore = "requires a real QuestDB server and QDB_QWP_WS_PUBLIC_MANUAL_PROBE=1"]
fn qwp_ws_public_manual_sender_submit_waits_and_row_is_queryable() -> TestResult {
    if std::env::var("QDB_QWP_WS_PUBLIC_MANUAL_PROBE").as_deref() != Ok("1") {
        eprintln!("set QDB_QWP_WS_PUBLIC_MANUAL_PROBE=1 to run the public manual sender probe");
        return Ok(());
    }

    let config = ProbeConfig::from_env()?;
    if config.auth_header.is_some() {
        return Err(Box::new(IoError::new(
            ErrorKind::InvalidInput,
            "QDB_QWP_WS_PUBLIC_MANUAL_PROBE does not support QDB_QWP_WS_AUTH_HEADER yet; use an unauthenticated local QuestDB server",
        )));
    }

    let table = unique_table_name("qwp_public_manual_probe");
    eprintln!("QuestDB build: {}", query_build(&config)?);
    eprintln!("probe table: {table}");
    let _cleanup = TableCleanup::new(config.clone(), table.clone());

    let conf = format!(
        "qwpws::addr={}:{};max_in_flight=4;",
        config.host, config.qwp_ws_port
    );
    let mut sender = SenderBuilder::from_conf(conf)?
        .qwp_ws_progress(QwpWsProgress::Manual)?
        .build()?;
    let mut buffer = sender.new_buffer();
    write_row(&mut buffer, &table, "SYM_PUBLIC_MANUAL", 33, 333.5, 33)?;

    sender.flush_and_get_fsn(&mut buffer)?;
    assert!(buffer.is_empty());
    sender.wait(crate::ingress::AckLevel::Ok, Duration::from_secs(10))?;

    let count = wait_for_count(&config, &table, 1, Duration::from_secs(10))?;
    assert_eq!(count, 1);
    assert!(has_row(&config, &table, "SYM_PUBLIC_MANUAL", 33, 333.5)?);

    Ok(())
}

#[test]
#[ignore = "requires a real QuestDB server and QDB_QWP_WS_PUBLIC_SFA_PROBE=1"]
fn qwp_ws_public_sender_sfa_recovers_after_unacked_disconnect() -> TestResult {
    if std::env::var("QDB_QWP_WS_PUBLIC_SFA_PROBE").as_deref() != Ok("1") {
        eprintln!("set QDB_QWP_WS_PUBLIC_SFA_PROBE=1 to run the public Sender SFA probe");
        return Ok(());
    }

    let config = ProbeConfig::from_env()?;
    if config.auth_header.is_some() {
        return Err(Box::new(IoError::new(
            ErrorKind::InvalidInput,
            "QDB_QWP_WS_PUBLIC_SFA_PROBE does not support QDB_QWP_WS_AUTH_HEADER yet; use an unauthenticated local QuestDB server",
        )));
    }

    let table = unique_table_name("qwp_public_sfa_probe");
    eprintln!("QuestDB build: {}", query_build(&config)?);
    eprintln!("probe table: {table}");
    let _cleanup = TableCleanup::new(config.clone(), table.clone());
    let sf_dir = TempDir::new()?;
    let sender_id = "public_probe";
    let slot_dir = sfa_slot_dir_for_sender(sf_dir.path(), sender_id);

    let proxy = DropUnackedFrameProxy::spawn(&config)?;
    let first_conf = public_sfa_conf("127.0.0.1", proxy.port, sf_dir.path(), sender_id, true);
    {
        let mut sender = SenderBuilder::from_conf(first_conf)?.build()?;
        let mut buffer = sender.new_buffer();
        write_row(
            &mut buffer,
            &table,
            "SYM_PUBLIC_SFA_REPLAYED",
            77,
            777.5,
            77,
        )?;
        sender.flush(&mut buffer)?;
        assert!(
            buffer.is_empty(),
            "locally published QWP/WebSocket flush must clear the caller buffer"
        );
        proxy.join()?;
    }
    let retained_sfa_files = sfa_file_count(&slot_dir)?;
    assert!(
        retained_sfa_files > 0,
        "unACKed public Sender flush must leave its QWP frame recoverable"
    );

    let second_conf = public_sfa_conf(
        &config.host,
        config.qwp_ws_port,
        sf_dir.path(),
        sender_id,
        false,
    );
    {
        let mut sender = SenderBuilder::from_conf(second_conf)?.build()?;
        let mut buffer = sender.new_buffer();
        write_row(
            &mut buffer,
            &table,
            "SYM_PUBLIC_SFA_FOLLOWUP",
            88,
            888.5,
            88,
        )?;
        sender.flush(&mut buffer)?;

        let count = wait_for_count(&config, &table, 2, Duration::from_secs(10))?;
        assert_eq!(
            count, 2,
            "public Sender SFA recovery should deliver the retained row exactly once before the follow-up"
        );
        assert!(has_row(
            &config,
            &table,
            "SYM_PUBLIC_SFA_REPLAYED",
            77,
            777.5
        )?);
        assert!(has_row(
            &config,
            &table,
            "SYM_PUBLIC_SFA_FOLLOWUP",
            88,
            888.5
        )?);
    }

    Ok(())
}

fn write_row(
    buffer: &mut Buffer,
    table: &str,
    sym: &str,
    qty: i64,
    px: f64,
    ts_offset: i64,
) -> ProbeResult<()> {
    buffer
        .table(table)?
        .symbol("sym", sym)?
        .column_i64("qty", qty)?
        .column_f64("px", px)?
        .at(TimestampNanos::new(1_700_000_000_000_000_000 + ts_offset))?;
    Ok(())
}

fn public_sfa_conf(
    host: &str,
    port: u16,
    sf_dir: &Path,
    sender_id: &str,
    short_reconnect: bool,
) -> String {
    let mut conf = format!(
        "qwpws::addr={host}:{port};sf_dir={};sender_id={sender_id};sf_max_bytes=64k;sf_max_total_bytes=128k;max_in_flight=4;",
        sf_dir.display()
    );
    if short_reconnect {
        conf.push_str(
            "reconnect_max_duration_millis=25;reconnect_initial_backoff_millis=1;reconnect_max_backoff_millis=1;",
        );
    }
    conf
}

fn sfa_slot_dir_for_sender(sf_dir: &Path, sender_id: &str) -> PathBuf {
    sf_dir.join(sender_id)
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

struct DropUnackedFrameProxy {
    port: u16,
    handle: thread::JoinHandle<ProxyResult<()>>,
}

impl DropUnackedFrameProxy {
    fn spawn(config: &ProbeConfig) -> ProbeResult<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let target_host = config.host.clone();
        let target_port = config.qwp_ws_port;
        let handle =
            thread::spawn(move || run_drop_unacked_frame_proxy(listener, target_host, target_port));
        Ok(Self { port, handle })
    }

    fn join(self) -> ProbeResult<()> {
        match self.handle.join() {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => Err(Box::new(err)),
            Err(_) => Err(Box::new(IoError::other(
                "drop-unacked proxy thread panicked",
            ))),
        }
    }
}

fn run_drop_unacked_frame_proxy(
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

    let dropped_frame = read_ws_frame_raw(&mut client)?;
    if !dropped_frame.payload.starts_with(b"QWP1") {
        return Err(IoError::new(
            ErrorKind::InvalidData,
            "public SFA probe expected a QWP message frame",
        ));
    }

    drop(listener);
    drop(client);
    drop(upstream);
    Ok(())
}

fn accept_with_timeout(listener: &TcpListener, timeout: Duration) -> ProxyResult<TcpStream> {
    let deadline = Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok((stream, _addr)) => {
                stream.set_nonblocking(false)?;
                return Ok(stream);
            }
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
    payload: Vec<u8>,
}

fn read_ws_frame_raw(stream: &mut TcpStream) -> ProxyResult<RawWsFrame> {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header)?;
    let masked = header[1] & 0x80 != 0;
    let len_short = header[1] & 0x7f;
    let payload_len = match len_short {
        126 => {
            let mut bytes = [0u8; 2];
            stream.read_exact(&mut bytes)?;
            u16::from_be_bytes(bytes) as usize
        }
        127 => {
            let mut bytes = [0u8; 8];
            stream.read_exact(&mut bytes)?;
            u64::from_be_bytes(bytes) as usize
        }
        len => len as usize,
    };
    let mut mask = [0u8; 4];
    if masked {
        stream.read_exact(&mut mask)?;
    }
    let mut payload = vec![0u8; payload_len];
    stream.read_exact(&mut payload)?;
    if masked {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index & 3];
        }
    }
    Ok(RawWsFrame { payload })
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
        return Err(Box::new(IoError::other(format!(
            "QuestDB query failed for {sql:?}: {error}"
        ))));
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
