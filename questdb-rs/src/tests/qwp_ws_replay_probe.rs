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

//! Ignored real-server probe for Step 4 of
//! `doc/QWP_WEBSOCKET_VALIDATION_PLAN.md`.
//!
//! This test intentionally bypasses the sync sender's normal WebSocket encoder:
//! it builds replay-mode QWP payloads directly, opens a fresh WebSocket
//! connection for each send, and verifies rows through QuestDB's HTTP query API.

use std::io::{Error as IoError, ErrorKind};
use std::net::TcpStream;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::ingress::{
    Buffer, QwpWsEncodeScratch, SymbolGlobalDict, TimestampNanos, perform_upgrade, read_message,
    write_binary_frame,
};

use super::{TestError, TestResult};

const WS_OPCODE_BINARY: u8 = 0x02;
const QWP_FLAG_DELTA_SYMBOL_DICT: u8 = 0x08;
const QWP_STATUS_OK: u8 = 0x00;
const QWP_STATUS_DURABLE_ACK: u8 = 0x02;
const SYMBOL_COUNT: usize = 10;
const BASE_TS_NANOS: i64 = 1_700_000_000_000_000_000;
const FIRST_WIRE_SEQUENCE: u64 = 0;

type ProbeResult<T> = std::result::Result<T, TestError>;

#[derive(Clone, Debug)]
struct ProbeConfig {
    host: String,
    qwp_ws_port: u16,
    http_port: u16,
    auth_header: Option<String>,
}

#[derive(Debug)]
struct PayloadMetrics {
    len: usize,
    flags: u8,
    table_count: u16,
    payload_len: u32,
    delta_start: u64,
    delta_count: u64,
}

#[test]
#[ignore = "requires a real QuestDB server and QDB_QWP_WS_REPLAY_PROBE=1"]
fn qwp_ws_replay_frame_is_self_sufficient_on_fresh_connection() -> TestResult {
    if std::env::var("QDB_QWP_WS_REPLAY_PROBE").as_deref() != Ok("1") {
        eprintln!("set QDB_QWP_WS_REPLAY_PROBE=1 to run the real-server replay probe");
        return Ok(());
    }

    let config = ProbeConfig::from_env()?;
    let table = unique_table_name();
    let (first_payload, second_payload, first_metrics, second_metrics) =
        build_replay_payloads(&table)?;

    eprintln!("QuestDB build: {}", query_build(&config)?);
    eprintln!("probe table: {table}");
    let _cleanup = TableCleanup::new(config.clone(), table.clone());
    log_payload_metrics("first replay payload", &first_metrics);
    log_payload_metrics("second replay payload", &second_metrics);

    let first_ack = send_one_replay_payload(&config, &first_payload, FIRST_WIRE_SEQUENCE)?;
    let second_ack = send_one_replay_payload(&config, &second_payload, FIRST_WIRE_SEQUENCE)?;
    eprintln!("first connection acked QWP sequence {first_ack}");
    eprintln!("fresh connection acked replay QWP sequence {second_ack}");

    let count = wait_for_count(&config, &table, SYMBOL_COUNT + 1, Duration::from_secs(10))?;
    assert_eq!(count, SYMBOL_COUNT + 1);
    assert!(
        has_replayed_row(&config, &table)?,
        "expected replayed row with sym=SYM_009 and qty=99"
    );

    Ok(())
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

fn parse_port(name: &str, default: u16) -> ProbeResult<u16> {
    match std::env::var(name) {
        Ok(value) => Ok(value.parse()?),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(err) => Err(Box::new(err)),
    }
}

fn unique_table_name() -> String {
    let since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    format!("qwp_replay_probe_{}_{}", std::process::id(), since_epoch)
}

fn build_replay_payloads(
    table: &str,
) -> ProbeResult<(Vec<u8>, Vec<u8>, PayloadMetrics, PayloadMetrics)> {
    let mut scratch = QwpWsEncodeScratch::new();
    let mut global_dict = SymbolGlobalDict::new();

    let mut first = Buffer::new_qwp();
    for idx in 0..SYMBOL_COUNT {
        let sym = format!("SYM_{idx:03}");
        first
            .table(table)?
            .symbol("sym", sym)?
            .column_i64("qty", idx as i64)?
            .column_f64("px", 100.0 + idx as f64)?
            .at(TimestampNanos::new(BASE_TS_NANOS + idx as i64))?;
    }
    first
        .as_qwp()
        .unwrap()
        .encode_ws_replay_message(&mut scratch, &mut global_dict, 1)?;
    let first_payload = scratch.message.clone();
    let first_metrics = payload_metrics(&first_payload)?;
    assert_replay_metrics("first payload", &first_metrics, SYMBOL_COUNT as u64);

    let mut second = Buffer::new_qwp();
    second
        .table(table)?
        .symbol("sym", "SYM_009")?
        .column_i64("qty", 99)?
        .column_f64("px", 999.5)?
        .at(TimestampNanos::new(BASE_TS_NANOS + 1_000))?;
    second
        .as_qwp()
        .unwrap()
        .encode_ws_replay_message(&mut scratch, &mut global_dict, 1)?;
    let second_payload = scratch.message.clone();
    let second_metrics = payload_metrics(&second_payload)?;
    assert_replay_metrics("second payload", &second_metrics, SYMBOL_COUNT as u64);

    Ok((first_payload, second_payload, first_metrics, second_metrics))
}

fn send_one_replay_payload(
    config: &ProbeConfig,
    payload: &[u8],
    expected_seq: u64,
) -> ProbeResult<u64> {
    let addr = format!("{}:{}", config.host, config.qwp_ws_port);
    let mut stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    stream.set_nodelay(true).ok();

    let host_header = format!("{}:{}", config.host, config.qwp_ws_port);
    perform_upgrade(
        &mut stream,
        &host_header,
        config.auth_header.as_deref(),
        1,
        Some("rust-qwp-replay-probe"),
        false,
    )?;

    let mut send_buf = Vec::new();
    write_binary_frame(&mut stream, &mut send_buf, payload)?;

    let mut scratch = Vec::new();
    let mut response = Vec::new();
    loop {
        let opcode = read_message(&mut stream, &mut scratch, &mut response)?;
        if opcode != WS_OPCODE_BINARY {
            return Err(Box::new(IoError::new(
                ErrorKind::InvalidData,
                format!("expected binary QWP response, got opcode 0x{opcode:x}"),
            )));
        }
        let status = *response
            .first()
            .ok_or_else(|| IoError::new(ErrorKind::UnexpectedEof, "empty QWP response frame"))?;
        match status {
            QWP_STATUS_OK => {
                let seq = response_sequence(&response)?;
                if seq != expected_seq {
                    return Err(Box::new(IoError::new(
                        ErrorKind::InvalidData,
                        format!("expected QWP sequence {expected_seq}, got {seq}"),
                    )));
                }
                return Ok(seq);
            }
            QWP_STATUS_DURABLE_ACK => continue,
            other => {
                let detail = qwp_error_detail(&response);
                return Err(Box::new(IoError::new(
                    ErrorKind::InvalidData,
                    format!("server rejected QWP frame with status 0x{other:02x}{detail}"),
                )));
            }
        }
    }
}

fn response_sequence(response: &[u8]) -> ProbeResult<u64> {
    if response.len() < 9 {
        return Err(Box::new(IoError::new(
            ErrorKind::UnexpectedEof,
            "QWP response missing sequence",
        )));
    }
    Ok(u64::from_le_bytes(response[1..9].try_into().unwrap()))
}

fn qwp_error_detail(response: &[u8]) -> String {
    if response.len() < 11 {
        return String::new();
    }
    let sequence = u64::from_le_bytes(response[1..9].try_into().unwrap());
    let msg_len = u16::from_le_bytes(response[9..11].try_into().unwrap()) as usize;
    let msg_end = 11usize.saturating_add(msg_len);
    if response.len() < msg_end {
        return format!(" (sequence={sequence}, truncated error message)");
    }
    match std::str::from_utf8(&response[11..msg_end]) {
        Ok(message) => format!(" (sequence={sequence}, message={message})"),
        Err(_) => format!(" (sequence={sequence}, non-UTF-8 error message)"),
    }
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

fn has_replayed_row(config: &ProbeConfig, table: &str) -> ProbeResult<bool> {
    let sql = format!("select sym, qty, px from '{table}' where qty = 99");
    let value = query_json(config, &sql)?;
    let Some(rows) = value.get("dataset").and_then(|dataset| dataset.as_array()) else {
        return Ok(false);
    };
    Ok(rows.iter().any(|row| {
        let Some(row) = row.as_array() else {
            return false;
        };
        row.first().and_then(|value| value.as_str()) == Some("SYM_009")
            && row.get(1).and_then(|value| value.as_i64()) == Some(99)
            && row.get(2).and_then(|value| value.as_f64()) == Some(999.5)
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

fn log_payload_metrics(label: &str, metrics: &PayloadMetrics) {
    eprintln!(
        "{label}: len={}, flags=0x{:02x}, table_count={}, payload_len={}, delta_start={}, delta_count={}",
        metrics.len,
        metrics.flags,
        metrics.table_count,
        metrics.payload_len,
        metrics.delta_start,
        metrics.delta_count
    );
}

fn assert_replay_metrics(label: &str, metrics: &PayloadMetrics, expected_delta_count: u64) {
    assert_eq!(
        metrics.flags & QWP_FLAG_DELTA_SYMBOL_DICT,
        QWP_FLAG_DELTA_SYMBOL_DICT,
        "{label} must use delta-symbol-dict mode"
    );
    assert_eq!(metrics.table_count, 1, "{label} should contain one table");
    assert_eq!(
        metrics.payload_len as usize + 12,
        metrics.len,
        "{label} QWP payload_len must match message length"
    );
    assert_eq!(
        metrics.delta_start, 0,
        "{label} must replay symbols from global id 0"
    );
    assert_eq!(
        metrics.delta_count, expected_delta_count,
        "{label} must carry the dense symbol prefix through the referenced high id"
    );
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
            )) as Box<dyn std::error::Error>
        })
}

fn payload_metrics(payload: &[u8]) -> ProbeResult<PayloadMetrics> {
    if payload.len() < 12 || &payload[0..4] != b"QWP1" {
        return Err(Box::new(IoError::new(
            ErrorKind::InvalidData,
            "not a QWP message",
        )));
    }
    let mut pos = 12;
    let delta_start = read_varint(payload, &mut pos)?;
    let delta_count = read_varint(payload, &mut pos)?;
    Ok(PayloadMetrics {
        len: payload.len(),
        flags: payload[5],
        table_count: u16::from_le_bytes(payload[6..8].try_into().unwrap()),
        payload_len: u32::from_le_bytes(payload[8..12].try_into().unwrap()),
        delta_start,
        delta_count,
    })
}

fn read_varint(buf: &[u8], pos: &mut usize) -> ProbeResult<u64> {
    let mut shift = 0;
    let mut result = 0u64;
    loop {
        let b = *buf
            .get(*pos)
            .ok_or_else(|| IoError::new(ErrorKind::UnexpectedEof, "truncated QWP varint"))?;
        *pos += 1;
        result |= ((b & 0x7F) as u64) << shift;
        if b & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
        if shift >= 64 {
            return Err(Box::new(IoError::new(
                ErrorKind::InvalidData,
                "QWP varint overflow",
            )));
        }
    }
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
