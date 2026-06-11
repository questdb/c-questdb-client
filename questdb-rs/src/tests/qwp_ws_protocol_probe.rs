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

//! Ignored real-server probe: validates real QuestDB response ordering with
//! multiple QWP/WebSocket frames in flight. It uses normal connection-scoped
//! QWP encoding to isolate ACK/order behavior from replay-frame encoding,
//! which is covered by `qwp_ws_replay_probe`.

use std::io::{Error as IoError, ErrorKind, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::ingress::{
    Buffer, QwpWsEncodeScratch, SymbolGlobalDict, TimestampNanos, perform_upgrade, read_message,
    write_binary_frame,
};

use super::{TestError, TestResult};

const WS_OPCODE_BINARY: u8 = 0x02;
const QWP_STATUS_OK: u8 = 0x00;
const QWP_STATUS_DURABLE_ACK: u8 = 0x02;
const QWP_STATUS_SCHEMA_MISMATCH: u8 = 0x03;
const QWP_STATUS_PARSE_ERROR: u8 = 0x05;
const BASE_TS_NANOS: i64 = 1_700_100_000_000_000_000;

type ProbeResult<T> = std::result::Result<T, TestError>;

#[derive(Clone, Debug)]
struct ProbeConfig {
    host: String,
    qwp_ws_port: u16,
    http_port: u16,
    auth_header: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ObservedResponse {
    Ok {
        sequence: u64,
    },
    DurableAck,
    Error {
        status: u8,
        sequence: u64,
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PostErrorObservation {
    NoResponseBeforeTimeout,
    ClosedOrErrored(String),
    Response(ObservedResponse),
}

#[test]
#[ignore = "requires a real QuestDB server and QDB_QWP_WS_PROTOCOL_PROBE=1"]
fn qwp_ws_real_server_ack_order_and_reject_probe() -> TestResult {
    if std::env::var("QDB_QWP_WS_PROTOCOL_PROBE").as_deref() != Ok("1") {
        eprintln!("set QDB_QWP_WS_PROTOCOL_PROBE=1 to run the real-server protocol probe");
        return Ok(());
    }

    let config = ProbeConfig::from_env()?;
    eprintln!("QuestDB build: {}", query_build(&config)?);

    probe_successful_multiple_in_flight(&config)?;
    probe_ordered_reject_then_later_success(&config)?;

    Ok(())
}

#[test]
#[ignore = "requires a real QuestDB server and QDB_QWP_WS_ERROR_TAXONOMY_PROBE=1"]
fn qwp_ws_real_server_error_taxonomy_probe() -> TestResult {
    if std::env::var("QDB_QWP_WS_ERROR_TAXONOMY_PROBE").as_deref() != Ok("1") {
        eprintln!(
            "set QDB_QWP_WS_ERROR_TAXONOMY_PROBE=1 to run the real-server error taxonomy probe"
        );
        return Ok(());
    }

    let config = ProbeConfig::from_env()?;
    eprintln!("QuestDB build: {}", query_build(&config)?);

    probe_malformed_frame_taxonomy(&config)?;
    probe_type_coercion_taxonomy(&config)?;

    Ok(())
}

fn probe_successful_multiple_in_flight(config: &ProbeConfig) -> ProbeResult<()> {
    let table = unique_table_name("qwp_order_probe_ok");
    let _cleanup = TableCleanup::new(config.clone(), table.clone());
    let payloads = build_normal_payloads(
        &table,
        &[
            ProbeRow::new("SYM_OK_0", 10, 100.0, 0),
            ProbeRow::new("SYM_OK_1", 20, 200.0, 1),
            ProbeRow::new("SYM_OK_2", 30, 300.0, 2),
        ],
    )?;

    let mut stream = open_ws_connection(config, "rust-qwp-order-probe")?;
    send_payloads_without_reading(&mut stream, &payloads)?;

    let responses = read_until_ok_covers(&mut stream, 2)?;
    let ok_sequences: Vec<u64> = responses
        .iter()
        .filter_map(|response| match response {
            ObservedResponse::Ok { sequence } => Some(*sequence),
            ObservedResponse::DurableAck | ObservedResponse::Error { .. } => None,
        })
        .collect();
    eprintln!("multi-in-flight OK sequences for {table}: {ok_sequences:?}");

    assert!(
        !ok_sequences.is_empty(),
        "expected at least one OK response covering sequence 2"
    );
    assert!(
        ok_sequences.windows(2).all(|pair| pair[0] < pair[1]),
        "OK sequences should be strictly increasing: {ok_sequences:?}"
    );
    assert!(
        ok_sequences.last().copied().unwrap_or_default() >= 2,
        "last OK should cumulatively cover sequence 2: {ok_sequences:?}"
    );

    let count = wait_for_count(config, &table, 3, Duration::from_secs(10))?;
    assert_eq!(count, 3);
    assert!(has_qty(config, &table, 10)?);
    assert!(has_qty(config, &table, 20)?);
    assert!(has_qty(config, &table, 30)?);

    Ok(())
}

fn probe_malformed_frame_taxonomy(config: &ProbeConfig) -> ProbeResult<()> {
    let table = unique_table_name("qwp_error_probe_malformed");
    let _cleanup = TableCleanup::new(config.clone(), table.clone());
    let valid_payloads = build_normal_payloads(
        &table,
        &[
            ProbeRow::new("SYM_PARSE_0", 10, 100.0, 0),
            ProbeRow::new("SYM_PARSE_2", 30, 300.0, 2),
        ],
    )?;
    let payloads = [
        valid_payloads[0].clone(),
        b"not-a-qwp-frame".to_vec(),
        valid_payloads[1].clone(),
    ];

    let mut stream = open_ws_connection(config, "rust-qwp-error-parse-probe")?;
    send_payloads_without_reading(&mut stream, &payloads)?;

    let (responses, error) = read_until_error(&mut stream)?;
    let post_error = observe_post_error(&mut stream);
    eprintln!("malformed-frame responses before error for {table}: {responses:?}");
    eprintln!(
        "malformed-frame error for {table}: status=0x{:02x}, sequence={}, message={:?}",
        error.status, error.sequence, error.message
    );
    eprintln!("malformed-frame post-error observation for {table}: {post_error:?}");

    assert_eq!(error.status, QWP_STATUS_PARSE_ERROR);
    assert_eq!(error.sequence, 1);
    assert_eq!(
        post_error,
        PostErrorObservation::Response(ObservedResponse::Ok { sequence: 2 }),
        "server should continue far enough to resolve the later valid frame"
    );

    let count = wait_for_count(config, &table, 2, Duration::from_secs(10))?;
    assert_eq!(count, 2);
    assert!(has_qty(config, &table, 10)?);
    assert!(has_qty(config, &table, 30)?);

    Ok(())
}

fn probe_type_coercion_taxonomy(config: &ProbeConfig) -> ProbeResult<()> {
    let table = unique_table_name("qwp_error_probe_coercion");
    let _cleanup = TableCleanup::new(config.clone(), table.clone());
    let payloads = build_type_coercion_payloads(&table)?;

    let mut stream = open_ws_connection(config, "rust-qwp-error-coercion-probe")?;
    send_payloads_without_reading(&mut stream, &payloads)?;

    let (responses, error) = read_until_error(&mut stream)?;
    let post_error = observe_post_error(&mut stream);
    eprintln!("type-coercion responses before error for {table}: {responses:?}");
    eprintln!(
        "type-coercion error for {table}: status=0x{:02x}, sequence={}, message={:?}",
        error.status, error.sequence, error.message
    );
    eprintln!("type-coercion post-error observation for {table}: {post_error:?}");

    assert_eq!(error.status, QWP_STATUS_SCHEMA_MISMATCH);
    assert_eq!(error.sequence, 1);
    assert_eq!(
        post_error,
        PostErrorObservation::Response(ObservedResponse::Ok { sequence: 2 }),
        "server should continue far enough to resolve the later valid frame"
    );

    let count = wait_for_count(config, &table, 2, Duration::from_secs(10))?;
    assert_eq!(count, 2);
    assert!(has_qty(config, &table, 10)?);
    assert!(has_qty(config, &table, 30)?);

    Ok(())
}

fn probe_ordered_reject_then_later_success(config: &ProbeConfig) -> ProbeResult<()> {
    let table = unique_table_name("qwp_order_probe_reject");
    let _cleanup = TableCleanup::new(config.clone(), table.clone());
    let valid_payloads = build_normal_payloads(
        &table,
        &[
            ProbeRow::new("SYM_REJECT_0", 10, 100.0, 0),
            ProbeRow::new("SYM_REJECT_2", 30, 300.0, 2),
        ],
    )?;
    let payloads = [
        valid_payloads[0].clone(),
        b"not-a-qwp-frame".to_vec(),
        valid_payloads[1].clone(),
    ];

    let mut stream = open_ws_connection(config, "rust-qwp-reject-probe")?;
    send_payloads_without_reading(&mut stream, &payloads)?;

    let (responses, error) = read_until_error(&mut stream)?;
    let ok_sequences: Vec<u64> = responses
        .iter()
        .filter_map(|response| match response {
            ObservedResponse::Ok { sequence } => Some(*sequence),
            ObservedResponse::DurableAck | ObservedResponse::Error { .. } => None,
        })
        .collect();
    eprintln!("ordered-reject responses before error for {table}: {responses:?}");
    eprintln!("ordered-reject terminal error for {table}: {error:?}");

    assert_eq!(
        error.sequence, 1,
        "bad frame should be reported as sequence 1"
    );
    assert!(
        ok_sequences.iter().all(|sequence| *sequence == 0),
        "server must not ACK beyond the bad frame before reporting it: {ok_sequences:?}"
    );

    let post_error = observe_post_error(&mut stream);
    eprintln!("post-error observation for {table}: {post_error:?}");
    assert_eq!(
        post_error,
        PostErrorObservation::Response(ObservedResponse::Ok { sequence: 2 }),
        "server should be able to resolve a later frame after sequence 1 is resolved by error"
    );

    let count = wait_for_count(config, &table, 2, Duration::from_secs(10))?;
    assert_eq!(count, 2);
    std::thread::sleep(Duration::from_millis(250));
    let final_count = query_count(config, &table)?;
    assert_eq!(
        final_count, 2,
        "both valid frames around rejected sequence 1 should be visible"
    );
    assert!(has_qty(config, &table, 10)?);
    assert!(has_qty(config, &table, 30)?);

    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct ProbeRow<'a> {
    symbol: &'a str,
    qty: i64,
    px: f64,
    ts_offset: i64,
}

impl<'a> ProbeRow<'a> {
    fn new(symbol: &'a str, qty: i64, px: f64, ts_offset: i64) -> Self {
        Self {
            symbol,
            qty,
            px,
            ts_offset,
        }
    }
}

fn build_normal_payloads(table: &str, rows: &[ProbeRow<'_>]) -> ProbeResult<Vec<Vec<u8>>> {
    let mut scratch = QwpWsEncodeScratch::new();
    let mut global_dict = SymbolGlobalDict::new();
    let mut payloads = Vec::with_capacity(rows.len());

    for row in rows {
        let mut buffer = Buffer::new_qwp();
        buffer
            .table(table)?
            .symbol("sym", row.symbol)?
            .column_i64("qty", row.qty)?
            .column_f64("px", row.px)?
            .at(TimestampNanos::new(BASE_TS_NANOS + row.ts_offset))?;
        payloads.push(encode_probe_buffer(
            &mut buffer,
            &mut scratch,
            &mut global_dict,
        )?);
    }

    Ok(payloads)
}

fn build_type_coercion_payloads(table: &str) -> ProbeResult<Vec<Vec<u8>>> {
    let mut scratch = QwpWsEncodeScratch::new();
    let mut global_dict = SymbolGlobalDict::new();
    let mut payloads = Vec::with_capacity(3);

    let mut first = Buffer::new_qwp();
    first
        .table(table)?
        .symbol("sym", "SYM_SCHEMA_0")?
        .column_i64("qty", 10)?
        .column_f64("px", 100.0)?
        .at(TimestampNanos::new(BASE_TS_NANOS))?;
    payloads.push(encode_probe_buffer(
        &mut first,
        &mut scratch,
        &mut global_dict,
    )?);

    let mut bad = Buffer::new_qwp();
    bad.table(table)?
        .symbol("sym", "SYM_SCHEMA_1")?
        .column_i64("qty", 20)?
        .column_str("px", "not-a-double")?
        .at(TimestampNanos::new(BASE_TS_NANOS + 1))?;
    payloads.push(encode_probe_buffer(
        &mut bad,
        &mut scratch,
        &mut global_dict,
    )?);

    let mut third = Buffer::new_qwp();
    third
        .table(table)?
        .symbol("sym", "SYM_SCHEMA_2")?
        .column_i64("qty", 30)?
        .column_f64("px", 300.0)?
        .at(TimestampNanos::new(BASE_TS_NANOS + 2))?;
    payloads.push(encode_probe_buffer(
        &mut third,
        &mut scratch,
        &mut global_dict,
    )?);

    Ok(payloads)
}

fn encode_probe_buffer(
    buffer: &mut Buffer,
    scratch: &mut QwpWsEncodeScratch,
    global_dict: &mut SymbolGlobalDict,
) -> ProbeResult<Vec<u8>> {
    buffer
        .as_qwp()
        .unwrap()
        .encode_ws_message(scratch, global_dict, 1)?;
    Ok(scratch.message.clone())
}

fn open_ws_connection(config: &ProbeConfig, client_id: &str) -> ProbeResult<TcpStream> {
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
        Some(client_id),
        false,
    )?;

    Ok(stream)
}

fn send_payloads_without_reading(stream: &mut TcpStream, payloads: &[Vec<u8>]) -> ProbeResult<()> {
    let mut send_buf = Vec::new();
    for payload in payloads {
        write_binary_frame(stream, &mut send_buf, payload)?;
    }
    stream.flush()?;
    Ok(())
}

fn read_until_ok_covers(
    stream: &mut TcpStream,
    target_sequence: u64,
) -> ProbeResult<Vec<ObservedResponse>> {
    let mut responses = Vec::new();
    let mut highest_ok = None;
    while highest_ok.is_none_or(|sequence| sequence < target_sequence) {
        let response = read_qwp_response(stream)?;
        match response {
            ObservedResponse::Ok { sequence } => {
                highest_ok = Some(sequence);
                responses.push(ObservedResponse::Ok { sequence });
            }
            ObservedResponse::DurableAck => responses.push(ObservedResponse::DurableAck),
            ObservedResponse::Error {
                status,
                sequence,
                message,
            } => {
                return Err(Box::new(IoError::new(
                    ErrorKind::InvalidData,
                    format!(
                        "unexpected QWP error while waiting for OK {target_sequence}: status=0x{status:02x}, sequence={sequence}, message={message}"
                    ),
                )));
            }
        }
    }
    Ok(responses)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ObservedError {
    status: u8,
    sequence: u64,
    message: String,
}

fn read_until_error(stream: &mut TcpStream) -> ProbeResult<(Vec<ObservedResponse>, ObservedError)> {
    let mut responses = Vec::new();
    loop {
        let response = read_qwp_response(stream)?;
        match response {
            ObservedResponse::Error {
                status,
                sequence,
                message,
            } => {
                return Ok((
                    responses,
                    ObservedError {
                        status,
                        sequence,
                        message,
                    },
                ));
            }
            other => responses.push(other),
        }
    }
}

fn read_qwp_response(stream: &mut TcpStream) -> ProbeResult<ObservedResponse> {
    let mut scratch = Vec::new();
    let mut response = Vec::new();
    let opcode = read_message(stream, &mut scratch, &mut response)?;
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
        QWP_STATUS_OK => Ok(ObservedResponse::Ok {
            sequence: response_sequence(&response)?,
        }),
        QWP_STATUS_DURABLE_ACK => Ok(ObservedResponse::DurableAck),
        other => {
            let (sequence, message) = qwp_error_body(&response)?;
            Ok(ObservedResponse::Error {
                status: other,
                sequence,
                message,
            })
        }
    }
}

fn observe_post_error(stream: &mut TcpStream) -> PostErrorObservation {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
    match read_qwp_response(stream) {
        Ok(response) => PostErrorObservation::Response(response),
        Err(err) => {
            let message = err.to_string();
            if message.contains("timed out")
                || message.contains("WouldBlock")
                || message.contains("Resource temporarily unavailable")
            {
                PostErrorObservation::NoResponseBeforeTimeout
            } else {
                PostErrorObservation::ClosedOrErrored(message)
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

fn qwp_error_body(response: &[u8]) -> ProbeResult<(u64, String)> {
    if response.len() < 11 {
        return Err(Box::new(IoError::new(
            ErrorKind::UnexpectedEof,
            "QWP error response truncated",
        )));
    }
    let sequence = u64::from_le_bytes(response[1..9].try_into().unwrap());
    let msg_len = u16::from_le_bytes(response[9..11].try_into().unwrap()) as usize;
    let msg_end = 11usize
        .checked_add(msg_len)
        .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "QWP error message overflow"))?;
    if response.len() < msg_end {
        return Err(Box::new(IoError::new(
            ErrorKind::UnexpectedEof,
            format!("QWP error response truncated, declared {msg_len} bytes"),
        )));
    }
    let message = std::str::from_utf8(&response[11..msg_end])?.to_string();
    Ok((sequence, message))
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
    let mut last_count = 0usize;
    while Instant::now() < deadline {
        match query_count(config, table) {
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

fn query_count(config: &ProbeConfig, table: &str) -> ProbeResult<usize> {
    let sql = format!("select count() from '{table}'");
    let value = query_json(config, &sql)?;
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

fn has_qty(config: &ProbeConfig, table: &str, qty: i64) -> ProbeResult<bool> {
    let sql = format!("select qty from '{table}' where qty = {qty}");
    let value = query_json(config, &sql)?;
    let Some(rows) = value.get("dataset").and_then(|dataset| dataset.as_array()) else {
        return Ok(false);
    };
    Ok(rows.iter().any(|row| {
        row.as_array()
            .and_then(|row| row.first())
            .and_then(|value| value.as_i64())
            == Some(qty)
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
