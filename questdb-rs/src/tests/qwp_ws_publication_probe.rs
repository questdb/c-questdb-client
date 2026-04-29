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

//! Ignored real-server probe for the Step 12 publication path.
//!
//! This exercises the prototype product path against a real QuestDB server:
//! `Buffer -> replay payload -> volatile queue -> manual driver -> real
//! WebSocket transport -> queryable row`.

use std::io::{Error as IoError, ErrorKind};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::ingress::qwp_ws_test_support::{
    DeliveryOutcome, ManualDriverPrototype, QwpWsPublicationDriver, VolatileFrameQueue,
    VolatileQueueOptions, connect_blocking_transport,
};
use crate::ingress::{Buffer, TimestampNanos};

use super::{TestError, TestResult};

type ProbeResult<T> = std::result::Result<T, TestError>;

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
    let sql = format!("select sym, qty, px from '{table}' where qty = 42");
    let value = query_json(config, &sql)?;
    let Some(rows) = value.get("dataset").and_then(|dataset| dataset.as_array()) else {
        return Ok(false);
    };
    Ok(rows.iter().any(|row| {
        let Some(row) = row.as_array() else {
            return false;
        };
        row.first().and_then(|value| value.as_str()) == Some("SYM_PUBLICATION")
            && row.get(1).and_then(|value| value.as_i64()) == Some(42)
            && row.get(2).and_then(|value| value.as_f64()) == Some(123.5)
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
