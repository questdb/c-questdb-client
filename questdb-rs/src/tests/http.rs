/*******************************************************************************
 *     ___                  _   ____  ____
 *    / _ \ _   _  ___  ___| |_|  _ \| __ )
 *   | | | | | | |/ _ \/ __| __| | | |  _ \
 *   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
 *    \__\_\\__,_|\___||___/\__|____/|____/
 *
 *  Copyright (c) 2014-2019 Appsicle
 *  Copyright (c) 2019-2023 QuestDB
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

use std::time::Duration;
use crate::ingress::{Buffer, SenderBuilder};
use crate::ErrorCode;
use crate::tests::mock::MockServer;

use crate::tests::TestResult;

trait MockitoServerExt {
    fn host(&self) -> &str;
    fn port(&self) -> u16;
}

impl MockitoServerExt for mockito::Server {
    fn host(&self) -> &str {
        "127.0.0.1"
    }

    fn port(&self) -> u16 {
        self.host_with_port()
            .split(':')
            .nth(1)
            .unwrap()
            .parse()
            .unwrap()
    }
}

#[test]
fn test_two_lines() -> TestResult {
    let mut buffer = Buffer::new();
    buffer
        .table("test")?
        .symbol("sym", "bol")?
        .column_f64("x", 1.0)?
        .at_now()?;
    buffer
        .table("test")?
        .symbol("sym", "bol")?
        .column_f64("x", 2.0)?
        .at_now()?;

    let mut server = mockito::Server::new();
    server
        .mock("POST", "/write?precision=u")
        .with_status(204)
        .with_header("content-type", "text/plain")
        .match_body(buffer.as_str())
        .create();

    let mut sender = SenderBuilder::new(server.host(), server.port())
        .http()
        .connect()?;
    sender.flush_and_keep(&buffer)?;

    Ok(())
}

#[test]
fn test_text_plain_error() -> TestResult {
    let mut buffer = Buffer::new();
    buffer
        .table("test")?
        .symbol("sym", "bol")?
        .column_f64("x", 1.0)?
        .at_now()?;
    buffer.table("test")?.column_f64("sym", 2.0)?.at_now()?;

    let mut server = mockito::Server::new();
    server
        .mock("POST", "/write?precision=u")
        .with_status(500)
        .with_header("content-type", "text/plain")
        .with_body("too many connections")
        .match_body(buffer.as_str())
        .create();

    let mut sender = SenderBuilder::new(server.host(), server.port())
        .http()
        .connect()?;
    let res = sender.flush_and_keep(&buffer);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(err.code(), ErrorCode::ServerFlushError);
    assert_eq!(err.msg(), "Could not flush buffer: too many connections");

    Ok(())
}

#[test]
fn test_bad_json_error() -> TestResult {
    let mut buffer = Buffer::new();
    buffer
        .table("test")?
        .symbol("sym", "bol")?
        .column_f64("x", 1.0)?
        .at_now()?;
    buffer.table("test")?.column_f64("sym", 2.0)?.at_now()?;

    let mut server = mockito::Server::new();
    server
        .mock("POST", "/write?precision=u")
        .with_status(500)
        .with_header("content-type", "application/json")
        .with_body("{\"error\":\"too many connections\"}")
        .match_body(buffer.as_str())
        .create();

    let mut sender = SenderBuilder::new(server.host(), server.port())
        .http()
        .connect()?;
    let res = sender.flush_and_keep(&buffer);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(err.code(), ErrorCode::ServerFlushError);
    assert_eq!(
        err.msg(),
        "Could not flush buffer: {\"error\":\"too many connections\"}"
    );

    Ok(())
}

#[test]
fn test_json_error() -> TestResult {
    let mut buffer = Buffer::new();
    buffer
        .table("test")?
        .symbol("sym", "bol")?
        .column_f64("x", 1.0)?
        .at_now()?;
    buffer.table("test")?.column_f64("sym", 2.0)?.at_now()?;

    let mut server = mockito::Server::new();
    server
        .mock("POST", "/write?precision=u")
        .with_status(400)
        .with_header("content-type", "application/json")
        .with_body(concat!(
            "{",
            "\"code\":\"invalid\",",
            "\"message\":\"failed to parse line protocol: invalid field format\",",
            "\"errorId\":\"ABC-2\",",
            "\"line\":2",
            "}"
        ))
        .match_body(buffer.as_str())
        .create();

    let mut sender = SenderBuilder::new(server.host(), server.port())
        .http()
        .connect()?;
    let res = sender.flush_and_keep(&buffer);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(err.code(), ErrorCode::ServerFlushError);
    assert_eq!(
        err.msg(),
        "Could not flush buffer: failed to parse line protocol: invalid field format [id: ABC-2, code: invalid, line: 2]"
    );

    Ok(())
}

#[test]
fn test_no_connection() -> TestResult {
    let mut buffer = Buffer::new();
    buffer
        .table("test")?
        .symbol("sym", "bol")?
        .column_f64("x", 1.0)?
        .at_now()?;

    let mut sender = SenderBuilder::new("127.0.0.1", 1).http().connect()?;
    let res = sender.flush_and_keep(&buffer);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(err.code(), ErrorCode::SocketError);
    assert!(err.msg().starts_with(
        "Could not flush buffer: http://127.0.0.1:1/write?precision=u: Connection Failed"
    ));
    Ok(())
}

#[test]
fn test_old_server_without_ilp_http_support() -> TestResult {
    let mut buffer = Buffer::new();
    buffer
        .table("test")?
        .symbol("sym", "bol")?
        .column_f64("x", 1.0)?
        .at_now()?;

    let mut server = mockito::Server::new();
    server
        .mock("POST", "/write?precision=u")
        .with_status(404)
        .with_header("content-type", "text/plain")
        .with_body("Not Found")
        .match_body(buffer.as_str())
        .create();

    let mut sender = SenderBuilder::new(server.host(), server.port())
        .http()
        .connect()?;
    let res = sender.flush_and_keep(&buffer);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(err.code(), ErrorCode::HttpNotSupported);
    assert_eq!(
        err.msg(),
        "Could not flush buffer: HTTP endpoint does not support ILP."
    );

    Ok(())
}

#[test]
fn test_http_auth() -> TestResult {
    let mut buffer = Buffer::new();
    buffer
        .table("test")?
        .symbol("sym", "bol")?
        .column_f64("x", 1.0)?
        .at_now()?;

    let mut server = mockito::Server::new();
    server
        .mock("POST", "/write?precision=u")
        .match_header("Authorization", "Basic QWxhZGRpbjpPcGVuU2VzYW1l")
        .with_status(204)
        .with_header("content-type", "text/plain")
        .match_body(buffer.as_str())
        .create();

    let mut sender = SenderBuilder::new(server.host(), server.port())
        .http()
        .basic_auth("Aladdin", "OpenSesame")
        .connect()?;
    sender.flush_and_keep(&buffer)?;

    Ok(())
}

#[test]
fn test_unauthenticated() -> TestResult {
    // WWW-Authenticate: Basic realm="Our Site"
    let mut buffer = Buffer::new();
    buffer
        .table("test")?
        .symbol("sym", "bol")?
        .column_f64("x", 1.0)?
        .at_now()?;

    let mut server = mockito::Server::new();
    server
        .mock("POST", "/write?precision=u")
        .with_status(401)
        .with_header("content-type", "text/plain")
        .with_header("WWW-Authenticate", "Basic realm=\"Our Site\"")
        .with_body("Unauthorized")
        .match_body(buffer.as_str())
        .create();

    let mut sender = SenderBuilder::new(server.host(), server.port())
        .http()
        .connect()?;

    let res = sender.flush_and_keep(&buffer);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(err.code(), ErrorCode::AuthError);
    assert_eq!(
        err.msg(),
        "Could not flush buffer: HTTP endpoint authentication error: Unauthorized [code: 401]"
    );

    Ok(())
}

#[test]
fn test_token_auth() -> TestResult {
    let mut buffer = Buffer::new();
    buffer
        .table("test")?
        .symbol("sym", "bol")?
        .column_f64("x", 1.0)?
        .at_now()?;

    let mut server = mockito::Server::new();
    server
        .mock("POST", "/write?precision=u")
        .match_header("Authorization", "Bearer 1234567890")
        .with_status(204)
        .with_header("content-type", "text/plain")
        .match_body(buffer.as_str())
        .create();

    let mut sender = SenderBuilder::new(server.host(), server.port())
        .http()
        .token_auth("1234567890")
        .connect()?;
    sender.flush_and_keep(&buffer)?;

    Ok(())
}

#[test]
fn test_timeout() -> TestResult {
    let mut buffer = Buffer::new();
    buffer
        .table("test")?
        .symbol("sym", "bol")?
        .column_f64("x", 1.0)?
        .at_now()?;

    // Here we use a mock (tcp) server instead and don't send a response back.
    let server = MockServer::new()?;

    let grace = Duration::from_millis(50);
    let time_start = std::time::Instant::now();
    let mut sender = SenderBuilder::new(server.host, server.port)
        .http()
        .read_timeout(grace)
        .connect()?;
    let res = sender.flush_and_keep(&buffer);
    let time_elapsed = time_start.elapsed();
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(err.code(), ErrorCode::SocketError);
    assert!(err.msg().contains("timed out reading response"));
    assert!(time_elapsed >= grace);
    Ok(())
}

// TODO:
//  * Test TLS.

