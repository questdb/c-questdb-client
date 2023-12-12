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

use crate::ingress::{Buffer, CertificateAuthority, SenderBuilder, TimestampNanos, Tls};
use crate::tests::mock::{certs_dir, HttpResponse, MockServer};
use crate::ErrorCode;
use std::io;
use std::time::Duration;

use crate::tests::TestResult;

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
    let buffer2 = buffer.clone();

    let mut server = MockServer::new()?;
    let mut sender = server.lsb().http().connect()?;

    let server_thread = std::thread::spawn(move || -> io::Result<()> {
        server.accept()?;

        let req = server.recv_http_q()?;
        assert_eq!(req.method(), "POST");
        assert_eq!(req.path(), "/write?precision=u");
        assert_eq!(
            req.header("user-agent"),
            Some(concat!("questdb/rust/", env!("CARGO_PKG_VERSION")))
        );
        assert_eq!(req.body_str().unwrap(), buffer2.as_str());

        server.send_http_response_q(HttpResponse::empty())?;

        Ok(())
    });

    let res = sender.flush(&mut buffer);

    server_thread.join().unwrap()?;

    res?;

    assert!(buffer.is_empty());

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

    let mut server = MockServer::new()?;
    let mut sender = server.lsb().http().connect()?;

    let buffer2 = buffer.clone();
    let server_thread = std::thread::spawn(move || -> io::Result<()> {
        server.accept()?;

        let req = server.recv_http_q()?;
        assert_eq!(req.method(), "POST");
        assert_eq!(req.path(), "/write?precision=u");
        assert_eq!(req.body_str().unwrap(), buffer2.as_str());

        server.send_http_response_q(
            HttpResponse::empty()
                .with_status(500, "Internal Server Error")
                .with_header("content-type", "text/plain")
                .with_body_str("too many connections"),
        )?;

        Ok(())
    });

    let res = sender.flush(&mut buffer);

    server_thread.join().unwrap()?;

    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(err.code(), ErrorCode::ServerFlushError);
    assert_eq!(err.msg(), "Could not flush buffer: too many connections");

    assert!(!buffer.is_empty());

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

    let mut server = MockServer::new()?;
    let mut sender = server.lsb().http().connect()?;

    let buffer2 = buffer.clone();
    let server_thread = std::thread::spawn(move || -> io::Result<()> {
        server.accept()?;

        let req = server.recv_http_q()?;
        assert_eq!(req.method(), "POST");
        assert_eq!(req.path(), "/write?precision=u");
        assert_eq!(req.body_str().unwrap(), buffer2.as_str());

        server.send_http_response_q(
            HttpResponse::empty()
                .with_status(500, "Internal Server Error")
                .with_body_json(&serde_json::json!({
                    "error": "too many connections",
                })),
        )?;

        Ok(())
    });

    let res = sender.flush_and_keep(&buffer);

    server_thread.join().unwrap()?;

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

    let mut server = MockServer::new()?;
    let mut sender = server.lsb().http().connect()?;

    let buffer2 = buffer.clone();
    let server_thread = std::thread::spawn(move || -> io::Result<()> {
        server.accept()?;

        let req = server.recv_http_q()?;
        assert_eq!(req.method(), "POST");
        assert_eq!(req.path(), "/write?precision=u");
        assert_eq!(req.body_str().unwrap(), buffer2.as_str());

        server.send_http_response_q(
            HttpResponse::empty()
                .with_status(400, "Bad Request")
                .with_body_json(&serde_json::json!({
                    "code": "invalid",
                    "message": "failed to parse line protocol: invalid field format",
                    "errorId": "ABC-2",
                    "line": 2,
                })),
        )?;

        Ok(())
    });

    let res = sender.flush_and_keep(&buffer);

    server_thread.join().unwrap()?;

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

    let mut server = MockServer::new()?;
    let mut sender = server.lsb().http().connect()?;

    let buffer2 = buffer.clone();
    let server_thread = std::thread::spawn(move || -> io::Result<()> {
        server.accept()?;

        let req = server.recv_http_q()?;
        assert_eq!(req.method(), "POST");
        assert_eq!(req.path(), "/write?precision=u");
        assert_eq!(req.body_str().unwrap(), buffer2.as_str());

        server.send_http_response_q(
            HttpResponse::empty()
                .with_status(404, "Not Found")
                .with_header("content-type", "text/plain")
                .with_body_str("Not Found"),
        )?;

        Ok(())
    });

    let res = sender.flush_and_keep(&buffer);

    server_thread.join().unwrap()?;

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
fn test_http_basic_auth() -> TestResult {
    let mut buffer = Buffer::new();
    buffer
        .table("test")?
        .symbol("sym", "bol")?
        .column_f64("x", 1.0)?
        .at_now()?;

    let mut server = MockServer::new()?;
    let mut sender = server
        .lsb()
        .http()
        .basic_auth("Aladdin", "OpenSesame")
        .connect()?;

    let buffer2 = buffer.clone();
    let server_thread = std::thread::spawn(move || -> io::Result<()> {
        server.accept()?;

        let req = server.recv_http_q()?;
        assert_eq!(req.method(), "POST");
        assert_eq!(req.path(), "/write?precision=u");
        assert_eq!(
            req.header("authorization"),
            Some("Basic QWxhZGRpbjpPcGVuU2VzYW1l")
        );
        assert_eq!(req.body_str().unwrap(), buffer2.as_str());

        server.send_http_response_q(HttpResponse::empty())?;

        Ok(())
    });

    let res = sender.flush(&mut buffer);

    server_thread.join().unwrap()?;

    res?;

    assert!(buffer.is_empty());

    Ok(())
}

#[test]
fn test_unauthenticated() -> TestResult {
    let mut buffer = Buffer::new();
    buffer
        .table("test")?
        .symbol("sym", "bol")?
        .column_f64("x", 1.0)?
        .at_now()?;

    let mut server = MockServer::new()?;
    let mut sender = server.lsb().http().connect()?;

    let buffer2 = buffer.clone();
    let server_thread = std::thread::spawn(move || -> io::Result<()> {
        server.accept()?;

        let req = server.recv_http_q()?;
        assert_eq!(req.method(), "POST");
        assert_eq!(req.path(), "/write?precision=u");
        assert_eq!(req.body_str().unwrap(), buffer2.as_str());

        server.send_http_response_q(
            HttpResponse::empty()
                .with_status(401, "Unauthorized")
                .with_body_str("Unauthorized")
                .with_header("WWW-Authenticate", "Basic realm=\"Our Site\""),
        )?;

        Ok(())
    });

    let res = sender.flush(&mut buffer);

    server_thread.join().unwrap()?;

    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(err.code(), ErrorCode::AuthError);
    assert_eq!(
        err.msg(),
        "Could not flush buffer: HTTP endpoint authentication error: Unauthorized [code: 401]"
    );

    assert!(!buffer.is_empty());

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

    let mut server = MockServer::new()?;
    let mut sender = server.lsb().http().token_auth("0123456789").connect()?;

    let buffer2 = buffer.clone();
    let server_thread = std::thread::spawn(move || -> io::Result<()> {
        server.accept()?;

        let req = server.recv_http_q()?;
        assert_eq!(req.method(), "POST");
        assert_eq!(req.path(), "/write?precision=u");
        assert_eq!(req.header("authorization"), Some("Bearer 0123456789"));
        assert_eq!(req.body_str().unwrap(), buffer2.as_str());

        server.send_http_response_q(HttpResponse::empty())?;

        Ok(())
    });

    let res = sender.flush(&mut buffer);

    server_thread.join().unwrap()?;

    res?;

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
    let mut sender = server.lsb().http().read_timeout(grace).connect()?;
    let res = sender.flush_and_keep(&buffer);
    let time_elapsed = time_start.elapsed();
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(err.code(), ErrorCode::SocketError);
    assert!(err.msg().contains("timed out reading response"));
    assert!(time_elapsed >= grace);
    Ok(())
}

#[test]
fn test_tls() -> TestResult {
    let mut ca_path = certs_dir();
    ca_path.push("server_rootCA.pem");

    let mut buffer = Buffer::new();
    buffer
        .table("test")?
        .symbol("t1", "v1")?
        .column_f64("f1", 0.5)?
        .at(TimestampNanos::new(10000000))?;
    let buffer2 = buffer.clone();

    let mut server = MockServer::new()?;
    let mut sender = server
        .lsb()
        .http()
        .tls(Tls::Enabled(CertificateAuthority::File(ca_path)))
        .connect()?;

    let server_thread = std::thread::spawn(move || -> io::Result<()> {
        server.accept_tls_sync()?;

        let req = server.recv_http_q()?;
        assert_eq!(req.method(), "POST");
        assert_eq!(req.path(), "/write?precision=u");
        assert_eq!(req.body_str().unwrap(), buffer2.as_str());

        server.send_http_response_q(HttpResponse::empty())?;

        Ok(())
    });

    let res = sender.flush_and_keep(&buffer);

    server_thread.join().unwrap()?;

    // Unpacking the error here allows server errors to bubble first.
    res?;

    Ok(())
}

#[test]
fn test_user_agent() -> TestResult {
    let mut buffer = Buffer::new();
    buffer
        .table("test")?
        .symbol("t1", "v1")?
        .column_f64("f1", 0.5)?
        .at(TimestampNanos::new(10000000))?;
    let buffer2 = buffer.clone();

    let mut server = MockServer::new()?;
    let mut sender = server
        .lsb()
        .http()
        .user_agent("wallabies/1.2.99")
        .connect()?;

    let server_thread = std::thread::spawn(move || -> io::Result<()> {
        server.accept()?;

        let req = server.recv_http_q()?;
        assert_eq!(req.header("user-agent"), Some("wallabies/1.2.99"));
        assert_eq!(req.body_str().unwrap(), buffer2.as_str());

        server.send_http_response_q(HttpResponse::empty())?;

        Ok(())
    });

    let res = sender.flush_and_keep(&buffer);

    server_thread.join().unwrap()?;

    // Unpacking the error here allows server errors to bubble first.
    res?;

    Ok(())
}

// TODO:
//  * Test HTTP keepalive (and keepalive timeout)
//  * Test user agent.
