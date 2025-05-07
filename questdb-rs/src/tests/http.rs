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

use crate::ingress::{Buffer, LineProtocolVersion, Protocol, SenderBuilder, TimestampNanos};
use crate::tests::mock::{certs_dir, HttpResponse, MockServer};
use crate::tests::TestResult;
use crate::ErrorCode;
use rstest::rstest;
use std::io;
use std::io::ErrorKind;
use std::time::Duration;

#[rstest]
fn test_two_lines(
    #[values(LineProtocolVersion::V1, LineProtocolVersion::V2)] version: LineProtocolVersion,
) -> TestResult {
    let mut buffer = Buffer::new().with_line_proto_version(version)?;
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

    let mut server = MockServer::new()?.configure_settings_response(2, &[1, 2]);
    let sender_builder = server.lsb_http();

    let server_thread = std::thread::spawn(move || -> io::Result<()> {
        server.accept()?;
        let req = server.recv_http_q()?;
        assert_eq!(req.method(), "GET");
        assert_eq!(req.path(), "/settings");
        assert_eq!(
            req.header("user-agent"),
            Some(concat!("questdb/rust/", env!("CARGO_PKG_VERSION")))
        );
        server.send_settings_response()?;

        let req = server.recv_http_q()?;
        assert_eq!(req.method(), "POST");
        assert_eq!(req.path(), "/write?precision=n");
        assert_eq!(
            req.header("user-agent"),
            Some(concat!("questdb/rust/", env!("CARGO_PKG_VERSION")))
        );
        assert_eq!(req.body(), buffer2.as_bytes());

        server.send_http_response_q(HttpResponse::empty())?;

        Ok(())
    });

    let mut sender = sender_builder.build()?;
    let res = sender.flush(&mut buffer);

    server_thread.join().unwrap()?;

    res?;

    assert!(buffer.is_empty());

    Ok(())
}

#[rstest]
fn test_text_plain_error(
    #[values(LineProtocolVersion::V1, LineProtocolVersion::V2)] version: LineProtocolVersion,
) -> TestResult {
    let mut buffer = Buffer::new().with_line_proto_version(version)?;
    buffer
        .table("test")?
        .symbol("sym", "bol")?
        .column_f64("x", 1.0)?
        .at_now()?;
    buffer.table("test")?.column_f64("sym", 2.0)?.at_now()?;

    let mut server = MockServer::new()?.configure_settings_response(2, &[1, 2]);
    let sender_builder = server.lsb_http();

    let buffer2 = buffer.clone();
    let server_thread = std::thread::spawn(move || -> io::Result<()> {
        server.accept()?;
        let req = server.recv_http_q()?;
        assert_eq!(req.method(), "GET");
        assert_eq!(req.path(), "/settings");
        assert_eq!(
            req.header("user-agent"),
            Some(concat!("questdb/rust/", env!("CARGO_PKG_VERSION")))
        );
        server.send_settings_response()?;

        let req = server.recv_http_q()?;
        assert_eq!(req.method(), "POST");
        assert_eq!(req.path(), "/write?precision=n");
        assert_eq!(req.body(), buffer2.as_bytes());

        server.send_http_response_q(
            HttpResponse::empty()
                .with_status(400, "Bad Request")
                .with_header("content-type", "text/plain")
                .with_body_str("bad wombat"),
        )?;

        Ok(())
    });

    let mut sender = sender_builder.build()?;
    let res = sender.flush(&mut buffer);

    server_thread.join().unwrap()?;

    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(err.code(), ErrorCode::ServerFlushError);
    assert_eq!(err.msg(), "Could not flush buffer: bad wombat");

    assert!(!buffer.is_empty());

    Ok(())
}

#[rstest]
fn test_bad_json_error(
    #[values(LineProtocolVersion::V1, LineProtocolVersion::V2)] version: LineProtocolVersion,
) -> TestResult {
    let mut buffer = Buffer::new().with_line_proto_version(version)?;
    buffer
        .table("test")?
        .symbol("sym", "bol")?
        .column_f64("x", 1.0)?
        .at_now()?;
    buffer.table("test")?.column_f64("sym", 2.0)?.at_now()?;

    let mut server = MockServer::new()?.configure_settings_response(2, &[1, 2]);
    let sender_builder = server.lsb_http();

    let buffer2 = buffer.clone();
    let server_thread = std::thread::spawn(move || -> io::Result<()> {
        server.accept()?;
        let req = server.recv_http_q()?;
        assert_eq!(req.method(), "GET");
        assert_eq!(req.path(), "/settings");
        assert_eq!(
            req.header("user-agent"),
            Some(concat!("questdb/rust/", env!("CARGO_PKG_VERSION")))
        );
        server.send_settings_response()?;

        let req = server.recv_http_q()?;
        assert_eq!(req.method(), "POST");
        assert_eq!(req.path(), "/write?precision=n");
        assert_eq!(req.body(), buffer2.as_bytes());

        server.send_http_response_q(
            HttpResponse::empty()
                .with_status(400, "Bad Request")
                .with_body_json(&serde_json::json!({
                    "error": "bad wombat",
                })),
        )?;

        Ok(())
    });

    let mut sender = sender_builder.build()?;
    let res = sender.flush_and_keep(&buffer);

    server_thread.join().unwrap()?;

    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(err.code(), ErrorCode::ServerFlushError);
    assert_eq!(
        err.msg(),
        "Could not flush buffer: {\"error\":\"bad wombat\"}"
    );

    Ok(())
}

#[rstest]
fn test_json_error(
    #[values(LineProtocolVersion::V1, LineProtocolVersion::V2)] version: LineProtocolVersion,
) -> TestResult {
    let mut buffer = Buffer::new().with_line_proto_version(version)?;
    buffer
        .table("test")?
        .symbol("sym", "bol")?
        .column_f64("x", 1.0)?
        .at_now()?;
    buffer.table("test")?.column_f64("sym", 2.0)?.at_now()?;

    let mut server = MockServer::new()?.configure_settings_response(2, &[1, 2]);
    let sender_builder = server.lsb_http();

    let buffer2 = buffer.clone();
    let server_thread = std::thread::spawn(move || -> io::Result<()> {
        server.accept()?;
        let req = server.recv_http_q()?;
        assert_eq!(req.method(), "GET");
        assert_eq!(req.path(), "/settings");
        assert_eq!(
            req.header("user-agent"),
            Some(concat!("questdb/rust/", env!("CARGO_PKG_VERSION")))
        );
        server.send_settings_response()?;

        let req = server.recv_http_q()?;
        assert_eq!(req.method(), "POST");
        assert_eq!(req.path(), "/write?precision=n");
        assert_eq!(req.body(), buffer2.as_bytes());

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

    let res = sender_builder.build()?.flush_and_keep(&buffer);

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

#[rstest]
fn test_no_connection(
    #[values(LineProtocolVersion::V1, LineProtocolVersion::V2)] version: LineProtocolVersion,
) -> TestResult {
    let mut buffer = Buffer::new().with_line_proto_version(version)?;
    buffer
        .table("test")?
        .symbol("sym", "bol")?
        .column_f64("x", 1.0)?
        .at_now()?;

    let mut sender = SenderBuilder::new(Protocol::Http, "127.0.0.1", 1)
        .disable_line_protocol_validation()?
        .build()?;
    let res = sender.flush_and_keep(&buffer);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(err.code(), ErrorCode::SocketError);
    assert!(err
        .msg()
        .starts_with("Could not flush buffer: http://127.0.0.1:1/write: io: Connection refused"));
    Ok(())
}

#[rstest]
fn test_old_server_without_ilp_http_support(
    #[values(LineProtocolVersion::V1, LineProtocolVersion::V2)] version: LineProtocolVersion,
) -> TestResult {
    let mut buffer = Buffer::new().with_line_proto_version(version)?;
    buffer
        .table("test")?
        .symbol("sym", "bol")?
        .column_f64("x", 1.0)?
        .at_now()?;

    let mut server = MockServer::new()?.configure_settings_response(2, &[1, 2]);
    let sender_builder = server.lsb_http();

    let buffer2 = buffer.clone();
    let server_thread = std::thread::spawn(move || -> io::Result<()> {
        server.accept()?;
        let req = server.recv_http_q()?;
        assert_eq!(req.method(), "GET");
        assert_eq!(req.path(), "/settings");
        assert_eq!(
            req.header("user-agent"),
            Some(concat!("questdb/rust/", env!("CARGO_PKG_VERSION")))
        );
        server.send_settings_response()?;

        let req = server.recv_http_q()?;
        assert_eq!(req.method(), "POST");
        assert_eq!(req.path(), "/write?precision=n");
        assert_eq!(req.body(), buffer2.as_bytes());

        server.send_http_response_q(
            HttpResponse::empty()
                .with_status(404, "Not Found")
                .with_header("content-type", "text/plain")
                .with_body_str("Not Found"),
        )?;

        Ok(())
    });

    let res = sender_builder.build()?.flush_and_keep(&buffer);

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

#[rstest]
fn test_http_basic_auth(
    #[values(LineProtocolVersion::V1, LineProtocolVersion::V2)] version: LineProtocolVersion,
) -> TestResult {
    let mut buffer = Buffer::new().with_line_proto_version(version)?;
    buffer
        .table("test")?
        .symbol("sym", "bol")?
        .column_f64("x", 1.0)?
        .at_now()?;

    let mut server = MockServer::new()?.configure_settings_response(2, &[1, 2]);
    let sender_builder = server
        .lsb_http()
        .username("Aladdin")?
        .password("OpenSesame")?;

    let buffer2 = buffer.clone();
    let server_thread = std::thread::spawn(move || -> io::Result<()> {
        server.accept()?;
        let req = server.recv_http_q()?;
        assert_eq!(req.method(), "GET");
        assert_eq!(req.path(), "/settings");
        assert_eq!(
            req.header("user-agent"),
            Some(concat!("questdb/rust/", env!("CARGO_PKG_VERSION")))
        );
        server.send_settings_response()?;

        let req = server.recv_http_q()?;

        assert_eq!(req.method(), "POST");
        assert_eq!(req.path(), "/write?precision=n");
        assert_eq!(
            req.header("authorization"),
            Some("Basic QWxhZGRpbjpPcGVuU2VzYW1l")
        );
        assert_eq!(req.body(), buffer2.as_bytes());

        server.send_http_response_q(HttpResponse::empty())?;

        Ok(())
    });

    let res = sender_builder.build()?.flush(&mut buffer);

    server_thread.join().unwrap()?;

    res?;

    assert!(buffer.is_empty());

    Ok(())
}

#[rstest]
fn test_unauthenticated(
    #[values(LineProtocolVersion::V1, LineProtocolVersion::V2)] version: LineProtocolVersion,
) -> TestResult {
    let mut buffer = Buffer::new().with_line_proto_version(version)?;
    buffer
        .table("test")?
        .symbol("sym", "bol")?
        .column_f64("x", 1.0)?
        .at_now()?;

    let mut server = MockServer::new()?.configure_settings_response(2, &[1, 2]);
    let sender_builder = server.lsb_http();

    let buffer2 = buffer.clone();
    let server_thread = std::thread::spawn(move || -> io::Result<()> {
        server.accept()?;
        let req = server.recv_http_q()?;
        assert_eq!(req.method(), "GET");
        assert_eq!(req.path(), "/settings");
        assert_eq!(
            req.header("user-agent"),
            Some(concat!("questdb/rust/", env!("CARGO_PKG_VERSION")))
        );
        server.send_settings_response()?;

        let req = server.recv_http_q()?;
        assert_eq!(req.method(), "POST");
        assert_eq!(req.path(), "/write?precision=n");
        assert_eq!(req.body(), buffer2.as_bytes());

        server.send_http_response_q(
            HttpResponse::empty()
                .with_status(401, "Unauthorized")
                .with_body_str("Unauthorized")
                .with_header("WWW-Authenticate", "Basic realm=\"Our Site\""),
        )?;

        Ok(())
    });

    let res = sender_builder.build()?.flush(&mut buffer);

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

#[rstest]
fn test_token_auth(
    #[values(LineProtocolVersion::V1, LineProtocolVersion::V2)] version: LineProtocolVersion,
) -> TestResult {
    let mut buffer = Buffer::new().with_line_proto_version(version)?;
    buffer
        .table("test")?
        .symbol("sym", "bol")?
        .column_f64("x", 1.0)?
        .at_now()?;

    let mut server = MockServer::new()?.configure_settings_response(2, &[1, 2]);
    let sender_builder = server.lsb_http().token("0123456789")?;

    let buffer2 = buffer.clone();
    let server_thread = std::thread::spawn(move || -> io::Result<()> {
        server.accept()?;
        let req = server.recv_http_q()?;
        assert_eq!(req.method(), "GET");
        assert_eq!(req.path(), "/settings");
        assert_eq!(
            req.header("user-agent"),
            Some(concat!("questdb/rust/", env!("CARGO_PKG_VERSION")))
        );
        server.send_settings_response()?;

        let req = server.recv_http_q()?;
        assert_eq!(req.method(), "POST");
        assert_eq!(req.path(), "/write?precision=n");
        assert_eq!(req.header("authorization"), Some("Bearer 0123456789"));
        assert_eq!(req.body(), buffer2.as_bytes());

        server.send_http_response_q(HttpResponse::empty())?;

        Ok(())
    });

    let res = sender_builder.build()?.flush(&mut buffer);

    server_thread.join().unwrap()?;

    res?;

    Ok(())
}

#[rstest]
fn test_request_timeout(
    #[values(LineProtocolVersion::V1, LineProtocolVersion::V2)] version: LineProtocolVersion,
) -> TestResult {
    let mut buffer = Buffer::new().with_line_proto_version(version)?;
    buffer
        .table("test")?
        .symbol("sym", "bol")?
        .column_f64("x", 1.0)?
        .at_now()?;

    // Here we use a mock (tcp) server instead and don't send a response back.
    let server = MockServer::new()?.configure_settings_response(2, &[1, 2]);

    let request_timeout = Duration::from_millis(50);
    let time_start = std::time::Instant::now();
    let mut sender = server
        .lsb_http()
        .disable_line_protocol_validation()?
        .request_timeout(request_timeout)?
        .build()?;
    let res = sender.flush_and_keep(&buffer);
    let time_elapsed = time_start.elapsed();
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(err.code(), ErrorCode::SocketError);
    assert!(err.msg().contains("per call"));
    assert!(time_elapsed >= request_timeout);
    Ok(())
}

#[rstest]
fn test_tls(
    #[values(LineProtocolVersion::V1, LineProtocolVersion::V2)] version: LineProtocolVersion,
) -> TestResult {
    let mut ca_path = certs_dir();
    ca_path.push("server_rootCA.pem");

    let mut buffer = Buffer::new().with_line_proto_version(version)?;
    buffer
        .table("test")?
        .symbol("t1", "v1")?
        .column_f64("f1", 0.5)?
        .at(TimestampNanos::new(10000000))?;
    let buffer2 = buffer.clone();

    let mut server = MockServer::new()?.configure_settings_response(2, &[1, 2]);
    let mut sender = server
        .lsb_https()
        .tls_roots(ca_path)?
        .disable_line_protocol_validation()?
        .build()?;

    let server_thread = std::thread::spawn(move || -> io::Result<()> {
        server.accept_tls_sync()?;
        let req = server.recv_http_q()?;
        assert_eq!(req.method(), "POST");
        assert_eq!(req.path(), "/write?precision=n");
        assert_eq!(req.body(), buffer2.as_bytes());

        server.send_http_response_q(HttpResponse::empty())?;

        Ok(())
    });

    let res = sender.flush_and_keep(&buffer);

    server_thread.join().unwrap()?;

    // Unpacking the error here allows server errors to bubble first.
    res?;

    Ok(())
}

#[rstest]
fn test_user_agent(
    #[values(LineProtocolVersion::V1, LineProtocolVersion::V2)] version: LineProtocolVersion,
) -> TestResult {
    let mut buffer = Buffer::new().with_line_proto_version(version)?;
    buffer
        .table("test")?
        .symbol("t1", "v1")?
        .column_f64("f1", 0.5)?
        .at(TimestampNanos::new(10000000))?;
    let buffer2 = buffer.clone();

    let mut server = MockServer::new()?.configure_settings_response(2, &[1, 2]);
    let sender_builder = server.lsb_http().user_agent("wallabies/1.2.99")?;

    let server_thread = std::thread::spawn(move || -> io::Result<()> {
        server.accept()?;
        let req = server.recv_http_q()?;
        assert_eq!(req.method(), "GET");
        assert_eq!(req.path(), "/settings");
        server.send_settings_response()?;

        let req = server.recv_http_q()?;
        assert_eq!(req.header("user-agent"), Some("wallabies/1.2.99"));
        assert_eq!(req.body(), buffer2.as_bytes());

        server.send_http_response_q(HttpResponse::empty())?;

        Ok(())
    });

    let res = sender_builder.build()?.flush_and_keep(&buffer);

    server_thread.join().unwrap()?;

    // Unpacking the error here allows server errors to bubble first.
    res?;

    Ok(())
}

#[rstest]
fn test_two_retries(
    #[values(LineProtocolVersion::V1, LineProtocolVersion::V2)] version: LineProtocolVersion,
) -> TestResult {
    // Note: This also tests that the _same_ connection is being reused, i.e. tests keepalive.

    let mut buffer = Buffer::new().with_line_proto_version(version)?;
    buffer
        .table("test")?
        .symbol("t1", "v1")?
        .column_f64("f1", 0.5)?
        .at(TimestampNanos::new(10000000))?;
    let buffer2 = buffer.clone();

    let mut server = MockServer::new()?.configure_settings_response(2, &[1, 2]);
    let sender_builder = server.lsb_http().retry_timeout(Duration::from_secs(30))?;

    let server_thread = std::thread::spawn(move || -> io::Result<()> {
        server.accept()?;
        let req = server.recv_http_q()?;
        assert_eq!(req.method(), "GET");
        assert_eq!(req.path(), "/settings");
        assert_eq!(
            req.header("user-agent"),
            Some(concat!("questdb/rust/", env!("CARGO_PKG_VERSION")))
        );
        server.send_settings_response()?;

        let req = server.recv_http_q()?;
        assert_eq!(req.body(), buffer2.as_bytes());

        server.send_http_response_q(
            HttpResponse::empty()
                .with_status(500, "Internal Server Error")
                .with_body_str("client should retry"),
        )?;

        let start_time = std::time::Instant::now();

        let req = server.recv_http_q()?;
        assert_eq!(req.body(), buffer2.as_bytes());
        let elapsed = std::time::Instant::now().duration_since(start_time);
        assert!(elapsed > Duration::from_millis(5));

        server.send_http_response_q(
            HttpResponse::empty()
                .with_status(500, "Internal Server Error")
                .with_body_str("client should retry"),
        )?;

        let start_time = std::time::Instant::now();

        let req = server.recv_http_q()?;
        assert_eq!(req.body(), buffer2.as_bytes());
        let elapsed = std::time::Instant::now().duration_since(start_time);
        assert!(elapsed > Duration::from_millis(15));

        server.send_http_response_q(HttpResponse::empty())?;

        Ok(())
    });

    let res = sender_builder.build()?.flush_and_keep(&buffer);

    server_thread.join().unwrap()?;

    // Unpacking the error here allows server errors to bubble first.
    res?;

    Ok(())
}

#[rstest]
fn test_one_retry(
    #[values(LineProtocolVersion::V1, LineProtocolVersion::V2)] version: LineProtocolVersion,
) -> TestResult {
    let mut buffer = Buffer::new().with_line_proto_version(version)?;
    buffer
        .table("test")?
        .symbol("t1", "v1")?
        .column_f64("f1", 0.5)?
        .at(TimestampNanos::new(10000000))?;
    let buffer2 = buffer.clone();

    let mut server = MockServer::new()?.configure_settings_response(2, &[1, 2]);
    let mut sender = server
        .lsb_http()
        .retry_timeout(Duration::from_millis(19))?
        .disable_line_protocol_validation()
        .unwrap()
        .build()?;

    let server_thread = std::thread::spawn(move || -> io::Result<()> {
        server.accept()?;
        let req = server.recv_http_q()?;
        assert_eq!(req.body(), buffer2.as_bytes());

        server.send_http_response_q(
            HttpResponse::empty()
                .with_status(500, "Internal Server Error")
                .with_body_str("error 1"),
        )?;

        let req = server.recv_http_q()?;
        assert_eq!(req.body(), buffer2.as_bytes());

        server.send_http_response_q(
            HttpResponse::empty()
                .with_status(500, "Internal Server Error")
                .with_body_str("error 2"),
        )?;

        let req = server.recv_http(2.0);

        let err = match req {
            Ok(_) => {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    "unexpected retry response",
                ));
            }
            Err(err) => err,
        };
        assert_eq!(err.kind(), ErrorKind::TimedOut);

        Ok(())
    });

    let res = sender.flush_and_keep(&buffer);

    server_thread.join().unwrap()?;

    let err = res.unwrap_err();
    assert_eq!(err.code(), ErrorCode::ServerFlushError);
    assert_eq!(err.msg(), "Could not flush buffer: error 2");

    Ok(())
}

#[rstest]
fn test_transactional(
    #[values(LineProtocolVersion::V1, LineProtocolVersion::V2)] version: LineProtocolVersion,
) -> TestResult {
    // A buffer with a two tables.
    let mut buffer1 = Buffer::new().with_line_proto_version(version)?;
    buffer1
        .table("tab1")?
        .symbol("t1", "v1")?
        .column_f64("f1", 0.5)?
        .at(TimestampNanos::new(10000001))?;
    buffer1
        .table("tab2")?
        .symbol("t1", "v1")?
        .column_f64("f1", 0.6)?
        .at(TimestampNanos::new(10000002))?;
    assert!(!buffer1.transactional());

    // A buffer with a single table.
    let mut buffer2 = Buffer::new().with_line_proto_version(version)?;
    buffer2
        .table("test")?
        .symbol("t1", "v1")?
        .column_f64("f1", 0.5)?
        .at(TimestampNanos::new(10000000))?;
    let buffer3 = buffer2.clone();
    assert!(buffer2.transactional());

    let mut server = MockServer::new()?.configure_settings_response(2, &[1, 2]);
    let sender_builder = server.lsb_http();

    let server_thread = std::thread::spawn(move || -> io::Result<()> {
        server.accept()?;
        let req = server.recv_http_q()?;
        assert_eq!(req.method(), "GET");
        assert_eq!(req.path(), "/settings");
        assert_eq!(
            req.header("user-agent"),
            Some(concat!("questdb/rust/", env!("CARGO_PKG_VERSION")))
        );
        server.send_settings_response()?;

        let req = server.recv_http_q()?;
        assert_eq!(req.body(), buffer3.as_bytes());

        server.send_http_response_q(HttpResponse::empty())?;

        Ok(())
    });

    let mut sender = sender_builder.build()?;

    let res = sender.flush_and_keep_with_flags(&buffer1, true);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidApiCall);
    assert_eq!(
        err.msg(),
        "Buffer contains lines for multiple tables. \
        Transactional flushes are only supported for buffers containing lines for a single table."
    );

    let res = sender.flush_and_keep_with_flags(&buffer2, true);

    server_thread.join().unwrap()?;

    // Unpacking the error here allows server errors to bubble first.
    res?;

    Ok(())
}

#[test]
fn test_sender_line_protocol_version() -> TestResult {
    let mut server = MockServer::new()?.configure_settings_response(2, &[1, 2]);
    let sender_builder = server.lsb_http();
    let server_thread = std::thread::spawn(move || -> io::Result<()> {
        server.accept()?;
        let req = server.recv_http_q()?;
        assert_eq!(req.method(), "GET");
        assert_eq!(req.path(), "/settings");
        assert_eq!(
            req.header("user-agent"),
            Some(concat!("questdb/rust/", env!("CARGO_PKG_VERSION")))
        );
        server.send_settings_response()?;
        Ok(())
    });
    let sender = sender_builder.build()?;
    assert_eq!(
        sender.default_line_protocol_version(),
        LineProtocolVersion::V2
    );
    assert_eq!(
        sender.support_line_protocol_versions().unwrap(),
        vec![LineProtocolVersion::V1, LineProtocolVersion::V2]
    );
    server_thread.join().unwrap()?;
    Ok(())
}

#[test]
fn test_sender_line_protocol_version_old_server1() -> TestResult {
    let mut server = MockServer::new()?.configure_settings_response(0, &[1, 2]);
    let sender_builder = server.lsb_http();
    let server_thread = std::thread::spawn(move || -> io::Result<()> {
        server.accept()?;
        let req = server.recv_http_q()?;
        assert_eq!(req.method(), "GET");
        assert_eq!(req.path(), "/settings");
        assert_eq!(
            req.header("user-agent"),
            Some(concat!("questdb/rust/", env!("CARGO_PKG_VERSION")))
        );
        server.send_settings_response()?;
        Ok(())
    });
    let sender = sender_builder.build()?;
    assert_eq!(
        sender.default_line_protocol_version(),
        LineProtocolVersion::V1
    );
    assert!(sender.support_line_protocol_versions().is_none());
    server_thread.join().unwrap()?;
    Ok(())
}

#[test]
fn test_sender_line_protocol_version_old_server2() -> TestResult {
    let mut server = MockServer::new()?.configure_settings_response(0, &[1, 2]);
    let sender_builder = server.lsb_http();
    let server_thread = std::thread::spawn(move || -> io::Result<()> {
        server.accept()?;
        server.send_http_response_q(
            HttpResponse::empty()
                .with_status(404, "Not Found")
                .with_header("content-type", "text/plain")
                .with_body_str("Not Found"),
        )?;
        Ok(())
    });
    let sender = sender_builder.build()?;
    assert_eq!(
        sender.default_line_protocol_version(),
        LineProtocolVersion::V1
    );
    assert!(sender.support_line_protocol_versions().is_none());
    server_thread.join().unwrap()?;
    Ok(())
}

#[test]
fn test_sender_line_protocol_version_unsupported_client() -> TestResult {
    let mut server = MockServer::new()?.configure_settings_response(3, &[3, 4]);
    let sender_builder = server.lsb_http();
    let server_thread = std::thread::spawn(move || -> io::Result<()> {
        server.accept()?;
        server.send_settings_response()?;
        Ok(())
    });
    let res1 = sender_builder.build();
    assert!(res1.is_err());
    let e1 = res1.err().unwrap();
    assert_eq!(e1.code(), ErrorCode::LineProtocolVersionError);
    assert!(e1.msg().contains("Server does not support current client"));
    server_thread.join().unwrap()?;
    Ok(())
}

#[test]
fn test_sender_disable_line_protocol_version_validation() -> TestResult {
    let mut server = MockServer::new()?.configure_settings_response(2, &[1, 2]);
    let mut sender = server
        .lsb_http()
        .disable_line_protocol_validation()?
        .build()?;
    let mut buffer =
        Buffer::new().with_line_proto_version(sender.default_line_protocol_version())?;
    buffer
        .table("test")?
        .symbol("sym", "bol")?
        .column_f64("x", 1.0)?
        .at_now()?;
    let buffer2 = buffer.clone();

    let server_thread = std::thread::spawn(move || -> io::Result<()> {
        server.accept()?;
        let req = server.recv_http_q()?;
        assert_eq!(req.body(), buffer2.as_bytes());
        server.send_http_response_q(HttpResponse::empty())?;
        Ok(())
    });

    sender.flush(&mut buffer)?;
    server_thread.join().unwrap()?;
    Ok(())
}

#[test]
fn test_sender_line_protocol_version1_not_support_array() -> TestResult {
    let mut buffer = Buffer::new().with_line_proto_version(LineProtocolVersion::V1)?;
    let res = buffer
        .table("test")?
        .symbol("sym", "bol")?
        .column_arr("x", &[1.0f64, 2.0]);
    assert!(res.is_err());
    let e1 = res.as_ref().err().unwrap();
    assert_eq!(e1.code(), ErrorCode::LineProtocolVersionError);
    assert!(e1
        .msg()
        .contains("line protocol version v1 does not support array datatype"));
    Ok(())
}
