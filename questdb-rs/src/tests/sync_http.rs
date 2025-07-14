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

use crate::ingress::{Buffer, Protocol, ProtocolVersion, SenderBuilder, TimestampNanos};
use crate::tests::mock::{certs_dir, HttpResponse, MockServer};
use crate::tests::{assert_err_contains, TestResult, f64_to_bytes};
use crate::ErrorCode;
use std::io;
use std::io::ErrorKind;
use std::time::Duration;

#[test]
fn test_two_lines_v1() -> TestResult {
    _test_two_lines(ProtocolVersion::V1)
}

#[test]
fn test_two_lines_v2() -> TestResult {
    _test_two_lines(ProtocolVersion::V2)
}

fn _test_two_lines(version: ProtocolVersion,
) -> TestResult {
    let mut server = MockServer::new()?;
    let mut sender = server.lsb_http().protocol_version(version)?.build()?;
    let mut buffer = sender.new_buffer();
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

    let server_thread = std::thread::spawn(move || -> io::Result<MockServer> {
        server.accept()?;
        let req = server.recv_http_q()?;
        assert_eq!(req.method(), "POST");
        assert_eq!(req.path(), "/write?precision=n");
        assert_eq!(
            req.header("user-agent"),
            Some(concat!("questdb/rust/", env!("CARGO_PKG_VERSION")))
        );
        assert_eq!(req.body(), buffer2.as_bytes());

        server.send_http_response_q(HttpResponse::empty())?;

        Ok(server)
    });

    let res = sender.flush(&mut buffer);

    _ = server_thread.join().unwrap()?;

    res?;

    assert!(buffer.is_empty());

    Ok(())
}

#[test]
fn test_text_plain_error_v1() -> TestResult {
    _test_text_plain_error(ProtocolVersion::V1)
}

#[test]
fn test_text_plain_error_v2() -> TestResult {
    _test_text_plain_error(ProtocolVersion::V2)
}

fn _test_text_plain_error(
    version: ProtocolVersion,
) -> TestResult {
    let mut server = MockServer::new()?;
    let mut sender = server.lsb_http().protocol_version(version)?.build()?;
    let mut buffer = sender.new_buffer();
    buffer
        .table("test")?
        .symbol("sym", "bol")?
        .column_f64("x", 1.0)?
        .at_now()?;
    buffer.table("test")?.column_f64("sym", 2.0)?.at_now()?;
    let buffer2 = buffer.clone();
    let server_thread = std::thread::spawn(move || -> io::Result<MockServer> {
        server.accept()?;
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

        Ok(server)
    });

    assert_err_contains(
        sender.flush(&mut buffer),
        ErrorCode::ServerFlushError,
        "Could not flush buffer: bad wombat",
    );

    assert!(!buffer.is_empty());
    _ = server_thread.join().unwrap()?;

    Ok(())
}

#[test]
fn test_bad_json_error_v1() -> TestResult {
    _test_bad_json_error(ProtocolVersion::V1)
}

#[test]
fn test_bad_json_error_v2() -> TestResult {
    _test_bad_json_error(ProtocolVersion::V2)
}

fn _test_bad_json_error(
    version: ProtocolVersion,
) -> TestResult {
    let mut server = MockServer::new()?;
    let mut sender = server.lsb_http().protocol_version(version)?.build()?;
    let mut buffer = sender.new_buffer();
    buffer
        .table("test")?
        .symbol("sym", "bol")?
        .column_f64("x", 1.0)?
        .at_now()?;
    buffer.table("test")?.column_f64("sym", 2.0)?.at_now()?;

    let buffer2 = buffer.clone();
    let server_thread = std::thread::spawn(move || -> io::Result<MockServer> {
        server.accept()?;
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

        Ok(server)
    });

    let res = sender.flush_and_keep(&buffer);

    _ = server_thread.join().unwrap()?;

    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(err.code(), ErrorCode::ServerFlushError);
    assert_eq!(
        err.msg(),
        "Could not flush buffer: {\"error\":\"bad wombat\"}"
    );

    Ok(())
}

#[test]
fn test_json_error_v1() -> TestResult {
    _test_json_error(ProtocolVersion::V1)
}

#[test]
fn test_json_error_v2() -> TestResult {
    _test_json_error(ProtocolVersion::V2)
}

fn _test_json_error(
    version: ProtocolVersion,
) -> TestResult {
    let mut server = MockServer::new()?;
    let mut sender = server.lsb_http().protocol_version(version)?.build()?;
    let mut buffer = sender.new_buffer();
    buffer
        .table("test")?
        .symbol("sym", "bol")?
        .column_f64("x", 1.0)?
        .at_now()?;
    buffer.table("test")?.column_f64("sym", 2.0)?.at_now()?;

    let buffer2 = buffer.clone();
    let server_thread = std::thread::spawn(move || -> io::Result<MockServer> {
        server.accept()?;
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

        Ok(server)
    });

    assert_err_contains(
        sender.flush_and_keep(&buffer),
        ErrorCode::ServerFlushError,
        "Could not flush buffer: failed to parse line protocol: invalid field format [id: ABC-2, code: invalid, line: 2]",
    );

    _ = server_thread.join().unwrap()?;
    Ok(())
}

#[test]
fn test_no_connection_v1() -> TestResult {
    _test_no_connection(ProtocolVersion::V1)
}

#[test]
fn test_no_connection_v2() -> TestResult {
    _test_no_connection(ProtocolVersion::V2)
}

fn _test_no_connection(
    version: ProtocolVersion,
) -> TestResult {
    let mut sender = SenderBuilder::new(Protocol::Http, "127.0.0.1", 1)
        .protocol_version(version)?
        .build()?;
    let mut buffer = sender.new_buffer();
    buffer
        .table("test")?
        .symbol("sym", "bol")?
        .column_f64("x", 1.0)?
        .at_now()?;
    let res = sender.flush_and_keep(&buffer);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(err.code(), ErrorCode::SocketError);
    assert!(err
        .msg()
        .starts_with("Could not flush buffer: http://127.0.0.1:1/write: io: Connection refused"));
    Ok(())
}

#[test]
fn test_old_server_without_ilp_http_support_v1() -> TestResult {
    _test_old_server_without_ilp_http_support(ProtocolVersion::V1)
}

#[test]
fn test_old_server_without_ilp_http_support_v2() -> TestResult {
    _test_old_server_without_ilp_http_support(ProtocolVersion::V2)
}

fn _test_old_server_without_ilp_http_support(
    version: ProtocolVersion,
) -> TestResult {
    let mut server = MockServer::new()?;
    let mut sender = server.lsb_http().protocol_version(version)?.build()?;
    let mut buffer = sender.new_buffer();
    buffer
        .table("test")?
        .symbol("sym", "bol")?
        .column_f64("x", 1.0)?
        .at_now()?;

    let buffer2 = buffer.clone();
    let server_thread = std::thread::spawn(move || -> io::Result<MockServer> {
        server.accept()?;
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

        Ok(server)
    });

    assert_err_contains(
        sender.flush_and_keep(&buffer),
        ErrorCode::HttpNotSupported,
        "Could not flush buffer: HTTP endpoint does not support ILP.",
    );

    _ = server_thread.join().unwrap()?;
    Ok(())
}

#[test]
fn test_http_basic_auth_v1() -> TestResult {
    _test_http_basic_auth(ProtocolVersion::V1)
}

#[test]
fn test_http_basic_auth_v2() -> TestResult {
    _test_http_basic_auth(ProtocolVersion::V2)
}

fn _test_http_basic_auth(
    version: ProtocolVersion,
) -> TestResult {
    let mut server = MockServer::new()?;
    let mut sender = server
        .lsb_http()
        .protocol_version(version)?
        .username("Aladdin")?
        .password("OpenSesame")?
        .build()?;
    let mut buffer = sender.new_buffer();
    buffer
        .table("test")?
        .symbol("sym", "bol")?
        .column_f64("x", 1.0)?
        .at_now()?;

    let buffer2 = buffer.clone();
    let server_thread = std::thread::spawn(move || -> io::Result<MockServer> {
        server.accept()?;
        let req = server.recv_http_q()?;
        assert_eq!(req.method(), "POST");
        assert_eq!(req.path(), "/write?precision=n");
        assert_eq!(
            req.header("authorization"),
            Some("Basic QWxhZGRpbjpPcGVuU2VzYW1l")
        );
        assert_eq!(req.body(), buffer2.as_bytes());

        server.send_http_response_q(HttpResponse::empty())?;

        Ok(server)
    });

    let res = sender.flush(&mut buffer);

    _ = server_thread.join().unwrap()?;

    res?;

    assert!(buffer.is_empty());

    Ok(())
}

#[test]
fn test_unauthenticated_v1() -> TestResult {
    _test_unauthenticated(ProtocolVersion::V1)
}

#[test]
fn test_unauthenticated_v2() -> TestResult {
    _test_unauthenticated(ProtocolVersion::V2)
}

fn _test_unauthenticated(
    version: ProtocolVersion,
) -> TestResult {
    let mut server = MockServer::new()?;
    let mut sender = server.lsb_http().protocol_version(version)?.build()?;
    let mut buffer = sender.new_buffer();
    buffer
        .table("test")?
        .symbol("sym", "bol")?
        .column_f64("x", 1.0)?
        .at_now()?;

    let buffer2 = buffer.clone();
    let server_thread = std::thread::spawn(move || -> io::Result<MockServer> {
        server.accept()?;
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

        Ok(server)
    });

    assert_err_contains(
        sender.flush(&mut buffer),
        ErrorCode::AuthError,
        "Could not flush buffer: HTTP endpoint authentication error: Unauthorized [code: 401]",
    );
    assert!(!buffer.is_empty());

    _ = server_thread.join().unwrap()?;
    Ok(())
}

#[test]
fn test_token_auth_v1() -> TestResult {
    _test_token_auth(ProtocolVersion::V1)
}

#[test]
fn test_token_auth_v2() -> TestResult {
    _test_token_auth(ProtocolVersion::V2)
}

fn _test_token_auth(
    version: ProtocolVersion,
) -> TestResult {
    let mut server = MockServer::new()?;
    let mut sender = server
        .lsb_http()
        .protocol_version(version)?
        .token("0123456789")?
        .build()?;
    let mut buffer = sender.new_buffer();
    buffer
        .table("test")?
        .symbol("sym", "bol")?
        .column_f64("x", 1.0)?
        .at_now()?;

    let buffer2 = buffer.clone();
    let server_thread = std::thread::spawn(move || -> io::Result<MockServer> {
        server.accept()?;
        let req = server.recv_http_q()?;
        assert_eq!(req.method(), "POST");
        assert_eq!(req.path(), "/write?precision=n");
        assert_eq!(req.header("authorization"), Some("Bearer 0123456789"));
        assert_eq!(req.body(), buffer2.as_bytes());

        server.send_http_response_q(HttpResponse::empty())?;

        Ok(server)
    });

    let res = sender.flush(&mut buffer);

    _ = server_thread.join().unwrap()?;

    res?;

    Ok(())
}

#[test]
fn test_request_timeout_v1() -> TestResult {
    _test_request_timeout(ProtocolVersion::V1)
}

#[test]
fn test_request_timeout_v2() -> TestResult {
    _test_request_timeout(ProtocolVersion::V2)
}

fn _test_request_timeout(
    version: ProtocolVersion,
) -> TestResult {
    let server = MockServer::new()?;
    let request_timeout = Duration::from_millis(50);
    let mut sender = server
        .lsb_http()
        .protocol_version(version)?
        .request_timeout(request_timeout)?
        .build()?;
    let mut buffer = sender.new_buffer();
    buffer
        .table("test")?
        .symbol("sym", "bol")?
        .column_f64("x", 1.0)?
        .at_now()?;

    // Here we use a mock (tcp) server instead and don't send a response back.
    let time_start = std::time::Instant::now();
    let res = sender.flush_and_keep(&buffer);
    let time_elapsed = time_start.elapsed();
    assert_err_contains(res, ErrorCode::SocketError, "per call");
    assert!(time_elapsed >= request_timeout);
    Ok(())
}

#[test]
fn test_tls_v1() -> TestResult {
    _test_tls(ProtocolVersion::V1)
}

#[test]
fn test_tls_v2() -> TestResult {
    _test_tls(ProtocolVersion::V2)
}

fn _test_tls(
    version: ProtocolVersion,
) -> TestResult {
    let mut ca_path = certs_dir();
    ca_path.push("server_rootCA.pem");
    let mut server = MockServer::new()?;
    let mut sender = server
        .lsb_https()
        .tls_roots(ca_path)?
        .protocol_version(version)?
        .build()?;

    let mut buffer = sender.new_buffer();
    buffer
        .table("test")?
        .symbol("t1", "v1")?
        .column_f64("f1", 0.5)?
        .at(TimestampNanos::new(10000000))?;
    let buffer2 = buffer.clone();
    let server_thread = std::thread::spawn(move || -> io::Result<MockServer> {
        server.accept_tls_sync()?;
        let req = server.recv_http_q()?;
        assert_eq!(req.method(), "POST");
        assert_eq!(req.path(), "/write?precision=n");
        assert_eq!(req.body(), buffer2.as_bytes());

        server.send_http_response_q(HttpResponse::empty())?;

        Ok(server)
    });

    let res = sender.flush_and_keep(&buffer);

    _ = server_thread.join().unwrap()?;

    // Unpacking the error here allows server errors to bubble first.
    res?;

    Ok(())
}

#[test]
fn test_user_agent_v1() -> TestResult {
    _test_user_agent(ProtocolVersion::V1)
}

#[test]
fn test_user_agent_v2() -> TestResult {
    _test_user_agent(ProtocolVersion::V2)
}

fn _test_user_agent(
    version: ProtocolVersion,
) -> TestResult {
    let mut server = MockServer::new()?;
    let mut sender = server
        .lsb_http()
        .user_agent("wallabies/1.2.99")?
        .protocol_version(version)?
        .build()?;
    let mut buffer = sender.new_buffer();
    buffer
        .table("test")?
        .symbol("t1", "v1")?
        .column_f64("f1", 0.5)?
        .at(TimestampNanos::new(10000000))?;
    let buffer2 = buffer.clone();
    let server_thread = std::thread::spawn(move || -> io::Result<MockServer> {
        server.accept()?;
        let req = server.recv_http_q()?;
        assert_eq!(req.header("user-agent"), Some("wallabies/1.2.99"));
        assert_eq!(req.body(), buffer2.as_bytes());

        server.send_http_response_q(HttpResponse::empty())?;

        Ok(server)
    });

    let res = sender.flush_and_keep(&buffer);

    _ = server_thread.join().unwrap()?;

    // Unpacking the error here allows server errors to bubble first.
    res?;

    Ok(())
}

#[test]
fn test_two_retries_v1() -> TestResult {
    _test_two_retries(ProtocolVersion::V1)
}

#[test]
fn test_two_retries_v2() -> TestResult {
    _test_two_retries(ProtocolVersion::V2)
}

fn _test_two_retries(
    version: ProtocolVersion,
) -> TestResult {
    // Note: This also tests that the _same_ connection is being reused, i.e. tests keepalive.
    let mut server = MockServer::new()?;
    let mut sender = server
        .lsb_http()
        .protocol_version(version)?
        .retry_timeout(Duration::from_secs(30))?
        .build()?;
    let mut buffer = sender.new_buffer();
    buffer
        .table("test")?
        .symbol("t1", "v1")?
        .column_f64("f1", 0.5)?
        .at(TimestampNanos::new(10000000))?;
    let buffer2 = buffer.clone();
    let server_thread = std::thread::spawn(move || -> io::Result<MockServer> {
        server.accept()?;
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

        Ok(server)
    });

    let res = sender.flush_and_keep(&buffer);

    _ = server_thread.join().unwrap()?;

    // Unpacking the error here allows server errors to bubble first.
    res?;

    Ok(())
}

#[test]
fn test_one_retry_v1() -> TestResult {
    _test_one_retry(ProtocolVersion::V1)
}

#[test]
fn test_one_retry_v2() -> TestResult {
    _test_one_retry(ProtocolVersion::V2)
}

fn _test_one_retry(version: ProtocolVersion) -> TestResult {
    let mut server = MockServer::new()?;
    let mut sender = server
        .lsb_http()
        .retry_timeout(Duration::from_millis(19))?
        .protocol_version(version)?
        .build()?;
    let mut buffer = sender.new_buffer();
    buffer
        .table("test")?
        .symbol("t1", "v1")?
        .column_f64("f1", 0.5)?
        .at(TimestampNanos::new(10000000))?;
    let buffer2 = buffer.clone();

    let server_thread = std::thread::spawn(move || -> io::Result<MockServer> {
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

        Ok(server)
    });

    assert_err_contains(
        sender.flush_and_keep(&buffer),
        ErrorCode::ServerFlushError,
        "Could not flush buffer: error 2",
    );

    _ = server_thread.join().unwrap()?;
    Ok(())
}

#[test]
fn test_transactional_v1() -> TestResult {
    _test_transactional(ProtocolVersion::V1)
}

#[test]
fn test_transactional_v2() -> TestResult {
    _test_transactional(ProtocolVersion::V2)
}

fn _test_transactional(version: ProtocolVersion) -> TestResult {
    let mut server = MockServer::new()?;
    let mut sender = server.lsb_http().protocol_version(version)?.build()?;
    // A buffer with a two tables.
    let mut buffer1 = sender.new_buffer();
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
    let mut buffer2 = sender.new_buffer();
    buffer2
        .table("test")?
        .symbol("t1", "v1")?
        .column_f64("f1", 0.5)?
        .at(TimestampNanos::new(10000000))?;
    let buffer3 = buffer2.clone();
    assert!(buffer2.transactional());

    let server_thread = std::thread::spawn(move || -> io::Result<MockServer> {
        server.accept()?;
        let req = server.recv_http_q()?;
        assert_eq!(req.body(), buffer3.as_bytes());

        server.send_http_response_q(HttpResponse::empty())?;

        Ok(server)
    });

    assert_err_contains(
        sender.flush_and_keep_with_flags(&buffer1, true),
        ErrorCode::InvalidApiCall,
        "Buffer contains lines for multiple tables. \
        Transactional flushes are only supported for buffers containing lines for a single table.",
    );

    let res = sender.flush_and_keep_with_flags(&buffer2, true);

    _ = server_thread.join().unwrap()?;

    // Unpacking the error here allows server errors to bubble first.
    res?;

    Ok(())
}

fn _test_sender_auto_detect_protocol_version(
    supported_versions: Option<Vec<u16>>,
    expect_version: ProtocolVersion,
    max_name_len: usize,
    expect_max_name_len: usize,
) -> TestResult {
    let supported_versions1 = supported_versions.clone();
    let mut server = MockServer::new()?
        .configure_settings_response(supported_versions.as_deref().unwrap_or(&[]), max_name_len);
    let sender_builder = server.lsb_http();

    let server_thread = std::thread::spawn(move || -> io::Result<MockServer> {
        server.accept()?;
        let req = server.recv_http_q()?;
        assert_eq!(req.method(), "GET");
        assert_eq!(req.path(), "/settings");
        match supported_versions1 {
            None => server.send_http_response_q(
                HttpResponse::empty()
                    .with_status(404, "Not Found")
                    .with_header("content-type", "text/plain")
                    .with_body_str("Not Found"),
            )?,
            Some(_) => server.send_settings_response()?,
        }
        let exp = &[
            b"test,t1=v1 ",
            f64_to_bytes("f1", 0.5, expect_version).as_slice(),
            b" 10000000\n",
        ]
        .concat();
        let req = server.recv_http_q()?;
        assert_eq!(req.body(), exp);
        server.send_http_response_q(HttpResponse::empty())?;
        Ok(server)
    });

    let mut sender = sender_builder.build()?;
    assert_eq!(sender.protocol_version(), expect_version);
    assert_eq!(sender.max_name_len(), expect_max_name_len);
    let mut buffer = sender.new_buffer();
    buffer
        .table("test")?
        .symbol("t1", "v1")?
        .column_f64("f1", 0.5)?
        .at(TimestampNanos::new(10000000))?;
    let res = sender.flush(&mut buffer);
    res?;
    _ = server_thread.join().unwrap()?;
    Ok(())
}

#[test]
fn test_sender_auto_protocol_version_basic() -> TestResult {
    _test_sender_auto_detect_protocol_version(Some(vec![1, 2]), ProtocolVersion::V2, 130, 130)
}

#[test]
fn test_sender_auto_protocol_version_old_server1() -> TestResult {
    _test_sender_auto_detect_protocol_version(Some(vec![]), ProtocolVersion::V1, 0, 127)
}

#[test]
fn test_sender_auto_protocol_version_old_server2() -> TestResult {
    _test_sender_auto_detect_protocol_version(None, ProtocolVersion::V1, 0, 127)
}

#[test]
fn test_sender_auto_protocol_version_only_v1() -> TestResult {
    _test_sender_auto_detect_protocol_version(Some(vec![1]), ProtocolVersion::V1, 127, 127)
}

#[test]
fn test_sender_auto_protocol_version_only_v2() -> TestResult {
    _test_sender_auto_detect_protocol_version(Some(vec![2]), ProtocolVersion::V2, 127, 127)
}

#[test]
fn test_sender_auto_protocol_version_unsupported_client() -> TestResult {
    let mut server = MockServer::new()?.configure_settings_response(&[3, 4], 127);
    let sender_builder = server.lsb_http();
    let server_thread = std::thread::spawn(move || -> io::Result<MockServer> {
        server.accept()?;
        server.send_settings_response()?;
        Ok(server)
    });
    assert_err_contains(
        sender_builder.build(),
        ErrorCode::ProtocolVersionError,
        "Server does not support current client",
    );

    // We keep the server around til the end of the test to ensure that the response is fully received.
    _ = server_thread.join().unwrap()?;
    Ok(())
}

#[test]
fn test_sender_short_max_name_len() -> TestResult {
    _test_sender_max_name_len(4, 4, 0)
}

#[test]
fn test_sender_specify_max_name_len_with_response() -> TestResult {
    _test_sender_max_name_len(4, 4, 127)
}

#[test]
fn test_sender_long_max_name_len() -> TestResult {
    _test_sender_max_name_len(130, 130, 0)
}

#[test]
fn test_sender_specify_max_name_len_without_response() -> TestResult {
    _test_sender_max_name_len(0, 16, 16)
}

#[test]
fn test_sender_default_max_name_len() -> TestResult {
    _test_sender_max_name_len(0, 127, 0)
}

fn _test_sender_max_name_len(
    response_max_name_len: usize,
    expect_max_name_len: usize,
    sender_specify_max_name_len: usize,
) -> TestResult {
    let mut server = MockServer::new()?;
    if response_max_name_len != 0 {
        server = server.configure_settings_response(&[1, 2], response_max_name_len);
    }

    let mut sender_builder = server.lsb_http();
    if sender_specify_max_name_len != 0 {
        sender_builder = sender_builder.max_name_len(sender_specify_max_name_len)?;
    }
    let server_thread = std::thread::spawn(move || -> io::Result<MockServer> {
        server.accept()?;
        match response_max_name_len {
            0 => server.send_http_response_q(
                HttpResponse::empty()
                    .with_status(404, "Not Found")
                    .with_header("content-type", "text/plain")
                    .with_body_str("Not Found"),
            )?,
            _ => server.send_settings_response()?,
        }
        Ok(server)
    });
    let sender = sender_builder.build()?;
    assert_eq!(sender.max_name_len(), expect_max_name_len);
    let mut buffer = sender.new_buffer();
    let name = "a name too long";
    if expect_max_name_len < name.len() {
        assert_err_contains(
            buffer.table(name),
            ErrorCode::InvalidName,
            r#"Bad name: "a name too long": Too long (max 4 characters)"#,
        );
    } else {
        assert!(buffer.table(name).is_ok());
    }
    // We keep the server around til the end of the test to ensure that the response is fully received.
    _ = server_thread.join().unwrap()?;
    Ok(())
}

#[test]
fn test_buffer_protocol_version1_not_support_array() -> TestResult {
    let mut buffer = Buffer::new(ProtocolVersion::V1);
    let res = buffer
        .table("test")?
        .symbol("sym", "bol")?
        .column_arr("x", &[1.0f64, 2.0]);
    assert_err_contains(
        res,
        ErrorCode::ProtocolVersionError,
        "Protocol version v1 does not support array datatype",
    );
    Ok(())
}
