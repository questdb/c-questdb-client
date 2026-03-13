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

use crate::ErrorCode;
use crate::ingress::{Buffer, Protocol, ProtocolVersion, Sender, SenderBuilder, TimestampNanos};
use crate::tests::mock::{HttpResponse, MockServer, certs_dir};
use crate::tests::{TestResult, assert_err_contains};
use rstest::rstest;
use std::io;
use std::io::ErrorKind;
use std::time::Duration;

#[rstest]
fn test_two_lines(
    #[values(ProtocolVersion::V1, ProtocolVersion::V2)] version: ProtocolVersion,
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

#[rstest]
fn test_text_plain_error(
    #[values(ProtocolVersion::V1, ProtocolVersion::V2)] version: ProtocolVersion,
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

#[rstest]
fn test_bad_json_error(
    #[values(ProtocolVersion::V1, ProtocolVersion::V2)] version: ProtocolVersion,
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

#[rstest]
fn test_json_error(
    #[values(ProtocolVersion::V1, ProtocolVersion::V2)] version: ProtocolVersion,
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

#[rstest]
fn test_no_connection(
    #[values(ProtocolVersion::V1, ProtocolVersion::V2)] version: ProtocolVersion,
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
    assert!(
        err.msg().starts_with(
            "Could not flush buffer: http://127.0.0.1:1/write: io: Connection refused"
        )
    );
    Ok(())
}

#[rstest]
fn test_old_server_without_ilp_http_support(
    #[values(ProtocolVersion::V1, ProtocolVersion::V2)] version: ProtocolVersion,
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

#[rstest]
fn test_http_basic_auth(
    #[values(ProtocolVersion::V1, ProtocolVersion::V2)] version: ProtocolVersion,
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

#[rstest]
fn test_unauthenticated(
    #[values(ProtocolVersion::V1, ProtocolVersion::V2)] version: ProtocolVersion,
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

#[rstest]
fn test_token_auth(
    #[values(ProtocolVersion::V1, ProtocolVersion::V2)] version: ProtocolVersion,
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

#[rstest]
fn test_request_timeout(
    #[values(ProtocolVersion::V1, ProtocolVersion::V2)] version: ProtocolVersion,
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

#[rstest]
fn test_tls(
    #[values(ProtocolVersion::V1, ProtocolVersion::V2)] version: ProtocolVersion,
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

#[rstest]
fn test_user_agent(
    #[values(ProtocolVersion::V1, ProtocolVersion::V2)] version: ProtocolVersion,
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

#[rstest]
fn test_two_retries(
    #[values(ProtocolVersion::V1, ProtocolVersion::V2)] version: ProtocolVersion,
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

#[rstest]
fn test_one_retry(
    #[values(ProtocolVersion::V1, ProtocolVersion::V2)] version: ProtocolVersion,
) -> TestResult {
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

#[rstest]
fn test_transactional(
    #[values(ProtocolVersion::V1, ProtocolVersion::V2)] version: ProtocolVersion,
) -> TestResult {
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

        let designated_ts = if expect_version == ProtocolVersion::V1 {
            " 10000000\n"
        } else {
            " 10000000n\n"
        };
        let exp = &[
            b"test,t1=v1 ",
            crate::tests::sender::f64_to_bytes("f1", 0.5, expect_version).as_slice(),
            designated_ts.as_bytes(),
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
    let mut server = MockServer::new()?.configure_settings_response(&[4, 5], 127);
    let sender_builder = server.lsb_http();
    let server_thread = std::thread::spawn(move || -> io::Result<MockServer> {
        server.accept()?;
        server.send_settings_response()?;
        Ok(server)
    });
    assert_err_contains(
        sender_builder.build(),
        ErrorCode::ProtocolVersionError,
        "Server does not support any of the client protocol versions",
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

// ==================== Multi-URL Integration Tests ====================

#[test]
fn test_multi_url_send_to_first_address() -> TestResult {
    // With multiple addresses configured, the first request should go to the first address.
    let mut server1 = MockServer::new()?;
    let server2 = MockServer::new()?;

    let mut sender = SenderBuilder::new(Protocol::Http, server1.host, server1.port)
        .address(server2.host, server2.port)?
        .protocol_version(ProtocolVersion::V2)?
        .build()?;

    let mut buffer = sender.new_buffer();
    buffer
        .table("test")?
        .symbol("sym", "val")?
        .column_f64("x", 1.0)?
        .at_now()?;
    let buffer2 = buffer.clone();

    let server_thread = std::thread::spawn(move || -> io::Result<MockServer> {
        server1.accept()?;
        let req = server1.recv_http_q()?;
        assert_eq!(req.method(), "POST");
        assert_eq!(req.path(), "/write?precision=n");
        assert_eq!(req.body(), buffer2.as_bytes());
        server1.send_http_response_q(HttpResponse::empty())?;
        Ok(server1)
    });

    sender.flush(&mut buffer)?;
    _ = server_thread.join().unwrap()?;
    Ok(())
}

#[test]
fn test_multi_url_failover_on_retriable_error() -> TestResult {
    // First server returns 500, second server should receive the retry.
    let mut server1 = MockServer::new()?;
    let mut server2 = MockServer::new()?;

    let mut sender = SenderBuilder::new(Protocol::Http, server1.host, server1.port)
        .address(server2.host, server2.port)?
        .protocol_version(ProtocolVersion::V2)?
        .retry_timeout(Duration::from_secs(5))?
        .build()?;

    let mut buffer = sender.new_buffer();
    buffer
        .table("test")?
        .symbol("sym", "val")?
        .column_f64("x", 1.0)?
        .at_now()?;
    let buffer2 = buffer.clone();
    let buffer3 = buffer.clone();

    let s1_thread = std::thread::spawn(move || -> io::Result<MockServer> {
        server1.accept()?;
        let req = server1.recv_http_q()?;
        assert_eq!(req.body(), buffer2.as_bytes());
        // Return a retriable 500 error.
        server1.send_http_response_q(
            HttpResponse::empty()
                .with_status(500, "Internal Server Error")
                .with_body_str("server1 is down"),
        )?;
        Ok(server1)
    });

    let s2_thread = std::thread::spawn(move || -> io::Result<MockServer> {
        server2.accept()?;
        let req = server2.recv_http_q()?;
        assert_eq!(req.body(), buffer3.as_bytes());
        // Second server succeeds.
        server2.send_http_response_q(HttpResponse::empty())?;
        Ok(server2)
    });

    sender.flush(&mut buffer)?;
    _ = s1_thread.join().unwrap()?;
    _ = s2_thread.join().unwrap()?;
    Ok(())
}

#[test]
fn test_multi_url_failover_on_503() -> TestResult {
    // 503 Service Unavailable should trigger failover.
    let mut server1 = MockServer::new()?;
    let mut server2 = MockServer::new()?;

    let mut sender = SenderBuilder::new(Protocol::Http, server1.host, server1.port)
        .address(server2.host, server2.port)?
        .protocol_version(ProtocolVersion::V2)?
        .retry_timeout(Duration::from_secs(5))?
        .build()?;

    let mut buffer = sender.new_buffer();
    buffer
        .table("test")?
        .column_f64("x", 1.0)?
        .at_now()?;
    let buf_copy = buffer.clone();

    let s1_thread = std::thread::spawn(move || -> io::Result<MockServer> {
        server1.accept()?;
        let _req = server1.recv_http_q()?;
        server1.send_http_response_q(
            HttpResponse::empty()
                .with_status(503, "Service Unavailable")
                .with_body_str("try later"),
        )?;
        Ok(server1)
    });

    let s2_thread = std::thread::spawn(move || -> io::Result<MockServer> {
        server2.accept()?;
        let req = server2.recv_http_q()?;
        assert_eq!(req.body(), buf_copy.as_bytes());
        server2.send_http_response_q(HttpResponse::empty())?;
        Ok(server2)
    });

    sender.flush(&mut buffer)?;
    _ = s1_thread.join().unwrap()?;
    _ = s2_thread.join().unwrap()?;
    Ok(())
}

#[test]
fn test_multi_url_all_servers_unavailable() -> TestResult {
    // All servers return 500 — should fail after retry timeout.
    let mut server1 = MockServer::new()?;
    let mut server2 = MockServer::new()?;

    let mut sender = SenderBuilder::new(Protocol::Http, server1.host, server1.port)
        .address(server2.host, server2.port)?
        .protocol_version(ProtocolVersion::V2)?
        .retry_timeout(Duration::from_millis(200))?
        .build()?;

    let mut buffer = sender.new_buffer();
    buffer
        .table("test")?
        .column_f64("x", 1.0)?
        .at_now()?;

    // Both servers always return 500.
    let s1_thread = std::thread::spawn(move || -> io::Result<MockServer> {
        server1.accept()?;
        loop {
            match server1.recv_http(1.0) {
                Ok(_req) => {
                    if server1
                        .send_http_response_q(
                            HttpResponse::empty()
                                .with_status(500, "Internal Server Error")
                                .with_body_str("server1 down"),
                        )
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        Ok(server1)
    });

    let s2_thread = std::thread::spawn(move || -> io::Result<MockServer> {
        server2.accept()?;
        loop {
            match server2.recv_http(1.0) {
                Ok(_req) => {
                    if server2
                        .send_http_response_q(
                            HttpResponse::empty()
                                .with_status(500, "Internal Server Error")
                                .with_body_str("server2 down"),
                        )
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        Ok(server2)
    });

    let res = sender.flush(&mut buffer);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(err.code(), ErrorCode::ServerFlushError);
    // Validate the error message contains useful information.
    let msg = format!("{}", err);
    assert!(
        msg.contains("server1 down") || msg.contains("server2 down"),
        "Error should contain one of the server error bodies: {}", msg
    );

    _ = s1_thread.join().unwrap();
    _ = s2_thread.join().unwrap();
    Ok(())
}

#[test]
fn test_multi_url_round_robin_rotation() -> TestResult {
    // After first failover, next flush should start from rotated position.
    let mut server1 = MockServer::new()?;
    let mut server2 = MockServer::new()?;

    let mut sender = SenderBuilder::new(Protocol::Http, server1.host, server1.port)
        .address(server2.host, server2.port)?
        .protocol_version(ProtocolVersion::V2)?
        .retry_timeout(Duration::from_secs(5))?
        .build()?;

    // First flush: server1 fails, server2 succeeds
    let mut buffer = sender.new_buffer();
    buffer
        .table("test")?
        .column_f64("x", 1.0)?
        .at_now()?;
    let buf_copy = buffer.clone();

    let s1_thread = std::thread::spawn(move || -> io::Result<MockServer> {
        server1.accept()?;
        let _req = server1.recv_http_q()?;
        server1.send_http_response_q(
            HttpResponse::empty()
                .with_status(500, "Internal Server Error")
                .with_body_str("server1 down"),
        )?;
        Ok(server1)
    });

    let s2_thread = std::thread::spawn(move || -> io::Result<MockServer> {
        server2.accept()?;
        let req = server2.recv_http_q()?;
        assert_eq!(req.body(), buf_copy.as_bytes());
        server2.send_http_response_q(HttpResponse::empty())?;
        Ok(server2)
    });

    sender.flush(&mut buffer)?;
    let _server1 = s1_thread.join().unwrap()?;
    let mut server2 = s2_thread.join().unwrap()?;

    // Second flush: after rotation, the sender's current index has been rotated.
    // Next initial attempt goes to the next endpoint in rotation.
    // With 2 servers and a rotation after the first failover, the current_index
    // points to server2 (index 1). The initial attempt of the next flush starts
    // from the current_index which is 1 (server2).
    let mut buffer2 = sender.new_buffer();
    buffer2
        .table("test")?
        .column_f64("y", 2.0)?
        .at_now()?;
    let buf2_copy = buffer2.clone();

    // server2 receives next flush (it's now the current endpoint after rotation)
    let s2_thread = std::thread::spawn(move || -> io::Result<MockServer> {
        let req = server2.recv_http_q()?;
        assert_eq!(req.body(), buf2_copy.as_bytes());
        server2.send_http_response_q(HttpResponse::empty())?;
        Ok(server2)
    });

    sender.flush(&mut buffer2)?;
    _ = s2_thread.join().unwrap()?;
    Ok(())
}

#[test]
fn test_multi_url_non_retriable_error_no_failover() -> TestResult {
    // 400 Bad Request is not retriable, so no failover should occur.
    let mut server1 = MockServer::new()?;
    let _server2 = MockServer::new()?;

    let mut sender = SenderBuilder::new(Protocol::Http, server1.host, server1.port)
        .address(_server2.host, _server2.port)?
        .protocol_version(ProtocolVersion::V2)?
        .retry_timeout(Duration::from_secs(5))?
        .build()?;

    let mut buffer = sender.new_buffer();
    buffer
        .table("test")?
        .column_f64("x", 1.0)?
        .at_now()?;

    let s1_thread = std::thread::spawn(move || -> io::Result<MockServer> {
        server1.accept()?;
        let _req = server1.recv_http_q()?;
        server1.send_http_response_q(
            HttpResponse::empty()
                .with_status(400, "Bad Request")
                .with_body_str("invalid line protocol"),
        )?;
        Ok(server1)
    });

    let res = sender.flush(&mut buffer);
    assert!(res.is_err());
    assert_eq!(res.unwrap_err().code(), ErrorCode::ServerFlushError);

    _ = s1_thread.join().unwrap()?;
    // server2 should never receive a request (we don't join on it)
    Ok(())
}

#[test]
fn test_multi_url_auth_error_no_failover() -> TestResult {
    // 401 Unauthorized is not retriable, so no failover.
    let mut server1 = MockServer::new()?;
    let _server2 = MockServer::new()?;

    let mut sender = SenderBuilder::new(Protocol::Http, server1.host, server1.port)
        .address(_server2.host, _server2.port)?
        .protocol_version(ProtocolVersion::V2)?
        .retry_timeout(Duration::from_secs(5))?
        .build()?;

    let mut buffer = sender.new_buffer();
    buffer
        .table("test")?
        .column_f64("x", 1.0)?
        .at_now()?;

    let s1_thread = std::thread::spawn(move || -> io::Result<MockServer> {
        server1.accept()?;
        let _req = server1.recv_http_q()?;
        server1.send_http_response_q(
            HttpResponse::empty()
                .with_status(401, "Unauthorized")
                .with_body_str("bad credentials"),
        )?;
        Ok(server1)
    });

    let res = sender.flush(&mut buffer);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(err.code(), ErrorCode::AuthError);
    let msg = format!("{}", err);
    assert!(msg.contains("bad credentials"), "Error should contain server message: {}", msg);

    _ = s1_thread.join().unwrap()?;
    Ok(())
}

#[test]
fn test_multi_url_failover_on_504() -> TestResult {
    // 504 Gateway Timeout should trigger failover.
    let mut server1 = MockServer::new()?;
    let mut server2 = MockServer::new()?;

    let mut sender = SenderBuilder::new(Protocol::Http, server1.host, server1.port)
        .address(server2.host, server2.port)?
        .protocol_version(ProtocolVersion::V2)?
        .retry_timeout(Duration::from_secs(5))?
        .build()?;

    let mut buffer = sender.new_buffer();
    buffer
        .table("test")?
        .column_f64("x", 1.0)?
        .at_now()?;
    let buf_copy = buffer.clone();

    let s1_thread = std::thread::spawn(move || -> io::Result<MockServer> {
        server1.accept()?;
        let _req = server1.recv_http_q()?;
        server1.send_http_response_q(
            HttpResponse::empty()
                .with_status(504, "Gateway Timeout")
                .with_body_str("upstream timeout"),
        )?;
        Ok(server1)
    });

    let s2_thread = std::thread::spawn(move || -> io::Result<MockServer> {
        server2.accept()?;
        let req = server2.recv_http_q()?;
        assert_eq!(req.body(), buf_copy.as_bytes());
        server2.send_http_response_q(HttpResponse::empty())?;
        Ok(server2)
    });

    sender.flush(&mut buffer)?;
    _ = s1_thread.join().unwrap()?;
    _ = s2_thread.join().unwrap()?;
    Ok(())
}

#[test]
fn test_multi_url_three_servers_failover_chain() -> TestResult {
    // Server1 returns 500, server2 returns 503, server3 succeeds.
    let mut server1 = MockServer::new()?;
    let mut server2 = MockServer::new()?;
    let mut server3 = MockServer::new()?;

    let mut sender = SenderBuilder::new(Protocol::Http, server1.host, server1.port)
        .address(server2.host, server2.port)?
        .address(server3.host, server3.port)?
        .protocol_version(ProtocolVersion::V2)?
        .retry_timeout(Duration::from_secs(10))?
        .build()?;

    let mut buffer = sender.new_buffer();
    buffer
        .table("test")?
        .column_f64("x", 1.0)?
        .at_now()?;
    let buf2 = buffer.clone();
    let buf3 = buffer.clone();

    let s1_thread = std::thread::spawn(move || -> io::Result<MockServer> {
        server1.accept()?;
        let _req = server1.recv_http_q()?;
        server1.send_http_response_q(
            HttpResponse::empty()
                .with_status(500, "Internal Server Error")
                .with_body_str("down"),
        )?;
        Ok(server1)
    });

    let s2_thread = std::thread::spawn(move || -> io::Result<MockServer> {
        server2.accept()?;
        let req = server2.recv_http_q()?;
        assert_eq!(req.body(), buf2.as_bytes());
        server2.send_http_response_q(
            HttpResponse::empty()
                .with_status(503, "Service Unavailable")
                .with_body_str("also down"),
        )?;
        Ok(server2)
    });

    let s3_thread = std::thread::spawn(move || -> io::Result<MockServer> {
        server3.accept()?;
        let req = server3.recv_http_q()?;
        assert_eq!(req.body(), buf3.as_bytes());
        server3.send_http_response_q(HttpResponse::empty())?;
        Ok(server3)
    });

    sender.flush(&mut buffer)?;
    _ = s1_thread.join().unwrap()?;
    _ = s2_thread.join().unwrap()?;
    _ = s3_thread.join().unwrap()?;
    Ok(())
}

#[test]
fn test_multi_url_successful_first_attempt_no_rotation() -> TestResult {
    // Successful first attempt should not cause rotation.
    let mut server1 = MockServer::new()?;
    let _server2 = MockServer::new()?;

    let mut sender = SenderBuilder::new(Protocol::Http, server1.host, server1.port)
        .address(_server2.host, _server2.port)?
        .protocol_version(ProtocolVersion::V2)?
        .build()?;

    let mut buffer = sender.new_buffer();
    buffer
        .table("test")?
        .column_f64("x", 1.0)?
        .at_now()?;
    let buf_copy = buffer.clone();

    let s1_thread = std::thread::spawn(move || -> io::Result<MockServer> {
        server1.accept()?;
        let req = server1.recv_http_q()?;
        assert_eq!(req.body(), buf_copy.as_bytes());
        server1.send_http_response_q(HttpResponse::empty())?;
        Ok(server1)
    });

    sender.flush(&mut buffer)?;
    let mut server1 = s1_thread.join().unwrap()?;

    // Second flush should also go to server1 (no rotation happened).
    let mut buffer2 = sender.new_buffer();
    buffer2
        .table("test")?
        .column_f64("y", 2.0)?
        .at_now()?;
    let buf2_copy = buffer2.clone();

    let s1_thread2 = std::thread::spawn(move || -> io::Result<MockServer> {
        let req = server1.recv_http_q()?;
        assert_eq!(req.body(), buf2_copy.as_bytes());
        server1.send_http_response_q(HttpResponse::empty())?;
        Ok(server1)
    });

    sender.flush(&mut buffer2)?;
    _ = s1_thread2.join().unwrap()?;
    Ok(())
}

#[test]
fn test_multi_url_config_string_builds_sender() -> TestResult {
    // Verify a multi-addr config string builds a working sender.
    let mut server1 = MockServer::new()?;
    let server2 = MockServer::new()?;

    let conf = format!(
        "http::addr={}:{};addr={}:{};protocol_version=2;",
        server1.host, server1.port, server2.host, server2.port
    );

    let mut sender = Sender::from_conf(&conf)?;

    let mut buffer = sender.new_buffer();
    buffer
        .table("test")?
        .column_f64("x", 1.0)?
        .at_now()?;

    let s1_thread = std::thread::spawn(move || -> io::Result<MockServer> {
        server1.accept()?;
        let _req = server1.recv_http_q()?;
        server1.send_http_response_q(HttpResponse::empty())?;
        Ok(server1)
    });

    sender.flush(&mut buffer)?;
    _ = s1_thread.join().unwrap()?;
    Ok(())
}

#[test]
fn test_multi_url_failover_on_507() -> TestResult {
    // 507 Insufficient Storage should trigger failover.
    let mut server1 = MockServer::new()?;
    let mut server2 = MockServer::new()?;

    let mut sender = SenderBuilder::new(Protocol::Http, server1.host, server1.port)
        .address(server2.host, server2.port)?
        .protocol_version(ProtocolVersion::V2)?
        .retry_timeout(Duration::from_secs(5))?
        .build()?;

    let mut buffer = sender.new_buffer();
    buffer
        .table("test")?
        .column_f64("x", 1.0)?
        .at_now()?;
    let buf_copy = buffer.clone();

    let s1_thread = std::thread::spawn(move || -> io::Result<MockServer> {
        server1.accept()?;
        let _req = server1.recv_http_q()?;
        server1.send_http_response_q(
            HttpResponse::empty()
                .with_status(507, "Insufficient Storage")
                .with_body_str("disk full"),
        )?;
        Ok(server1)
    });

    let s2_thread = std::thread::spawn(move || -> io::Result<MockServer> {
        server2.accept()?;
        let req = server2.recv_http_q()?;
        assert_eq!(req.body(), buf_copy.as_bytes());
        server2.send_http_response_q(HttpResponse::empty())?;
        Ok(server2)
    });

    sender.flush(&mut buffer)?;
    _ = s1_thread.join().unwrap()?;
    _ = s2_thread.join().unwrap()?;
    Ok(())
}

#[test]
fn test_multi_url_failover_on_request_timeout() -> TestResult {
    // First server accepts but never responds (timeout),
    // second server should receive the retry.
    let server1 = MockServer::new()?;
    let mut server2 = MockServer::new()?;

    let mut sender = SenderBuilder::new(Protocol::Http, server1.host, server1.port)
        .address(server2.host, server2.port)?
        .protocol_version(ProtocolVersion::V2)?
        .request_timeout(Duration::from_millis(100))?
        .retry_timeout(Duration::from_secs(5))?
        .request_min_throughput(0)?
        .build()?;

    let mut buffer = sender.new_buffer();
    buffer
        .table("test")?
        .column_f64("x", 1.0)?
        .at_now()?;
    let buf_copy = buffer.clone();

    // server1 accepts but never responds — the client will time out.
    // We don't join on server1's thread since it just hangs.

    let s2_thread = std::thread::spawn(move || -> io::Result<MockServer> {
        server2.accept()?;
        let req = server2.recv_http_q()?;
        assert_eq!(req.body(), buf_copy.as_bytes());
        server2.send_http_response_q(HttpResponse::empty())?;
        Ok(server2)
    });

    sender.flush(&mut buffer)?;
    _ = s2_thread.join().unwrap()?;
    Ok(())
}

#[test]
fn test_multi_url_retriable_status_codes() -> TestResult {
    // Test that all retriable status codes trigger failover.
    let retriable_codes: Vec<(u16, &str)> = vec![
        (421, "Misdirected Request"),
        (500, "Internal Server Error"),
        (502, "Bad Gateway"),
        (503, "Service Unavailable"),
        (504, "Gateway Timeout"),
        (507, "Insufficient Storage"),
        (509, "Bandwidth Limit Exceeded"),
        (523, "Origin Is Unreachable"),
        (524, "A Timeout Occurred"),
        (529, "Site is overloaded"),
        (599, "Network Connect Timeout Error"),
    ];

    for (code, text) in retriable_codes {
        let mut server1 = MockServer::new()?;
        let mut server2 = MockServer::new()?;

        let mut sender = SenderBuilder::new(Protocol::Http, server1.host, server1.port)
            .address(server2.host, server2.port)?
            .protocol_version(ProtocolVersion::V2)?
            .retry_timeout(Duration::from_secs(5))?
            .build()?;

        let mut buffer = sender.new_buffer();
        buffer
            .table("test")?
            .column_f64("x", 1.0)?
            .at_now()?;
        let buf_copy = buffer.clone();

        let code_copy = code;
        let text_copy = text.to_string();
        let s1_thread = std::thread::spawn(move || -> io::Result<MockServer> {
            server1.accept()?;
            let _req = server1.recv_http_q()?;
            server1.send_http_response_q(
                HttpResponse::empty()
                    .with_status(code_copy, &text_copy)
                    .with_body_str("error"),
            )?;
            Ok(server1)
        });

        let s2_thread = std::thread::spawn(move || -> io::Result<MockServer> {
            server2.accept()?;
            let req = server2.recv_http_q()?;
            assert_eq!(req.body(), buf_copy.as_bytes());
            server2.send_http_response_q(HttpResponse::empty())?;
            Ok(server2)
        });

        sender.flush(&mut buffer).map_err(|e| {
            format!("Failed for status code {code}: {}", e.msg())
        })?;
        _ = s1_thread.join().unwrap()?;
        _ = s2_thread.join().unwrap()?;
    }
    Ok(())
}

#[test]
fn test_multi_url_non_retriable_status_codes() -> TestResult {
    // Test that non-retriable status codes do NOT trigger failover.
    let non_retriable_codes: Vec<(u16, &str, ErrorCode)> = vec![
        (400, "Bad Request", ErrorCode::ServerFlushError),
        (401, "Unauthorized", ErrorCode::AuthError),
        (403, "Forbidden", ErrorCode::AuthError),
        (404, "Not Found", ErrorCode::HttpNotSupported),
        (422, "Unprocessable Entity", ErrorCode::ServerFlushError),
    ];

    for (code, text, expected_error_code) in non_retriable_codes {
        let mut server1 = MockServer::new()?;
        let _server2 = MockServer::new()?;

        let mut sender = SenderBuilder::new(Protocol::Http, server1.host, server1.port)
            .address(_server2.host, _server2.port)?
            .protocol_version(ProtocolVersion::V2)?
            .retry_timeout(Duration::from_secs(5))?
            .build()?;

        let mut buffer = sender.new_buffer();
        buffer
            .table("test")?
            .column_f64("x", 1.0)?
            .at_now()?;

        let code_copy = code;
        let text_copy = text.to_string();
        let s1_thread = std::thread::spawn(move || -> io::Result<MockServer> {
            server1.accept()?;
            let _req = server1.recv_http_q()?;
            server1.send_http_response_q(
                HttpResponse::empty()
                    .with_status(code_copy, &text_copy)
                    .with_body_str("error body"),
            )?;
            Ok(server1)
        });

        let res = sender.flush(&mut buffer);
        assert!(
            res.is_err(),
            "Expected error for status code {code}, but got Ok"
        );
        assert_eq!(
            res.unwrap_err().code(),
            expected_error_code,
            "Wrong error code for status {code}"
        );

        _ = s1_thread.join().unwrap()?;
    }
    Ok(())
}

#[test]
fn test_multi_url_single_address_still_works() -> TestResult {
    // Verify single-address configuration works unchanged with new multi-url code.
    let mut server = MockServer::new()?;
    let mut sender = server
        .lsb_http()
        .protocol_version(ProtocolVersion::V2)?
        .retry_timeout(Duration::from_millis(50))?
        .build()?;

    let mut buffer = sender.new_buffer();
    buffer
        .table("test")?
        .column_f64("x", 1.0)?
        .at_now()?;

    let server_thread = std::thread::spawn(move || -> io::Result<MockServer> {
        server.accept()?;
        let _req = server.recv_http_q()?;
        server.send_http_response_q(HttpResponse::empty())?;
        Ok(server)
    });

    sender.flush(&mut buffer)?;
    _ = server_thread.join().unwrap()?;
    Ok(())
}

#[test]
fn test_multi_url_single_address_retry_no_rotation() -> TestResult {
    // Single address: retry stays on the same server (no rotation effect).
    let mut server = MockServer::new()?;
    let mut sender = server
        .lsb_http()
        .protocol_version(ProtocolVersion::V2)?
        .retry_timeout(Duration::from_secs(5))?
        .build()?;

    let mut buffer = sender.new_buffer();
    buffer
        .table("test")?
        .column_f64("x", 1.0)?
        .at_now()?;
    let buf_copy = buffer.clone();

    let server_thread = std::thread::spawn(move || -> io::Result<MockServer> {
        server.accept()?;
        let _req = server.recv_http_q()?;
        server.send_http_response_q(
            HttpResponse::empty()
                .with_status(500, "Internal Server Error")
                .with_body_str("first fail"),
        )?;
        let req = server.recv_http_q()?;
        assert_eq!(req.body(), buf_copy.as_bytes());
        server.send_http_response_q(HttpResponse::empty())?;
        Ok(server)
    });

    sender.flush(&mut buffer)?;
    _ = server_thread.join().unwrap()?;
    Ok(())
}

/// Test that 421 Misdirected Request triggers failover to the next endpoint.
#[test]
fn test_multi_url_failover_on_421() -> TestResult {
    let mut server1 = MockServer::new()?;
    let mut server2 = MockServer::new()?;

    let mut sender = SenderBuilder::new(Protocol::Http, server1.host, server1.port)
        .address(server2.host, server2.port)?
        .protocol_version(ProtocolVersion::V2)?
        .retry_timeout(Duration::from_secs(5))?
        .build()?;

    let mut buffer = sender.new_buffer();
    buffer
        .table("test")?
        .column_f64("x", 1.0)?
        .at_now()?;
    let buf_copy = buffer.clone();

    // Server1 returns 421 Misdirected Request — should trigger failover.
    let s1_thread = std::thread::spawn(move || -> io::Result<MockServer> {
        server1.accept()?;
        let _req = server1.recv_http_q()?;
        server1.send_http_response_q(
            HttpResponse::empty().with_status(421, "Misdirected Request"),
        )?;
        Ok(server1)
    });

    let s2_thread = std::thread::spawn(move || -> io::Result<MockServer> {
        server2.accept()?;
        let req = server2.recv_http_q()?;
        assert_eq!(req.body(), buf_copy.as_bytes());
        server2.send_http_response_q(HttpResponse::empty().with_status(200, "OK"))?;
        Ok(server2)
    });

    sender.flush(&mut buffer)?;
    _ = s1_thread.join().unwrap()?;
    _ = s2_thread.join().unwrap()?;
    Ok(())
}

/// Test that settings negotiation tries the next endpoint if the first one fails.
#[test]
fn test_multi_url_settings_negotiation_failover() -> TestResult {
    let mut server1 = MockServer::new()?;
    let mut server2 = MockServer::new()?;

    let s1_port = server1.port;
    let s2_port = server2.port;

    // Build sender — this triggers settings negotiation.
    // Server1's /settings endpoint returns 500, server2's returns valid settings.
    let s1_thread = std::thread::spawn(move || -> io::Result<MockServer> {
        server1.accept()?;
        let _req = server1.recv_http_q()?;
        server1.send_http_response_q(
            HttpResponse::empty()
                .with_status(500, "Internal Server Error")
                .with_body_str("settings endpoint down"),
        )?;
        Ok(server1)
    });

    let s2_thread = std::thread::spawn(move || -> io::Result<MockServer> {
        server2.accept()?;
        let _req = server2.recv_http_q()?;
        let settings_json = r#"{
            "config": {
                "line.proto.support.versions": [1, 2],
                "cairo.max.file.name.length": 127
            }
        }"#;
        server2.send_http_response_q(
            HttpResponse::empty()
                .with_status(200, "OK")
                .with_header("Content-Type", "application/json")
                .with_body_str(settings_json),
        )?;
        Ok(server2)
    });

    // auto protocol version triggers settings negotiation
    let sender = SenderBuilder::new(Protocol::Http, "127.0.0.1", s1_port)
        .address("127.0.0.1", s2_port)?
        .build()?;

    // If we got here, settings were successfully negotiated via server2.
    assert_eq!(sender.protocol_version(), ProtocolVersion::V2);

    _ = s1_thread.join().unwrap()?;
    _ = s2_thread.join().unwrap()?;
    Ok(())
}

/// Test that connection refused on server1 triggers failover to server2.
#[test]
fn test_multi_url_failover_on_connection_refused() -> TestResult {
    // server1 is dropped immediately so its port refuses connections.
    let server1 = MockServer::new()?;
    let s1_port = server1.port;
    drop(server1);

    let mut server2 = MockServer::new()?;

    let mut sender = SenderBuilder::new(Protocol::Http, "127.0.0.1", s1_port)
        .address(server2.host, server2.port)?
        .protocol_version(ProtocolVersion::V2)?
        .retry_timeout(Duration::from_secs(5))?
        .build()?;

    let mut buffer = sender.new_buffer();
    buffer
        .table("test")?
        .column_f64("x", 1.0)?
        .at_now()?;
    let buf_copy = buffer.clone();

    let s2_thread = std::thread::spawn(move || -> io::Result<MockServer> {
        server2.accept()?;
        let req = server2.recv_http_q()?;
        assert_eq!(req.body(), buf_copy.as_bytes());
        server2.send_http_response_q(HttpResponse::empty().with_status(200, "OK"))?;
        Ok(server2)
    });

    sender.flush(&mut buffer)?;
    _ = s2_thread.join().unwrap()?;
    Ok(())
}

/// Test that 502 Bad Gateway triggers failover.
#[test]
fn test_multi_url_failover_on_502() -> TestResult {
    let mut server1 = MockServer::new()?;
    let mut server2 = MockServer::new()?;

    let mut sender = SenderBuilder::new(Protocol::Http, server1.host, server1.port)
        .address(server2.host, server2.port)?
        .protocol_version(ProtocolVersion::V2)?
        .retry_timeout(Duration::from_secs(5))?
        .build()?;

    let mut buffer = sender.new_buffer();
    buffer
        .table("test")?
        .column_f64("x", 1.0)?
        .at_now()?;
    let buf_copy = buffer.clone();

    let s1_thread = std::thread::spawn(move || -> io::Result<MockServer> {
        server1.accept()?;
        let _req = server1.recv_http_q()?;
        server1.send_http_response_q(
            HttpResponse::empty().with_status(502, "Bad Gateway"),
        )?;
        Ok(server1)
    });

    let s2_thread = std::thread::spawn(move || -> io::Result<MockServer> {
        server2.accept()?;
        let req = server2.recv_http_q()?;
        assert_eq!(req.body(), buf_copy.as_bytes());
        server2.send_http_response_q(HttpResponse::empty().with_status(200, "OK"))?;
        Ok(server2)
    });

    sender.flush(&mut buffer)?;
    _ = s1_thread.join().unwrap()?;
    _ = s2_thread.join().unwrap()?;
    Ok(())
}

// ==================== End of Multi-URL Tests ====================

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

// --- Rotation unit tests (moved from ingress/sender/http.rs) ---

mod rotation {
    use crate::ingress::conf;
    use crate::ingress::sender::http::{HttpEndpoint, SyncHttpHandlerState};

    fn make_dummy_agent() -> ureq::Agent {
        ureq::Agent::new_with_defaults()
    }

    fn make_endpoint(host: &str, port: u16) -> HttpEndpoint {
        HttpEndpoint {
            agent: make_dummy_agent(),
            url: format!("http://{host}:{port}/write"),
            settings_url: format!("http://{host}:{port}/settings"),
        }
    }

    fn make_state(hosts: &[(&str, u16)]) -> SyncHttpHandlerState {
        let endpoints: Vec<HttpEndpoint> = hosts
            .iter()
            .map(|(h, p)| make_endpoint(h, *p))
            .collect();
        SyncHttpHandlerState {
            endpoints,
            current_index: 0,
            auth: None,
            config: conf::HttpConfig::default(),
        }
    }

    #[test]
    fn rotation_single_endpoint_no_op() {
        let mut state = make_state(&[("host1", 9000)]);
        assert_eq!(state.current_index, 0);
        assert_eq!(state.current_endpoint().url, "http://host1:9000/write");
        state.rotate();
        assert_eq!(state.current_index, 0);
        assert_eq!(state.current_endpoint().url, "http://host1:9000/write");
    }

    #[test]
    fn rotation_round_robin_three() {
        let mut state = make_state(&[("host1", 9000), ("host2", 9001), ("host3", 9002)]);

        assert_eq!(state.current_endpoint().url, "http://host1:9000/write");
        state.rotate();
        assert_eq!(state.current_endpoint().url, "http://host2:9001/write");
        state.rotate();
        assert_eq!(state.current_endpoint().url, "http://host3:9002/write");
        state.rotate();
        assert_eq!(state.current_endpoint().url, "http://host1:9000/write");
        state.rotate();
        assert_eq!(state.current_endpoint().url, "http://host2:9001/write");
    }

    #[test]
    fn rotation_two_endpoints_alternates() {
        let mut state = make_state(&[("a", 1), ("b", 2)]);

        for _ in 0..10 {
            assert_eq!(state.current_index, 0);
            state.rotate();
            assert_eq!(state.current_index, 1);
            state.rotate();
        }
    }

    #[test]
    fn rotation_wraps_at_boundary() {
        let mut state = make_state(&[("a", 1), ("b", 2), ("c", 3), ("d", 4), ("e", 5)]);
        for i in 0..25 {
            assert_eq!(state.current_index, i % 5);
            state.rotate();
        }
    }

    #[test]
    fn current_endpoint_returns_correct_endpoint() {
        let state = make_state(&[("first", 1000), ("second", 2000), ("third", 3000)]);
        assert_eq!(state.current_endpoint().url, "http://first:1000/write");
        assert_eq!(
            state.current_endpoint().settings_url,
            "http://first:1000/settings"
        );
    }

    #[test]
    fn rotation_after_manual_index_set() {
        let mut state = make_state(&[("a", 1), ("b", 2), ("c", 3)]);
        state.current_index = 2;
        state.rotate();
        assert_eq!(state.current_index, 0); // wraps from 2 -> 0
        state.rotate();
        assert_eq!(state.current_index, 1);
    }
}
