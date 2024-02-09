/*******************************************************************************
 *     ___                  _   ____  ____
 *    / _ \ _   _  ___  ___| |_|  _ \| __ )
 *   | | | | | | |/ _ \/ __| __| | | |  _ \
 *   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
 *    \__\_\\__,_|\___||___/\__|____/|____/
 *
 *  Copyright (c) 2014-2019 Appsicle
 *  Copyright (c) 2019-2024 QuestDB
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
use std::io::ErrorKind;
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
        assert_eq!(req.path(), "/write?precision=n");
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
        assert_eq!(req.path(), "/write?precision=n");
        assert_eq!(req.body_str().unwrap(), buffer2.as_str());

        server.send_http_response_q(
            HttpResponse::empty()
                .with_status(400, "Bad Request")
                .with_header("content-type", "text/plain")
                .with_body_str("bad wombat"),
        )?;

        Ok(())
    });

    let res = sender.flush(&mut buffer);

    server_thread.join().unwrap()?;

    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(err.code(), ErrorCode::ServerFlushError);
    assert_eq!(err.msg(), "Could not flush buffer: bad wombat");

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
        assert_eq!(req.path(), "/write?precision=n");
        assert_eq!(req.body_str().unwrap(), buffer2.as_str());

        server.send_http_response_q(
            HttpResponse::empty()
                .with_status(400, "Bad Request")
                .with_body_json(&serde_json::json!({
                    "error": "bad wombat",
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
        "Could not flush buffer: {\"error\":\"bad wombat\"}"
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
        assert_eq!(req.path(), "/write?precision=n");
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
        "Could not flush buffer: http://127.0.0.1:1/write?precision=n: Connection Failed"
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
        assert_eq!(req.path(), "/write?precision=n");
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
        assert_eq!(req.path(), "/write?precision=n");
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
        assert_eq!(req.path(), "/write?precision=n");
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
        assert_eq!(req.path(), "/write?precision=n");
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
        assert_eq!(req.path(), "/write?precision=n");
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

#[test]
fn test_retry_on_500_err() -> TestResult {
    // Note: This also tests that the _same_ connection is being reused, i.e. tests keepalive.

    let mut buffer = Buffer::new();
    buffer
        .table("test")?
        .symbol("t1", "v1")?
        .column_f64("f1", 0.5)?
        .at(TimestampNanos::new(10000000))?;
    let buffer2 = buffer.clone();

    let mut retry_interval = Duration::from_millis(50);
    if std::env::var("TF_BUILD").is_ok() {
        // Slow everything down on the CI. The boxes can be _very_ slow there.
        retry_interval = Duration::from_secs(2);
    }

    let mut server = MockServer::new()?;
    let mut sender = server
        .lsb()
        .http()
        .retry_interval(retry_interval)
        .connect()?;

    let server_thread = std::thread::spawn(move || -> io::Result<()> {
        server.accept()?;

        let req = server.recv_http_q()?;
        assert_eq!(req.body_str().unwrap(), buffer2.as_str());

        server.send_http_response_q(
            HttpResponse::empty()
                .with_status(500, "Internal Server Error")
                .with_body_str("client should retry"),
        )?;

        let start_time = std::time::Instant::now();

        let req = server.recv_http_q()?;
        assert_eq!(req.body_str().unwrap(), buffer2.as_str());
        let elapsed = std::time::Instant::now().duration_since(start_time);
        assert!(elapsed > retry_interval);
        assert!(elapsed < (retry_interval * 3 / 2));

        server.send_http_response_q(
            HttpResponse::empty()
                .with_status(500, "Internal Server Error")
                .with_body_str("client should retry"),
        )?;

        let start_time = std::time::Instant::now();

        let req = server.recv_http_q()?;
        assert_eq!(req.body_str().unwrap(), buffer2.as_str());
        assert!(std::time::Instant::now().duration_since(start_time) > (retry_interval * 2));

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
fn test_max_retry() -> TestResult {
    let mut buffer = Buffer::new();
    buffer
        .table("test")?
        .symbol("t1", "v1")?
        .column_f64("f1", 0.5)?
        .at(TimestampNanos::new(10000000))?;
    let buffer2 = buffer.clone();

    let retry_interval = Duration::from_millis(1);

    let mut server = MockServer::new()?;
    let mut sender = server
        .lsb()
        .http()
        .retry_interval(retry_interval)
        .max_retries(1)
        .connect()?;

    let server_thread = std::thread::spawn(move || -> io::Result<()> {
        server.accept()?;

        let req = server.recv_http_q()?;
        assert_eq!(req.body_str().unwrap(), buffer2.as_str());

        server.send_http_response_q(
            HttpResponse::empty()
                .with_status(500, "Internal Server Error")
                .with_body_str("error 1"),
        )?;

        let req = server.recv_http_q()?;
        assert_eq!(req.body_str().unwrap(), buffer2.as_str());

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
                ))
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

#[test]
fn test_transactional() -> TestResult {
    // A buffer with a two tables.
    let mut buffer1 = Buffer::new();
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
    let mut buffer2 = Buffer::new();
    buffer2
        .table("test")?
        .symbol("t1", "v1")?
        .column_f64("f1", 0.5)?
        .at(TimestampNanos::new(10000000))?;
    let buffer3 = buffer2.clone();
    assert!(buffer2.transactional());

    let mut server = MockServer::new()?;
    let mut sender = server.lsb().http().transactional().connect()?;

    let server_thread = std::thread::spawn(move || -> io::Result<()> {
        server.accept()?;

        let req = server.recv_http_q()?;
        assert_eq!(req.body_str().unwrap(), buffer3.as_str());

        server.send_http_response_q(HttpResponse::empty())?;

        Ok(())
    });

    let res = sender.flush_and_keep(&buffer1);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidApiCall);
    assert_eq!(
        err.msg(),
        "Buffer contains lines for multiple tables. \
        Transactional flushes are only supported for buffers containing lines for a single table."
    );

    let res = sender.flush_and_keep(&buffer2);

    server_thread.join().unwrap()?;

    // Unpacking the error here allows server errors to bubble first.
    res?;

    Ok(())
}
