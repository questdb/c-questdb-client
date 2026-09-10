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
use crate::ingress::{Buffer, Protocol, ProtocolVersion, SenderBuilder, TimestampNanos};
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

#[test]
fn test_retryable_provider_failure_is_retried_within_the_budget() -> TestResult {
    // Regression: the auth header used to be resolved in `Sender::flush_impl`,
    // outside `http_send_with_retries`, so a provider failure ended the flush
    // after zero requests and zero milliseconds of `retry_timeout`. The C and
    // Python bindings clear the sender-owned buffer on any flush failure, and
    // the retry they document -- `SocketError` means "retry, exactly as you
    // would any other" -- then re-flushed an empty buffer and reported success,
    // so a peer holding the OIDC token-store lock for a few seconds destroyed
    // the batch and the loss looked like a successful write.
    //
    // The provider fails twice with a retryable error and then succeeds. The
    // assertion is that the flush completes, with the rows intact, on the
    // budget the caller configured.
    let mut server = MockServer::new()?;
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = calls.clone();
    let mut sender = server
        .lsb_http()
        .protocol_version(ProtocolVersion::V2)?
        .http_token_provider(move || {
            if seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst) < 2 {
                // The shape a token-store lock wait produces: recoverable, and
                // classified `SocketError` by `classify_provider_error`.
                return Err(crate::error::fmt!(
                    SocketError,
                    "could not acquire the OIDC token-store lock"
                ));
            }
            Ok("tok".to_string())
        })?
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
        // The rows survived the provider failures rather than being dropped.
        assert_eq!(req.body(), buffer2.as_bytes());
        assert_eq!(req.header("authorization"), Some("Bearer tok"));
        server.send_http_response_q(HttpResponse::empty())?;
        Ok(server)
    });

    // Assert the flush before joining. On a regression the flush fails without
    // ever sending, so the server thread is still parked in `accept()` and
    // joining it first would hang CI instead of failing it.
    sender.flush_and_keep(&buffer)?;
    _ = server_thread.join().unwrap()?;
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 3);
    Ok(())
}

#[test]
fn test_terminal_provider_failure_does_not_spend_the_retry_budget() -> TestResult {
    // The other half of the contract above: only the failures
    // `classify_provider_error` leaves as `SocketError` are re-resolved. A
    // caller contract violation arrives as a terminal `ConfigError` and must
    // fail the flush at once -- retrying it would burn the whole window on
    // state that no later invocation changes, and (unlike the retryable case)
    // waiting cannot help.
    let server = MockServer::new()?;
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = calls.clone();
    let mut sender = server
        .lsb_http()
        .protocol_version(ProtocolVersion::V2)?
        .http_token_provider(move || {
            seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err::<String, _>(crate::error::fmt!(
                InvalidApiCall,
                "provider contract violation"
            ))
        })?
        .retry_timeout(Duration::from_secs(30))?
        .build()?;
    let mut buffer = sender.new_buffer();
    buffer
        .table("test")?
        .symbol("t1", "v1")?
        .column_f64("f1", 0.5)?
        .at(TimestampNanos::new(10000000))?;

    let start = std::time::Instant::now();
    let err = sender.flush_and_keep(&buffer).unwrap_err();
    let elapsed = start.elapsed();

    assert_eq!(err.code(), crate::ErrorCode::ConfigError);
    // Resolved once, not on a ladder, and nowhere near the 30s budget.
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(elapsed < Duration::from_secs(5), "elapsed: {elapsed:?}");
    Ok(())
}

#[test]
fn test_interaction_required_fails_the_flush_without_waiting() -> TestResult {
    // `classify_provider_error` keeps `InteractionRequired` retryable so the QWP
    // drainer does not abandon queued frames on a condition a human can fix. A
    // single foreground flush has no such horizon: nothing it waits for produces
    // a sign-in, so re-resolving would only make "nobody has signed in" arrive a
    // whole `retry_timeout` late, on every flush.
    let server = MockServer::new()?;
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = calls.clone();
    let mut sender = server
        .lsb_http()
        .protocol_version(ProtocolVersion::V2)?
        .http_token_provider(move || {
            seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err::<String, _>(crate::Error::from(
                crate::oidc::OidcError::interaction_required("no cached credential"),
            ))
        })?
        .retry_timeout(Duration::from_secs(30))?
        .build()?;
    let mut buffer = sender.new_buffer();
    buffer
        .table("test")?
        .symbol("t1", "v1")?
        .column_f64("f1", 0.5)?
        .at(TimestampNanos::new(10000000))?;

    let start = std::time::Instant::now();
    let err = sender.flush_and_keep(&buffer).unwrap_err();
    let elapsed = start.elapsed();

    // Still classified retryable for callers that key on the code.
    assert_eq!(err.code(), crate::ErrorCode::SocketError);
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(elapsed < Duration::from_secs(5), "elapsed: {elapsed:?}");
    Ok(())
}

#[test]
fn test_credential_rotation_budget_is_one_per_flush() -> TestResult {
    // Regression: the rotation budget is one per FLUSH. `http_send_with_retries`
    // spends it on the pre-loop 401, then hands off to `retry_http_send`, which
    // used to start its own `auth_retry_used` at `false` -- so a second 401 later
    // in the same flush rotated again and replayed the whole buffer a second
    // time, twice what the C header and this module both promise.
    //
    // Script: 401 (rotate) -> 500 (ladder) -> 401. The assertion is that the
    // second 401 ends the flush instead of buying another replay.
    let mut server = MockServer::new()?;
    let provider_seq = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut sender = server
        .lsb_http()
        .protocol_version(ProtocolVersion::V2)?
        .http_token_provider(move || {
            Ok::<_, crate::Error>(format!(
                "tok{}",
                provider_seq.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            ))
        })?
        .retry_timeout(Duration::from_secs(30))?
        .build()?;
    let mut buffer = sender.new_buffer();
    buffer
        .table("test")?
        .symbol("t1", "v1")?
        .column_f64("f1", 0.5)?
        .at(TimestampNanos::new(10000000))?;

    let server_thread = std::thread::spawn(move || -> io::Result<usize> {
        server.accept()?;
        let mut requests = 0usize;

        // 1: the credential resolved for the flush. 401 spends the budget.
        let req = server.recv_http_q()?;
        requests += 1;
        assert_eq!(req.header("authorization"), Some("Bearer tok0"));
        server.send_http_response_q(
            HttpResponse::empty()
                .with_status(401, "Unauthorized")
                .with_body_str("Unauthorized"),
        )?;

        // 2: the one rotated replay, answered 5xx so the flush enters
        // `retry_http_send` with the budget already spent.
        let req = server.recv_http_q()?;
        requests += 1;
        assert_eq!(req.header("authorization"), Some("Bearer tok1"));
        server.send_http_response_q(
            HttpResponse::empty()
                .with_status(500, "Internal Server Error")
                .with_body_str("client should retry"),
        )?;

        // 3: a second 401 inside the retry loop. It must be reported, not
        // rotated: the provider still has fresh values to hand out, so a
        // surviving budget would show up as a fourth request bearing "tok2".
        let req = server.recv_http_q()?;
        requests += 1;
        assert_eq!(req.header("authorization"), Some("Bearer tok1"));
        server.send_http_response_q(
            HttpResponse::empty()
                .with_status(401, "Unauthorized")
                .with_body_str("Unauthorized"),
        )?;

        // Nothing further may arrive. Read with a short deadline so a
        // regression fails here rather than hanging the suite.
        Ok(requests)
    });

    let res = sender.flush_and_keep(&buffer);
    let requests = server_thread.join().unwrap()?;

    assert_eq!(
        requests, 3,
        "one flush must not spend the rotation budget twice"
    );
    let err = res.unwrap_err();
    assert_eq!(err.code(), ErrorCode::AuthError);
    Ok(())
}

#[test]
fn test_credential_rotation_keeps_retry_backoff() -> TestResult {
    // Regression: `retry_http_send`'s credential-rotation branch used to make
    // the rotated retry immediate by setting `retry_interval_ms = 0`. That
    // value is the backoff *ladder*, so every later
    // `retry_interval_ms.saturating_mul(2)` computed `0 * 2` and a single 401
    // disabled backoff for the rest of the window: any genuinely retryable
    // failure after it re-sent the whole buffer with a sub-millisecond gap
    // until `retry_end`.
    //
    // The script is 500 (ladder -> 10ms), 401 (rotate, retried with no wait),
    // 500 (ladder -> 20ms); the wait before the fourth request is then the
    // assertion -- with the bug it arrives in ~1ms.
    let mut server = MockServer::new()?;
    let provider_seq = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut sender = server
        .lsb_http()
        .protocol_version(ProtocolVersion::V2)?
        // A fresh value per call, so the 401 reads as an expiry the provider
        // can rotate out of rather than a genuine rejection (which is what
        // `rotated_auth_after_401` returning `None` would mean).
        .http_token_provider(move || {
            Ok::<_, crate::Error>(format!(
                "tok{}",
                provider_seq.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            ))
        })?
        .retry_timeout(Duration::from_secs(30))?
        .build()?;
    let mut buffer = sender.new_buffer();
    buffer
        .table("test")?
        .symbol("t1", "v1")?
        .column_f64("f1", 0.5)?
        .at(TimestampNanos::new(10000000))?;

    let server_thread = std::thread::spawn(move || -> io::Result<MockServer> {
        server.accept()?;

        // 1: the attempt made before the retry loop. A 5xx starts the ladder.
        let req = server.recv_http_q()?;
        assert_eq!(req.header("authorization"), Some("Bearer tok0"));
        server.send_http_response_q(
            HttpResponse::empty()
                .with_status(500, "Internal Server Error")
                .with_body_str("client should retry"),
        )?;

        // 2: still the credential resolved for the flush. Answer 401 so the
        // provider is consulted again and hands back a rotated value.
        let req = server.recv_http_q()?;
        assert_eq!(req.header("authorization"), Some("Bearer tok0"));
        server.send_http_response_q(
            HttpResponse::empty()
                .with_status(401, "Unauthorized")
                .with_body_str("Unauthorized"),
        )?;

        // 3: carries the rotated credential, which is what proves the
        // rotation branch ran at all.
        let req = server.recv_http_q()?;
        assert_eq!(req.header("authorization"), Some("Bearer tok1"));
        server.send_http_response_q(
            HttpResponse::empty()
                .with_status(500, "Internal Server Error")
                .with_body_str("client should retry"),
        )?;

        // 4: the ladder must have survived the rotation and be at ~20ms.
        let start_time = std::time::Instant::now();
        let req = server.recv_http_q()?;
        let elapsed = std::time::Instant::now().duration_since(start_time);
        assert_eq!(req.header("authorization"), Some("Bearer tok1"));
        assert!(
            elapsed > Duration::from_millis(15),
            "credential rotation disabled the retry backoff: \
             the next attempt came after {elapsed:?}"
        );

        server.send_http_response_q(HttpResponse::empty())?;

        Ok(server)
    });

    let res = sender.flush_and_keep(&buffer);

    _ = server_thread.join().unwrap()?;

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
