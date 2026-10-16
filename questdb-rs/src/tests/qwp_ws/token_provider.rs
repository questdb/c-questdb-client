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

//! Rotating credentials on the QWP/WebSocket sender and the egress reader
//! (design/qwp-token-provider-spec.md §6, §8.1, §8.2): the provider hears
//! about a rejected token, a `RefreshingTokenProvider` refreshes it, the
//! `WWW-Authenticate` challenge decides whether a 401 is retried, and a
//! connect the caller waits for retries only a retryable provider failure.

use super::*;

use crate::token_provider::{BearerTokenProvider, ExpiringToken, RefreshingTokenProvider};
use std::sync::Mutex;

const PLAIN_401: &[u8] =
    b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const INVALID_TOKEN_401: &[u8] = b"HTTP/1.1 401 Unauthorized\r\n\
    WWW-Authenticate: Bearer realm=\"questdb\", error=\"invalid_token\"\r\n\
    Content-Length: 0\r\nConnection: close\r\n\r\n";
const INSUFFICIENT_SCOPE_401: &[u8] = b"HTTP/1.1 401 Unauthorized\r\n\
    WWW-Authenticate: Bearer error=\"insufficient_scope\"\r\n\
    Content-Length: 0\r\nConnection: close\r\n\r\n";

/// Answers the first connection with `rejection`, upgrades the next one if it
/// arrives within two seconds, and reports each connection's request lines.
fn spawn_reject_then_upgrade_server(
    rejection: &'static [u8],
) -> (u16, mpsc::Receiver<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let (mut first, _) = listener.accept().unwrap();
        let request = read_request_until_blank(&mut first).unwrap();
        let lines = String::from_utf8_lossy(&request)
            .split("\r\n")
            .take_while(|line| !line.is_empty())
            .map(String::from)
            .collect();
        first.write_all(rejection).unwrap();
        drop(first);
        let _ = tx.send(lines);

        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut second = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return;
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return,
            }
        };
        second.set_nonblocking(false).unwrap();
        let lines = perform_server_upgrade(&mut second).unwrap();
        let _ = tx.send(lines);
        second
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        if read_frame(&mut second).is_ok() {
            let _ = write_qwp_error_response(
                &mut second,
                QWP_STATUS_SCHEMA_MISMATCH,
                FIRST_WIRE_SEQUENCE,
                b"done",
            );
        }
    });
    (port, rx)
}

fn authorization(lines: &[String]) -> String {
    lines
        .iter()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case("authorization")
                .then(|| value.trim().to_string())
        })
        .expect("authorization header")
}

fn counting_refreshing_provider() -> (RefreshingTokenProvider, Arc<AtomicUsize>) {
    let fetches = Arc::new(AtomicUsize::new(0));
    let provider = RefreshingTokenProvider::builder({
        let fetches = Arc::clone(&fetches);
        move || -> crate::Result<ExpiringToken> {
            let n = fetches.fetch_add(1, Ordering::SeqCst) + 1;
            Ok(ExpiringToken::expires_in(
                format!("T{n}"),
                Duration::from_secs(3_600),
            ))
        }
    })
    .build()
    .unwrap();
    assert!(provider.await_ready(Duration::from_secs(5)));
    (provider, fetches)
}

/// C10: a stale token gets exactly one 401, then an immediate retry with the
/// token the forced refresh fetched.
#[test]
fn a_refreshing_provider_refreshes_a_rejected_token_and_retries_once() {
    let (provider, fetches) = counting_refreshing_provider();
    let (port, rx) = spawn_reject_then_upgrade_server(PLAIN_401);
    let builder = SenderBuilder::new(Protocol::Ws, "127.0.0.1", port)
        .qwp_ws_token_provider(provider.clone())
        .unwrap();
    let mut sender = build_qwp_ws_sender_from_builder(ProgressCase::Background, builder);
    let mut buf = sender.new_buffer();
    buf.table("trades")
        .unwrap()
        .column_i64("qty", 1)
        .unwrap()
        .at_now()
        .unwrap();
    let _ = sender.flush_and_get_fsn(&mut buf);

    let first = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let second = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("the endpoint was not retried with the refreshed token");
    assert_eq!(authorization(&first), "Bearer T1");
    assert_eq!(authorization(&second), "Bearer T2");
    assert_eq!(
        fetches.load(Ordering::SeqCst),
        2,
        "prefetch plus one forced"
    );
    drop(sender);
    provider.close();
}

/// A provider of the application's own type hears which token was rejected,
/// once, before it is asked for a replacement.
#[test]
fn an_application_provider_hears_the_rejected_token() {
    #[derive(Default)]
    struct Recording {
        rejected: Arc<Mutex<Vec<(String, u16)>>>,
    }
    impl BearerTokenProvider for Recording {
        fn token(&self) -> crate::Result<String> {
            let rejected = self.rejected.lock().unwrap();
            Ok(if rejected.is_empty() {
                "stale"
            } else {
                "fresh"
            }
            .to_string())
        }

        fn on_rejected(&self, token: &str, http_status: u16) {
            self.rejected
                .lock()
                .unwrap()
                .push((token.to_string(), http_status));
        }
    }

    let provider = Recording::default();
    let rejected = Arc::clone(&provider.rejected);
    let (port, rx) = spawn_reject_then_upgrade_server(PLAIN_401);
    let builder = SenderBuilder::new(Protocol::Ws, "127.0.0.1", port)
        .qwp_ws_token_provider(provider)
        .unwrap();
    let mut sender = build_qwp_ws_sender_from_builder(ProgressCase::Background, builder);
    let mut buf = sender.new_buffer();
    buf.table("trades")
        .unwrap()
        .column_i64("qty", 1)
        .unwrap()
        .at_now()
        .unwrap();
    let _ = sender.flush_and_get_fsn(&mut buf);

    let first = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let second = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(authorization(&first), "Bearer stale");
    assert_eq!(authorization(&second), "Bearer fresh");
    assert_eq!(*rejected.lock().unwrap(), vec![("stale".to_string(), 401)]);
}

/// C23: a plain 401 and one with `Bearer error="invalid_token"` are retried
/// with a new token; one whose challenge names another error is not.
#[test]
fn the_www_authenticate_challenge_decides_whether_a_401_is_retried() {
    for (rejection, retried) in [
        (PLAIN_401, true),
        (INVALID_TOKEN_401, true),
        (INSUFFICIENT_SCOPE_401, false),
    ] {
        let calls = Arc::new(AtomicUsize::new(0));
        let (port, rx) = spawn_reject_then_upgrade_server(rejection);
        let conf = format!("ws::addr=127.0.0.1:{port};initial_connect_retry=off;");
        let result = SenderBuilder::from_conf(&conf)
            .unwrap()
            .qwp_ws_token_provider({
                let calls = Arc::clone(&calls);
                move || {
                    let n = calls.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, crate::Error>(if n == 0 { "stale" } else { "fresh" }.to_string())
                }
            })
            .unwrap()
            .build();
        let first = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(authorization(&first), "Bearer stale");
        if retried {
            let second = rx.recv_timeout(Duration::from_secs(5)).unwrap();
            assert_eq!(authorization(&second), "Bearer fresh");
            drop(result);
        } else {
            let Err(err) = result else {
                panic!("a 401 for insufficient scope must fail the connect");
            };
            assert_eq!(err.code(), ErrorCode::AuthError, "{err}");
            assert!(err.msg().contains("insufficient_scope"), "{err}");
            assert_eq!(calls.load(Ordering::SeqCst), 1, "no second token pull");
            assert!(
                rx.recv_timeout(Duration::from_millis(500)).is_err(),
                "the endpoint was retried although no new token can help"
            );
        }
    }
}

/// A connect the caller waits for (`initial_connect_retry=sync`) against a
/// provider that fails with `error`: the result, how often the provider was
/// called, and how long the connect took.
fn sync_initial_connect_with(
    error: impl Fn() -> crate::Error + Send + Sync + 'static,
) -> (crate::Result<()>, usize, Duration) {
    // Bound but never accepted: the provider runs before any dial.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let calls = Arc::new(AtomicUsize::new(0));
    let conf = format!(
        "ws::addr=127.0.0.1:{port};initial_connect_retry=sync;\
         reconnect_initial_backoff_millis=10;reconnect_max_backoff_millis=10;\
         reconnect_max_duration_millis=1500;"
    );
    let builder = SenderBuilder::from_conf(&conf)
        .unwrap()
        .qwp_ws_token_provider({
            let calls = Arc::clone(&calls);
            move || -> crate::Result<String> {
                calls.fetch_add(1, Ordering::SeqCst);
                Err(error())
            }
        })
        .unwrap();
    let started = Instant::now();
    let result = builder.build().map(drop);
    let elapsed = started.elapsed();
    drop(listener);
    (result, calls.load(Ordering::SeqCst), elapsed)
}

/// C12, D8: a failure the provider did not classify ends the connect at once.
#[test]
fn sync_initial_connect_fails_fast_on_an_unclassified_provider_failure() {
    let (result, calls, elapsed) =
        sync_initial_connect_with(|| crate::Error::new(ErrorCode::SocketError, "idp down"));
    let err = result.expect_err("the provider never supplies a token");
    assert!(err.msg().contains("idp down"), "{err}");
    assert_eq!(calls, 1, "an unclassified failure was retried");
    assert!(elapsed < Duration::from_millis(1_000), "{elapsed:?}");
}

/// C12, D8: a permanent token-unavailable failure ends the connect at once.
#[test]
fn sync_initial_connect_fails_fast_on_a_permanent_provider_failure() {
    let (result, calls, _) = sync_initial_connect_with(|| {
        crate::Error::token_unavailable(false, None, "identity not assigned")
    });
    let err = result.expect_err("the provider never supplies a token");
    assert!(err.msg().contains("identity not assigned"), "{err}");
    assert_eq!(calls, 1, "a permanent failure was retried");
}

/// C12, D6: a retryable token-unavailable failure is retried within the
/// reconnect budget.
#[test]
fn sync_initial_connect_retries_a_retryable_provider_failure() {
    let (result, calls, _) = sync_initial_connect_with(|| {
        crate::Error::token_unavailable(true, None, "idp unreachable")
    });
    let err = result.expect_err("the provider never supplies a token");
    assert!(err.msg().contains("idp unreachable"), "{err}");
    assert!(
        calls > 1,
        "a retryable failure must be retried, got {calls} call(s)"
    );
}

/// A `RefreshingTokenProvider` whose source keeps failing retryably is retried
/// within the budget; a closed one stops every client at once.
#[test]
fn sync_initial_connect_with_a_refreshing_provider() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let conf = format!(
        "ws::addr=127.0.0.1:{port};initial_connect_retry=sync;\
         reconnect_initial_backoff_millis=10;reconnect_max_backoff_millis=10;\
         reconnect_max_duration_millis=800;"
    );
    let fetches = Arc::new(AtomicUsize::new(0));
    let provider = RefreshingTokenProvider::builder({
        let fetches = Arc::clone(&fetches);
        move || -> crate::Result<ExpiringToken> {
            fetches.fetch_add(1, Ordering::SeqCst);
            Err(crate::Error::token_unavailable(
                true,
                None,
                "idp unreachable",
            ))
        }
    })
    .cold_wait(Duration::from_millis(100))
    .backoff_initial(Duration::from_millis(10))
    .backoff_max(Duration::from_millis(20))
    .build()
    .unwrap();
    let err = SenderBuilder::from_conf(&conf)
        .unwrap()
        .qwp_ws_token_provider(provider.clone())
        .unwrap()
        .build()
        .map(drop)
        .expect_err("the source never supplies a token");
    assert!(err.msg().contains("idp unreachable"), "{err}");
    assert!(fetches.load(Ordering::SeqCst) > 1);

    provider.close();
    let started = Instant::now();
    let err = SenderBuilder::from_conf(&conf)
        .unwrap()
        .qwp_ws_token_provider(provider)
        .unwrap()
        .build()
        .map(drop)
        .expect_err("a closed provider supplies no token");
    assert_eq!(err.code(), ErrorCode::AuthError, "{err}");
    assert!(err.msg().contains("closed"), "{err}");
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "a closed provider was retried"
    );
    drop(listener);
}

/// The egress reader refreshes a rejected token through a
/// `RefreshingTokenProvider` and replays the endpoint once.
#[cfg(feature = "sync-reader-qwp-ws")]
#[test]
fn the_reader_refreshes_a_rejected_token() {
    let (provider, fetches) = counting_refreshing_provider();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut first, _) = listener.accept().unwrap();
        let request = read_request_until_blank(&mut first).unwrap();
        tx.send(String::from_utf8_lossy(&request).into_owned())
            .unwrap();
        first.write_all(INVALID_TOKEN_401).unwrap();
        drop(first);
        let (mut second, _) = listener.accept().unwrap();
        // Version 0 lets the reader connect without a SERVER_INFO frame.
        let request_lines = perform_server_upgrade_with_version(&mut second, 0).unwrap();
        tx.send(request_lines.join("\r\n")).unwrap();
        let mut sink = [0u8; 256];
        let _ = second.read(&mut sink);
    });
    let cfg = crate::egress::ReaderConfig::from_conf(format!("ws::addr=127.0.0.1:{port};"))
        .unwrap()
        .token_provider(provider.clone())
        .unwrap();
    let reader = crate::egress::Reader::from_config(&cfg);
    let has_authorization = |request: &str, value: &str| {
        request.split("\r\n").any(|line| {
            line.split_once(':').is_some_and(|(key, found)| {
                key.eq_ignore_ascii_case("authorization") && found.trim() == value
            })
        })
    };
    let first = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(has_authorization(&first, "Bearer T1"), "{first}");
    let second = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(has_authorization(&second, "Bearer T2"), "{second}");
    let reader = reader.expect("the replay with the refreshed token connects");
    assert_eq!(fetches.load(Ordering::SeqCst), 2);
    drop(reader);
    server.join().unwrap();
    provider.close();
}

/// This client selects no token provider from a connect string, so the keys
/// the specification reserves for that are rejected on every schema, with a
/// pointer to the in-code API (spec §7.2): a string that asked for a
/// credential must never connect without one.
#[test]
fn the_reserved_token_provider_keys_are_rejected() {
    for setting in [
        "token_provider=azure",
        "azure_resource=api://questdb",
        "azure_client_id=00000000-0000-0000-0000-000000000000",
        "azure_credential=managed_identity",
    ] {
        let key = setting.split('=').next().unwrap();
        // Every schema this build supports.
        let mut schemas = vec!["ws", "wss"];
        #[cfg(feature = "_sender-http")]
        schemas.extend(["http", "https"]);
        #[cfg(feature = "_sender-tcp")]
        schemas.extend(["tcp", "tcps"]);
        for schema in schemas {
            let conf = format!("{schema}::addr=localhost:9000;{setting};");
            let Err(err) = SenderBuilder::from_conf(&conf) else {
                panic!("{conf} was accepted");
            };
            assert_eq!(err.code(), ErrorCode::ConfigError, "{conf}: {err}");
            assert!(err.msg().contains(&format!("\"{key}\"")), "{err}");
            assert!(
                err.msg().contains("supported token_provider values: none"),
                "{err}"
            );
            assert!(err.msg().contains("bearer_token_provider"), "{err}");
        }
        #[cfg(feature = "sync-reader-qwp-ws")]
        {
            let conf = format!("ws::addr=localhost:9000;{setting};");
            let err = crate::egress::ReaderConfig::from_conf(&conf).unwrap_err();
            assert_eq!(err.code(), ErrorCode::ConfigError, "{err}");
            assert!(
                err.msg().contains("supported token_provider values: none"),
                "{err}"
            );
        }
        let conf = format!("ws::addr=localhost:9000;lazy_connect=true;{setting};");
        let Err(err) = crate::QuestDb::connect(&conf) else {
            panic!("the pool accepted {conf}");
        };
        assert!(
            err.msg().contains("supported token_provider values: none"),
            "{err}"
        );
    }
}

// ---------- §8.3: rejections and outages once connected ----------

const FORBIDDEN_403: &[u8] =
    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// Reads an upgrade request and answers it with `rejection`, returning the
/// request's `Authorization` header.
fn reject_upgrade(stream: &mut TcpStream, rejection: &[u8]) -> String {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let request = read_request_until_blank(stream).unwrap();
    let lines: Vec<String> = String::from_utf8_lossy(&request)
        .split("\r\n")
        .take_while(|line| !line.is_empty())
        .map(String::from)
        .collect();
    stream.write_all(rejection).unwrap();
    authorization(&lines)
}

/// Reads frames, acknowledging each, until the client goes away.
fn ack_every_frame(stream: &mut TcpStream) {
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut wire_seq = FIRST_WIRE_SEQUENCE;
    while let Ok((_, opcode, _)) = read_frame(stream) {
        if opcode == OPCODE_CLOSE || write_qwp_ok_response(stream, wire_seq).is_err() {
            return;
        }
        wire_seq += 1;
    }
}

/// Upgrades the first connection and drops it as soon as one frame arrives,
/// unacknowledged. Answers the next connections with `rejections`, one each,
/// then upgrades one more and acknowledges everything on it. Reports each
/// connection's `Authorization` header.
fn spawn_reject_after_disconnect_server(
    rejections: Vec<&'static [u8]>,
) -> (u16, mpsc::Receiver<String>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut first, _) = listener.accept().unwrap();
        let lines = perform_server_upgrade(&mut first).unwrap();
        let _ = tx.send(authorization(&lines));
        read_frame(&mut first).unwrap();
        drop(first);
        for rejection in rejections {
            let (mut rejected, _) = listener.accept().unwrap();
            let _ = tx.send(reject_upgrade(&mut rejected, rejection));
        }
        let (mut accepted, _) = listener.accept().unwrap();
        let lines = perform_server_upgrade(&mut accepted).unwrap();
        let _ = tx.send(authorization(&lines));
        ack_every_frame(&mut accepted);
    });
    (port, rx, server)
}

/// Collects connection events until a reconnect succeeds, returning the
/// `AuthFailed` events seen before it.
fn auth_failures_until_reconnected(
    events: &mpsc::Receiver<crate::ingress::ConnectionEvent>,
) -> Vec<crate::ingress::ConnectionEvent> {
    let mut auth_failed = Vec::new();
    loop {
        let event = events
            .recv_timeout(Duration::from_secs(10))
            .expect("the sender did not report a reconnect");
        match event.kind {
            crate::ingress::ConnectionEventKind::AuthFailed => auth_failed.push(event),
            crate::ingress::ConnectionEventKind::Reconnected => return auth_failed,
            _ => {}
        }
    }
}

/// C11, D1, C15: once connected, a sender rides out the server rejecting its
/// credential -- 401 or 403, static credentials included -- with capped
/// backoff and one `auth_failed` event per round, then delivers the queued
/// row from memory or disk store-and-forward when the server accepts the
/// credential again.
#[test]
fn an_established_sender_rides_out_upgrade_rejections() {
    for (progress, disk) in [
        (ProgressCase::Background, false),
        (ProgressCase::Manual, false),
        (ProgressCase::Background, true),
    ] {
        let sf_dir = tempfile::TempDir::new().unwrap();
        let sf = if disk {
            format!("sf_dir={};sender_id=d1;", sf_dir.path().display())
        } else {
            String::new()
        };
        let (port, authorizations, server) =
            spawn_reject_after_disconnect_server(vec![PLAIN_401, FORBIDDEN_403, INVALID_TOKEN_401]);
        let (tx, events) = mpsc::channel();
        let builder = SenderBuilder::from_conf(format!(
            "ws::addr=127.0.0.1:{port};token=static-secret;{sf}\
             reconnect_initial_backoff_millis=1;reconnect_max_backoff_millis=5;"
        ))
        .unwrap()
        .connection_listener(
            Arc::new(move |event| {
                let _ = tx.send(event.clone());
            }),
            0,
        )
        .unwrap();
        let mut sender = build_qwp_ws_sender_from_builder(progress, builder);
        let mut buf = one_row_buffer(&sender);
        sender.flush(&mut buf).unwrap();

        sender
            .wait(crate::ingress::AckLevel::Ok, Duration::from_secs(10))
            .unwrap_or_else(|err| {
                panic!(
                    "{}: the row was not delivered after the rejections: {err}",
                    progress.name()
                )
            });
        let auth_failed = auth_failures_until_reconnected(&events);
        assert_eq!(auth_failed.len(), 3, "{}: {auth_failed:?}", progress.name());
        for event in &auth_failed {
            assert_eq!(event.cause_code, Some(ErrorCode::AuthError));
            assert_eq!(event.host.as_deref(), Some("127.0.0.1"));
        }
        let presented: Vec<String> = authorizations.try_iter().collect();
        assert_eq!(
            presented,
            vec!["Bearer static-secret"; 5],
            "{}",
            progress.name()
        );
        drop(sender);
        server.join().unwrap();
    }
}

/// C13: once connected, a sender rides out a token provider that cannot
/// supply a credential -- even one it classifies permanent -- and recovers
/// when the provider does.
#[test]
fn an_established_sender_rides_out_a_token_outage() {
    let (port, authorizations, server) = spawn_reject_after_disconnect_server(Vec::new());
    let calls = Arc::new(AtomicUsize::new(0));
    let (tx, events) = mpsc::channel();
    let builder = SenderBuilder::from_conf(format!(
        "ws::addr=127.0.0.1:{port};\
         reconnect_initial_backoff_millis=1;reconnect_max_backoff_millis=5;"
    ))
    .unwrap()
    .qwp_ws_token_provider({
        let calls = Arc::clone(&calls);
        move || -> crate::Result<String> {
            match calls.fetch_add(1, Ordering::SeqCst) {
                1..=3 => Err(crate::Error::token_unavailable(
                    false,
                    None,
                    "identity not assigned",
                )),
                n => Ok(format!("T{n}")),
            }
        }
    })
    .unwrap()
    .connection_listener(
        Arc::new(move |event| {
            let _ = tx.send(event.clone());
        }),
        0,
    )
    .unwrap();
    let mut sender = builder.build().unwrap();
    let mut buf = one_row_buffer(&sender);
    sender.flush(&mut buf).unwrap();

    sender
        .wait(crate::ingress::AckLevel::Ok, Duration::from_secs(10))
        .expect("the row is delivered once the provider recovers");
    assert_eq!(calls.load(Ordering::SeqCst), 5);
    let mut unavailable = 0;
    loop {
        let event = events.recv_timeout(Duration::from_secs(10)).unwrap();
        match event.kind {
            crate::ingress::ConnectionEventKind::CredentialUnavailable => {
                unavailable += 1;
                assert!(
                    event
                        .cause_msg
                        .as_deref()
                        .is_some_and(|msg| msg.contains("identity not assigned")),
                    "{event:?}"
                );
            }
            crate::ingress::ConnectionEventKind::Reconnected => break,
            _ => {}
        }
    }
    assert_eq!(unavailable, 3);
    let presented: Vec<String> = authorizations.try_iter().collect();
    assert_eq!(presented, vec!["Bearer T0", "Bearer T4"]);
    drop(sender);
    server.join().unwrap();
}

/// A provider with a cache, as a refreshing one has: it rotates the token a
/// server rejected.
struct RotatingOnRejection {
    current: Mutex<usize>,
}

impl BearerTokenProvider for RotatingOnRejection {
    fn token(&self) -> crate::Result<String> {
        Ok(format!("T{}", *self.current.lock().unwrap()))
    }

    fn on_rejected(&self, token: &str, _http_status: u16) {
        let mut current = self.current.lock().unwrap();
        if token == format!("T{}", *current) {
            *current += 1;
        }
    }
}

#[derive(Clone, Copy)]
enum OrphanConnection {
    /// Upgrade, read the dictionary catch-up and the data frame, and drop the
    /// connection without acknowledging them.
    DropUnacked,
    /// Answer the upgrade with this rejection.
    Reject(&'static [u8]),
    /// Upgrade, read both frames and acknowledge the data frame.
    Drain,
}

/// Upgrades the primary sender's own connection, then serves the orphan
/// drainer's connections by `script`. Reports each orphan connection's
/// `Authorization` header, including any that arrive within half a second
/// after the script.
fn spawn_orphan_script_server(
    script: Vec<OrphanConnection>,
) -> (u16, mpsc::Receiver<String>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut foreground, _) = listener.accept().unwrap();
        perform_server_upgrade(&mut foreground).unwrap();
        for step in script {
            let (mut orphan, _) = listener.accept().unwrap();
            orphan
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            match step {
                OrphanConnection::Reject(rejection) => {
                    let _ = tx.send(reject_upgrade(&mut orphan, rejection));
                }
                OrphanConnection::DropUnacked | OrphanConnection::Drain => {
                    let lines = perform_server_upgrade(&mut orphan).unwrap();
                    let _ = tx.send(authorization(&lines));
                    let (_, _, _catch_up) = read_frame(&mut orphan).unwrap();
                    let (_, _, _data) = read_frame(&mut orphan).unwrap();
                    if matches!(step, OrphanConnection::Drain) {
                        write_qwp_ok_response(&mut orphan, FIRST_WIRE_SEQUENCE + 1).unwrap();
                        thread::sleep(Duration::from_millis(50));
                    }
                }
            }
        }
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_millis(500);
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((mut extra, _)) => {
                    extra.set_nonblocking(false).unwrap();
                    let _ = tx.send(reject_upgrade(&mut extra, PLAIN_401));
                }
                Err(_) => thread::sleep(Duration::from_millis(5)),
            }
        }
    });
    (port, rx, server)
}

fn orphan_drain_conf(port: u16, sf_dir: &std::path::Path, auth: &str) -> String {
    format!(
        "ws::addr=127.0.0.1:{port};qwp_ws_progress=manual;{auth}\
         sf_dir={};sender_id=primary;drain_orphans=on;max_background_drainers=1;\
         sf_max_segment_bytes=256;sf_max_total_bytes=1024;\
         reconnect_initial_backoff_millis=1;reconnect_max_backoff_millis=5;\
         reconnect_max_duration_millis=60000;",
        sf_dir.display()
    )
}

/// C16: an orphan drain that loses its connection mid-drain, and is then
/// rejected for a whole round while the server catches up with a rotated
/// token, rides the rejection out and drains the slot with the new token.
#[test]
fn an_orphan_drain_rides_out_a_token_rotation() {
    let sf_dir = tempfile::TempDir::new().unwrap();
    seed_orphan_slot(sf_dir.path());
    let orphan_slot = sf_dir.path().join("orphan");
    let (port, authorizations, server) = spawn_orphan_script_server(vec![
        OrphanConnection::DropUnacked,
        // The drainer reconnects with T0, which the server rejects; told so,
        // the provider rotates to T1 and the drainer retries at once. The
        // server has not caught up yet and rejects T1 too.
        OrphanConnection::Reject(PLAIN_401),
        OrphanConnection::Reject(INVALID_TOKEN_401),
        // A later round presents T1 again, and it is accepted.
        OrphanConnection::Drain,
    ]);
    let mut sender = SenderBuilder::from_conf(orphan_drain_conf(port, sf_dir.path(), ""))
        .unwrap()
        .qwp_ws_token_provider(RotatingOnRejection {
            current: Mutex::new(0),
        })
        .unwrap()
        .build()
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    while slot_has_sfa_file(&orphan_slot) {
        assert!(
            Instant::now() < deadline,
            "the orphan slot was not drained; .last_error: {:?}",
            std::fs::read_to_string(orphan_slot.join(".last_error"))
        );
        if !sender.drive_once().unwrap() {
            thread::sleep(Duration::from_millis(1));
        }
    }
    drop(sender);
    server.join().unwrap();
    let presented: Vec<String> = authorizations.try_iter().collect();
    assert_eq!(
        presented,
        vec!["Bearer T0", "Bearer T0", "Bearer T1", "Bearer T1"]
    );
    assert!(!orphan_slot.join(".failed").exists());
}

/// C11, orphan drain with a static credential: the first rejection
/// mid-drain retires the slot for the session, keeping it on disk.
#[test]
fn an_orphan_drain_gives_up_a_rejected_static_credential_at_once() {
    let sf_dir = tempfile::TempDir::new().unwrap();
    seed_orphan_slot(sf_dir.path());
    let orphan_slot = sf_dir.path().join("orphan");
    let (port, authorizations, server) = spawn_orphan_script_server(vec![
        OrphanConnection::DropUnacked,
        OrphanConnection::Reject(FORBIDDEN_403),
    ]);
    let mut sender = SenderBuilder::from_conf(orphan_drain_conf(
        port,
        sf_dir.path(),
        "token=static-secret;",
    ))
    .unwrap()
    .build()
    .unwrap();

    let last_error = orphan_slot.join(".last_error");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !std::fs::read_to_string(&last_error).is_ok_and(|text| text.contains("static")) {
        assert!(Instant::now() < deadline, "the orphan slot was not retired");
        if !sender.drive_once().unwrap() {
            thread::sleep(Duration::from_millis(1));
        }
    }
    // Keep driving: a retired slot is not dialled again.
    let until = Instant::now() + Duration::from_millis(300);
    while Instant::now() < until {
        let _ = sender.drive_once().unwrap();
        thread::sleep(Duration::from_millis(5));
    }
    drop(sender);
    server.join().unwrap();
    let presented: Vec<String> = authorizations.try_iter().collect();
    assert_eq!(presented, vec!["Bearer static-secret"; 2]);
    let reason = std::fs::read_to_string(&last_error).unwrap();
    assert!(reason.contains("HTTP status 403"), "{reason}");
    assert!(!orphan_slot.join(".failed").exists());
    assert!(slot_has_sfa_file(&orphan_slot), "the slot stays on disk");
}
