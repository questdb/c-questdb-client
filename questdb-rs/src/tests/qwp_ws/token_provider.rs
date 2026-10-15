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
        for schema in ["ws", "wss", "http", "https", "tcp"] {
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
