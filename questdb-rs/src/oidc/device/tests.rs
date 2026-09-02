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

//! Device-flow tests driven by an in-process mock identity provider.
//!
//! A no-op sleep hook is injected so the poll loop (whose interval is floored at
//! 5s in production) runs instantly; the mock scripts the token endpoint's
//! `authorization_pending` / `slow_down` / success sequence.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Barrier, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use tempfile::TempDir;

use super::*;
use crate::oidc::error::OidcErrorKind;
use crate::oidc::token_store::{
    FileTokenStore, PersistedToken, TokenStore, TokenStoreKey, TokenStoreResult,
};

/// A tiny single-request-per-connection HTTP mock. The handler receives
/// `(method, path, body)` and returns `(status, json_body)`.
struct MockServer {
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl MockServer {
    fn start<H>(handler: H) -> Self
    where
        H: Fn(&str, &str, &str) -> (u16, String) + Send + Sync + 'static,
    {
        Self::start_inner(None, None, handler)
    }

    /// Like [`start`], but stamps a `Retry-After: <secs>` header on every response.
    /// The tiny mock can't otherwise set one, and the 429 / `slow_down` backoff
    /// path needs it to exercise a low Retry-After.
    fn start_with_retry_after<H>(secs: u64, handler: H) -> Self
    where
        H: Fn(&str, &str, &str) -> (u16, String) + Send + Sync + 'static,
    {
        Self::start_inner(Some(secs), None, handler)
    }

    /// Like [`start`], but stamps a `Location: <target>` header on every 3xx
    /// response, so the redirect-follow defense (the client must NOT follow a
    /// 30x to another host) can be exercised end-to-end.
    fn start_redirecting<H>(location: impl Into<String>, handler: H) -> Self
    where
        H: Fn(&str, &str, &str) -> (u16, String) + Send + Sync + 'static,
    {
        Self::start_inner(None, Some(location.into()), handler)
    }

    fn start_inner<H>(retry_after: Option<u64>, location: Option<String>, handler: H) -> Self
    where
        H: Fn(&str, &str, &str) -> (u16, String) + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock");
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let handler = Arc::new(handler);
        let handle = {
            let shutdown = Arc::clone(&shutdown);
            std::thread::spawn(move || {
                while !shutdown.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            handle_conn(stream, &*handler, retry_after, location.as_deref())
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        Err(_) => break,
                    }
                }
            })
        };
        MockServer {
            addr,
            shutdown,
            handle: Some(handle),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn handle_conn<H>(
    mut stream: TcpStream,
    handler: &H,
    retry_after: Option<u64>,
    location: Option<&str>,
) where
    H: Fn(&str, &str, &str) -> (u16, String),
{
    stream.set_nonblocking(false).ok();
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let headers_end = loop {
        match stream.read(&mut tmp) {
            Ok(0) => return,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if let Some(pos) = find_subsequence(&buf, b"\r\n\r\n") {
                    break pos + 4;
                }
            }
            Err(_) => return,
        }
    };
    let head = String::from_utf8_lossy(&buf[..headers_end]).to_string();
    let req_line = head.lines().next().unwrap_or("");
    let mut parts = req_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let raw_path = parts.next().unwrap_or("").to_string();
    let path = raw_path.split('?').next().unwrap_or("").to_string();
    let content_length = head
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            if k.trim().eq_ignore_ascii_case("content-length") {
                v.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);
    let mut body = buf[headers_end..].to_vec();
    while body.len() < content_length {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => body.extend_from_slice(&tmp[..n]),
            Err(_) => break,
        }
    }
    let body_str = String::from_utf8_lossy(&body).to_string();
    let (status, json) = handler(&method, &path, &body_str);
    // Sentinel: status 0 means "simulate a transport failure" — drop the
    // connection without any HTTP response, so the client sees no status.
    if status == 0 {
        return;
    }
    let retry_after_header = match retry_after {
        Some(secs) => format!("Retry-After: {secs}\r\n"),
        None => String::new(),
    };
    // Emit a Location only on a 3xx, so a redirect-follow defense test can point
    // the token endpoint's 30x at a sink and prove the client never chases it.
    let location_header = match location {
        Some(loc) if (300..400).contains(&status) => format!("Location: {loc}\r\n"),
        _ => String::new(),
    };
    let response = format!(
        "HTTP/1.1 {status} MOCK\r\nContent-Type: application/json\r\n{retry_after_header}{location_header}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        json.len(),
        json
    );
    stream.write_all(response.as_bytes()).ok();
    stream.flush().ok();
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn no_sleep() -> SleepFn {
    Arc::new(|_| {})
}

/// Build an auth against the mock with explicit endpoints, non-interactive TTY
/// bypassed, no browser, and instant polling.
fn explicit_auth(mock: &MockServer, groups_in_token: bool) -> OidcDeviceAuth {
    OidcDeviceAuth::builder()
        .client_id("questdb")
        .device_authorization_endpoint(mock.url("/device"))
        .token_endpoint(mock.url("/token"))
        .scope("openid")
        .groups_in_token(groups_in_token)
        .interactive(true)
        .open_browser(false)
        .timeout(Duration::from_secs(5))
        .sleep_hook(no_sleep())
        .build()
        .expect("build auth")
}

fn sign_in_and_token(auth: &OidcDeviceAuth) -> Result<String> {
    auth.sign_in()?;
    auth.token()
}

#[test]
fn discard_credentials_drops_the_in_memory_token_without_the_acquire_lock() {
    // Regression: the credential teardown used to live only after
    // `lock_acquire()` inside `close()`. Any close that skipped the drain --
    // notably one issued from inside a renderer callback, which runs within
    // that very critical section -- therefore left the access and refresh
    // tokens resident for the remaining life of the provider, contradicting
    // close's documented "drops the in-memory credential".
    let auth = OidcDeviceAuth::builder()
        .client_id("questdb")
        .device_authorization_endpoint("https://idp.example/device")
        .token_endpoint("https://idp.example/token")
        .scope("openid")
        .interactive(false)
        .open_browser(false)
        .build()
        .expect("build auth");

    let now = now_epoch();
    *auth.lock_tokens() = Some(TokenSet {
        access_token: Some("AT-secret".to_string()),
        id_token: Some("ID-secret".to_string()),
        refresh_token: Some("RT-secret".to_string()),
        expires_at: now + 300.0,
        token_type: "Bearer".to_string(),
        scope: Some("openid".to_string()),
        sub: Some("subject".to_string()),
        issued_at: now,
    });
    assert!(auth.lock_tokens().is_some());

    // Hold the acquisition lock, exactly as a running callback would, and show
    // the teardown still completes rather than deadlocking or being skipped.
    let held = auth.lock_acquire();
    auth.discard_credentials();
    drop(held);

    assert!(
        auth.lock_tokens().is_none(),
        "the in-memory credential must be dropped even when the drain is skipped"
    );
}

#[test]
fn close_cancels_device_polling_and_disables_shared_auth() {
    let (polling_tx, polling_rx) = mpsc::sync_channel(1);
    let mock = MockServer::start(move |method, path, _body| match (method, path) {
        ("POST", "/device") => (200, device_response()),
        ("POST", "/token") => {
            let _ = polling_tx.try_send(());
            (400, r#"{"error":"authorization_pending"}"#.to_string())
        }
        _ => (404, "{}".to_string()),
    });
    // Do not install the test sleep hook: production polling waits on the close
    // condvar, which must wake rather than wait out the five-second interval.
    let auth = Arc::new(
        OidcDeviceAuth::builder()
            .client_id("questdb")
            .device_authorization_endpoint(mock.url("/device"))
            .token_endpoint(mock.url("/token"))
            .scope("openid")
            .interactive(true)
            .open_browser(false)
            .timeout(Duration::from_secs(5))
            .build()
            .expect("build auth"),
    );
    let worker_auth = Arc::clone(&auth);
    let worker = std::thread::spawn(move || worker_auth.sign_in());

    polling_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("sign-in did not reach token polling");
    let started = Instant::now();
    auth.close();
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "close waited out the device poll interval"
    );
    let error = worker.join().expect("sign-in thread panicked").unwrap_err();
    assert_eq!(error.kind(), OidcErrorKind::Cancelled);
    assert!(auth.is_closed());
    assert_eq!(auth.token().unwrap_err().kind(), OidcErrorKind::Cancelled);
    // clear is the exception: it is pure teardown, and close leaves the
    // persisted entry behind, so it has to keep working afterwards.
    auth.try_clear()
        .expect("clear must remain available on a closed provider");
    // Idempotent, including the synchronous drain guarantee.
    auth.close();
}

#[test]
fn close_cancels_file_store_lock_wait() {
    let dir = TempDir::new().unwrap();
    let store = FileTokenStore::at(dir.path());
    let auth = Arc::new(
        OidcDeviceAuth::builder()
            .client_id("questdb")
            .device_authorization_endpoint("https://idp.example/device")
            .token_endpoint("https://idp.example/token")
            .scope("openid")
            .interactive(true)
            .open_browser(false)
            .token_store(store.clone())
            .build()
            .expect("build auth"),
    );
    let key = auth.store_key.as_ref().unwrap().clone();
    let release = Arc::new(Barrier::new(2));
    let (locked_tx, locked_rx) = mpsc::sync_channel(1);
    let holder_release = Arc::clone(&release);
    let holder = std::thread::spawn(move || {
        store
            .in_lock(&key, &mut || {
                locked_tx.send(()).unwrap();
                holder_release.wait();
                Ok(())
            })
            .unwrap();
    });
    locked_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("holder did not acquire token-store lock");

    let clear_auth = Arc::clone(&auth);
    let clear = std::thread::spawn(move || clear_auth.try_clear());
    // Observe clear holding the auth acquisition lock, which means it has
    // reached (or is about to reach) the externally held store lock.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match auth.acquire.try_lock() {
            Err(TryLockError::WouldBlock) => break,
            Err(TryLockError::Poisoned(_)) => panic!("auth lock was poisoned"),
            Ok(guard) => {
                drop(guard);
                assert!(Instant::now() < deadline, "clear did not acquire auth lock");
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

    let close_auth = Arc::clone(&auth);
    let (closed_tx, closed_rx) = mpsc::sync_channel(1);
    let closer = std::thread::spawn(move || {
        close_auth.close();
        closed_tx.send(()).unwrap();
    });
    let closed_promptly = closed_rx.recv_timeout(Duration::from_secs(2)).is_ok();
    // Always unblock the holder so a failed assertion cannot strand the test.
    release.wait();
    holder.join().unwrap();
    closer.join().unwrap();
    assert!(
        closed_promptly,
        "close waited for the held token-store lock"
    );
    assert_eq!(
        clear.join().unwrap().unwrap_err().kind(),
        OidcErrorKind::Cancelled
    );
}

/// Reserve a loopback port with no listener, so connects to it are refused
/// (ECONNREFUSED) — modelling a pre-send transport failure where the request
/// never leaves the client. Loopback `http` is allowed without insecure
/// transport, so this needs no extra opt-in.
fn dead_loopback_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

/// A no-store auth whose token endpoint points at a closed loopback port, so a
/// refresh POST fails pre-send (connection refused): the request never reaches
/// the IdP, proving a refresh token carried in it was not consumed.
fn auth_with_dead_token_endpoint() -> OidcDeviceAuth {
    let addr = dead_loopback_addr();
    OidcDeviceAuth::builder()
        .client_id("questdb")
        .device_authorization_endpoint(format!("http://{addr}/device"))
        .token_endpoint(format!("http://{addr}/token"))
        .scope("openid")
        .interactive(true)
        .open_browser(false)
        .timeout(Duration::from_secs(5))
        .sleep_hook(no_sleep())
        .build()
        .expect("build auth")
}

fn device_response() -> String {
    serde_json::json!({
        "device_code": "DEV-CODE-123",
        "user_code": "WXYZ-1234",
        "verification_uri": "https://idp.example.com/activate",
        "verification_uri_complete": "https://idp.example.com/activate?user_code=WXYZ-1234",
        "expires_in": 600,
        "interval": 5
    })
    .to_string()
}

#[test]
fn token_requires_explicit_sign_in_without_starting_device_flow() {
    let device_calls = Arc::new(AtomicUsize::new(0));
    let mock = {
        let device_calls = Arc::clone(&device_calls);
        MockServer::start(move |method, path, _body| match (method, path) {
            ("POST", "/device") => {
                device_calls.fetch_add(1, Ordering::SeqCst);
                (200, device_response())
            }
            ("POST", "/token") => (
                200,
                r#"{"access_token":"AT-explicit","expires_in":300}"#.to_string(),
            ),
            _ => (404, "{}".to_string()),
        })
    };
    let auth = explicit_auth(&mock, false);

    let err = auth.token().unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::InteractionRequired);
    assert_eq!(
        device_calls.load(Ordering::SeqCst),
        0,
        "token() unexpectedly started the interactive device flow"
    );

    auth.sign_in().unwrap();
    assert_eq!(device_calls.load(Ordering::SeqCst), 1);
    assert_eq!(auth.token().unwrap(), "AT-explicit");
}

#[test]
fn explicit_builder_rejects_endpoints_off_pinned_issuer_origin() {
    let err = OidcDeviceAuth::builder()
        .client_id("questdb")
        .issuer("https://idp.example.com/realms/prod")
        .device_authorization_endpoint("https://tokens.example.com/device")
        .token_endpoint("https://tokens.example.com/token")
        .build()
        .unwrap_err();

    assert_eq!(err.kind(), OidcErrorKind::Config);
    assert!(err.message().contains("pinned issuer origin"));
}

#[test]
fn token_does_not_wait_behind_interactive_sign_in() {
    struct BlockingPrompt {
        entered: Arc<Barrier>,
        release: Arc<Barrier>,
    }

    impl Renderer for BlockingPrompt {
        fn on_prompt(&self, _challenge: &DeviceCodeChallenge) {
            self.entered.wait();
            self.release.wait();
        }
    }

    let mock = MockServer::start(|method, path, _body| match (method, path) {
        ("POST", "/device") => (200, device_response()),
        ("POST", "/token") => (
            200,
            r#"{"access_token":"AT-after-prompt","expires_in":300}"#.to_string(),
        ),
        _ => (404, "{}".to_string()),
    });
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let auth = Arc::new(
        OidcDeviceAuth::builder()
            .client_id("questdb")
            .device_authorization_endpoint(mock.url("/device"))
            .token_endpoint(mock.url("/token"))
            .interactive(true)
            .open_browser(false)
            .sleep_hook(no_sleep())
            .renderer(BlockingPrompt {
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
            })
            .build()
            .unwrap(),
    );

    let signer = {
        let auth = Arc::clone(&auth);
        std::thread::spawn(move || auth.sign_in())
    };
    entered.wait();

    let (result_tx, result_rx) = std::sync::mpsc::channel();
    let token_caller = {
        let auth = Arc::clone(&auth);
        std::thread::spawn(move || {
            let result = auth.token().map_err(|error| error.kind());
            result_tx.send(result).unwrap();
        })
    };
    let token_result = result_rx.recv_timeout(Duration::from_secs(1));

    // Always unblock the signer before asserting, so a regression fails rather
    // than leaving a permanently hung test process.
    release.wait();
    signer.join().unwrap().unwrap();
    token_caller.join().unwrap();

    assert_eq!(
        token_result.expect("token() blocked behind the interactive sign-in"),
        Err(OidcErrorKind::InteractionRequired)
    );
}

#[test]
fn token_waits_behind_concurrent_silent_refresh_and_reuses_result() {
    let token_calls = Arc::new(AtomicUsize::new(0));
    let (refresh_entered_tx, refresh_entered_rx) = std::sync::mpsc::channel();
    let (release_refresh_tx, release_refresh_rx) = std::sync::mpsc::channel();
    let release_refresh_rx = Arc::new(Mutex::new(release_refresh_rx));
    let mock = {
        let token_calls = Arc::clone(&token_calls);
        let release_refresh_rx = Arc::clone(&release_refresh_rx);
        MockServer::start(move |method, path, _body| match (method, path) {
            ("POST", "/token") => {
                let call = token_calls.fetch_add(1, Ordering::SeqCst);
                if call == 0 {
                    refresh_entered_tx.send(()).unwrap();
                    release_refresh_rx.lock().unwrap().recv().unwrap();
                }
                (
                    200,
                    r#"{"access_token":"AT-refreshed","refresh_token":"RT-2","expires_in":300}"#
                        .to_string(),
                )
            }
            _ => (404, "{}".to_string()),
        })
    };
    let auth = Arc::new(explicit_auth(&mock, false));
    *auth.tokens.lock().unwrap() = Some(expired_tokens("RT-1"));

    let first = {
        let auth = Arc::clone(&auth);
        std::thread::spawn(move || auth.token())
    };
    refresh_entered_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("first caller did not enter silent refresh");

    let (second_tx, second_rx) = std::sync::mpsc::channel();
    let second = {
        let auth = Arc::clone(&auth);
        std::thread::spawn(move || second_tx.send(auth.token()).unwrap())
    };
    let before_release = second_rx.recv_timeout(Duration::from_millis(200));
    let waited_for_refresh = matches!(
        &before_release,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout)
    );

    // Always release and join the refresh before asserting, so a regression
    // cannot leave the mock or either caller blocked.
    release_refresh_tx.send(()).unwrap();
    let first_result = first.join().unwrap();
    let second_result = match before_release {
        Ok(result) => result,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => second_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("second caller did not resume after refresh"),
        Err(error) => panic!("second token caller disconnected: {error}"),
    };
    second.join().unwrap();

    assert!(
        waited_for_refresh,
        "token() failed fast instead of waiting behind a silent refresh"
    );
    assert_eq!(first_result.unwrap(), "AT-refreshed");
    assert_eq!(second_result.unwrap(), "AT-refreshed");
    assert_eq!(
        token_calls.load(Ordering::SeqCst),
        1,
        "concurrent callers performed duplicate refreshes"
    );
}

#[test]
fn happy_path_returns_access_token() {
    let poll = Arc::new(AtomicUsize::new(0));
    let mock = {
        let poll = Arc::clone(&poll);
        MockServer::start(move |method, path, _body| match (method, path) {
            ("POST", "/device") => (200, device_response()),
            ("POST", "/token") => {
                // Two pending polls then success, proving the loop keeps polling.
                if poll.fetch_add(1, Ordering::SeqCst) < 2 {
                    (400, r#"{"error":"authorization_pending"}"#.to_string())
                } else {
                    (
                        200,
                        r#"{"access_token":"AT-999","token_type":"Bearer","expires_in":300}"#
                            .to_string(),
                    )
                }
            }
            _ => (404, "{}".to_string()),
        })
    };
    let auth = explicit_auth(&mock, false);
    assert_eq!(sign_in_and_token(&auth).unwrap(), "AT-999");
    assert!(poll.load(Ordering::SeqCst) >= 3);
    // Cached: a second call does not poll again.
    let before = poll.load(Ordering::SeqCst);
    assert_eq!(auth.token().unwrap(), "AT-999");
    assert_eq!(poll.load(Ordering::SeqCst), before);
}

#[test]
fn groups_mode_selects_id_token() {
    let mock = MockServer::start(|method, path, _body| match (method, path) {
        ("POST", "/device") => (200, device_response()),
        ("POST", "/token") => (
            200,
            r#"{"access_token":"AT-1","id_token":"ID-TOKEN-abc","expires_in":300}"#.to_string(),
        ),
        _ => (404, "{}".to_string()),
    });
    let auth = explicit_auth(&mock, true);
    assert_eq!(sign_in_and_token(&auth).unwrap(), "ID-TOKEN-abc");
}

#[test]
fn groups_mode_missing_id_token_errors() {
    let mock = MockServer::start(|method, path, _body| match (method, path) {
        ("POST", "/device") => (200, device_response()),
        // Grant completes but omits the required id_token.
        ("POST", "/token") => (
            200,
            r#"{"access_token":"AT-only","expires_in":300}"#.to_string(),
        ),
        _ => (404, "{}".to_string()),
    });
    let auth = explicit_auth(&mock, true);
    let err = auth.sign_in().unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::DeviceFlow);
}

#[test]
fn slow_down_then_success() {
    let poll = Arc::new(AtomicUsize::new(0));
    let mock = {
        let poll = Arc::clone(&poll);
        MockServer::start(move |method, path, _body| match (method, path) {
            ("POST", "/device") => (200, device_response()),
            ("POST", "/token") => {
                if poll.fetch_add(1, Ordering::SeqCst) == 0 {
                    (400, r#"{"error":"slow_down"}"#.to_string())
                } else {
                    (
                        200,
                        r#"{"access_token":"AT-slow","expires_in":300}"#.to_string(),
                    )
                }
            }
            _ => (404, "{}".to_string()),
        })
    };
    let auth = explicit_auth(&mock, false);
    assert_eq!(sign_in_and_token(&auth).unwrap(), "AT-slow");
}

#[test]
fn slow_down_via_429_still_increases_interval() {
    // RFC 8628: `slow_down` MUST increase the poll interval — even when the IdP
    // bundles it into an HTTP 429 with a low Retry-After (1s here), which would
    // otherwise let the generic 429 backoff undercut the +5s step.
    let slept: Arc<std::sync::Mutex<Vec<Duration>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let poll = Arc::new(AtomicUsize::new(0));
    let mock = {
        let poll = Arc::clone(&poll);
        MockServer::start_with_retry_after(1, move |method, path, _body| match (method, path) {
            ("POST", "/device") => (200, device_response()),
            ("POST", "/token") => {
                if poll.fetch_add(1, Ordering::SeqCst) == 0 {
                    (429, r#"{"error":"slow_down"}"#.to_string())
                } else {
                    (
                        200,
                        r#"{"access_token":"AT-sd","expires_in":300}"#.to_string(),
                    )
                }
            }
            _ => (404, "{}".to_string()),
        })
    };
    let recorder = Arc::clone(&slept);
    let auth = OidcDeviceAuth::builder()
        .client_id("questdb")
        .device_authorization_endpoint(mock.url("/device"))
        .token_endpoint(mock.url("/token"))
        .interactive(true)
        .open_browser(false)
        .sleep_hook(Arc::new(move |d: Duration| {
            recorder.lock().unwrap().push(d)
        }))
        .build()
        .expect("build");
    assert_eq!(sign_in_and_token(&auth).unwrap(), "AT-sd");
    let durations = slept.lock().unwrap();
    // The first poll is immediate. The only sleep is before the retry and must
    // use the original 5s interval plus slow_down's mandatory 5s increase,
    // rather than shrinking toward the 1s Retry-After.
    assert_eq!(poll.load(Ordering::SeqCst), 2);
    assert_eq!(durations.as_slice(), &[Duration::from_secs(10)]);
}

#[test]
fn poll_retries_json_and_non_json_http_408() {
    for transient_body in [
        r#"{"error":"request_timeout"}"#,
        "<html>upstream timed out</html>",
    ] {
        let polls = Arc::new(AtomicUsize::new(0));
        let mock = {
            let polls = Arc::clone(&polls);
            let transient_body = transient_body.to_string();
            MockServer::start_with_retry_after(7, move |method, path, _body| match (method, path) {
                ("POST", "/device") => (200, device_response()),
                ("POST", "/token") => {
                    if polls.fetch_add(1, Ordering::SeqCst) == 0 {
                        (408, transient_body.clone())
                    } else {
                        (
                            200,
                            r#"{"access_token":"AT-after-408","expires_in":300}"#.to_string(),
                        )
                    }
                }
                _ => (404, "{}".to_string()),
            })
        };
        let sleeps = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sleep_log = Arc::clone(&sleeps);
        let auth = OidcDeviceAuth::builder()
            .client_id("questdb")
            .device_authorization_endpoint(mock.url("/device"))
            .token_endpoint(mock.url("/token"))
            .interactive(true)
            .open_browser(false)
            .sleep_hook(Arc::new(move |duration| {
                sleep_log.lock().unwrap().push(duration)
            }))
            .build()
            .expect("build");

        assert_eq!(sign_in_and_token(&auth).unwrap(), "AT-after-408");
        assert_eq!(polls.load(Ordering::SeqCst), 2);
        assert_eq!(
            sleeps.lock().unwrap().as_slice(),
            &[Duration::from_secs(7)],
            "HTTP 408 did not honor Retry-After before polling again"
        );
    }
}

#[test]
fn device_code_lifetime_is_floored() {
    // A hostile/buggy tiny expires_in is raised to the minimum so the flow isn't
    // aborted after a single poll; a huge one is capped; a sane one is unchanged.
    assert_eq!(clamp_lifetime(Some(1)), MIN_DEVICE_CODE_LIFETIME);
    assert_eq!(clamp_lifetime(Some(0)), DEFAULT_DEVICE_CODE_LIFETIME);
    assert_eq!(clamp_lifetime(None), DEFAULT_DEVICE_CODE_LIFETIME);
    assert_eq!(clamp_lifetime(Some(600)), 600);
    assert_eq!(clamp_lifetime(Some(100_000)), MAX_DEVICE_CODE_LIFETIME);
}

#[test]
fn poll_interval_is_floored_and_capped() {
    // A hostile/buggy interval is floored to MIN_POLL_INTERVAL so a 0 or negative
    // value can't drive a tight poll-flood against the IdP, and capped at
    // MAX_POLL_INTERVAL; a sane value is unchanged.
    assert_eq!(clamp_interval(-5), MIN_POLL_INTERVAL);
    assert_eq!(clamp_interval(0), MIN_POLL_INTERVAL);
    assert_eq!(clamp_interval(1), MIN_POLL_INTERVAL);
    assert_eq!(clamp_interval(MIN_POLL_INTERVAL as i64), MIN_POLL_INTERVAL);
    assert_eq!(clamp_interval(30), 30);
    assert_eq!(clamp_interval(100_000), MAX_POLL_INTERVAL);
}

#[test]
fn access_denied_is_device_flow_error() {
    let mock = MockServer::start(|method, path, _body| match (method, path) {
        ("POST", "/device") => (200, device_response()),
        ("POST", "/token") => (
            400,
            r#"{"error":"access_denied","error_description":"user declined"}"#.to_string(),
        ),
        _ => (404, "{}".to_string()),
    });
    let auth = explicit_auth(&mock, false);
    let err = auth.sign_in().unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::DeviceFlow);
    assert_eq!(err.idp_error(), Some("access_denied"));
    assert_eq!(err.idp_error_description(), Some("user declined"));
}

#[test]
fn empty_error_description_keeps_error_code() {
    // An empty error_description must not erase the error code from the message or
    // the structured fields (it previously shadowed both, yielding "failed: ").
    let mock = MockServer::start(|method, path, _body| match (method, path) {
        ("POST", "/device") => (200, device_response()),
        ("POST", "/token") => (
            400,
            r#"{"error":"access_denied","error_description":""}"#.to_string(),
        ),
        _ => (404, "{}".to_string()),
    });
    let auth = explicit_auth(&mock, false);
    let err = auth.sign_in().unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::DeviceFlow);
    assert_eq!(err.idp_error(), Some("access_denied"));
    // The empty description is normalized to absent, not surfaced as Some("").
    assert_eq!(err.idp_error_description(), None);
    // The code survives in both the message and the Display output.
    assert!(
        err.message().contains("access_denied"),
        "message: {}",
        err.message()
    );
    assert!(format!("{err}").contains("access_denied"), "display: {err}");
}

#[test]
fn control_chars_in_token_are_rejected() {
    let mock = MockServer::start(|method, path, _body| match (method, path) {
        ("POST", "/device") => (200, device_response()),
        // A token carrying a control byte (header-injection vector) is dropped,
        // so the grant is treated as missing the required token.
        ("POST", "/token") => (
            200,
            r#"{"access_token":"bad\ntoken","expires_in":300}"#.to_string(),
        ),
        _ => (404, "{}".to_string()),
    });
    let auth = explicit_auth(&mock, false);
    let err = auth.sign_in().unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::DeviceFlow);
}

#[test]
fn silent_refresh_without_reprompt() {
    let device_calls = Arc::new(AtomicUsize::new(0));
    let mock = {
        let device_calls = Arc::clone(&device_calls);
        MockServer::start(move |method, path, body| match (method, path) {
            ("POST", "/device") => {
                device_calls.fetch_add(1, Ordering::SeqCst);
                (200, device_response())
            }
            ("POST", "/token") => {
                if body.contains("grant_type=refresh_token") {
                    (
                        200,
                        r#"{"access_token":"AT-refreshed","expires_in":300}"#.to_string(),
                    )
                } else {
                    // Initial sign-in yields a refresh token.
                    (
                        200,
                        r#"{"access_token":"AT-initial","refresh_token":"RT-1","expires_in":300}"#
                            .to_string(),
                    )
                }
            }
            _ => (404, "{}".to_string()),
        })
    };
    let auth = explicit_auth(&mock, false);
    assert_eq!(sign_in_and_token(&auth).unwrap(), "AT-initial");
    assert_eq!(device_calls.load(Ordering::SeqCst), 1);

    // Force the cached token to look expired, so the next call must refresh.
    auth.tokens.lock().unwrap().as_mut().unwrap().expires_at = 1.0;
    assert_eq!(auth.token().unwrap(), "AT-refreshed");
    // No second device-authorization request: the refresh was silent.
    assert_eq!(device_calls.load(Ordering::SeqCst), 1);
    // The refresh response omitted a refresh_token, so the original RT-1 must be
    // carried forward (not dropped) — otherwise the next refresh couldn't run.
    assert_eq!(
        auth.tokens
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .refresh_token
            .as_deref(),
        Some("RT-1")
    );
}

#[test]
fn refresh_request_sends_complete_configured_scope_like_java() {
    let refresh_body = Arc::new(Mutex::new(None));
    let mock = {
        let refresh_body = Arc::clone(&refresh_body);
        MockServer::start(move |method, path, body| {
            match (method, path) {
            ("POST", "/device") => (200, device_response()),
            ("POST", "/token") if body.contains("grant_type=refresh_token") => {
                *refresh_body.lock().unwrap() = Some(body.to_string());
                (
                    200,
                    r#"{"access_token":"AT-refreshed","expires_in":300}"#.to_string(),
                )
            }
            ("POST", "/token") => (
                200,
                r#"{"access_token":"AT-initial","refresh_token":"RT-1","expires_in":300,"scope":"openid offline_access"}"#
                    .to_string(),
            ),
            _ => (404, "{}".to_string()),
        }
        })
    };
    let auth = OidcDeviceAuth::builder()
        .client_id("questdb")
        .device_authorization_endpoint(mock.url("/device"))
        .token_endpoint(mock.url("/token"))
        .scope("openid profile offline_access")
        .interactive(true)
        .open_browser(false)
        .timeout(Duration::from_secs(5))
        .sleep_hook(no_sleep())
        .build()
        .expect("build auth");

    assert_eq!(sign_in_and_token(&auth).unwrap(), "AT-initial");
    assert_eq!(
        auth.tokens
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .scope
            .as_deref(),
        Some("openid offline_access"),
        "the IdP's narrower granted scope must be recorded"
    );
    auth.tokens.lock().unwrap().as_mut().unwrap().expires_at = 1.0;
    assert_eq!(auth.token().unwrap(), "AT-refreshed");

    let body = refresh_body
        .lock()
        .unwrap()
        .clone()
        .expect("refresh request was captured");
    let fields: Vec<&str> = body.split('&').collect();
    assert!(fields.contains(&"grant_type=refresh_token"));
    assert!(fields.contains(&"refresh_token=RT-1"));
    assert!(fields.contains(&"client_id=questdb"));
    assert!(
        fields.contains(&"scope=openid+profile+offline_access"),
        "refresh request must preserve the complete configured scope; body={body}"
    );
}

#[test]
fn groups_mode_refresh_preserves_configured_openid_scope() {
    // The configured scope is exactly `openid`, so Java-compatible refresh
    // behavior sends exactly `scope=openid` without groups mode synthesizing or
    // otherwise changing the request.
    let refresh_body = Arc::new(Mutex::new(None));
    let mock = {
        let refresh_body = Arc::clone(&refresh_body);
        MockServer::start(move |method, path, body| {
            match (method, path) {
            ("POST", "/device") => (200, device_response()),
            ("POST", "/token") if body.contains("grant_type=refresh_token") => {
                *refresh_body.lock().unwrap() = Some(body.to_string());
                (
                    200,
                    r#"{"access_token":"AT-refreshed","id_token":"ID-refreshed","expires_in":300}"#
                        .to_string(),
                )
            }
            ("POST", "/token") => (
                200,
                r#"{"access_token":"AT-1","id_token":"ID-1","refresh_token":"RT-1","expires_in":300}"#
                    .to_string(),
            ),
            _ => (404, "{}".to_string()),
        }
        })
    };
    let auth = explicit_auth(&mock, true);
    assert_eq!(sign_in_and_token(&auth).unwrap(), "ID-1");

    // Force a refresh; because the request carries `openid`, the IdP re-issues an
    // id_token and the silent refresh succeeds without an interactive re-prompt.
    auth.tokens.lock().unwrap().as_mut().unwrap().expires_at = 1.0;
    assert_eq!(auth.token().unwrap(), "ID-refreshed");

    let body = refresh_body
        .lock()
        .unwrap()
        .clone()
        .expect("refresh request was captured");
    let fields: Vec<&str> = body.split('&').collect();
    assert!(fields.contains(&"grant_type=refresh_token"));
    assert!(
        fields.contains(&"scope=openid"),
        "groups-mode refresh must request the openid scope so the IdP re-issues \
         an id_token; body={body}"
    );
}

#[test]
fn groups_mode_preserves_scope_and_loads_java_store_entry() {
    let mock = MockServer::start(|_, _, _| (404, "{}".to_string()));
    let dir = TempDir::new().unwrap();
    let configured_scope = "profile offline_access";
    let java_key = TokenStoreKey::from_config(
        "questdb",
        &mock.url("/token"),
        &mock.url("/device"),
        configured_scope,
        None,
        true,
        None,
    );
    FileTokenStore::at(dir.path())
        .save(
            &java_key,
            &PersistedToken::new(
                None,
                Some("ID-from-Java".to_string()),
                Some("RT-from-Java".to_string()),
                now_epoch() + 300.0,
                300.0,
            ),
        )
        .unwrap();

    let auth = OidcDeviceAuth::builder()
        .client_id("questdb")
        .device_authorization_endpoint(mock.url("/device"))
        .token_endpoint(mock.url("/token"))
        .scope(configured_scope)
        .groups_in_token(true)
        .interactive(true)
        .open_browser(false)
        .token_store(FileTokenStore::at(dir.path()))
        .build()
        .unwrap();

    assert_eq!(auth.config().scope, configured_scope);
    assert_eq!(
        auth.store_key.as_ref().unwrap().hash(),
        java_key.hash(),
        "groups mode changed the Java-compatible persisted identity"
    );
    assert_eq!(auth.token().unwrap(), "ID-from-Java");
}

#[test]
fn empty_scope_falls_back_to_openid() {
    // An explicit empty scope is filtered (like audience), not sent verbatim.
    let auth = OidcDeviceAuth::builder()
        .client_id("questdb")
        .device_authorization_endpoint("https://idp.example.com/device")
        .token_endpoint("https://idp.example.com/token")
        .scope("")
        .interactive(false)
        .build()
        .expect("build");
    assert_eq!(auth.config().scope, "openid");
}

#[test]
fn non_interactive_context_refuses() {
    let mock = MockServer::start(|_m, _p, _b| (404, "{}".to_string()));
    let auth = OidcDeviceAuth::builder()
        .client_id("questdb")
        .device_authorization_endpoint(mock.url("/device"))
        .token_endpoint(mock.url("/token"))
        .interactive(false)
        .open_browser(false)
        .sleep_hook(no_sleep())
        .build()
        .unwrap();
    let err = auth.sign_in().unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::InteractionRequired);
}

#[test]
fn explicit_empty_client_id_is_rejected_during_build() {
    let err = OidcDeviceAuth::builder()
        .client_id("")
        .device_authorization_endpoint("https://idp.example.com/device")
        .token_endpoint("https://idp.example.com/token")
        .build()
        .unwrap_err();

    assert_eq!(err.kind(), OidcErrorKind::Config);
    assert!(err.message().contains("client_id must not be empty"));
}

#[test]
fn discovery_from_questdb_settings() {
    // One mock plays both QuestDB (/settings) and the IdP (/device, /token).
    let mock = MockServer::start(|method, path, _body| match (method, path) {
        ("GET", "/settings") => (
            200,
            serde_json::json!({
                "config": {
                    "acl.oidc.enabled": true,
                    "acl.oidc.client.id": "discovered-client",
                    "acl.oidc.scope": "openid",
                    "acl.oidc.groups.encoded.in.token": false
                }
            })
            .to_string(),
        ),
        ("POST", "/device") => (200, device_response()),
        ("POST", "/token") => (
            200,
            r#"{"access_token":"AT-discovered","expires_in":300}"#.to_string(),
        ),
        _ => (404, "{}".to_string()),
    });
    // client id comes from /settings; endpoints passed explicitly (the server
    // does not advertise absolute IdP URLs in this unit test).
    let auth = OidcDeviceAuth::from_questdb(mock.url(""))
        .device_authorization_endpoint(mock.url("/device"))
        .token_endpoint(mock.url("/token"))
        .interactive(true)
        .open_browser(false)
        .allow_insecure_transport(true)
        .sleep_hook(no_sleep())
        .build()
        .expect("discovery build");
    assert_eq!(auth.config().client_id, "discovered-client");
    assert_eq!(sign_in_and_token(&auth).unwrap(), "AT-discovered");
}

#[test]
fn oidc_disabled_on_server_errors() {
    let mock = MockServer::start(|method, path, _body| match (method, path) {
        ("GET", "/settings") => (
            200,
            serde_json::json!({"config": {"acl.oidc.enabled": false}}).to_string(),
        ),
        _ => (404, "{}".to_string()),
    });
    let err = OidcDeviceAuth::from_questdb(mock.url(""))
        .device_authorization_endpoint(mock.url("/device"))
        .token_endpoint(mock.url("/token"))
        .allow_insecure_transport(true)
        .build()
        .unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::Config);
}

// -- endpoint-pinning rejection paths (settings-supplied endpoints) ----------

/// A `/settings` response advertising the given credential endpoints.
fn settings_advertising(token_ep: &str, device_ep: &str) -> String {
    serde_json::json!({
        "config": {
            "acl.oidc.enabled": true,
            "acl.oidc.client.id": "questdb",
            "acl.oidc.scope": "openid",
            "acl.oidc.token.endpoint": token_ep,
            "acl.oidc.device.authorization.endpoint": device_ep,
        }
    })
    .to_string()
}

#[test]
fn settings_endpoint_off_issuer_origin_rejected() {
    // A tampered / misconfigured /settings advertises credential endpoints on an
    // origin other than the pinned issuer — must be refused before any POST.
    let mock = MockServer::start(|method, path, _body| match (method, path) {
        ("GET", "/settings") => (
            200,
            settings_advertising(
                "https://evil.example.com/token",
                "https://evil.example.com/device",
            ),
        ),
        _ => (404, "{}".to_string()),
    });
    let err = OidcDeviceAuth::from_questdb(mock.url(""))
        .issuer("https://idp.example.com")
        .allow_insecure_transport(true)
        .build()
        .unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::Config);
    // Pin the cause to the origin check, not some earlier Config error.
    assert!(
        err.message().contains("pinned issuer origin"),
        "expected origin-pin rejection, got: {}",
        err.message()
    );
}

#[test]
fn settings_endpoint_sibling_tenant_path_rejected() {
    // Same origin as the issuer, but a sibling tenant path (/realms/production
    // vs the pinned /realms/prod) — the path pin must reject it.
    let mock = MockServer::start(|method, path, _body| match (method, path) {
        ("GET", "/settings") => (
            200,
            settings_advertising(
                "https://idp.example.com/realms/production/token",
                "https://idp.example.com/realms/production/device",
            ),
        ),
        _ => (404, "{}".to_string()),
    });
    let err = OidcDeviceAuth::from_questdb(mock.url(""))
        .issuer("https://idp.example.com/realms/prod")
        .allow_insecure_transport(true)
        .build()
        .unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::Config);
    // Origin matches, so the rejection must come from the path pin specifically.
    assert!(
        err.message().contains("different tenant"),
        "expected path-pin rejection, got: {}",
        err.message()
    );
}

#[test]
fn settings_endpoint_semicolon_tenant_path_rejected() {
    for suffix in [";tenant=evil", "%3Btenant=evil"] {
        let settings = settings_advertising(
            &format!("https://idp.example.com/realms/prod{suffix}/token"),
            &format!("https://idp.example.com/realms/prod{suffix}/device"),
        );
        let mock = MockServer::start(move |method, path, _body| match (method, path) {
            ("GET", "/settings") => (200, settings.clone()),
            _ => (404, "{}".to_string()),
        });
        let err = OidcDeviceAuth::from_questdb(mock.url(""))
            .issuer("https://idp.example.com/realms/prod")
            .allow_insecure_transport(true)
            .build()
            .unwrap_err();
        assert_eq!(err.kind(), OidcErrorKind::Config);
        assert!(
            err.message().contains("different tenant"),
            "expected {suffix:?} path-pin rejection, got: {}",
            err.message()
        );
    }
}

// -- IdP .well-known discovery + plaintext-channel guard ---------------------

/// A `/settings` response advertising only the client id (no endpoints), so the
/// credential endpoints must come from IdP discovery.
fn settings_client_only() -> String {
    serde_json::json!({
        "config": {"acl.oidc.enabled": true, "acl.oidc.client.id": "questdb"}
    })
    .to_string()
}

#[test]
fn idp_discovery_supplies_endpoints() {
    // /settings advertises no endpoints, so they are discovered from the IdP's
    // .well-known document (fetched from the pinned issuer). The doc's declared
    // issuer matches the pin, so its endpoints are trusted and used.
    let base: Arc<std::sync::OnceLock<String>> = Arc::new(std::sync::OnceLock::new());
    let mock = {
        let base = Arc::clone(&base);
        MockServer::start(move |method, path, _body| match (method, path) {
            ("GET", "/settings") => (200, settings_client_only()),
            ("GET", "/.well-known/openid-configuration") => {
                let b = base.get().cloned().unwrap_or_default();
                (
                    200,
                    serde_json::json!({
                        "issuer": b,
                        "token_endpoint": format!("{b}/token"),
                        "device_authorization_endpoint": format!("{b}/device"),
                    })
                    .to_string(),
                )
            }
            _ => (404, "{}".to_string()),
        })
    };
    base.set(mock.url("")).unwrap();
    let auth = OidcDeviceAuth::from_questdb(mock.url(""))
        .issuer(mock.url(""))
        .allow_insecure_transport(true)
        .interactive(false)
        .open_browser(false)
        .sleep_hook(no_sleep())
        .build()
        .expect("IdP discovery should supply the endpoints");
    assert_eq!(auth.config().token_endpoint, mock.url("/token"));
    assert_eq!(
        auth.config().device_authorization_endpoint,
        mock.url("/device")
    );
}

#[test]
fn idp_discovery_issuer_mismatch_rejected() {
    // The .well-known doc declares an issuer other than the pinned one (RFC 8414
    // violation / wrong tenant); its endpoints must be refused, not trusted.
    let mock = MockServer::start(|method, path, _body| match (method, path) {
        ("GET", "/settings") => (200, settings_client_only()),
        ("GET", "/.well-known/openid-configuration") => (
            200,
            serde_json::json!({
                "issuer": "https://wrong.example.com",
                "token_endpoint": "https://wrong.example.com/token",
                "device_authorization_endpoint": "https://wrong.example.com/device",
            })
            .to_string(),
        ),
        _ => (404, "{}".to_string()),
    });
    let err = OidcDeviceAuth::from_questdb(mock.url(""))
        .issuer(mock.url(""))
        .allow_insecure_transport(true)
        .build()
        .unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::Config);
    assert!(
        err.message().contains("does not match the pinned issuer"),
        "expected issuer-mismatch rejection, got: {}",
        err.message()
    );
}

#[test]
fn idp_discovery_missing_device_endpoint_rejected() {
    // The discovery doc declares a matching issuer + token endpoint but omits
    // device_authorization_endpoint (the IdP does not support the device grant) —
    // resolution must fail with a clear error, not return a half-built config.
    let base: Arc<std::sync::OnceLock<String>> = Arc::new(std::sync::OnceLock::new());
    let mock = {
        let base = Arc::clone(&base);
        MockServer::start(move |method, path, _body| match (method, path) {
            ("GET", "/settings") => (200, settings_client_only()),
            ("GET", "/.well-known/openid-configuration") => {
                let b = base.get().cloned().unwrap_or_default();
                (
                    200,
                    serde_json::json!({
                        "issuer": b,
                        "token_endpoint": format!("{b}/token"),
                    })
                    .to_string(),
                )
            }
            _ => (404, "{}".to_string()),
        })
    };
    base.set(mock.url("")).unwrap();
    let err = OidcDeviceAuth::from_questdb(mock.url(""))
        .issuer(mock.url(""))
        .allow_insecure_transport(true)
        .build()
        .unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::Config);
    assert!(
        err.message().contains("device_authorization_endpoint"),
        "expected missing-device-endpoint rejection, got: {}",
        err.message()
    );
}

#[test]
fn idp_discovery_without_doc_issuer_rejected() {
    // A .well-known doc that declares no issuer (RFC 8414 requires one) must fail
    // closed, not have its endpoints trusted just because the fetch was over TLS.
    let mock = MockServer::start(|method, path, _body| match (method, path) {
        ("GET", "/settings") => (200, settings_client_only()),
        ("GET", "/.well-known/openid-configuration") => (
            200,
            serde_json::json!({
                "token_endpoint": "https://idp.example.com/token",
                "device_authorization_endpoint": "https://idp.example.com/device",
            })
            .to_string(),
        ),
        _ => (404, "{}".to_string()),
    });
    let err = OidcDeviceAuth::from_questdb(mock.url(""))
        .issuer(mock.url(""))
        .allow_insecure_transport(true)
        .build()
        .unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::Config);
    assert!(
        err.message().contains("declares no"),
        "expected no-issuer rejection, got: {}",
        err.message()
    );
}

#[test]
fn discovery_without_issuer_pin_rejected() {
    // /settings advertises no endpoints and no issuer is pinned, so discovery
    // can't proceed safely — a tampered /settings could otherwise name any IdP.
    // Must refuse up front, pointing the user at issuer(...).
    let mock = MockServer::start(|method, path, _body| match (method, path) {
        ("GET", "/settings") => (200, settings_client_only()),
        _ => (404, "{}".to_string()),
    });
    let err = OidcDeviceAuth::from_questdb(mock.url(""))
        .allow_insecure_transport(true)
        .build()
        .unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::Config);
    assert!(
        err.message().contains("not pinned"),
        "expected 'issuer not pinned' rejection, got: {}",
        err.message()
    );
}

#[test]
fn loopback_plaintext_settings_endpoints_allowed() {
    // The plaintext-/settings guard (which demands an issuer pin when a tampered
    // channel could redirect credentials) is waived over a LOOPBACK http channel:
    // there is no in-transit MITM to worry about locally. So settings-advertised
    // endpoints with no issuer pin are accepted here — exercising the guard's
    // reachable (loopback) branch end-to-end.
    //
    // The non-loopback *trigger* of that guard is covered by
    // `plaintext_non_loopback_settings_channel_flagged` in discovery.rs: the guard
    // sits after a successful /settings fetch, so an in-process test can't have a
    // host that is both plaintext-rejected there and reachable — the mock is
    // always loopback.
    let mock = MockServer::start(|method, path, _body| match (method, path) {
        ("GET", "/settings") => (
            200,
            settings_advertising(
                "https://idp.example.com/token",
                "https://idp.example.com/device",
            ),
        ),
        _ => (404, "{}".to_string()),
    });
    let auth = OidcDeviceAuth::from_questdb(mock.url(""))
        .allow_insecure_transport(true)
        .interactive(false)
        .open_browser(false)
        .sleep_hook(no_sleep())
        .build()
        .expect("loopback plaintext settings endpoints should be allowed");
    assert_eq!(
        auth.config().token_endpoint,
        "https://idp.example.com/token"
    );
}

#[test]
fn allow_insecure_does_not_relax_idp_endpoints() {
    // allow_insecure_transport relaxes only the QuestDB /settings channel; a
    // plaintext non-loopback IdP endpoint is still refused when the flow POSTs to
    // it. build() succeeds (co-located, well-formed); the scheme is enforced at
    // flow time by require_secure, before any network I/O.
    let auth = OidcDeviceAuth::builder()
        .client_id("questdb")
        .device_authorization_endpoint("http://idp.example.com/device")
        .token_endpoint("http://idp.example.com/token")
        .scope("openid")
        .interactive(true)
        .open_browser(false)
        .allow_insecure_transport(true)
        .sleep_hook(no_sleep())
        .build()
        .expect("build succeeds; scheme is enforced at flow time");
    let err = auth.sign_in().unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::Config);
    // Pin the cause to the transport-security check on the IdP endpoint.
    assert!(
        err.message().contains("insecure URL"),
        "expected require_secure rejection, got: {}",
        err.message()
    );
}

// -- refresh branches --------------------------------------------------------

#[test]
fn refresh_transient_error_preserves_token_no_reprompt() {
    // A 5xx during refresh keeps the refresh token usable: surface a Network
    // error and do NOT re-prompt (the refresh token is still valid). Repeated
    // transport token lookups must then back off instead of POSTing once per
    // flush while the provider is unavailable.
    let device_calls = Arc::new(AtomicUsize::new(0));
    let refresh_calls = Arc::new(AtomicUsize::new(0));
    let mock = {
        let device_calls = Arc::clone(&device_calls);
        let refresh_calls = Arc::clone(&refresh_calls);
        MockServer::start(move |method, path, body| match (method, path) {
            ("POST", "/device") => {
                device_calls.fetch_add(1, Ordering::SeqCst);
                (200, device_response())
            }
            ("POST", "/token") => {
                if body.contains("grant_type=refresh_token") {
                    refresh_calls.fetch_add(1, Ordering::SeqCst);
                    (503, r#"{"error":"temporarily_unavailable"}"#.to_string())
                } else {
                    (
                        200,
                        r#"{"access_token":"AT-initial","refresh_token":"RT-1","expires_in":300}"#
                            .to_string(),
                    )
                }
            }
            _ => (404, "{}".to_string()),
        })
    };
    let auth = explicit_auth(&mock, false);
    assert_eq!(sign_in_and_token(&auth).unwrap(), "AT-initial");
    // Force the cached token to look expired so the next call must refresh.
    auth.tokens.lock().unwrap().as_mut().unwrap().expires_at = 1.0;
    let err = auth.token().unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::Network);
    assert_eq!(err.status(), Some(503));
    let backed_off = auth.token().unwrap_err();
    assert_eq!(backed_off.kind(), OidcErrorKind::Network);
    assert!(backed_off.message().contains("temporarily backed off"));
    assert_eq!(refresh_calls.load(Ordering::SeqCst), 1);
    assert_eq!(device_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn refresh_transient_responses_preserve_structured_metadata() {
    let cases = [
        (
            408,
            r#"{"error":"temporarily_unavailable","error_description":"request timed out"}"#,
            Some("temporarily_unavailable"),
            Some("request timed out"),
        ),
        (408, "<html>request timed out</html>", None, None),
        (
            503,
            r#"{"error":"temporarily_unavailable","error_description":"service overloaded"}"#,
            Some("temporarily_unavailable"),
            Some("service overloaded"),
        ),
        (503, "<html>service unavailable</html>", None, None),
    ];

    for (status, response_body, expected_error, expected_description) in cases {
        let device_calls = Arc::new(AtomicUsize::new(0));
        let refresh_calls = Arc::new(AtomicUsize::new(0));
        let mock = {
            let device_calls = Arc::clone(&device_calls);
            let refresh_calls = Arc::clone(&refresh_calls);
            let response_body = response_body.to_string();
            MockServer::start_with_retry_after(11, move |method, path, body| match (method, path) {
                ("POST", "/device") => {
                    device_calls.fetch_add(1, Ordering::SeqCst);
                    (200, device_response())
                }
                ("POST", "/token") if body.contains("grant_type=refresh_token") => {
                    refresh_calls.fetch_add(1, Ordering::SeqCst);
                    (status, response_body.clone())
                }
                ("POST", "/token") => (
                    200,
                    r#"{"access_token":"AT-initial","refresh_token":"RT-1","expires_in":300}"#
                        .to_string(),
                ),
                _ => (404, "{}".to_string()),
            })
        };
        let auth = explicit_auth(&mock, false);
        assert_eq!(sign_in_and_token(&auth).unwrap(), "AT-initial");
        auth.tokens.lock().unwrap().as_mut().unwrap().expires_at = 1.0;

        let err = auth.token().unwrap_err();
        assert_eq!(err.kind(), OidcErrorKind::Network);
        assert_eq!(err.status(), Some(status));
        assert_eq!(err.retry_after_secs(), Some(11));
        assert_eq!(err.idp_error(), expected_error);
        assert_eq!(err.idp_error_description(), expected_description);
        assert_eq!(refresh_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            device_calls.load(Ordering::SeqCst),
            1,
            "a transient refresh response started another device flow"
        );

        // The crate-wide error retained by Rust transports and exposed through
        // the C error view must carry the same OIDC details.
        let public_error: crate::Error = err.into();
        let preserved = public_error.oidc_error().unwrap();
        assert_eq!(preserved.status(), Some(status));
        assert_eq!(preserved.retry_after_secs(), Some(11));
        assert_eq!(preserved.idp_error(), expected_error);
        assert_eq!(preserved.idp_error_description(), expected_description);
    }
}

#[test]
fn refresh_rejected_requires_explicit_device_flow() {
    // A 4xx (revoked / expired refresh token) is terminal. A token-provider call
    // must report that interaction is required without starting a device flow;
    // only the subsequent explicit sign_in() may prompt.
    let device_calls = Arc::new(AtomicUsize::new(0));
    let mock = {
        let device_calls = Arc::clone(&device_calls);
        MockServer::start(move |method, path, body| match (method, path) {
            ("POST", "/device") => {
                device_calls.fetch_add(1, Ordering::SeqCst);
                (200, device_response())
            }
            ("POST", "/token") => {
                if body.contains("grant_type=refresh_token") {
                    (400, r#"{"error":"invalid_grant"}"#.to_string())
                } else {
                    // Tag each fresh sign-in by the device-call count so the test
                    // can prove a second sign-in actually happened.
                    let n = device_calls.load(Ordering::SeqCst);
                    (
                        200,
                        format!(
                            r#"{{"access_token":"AT-{n}","refresh_token":"RT-{n}","expires_in":300}}"#
                        ),
                    )
                }
            }
            _ => (404, "{}".to_string()),
        })
    };
    let auth = explicit_auth(&mock, false);
    assert_eq!(sign_in_and_token(&auth).unwrap(), "AT-1");
    auth.tokens.lock().unwrap().as_mut().unwrap().expires_at = 1.0;
    let err = auth.token().unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::InteractionRequired);
    assert_eq!(device_calls.load(Ordering::SeqCst), 1);
    auth.sign_in().unwrap();
    assert_eq!(auth.token().unwrap(), "AT-2");
    assert_eq!(device_calls.load(Ordering::SeqCst), 2);
}

#[test]
fn groups_mode_refresh_without_id_token_requires_explicit_sign_in() {
    // In groups mode a refresh that returns 200 but omits the id_token does not
    // satisfy the requirement. The provider reports InteractionRequired without
    // prompting, and a later explicit sign_in() starts the fresh device flow.
    let device_calls = Arc::new(AtomicUsize::new(0));
    let mock = {
        let device_calls = Arc::clone(&device_calls);
        MockServer::start(move |method, path, body| match (method, path) {
            ("POST", "/device") => {
                device_calls.fetch_add(1, Ordering::SeqCst);
                (200, device_response())
            }
            ("POST", "/token") => {
                if body.contains("grant_type=refresh_token") {
                    (
                        200,
                        r#"{"access_token":"AT-refreshed","refresh_token":"RT-2","expires_in":300}"#
                            .to_string(),
                    )
                } else {
                    (
                        200,
                        r#"{"access_token":"AT-1","id_token":"ID-1","refresh_token":"RT-1","expires_in":300}"#
                            .to_string(),
                    )
                }
            }
            _ => (404, "{}".to_string()),
        })
    };
    let auth = explicit_auth(&mock, true);
    assert_eq!(sign_in_and_token(&auth).unwrap(), "ID-1");
    auth.tokens.lock().unwrap().as_mut().unwrap().expires_at = 1.0;
    let err = auth.token().unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::InteractionRequired);
    assert_eq!(device_calls.load(Ordering::SeqCst), 1);
    auth.sign_in().unwrap();
    assert_eq!(auth.token().unwrap(), "ID-1");
    assert_eq!(device_calls.load(Ordering::SeqCst), 2);
}

/// Build an auth with explicit dummy endpoints — no server is contacted, enough
/// to exercise the pure `tokenset_from_response` mapping.
fn offline_auth() -> OidcDeviceAuth {
    OidcDeviceAuth::builder()
        .client_id("questdb")
        .device_authorization_endpoint("https://idp.example.com/device")
        .token_endpoint("https://idp.example.com/token")
        .scope("openid")
        .interactive(false)
        .open_browser(false)
        .sleep_hook(no_sleep())
        .build()
        .expect("build auth")
}

#[test]
fn lifetime_cap_bounds_refreshable_and_opaque_tokens() {
    // `expires_at` and `issued_at` are stamped from the same `now`, so their
    // difference is exactly the (capped or uncapped) lifetime — no clock race.
    let auth = offline_auth();
    let long: i64 = 24 * 3600; // a 24h IdP TTL, far over the 1h cap

    // No refresh token and an opaque access token: cap the believed lifetime so a
    // hostile or stale `expires_in` cannot wedge the client indefinitely.
    let ts = auth.tokenset_from_response(
        &serde_json::json!({
            "access_token": "AT",
            "expires_in": long,
        }),
        None,
    );
    assert!(ts.refresh_token.is_none());
    assert!(
        (ts.expires_at - ts.issued_at - MAX_EXPIRES_IN as f64).abs() < 1.0,
        "opaque token without refresh: lifetime must be capped (got {}s)",
        ts.expires_at - ts.issued_at
    );

    // With a refresh token in the response: the cap fires, so a silent refresh
    // re-checks at least hourly (bounding a leaked long-lived access token).
    let ts = auth.tokenset_from_response(
        &serde_json::json!({
            "access_token": "AT",
            "refresh_token": "RT",
            "expires_in": long,
        }),
        None,
    );
    assert!(ts.refresh_token.is_some());
    assert!(
        (ts.expires_at - ts.issued_at - MAX_EXPIRES_IN as f64).abs() < 1.0,
        "with refresh token: lifetime must be capped to MAX_EXPIRES_IN (got {}s)",
        ts.expires_at - ts.issued_at
    );

    // Regression (M1): a refresh from a non-rotating IdP omits refresh_token, but
    // the prior one is carried forward — the effective token can rotate, so the
    // cap MUST still fire. Previously the cap keyed off the response body alone,
    // leaving the carried-forward case uncapped for the sender's whole lifetime.
    let ts = auth.tokenset_from_response(
        &serde_json::json!({
            "access_token": "AT",
            "expires_in": long,
        }),
        Some("carried-RT"),
    );
    assert_eq!(ts.refresh_token.as_deref(), Some("carried-RT"));
    assert!(
        (ts.expires_at - ts.issued_at - MAX_EXPIRES_IN as f64).abs() < 1.0,
        "carried-forward refresh token: lifetime must be capped (got {}s)",
        ts.expires_at - ts.issued_at
    );
}

// -- poll-loop error branches ------------------------------------------------

/// A device-authorization response with a tiny lifetime (clamped up to the 60s
/// floor) and the max poll interval, so a single virtual sleep crosses the
/// deadline.
fn device_response_short() -> String {
    serde_json::json!({
        "device_code": "DEV-CODE-123",
        "user_code": "WXYZ-1234",
        "verification_uri": "https://idp.example.com/activate",
        "expires_in": 1,
        "interval": 60
    })
    .to_string()
}

#[test]
fn expired_token_error_returns_timeout() {
    // The IdP reports the code expired via the OAuth error body → Timeout kind.
    let mock = MockServer::start(|method, path, _body| match (method, path) {
        ("POST", "/device") => (200, device_response()),
        ("POST", "/token") => (400, r#"{"error":"expired_token"}"#.to_string()),
        _ => (404, "{}".to_string()),
    });
    let auth = explicit_auth(&mock, false);
    let err = auth.sign_in().unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::Timeout);
    assert_eq!(err.idp_error(), Some("expired_token"));
}

#[test]
fn deadline_expiry_returns_timeout() {
    // The IdP never authorizes (always pending). A virtual clock advanced by the
    // sleep hook drives the loop past the (60s-clamped) device-code deadline,
    // exercising the deadline-expiry Timeout branch instantly.
    let mock = MockServer::start(|method, path, _body| match (method, path) {
        ("POST", "/device") => (200, device_response_short()),
        ("POST", "/token") => (400, r#"{"error":"authorization_pending"}"#.to_string()),
        _ => (404, "{}".to_string()),
    });
    let base = Instant::now();
    let virtual_ns = Arc::new(AtomicU64::new(0));
    let now_ns = Arc::clone(&virtual_ns);
    let sleep_ns = Arc::clone(&virtual_ns);
    let auth = OidcDeviceAuth::builder()
        .client_id("questdb")
        .device_authorization_endpoint(mock.url("/device"))
        .token_endpoint(mock.url("/token"))
        .scope("openid")
        .interactive(true)
        .open_browser(false)
        .now_hook(Arc::new(move || {
            base + Duration::from_nanos(now_ns.load(Ordering::SeqCst))
        }))
        .sleep_hook(Arc::new(move |d: Duration| {
            sleep_ns.fetch_add(d.as_nanos() as u64, Ordering::SeqCst);
        }))
        .build()
        .expect("build");
    let err = auth.sign_in().unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::Timeout);
    assert!(err.message().contains("expired"), "got: {}", err.message());
}

#[test]
fn transport_failures_continue_until_device_code_expiry() {
    // Every token-endpoint poll drops the connection without an HTTP status.
    // Match Java by retrying throughout the device-code lifetime instead of
    // aborting after three consecutive failures. The server's one-second
    // lifetime is clamped to 60 seconds and polled every five seconds, yielding
    // twelve attempts before the virtual clock reaches the deadline.
    let polls = Arc::new(AtomicUsize::new(0));
    let mock = {
        let polls = Arc::clone(&polls);
        MockServer::start(move |method, path, _body| match (method, path) {
            ("POST", "/device") => (
                200,
                serde_json::json!({
                    "device_code": "DEV-CODE-123",
                    "user_code": "WXYZ-1234",
                    "verification_uri": "https://idp.example.com/activate",
                    "expires_in": 1,
                    "interval": 5
                })
                .to_string(),
            ),
            ("POST", "/token") => {
                polls.fetch_add(1, Ordering::SeqCst);
                (0, String::new()) // 0 == drop the connection
            }
            _ => (404, "{}".to_string()),
        })
    };
    let base = Instant::now();
    let virtual_ns = Arc::new(AtomicU64::new(0));
    let now_ns = Arc::clone(&virtual_ns);
    let sleep_ns = Arc::clone(&virtual_ns);
    let auth = OidcDeviceAuth::builder()
        .client_id("questdb")
        .device_authorization_endpoint(mock.url("/device"))
        .token_endpoint(mock.url("/token"))
        .scope("openid")
        .interactive(true)
        .open_browser(false)
        .now_hook(Arc::new(move || {
            base + Duration::from_nanos(now_ns.load(Ordering::SeqCst))
        }))
        .sleep_hook(Arc::new(move |d: Duration| {
            sleep_ns.fetch_add(d.as_nanos() as u64, Ordering::SeqCst);
        }))
        .build()
        .expect("build");
    let err = auth.sign_in().unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::Timeout);
    assert_eq!(err.idp_error(), Some("expired_token"));
    assert_eq!(polls.load(Ordering::SeqCst), 12);
}

#[test]
fn poll_redirect_is_terminal() {
    // A 3xx from the token endpoint (which never legitimately redirects) is a
    // terminal device-flow error, not something to keep polling.
    let mock = MockServer::start(|method, path, _body| match (method, path) {
        ("POST", "/device") => (200, device_response()),
        ("POST", "/token") => (302, "{}".to_string()),
        _ => (404, "{}".to_string()),
    });
    let auth = explicit_auth(&mock, false);
    let err = auth.sign_in().unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::DeviceFlow);
    assert_eq!(err.status(), Some(302));
}

#[test]
fn poll_does_not_follow_redirect_to_another_host() {
    // A 30x from the token endpoint must NOT be followed. Only the original URL is
    // vetted; following a redirect could resend the device_code / refresh_token
    // (POSTed in the request body) to another origin, even downgrading to
    // plaintext. `HttpClient` sets max_redirects(0), so the 30x is returned as-is
    // and the sink is never contacted. Without that defense the client would chase
    // the Location and accept the sink's response as a token.
    let sink_hits = Arc::new(AtomicUsize::new(0));
    let sink = {
        let sink_hits = Arc::clone(&sink_hits);
        MockServer::start(move |_method, _path, _body| {
            sink_hits.fetch_add(1, Ordering::SeqCst);
            (
                200,
                r#"{"access_token":"STOLEN","expires_in":300}"#.to_string(),
            )
        })
    };
    let sink_url = sink.url("/steal");
    let mock =
        MockServer::start_redirecting(sink_url, |method, path, _body| match (method, path) {
            ("POST", "/device") => (200, device_response()),
            ("POST", "/token") => (302, "{}".to_string()),
            _ => (404, "{}".to_string()),
        });
    let auth = explicit_auth(&mock, false);
    let err = auth.sign_in().unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::DeviceFlow);
    assert_eq!(err.status(), Some(302));
    assert_eq!(
        sink_hits.load(Ordering::SeqCst),
        0,
        "the redirect target must never be contacted — credentials must not be resent"
    );
}

#[test]
fn poll_non_json_body_is_terminal_rejection() {
    // A non-JSON 4xx (a WAF / proxy error page) at the token endpoint is a
    // terminal rejection — a conformant poll reply is always JSON.
    let mock = MockServer::start(|method, path, _body| match (method, path) {
        ("POST", "/device") => (200, device_response()),
        ("POST", "/token") => (403, "<html>Forbidden</html>".to_string()),
        _ => (404, "{}".to_string()),
    });
    let auth = explicit_auth(&mock, false);
    let err = auth.sign_in().unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::DeviceFlow);
    assert_eq!(err.status(), Some(403));
}

// -- request_device_code error paths -----------------------------------------

#[test]
fn device_request_http_408_is_retryable_with_json_or_non_json_body() {
    for (body, expected_error) in [
        (
            r#"{"error":"temporarily_unavailable","error_description":"request timed out"}"#,
            Some("temporarily_unavailable"),
        ),
        ("<html>request timed out</html>", None),
    ] {
        let response_body = body.to_string();
        let mock = MockServer::start_with_retry_after(13, move |method, path, _body| {
            match (method, path) {
                ("POST", "/device") => (408, response_body.clone()),
                _ => (404, "{}".to_string()),
            }
        });
        let auth = explicit_auth(&mock, false);
        let err = auth.sign_in().unwrap_err();
        assert_eq!(err.kind(), OidcErrorKind::Network);
        assert_eq!(err.status(), Some(408));
        assert_eq!(err.retry_after_secs(), Some(13));
        assert_eq!(err.idp_error(), expected_error);
    }
}

#[test]
fn device_endpoint_rejection_errors() {
    // A non-200 from the device-authorization endpoint surfaces the IdP error.
    let mock = MockServer::start(|method, path, _body| match (method, path) {
        ("POST", "/device") => (400, r#"{"error":"invalid_client"}"#.to_string()),
        _ => (404, "{}".to_string()),
    });
    let auth = explicit_auth(&mock, false);
    let err = auth.sign_in().unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::DeviceFlow);
    assert_eq!(err.idp_error(), Some("invalid_client"));
    assert_eq!(err.status(), Some(400));
}

#[test]
fn device_endpoint_missing_required_field_errors() {
    // A 200 device response missing a required field (device_code) can't start
    // the flow.
    let mock = MockServer::start(|method, path, _body| match (method, path) {
        ("POST", "/device") => (
            200,
            r#"{"user_code":"WXYZ-1234","verification_uri":"https://idp.example.com/act"}"#
                .to_string(),
        ),
        _ => (404, "{}".to_string()),
    });
    let auth = explicit_auth(&mock, false);
    let err = auth.sign_in().unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::DeviceFlow);
    assert_eq!(err.status(), Some(200));
}

// -- token-cache hygiene -----------------------------------------------------

#[test]
fn cached_token_fast_path_selects_only_required_credential() {
    for (groups_in_token, expected) in [(false, "AT-cached"), (true, "ID-cached")] {
        let auth = OidcDeviceAuth::builder()
            .client_id("questdb")
            .device_authorization_endpoint("https://idp.example.com/device")
            .token_endpoint("https://idp.example.com/token")
            .groups_in_token(groups_in_token)
            .interactive(false)
            .build()
            .unwrap();
        let now = now_epoch();
        *auth.tokens.lock().unwrap() = Some(TokenSet {
            access_token: Some("AT-cached".to_string()),
            id_token: Some("ID-cached".to_string()),
            refresh_token: Some("RT-cached".to_string()),
            expires_at: now + 300.0,
            token_type: "Bearer".to_string(),
            scope: Some("openid".to_string()),
            sub: Some("subject".to_string()),
            issued_at: now,
        });

        assert_eq!(auth.token().unwrap(), expected);
        // The explicit snapshot API still returns the complete token state.
        let snapshot = auth.token_set().unwrap();
        assert_eq!(snapshot.access_token.as_deref(), Some("AT-cached"));
        assert_eq!(snapshot.id_token.as_deref(), Some("ID-cached"));
        assert_eq!(snapshot.refresh_token.as_deref(), Some("RT-cached"));
    }
}

#[test]
fn stale_token_cleared_when_no_refresh_and_device_flow_fails() {
    // A cached token with NO refresh token, forced expired: obtain_tokens must
    // clear it before the interactive flow, so a failing device flow leaves no
    // stale token cached.
    let device_calls = Arc::new(AtomicUsize::new(0));
    let mock = {
        let device_calls = Arc::clone(&device_calls);
        MockServer::start(move |method, path, _body| match (method, path) {
            // First sign-in succeeds; the second device request is rejected so
            // run_device_flow fails.
            ("POST", "/device") => {
                if device_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    (200, device_response())
                } else {
                    (400, r#"{"error":"invalid_client"}"#.to_string())
                }
            }
            ("POST", "/token") => (
                200,
                r#"{"access_token":"AT-1","expires_in":300}"#.to_string(),
            ),
            _ => (404, "{}".to_string()),
        })
    };
    let auth = explicit_auth(&mock, false);
    assert_eq!(sign_in_and_token(&auth).unwrap(), "AT-1");
    assert!(auth.token_set().is_some());
    // Force expiry; the cached token has no refresh token.
    auth.tokens.lock().unwrap().as_mut().unwrap().expires_at = 1.0;
    let err = auth.token().unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::InteractionRequired);
    assert_eq!(device_calls.load(Ordering::SeqCst), 1);
    assert!(
        auth.token_set().is_none(),
        "stale expired token left cached after a non-interactive lookup"
    );
    let err = auth.sign_in().unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::DeviceFlow);
    assert!(auth.token_set().is_none());
}

// -- token store persistence (Layer 1 + Layer 2) -----------------------------

/// An auth wired to a `FileTokenStore` rooted at `dir`, against the mock IdP.
fn auth_with_store(mock: &MockServer, dir: &Path) -> OidcDeviceAuth {
    OidcDeviceAuth::builder()
        .client_id("questdb")
        .device_authorization_endpoint(mock.url("/device"))
        .token_endpoint(mock.url("/token"))
        .scope("openid")
        .interactive(true)
        .open_browser(false)
        .sleep_hook(no_sleep())
        .token_store(FileTokenStore::at(dir))
        .build()
        .expect("build auth with store")
}

/// An in-memory store whose save path can fail after the refresh parent has been
/// cleared. The independent mutex models the store's cross-process lock.
#[derive(Clone, Default)]
struct FailingSaveStore {
    token: Arc<std::sync::Mutex<Option<PersistedToken>>>,
    coordination: Arc<std::sync::Mutex<()>>,
    fail_save: Arc<AtomicBool>,
    fail_clear: Arc<AtomicBool>,
    operations: Arc<std::sync::Mutex<Vec<&'static str>>>,
}

impl FailingSaveStore {
    fn seed(&self, token: PersistedToken) {
        *self.token.lock().unwrap() = Some(token);
    }

    fn token(&self) -> Option<PersistedToken> {
        self.token.lock().unwrap().clone()
    }
}

impl TokenStore for FailingSaveStore {
    fn load(&self, _key: &TokenStoreKey) -> TokenStoreResult<Option<PersistedToken>> {
        self.operations.lock().unwrap().push("load");
        Ok(self.token())
    }

    fn save(&self, _key: &TokenStoreKey, token: &PersistedToken) -> TokenStoreResult<()> {
        self.operations.lock().unwrap().push("save");
        if self.fail_save.load(Ordering::SeqCst) {
            return Err(Box::new(std::io::Error::other("injected save failure")));
        }
        *self.token.lock().unwrap() = Some(token.clone());
        Ok(())
    }

    fn clear(&self, _key: &TokenStoreKey) -> TokenStoreResult<()> {
        self.operations.lock().unwrap().push("clear");
        if self.fail_clear.load(Ordering::SeqCst) {
            return Err(Box::new(std::io::Error::other("injected clear failure")));
        }
        *self.token.lock().unwrap() = None;
        Ok(())
    }

    fn in_lock(
        &self,
        _key: &TokenStoreKey,
        action: &mut dyn FnMut() -> TokenStoreResult<()>,
    ) -> TokenStoreResult<()> {
        let _guard = self.coordination.lock().unwrap();
        action()
    }
}

/// An in-memory store that exposes whether a peer attempted the locked lazy
/// load while another auth instance holds the coordination lock across refresh.
#[derive(Clone, Default)]
struct TombstoneRaceStore {
    token: Arc<std::sync::Mutex<Option<PersistedToken>>>,
    coordination: Arc<std::sync::Mutex<()>>,
    progress: Arc<(std::sync::Mutex<TombstoneRaceProgress>, std::sync::Condvar)>,
}

#[derive(Default)]
struct TombstoneRaceProgress {
    lock_attempts: usize,
    loads: usize,
}

impl TombstoneRaceStore {
    fn seed(&self, token: PersistedToken) {
        *self.token.lock().unwrap() = Some(token);
    }

    fn token(&self) -> Option<PersistedToken> {
        self.token.lock().unwrap().clone()
    }

    fn wait_for_peer_load_or_lock_attempt(&self) -> (bool, usize, usize) {
        let (progress, changed) = &*self.progress;
        let (progress, timeout) = changed
            .wait_timeout_while(
                progress.lock().unwrap(),
                Duration::from_secs(5),
                |progress| progress.lock_attempts < 3 && progress.loads < 3,
            )
            .unwrap();
        (!timeout.timed_out(), progress.lock_attempts, progress.loads)
    }
}

impl TokenStore for TombstoneRaceStore {
    fn load(&self, _key: &TokenStoreKey) -> TokenStoreResult<Option<PersistedToken>> {
        let (progress, changed) = &*self.progress;
        progress.lock().unwrap().loads += 1;
        changed.notify_all();
        Ok(self.token())
    }

    fn save(&self, _key: &TokenStoreKey, token: &PersistedToken) -> TokenStoreResult<()> {
        *self.token.lock().unwrap() = Some(token.clone());
        Ok(())
    }

    fn clear(&self, _key: &TokenStoreKey) -> TokenStoreResult<()> {
        *self.token.lock().unwrap() = None;
        Ok(())
    }

    fn in_lock(
        &self,
        _key: &TokenStoreKey,
        action: &mut dyn FnMut() -> TokenStoreResult<()>,
    ) -> TokenStoreResult<()> {
        let (progress, changed) = &*self.progress;
        progress.lock().unwrap().lock_attempts += 1;
        changed.notify_all();
        let _guard = self.coordination.lock().unwrap();
        action()
    }
}

fn auth_with_failing_store(
    mock: &MockServer,
    store: FailingSaveStore,
    interactive: bool,
) -> OidcDeviceAuth {
    OidcDeviceAuth::builder()
        .client_id("questdb")
        .device_authorization_endpoint(mock.url("/device"))
        .token_endpoint(mock.url("/token"))
        .scope("openid")
        .interactive(interactive)
        .open_browser(false)
        .sleep_hook(no_sleep())
        .token_store(store)
        .build()
        .expect("build auth with test store")
}

fn expired_tokens(refresh_token: &str) -> TokenSet {
    TokenSet {
        access_token: Some("AT-expired".to_string()),
        id_token: None,
        refresh_token: Some(refresh_token.to_string()),
        expires_at: 1.0,
        token_type: "Bearer".to_string(),
        scope: Some("openid".to_string()),
        sub: None,
        issued_at: 0.0,
    }
}

/// The store key matching `auth_with_store`'s config, for inspecting the file.
fn key_for(mock: &MockServer) -> TokenStoreKey {
    TokenStoreKey::from_config(
        "questdb",
        &mock.url("/token"),
        &mock.url("/device"),
        "openid",
        None,
        false,
        None,
    )
}

/// A mock that signs in with a refresh token, then answers refresh polls. The
/// `refresh_body` closure builds the refresh response so a test can pick rotating
/// vs non-rotating behaviour. Counts device-authorization requests.
fn persistence_mock(
    device_calls: Arc<AtomicUsize>,
    refresh_body: impl Fn() -> String + Send + Sync + 'static,
) -> MockServer {
    MockServer::start(move |method, path, body| match (method, path) {
        ("POST", "/device") => {
            device_calls.fetch_add(1, Ordering::SeqCst);
            (200, device_response())
        }
        ("POST", "/token") => {
            if body.contains("grant_type=refresh_token") {
                (200, refresh_body())
            } else {
                (
                    200,
                    r#"{"access_token":"AT-initial","refresh_token":"RT-1","expires_in":300}"#
                        .to_string(),
                )
            }
        }
        _ => (404, "{}".to_string()),
    })
}

/// Rewrite the persisted entry with an expired access token (keeping the refresh
/// token), simulating a restart after the access token's lifetime elapsed — so a
/// fresh instance must silently refresh rather than serve the on-disk token.
fn expire_persisted(dir: &Path, key: &TokenStoreKey) {
    let store = FileTokenStore::at(dir);
    let p = store.load(key).unwrap().unwrap();
    let expired = PersistedToken::new(
        p.access_token().map(String::from),
        p.id_token().map(String::from),
        p.refresh_token().map(String::from),
        1.0, // long past
        300.0,
    );
    store.save(key, &expired).unwrap();
}

#[test]
fn success_renderer_panic_keeps_token_cached_and_persisted() {
    struct PanicOnSuccess;

    impl Renderer for PanicOnSuccess {
        fn on_success(&self, _identity: Option<&str>, _expires_in_secs: f64) {
            panic!("injected renderer panic");
        }
    }

    let device_calls = Arc::new(AtomicUsize::new(0));
    let mock = persistence_mock(Arc::clone(&device_calls), || {
        r#"{"access_token":"AT-refreshed","expires_in":300}"#.to_string()
    });
    let dir = TempDir::new().unwrap();
    let key = key_for(&mock);
    let auth = OidcDeviceAuth::builder()
        .client_id("questdb")
        .device_authorization_endpoint(mock.url("/device"))
        .token_endpoint(mock.url("/token"))
        .scope("openid")
        .interactive(true)
        .open_browser(false)
        .sleep_hook(no_sleep())
        .renderer(PanicOnSuccess)
        .token_store(FileTokenStore::at(dir.path()))
        .build()
        .unwrap();

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| auth.sign_in()));
    assert!(
        result.is_err(),
        "the custom renderer should still propagate its panic"
    );
    assert_eq!(
        auth.token_set().unwrap().access_token.as_deref(),
        Some("AT-initial"),
        "the authorized token was lost from memory"
    );
    assert_eq!(
        FileTokenStore::at(dir.path())
            .load(&key)
            .unwrap()
            .unwrap()
            .access_token(),
        Some("AT-initial"),
        "the authorized token was not persisted before the callback"
    );

    // The acquisition lock is poisoned by the renderer panic, but the cache fast
    // path must still return the completed sign-in without another device flow.
    assert_eq!(auth.token().unwrap(), "AT-initial");
    assert_eq!(device_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn restart_resumes_from_persisted_token_without_reprompt() {
    let device_calls = Arc::new(AtomicUsize::new(0));
    let mock = persistence_mock(Arc::clone(&device_calls), || {
        r#"{"access_token":"AT-refreshed","expires_in":300}"#.to_string()
    });
    let dir = TempDir::new().unwrap();
    let key = key_for(&mock);

    // First run: sign in, persisting the token (one device prompt).
    let auth_a = auth_with_store(&mock, dir.path());
    assert_eq!(sign_in_and_token(&auth_a).unwrap(), "AT-initial");
    assert_eq!(device_calls.load(Ordering::SeqCst), 1);
    drop(auth_a); // simulate a process restart

    // A brand-new instance sharing the store resumes the still-valid access token
    // straight from disk — no network, no re-prompt.
    let auth_b = auth_with_store(&mock, dir.path());
    assert_eq!(auth_b.token().unwrap(), "AT-initial");
    assert_eq!(device_calls.load(Ordering::SeqCst), 1);
    drop(auth_b);

    // Simulate the persisted access token having expired; a fresh instance must
    // silently refresh from the persisted refresh token, still no device prompt.
    expire_persisted(dir.path(), &key);
    let auth_c = auth_with_store(&mock, dir.path());
    assert_eq!(auth_c.token().unwrap(), "AT-refreshed");
    assert_eq!(
        device_calls.load(Ordering::SeqCst),
        1,
        "a persisted refresh token must not trigger a re-prompt"
    );
}

#[test]
fn refresh_only_persisted_entry_is_rejected_in_both_token_modes() {
    for groups_in_token in [false, true] {
        let device_calls = Arc::new(AtomicUsize::new(0));
        let refresh_calls = Arc::new(AtomicUsize::new(0));
        let mock = {
            let device_calls = Arc::clone(&device_calls);
            let refresh_calls = Arc::clone(&refresh_calls);
            MockServer::start(move |method, path, body| match (method, path) {
                ("POST", "/device") => {
                    device_calls.fetch_add(1, Ordering::SeqCst);
                    (200, device_response())
                }
                ("POST", "/token") if body.contains("grant_type=refresh_token") => {
                    refresh_calls.fetch_add(1, Ordering::SeqCst);
                    (
                        200,
                        r#"{"access_token":"AT-refreshed","id_token":"ID-refreshed","expires_in":300}"#
                            .to_string(),
                    )
                }
                _ => (404, "{}".to_string()),
            })
        };
        let store = FailingSaveStore::default();
        store.seed(PersistedToken::new(
            None,
            None,
            Some("RT-only".to_string()),
            0.0,
            0.0,
        ));
        let auth = OidcDeviceAuth::builder()
            .client_id("questdb")
            .device_authorization_endpoint(mock.url("/device"))
            .token_endpoint(mock.url("/token"))
            .scope("openid")
            .groups_in_token(groups_in_token)
            .interactive(false)
            .open_browser(false)
            .sleep_hook(no_sleep())
            .token_store(store.clone())
            .build()
            .expect("build auth with refresh-only store");

        let err = auth.token().unwrap_err();
        assert_eq!(err.kind(), OidcErrorKind::InteractionRequired);
        assert_eq!(refresh_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            device_calls.load(Ordering::SeqCst),
            0,
            "non-interactive auth unexpectedly started a device flow"
        );
    }
}

#[test]
fn persist_restores_non_rotating_refresh_token_after_consuming_parent() {
    // Non-rotating IdP: the refresh response carries no new refresh_token.
    let device_calls = Arc::new(AtomicUsize::new(0));
    let mock = persistence_mock(Arc::clone(&device_calls), || {
        r#"{"access_token":"AT-refreshed","expires_in":300}"#.to_string()
    });
    let dir = TempDir::new().unwrap();
    let reader = FileTokenStore::at(dir.path());
    let key = key_for(&mock);

    let auth = auth_with_store(&mock, dir.path());
    assert_eq!(sign_in_and_token(&auth).unwrap(), "AT-initial");
    let before = reader.load(&key).unwrap().unwrap();
    assert_eq!(before.access_token(), Some("AT-initial"));
    assert_eq!(before.refresh_token(), Some("RT-1"));
    drop(auth);

    // Expire the on-disk access token, then a fresh instance silently refreshes.
    expire_persisted(dir.path(), &key);
    let auth2 = auth_with_store(&mock, dir.path());
    assert_eq!(auth2.token().unwrap(), "AT-refreshed");

    // Even though the refresh token did not rotate, it was removed before the
    // network call and must be restored with the refreshed access token.
    let after = reader.load(&key).unwrap().unwrap();
    assert_eq!(
        after.access_token(),
        Some("AT-refreshed"),
        "the consumed parent must be restored after a non-rotating refresh"
    );
    assert_eq!(after.refresh_token(), Some("RT-1"));
}

#[test]
fn groups_mode_refresh_without_id_token_keeps_the_rotated_credential() {
    // Regression: a refresh that rotates the refresh token but withholds the
    // required kind must not destroy the credential.
    //
    // `refresh_under_lock` deletes the persisted parent and drops the in-memory
    // copy *before* submitting (refresh-token-reuse defence). If the response
    // then lacks the id_token this configuration serves -- which OIDC Core 12.1
    // expressly permits -- the rotated replacement used to be discarded on both
    // sides, leaving nothing anywhere. A headless caller with a token store was
    // locked out after its first silent refresh, and a restart did not recover.
    let device_calls = Arc::new(AtomicUsize::new(0));
    let mock = {
        let device_calls = Arc::clone(&device_calls);
        MockServer::start(move |method, path, body| match (method, path) {
            ("POST", "/device") => {
                device_calls.fetch_add(1, Ordering::SeqCst);
                (200, device_response())
            }
            ("POST", "/token") => {
                if body.contains("grant_type=refresh_token") {
                    // Rotates the refresh token, but returns no id_token.
                    (
                        200,
                        r#"{"access_token":"AT-refreshed","refresh_token":"RT-2","expires_in":300}"#
                            .to_string(),
                    )
                } else {
                    (
                        200,
                        r#"{"access_token":"AT-1","id_token":"ID-1","refresh_token":"RT-1","expires_in":300}"#
                            .to_string(),
                    )
                }
            }
            _ => (404, "{}".to_string()),
        })
    };
    let dir = TempDir::new().unwrap();
    let key = TokenStoreKey::from_config(
        "questdb",
        &mock.url("/token"),
        &mock.url("/device"),
        "openid",
        None,
        true, // groups_in_token
        None,
    );
    let groups_auth = |dir: &Path| {
        OidcDeviceAuth::builder()
            .client_id("questdb")
            .device_authorization_endpoint(mock.url("/device"))
            .token_endpoint(mock.url("/token"))
            .scope("openid")
            .groups_in_token(true)
            .interactive(false)
            .open_browser(false)
            .sleep_hook(no_sleep())
            .token_store(FileTokenStore::at(dir))
            .build()
            .expect("build groups-mode auth with store")
    };

    // Sign in once so RT-1 is persisted, then expire the stored token so the
    // next instance must refresh.
    let first = OidcDeviceAuth::builder()
        .client_id("questdb")
        .device_authorization_endpoint(mock.url("/device"))
        .token_endpoint(mock.url("/token"))
        .scope("openid")
        .groups_in_token(true)
        .interactive(true)
        .open_browser(false)
        .sleep_hook(no_sleep())
        .token_store(FileTokenStore::at(dir.path()))
        .build()
        .expect("build groups-mode auth");
    assert_eq!(sign_in_and_token(&first).unwrap(), "ID-1");
    drop(first);
    expire_persisted(dir.path(), &key);

    // The silent refresh cannot satisfy groups mode, so this still reports
    // InteractionRequired and never prompts.
    let auth = groups_auth(dir.path());
    let err = auth.token().unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::InteractionRequired);
    assert_eq!(
        device_calls.load(Ordering::SeqCst),
        1,
        "a non-interactive token() must not start a device flow"
    );

    // ...but the rotated credential survives, in memory and on disk. Before the
    // fix both were empty here.
    let cached = auth.tokens.lock().unwrap();
    assert_eq!(
        cached.as_ref().and_then(|t| t.refresh_token.as_deref()),
        Some("RT-2"),
        "the rotated refresh token was dropped from the in-memory cache"
    );
    drop(cached);

    let reader = FileTokenStore::at(dir.path());
    let after = reader
        .load(&key)
        .unwrap()
        .expect("the persisted entry was destroyed by a refresh that rotated it");
    assert_eq!(after.refresh_token(), Some("RT-2"));
    assert_eq!(after.access_token(), Some("AT-refreshed"));

    // A restart still finds a usable refresh token rather than being locked out.
    let restarted = groups_auth(dir.path());
    assert_eq!(
        restarted.token().unwrap_err().kind(),
        OidcErrorKind::InteractionRequired
    );
    assert_eq!(
        reader.load(&key).unwrap().unwrap().refresh_token(),
        Some("RT-2"),
        "a restart must not consume the credential without replacing it"
    );
}

#[test]
fn retry_after_raises_the_poll_interval_and_never_lowers_it() {
    // RFC 8628 3.5: the client waits at least the advertised interval. A proxy
    // or WAF answering `Retry-After: 1` to a flow whose interval is 30 used to
    // set the interval to 5 -- six times faster than the identity provider
    // asked for, for the rest of the flow.
    assert_eq!(backoff(30, Some(1), false), 30);
    assert_eq!(backoff(30, Some(45), false), 45);

    // A long Retry-After is honoured rather than truncated to MAX_POLL_INTERVAL.
    // Ignoring a rate limiter's stated pause is what earns a ban; the caller
    // still clips the wait to the remaining device-code lifetime.
    assert_eq!(backoff(5, Some(300), false), 300);
    assert!(backoff(5, Some(300), false) > MAX_POLL_INTERVAL);

    // Absent Retry-After keeps the RFC 8628 +5s step.
    assert_eq!(backoff(10, None, false), 15);

    // slow_down MUST increase, even against a contradictory low Retry-After.
    assert_eq!(backoff(30, Some(1), true), 35);
    assert_eq!(backoff(30, None, true), 35);

    // The floor still applies.
    assert_eq!(backoff(1, Some(0), false), MIN_POLL_INTERVAL);
}

#[test]
fn clear_after_close_still_deletes_the_persisted_entry() {
    // close() drops the in-memory credential but deliberately leaves the
    // persisted entry, so clear() has to outlive it. It used to refuse:
    // acquire_for_operation and the store-cancellation predicate both key on
    // `closed`, the latter aborting the delete before it began. That left a
    // long-lived plaintext refresh token on disk with no supported way to
    // remove it.
    let device_calls = Arc::new(AtomicUsize::new(0));
    let mock = persistence_mock(Arc::clone(&device_calls), || {
        r#"{"access_token":"AT-refreshed","refresh_token":"RT-2","expires_in":300}"#.to_string()
    });
    let dir = TempDir::new().unwrap();
    let reader = FileTokenStore::at(dir.path());
    let key = key_for(&mock);

    let auth = auth_with_store(&mock, dir.path());
    assert_eq!(sign_in_and_token(&auth).unwrap(), "AT-initial");
    assert!(
        reader.load(&key).unwrap().is_some(),
        "nothing was persisted"
    );

    auth.close();
    assert!(
        reader.load(&key).unwrap().is_some(),
        "close must leave the persisted entry alone -- clear is what removes it"
    );

    auth.try_clear()
        .expect("clear must work on a closed provider");
    assert!(
        reader.load(&key).unwrap().is_none(),
        "the persisted credential survived clear() after close()"
    );
}

#[test]
fn persist_rewrites_when_refresh_token_rotates() {
    // Rotating IdP: the refresh response carries a new refresh_token.
    let device_calls = Arc::new(AtomicUsize::new(0));
    let mock = persistence_mock(Arc::clone(&device_calls), || {
        r#"{"access_token":"AT-refreshed","refresh_token":"RT-2","expires_in":300}"#.to_string()
    });
    let dir = TempDir::new().unwrap();
    let reader = FileTokenStore::at(dir.path());
    let key = key_for(&mock);

    let auth = auth_with_store(&mock, dir.path());
    assert_eq!(sign_in_and_token(&auth).unwrap(), "AT-initial");
    drop(auth);

    // Expire the on-disk access token, then a fresh instance silently refreshes
    // and the IdP rotates the refresh token.
    expire_persisted(dir.path(), &key);
    let auth2 = auth_with_store(&mock, dir.path());
    assert_eq!(auth2.token().unwrap(), "AT-refreshed");

    // A rotated refresh token MUST be persisted, or a later restart would replay a
    // revoked one; so the file now holds the rotated token and the new access token.
    let after = reader.load(&key).unwrap().unwrap();
    assert_eq!(after.access_token(), Some("AT-refreshed"));
    assert_eq!(after.refresh_token(), Some("RT-2"));
}

#[test]
fn replacement_without_refresh_token_clears_rejected_persisted_token() {
    let device_calls = Arc::new(AtomicUsize::new(0));
    let device_token_calls = Arc::new(AtomicUsize::new(0));
    let refresh_calls = Arc::new(AtomicUsize::new(0));
    let mock = {
        let device_calls = Arc::clone(&device_calls);
        let device_token_calls = Arc::clone(&device_token_calls);
        let refresh_calls = Arc::clone(&refresh_calls);
        MockServer::start(move |method, path, body| match (method, path) {
            ("POST", "/device") => {
                device_calls.fetch_add(1, Ordering::SeqCst);
                (200, device_response())
            }
            ("POST", "/token") if body.contains("grant_type=refresh_token") => {
                let attempt = refresh_calls.fetch_add(1, Ordering::SeqCst);
                if attempt == 0 {
                    // The first process learns that the persisted token is no
                    // longer usable and falls back to a replacement device flow.
                    (400, r#"{"error":"invalid_grant"}"#.to_string())
                } else {
                    // If the rejected token survives on disk, the restarted
                    // process stops here with a retryable error instead of
                    // reaching its device flow.
                    (503, r#"{"error":"temporarily_unavailable"}"#.to_string())
                }
            }
            ("POST", "/token") => {
                let attempt = device_token_calls.fetch_add(1, Ordering::SeqCst);
                if attempt == 0 {
                    (
                        200,
                        r#"{"access_token":"AT-initial","refresh_token":"RT-rejected","expires_in":300}"#
                            .to_string(),
                    )
                } else {
                    // The replacement and post-restart flows deliberately issue
                    // no refresh token.
                    (
                        200,
                        format!(r#"{{"access_token":"AT-device-{attempt}","expires_in":300}}"#),
                    )
                }
            }
            _ => (404, "{}".to_string()),
        })
    };
    let dir = TempDir::new().unwrap();
    let reader = FileTokenStore::at(dir.path());
    let key = key_for(&mock);

    let auth = auth_with_store(&mock, dir.path());
    assert_eq!(sign_in_and_token(&auth).unwrap(), "AT-initial");
    expire_persisted(dir.path(), &key);
    auth.tokens.lock().unwrap().as_mut().unwrap().expires_at = 1.0;

    // The provider consumes the rejected refresh parent but never starts a
    // replacement prompt. Only explicit sign_in() runs the new device flow.
    let err = auth.token().unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::InteractionRequired);
    assert_eq!(device_calls.load(Ordering::SeqCst), 1);
    auth.sign_in().unwrap();
    assert_eq!(auth.token().unwrap(), "AT-device-1");
    assert!(
        reader.load(&key).unwrap().is_none(),
        "the rejected persisted refresh token survived its replacement sign-in"
    );
    drop(auth);

    // A new process has no credential to load and must ask for explicit sign-in,
    // rather than starting a prompt from token().
    let restarted = auth_with_store(&mock, dir.path());
    let err = restarted.token().unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::InteractionRequired);
    restarted.sign_in().unwrap();
    assert_eq!(restarted.token().unwrap(), "AT-device-2");
    assert_eq!(refresh_calls.load(Ordering::SeqCst), 1);
    assert_eq!(device_calls.load(Ordering::SeqCst), 3);
}

#[test]
fn clear_deletes_the_persisted_entry() {
    let device_calls = Arc::new(AtomicUsize::new(0));
    let mock = persistence_mock(Arc::clone(&device_calls), || {
        r#"{"access_token":"AT-refreshed","expires_in":300}"#.to_string()
    });
    let dir = TempDir::new().unwrap();
    let reader = FileTokenStore::at(dir.path());
    let key = key_for(&mock);

    let auth = auth_with_store(&mock, dir.path());
    sign_in_and_token(&auth).unwrap();
    assert!(reader.load(&key).unwrap().is_some());

    auth.clear();
    assert!(
        reader.load(&key).unwrap().is_none(),
        "clear() must delete the persisted entry"
    );
}

#[test]
fn try_clear_reports_persisted_deletion_failure() {
    let mock = MockServer::start(|_, _, _| (404, "{}".to_string()));
    let store = FailingSaveStore::default();
    store.seed(PersistedToken::new(
        Some("AT-persisted".to_string()),
        None,
        Some("RT-persisted".to_string()),
        now_epoch() + 300.0,
        300.0,
    ));
    store.fail_clear.store(true, Ordering::SeqCst);
    let auth = auth_with_failing_store(&mock, store.clone(), false);
    *auth.tokens.lock().unwrap() = Some(expired_tokens("RT-in-memory"));

    let err = auth.try_clear().unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::Network);
    assert!(err.message().contains("injected clear failure"));
    assert!(auth.token_set().is_none(), "in-memory token was retained");
    assert!(
        store.token().is_some(),
        "failing test store unexpectedly deleted the persisted token"
    );
    assert!(
        auth.store_state.lock().unwrap().load_attempted,
        "the same auth may reload a credential after clear was requested"
    );
}

#[test]
fn tampered_persisted_token_is_rejected_on_load() {
    // A persisted access_token carrying a CR/LF (a header-injection vector) must be
    // rejected on load exactly like a wire token, so it never reaches a header. The
    // whole entry is unusable, so the flow falls back to a fresh device sign-in.
    let device_calls = Arc::new(AtomicUsize::new(0));
    let mock = persistence_mock(Arc::clone(&device_calls), || {
        r#"{"access_token":"AT-refreshed","expires_in":300}"#.to_string()
    });
    let dir = TempDir::new().unwrap();
    let writer = FileTokenStore::at(dir.path());
    let key = key_for(&mock);

    let now = crate::oidc::token::now_epoch();
    let tampered = PersistedToken::new(
        Some("bad\r\nInjected: header".to_string()),
        None,
        Some("RT-1".to_string()),
        now + 300.0,
        300.0,
    );
    writer.save(&key, &tampered).unwrap();

    let auth = auth_with_store(&mock, dir.path());
    // The tampered served token is dropped and the entry rejected wholesale,
    // but token() must not turn that into a hidden prompt.
    let err = auth.token().unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::InteractionRequired);
    assert_eq!(device_calls.load(Ordering::SeqCst), 0);
    auth.sign_in().unwrap();
    assert_eq!(auth.token().unwrap(), "AT-initial");
    assert_eq!(device_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn tampered_persisted_refresh_token_is_dropped_on_load() {
    // A persisted refresh_token carrying a CR/LF is dropped by is_safe_token_str on
    // load, just like the served token, so it is never submitted to the token
    // endpoint. With an expired access token and no usable refresh token, token()
    // reports InteractionRequired instead of refreshing with the tampered value.
    let refresh_calls = Arc::new(AtomicUsize::new(0));
    let mock = {
        let refresh_calls = Arc::clone(&refresh_calls);
        MockServer::start(move |method, path, body| match (method, path) {
            ("POST", "/token") if body.contains("grant_type=refresh_token") => {
                refresh_calls.fetch_add(1, Ordering::SeqCst);
                (
                    200,
                    r#"{"access_token":"AT-refreshed","expires_in":300}"#.to_string(),
                )
            }
            _ => (404, "{}".to_string()),
        })
    };
    let dir = TempDir::new().unwrap();
    let writer = FileTokenStore::at(dir.path());
    let key = key_for(&mock);
    let tampered = PersistedToken::new(
        Some("AT-expired".to_string()),
        None,
        Some("RT-1\r\nInjected: header".to_string()), // control chars in the refresh token
        1.0,                                          // expired access token
        300.0,
    );
    writer.save(&key, &tampered).unwrap();

    let auth = auth_with_store(&mock, dir.path());
    let err = auth.token().unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::InteractionRequired);
    assert_eq!(
        refresh_calls.load(Ordering::SeqCst),
        0,
        "a tampered refresh token must never be submitted to the token endpoint"
    );
}

#[test]
fn refresh_refuses_in_memory_fallback_when_persisted_entry_has_no_refresh_token() {
    // A refresh-token-less peer entry means the in-memory parent is no longer
    // authoritative. Reusing it could trigger rotating-token reuse detection.
    let device_calls = Arc::new(AtomicUsize::new(0));
    let refresh_calls = Arc::new(AtomicUsize::new(0));
    let mock = {
        let device_calls = Arc::clone(&device_calls);
        let refresh_calls = Arc::clone(&refresh_calls);
        MockServer::start(move |method, path, body| match (method, path) {
            ("POST", "/device") => {
                device_calls.fetch_add(1, Ordering::SeqCst);
                (200, device_response())
            }
            ("POST", "/token") if body.contains("grant_type=refresh_token") => {
                refresh_calls.fetch_add(1, Ordering::SeqCst);
                (
                    200,
                    r#"{"access_token":"AT-refreshed","expires_in":300}"#.to_string(),
                )
            }
            ("POST", "/token") => (
                200,
                r#"{"access_token":"AT-initial","refresh_token":"RT-1","expires_in":300}"#
                    .to_string(),
            ),
            _ => (404, "{}".to_string()),
        })
    };
    let dir = TempDir::new().unwrap();
    let key = key_for(&mock);

    // Sign in: in-memory + disk hold RT-1, so last_persisted_refresh == RT-1.
    let auth = auth_with_store(&mock, dir.path());
    assert_eq!(sign_in_and_token(&auth).unwrap(), "AT-initial");
    assert_eq!(device_calls.load(Ordering::SeqCst), 1);

    // A peer process / corruption overwrites the file for this identity with a
    // served token, NO refresh token, and a long-past expiry — a state the load
    // path accepts (only the served token is required) but that must never reach
    // the refresh network call as the refresh source.
    let writer = FileTokenStore::at(dir.path());
    writer
        .save(
            &key,
            &PersistedToken::new(Some("AT-stale".to_string()), None, None, 1.0, 300.0),
        )
        .unwrap();

    // Force the in-memory access token expired while keeping its refresh token, so
    // obtain_tokens enters the coordinated refresh and re-reads the swapped file.
    auth.tokens.lock().unwrap().as_mut().unwrap().expires_at = 1.0;

    let err = auth.token().unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::Network);
    assert!(err.message().contains("has no refresh token"));
    assert_eq!(refresh_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        device_calls.load(Ordering::SeqCst),
        1,
        "a fail-closed refresh must not re-prompt in the same call"
    );
    assert_eq!(auth.token_set().unwrap().refresh_token, None);
}

#[test]
fn failed_rotated_child_save_leaves_no_reusable_parent() {
    let refresh_calls = Arc::new(AtomicUsize::new(0));
    let mock = {
        let refresh_calls = Arc::clone(&refresh_calls);
        MockServer::start(move |method, path, body| {
            if (method, path) == ("POST", "/token") && body.contains("grant_type=refresh_token") {
                refresh_calls.fetch_add(1, Ordering::SeqCst);
                return (
                    200,
                    r#"{"access_token":"AT-2","refresh_token":"RT-2","expires_in":300}"#
                        .to_string(),
                );
            }
            (404, "{}".to_string())
        })
    };
    let store = FailingSaveStore::default();
    store.seed(PersistedToken::new(
        Some("AT-expired".to_string()),
        None,
        Some("RT-1".to_string()),
        1.0,
        300.0,
    ));
    store.fail_save.store(true, Ordering::SeqCst);

    let auth = auth_with_failing_store(&mock, store.clone(), false);
    assert_eq!(auth.token().unwrap(), "AT-2");
    assert_eq!(
        auth.token_set().unwrap().refresh_token.as_deref(),
        Some("RT-2")
    );
    assert!(
        store.token().is_none(),
        "a failed child save must not leave the submitted parent in the store"
    );
    assert_eq!(
        *store.operations.lock().unwrap(),
        ["load", "load", "clear", "save"],
        "the parent must be cleared before the refresh result is saved"
    );

    // Model a peer that loaded RT-1 before the first process consumed it. The
    // missing store entry proves that its in-memory copy is no longer safe.
    let stale_peer = auth_with_failing_store(&mock, store.clone(), false);
    *stale_peer.tokens.lock().unwrap() = Some(expired_tokens("RT-1"));
    *stale_peer.store_state.lock().unwrap() = StoreState {
        load_attempted: true,
        last_persisted_refresh: Some("RT-1".to_string()),
        ..StoreState::default()
    };
    let err = stale_peer.token().unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::Network);
    assert!(err.message().contains("removed by another refresh attempt"));
    assert_eq!(
        refresh_calls.load(Ordering::SeqCst),
        1,
        "the stale peer replayed a refresh-token parent"
    );
    assert_eq!(stale_peer.token_set().unwrap().refresh_token, None);
}

#[test]
fn lazy_load_waits_out_peer_refresh_tombstone() {
    let refresh_calls = Arc::new(AtomicUsize::new(0));
    let refresh_entered = Arc::new(Barrier::new(2));
    let release_refresh = Arc::new(Barrier::new(2));
    let mock = {
        let refresh_calls = Arc::clone(&refresh_calls);
        let refresh_entered = Arc::clone(&refresh_entered);
        let release_refresh = Arc::clone(&release_refresh);
        MockServer::start(move |method, path, body| {
            if (method, path) == ("POST", "/token") && body.contains("grant_type=refresh_token") {
                refresh_calls.fetch_add(1, Ordering::SeqCst);
                // refresh_under_lock has consumed RT-1 but still holds the
                // coordination lock. Keep the child unsaved until the peer has
                // attempted its one-shot lazy load.
                refresh_entered.wait();
                release_refresh.wait();
                return (
                    200,
                    r#"{"access_token":"AT-2","refresh_token":"RT-2","expires_in":300}"#
                        .to_string(),
                );
            }
            (404, "{}".to_string())
        })
    };
    let store = TombstoneRaceStore::default();
    store.seed(PersistedToken::new(
        Some("AT-expired".to_string()),
        None,
        Some("RT-1".to_string()),
        1.0,
        300.0,
    ));
    let build_auth = || {
        OidcDeviceAuth::builder()
            .client_id("questdb")
            .device_authorization_endpoint(mock.url("/device"))
            .token_endpoint(mock.url("/token"))
            .scope("openid")
            .interactive(false)
            .open_browser(false)
            .sleep_hook(no_sleep())
            .token_store(store.clone())
            .build()
            .unwrap()
    };

    let refreshing = build_auth();
    let refresh_thread = std::thread::spawn(move || refreshing.token());
    refresh_entered.wait();
    let parent_consumed = store.token().is_none();

    let peer = build_auth();
    let peer_thread = std::thread::spawn(move || peer.token());
    // With an unlocked lazy load, the peer reaches a third load here, observes
    // None, and permanently latches the tombstone. With the fix, its third lock
    // attempt blocks until RT-2 is saved.
    let (peer_attempted, lock_attempts, loads) = store.wait_for_peer_load_or_lock_attempt();
    release_refresh.wait();

    let refreshed = refresh_thread.join().unwrap();
    let peer_token = peer_thread.join().unwrap();
    assert!(
        parent_consumed,
        "refresh parent was not consumed before the token request"
    );
    assert!(
        peer_attempted,
        "peer never attempted to load during the refresh tombstone window: locks={lock_attempts}, loads={loads}"
    );
    assert_eq!(refreshed.unwrap(), "AT-2");
    assert_eq!(
        peer_token.unwrap(),
        "AT-2",
        "peer permanently cached the temporary refresh tombstone"
    );
    assert_eq!(refresh_calls.load(Ordering::SeqCst), 1);
    assert_eq!(store.token().unwrap().refresh_token(), Some("RT-2"));
}

#[test]
fn lost_refresh_response_consumes_parent_before_retry() {
    let refresh_calls = Arc::new(AtomicUsize::new(0));
    let mock = {
        let refresh_calls = Arc::clone(&refresh_calls);
        MockServer::start(move |method, path, body| {
            if (method, path) == ("POST", "/token") && body.contains("grant_type=refresh_token") {
                refresh_calls.fetch_add(1, Ordering::SeqCst);
                // 0 == drop the connection: an ambiguous post-send transport
                // failure with NO HTTP status. The IdP may have consumed and
                // rotated RT-1 before the response was lost, so the parent must
                // stay discarded (a clean HTTP status is handled the opposite
                // way — see `transient_status_refresh_preserves_persisted_parent`).
                return (0, String::new());
            }
            (404, "{}".to_string())
        })
    };
    let store = FailingSaveStore::default();
    store.seed(PersistedToken::new(
        Some("AT-expired".to_string()),
        None,
        Some("RT-1".to_string()),
        1.0,
        300.0,
    ));
    let auth = auth_with_failing_store(&mock, store.clone(), false);

    let err = auth.token().unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::Network);
    assert!(store.token().is_none());
    assert_eq!(auth.token_set().unwrap().refresh_token, None);
    assert_eq!(refresh_calls.load(Ordering::SeqCst), 1);

    // A transport failure with no status can happen after the IdP consumed RT-1.
    // A later call must require a new sign-in rather than submitting RT-1 again.
    let err = auth.token().unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::InteractionRequired);
    assert_eq!(refresh_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn refresh_ambiguous_transport_failure_discards_in_memory_parent() {
    // Default (no-store) path: a status-less transport failure that may have
    // reached the IdP is ambiguous — the parent may have been consumed and
    // rotated with its response lost. Resubmitting it to a reuse-detecting IdP
    // would revoke the whole token family, so the in-memory parent must be
    // discarded and the next call must require a fresh sign-in rather than replay
    // RT-1. This makes the default path match the store path's
    // `lost_refresh_response_consumes_parent_before_retry`.
    let refresh_calls = Arc::new(AtomicUsize::new(0));
    let mock = {
        let refresh_calls = Arc::clone(&refresh_calls);
        MockServer::start(move |method, path, body| {
            if (method, path) == ("POST", "/token") && body.contains("grant_type=refresh_token") {
                refresh_calls.fetch_add(1, Ordering::SeqCst);
                return (0, String::new()); // drop after reading: post-send, no status
            }
            (404, "{}".to_string())
        })
    };
    let auth = explicit_auth(&mock, false);
    *auth.tokens.lock().unwrap() = Some(expired_tokens("RT-1"));

    let err = auth.token().unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::Network);
    assert_eq!(
        auth.token_set().unwrap().refresh_token,
        None,
        "an ambiguous post-send failure must discard the in-memory refresh token"
    );
    assert_eq!(refresh_calls.load(Ordering::SeqCst), 1);

    // The next call must re-sign-in, never resubmit the possibly-consumed RT-1.
    let err = auth.token().unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::InteractionRequired);
    assert_eq!(refresh_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn refresh_pre_send_failure_keeps_in_memory_parent() {
    // Default (no-store) path: a pre-send connection failure proves the IdP never
    // received the refresh request, so the still-valid refresh token must be
    // retained and retried — a transient IdP outage must not wedge an unattended
    // client into an interactive re-sign-in. The outage-tolerance half of the
    // store/no-store consistency fix (discarding uniformly would terminalize a
    // long-lived transport on a momentary connect blip).
    let auth = auth_with_dead_token_endpoint();
    *auth.tokens.lock().unwrap() = Some(expired_tokens("RT-1"));

    let err = auth.token().unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::Network);
    assert_eq!(
        auth.token_set().unwrap().refresh_token.as_deref(),
        Some("RT-1"),
        "a pre-send connect failure must keep the refresh token for a later retry"
    );

    // A later call keeps retrying with RT-1 rather than giving up.
    let err = auth.token().unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::Network);
    assert_eq!(
        auth.token_set().unwrap().refresh_token.as_deref(),
        Some("RT-1")
    );
}

#[test]
fn refresh_pre_send_failure_keeps_persisted_parent() {
    // Store path: a pre-send connection failure proves the refresh token was not
    // consumed, so it must be restored on disk and in memory (not tombstoned) and
    // remain replayable by this process, a peer, or a restart. Together with
    // `lost_refresh_response_consumes_parent_before_retry` this pins that only a
    // genuinely ambiguous post-send failure consumes the persisted parent.
    let addr = dead_loopback_addr();
    let store = FailingSaveStore::default();
    store.seed(PersistedToken::new(
        Some("AT-expired".to_string()),
        None,
        Some("RT-1".to_string()),
        1.0,
        300.0,
    ));
    let auth = OidcDeviceAuth::builder()
        .client_id("questdb")
        .device_authorization_endpoint(format!("http://{addr}/device"))
        .token_endpoint(format!("http://{addr}/token"))
        .scope("openid")
        .interactive(true)
        .open_browser(false)
        .timeout(Duration::from_secs(5))
        .sleep_hook(no_sleep())
        .token_store(store.clone())
        .build()
        .expect("build auth with store");

    let err = auth.token().unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::Network);
    assert_eq!(
        store
            .token()
            .and_then(|t| t.refresh_token().map(str::to_string)),
        Some("RT-1".to_string()),
        "a pre-send connect failure must not consume the persisted refresh token"
    );
    assert_eq!(
        auth.token_set()
            .and_then(|t| t.refresh_token.clone())
            .as_deref(),
        Some("RT-1")
    );
}

#[test]
fn transient_status_refresh_preserves_persisted_parent() {
    // A clean transient HTTP status (503) means the IdP answered WITHOUT
    // consuming the refresh token, so a store-backed refresh must keep RT-1 (on
    // disk and in memory) and retry — never brick an unattended client by
    // forcing an interactive re-sign-in it cannot perform. Mirrors the no-store
    // path (`refresh_transient_error_preserves_token_no_reprompt`). Regression
    // test for a transient IdP hiccup permanently destroying a still-valid
    // persisted refresh token.
    let refresh_calls = Arc::new(AtomicUsize::new(0));
    let mock = {
        let refresh_calls = Arc::clone(&refresh_calls);
        MockServer::start(move |method, path, body| {
            if (method, path) == ("POST", "/token") && body.contains("grant_type=refresh_token") {
                // First poll: transient 503 (non-consuming). Second: success,
                // rotating RT-1 -> RT-2.
                if refresh_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    return (503, r#"{"error":"temporarily_unavailable"}"#.to_string());
                }
                return (
                    200,
                    r#"{"access_token":"AT-2","refresh_token":"RT-2","expires_in":300}"#
                        .to_string(),
                );
            }
            (404, "{}".to_string())
        })
    };
    let store = FailingSaveStore::default();
    store.seed(PersistedToken::new(
        Some("AT-expired".to_string()),
        None,
        Some("RT-1".to_string()),
        1.0,
        300.0,
    ));
    let auth = auth_with_failing_store(&mock, store.clone(), false);

    // The transient 503 surfaces a Network error, but the still-valid refresh
    // token is retained on disk and in memory rather than consumed.
    let err = auth.token().unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::Network);
    assert_eq!(err.status(), Some(503));
    assert_eq!(
        store
            .token()
            .and_then(|t| t.refresh_token().map(str::to_string)),
        Some("RT-1".to_string()),
        "a transient 503 must not consume the persisted refresh token"
    );
    assert_eq!(
        auth.token_set().and_then(|t| t.refresh_token.clone()),
        Some("RT-1".to_string()),
        "the in-memory refresh token must survive a transient 503"
    );

    // An explicit recovery bypasses token()'s short stampede backoff and retries
    // immediately, rotating RT-1 -> RT-2 without another device flow.
    auth.sign_in().unwrap();
    assert_eq!(auth.token().unwrap(), "AT-2");
    assert_eq!(refresh_calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        store
            .token()
            .and_then(|t| t.refresh_token().map(str::to_string)),
        Some("RT-2".to_string()),
    );
}

#[test]
fn coordinated_refresh_never_falls_back_without_the_store_lock() {
    struct LockUnavailableStore;

    impl TokenStore for LockUnavailableStore {
        fn load(&self, _key: &TokenStoreKey) -> TokenStoreResult<Option<PersistedToken>> {
            Ok(None)
        }

        fn save(&self, _key: &TokenStoreKey, _token: &PersistedToken) -> TokenStoreResult<()> {
            Ok(())
        }

        fn clear(&self, _key: &TokenStoreKey) -> TokenStoreResult<()> {
            Ok(())
        }

        fn in_lock(
            &self,
            _key: &TokenStoreKey,
            _action: &mut dyn FnMut() -> TokenStoreResult<()>,
        ) -> TokenStoreResult<()> {
            Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "peer holds the refresh lock",
            )))
        }
    }

    let token_calls = Arc::new(AtomicUsize::new(0));
    let mock = {
        let token_calls = Arc::clone(&token_calls);
        MockServer::start(move |method, path, _body| {
            if (method, path) == ("POST", "/token") {
                token_calls.fetch_add(1, Ordering::SeqCst);
            }
            (500, r#"{"error":"must_not_be_called"}"#.to_string())
        })
    };
    let auth = OidcDeviceAuth::builder()
        .client_id("questdb")
        .device_authorization_endpoint(mock.url("/device"))
        .token_endpoint(mock.url("/token"))
        .scope("openid")
        .interactive(true)
        .open_browser(false)
        .sleep_hook(no_sleep())
        .token_store(LockUnavailableStore)
        .build()
        .unwrap();
    *auth.tokens.lock().unwrap() = Some(TokenSet {
        access_token: Some("AT-expired".to_string()),
        id_token: None,
        refresh_token: Some("RT-1".to_string()),
        expires_at: 1.0,
        token_type: "Bearer".to_string(),
        scope: Some("openid".to_string()),
        sub: None,
        issued_at: 0.0,
    });

    let err = auth.token().unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::Network);
    assert!(err.message().contains("cross-process OIDC refresh lock"));
    assert_eq!(
        token_calls.load(Ordering::SeqCst),
        0,
        "refresh ran after coordination failed"
    );
}

#[test]
fn first_use_store_lock_failure_is_retryable_and_never_prompts() {
    struct LockedStore;

    impl TokenStore for LockedStore {
        fn load(&self, _key: &TokenStoreKey) -> TokenStoreResult<Option<PersistedToken>> {
            Ok(None)
        }

        fn save(&self, _key: &TokenStoreKey, _token: &PersistedToken) -> TokenStoreResult<()> {
            Ok(())
        }

        fn clear(&self, _key: &TokenStoreKey) -> TokenStoreResult<()> {
            Ok(())
        }

        fn in_lock(
            &self,
            _key: &TokenStoreKey,
            _action: &mut dyn FnMut() -> TokenStoreResult<()>,
        ) -> TokenStoreResult<()> {
            Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "peer holds the token-store lock",
            )))
        }
    }

    let device_calls = Arc::new(AtomicUsize::new(0));
    let mock = {
        let device_calls = Arc::clone(&device_calls);
        MockServer::start(move |method, path, _body| {
            if (method, path) == ("POST", "/device") {
                device_calls.fetch_add(1, Ordering::SeqCst);
            }
            (500, r#"{"error":"must_not_be_called"}"#.to_string())
        })
    };
    let auth = OidcDeviceAuth::builder()
        .client_id("questdb")
        .device_authorization_endpoint(mock.url("/device"))
        .token_endpoint(mock.url("/token"))
        .scope("openid")
        .interactive(true)
        .open_browser(false)
        .sleep_hook(no_sleep())
        .token_store(LockedStore)
        .build()
        .unwrap();

    for err in [auth.token().unwrap_err(), auth.sign_in().unwrap_err()] {
        assert_eq!(err.kind(), OidcErrorKind::Network);
        assert!(
            err.message()
                .contains("Could not load the OIDC token store")
        );
    }
    assert_eq!(
        device_calls.load(Ordering::SeqCst),
        0,
        "store contention started a needless device flow"
    );
}

#[test]
fn transient_store_load_error_is_retryable_and_retried() {
    // M2: FileTokenStore reports a missing/corrupt/oversized file as Ok(None); the
    // only case it surfaces as Err is a genuine (transient) I/O error. A transient
    // failure on the first load must NOT permanently disable persistence — a later
    // call must retry and resume from the on-disk token instead of re-prompting.
    struct FlakyStore {
        loads: std::sync::atomic::AtomicUsize,
        inner: FileTokenStore,
    }
    impl TokenStore for FlakyStore {
        fn load(&self, key: &TokenStoreKey) -> TokenStoreResult<Option<PersistedToken>> {
            if self.loads.fetch_add(1, Ordering::SeqCst) == 0 {
                return Err(Box::new(std::io::Error::other("transient EMFILE")));
            }
            self.inner.load(key)
        }
        fn save(&self, key: &TokenStoreKey, token: &PersistedToken) -> TokenStoreResult<()> {
            self.inner.save(key, token)
        }
        fn clear(&self, key: &TokenStoreKey) -> TokenStoreResult<()> {
            self.inner.clear(key)
        }
        fn in_lock(
            &self,
            key: &TokenStoreKey,
            action: &mut dyn FnMut() -> TokenStoreResult<()>,
        ) -> TokenStoreResult<()> {
            self.inner.in_lock(key, action)
        }
    }

    let mock = MockServer::start(|_, _, _| (404, "{}".to_string()));
    let dir = TempDir::new().unwrap();
    let key = key_for(&mock);
    // Seed a valid persisted entry (a refresh token) via a plain store.
    let now = crate::oidc::token::now_epoch();
    FileTokenStore::at(dir.path())
        .save(
            &key,
            &PersistedToken::new(
                Some("AT".to_string()),
                None,
                Some("RT-1".to_string()),
                now + 300.0,
                300.0,
            ),
        )
        .unwrap();

    let auth = OidcDeviceAuth::builder()
        .client_id("questdb")
        .device_authorization_endpoint(mock.url("/device"))
        .token_endpoint(mock.url("/token"))
        .scope("openid")
        .interactive(true)
        .open_browser(false)
        .sleep_hook(no_sleep())
        .token_store(FlakyStore {
            loads: std::sync::atomic::AtomicUsize::new(0),
            inner: FileTokenStore::at(dir.path()),
        })
        .build()
        .unwrap();

    // The public first-use path surfaces the transient load failure as retryable
    // rather than claiming that an interactive sign-in is required.
    let err = auth.token().unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::Network);
    assert!(err.message().contains("transient EMFILE"));
    assert!(
        auth.token_set().is_none(),
        "nothing should be adopted after a transient load error"
    );
    // The error was not latched, so a second attempt retries and resumes.
    assert_eq!(auth.token().unwrap(), "AT");
    assert_eq!(
        auth.token_set().unwrap().refresh_token.as_deref(),
        Some("RT-1")
    );
}

#[test]
fn repeated_store_load_failures_are_backed_off() {
    struct UnreadableStore {
        loads: Arc<AtomicUsize>,
    }

    impl TokenStore for UnreadableStore {
        fn load(&self, _key: &TokenStoreKey) -> TokenStoreResult<Option<PersistedToken>> {
            self.loads.fetch_add(1, Ordering::SeqCst);
            Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "token store is unreadable",
            )))
        }

        fn save(&self, _key: &TokenStoreKey, _token: &PersistedToken) -> TokenStoreResult<()> {
            Ok(())
        }

        fn clear(&self, _key: &TokenStoreKey) -> TokenStoreResult<()> {
            Ok(())
        }

        fn in_lock(
            &self,
            _key: &TokenStoreKey,
            action: &mut dyn FnMut() -> TokenStoreResult<()>,
        ) -> TokenStoreResult<()> {
            action()
        }
    }

    let loads = Arc::new(AtomicUsize::new(0));
    let mock = MockServer::start(|_, _, _| (404, "{}".to_string()));
    let auth = OidcDeviceAuth::builder()
        .client_id("questdb")
        .device_authorization_endpoint(mock.url("/device"))
        .token_endpoint(mock.url("/token"))
        .scope("openid")
        .interactive(true)
        .open_browser(false)
        .token_store(UnreadableStore {
            loads: Arc::clone(&loads),
        })
        .build()
        .unwrap();

    // Java gives a one-shot store fault one immediate free retry. A second
    // consecutive failure starts the 5s exponential backoff, so the third hot
    // path lookup reports the failure without opening/logging the store again.
    assert_eq!(auth.token().unwrap_err().kind(), OidcErrorKind::Network);
    assert_eq!(auth.token().unwrap_err().kind(), OidcErrorKind::Network);
    let backed_off = auth.token().unwrap_err();
    assert_eq!(backed_off.kind(), OidcErrorKind::Network);
    assert!(backed_off.message().contains("temporarily backed off"));
    assert_eq!(loads.load(Ordering::SeqCst), 2);

    // An explicit recovery request bypasses the transport-path throttle.
    assert_eq!(auth.sign_in().unwrap_err().kind(), OidcErrorKind::Network);
    assert_eq!(loads.load(Ordering::SeqCst), 3);
}

/// A minimal JWT (`header.payload.sig`) whose payload carries `exp` (and a `sub`),
/// for exercising the unverified `exp`-bounding of the believed lifetime.
fn jwt_with_exp(exp: i64) -> String {
    use base64ct::{Base64UrlUnpadded, Encoding};
    let payload = format!(r#"{{"exp":{exp},"sub":"user@example.com"}}"#);
    let b64 = Base64UrlUnpadded::encode_string(payload.as_bytes());
    format!("header.{b64}.signature")
}

#[test]
fn wire_expiry_bounded_by_jwt_exp() {
    // M3: a non-conformant `expires_in` with NO refresh token (so the rotation cap
    // doesn't apply) must not push the believed expiry past the served token's own
    // JWT `exp` — otherwise one bad field wedges the sender on permanent auth
    // failures with no self-heal.
    let mock = MockServer::start(|_, _, _| (404, "{}".to_string()));
    let auth = explicit_auth(&mock, false);
    let exp = (crate::oidc::token::now_epoch() + 86_400.0).floor(); // 24h out
    let body = serde_json::json!({
        "access_token": jwt_with_exp(exp as i64),
        "expires_in": 99_999_999_999i64,
    });
    let ts = auth.tokenset_from_response(&body, None);
    assert!(
        (ts.expires_at() - exp).abs() < 1.5,
        "expires_at not bounded by the JWT exp: {} (exp {exp})",
        ts.expires_at()
    );
}

#[test]
fn groups_mode_expiry_uses_id_token_exp() {
    // M6: in groups mode the served token is the id_token, so the believed expiry
    // must follow the id_token's exp, not the access token's `expires_in`.
    let mock = MockServer::start(|_, _, _| (404, "{}".to_string()));
    let auth = explicit_auth(&mock, true);
    let now = crate::oidc::token::now_epoch();
    let id_exp = (now + 120.0).floor(); // id_token expires in 2 minutes
    let body = serde_json::json!({
        "access_token": jwt_with_exp((now + 100_000.0) as i64), // long-lived
        "id_token": jwt_with_exp(id_exp as i64),                // short-lived
        "expires_in": 100_000,
    });
    let ts = auth.tokenset_from_response(&body, None);
    assert!(
        (ts.expires_at() - id_exp).abs() < 1.5,
        "groups mode ignored the id_token exp: {} (id_exp {id_exp})",
        ts.expires_at()
    );
}

#[test]
fn persisted_expiry_honors_jwt_exp_but_caps_opaque() {
    // M3: a persisted no-refresh JWT token (e.g. written by another language
    // client) whose real exp is well beyond an hour must be honored, not capped to
    // 1h. An opaque (non-JWT) token has no self-describing expiry, so the
    // untrusted-file 1h cap still applies.
    let mock = MockServer::start(|_, _, _| (404, "{}".to_string()));
    let auth = explicit_auth(&mock, false);
    let now = crate::oidc::token::now_epoch();

    let exp = (now + 8.0 * 3600.0).floor(); // 8h out
    let jwt = PersistedToken::new(
        Some(jwt_with_exp(exp as i64)),
        None,
        None,
        exp,
        8.0 * 3600.0,
    );
    let ts = auth.tokenset_from_persisted(&jwt).unwrap();
    assert!(
        (ts.expires_at() - exp).abs() < 1.5,
        "persisted JWT exp was capped instead of honored: {}",
        ts.expires_at()
    );

    let opaque = PersistedToken::new(
        Some("opaque-token".to_string()),
        None,
        None,
        now + 8.0 * 3600.0,
        300.0,
    );
    let ts2 = auth.tokenset_from_persisted(&opaque).unwrap();
    assert!(
        ts2.expires_at() <= now + 3600.0 + 5.0,
        "opaque token not capped to the 1h untrusted-file window: {}",
        ts2.expires_at()
    );
}
