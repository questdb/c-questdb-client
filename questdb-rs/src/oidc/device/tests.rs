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
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use tempfile::TempDir;

use super::*;
use crate::oidc::error::OidcErrorKind;
use crate::oidc::token_store::{FileTokenStore, PersistedToken, TokenStore, TokenStoreKey};

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
        Self::start_inner(None, handler)
    }

    /// Like [`start`], but stamps a `Retry-After: <secs>` header on every response.
    /// The tiny mock can't otherwise set one, and the 429 / `slow_down` backoff
    /// path needs it to exercise a low Retry-After.
    fn start_with_retry_after<H>(secs: u64, handler: H) -> Self
    where
        H: Fn(&str, &str, &str) -> (u16, String) + Send + Sync + 'static,
    {
        Self::start_inner(Some(secs), handler)
    }

    fn start_inner<H>(retry_after: Option<u64>, handler: H) -> Self
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
                        Ok((stream, _)) => handle_conn(stream, &*handler, retry_after),
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

fn handle_conn<H>(mut stream: TcpStream, handler: &H, retry_after: Option<u64>)
where
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
    let response = format!(
        "HTTP/1.1 {status} MOCK\r\nContent-Type: application/json\r\n{retry_after_header}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
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
    assert_eq!(auth.token().unwrap(), "AT-999");
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
    assert_eq!(auth.token().unwrap(), "ID-TOKEN-abc");
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
    let err = auth.token().unwrap_err();
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
    assert_eq!(auth.token().unwrap(), "AT-slow");
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
    assert_eq!(auth.token().unwrap(), "AT-sd");
    let durations = slept.lock().unwrap();
    // Two polls: the sleep before the retry (after the slow_down) must exceed the
    // first by at least the +5s step, not shrink toward the 1s Retry-After.
    assert!(
        durations.len() >= 2,
        "expected >=2 polls, got {durations:?}"
    );
    assert!(
        durations[1] >= durations[0] + Duration::from_secs(5),
        "slow_down via 429 must increase the interval, got {durations:?}"
    );
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
    let err = auth.token().unwrap_err();
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
    let err = auth.token().unwrap_err();
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
    let err = auth.token().unwrap_err();
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
    assert_eq!(auth.token().unwrap(), "AT-initial");
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
    let err = auth.token().unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::InteractionRequired);
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
    assert_eq!(auth.token().unwrap(), "AT-discovered");
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
    let err = auth.token().unwrap_err();
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
    // error and do NOT re-prompt (the refresh token is still valid).
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
    assert_eq!(auth.token().unwrap(), "AT-initial");
    // Force the cached token to look expired so the next call must refresh.
    auth.tokens.lock().unwrap().as_mut().unwrap().expires_at = 1.0;
    let err = auth.token().unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::Network);
    assert_eq!(device_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn refresh_rejected_falls_back_to_device_flow() {
    // A 4xx (revoked / expired refresh token) is terminal: fall through to a
    // fresh interactive sign-in rather than propagating the error.
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
    assert_eq!(auth.token().unwrap(), "AT-1");
    auth.tokens.lock().unwrap().as_mut().unwrap().expires_at = 1.0;
    assert_eq!(auth.token().unwrap(), "AT-2");
    assert_eq!(device_calls.load(Ordering::SeqCst), 2);
}

#[test]
fn groups_mode_refresh_without_id_token_reprompts() {
    // In groups mode a refresh that returns 200 but omits the id_token does not
    // satisfy the requirement; fall through to a fresh sign-in.
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
    assert_eq!(auth.token().unwrap(), "ID-1");
    auth.tokens.lock().unwrap().as_mut().unwrap().expires_at = 1.0;
    // Refresh yields no id_token, so a fresh device flow must run.
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
fn lifetime_cap_applies_only_with_refresh_token() {
    // `expires_at` and `issued_at` are stamped from the same `now`, so their
    // difference is exactly the (capped or uncapped) lifetime — no clock race.
    let auth = offline_auth();
    let long: i64 = 24 * 3600; // a 24h IdP TTL, far over the 1h cap

    // No refresh token: trust the IdP's real TTL. Capping can't rotate the token
    // (there is nothing to refresh with) and would only force a headless-breaking
    // re-prompt, while the token stays valid at the server for the full 24h.
    let ts = auth.tokenset_from_response(
        &serde_json::json!({
            "access_token": "AT",
            "expires_in": long,
        }),
        None,
    );
    assert!(ts.refresh_token.is_none());
    assert!(
        (ts.expires_at - ts.issued_at - long as f64).abs() < 1.0,
        "no refresh token: lifetime must not be capped (got {}s)",
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
    let err = auth.token().unwrap_err();
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
    let err = auth.token().unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::Timeout);
    assert!(err.message().contains("expired"), "got: {}", err.message());
}

#[test]
fn transport_failure_surfaces_network_error_not_timeout() {
    // The device endpoint works, but every token-endpoint poll drops the
    // connection (no HTTP status). After MAX_CONSECUTIVE_TRANSPORT_FAILURES the
    // flow must surface the real network cause rather than poll silently until
    // the code expires and report a Timeout. (Both endpoints stay co-located on
    // the one mock, satisfying the origin check.)
    let mock = MockServer::start(|method, path, _body| match (method, path) {
        ("POST", "/device") => (200, device_response()),
        ("POST", "/token") => (0, String::new()), // 0 == drop the connection
        _ => (404, "{}".to_string()),
    });
    let auth = explicit_auth(&mock, false);
    let err = auth.token().unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::Network);
    assert!(
        err.message().contains("unreachable"),
        "expected an unreachable-endpoint message, got: {}",
        err.message()
    );
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
    let err = auth.token().unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::DeviceFlow);
    assert_eq!(err.status(), Some(302));
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
    let err = auth.token().unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::DeviceFlow);
    assert_eq!(err.status(), Some(403));
}

// -- request_device_code error paths -----------------------------------------

#[test]
fn device_endpoint_rejection_errors() {
    // A non-200 from the device-authorization endpoint surfaces the IdP error.
    let mock = MockServer::start(|method, path, _body| match (method, path) {
        ("POST", "/device") => (400, r#"{"error":"invalid_client"}"#.to_string()),
        _ => (404, "{}".to_string()),
    });
    let auth = explicit_auth(&mock, false);
    let err = auth.token().unwrap_err();
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
    let err = auth.token().unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::DeviceFlow);
    assert_eq!(err.status(), Some(200));
}

// -- token-cache hygiene -----------------------------------------------------

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
    assert_eq!(auth.token().unwrap(), "AT-1");
    assert!(auth.token_set().is_some());
    // Force expiry; the cached token has no refresh token.
    auth.tokens.lock().unwrap().as_mut().unwrap().expires_at = 1.0;
    let err = auth.token().unwrap_err();
    assert_eq!(err.kind(), OidcErrorKind::DeviceFlow);
    assert!(
        auth.token_set().is_none(),
        "stale expired token left cached after a failed sign-in"
    );
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
fn restart_resumes_from_persisted_token_without_reprompt() {
    let device_calls = Arc::new(AtomicUsize::new(0));
    let mock = persistence_mock(Arc::clone(&device_calls), || {
        r#"{"access_token":"AT-refreshed","expires_in":300}"#.to_string()
    });
    let dir = TempDir::new().unwrap();
    let key = key_for(&mock);

    // First run: sign in, persisting the token (one device prompt).
    let auth_a = auth_with_store(&mock, dir.path());
    assert_eq!(auth_a.token().unwrap(), "AT-initial");
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
fn persist_skips_write_when_refresh_token_unchanged() {
    // Non-rotating IdP: the refresh response carries no new refresh_token.
    let device_calls = Arc::new(AtomicUsize::new(0));
    let mock = persistence_mock(Arc::clone(&device_calls), || {
        r#"{"access_token":"AT-refreshed","expires_in":300}"#.to_string()
    });
    let dir = TempDir::new().unwrap();
    let reader = FileTokenStore::at(dir.path());
    let key = key_for(&mock);

    let auth = auth_with_store(&mock, dir.path());
    assert_eq!(auth.token().unwrap(), "AT-initial");
    let before = reader.load(&key).unwrap().unwrap();
    assert_eq!(before.access_token(), Some("AT-initial"));
    assert_eq!(before.refresh_token(), Some("RT-1"));
    drop(auth);

    // Expire the on-disk access token, then a fresh instance silently refreshes.
    expire_persisted(dir.path(), &key);
    let auth2 = auth_with_store(&mock, dir.path());
    assert_eq!(auth2.token().unwrap(), "AT-refreshed");

    // The refresh token did not rotate, so the file was NOT rewritten — it still
    // holds the (expired) access token, unchanged.
    let after = reader.load(&key).unwrap().unwrap();
    assert_eq!(
        after.access_token(),
        Some("AT-initial"),
        "a non-rotating refresh must not rewrite the file"
    );
    assert_eq!(after.refresh_token(), Some("RT-1"));
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
    assert_eq!(auth.token().unwrap(), "AT-initial");
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
fn clear_deletes_the_persisted_entry() {
    let device_calls = Arc::new(AtomicUsize::new(0));
    let mock = persistence_mock(Arc::clone(&device_calls), || {
        r#"{"access_token":"AT-refreshed","expires_in":300}"#.to_string()
    });
    let dir = TempDir::new().unwrap();
    let reader = FileTokenStore::at(dir.path());
    let key = key_for(&mock);

    let auth = auth_with_store(&mock, dir.path());
    auth.token().unwrap();
    assert!(reader.load(&key).unwrap().is_some());

    auth.clear();
    assert!(
        reader.load(&key).unwrap().is_none(),
        "clear() must delete the persisted entry"
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
    // The tampered served token is dropped, the entry rejected wholesale, so a
    // fresh device flow runs and yields the clean initial token.
    assert_eq!(auth.token().unwrap(), "AT-initial");
    assert_eq!(device_calls.load(Ordering::SeqCst), 1);
}
