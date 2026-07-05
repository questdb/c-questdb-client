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
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use super::*;
use crate::oidc::error::OidcErrorKind;

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
                        Ok((stream, _)) => handle_conn(stream, &*handler),
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

fn handle_conn<H>(mut stream: TcpStream, handler: &H)
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
    let response = format!(
        "HTTP/1.1 {status} MOCK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
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
    // The discovery doc omits device_authorization_endpoint (the IdP does not
    // support the device grant) — resolution must fail with a clear error rather
    // than return a half-built config.
    let mock = MockServer::start(|method, path, _body| match (method, path) {
        ("GET", "/settings") => (200, settings_client_only()),
        // No `issuer` (its absence is tolerated) and no device endpoint.
        ("GET", "/.well-known/openid-configuration") => (
            200,
            serde_json::json!({"token_endpoint": "https://idp.example.com/token"}).to_string(),
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
        err.message().contains("device_authorization_endpoint"),
        "expected missing-device-endpoint rejection, got: {}",
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
    let ts = auth.tokenset_from_response(&serde_json::json!({
        "access_token": "AT",
        "expires_in": long,
    }));
    assert!(ts.refresh_token.is_none());
    assert!(
        (ts.expires_at - ts.issued_at - long as f64).abs() < 1.0,
        "no refresh token: lifetime must not be capped (got {}s)",
        ts.expires_at - ts.issued_at
    );

    // With a refresh token: the cap fires, so a silent refresh re-checks at least
    // hourly (bounding a leaked long-lived access token).
    let ts = auth.tokenset_from_response(&serde_json::json!({
        "access_token": "AT",
        "refresh_token": "RT",
        "expires_in": long,
    }));
    assert!(ts.refresh_token.is_some());
    assert!(
        (ts.expires_at - ts.issued_at - MAX_EXPIRES_IN as f64).abs() < 1.0,
        "with refresh token: lifetime must be capped to MAX_EXPIRES_IN (got {}s)",
        ts.expires_at - ts.issued_at
    );
}
