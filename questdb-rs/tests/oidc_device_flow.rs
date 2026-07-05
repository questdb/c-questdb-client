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

//! Integration tests for the ILP/HTTP `http_token_provider` — the sender-side
//! integration point for OIDC (and any other rotating token source). A mock
//! `/write` server captures the `Authorization` header so the tests can assert
//! the provider's token reaches the wire and is re-pulled per flush. The device
//! flow itself is unit-tested in-crate against a mock identity provider.

#![cfg(feature = "sync-sender-http")]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use questdb::ingress::{Protocol, ProtocolVersion, SenderBuilder, TimestampNanos};

/// A captured request: `(path, authorization_header)`.
type Captured = (String, Option<String>);

struct MockServer {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<Captured>>>,
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
        let requests = Arc::new(Mutex::new(Vec::new()));
        let handler = Arc::new(handler);
        let handle = {
            let shutdown = Arc::clone(&shutdown);
            let requests = Arc::clone(&requests);
            std::thread::spawn(move || {
                while !shutdown.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((stream, _)) => handle_conn(stream, &*handler, &requests),
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
            requests,
            shutdown,
            handle: Some(handle),
        }
    }

    fn host(&self) -> String {
        self.addr.ip().to_string()
    }

    fn port(&self) -> u16 {
        self.addr.port()
    }

    #[cfg_attr(not(feature = "oidc"), allow(dead_code))]
    fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }

    /// The `Authorization` headers seen on `/write` requests, in order.
    fn write_auth_headers(&self) -> Vec<Option<String>> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|(path, _)| path == "/write")
            .map(|(_, auth)| auth.clone())
            .collect()
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

fn handle_conn<H>(mut stream: TcpStream, handler: &H, requests: &Mutex<Vec<Captured>>)
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
    let auth = header_value(&head, "authorization");
    let content_length = header_value(&head, "content-length")
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = buf[headers_end..].to_vec();
    while body.len() < content_length {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => body.extend_from_slice(&tmp[..n]),
            Err(_) => break,
        }
    }
    requests.lock().unwrap().push((path.clone(), auth));
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

fn header_value(head: &str, name: &str) -> Option<String> {
    head.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        if k.trim().eq_ignore_ascii_case(name) {
            Some(v.trim().to_string())
        } else {
            None
        }
    })
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Build an ILP/HTTP sender against the mock with an explicit protocol version
/// (skipping the build-time `/settings` probe).
fn sender_with_provider<F, E>(
    mock: &MockServer,
    provider: F,
) -> questdb::Result<questdb::ingress::Sender>
where
    F: Fn() -> std::result::Result<String, E> + Send + Sync + 'static,
    E: Into<questdb::Error>,
{
    SenderBuilder::new(Protocol::Http, mock.host(), mock.port())
        .protocol_version(ProtocolVersion::V1)?
        .http_token_provider(provider)?
        .build()
}

fn send_one_row(sender: &mut questdb::ingress::Sender) -> questdb::Result<()> {
    let mut buffer = sender.new_buffer();
    buffer
        .table("trades")?
        .symbol("symbol", "ETH-USD")?
        .column_f64("price", 2615.54)?
        .at(TimestampNanos::now())?;
    sender.flush(&mut buffer)
}

#[test]
fn provider_token_reaches_wire_and_rotates() {
    let mock = MockServer::start(|_method, path, _body| match path {
        "/write" => (204, String::new()),
        _ => (404, "{}".to_string()),
    });

    // A rotating provider: each call yields the next token.
    let counter = Arc::new(AtomicUsize::new(0));
    let mut sender = sender_with_provider(&mock, {
        let counter = Arc::clone(&counter);
        move || Ok::<_, questdb::Error>(format!("token-{}", counter.fetch_add(1, Ordering::SeqCst)))
    })
    .expect("build sender");

    send_one_row(&mut sender).expect("flush 1");
    send_one_row(&mut sender).expect("flush 2");

    let headers = mock.write_auth_headers();
    assert_eq!(headers.len(), 2, "expected two /write requests");
    assert_eq!(headers[0].as_deref(), Some("Bearer token-0"));
    // The provider is re-pulled per flush, so a rotated token is used.
    assert_eq!(headers[1].as_deref(), Some("Bearer token-1"));
}

#[test]
fn provider_error_fails_flush() {
    let mock = MockServer::start(|_m, path, _b| match path {
        "/write" => (204, String::new()),
        _ => (404, "{}".to_string()),
    });
    let mut sender = sender_with_provider(&mock, || {
        Err::<String, _>(questdb::Error::new(
            questdb::ErrorCode::AuthError,
            "token source unavailable",
        ))
    })
    .expect("build sender");

    let err = send_one_row(&mut sender).unwrap_err();
    assert_eq!(err.code(), questdb::ErrorCode::AuthError);
    // The provider failed before any request was sent.
    assert!(mock.write_auth_headers().is_empty());
}

#[test]
fn provider_control_char_token_rejected() {
    let mock = MockServer::start(|_m, path, _b| match path {
        "/write" => (204, String::new()),
        _ => (404, "{}".to_string()),
    });
    let mut sender = sender_with_provider(&mock, || {
        Ok::<_, questdb::Error>("bad\r\ninjected: header".to_string())
    })
    .expect("build sender");

    let err = send_one_row(&mut sender).unwrap_err();
    assert_eq!(err.code(), questdb::ErrorCode::AuthError);
    assert!(mock.write_auth_headers().is_empty());
}

#[test]
fn http_token_provider_conflicts_with_token() {
    // Setting a provider after a static token is rejected up front.
    let result = SenderBuilder::new(Protocol::Http, "127.0.0.1", 9000u16)
        .token("static-token")
        .unwrap()
        .http_token_provider(|| Ok::<_, questdb::Error>("provided".to_string()));
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), questdb::ErrorCode::ConfigError);

    // The reverse order (static token after a provider) is caught at build time.
    let build = SenderBuilder::new(Protocol::Http, "127.0.0.1", 9000u16)
        .http_token_provider(|| Ok::<_, questdb::Error>("provided".to_string()))
        .unwrap()
        .username("admin")
        .unwrap()
        .password("quest")
        .unwrap()
        .protocol_version(ProtocolVersion::V1)
        .unwrap()
        .build();
    assert!(build.is_err());
    assert_eq!(build.unwrap_err().code(), questdb::ErrorCode::ConfigError);
}

#[test]
fn http_token_provider_conflicts_with_partial_basic_auth() {
    // A provider plus a half-specified basic auth (username, no password) must
    // report the provider conflict precisely, not the generic "password missing".
    let build = SenderBuilder::new(Protocol::Http, "127.0.0.1", 9000u16)
        .http_token_provider(|| Ok::<_, questdb::Error>("provided".to_string()))
        .unwrap()
        .username("admin")
        .unwrap()
        .protocol_version(ProtocolVersion::V1)
        .unwrap()
        .build();
    let err = build.unwrap_err();
    assert_eq!(err.code(), questdb::ErrorCode::ConfigError);
    assert!(
        err.msg().contains("http_token_provider"),
        "expected the provider-conflict message, got: {}",
        err.msg()
    );
}

/// End-to-end: an interactive OIDC device-flow token is pulled by the sender and
/// sent as a Bearer header. Incurs one real ~5s poll wait (the poll interval is
/// floored at 5s and the external test can't inject the no-op sleep the in-crate
/// tests use), so it is gated on the `oidc` feature.
#[cfg(feature = "oidc")]
#[test]
fn oidc_token_flows_through_sender() {
    use questdb::oidc::OidcDeviceAuth;

    let mock = MockServer::start(|method, path, _body| match (method, path) {
        ("POST", "/device") => (
            200,
            serde_json::json!({
                "device_code": "DEV-1",
                "user_code": "ABCD-1234",
                "verification_uri": "https://idp.example.com/activate",
                "expires_in": 600,
                "interval": 5
            })
            .to_string(),
        ),
        // Succeeds on the first poll, so only one ~5s wait is incurred.
        ("POST", "/token") => (
            200,
            r#"{"access_token":"OIDC-ACCESS-TOKEN","expires_in":300}"#.to_string(),
        ),
        ("POST", "/write") => (204, String::new()),
        _ => (404, "{}".to_string()),
    });

    let auth = Arc::new(
        OidcDeviceAuth::builder()
            .client_id("questdb")
            .device_authorization_endpoint(mock.url("/device"))
            .token_endpoint(mock.url("/token"))
            .scope("openid")
            .interactive(true)
            .open_browser(false)
            .build()
            .expect("build auth"),
    );

    let mut sender = sender_with_provider(&mock, {
        let auth = Arc::clone(&auth);
        move || auth.token()
    })
    .expect("build sender");

    send_one_row(&mut sender).expect("flush");

    let headers = mock.write_auth_headers();
    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].as_deref(), Some("Bearer OIDC-ACCESS-TOKEN"));
}
