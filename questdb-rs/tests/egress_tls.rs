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

//! End-to-end TLS handshake coverage for the QWP egress reader.
//!
//! The unit tests in `egress::tls` cover the rustls config builder
//! (PEM loading, knob validation) but never finish a TLS handshake.
//! The mock here wraps a `TcpListener` in a `rustls::ServerConfig`
//! seeded from the checked-in self-signed certs and runs the WS
//! upgrade through `tungstenite::accept_hdr` over the live TLS
//! stream — exercising the full `wss://` connect path the way a
//! real broker would.

#![cfg(feature = "sync-reader-qwp-ws")]

use std::io::Read;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;

use questdb::ErrorCode;
use questdb::egress::{Reader, ServerRole};
use rustls::ServerConfig;
use rustls::server::ServerConnection;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tungstenite::handshake::server::{Request, Response};
use tungstenite::http::HeaderValue;
use tungstenite::{Message, accept_hdr};

// ---------------------------------------------------------------------------
// Wire helpers (subset of egress_failover.rs — duplicated here so this file
// stays standalone and we can grep "wss" or "TLS" without false positives
// from the much larger failover suite).
// ---------------------------------------------------------------------------

const MAGIC: [u8; 4] = *b"QWP1";
const MSG_QUERY_REQUEST: u8 = 0x10;
const MSG_RESULT_END: u8 = 0x12;
const MSG_SERVER_INFO: u8 = 0x18;

fn framed(version: u8, flags: u8, table_count: u16, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(12 + payload.len());
    buf.extend_from_slice(&MAGIC);
    buf.push(version);
    buf.push(flags);
    buf.extend_from_slice(&table_count.to_le_bytes());
    buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    buf.extend_from_slice(payload);
    buf
}

fn encode_varint_u64(mut v: u64, out: &mut Vec<u8>) {
    while v & !0x7F != 0 {
        out.push(((v & 0x7F) as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn server_info_frame(role: ServerRole, node_id: &str, cluster_id: &str) -> Vec<u8> {
    let role_byte = match role {
        ServerRole::Standalone => 0x00,
        ServerRole::Primary => 0x01,
        ServerRole::Replica => 0x02,
        ServerRole::PrimaryCatchup => 0x03,
        ServerRole::Other(b) => b,
        _ => 0xFF,
    };
    let mut payload = vec![MSG_SERVER_INFO, role_byte];
    payload.extend_from_slice(&0u64.to_le_bytes()); // epoch
    payload.extend_from_slice(&0u32.to_le_bytes()); // capabilities
    payload.extend_from_slice(&0i64.to_le_bytes()); // server_wall_ns
    payload.extend_from_slice(&(cluster_id.len() as u16).to_le_bytes());
    payload.extend_from_slice(cluster_id.as_bytes());
    payload.extend_from_slice(&(node_id.len() as u16).to_le_bytes());
    payload.extend_from_slice(node_id.as_bytes());
    framed(1, 0, 0, &payload)
}

fn result_end_frame(request_id: i64) -> Vec<u8> {
    let mut payload = Vec::with_capacity(16);
    payload.push(MSG_RESULT_END);
    payload.extend_from_slice(&request_id.to_le_bytes());
    encode_varint_u64(0, &mut payload);
    encode_varint_u64(0, &mut payload);
    framed(1, 0, 0, &payload)
}

// ---------------------------------------------------------------------------
// TLS config + mock server
// ---------------------------------------------------------------------------

fn certs_dir() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.push("tls_certs");
    p
}

fn root_ca_path() -> PathBuf {
    certs_dir().join("server_rootCA.pem")
}

/// Build the rustls server config once per process. The first
/// `ServerConfig::builder()` on a fresh process needs a default
/// `CryptoProvider` installed; we install one lazily here so this
/// file works whether or not other tests have already done so. The
/// `ring` provider is the lib's default-feature crypto provider,
/// matching what the client side will use during the handshake.
fn tls_server_config() -> Arc<ServerConfig> {
    static CFG: OnceLock<Arc<ServerConfig>> = OnceLock::new();
    CFG.get_or_init(|| {
        // Install the default provider, ignoring "already installed"
        // because another test or the client side may have got there
        // first. Ring is the lib's default crypto feature.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let dir = certs_dir();
        let cert_chain: Vec<CertificateDer<'static>> =
            CertificateDer::pem_file_iter(dir.join("server.crt"))
                .expect("open server.crt")
                .collect::<Result<_, _>>()
                .expect("parse server.crt");
        let key = PrivateKeyDer::from_pem_file(dir.join("server.key")).expect("load server.key");

        let cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .expect("build ServerConfig");
        Arc::new(cfg)
    })
    .clone()
}

/// In-process TLS+WS mock. Each accepted connection (a) finishes the
/// rustls handshake, (b) runs through `tungstenite::accept_hdr` to
/// produce a WS, (c) sends SERVER_INFO + replies to one
/// QUERY_REQUEST with RESULT_END. Mirrors `happy_script` from the
/// failover suite but with a TLS-wrapped stream all the way down.
struct TlsMockServer {
    addr: SocketAddr,
    accept_count: Arc<AtomicUsize>,
    shutdown: Arc<Mutex<bool>>,
    listener_handle: Option<thread::JoinHandle<()>>,
    workers: Arc<Mutex<Vec<thread::JoinHandle<()>>>>,
}

impl TlsMockServer {
    fn start() -> Self {
        // Bind via the same hostname the client will resolve. On
        // macOS `localhost` returns both `::1` and `127.0.0.1`, and
        // the egress client only attempts the first address — so
        // binding only on `127.0.0.1` while the client tries `::1`
        // first races into "Connection refused" on dual-stack hosts.
        // `TcpListener::bind("localhost:0")` walks the same address
        // list and lands on whichever loopback the client will pick.
        let listener = TcpListener::bind("localhost:0").expect("bind localhost:0");
        let addr = listener.local_addr().expect("local_addr");
        let cfg = tls_server_config();
        let accept_count = Arc::new(AtomicUsize::new(0));
        let accept_count_clone = Arc::clone(&accept_count);
        let shutdown = Arc::new(Mutex::new(false));
        let shutdown_clone = Arc::clone(&shutdown);
        let workers: Arc<Mutex<Vec<thread::JoinHandle<()>>>> = Arc::new(Mutex::new(Vec::new()));
        let workers_clone = Arc::clone(&workers);

        let handle = thread::spawn(move || {
            for stream in listener.incoming() {
                if *shutdown_clone.lock().unwrap() {
                    break;
                }
                let stream = match stream {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                accept_count_clone.fetch_add(1, Ordering::SeqCst);
                let cfg = Arc::clone(&cfg);
                let worker = thread::spawn(move || serve_one(stream, cfg));
                workers_clone.lock().unwrap().push(worker);
            }
        });

        TlsMockServer {
            addr,
            accept_count,
            shutdown,
            listener_handle: Some(handle),
            workers,
        }
    }

    /// Connect-string addr in `localhost:<port>` form. The TLS server
    /// listens on `127.0.0.1` but the test CA's leaf cert SAN is
    /// `DnsName("localhost")` only — using the IP literal in the URL
    /// fails certificate hostname validation before we even get to
    /// the WS handshake. Resolve to the loopback hostname so rustls
    /// validates against the SAN it actually has.
    fn url(&self) -> String {
        format!("localhost:{}", self.addr.port())
    }

    fn accepts(&self) -> usize {
        self.accept_count.load(Ordering::SeqCst)
    }
}

impl Drop for TlsMockServer {
    fn drop(&mut self) {
        *self.shutdown.lock().unwrap() = true;
        // Tickle the listener so accept() returns and the loop exits.
        let _ = TcpStream::connect(self.addr);
        if let Some(h) = self.listener_handle.take() {
            let _ = h.join();
        }
        let workers = std::mem::take(&mut *self.workers.lock().unwrap());
        for w in workers {
            let _ = w.join();
        }
    }
}

#[allow(clippy::result_large_err)]
fn serve_one(tcp: TcpStream, cfg: Arc<ServerConfig>) {
    // Drive the TLS handshake to completion before handing the stream
    // to tungstenite. `rustls::StreamOwned` is `Read + Write`, so the
    // WS upgrade negotiates over the encrypted channel transparently.
    let conn = match ServerConnection::new(cfg) {
        Ok(c) => c,
        Err(_) => return,
    };
    let stream = rustls::StreamOwned::new(conn, tcp);

    let mut ws = match accept_hdr(stream, |_req: &Request, mut resp: Response| {
        let header = HeaderValue::from_static("1");
        resp.headers_mut().insert("x-qwp-version", header);
        Ok(resp)
    }) {
        Ok(ws) => ws,
        Err(_) => return,
    };

    // SERVER_INFO -> AwaitQueryRequest -> RESULT_END.
    let info = server_info_frame(ServerRole::Standalone, "tls-mock", "tls-cluster");
    if ws.send(Message::Binary(info.into())).is_err() {
        return;
    }

    // Read until QUERY_REQUEST (msg_kind 0x10) and grab the request_id.
    let request_id = loop {
        match ws.read() {
            Ok(Message::Binary(b)) if !b.is_empty() && b[0] == MSG_QUERY_REQUEST => {
                if b.len() < 9 {
                    return;
                }
                let mut id = [0u8; 8];
                id.copy_from_slice(&b[1..9]);
                break i64::from_le_bytes(id);
            }
            Ok(_) => continue,
            Err(_) => return,
        }
    };

    let end = result_end_frame(request_id);
    let _ = ws.send(Message::Binary(end.into()));
    // Best-effort clean shutdown; ignore errors during close.
    let _ = ws.close(None);
    let _ = ws.flush();
    while ws.read().is_ok() {}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Happy path: a `wss://` client trusting the test self-signed CA
/// connects, runs a query end-to-end through the encrypted channel,
/// and sees the cursor reach `RESULT_END`. Pins the full TLS path —
/// rustls handshake + tungstenite WS upgrade + QWP frame exchange.
#[test]
fn qwps_handshake_succeeds_with_pem_root() {
    let srv = TlsMockServer::start();
    let conf = format!(
        "wss::addr={};tls_ca=pem_file;tls_roots={};failover=off",
        srv.url(),
        root_ca_path().display()
    );
    let mut reader = Reader::from_conf(&conf).expect("TLS connect");
    {
        let mut cursor = reader
            .prepare("select 1")
            .execute()
            .expect("execute over TLS");
        let batch = cursor.next_batch().expect("next_batch over TLS");
        assert!(batch.is_none(), "RESULT_END terminal returns no batch view");
        // After RESULT_END the cursor must be in a terminal state.
        assert!(cursor.terminal().is_some());
    }
    drop(reader);
    assert_eq!(srv.accepts(), 1, "exactly one TLS connection accepted");
}

/// Negative path: same server, client uses the default `tls_ca`
/// (webpki roots), which does NOT contain the test self-signed CA.
/// The rustls handshake must fail and surface as `TlsError` — not as
/// `SocketError` or `HandshakeError` (which would mean the
/// `T::Tls(_)` arm in `transport::map_ws_error` was bypassed).
#[test]
fn qwps_handshake_fails_against_unknown_ca_with_tls_error() {
    let srv = TlsMockServer::start();
    // Default tls_ca=webpki_roots; no `tls_roots` override. The
    // self-signed CA isn't in webpki's bundle so verification must
    // fail before the WS upgrade is even attempted.
    let conf = format!("wss::addr={};failover=off", srv.url());
    let err = match Reader::from_conf(&conf) {
        Err(e) => e,
        Ok(_) => panic!("connect must fail when the server cert chain doesn't validate"),
    };
    assert_eq!(
        err.code(),
        ErrorCode::TlsError,
        "untrusted self-signed cert must surface as TlsError; got {:?}: {}",
        err.code(),
        err.msg()
    );
}

/// Negative path: a `ws://` (plain TCP) client against a TLS server.
/// The server reads the client's HTTP upgrade bytes as TLS records,
/// fails the handshake, and tears the connection down. The client
/// sees a closed connection mid-handshake — we don't pin the exact
/// code (tungstenite has surfaced this as `SocketError` /
/// `ProtocolError` / `HandshakeError` across versions depending on
/// where the read fails) but it must be one of those three, never
/// `Ok`.
#[test]
fn qwp_plain_client_against_tls_server_fails() {
    let srv = TlsMockServer::start();
    let conf = format!("ws::addr={};failover=off", srv.url());
    // Bound how long we tolerate the doomed handshake — a stuck
    // mock would otherwise hang the test indefinitely. Any of the
    // listed error codes is an acceptable failure mode.
    let started = std::time::Instant::now();
    let err = match Reader::from_conf(&conf) {
        Err(e) => e,
        Ok(_) => panic!("a plain client must not succeed against a TLS server"),
    };
    assert!(
        started.elapsed() < std::time::Duration::from_secs(30),
        "handshake should fail promptly, took {:?}",
        started.elapsed()
    );
    assert!(
        matches!(
            err.code(),
            ErrorCode::SocketError | ErrorCode::ProtocolError | ErrorCode::HandshakeError
        ),
        "plain-vs-TLS mismatch must surface as a transport/handshake error; got {:?}: {}",
        err.code(),
        err.msg()
    );
}

/// `tls_ca=os_roots`: same self-signed mock server, but the client
/// trusts only the OS-native root store. The test CA isn't there, so
/// the handshake must reach the TLS layer (not error out at parse) and
/// fail with `TlsError`. Pins that `tls_ca=os_roots` actually wires
/// `rustls_native_certs::load_native_certs` into the rustls config — a
/// regression that silently fell back to webpki roots would still fail
/// with `TlsError` here (so this test alone doesn't fully disambiguate
/// os_roots vs webpki_roots), but a regression that bypassed cert
/// validation entirely would surface as `Ok(_)` and the test would
/// catch it.
#[cfg(feature = "tls-native-certs")]
#[test]
fn qwps_handshake_fails_against_unknown_ca_with_os_roots() {
    let srv = TlsMockServer::start();
    let conf = format!("wss::addr={};tls_ca=os_roots;failover=off", srv.url());
    let err = match Reader::from_conf(&conf) {
        Err(e) => e,
        Ok(_) => panic!(
            "tls_ca=os_roots must reject the self-signed test cert \
             (cert is not in any OS root store)"
        ),
    };
    assert_eq!(
        err.code(),
        ErrorCode::TlsError,
        "untrusted self-signed cert under tls_ca=os_roots must surface as \
         TlsError; got {:?}: {}",
        err.code(),
        err.msg()
    );
}

/// `tls_ca=webpki_and_os_roots`: union of both default stores. The
/// test CA is in neither, so the handshake must fail with `TlsError`.
/// Pins that combined-roots mode reaches the TLS verifier rather than
/// being misconfigured as a no-op (which would `Ok(_)`).
#[cfg(all(feature = "tls-webpki-certs", feature = "tls-native-certs"))]
#[test]
fn qwps_handshake_fails_against_unknown_ca_with_webpki_and_os_roots() {
    let srv = TlsMockServer::start();
    let conf = format!(
        "wss::addr={};tls_ca=webpki_and_os_roots;failover=off",
        srv.url()
    );
    let err = match Reader::from_conf(&conf) {
        Err(e) => e,
        Ok(_) => panic!(
            "tls_ca=webpki_and_os_roots must reject the self-signed test cert \
             (cert is in neither store)"
        ),
    };
    assert_eq!(
        err.code(),
        ErrorCode::TlsError,
        "untrusted self-signed cert under tls_ca=webpki_and_os_roots must \
         surface as TlsError; got {:?}: {}",
        err.code(),
        err.msg()
    );
}

/// `tls_verify=unsafe_off`: cert verification disabled entirely. Same
/// untrusted self-signed cert that fails under every other `tls_ca`
/// mode must now connect cleanly. This is the targeted regression
/// guard the wider TLS suite needed: if a refactor accidentally wires
/// the WebPKI verifier (or any real verifier) in place of
/// `NoCertificateVerification` on `unsafe_off`, the handshake
/// would fail with `TlsError` and this test would catch it. Run
/// end-to-end (connect + execute + RESULT_END) so we exercise the
/// post-handshake path too.
#[cfg(feature = "insecure-skip-verify")]
#[test]
fn qwps_unsafe_off_skips_verification_against_untrusted_cert() {
    let srv = TlsMockServer::start();
    let conf = format!("wss::addr={};tls_verify=unsafe_off;failover=off", srv.url());
    let mut reader = Reader::from_conf(&conf).expect(
        "tls_verify=unsafe_off must accept any cert; if this errored, the \
         NoCertificateVerification verifier was not wired in",
    );
    {
        let mut cursor = reader
            .prepare("select 1")
            .execute()
            .expect("execute over unsafe_off TLS");
        let batch = cursor.next_batch().expect("next_batch over unsafe_off TLS");
        assert!(batch.is_none(), "RESULT_END terminal returns no batch view");
        assert!(cursor.terminal().is_some());
    }
    drop(reader);
    assert_eq!(
        srv.accepts(),
        1,
        "exactly one TLS connection accepted under unsafe_off"
    );
}

/// Cert/key fixtures must exist before any test runs — fail loudly
/// here rather than producing a confusing `ConfigError` from
/// `tls_roots=<missing path>` later.
#[test]
fn tls_certs_fixture_present() {
    let dir = certs_dir();
    for name in ["server.crt", "server.key", "server_rootCA.pem"] {
        let p = dir.join(name);
        assert!(
            p.exists(),
            "missing TLS test fixture {:?}; run from a checkout that includes tls_certs/",
            p
        );
        let mut buf = Vec::new();
        std::fs::File::open(&p)
            .and_then(|mut f| f.read_to_end(&mut buf))
            .unwrap_or_else(|e| panic!("read {:?}: {}", p, e));
        assert!(!buf.is_empty(), "{:?} is empty", p);
    }
}
