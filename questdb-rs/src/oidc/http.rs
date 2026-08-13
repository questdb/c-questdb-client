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

//! A small HTTPS helper for the OIDC device flow and discovery.
//!
//! Reuses the crate's rustls configuration ([`configure_tls`]) but builds its
//! own [`ureq::Agent`] (the ILP/HTTP sender's agent is ILP-specific), refusing
//! redirects, bounding the response body, and holding every IdP call to `https`
//! (or loopback `http`).

use std::fmt::Debug;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rustls::{ClientConfig, ClientConnection, StreamOwned};
use rustls_pki_types::ServerName;
use rustls_pki_types::pem::PemObject;
use ureq::http::Uri;
use ureq::unversioned::resolver::DefaultResolver;
use ureq::unversioned::transport::{
    Buffers, Connector, Either, LazyBuffers, NextTimeout, TcpConnector, Transport, TransportAdapter,
};

use crate::ingress::tls::{TlsSettings, configure_tls};
use crate::oidc::error::{OidcError, Result};

const USER_AGENT: &str = concat!("questdb/rust/", env!("CARGO_PKG_VERSION"), " (oidc)");

/// Cap on a response body: OIDC / discovery JSON is a few KiB, so 4 MiB is ample
/// headroom while refusing to buffer an unbounded body from a hostile / stalled
/// server.
const MAX_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;

/// Cap on how much of an HTTP *error* body (status >= 400) is echoed into a
/// diagnostic message. Enough to show a proxy/WAF error title or an OAuth
/// `error_description`, but short so little can spill into a log. A 2xx/3xx body —
/// which on the token / device-authorization endpoints can carry a credential — is
/// never snippeted (see [`non_json_body_detail`]), so a non-conformant or truncated
/// token response cannot leak the secret through this path.
const MAX_BODY_SNIPPET_CHARS: usize = 120;

/// The result of a `POST` to the IdP token / device-authorization endpoint:
/// the HTTP status, the parsed JSON body, and any `Retry-After` (delta-seconds).
pub(crate) struct PostResult {
    pub(crate) status: u16,
    pub(crate) body: serde_json::Value,
    pub(crate) retry_after: Option<u64>,
}

/// HTTP statuses that indicate a retryable timeout, rate limit, or server-side
/// failure rather than rejected credentials or invalid configuration.
pub(crate) fn is_transient_http_status(status: u16) -> bool {
    status == 408 || status == 429 || status >= 500
}

/// A reusable HTTPS client for the OIDC flow.
pub(crate) struct HttpClient {
    agent: ureq::Agent,
}

impl HttpClient {
    /// Build a client verifying TLS against the default roots, or against
    /// `ca_bundle` (a PEM file) when given. `timeout` bounds each whole request
    /// (connect + send + receive), so a stalled IdP can't pin the caller.
    pub(crate) fn new(ca_bundle: Option<&Path>, timeout: Duration) -> Result<Self> {
        let tls_config = configure_tls(default_tls_settings(ca_bundle)?)
            .map_err(|e| OidcError::config(format!("Could not configure TLS for OIDC: {e}")))?;
        let connector = TcpConnector::default().chain(TlsConnector::new(tls_config));
        let config = ureq::Agent::config_builder()
            .user_agent(USER_AGENT)
            .no_delay(true)
            // We inspect the status ourselves (a 4xx token-endpoint reply carries
            // `authorization_pending` / `slow_down`), so don't turn it into an error.
            .http_status_as_error(false)
            // These endpoints never legitimately redirect. Auto-following is
            // unsafe: only the original URL is vetted, and a 30x could re-send a
            // credential to another host, even downgrading to plaintext. Return
            // the 30x as-is so the caller fails it fast.
            .max_redirects(0)
            .max_redirects_will_error(false)
            .timeout_global(Some(timeout))
            .timeout_connect(Some(timeout))
            .build();
        let agent = ureq::Agent::with_parts(config, connector, DefaultResolver::default());
        Ok(HttpClient { agent })
    }

    /// GET a URL and parse a JSON response, erroring on a non-2xx status.
    pub(crate) fn get_json(&self, url: &str, allow_insecure: bool) -> Result<serde_json::Value> {
        require_secure(url, allow_insecure)?;
        let response = self
            .agent
            .get(url)
            .header("Accept", "application/json")
            .call()
            .map_err(|e| OidcError::network(format!("Failed to reach {url}: {e}")))?;
        let status = response.status().as_u16();
        let retry_after = parse_retry_after(response.headers());
        let body = read_body(url, response)?;
        if !(200..300).contains(&status) {
            let snippet = body_snippet(&body);
            let msg = format!("HTTP {status} from {url}: {snippet}");
            // A 408 / 429 / 5xx is a transient timeout, rate-limit, or server
            // issue; anything else (a wrong URL, OIDC not advertised, an auth
            // gate) is a configuration problem.
            return Err(if is_transient_http_status(status) {
                OidcError::network(msg).with_status(Some(status))
            } else {
                OidcError::config(msg).with_status(Some(status))
            }
            .with_retry_after(retry_after));
        }
        serde_json::from_slice(&body).map_err(|e| {
            OidcError::config(format!("Invalid JSON from {url}: {e}")).with_status(Some(status))
        })
    }

    /// POST a form-urlencoded body and parse the JSON response.
    ///
    /// The HTTP status is returned rather than raised (a 4xx token reply carries
    /// the OAuth error body), unless the body is not JSON — then it is an error
    /// carrying the status so the caller can classify terminal-vs-transient.
    pub(crate) fn post_form(
        &self,
        url: &str,
        form: &[(&str, &str)],
        allow_insecure: bool,
    ) -> Result<PostResult> {
        require_secure(url, allow_insecure)?;
        let response = self
            .agent
            .post(url)
            .header("Accept", "application/json")
            .send_form(form.iter().copied())
            .map_err(|e| {
                // Record whether the request provably never left the client, so a
                // refresh caller can safely keep a refresh token that the IdP
                // cannot have seen (vs. an ambiguous mid-flight drop, where the
                // parent may have been consumed and rotated).
                let unsent = request_provably_unsent(&e);
                OidcError::network(format!("Failed to reach {url}: {e}"))
                    .with_request_unsent(unsent)
            })?;
        let status = response.status().as_u16();
        let retry_after = parse_retry_after(response.headers());
        let body = read_body(url, response)?;
        match serde_json::from_slice::<serde_json::Value>(&body) {
            Ok(value) => Ok(PostResult {
                status,
                body: value,
                retry_after,
            }),
            Err(_) => {
                // A 2xx/3xx body from these endpoints can carry the OAuth secrets
                // (access/refresh token, device_code); a non-conformant or truncated
                // token response lands here, so its bytes must never be echoed into
                // this (displayable/loggable) error. Only an HTTP error body
                // (>= 400) — an intermediary/IdP error page that cannot carry an
                // issued token — is snippeted for diagnostics.
                let detail = non_json_body_detail(status, &body);
                let msg = format!("HTTP {status} from {url}: {detail}");
                // A transient 408/429/5xx (a timeout or proxy/WAF error page) stays
                // retryable; anything else is a terminal rejection. Either way carry
                // the status + Retry-After so the poll loop / refresh can classify
                // and back off correctly.
                let err = if is_transient_http_status(status) {
                    OidcError::network(msg)
                } else {
                    OidcError::device_flow(msg)
                };
                Err(err.with_status(Some(status)).with_retry_after(retry_after))
            }
        }
    }
}

/// True when a `ureq` send failure proves the HTTP request was never
/// transmitted, so a refresh token carried in it was not consumed by the IdP and
/// is safe to reuse. Only unambiguous pre-send failures qualify — DNS
/// resolution, TCP connect, TLS handshake, or proxy-tunnel setup — plus a
/// resolve/connect-phase timeout. Every other failure (an I/O error at an
/// unknown or post-connect phase, a send/receive-phase or global timeout, a
/// protocol or decode error) may have reached the IdP and is treated as
/// ambiguous.
///
/// `ureq` maps most connect failures to [`ureq::Error::Io`] and carries the
/// [`io::ErrorKind`](std::io::ErrorKind) as the reason (`ConnectionFailed` is a
/// last resort), so the `Io` arm inspects the kind: only kinds that mean "no
/// connection was ever established" qualify — a reset / broken pipe / EOF may
/// have occurred after the request bytes were written. `ureq::Error` and
/// `ureq::Timeout` are `#[non_exhaustive]`, so any future variant falls through
/// to the fail-safe `false` (treat as possibly-sent).
fn request_provably_unsent(err: &ureq::Error) -> bool {
    use std::io::ErrorKind;
    use ureq::Error;
    match err {
        Error::HostNotFound
        | Error::ConnectionFailed
        | Error::ConnectProxyFailed(_)
        | Error::TlsRequired
        | Error::Tls(_) => true,
        Error::Io(e) => matches!(
            e.kind(),
            ErrorKind::ConnectionRefused
                | ErrorKind::NetworkUnreachable
                | ErrorKind::HostUnreachable
                | ErrorKind::AddrNotAvailable
        ),
        Error::Timeout(reason) => {
            matches!(reason, ureq::Timeout::Resolve | ureq::Timeout::Connect)
        }
        _ => false,
    }
}

/// Read a response body, bounded by [`MAX_RESPONSE_BYTES`].
fn read_body(url: &str, response: ureq::http::Response<ureq::Body>) -> Result<Vec<u8>> {
    response
        .into_body()
        .into_with_config()
        .limit(MAX_RESPONSE_BYTES)
        .read_to_vec()
        .map_err(|e| OidcError::network(format!("Failed to read response body from {url}: {e}")))
}

/// A short, printable snippet of a (possibly binary / error-page) body for a
/// diagnostic message.
fn body_snippet(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    let snippet: String = text.chars().take(MAX_BODY_SNIPPET_CHARS).collect();
    crate::oidc::render::strip_control(&snippet)
}

/// Diagnostic detail for a token / device-authorization response whose body did
/// not parse as JSON. These endpoints return the OAuth secrets (access/refresh
/// token, device_code) in a *successful* (2xx) body, so a 2xx/3xx body is never
/// echoed: a non-conformant or truncated token response would otherwise leak the
/// credential into this displayable/loggable error. Only a genuine HTTP error
/// response (status >= 400), which cannot carry an issued token, is snippeted.
fn non_json_body_detail(status: u16, body: &[u8]) -> String {
    if status >= 400 {
        body_snippet(body)
    } else {
        "unexpected non-JSON response body".to_string()
    }
}

/// Parse a `Retry-After` header as a non-negative number of seconds.
///
/// Honors only the delta-seconds form (RFC 7231 §7.1.3) — a bare run of ASCII
/// digits, at most 9 (>31 years is meaningless). The HTTP-date form is ignored;
/// the caller's fixed back-off covers that rarer case.
fn parse_retry_after(headers: &ureq::http::HeaderMap) -> Option<u64> {
    let value = headers.get("retry-after")?.to_str().ok()?.trim();
    if value.is_empty() || value.len() > 9 || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

/// True if `host` is a loopback address — plaintext `http` is safe there because
/// the request never leaves the machine.
fn is_loopback(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    // Strip the brackets off an IPv6 literal before parsing.
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    match bare.parse::<IpAddr>() {
        Ok(addr) => addr.is_loopback(),
        Err(_) => false,
    }
}

/// Refuse to send a request over a channel that isn't `https` (or loopback
/// `http`, or — when `allow_insecure` — any `http`).
fn require_secure(url: &str, allow_insecure: bool) -> Result<()> {
    let uri: Uri = url
        .parse()
        .map_err(|e| OidcError::config(format!("Malformed endpoint URL {url:?}: {e}")))?;
    let scheme = uri.scheme_str().unwrap_or("").to_ascii_lowercase();
    if scheme == "https" {
        // A hostless https URL (e.g. `https:///path`) would pass this gate and
        // then reach the TLS connector, which needs a URI authority. Reject it
        // here with a clear config error. Endpoints are already origin-checked
        // at build time, so this is defense in depth.
        if uri.host().unwrap_or("").is_empty() {
            return Err(OidcError::config(format!(
                "Malformed endpoint URL {url:?}: an https URL must have a host."
            )));
        }
        return Ok(());
    }
    if scheme == "http" {
        let host = uri.host().unwrap_or("");
        if is_loopback(host) || allow_insecure {
            return Ok(());
        }
    }
    Err(OidcError::config(format!(
        "Refusing to use insecure URL {url:?} (scheme {scheme:?}). Use https \
         (loopback http is always allowed for local development); enable \
         allow_insecure_transport only to permit plaintext to a non-loopback \
         QuestDB server. The identity provider is always held to https."
    )))
}

/// Pick the rustls trust anchors: an explicit PEM `ca_bundle`, else the crate's
/// compiled-in default roots.
fn default_tls_settings(ca_bundle: Option<&Path>) -> Result<TlsSettings> {
    if let Some(path) = ca_bundle {
        let file = std::fs::File::open(path).map_err(|e| {
            OidcError::config(format!(
                "Could not open the CA bundle {path:?}: {e}. Point ca_bundle at a \
                 readable PEM certificate file."
            ))
        })?;
        let certs = rustls_pki_types::CertificateDer::pem_reader_iter(file)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| {
                OidcError::config(format!("Could not read the CA bundle {path:?}: {e}."))
            })?;
        if certs.is_empty() {
            return Err(OidcError::config(format!(
                "The CA bundle {path:?} contained no certificates."
            )));
        }
        return Ok(TlsSettings::PemFile(certs));
    }

    #[cfg(all(feature = "tls-webpki-certs", feature = "tls-native-certs"))]
    let settings = TlsSettings::WebpkiAndOsRoots;
    #[cfg(all(feature = "tls-webpki-certs", not(feature = "tls-native-certs")))]
    let settings = TlsSettings::WebpkiRoots;
    #[cfg(all(feature = "tls-native-certs", not(feature = "tls-webpki-certs")))]
    let settings = TlsSettings::OsRoots;
    #[cfg(not(any(feature = "tls-webpki-certs", feature = "tls-native-certs")))]
    return Err(OidcError::config(
        "OIDC needs a TLS root source; enable the \"tls-webpki-certs\" or \
         \"tls-native-certs\" feature (both are in the default set), or pass an \
         explicit CA bundle.",
    ));
    #[cfg(any(feature = "tls-webpki-certs", feature = "tls-native-certs"))]
    Ok(settings)
}

// ---------------------------------------------------------------------------
// ureq rustls transport glue.
//
// ureq is compiled without built-in TLS (`default-features = false`), so HTTPS
// needs a custom connector. This mirrors the ILP/HTTP sender's connector
// (`ingress::sender::http`); it is kept separate because the OIDC client builds
// its own IdP-specific `ureq::Agent` (no redirects, its own timeouts, bounded
// body) rather than sharing the sender's ILP-specific one. Pure transport
// plumbing — no security decisions live here (root selection is in
// `configure_tls`, scheme enforcement in `require_secure`).
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct TlsConnector {
    tls_config: Arc<ClientConfig>,
}

impl TlsConnector {
    fn new(tls_config: Arc<ClientConfig>) -> Self {
        TlsConnector { tls_config }
    }
}

impl<In: Transport> Connector<In> for TlsConnector {
    type Out = Either<In, TlsTransport>;

    fn connect(
        &self,
        details: &ureq::unversioned::transport::ConnectionDetails,
        chained: Option<In>,
    ) -> std::result::Result<Option<Self::Out>, ureq::Error> {
        let transport = match chained {
            Some(t) => t,
            None => return Ok(None),
        };

        if !details.needs_tls() {
            return Ok(Some(Either::A(transport)));
        }

        // Never `.expect()` here: this crate is built into a `panic = "abort"`
        // FFI, so a panic on a missing authority would abort the host process.
        // A URI without an authority is already rejected upstream
        // (`require_secure` + `reject_confusable_authority`); return a TLS error
        // as a local safety net rather than relying on that.
        let name_borrowed: ServerName<'_> = details
            .uri
            .authority()
            .ok_or(ureq::Error::Tls("tls uri has no authority"))?
            .host()
            .try_into()
            .map_err(|_e| ureq::Error::Tls("tls invalid dns name error"))?;
        let name = name_borrowed.to_owned();
        let conn = ClientConnection::new(self.tls_config.clone(), name)
            .map_err(|_e| ureq::Error::Tls("tls client connection error"))?;
        let stream = StreamOwned {
            conn,
            sock: TransportAdapter::new(transport.boxed()),
        };
        let buffers = LazyBuffers::new(
            details.config.input_buffer_size(),
            details.config.output_buffer_size(),
        );
        Ok(Some(Either::B(TlsTransport { buffers, stream })))
    }
}

struct TlsTransport {
    buffers: LazyBuffers,
    stream: StreamOwned<ClientConnection, TransportAdapter>,
}

impl Debug for TlsTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsTransport").finish()
    }
}

impl Transport for TlsTransport {
    fn buffers(&mut self) -> &mut dyn Buffers {
        &mut self.buffers
    }

    fn transmit_output(
        &mut self,
        amount: usize,
        timeout: NextTimeout,
    ) -> std::result::Result<(), ureq::Error> {
        self.stream.get_mut().set_timeout(timeout);
        let output = &self.buffers.output()[..amount];
        self.stream.write_all(output)?;
        Ok(())
    }

    fn await_input(&mut self, timeout: NextTimeout) -> std::result::Result<bool, ureq::Error> {
        if self.buffers.can_use_input() {
            return Ok(true);
        }
        self.stream.get_mut().set_timeout(timeout);
        let input = self.buffers.input_append_buf();
        let amount = self.stream.read(input)?;
        self.buffers.input_appended(amount);
        Ok(amount > 0)
    }

    fn is_open(&mut self) -> bool {
        self.stream.get_mut().get_mut().is_open()
    }

    fn is_tls(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Mutex, OnceLock};
    use std::thread::{self, JoinHandle};

    use rustls::server::ServerConnection;
    use rustls::{ServerConfig, StreamOwned};
    use rustls_pki_types::{CertificateDer, PrivateKeyDer};

    fn tls_certs_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tls_certs")
    }

    fn root_ca_path() -> PathBuf {
        tls_certs_dir().join("server_rootCA.pem")
    }

    fn tls_server_config() -> Arc<ServerConfig> {
        static CONFIG: OnceLock<Arc<ServerConfig>> = OnceLock::new();
        CONFIG
            .get_or_init(|| {
                let cert_chain: Vec<CertificateDer<'static>> =
                    CertificateDer::pem_file_iter(tls_certs_dir().join("server.crt"))
                        .expect("open OIDC TLS test certificate")
                        .collect::<std::result::Result<_, _>>()
                        .expect("parse OIDC TLS test certificate");
                let key = PrivateKeyDer::from_pem_file(tls_certs_dir().join("server.key"))
                    .expect("load OIDC TLS test private key");
                Arc::new(
                    ServerConfig::builder()
                        .with_no_client_auth()
                        .with_single_cert(cert_chain, key)
                        .expect("build OIDC TLS test server config"),
                )
            })
            .clone()
    }

    /// A one-request HTTPS endpoint using the repository's localhost test
    /// certificate. It is intentionally separate from the plaintext device-flow
    /// mock: these tests must execute the production OIDC TLS connector.
    struct TlsJsonServer {
        addr: SocketAddr,
        url_host: &'static str,
        requests: Arc<Mutex<Vec<String>>>,
        accepts: Arc<AtomicUsize>,
        shutdown: Arc<AtomicBool>,
        handle: Option<JoinHandle<()>>,
    }

    impl TlsJsonServer {
        fn start(bind: &str, url_host: &'static str) -> Self {
            let listener = TcpListener::bind(bind).expect("bind OIDC TLS test server");
            let addr = listener.local_addr().expect("OIDC TLS test server address");
            listener
                .set_nonblocking(true)
                .expect("set OIDC TLS listener nonblocking");
            let requests = Arc::new(Mutex::new(Vec::new()));
            let accepts = Arc::new(AtomicUsize::new(0));
            let shutdown = Arc::new(AtomicBool::new(false));
            let handle = {
                let requests = Arc::clone(&requests);
                let accepts = Arc::clone(&accepts);
                let shutdown = Arc::clone(&shutdown);
                thread::spawn(move || {
                    while !shutdown.load(Ordering::Relaxed) {
                        match listener.accept() {
                            Ok((stream, _)) => {
                                accepts.fetch_add(1, Ordering::SeqCst);
                                serve_tls_json(stream, tls_server_config(), &requests);
                                break;
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                thread::sleep(Duration::from_millis(1));
                            }
                            Err(_) => break,
                        }
                    }
                })
            };
            TlsJsonServer {
                addr,
                url_host,
                requests,
                accepts,
                shutdown,
                handle: Some(handle),
            }
        }

        fn localhost() -> Self {
            // Bind via the same hostname the client resolves so dual-stack hosts
            // do not connect to ::1 while the fixture listens on 127.0.0.1.
            Self::start("localhost:0", "localhost")
        }

        fn hostname_mismatch() -> Self {
            // The leaf certificate contains only DNS:localhost, never this IP.
            Self::start("127.0.0.1:0", "127.0.0.1")
        }

        fn url(&self, path: &str) -> String {
            format!("https://{}:{}{path}", self.url_host, self.addr.port())
        }

        fn request_bodies(&self) -> Vec<String> {
            self.requests.lock().unwrap().clone()
        }

        fn accepts(&self) -> usize {
            self.accepts.load(Ordering::SeqCst)
        }
    }

    impl Drop for TlsJsonServer {
        fn drop(&mut self) {
            self.shutdown.store(true, Ordering::Relaxed);
            // Wake a listener that has not accepted the test request because the
            // client failed before dialing.
            let _ = TcpStream::connect(self.addr);
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    fn serve_tls_json(tcp: TcpStream, config: Arc<ServerConfig>, requests: &Mutex<Vec<String>>) {
        tcp.set_nonblocking(false).ok();
        tcp.set_read_timeout(Some(Duration::from_secs(5))).ok();
        tcp.set_write_timeout(Some(Duration::from_secs(5))).ok();
        let Ok(conn) = ServerConnection::new(config) else {
            return;
        };
        let mut stream = StreamOwned::new(conn, tcp);
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 4096];
        let headers_end = loop {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    bytes.extend_from_slice(&chunk[..n]);
                    if let Some(pos) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        break pos + 4;
                    }
                    if bytes.len() > 64 * 1024 {
                        return;
                    }
                }
            }
        };
        let headers = String::from_utf8_lossy(&bytes[..headers_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.eq_ignore_ascii_case("content-length") {
                    value.trim().parse::<usize>().ok()
                } else {
                    None
                }
            })
            .unwrap_or(0);
        while bytes.len() - headers_end < content_length {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(n) => bytes.extend_from_slice(&chunk[..n]),
            }
        }
        requests.lock().unwrap().push(
            String::from_utf8_lossy(&bytes[headers_end..headers_end + content_length]).into_owned(),
        );

        let body = r#"{"access_token":"AT-tls","expires_in":300}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.flush();
    }

    fn assert_tls_network_error(err: OidcError) {
        assert_eq!(err.kind(), crate::oidc::error::OidcErrorKind::Network);
        let message = err.message().to_ascii_lowercase();
        assert!(
            message.contains("tls")
                || message.contains("certificate")
                || message.contains("issuer"),
            "expected a TLS verification failure, got: {}",
            err.message()
        );
    }

    #[test]
    fn https_post_form_succeeds_with_custom_ca() {
        let server = TlsJsonServer::localhost();
        let client = HttpClient::new(Some(&root_ca_path()), Duration::from_secs(5)).unwrap();
        let result = client
            .post_form(
                &server.url("/token"),
                &[("grant_type", "refresh_token"), ("client_id", "questdb")],
                false,
            )
            .unwrap();

        assert_eq!(result.status, 200);
        assert_eq!(
            result.body.get("access_token").and_then(|v| v.as_str()),
            Some("AT-tls")
        );
        assert_eq!(server.accepts(), 1);
        let requests = server.request_bodies();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].contains("grant_type=refresh_token"));
        assert!(requests[0].contains("client_id=questdb"));
    }

    #[test]
    fn https_rejects_unknown_ca() {
        let server = TlsJsonServer::localhost();
        let client = HttpClient::new(None, Duration::from_secs(5)).unwrap();
        let err = match client.post_form(&server.url("/token"), &[("client_id", "questdb")], false)
        {
            Err(err) => err,
            Ok(_) => panic!("an unknown CA must fail verification"),
        };

        assert_tls_network_error(err);
        assert_eq!(server.accepts(), 1);
        assert!(server.request_bodies().is_empty());
    }

    #[test]
    fn https_rejects_hostname_mismatch() {
        let server = TlsJsonServer::hostname_mismatch();
        let client = HttpClient::new(Some(&root_ca_path()), Duration::from_secs(5)).unwrap();
        let err = match client.post_form(&server.url("/token"), &[("client_id", "questdb")], false)
        {
            Err(err) => err,
            Ok(_) => panic!("a hostname mismatch must fail verification"),
        };

        assert_tls_network_error(err);
        assert_eq!(server.accepts(), 1);
        assert!(server.request_bodies().is_empty());
    }

    #[test]
    fn https_always_allowed() {
        assert!(require_secure("https://idp.example.com/token", false).is_ok());
    }

    #[test]
    fn hostless_https_rejected() {
        // A hostless https URL must never slip through to the TLS connector,
        // which needs a URI authority (a missing one would otherwise reach the
        // `.expect` there — an abort under the `panic = "abort"` FFI).
        for url in ["https:///token", "https://:443/token"] {
            let err = require_secure(url, false).unwrap_err();
            assert_eq!(
                err.kind(),
                crate::oidc::error::OidcErrorKind::Config,
                "{url} should be rejected as a config error"
            );
        }
    }

    #[test]
    fn loopback_http_allowed() {
        for url in [
            "http://localhost:9000/settings",
            "http://127.0.0.1:9000/settings",
            "http://[::1]:9000/settings",
        ] {
            assert!(require_secure(url, false).is_ok(), "should allow {url}");
        }
    }

    #[test]
    fn non_loopback_http_rejected_unless_insecure() {
        assert!(require_secure("http://questdb.example.com:9000/settings", false).is_err());
        assert!(require_secure("http://questdb.example.com:9000/settings", true).is_ok());
    }

    #[test]
    fn malformed_url_is_config_error() {
        let err = require_secure("not a url", false).unwrap_err();
        assert_eq!(err.kind(), crate::oidc::error::OidcErrorKind::Config);
    }

    #[test]
    fn is_loopback_cases() {
        assert!(is_loopback("localhost"));
        assert!(is_loopback("LOCALHOST"));
        assert!(is_loopback("127.0.0.1"));
        assert!(is_loopback("127.5.5.5"));
        assert!(is_loopback("::1"));
        assert!(is_loopback("[::1]"));
        assert!(!is_loopback("example.com"));
        assert!(!is_loopback("10.0.0.1"));
    }

    #[test]
    fn transient_http_statuses_include_request_timeout() {
        for status in [408, 429, 500, 503, 599] {
            assert!(is_transient_http_status(status), "HTTP {status}");
        }
        for status in [200, 302, 400, 401, 403, 404] {
            assert!(!is_transient_http_status(status), "HTTP {status}");
        }
    }

    #[test]
    fn non_json_success_body_is_never_echoed_into_error() {
        // A non-conformant / truncated 2xx token response carries the secret in a
        // non-JSON body; it must never reach a displayable/loggable error message.
        let secret_form = "access_token=SECRET-eyJhbGciOiJSUzI1NiJ9&token_type=bearer";
        let truncated_json = r#"{"access_token":"SECRET-eyJhbGciOiJSUzI1NiJ9.eyJzdWIi"#;
        for status in [200u16, 201, 204, 301, 302, 399] {
            for body in [secret_form, truncated_json] {
                let detail = non_json_body_detail(status, body.as_bytes());
                assert!(
                    !detail.contains("SECRET"),
                    "HTTP {status} non-JSON body leaked into the error detail: {detail}"
                );
                assert_eq!(detail, "unexpected non-JSON response body");
            }
        }

        // A genuine HTTP error page (>= 400) cannot carry an issued token, so its
        // body is still snippeted for diagnostics.
        let detail = non_json_body_detail(503, b"Service Unavailable (upstream proxy)");
        assert!(
            detail.contains("Service Unavailable"),
            "error-page body should still be snippeted, got: {detail}"
        );
        let detail = non_json_body_detail(400, b"invalid_request: bad client");
        assert!(detail.contains("invalid_request"), "got: {detail}");
    }

    #[test]
    fn parse_retry_after_only_accepts_delta_seconds() {
        use ureq::http::{HeaderMap, HeaderValue};
        fn with_retry_after(v: &str) -> HeaderMap {
            let mut h = HeaderMap::new();
            h.insert("retry-after", HeaderValue::from_str(v).unwrap());
            h
        }
        // A bare run of ASCII digits (delta-seconds), trimmed.
        assert_eq!(parse_retry_after(&with_retry_after("5")), Some(5));
        assert_eq!(parse_retry_after(&with_retry_after("0")), Some(0));
        assert_eq!(parse_retry_after(&with_retry_after("  7 ")), Some(7));
        // 9 digits is the max accepted; 10 is rejected (no u64 overflow risk, and
        // >31 years is meaningless).
        assert_eq!(
            parse_retry_after(&with_retry_after("999999999")),
            Some(999_999_999)
        );
        assert_eq!(parse_retry_after(&with_retry_after("1000000000")), None);
        // Rejected: empty, sign, decimal, and the HTTP-date form.
        assert_eq!(parse_retry_after(&with_retry_after("")), None);
        assert_eq!(parse_retry_after(&with_retry_after("-5")), None);
        assert_eq!(parse_retry_after(&with_retry_after("1.5")), None);
        assert_eq!(
            parse_retry_after(&with_retry_after("Fri, 31 Dec 1999 23:59:59 GMT")),
            None
        );
        // Absent header.
        assert_eq!(parse_retry_after(&HeaderMap::new()), None);
    }

    #[test]
    fn request_provably_unsent_classifies_pre_send_failures() {
        use ureq::Error;
        // Pre-send: the request never left the client, so a refresh token carried
        // in it was not consumed by the IdP — safe to keep and retry.
        assert!(request_provably_unsent(&Error::HostNotFound));
        assert!(request_provably_unsent(&Error::ConnectionFailed));
        assert!(request_provably_unsent(&Error::ConnectProxyFailed(
            "x".into()
        )));
        assert!(request_provably_unsent(&Error::TlsRequired));
        assert!(request_provably_unsent(&Error::Tls("handshake")));
        assert!(request_provably_unsent(&Error::Timeout(
            ureq::Timeout::Resolve
        )));
        assert!(request_provably_unsent(&Error::Timeout(
            ureq::Timeout::Connect
        )));
        // ureq surfaces a refused/unreachable connect as `Io` with the kind as
        // the reason: those never established a connection, so the request is
        // provably unsent.
        for kind in [
            std::io::ErrorKind::ConnectionRefused,
            std::io::ErrorKind::NetworkUnreachable,
            std::io::ErrorKind::HostUnreachable,
            std::io::ErrorKind::AddrNotAvailable,
        ] {
            assert!(
                request_provably_unsent(&Error::Io(std::io::Error::new(kind, "no connection"))),
                "{kind:?} should be pre-send"
            );
        }
        // Ambiguous — the request may have reached the IdP, so it is NOT provably
        // unsent and the parent must be treated as possibly-consumed. A reset or
        // EOF can happen after the request bytes were written.
        assert!(!request_provably_unsent(&Error::Timeout(
            ureq::Timeout::Global
        )));
        assert!(!request_provably_unsent(&Error::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "reset mid-flight",
        ))));
        assert!(!request_provably_unsent(&Error::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "eof reading response",
        ))));
        assert!(!request_provably_unsent(&Error::StatusCode(500)));
    }
}
