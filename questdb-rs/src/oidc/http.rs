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

/// Cap on how much of a non-JSON / error body is echoed into a diagnostic error
/// message. Enough to show a proxy/WAF error title or an OAuth `error_description`,
/// but short so an unexpected token-endpoint body can't spill much into a log. A
/// valid token response is JSON and never reaches this path (only a parse failure
/// snippets), so this only ever quotes an intermediary's error page.
const MAX_BODY_SNIPPET_CHARS: usize = 120;

/// The result of a `POST` to the IdP token / device-authorization endpoint:
/// the HTTP status, the parsed JSON body, and any `Retry-After` (delta-seconds).
pub(crate) struct PostResult {
    pub(crate) status: u16,
    pub(crate) body: serde_json::Value,
    pub(crate) retry_after: Option<u64>,
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
        let body = read_body(url, response)?;
        if !(200..300).contains(&status) {
            let snippet = body_snippet(&body);
            let msg = format!("HTTP {status} from {url}: {snippet}");
            // A 5xx / 429 is a transient server / rate-limit issue; anything else
            // (a wrong URL, OIDC not advertised, an auth gate) is a configuration
            // problem.
            return Err(if status >= 500 || status == 429 {
                OidcError::network(msg).with_status(Some(status))
            } else {
                OidcError::config(msg).with_status(Some(status))
            });
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
            .map_err(|e| OidcError::network(format!("Failed to reach {url}: {e}")))?;
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
                let snippet = body_snippet(&body);
                let msg = format!("HTTP {status} from {url}: {snippet}");
                // Non-JSON body: a transient 5xx/429 (a proxy/WAF error page)
                // stays retryable; anything else is a terminal rejection. Either
                // way carry the status + Retry-After so the poll loop / refresh
                // can classify and back off correctly.
                let err = if status >= 500 || status == 429 {
                    OidcError::network(msg)
                } else {
                    OidcError::device_flow(msg)
                };
                Err(err.with_status(Some(status)).with_retry_after(retry_after))
            }
        }
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

        let name_borrowed: ServerName<'_> = details
            .uri
            .authority()
            .expect("uri authority for tls")
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

    #[test]
    fn https_always_allowed() {
        assert!(require_secure("https://idp.example.com/token", false).is_ok());
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
}
