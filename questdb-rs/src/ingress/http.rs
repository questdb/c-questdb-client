use super::conf::ConfigSetting;
use crate::error::fmt;
use crate::{error, Error};
use base64ct::Base64;
use base64ct::Encoding;
use rand::Rng;
use rustls::{ClientConnection, StreamOwned};
use rustls_pki_types::ServerName;
use std::fmt;
use std::fmt::{Debug, Write};
use std::io::{Read, Write as IoWrite};
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
use ureq::http::Response;
use ureq::unversioned::transport::{
    Buffers, Connector, LazyBuffers, NextTimeout, Transport, TransportAdapter,
};

use crate::ingress::LineProtocolVersion;
use ureq::unversioned::*;
use ureq::Error::*;
use ureq::{http, Body};

#[derive(PartialEq, Debug, Clone)]
pub(super) struct BasicAuthParams {
    pub(super) username: String,
    pub(super) password: String,
}

impl BasicAuthParams {
    pub(super) fn to_header_string(&self) -> String {
        let pair = format!("{}:{}", self.username, self.password);
        let encoded = Base64::encode_string(pair.as_bytes());
        format!("Basic {encoded}")
    }
}

#[derive(PartialEq, Debug, Clone)]
pub(super) struct TokenAuthParams {
    pub(super) token: String,
}

impl TokenAuthParams {
    pub(super) fn to_header_string(&self) -> crate::Result<String> {
        if self.token.contains('\n') {
            return Err(error::fmt!(
                AuthError,
                "Bad auth token: Should not contain new-line char."
            ));
        }
        Ok(format!("Bearer {}", self.token))
    }
}

#[derive(Debug, Clone)]
pub(super) struct HttpConfig {
    pub(super) request_min_throughput: ConfigSetting<u64>,
    pub(super) user_agent: String,
    pub(super) retry_timeout: ConfigSetting<Duration>,
    pub(super) request_timeout: ConfigSetting<Duration>,
    pub(super) disable_line_proto_validation: ConfigSetting<bool>,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            request_min_throughput: ConfigSetting::new_default(102400), // 100 KiB/s
            user_agent: concat!("questdb/rust/", env!("CARGO_PKG_VERSION")).to_string(),
            retry_timeout: ConfigSetting::new_default(Duration::from_secs(10)),
            request_timeout: ConfigSetting::new_default(Duration::from_secs(10)),
            disable_line_proto_validation: ConfigSetting::new_default(false),
        }
    }
}

pub(super) struct HttpHandlerState {
    /// Maintains a pool of open HTTP connections to the endpoint.
    pub(super) agent: ureq::Agent,

    /// The URL of the HTTP endpoint.
    pub(super) url: String,

    /// The content of the `Authorization` HTTP header.
    pub(super) auth: Option<String>,

    /// HTTP params configured via the `SenderBuilder`.
    pub(super) config: HttpConfig,
}

impl HttpHandlerState {
    fn send_request(
        &self,
        buf: &[u8],
        request_timeout: Duration,
    ) -> (bool, Result<Response<Body>, ureq::Error>) {
        let request = self
            .agent
            .post(&self.url)
            .config()
            .timeout_per_call(Some(request_timeout))
            .build()
            .query_pairs([("precision", "n")])
            .content_type("text/plain; charset=utf-8");

        let request = match self.auth.as_ref() {
            Some(auth) => request.header("Authorization", auth),
            None => request,
        };
        let response = request.send(buf);
        match &response {
            Ok(res) => (need_retry(Ok(res.status())), response),
            Err(err) => (need_retry(Err(err)), response),
        }
    }

    pub(crate) fn get_request(
        &self,
        url: &str,
        request_timeout: Duration,
    ) -> (bool, Result<Response<Body>, ureq::Error>) {
        let request = self
            .agent
            .get(url)
            .config()
            .timeout_per_call(Some(request_timeout))
            .build();
        let response = request.call();
        match &response {
            Ok(res) => (need_retry(Ok(res.status())), response),
            Err(err) => (need_retry(Err(err)), response),
        }
    }
}

#[derive(Debug)]
pub struct TlsConnector {
    tls_config: Option<Arc<rustls::ClientConfig>>,
}

impl<In: Transport> Connector<In> for TlsConnector {
    type Out = transport::Either<In, TlsTransport>;

    fn connect(
        &self,
        details: &transport::ConnectionDetails,
        chained: Option<In>,
    ) -> std::result::Result<Option<Self::Out>, ureq::Error> {
        let transport = match chained {
            Some(t) => t,
            None => return Ok(None),
        };

        // Only add TLS if we are connecting via HTTPS, otherwise use chained transport as is.
        if !details.needs_tls() {
            return Ok(Some(transport::Either::A(transport)));
        }

        match self.tls_config.as_ref() {
            Some(config) => {
                let name_borrowed: ServerName<'_> = details
                    .uri
                    .authority()
                    .expect("uri authority for tls")
                    .host()
                    .try_into()
                    .map_err(|_e| ureq::Error::Tls("tls invalid dns name error"))?;

                let name = name_borrowed.to_owned();
                let conn = ClientConnection::new(config.clone(), name)
                    .map_err(|_e| ureq::Error::Tls("tls client connection error"))?;
                let stream = StreamOwned {
                    conn,
                    sock: TransportAdapter::new(transport.boxed()),
                };
                let buffers = LazyBuffers::new(
                    details.config.input_buffer_size(),
                    details.config.output_buffer_size(),
                );

                let transport = TlsTransport { buffers, stream };
                Ok(Some(transport::Either::B(transport)))
            }
            _ => Ok(Some(transport::Either::A(transport))),
        }
    }
}

impl TlsConnector {
    pub fn new(tls_config: Option<Arc<rustls::ClientConfig>>) -> Self {
        TlsConnector { tls_config }
    }
}

pub struct TlsTransport {
    buffers: LazyBuffers,
    stream: StreamOwned<ClientConnection, TransportAdapter>,
}

impl Debug for TlsTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsTransport")
            .field("chained", &self.stream.sock.inner())
            .finish()
    }
}

impl Transport for TlsTransport {
    fn buffers(&mut self) -> &mut dyn Buffers {
        &mut self.buffers
    }

    fn transmit_output(&mut self, amount: usize, timeout: NextTimeout) -> Result<(), ureq::Error> {
        self.stream.get_mut().set_timeout(timeout);
        let output = &self.buffers.output()[..amount];
        self.stream.write_all(output)?;
        Ok(())
    }

    fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, ureq::Error> {
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

fn need_retry(res: Result<http::status::StatusCode, &ureq::Error>) -> bool {
    match res {
        Ok(status) => {
            status.is_server_error()
                && matches!(
                    status.as_u16(),
                    // Official HTTP codes
                    500 | // Internal Server Error
                    503 | // Service Unavailable
                    504 | // Gateway Timeout

                    // Unofficial extensions
                    507 | // Insufficient Storage
                    509 | // Bandwidth Limit Exceeded
                    523 | // Origin is Unreachable
                    524 | // A Timeout Occurred
                    529 | // Site is overloaded
                    599 // Network Connect Timeout Error
                )
        }
        Err(err) => matches!(err, Timeout(_) | ConnectionFailed | TooManyRedirects),
    }
}

fn parse_json_error(json: &serde_json::Value, msg: &str) -> Error {
    let mut description = msg.to_string();
    error::fmt!(ServerFlushError, "Could not flush buffer: {}", msg);

    let error_id = json.get("errorId").and_then(|v| v.as_str());
    let code = json.get("code").and_then(|v| v.as_str());
    let line = json.get("line").and_then(|v| v.as_i64());

    let mut printed_detail = false;
    if error_id.is_some() || code.is_some() || line.is_some() {
        description.push_str(" [");

        if let Some(error_id) = error_id {
            description.push_str("id: ");
            description.push_str(error_id);
            printed_detail = true;
        }

        if let Some(code) = code {
            if printed_detail {
                description.push_str(", ");
            }
            description.push_str("code: ");
            description.push_str(code);
            printed_detail = true;
        }

        if let Some(line) = line {
            if printed_detail {
                description.push_str(", ");
            }
            description.push_str("line: ");
            write!(description, "{}", line).unwrap();
        }

        description.push(']');
    }

    error::fmt!(ServerFlushError, "Could not flush buffer: {}", description)
}

pub(super) fn parse_http_error(http_status_code: u16, response: Response<Body>) -> Error {
    let (head, body) = response.into_parts();
    let body_content = body.into_with_config().lossy_utf8(true).read_to_string();
    if http_status_code == 404 {
        return error::fmt!(
            HttpNotSupported,
            "Could not flush buffer: HTTP endpoint does not support ILP."
        );
    } else if [401, 403].contains(&http_status_code) {
        let description = match body_content {
            Ok(msg) if !msg.is_empty() => format!(": {}", msg),
            _ => "".to_string(),
        };
        return error::fmt!(
            AuthError,
            "Could not flush buffer: HTTP endpoint authentication error{} [code: {}]",
            description,
            http_status_code
        );
    }

    let is_json = match head.headers.get("Content-Type") {
        Some(header_value) => match header_value.to_str() {
            Ok(s) => s.eq_ignore_ascii_case("application/json"),
            Err(_) => false,
        },
        None => false,
    };
    match body_content {
        Ok(msg) => {
            let string_err = || error::fmt!(ServerFlushError, "Could not flush buffer: {}", msg);

            if !is_json {
                return string_err();
            }

            let json: serde_json::Value = match serde_json::from_str(&msg) {
                Ok(json) => json,
                Err(_) => {
                    return string_err();
                }
            };

            if let Some(serde_json::Value::String(ref msg)) = json.get("message") {
                parse_json_error(&json, msg)
            } else {
                string_err()
            }
        }
        Err(err) => {
            error::fmt!(SocketError, "Could not flush buffer: {}", err)
        }
    }
}

#[allow(clippy::result_large_err)] // `ureq::Error` is large enough to cause this warning.
fn retry_http_send(
    state: &HttpHandlerState,
    buf: &[u8],
    request_timeout: Duration,
    retry_timeout: Duration,
    mut last_rep: Result<Response<Body>, ureq::Error>,
) -> Result<Response<Body>, ureq::Error> {
    let mut rng = rand::rng();
    let retry_end = std::time::Instant::now() + retry_timeout;
    let mut retry_interval_ms = 10;
    let mut need_retry;
    loop {
        let jitter_ms = rng.random_range(-5i32..5);
        let to_sleep_ms = retry_interval_ms + jitter_ms;
        let to_sleep = Duration::from_millis(to_sleep_ms as u64);
        if (std::time::Instant::now() + to_sleep) > retry_end {
            return last_rep;
        }
        sleep(to_sleep);
        if let Ok(last_rep) = last_rep {
            // Actively consume the reader to return the connection to the connection pool.
            // see https://github.com/algesten/ureq/issues/94
            _ = last_rep.into_body().read_to_vec();
        }
        (need_retry, last_rep) = state.send_request(buf, request_timeout);
        if !need_retry {
            return last_rep;
        }
        retry_interval_ms = (retry_interval_ms * 2).min(1000);
    }
}

#[allow(clippy::result_large_err)] // `ureq::Error` is large enough to cause this warning.
pub(super) fn http_send_with_retries(
    state: &HttpHandlerState,
    buf: &[u8],
    request_timeout: Duration,
    retry_timeout: Duration,
) -> Result<Response<Body>, ureq::Error> {
    let (need_retry, last_rep) = state.send_request(buf, request_timeout);
    if !need_retry || retry_timeout.is_zero() {
        return last_rep;
    }

    retry_http_send(state, buf, request_timeout, retry_timeout, last_rep)
}

pub(super) fn get_line_protocol_version(
    state: &HttpHandlerState,
    settings_url: &str,
) -> Result<(Option<Vec<LineProtocolVersion>>, LineProtocolVersion), Error> {
    let mut support_versions: Option<Vec<_>> = None;
    let mut default_version = LineProtocolVersion::V1;

    let response = match http_get_with_retries(
        state,
        settings_url,
        *state.config.request_timeout,
        Duration::from_secs(1),
    ) {
        Ok(res) => {
            if res.status().is_client_error() || res.status().is_server_error() {
                if res.status().as_u16() == 404 {
                    return Ok((support_versions, default_version));
                }
                return Err(fmt!(
                    LineProtocolVersionError,
                    "Failed to detect server's line protocol version, settings url: {}, status code: {}.",
                    settings_url,
                    res.status()
                ));
            } else {
                res
            }
        }
        Err(err) => {
            let e = match err {
                ureq::Error::StatusCode(code) => {
                    if code == 404 {
                        return Ok((support_versions, default_version));
                    } else {
                        fmt!(
                            LineProtocolVersionError,
                            "Failed to detect server's line protocol version, settings url: {}, err: {}.",
                            settings_url,
                            err
                        )
                    }
                }
                e => {
                    fmt!(
                        LineProtocolVersionError,
                        "Failed to detect server's line protocol version, settings url: {}, err: {}.",
                        settings_url,
                        e
                    )
                }
            };
            return Err(e);
        }
    };

    let (_, body) = response.into_parts();
    let body_content = body.into_with_config().lossy_utf8(true).read_to_string();

    if let Ok(msg) = body_content {
        let json: serde_json::Value = serde_json::from_str(&msg).map_err(|_| {
            error::fmt!(
                LineProtocolVersionError,
                "Malformed server response, settings url: {}, err: response is not valid JSON.",
                settings_url,
            )
        })?;

        if let Some(serde_json::Value::Array(ref values)) = json.get("line.proto.support.versions")
        {
            let mut versions = Vec::new();
            for value in values.iter() {
                if let Some(v) = value.as_u64() {
                    match v {
                        1 => versions.push(LineProtocolVersion::V1),
                        2 => versions.push(LineProtocolVersion::V2),
                        _ => {}
                    }
                }
            }
            support_versions = Some(versions);
        }

        if let Some(serde_json::Value::Number(ref v)) = json.get("line.proto.default.version") {
            default_version = match v.as_u64() {
                Some(vu64) => match vu64 {
                    1 => LineProtocolVersion::V1,
                    2 => LineProtocolVersion::V2,
                    _ => {
                        if let Some(ref versions) = support_versions {
                            if versions.contains(&LineProtocolVersion::V2) {
                                LineProtocolVersion::V2
                            } else if versions.contains(&LineProtocolVersion::V1) {
                                LineProtocolVersion::V1
                            } else {
                                return Err(error::fmt!(
                                    LineProtocolVersionError,
                                    "Server does not support current client"
                                ));
                            }
                        } else {
                            return Err(error::fmt!(
                                LineProtocolVersionError,
                                "Unexpected response version content."
                            ));
                        }
                    }
                },
                None => {
                    return Err(error::fmt!(
                        LineProtocolVersionError,
                        "Not a valid int for line.proto.default.version in response."
                    ))
                }
            };
        }
    } else {
        return Err(error::fmt!(
            LineProtocolVersionError,
            "Malformed server response, settings url: {}, err: failed to read response body as UTF-8", settings_url
        ));
    }
    Ok((support_versions, default_version))
}

#[allow(clippy::result_large_err)] // `ureq::Error` is large enough to cause this warning.
fn retry_http_get(
    state: &HttpHandlerState,
    url: &str,
    request_timeout: Duration,
    retry_timeout: Duration,
    mut last_rep: Result<Response<Body>, ureq::Error>,
) -> Result<Response<Body>, ureq::Error> {
    let mut rng = rand::rng();
    let retry_end = std::time::Instant::now() + retry_timeout;
    let mut retry_interval_ms = 10;
    let mut need_retry;
    loop {
        let jitter_ms = rng.random_range(-5i32..5);
        let to_sleep_ms = retry_interval_ms + jitter_ms;
        let to_sleep = Duration::from_millis(to_sleep_ms as u64);
        if (std::time::Instant::now() + to_sleep) > retry_end {
            return last_rep;
        }
        sleep(to_sleep);
        if let Ok(last_rep) = last_rep {
            // Actively consume the reader to return the connection to the connection pool.
            // see https://github.com/algesten/ureq/issues/94
            _ = last_rep.into_body().read_to_vec();
        }
        (need_retry, last_rep) = state.get_request(url, request_timeout);
        if !need_retry {
            return last_rep;
        }
        retry_interval_ms = (retry_interval_ms * 2).min(1000);
    }
}

#[allow(clippy::result_large_err)] // `ureq::Error` is large enough to cause this warning.
fn http_get_with_retries(
    state: &HttpHandlerState,
    url: &str,
    request_timeout: Duration,
    retry_timeout: Duration,
) -> Result<Response<Body>, ureq::Error> {
    let (need_retry, last_rep) = state.get_request(url, request_timeout);
    if !need_retry || retry_timeout.is_zero() {
        return last_rep;
    }

    retry_http_get(state, url, request_timeout, retry_timeout, last_rep)
}
