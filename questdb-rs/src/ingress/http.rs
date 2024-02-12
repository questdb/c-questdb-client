use crate::{error, Error};
use base64ct::Base64;
use base64ct::Encoding;
use rand::Rng;
use std::fmt::Write;
use std::thread::sleep;
use std::time::Duration;

use super::conf::ConfigSetting;

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
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
    pub(super) min_throughput: ConfigSetting<u64>,
    pub(super) user_agent: ConfigSetting<Option<String>>,
    pub(super) retry_timeout: ConfigSetting<Duration>,
    pub(super) grace_timeout: ConfigSetting<Duration>,
    pub(super) transactional: ConfigSetting<bool>,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            min_throughput: ConfigSetting::new_default(102400), // 100 KiB/s
            user_agent: ConfigSetting::new_default(None),
            retry_timeout: ConfigSetting::new_default(Duration::from_secs(10)),
            grace_timeout: ConfigSetting::new_default(Duration::from_secs(5)),
            transactional: ConfigSetting::new_default(false),
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

pub(super) fn parse_json_error(json: &serde_json::Value, msg: &str) -> Error {
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

pub(super) fn parse_http_error(http_status_code: u16, response: ureq::Response) -> Error {
    if http_status_code == 404 {
        return error::fmt!(
            HttpNotSupported,
            "Could not flush buffer: HTTP endpoint does not support ILP."
        );
    } else if [401, 403].contains(&http_status_code) {
        let description = match response.into_string() {
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

    let is_json = response
        .content_type()
        .eq_ignore_ascii_case("application/json");
    match response.into_string() {
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

            return if let Some(serde_json::Value::String(ref msg)) = json.get("message") {
                parse_json_error(&json, msg)
            } else {
                string_err()
            };
        }
        Err(err) => {
            error::fmt!(SocketError, "Could not flush buffer: {}", err)
        }
    }
}

pub(super) fn is_retriable_error(err: &ureq::Error) -> bool {
    use ureq::Error::*;
    match err {
        Transport(_) => true,

        // Official HTTP codes
        Status(500, _) |  // Internal Server Error
        Status(503, _) |  // Service Unavailable
        Status(504, _) |  // Gateway Timeout

        // Unofficial extensions
        Status(507, _) | // Insufficient Storage
        Status(509, _) | // Bandwidth Limit Exceeded
        Status(523, _) | // Origin is Unreachable
        Status(524, _) | // A Timeout Occurred
        Status(529, _) | // Site is overloaded
        Status(599, _) => { // Network Connect Timeout Error
            true
        }
        _ => false
    }
}

#[allow(clippy::result_large_err)] // `ureq::Error` is large enough to cause this warning.
fn retry_http_send(
    request: ureq::Request,
    buf: &[u8],
    retry_timeout: Duration,
    mut last_err: ureq::Error,
) -> Result<ureq::Response, ureq::Error> {
    let mut rng = rand::thread_rng();
    let retry_end = std::time::Instant::now() + retry_timeout;
    let mut retry_interval_ms = 10;
    loop {
        let jitter_ms = rng.gen_range(-5i32..5);
        let to_sleep_ms = retry_interval_ms + jitter_ms;
        let to_sleep = Duration::from_millis(to_sleep_ms as u64);
        if (std::time::Instant::now() + to_sleep) > retry_end {
            return Err(last_err);
        }
        sleep(to_sleep);
        last_err = match request.clone().send_bytes(buf) {
            Ok(res) => return Ok(res),
            Err(err) => {
                if !is_retriable_error(&err) {
                    return Err(err);
                }
                err
            }
        };
        retry_interval_ms = (retry_interval_ms * 2).min(1000);
    }
}

#[allow(clippy::result_large_err)] // `ureq::Error` is large enough to cause this warning.
pub(super) fn http_send_with_retries(
    request: ureq::Request,
    buf: &[u8],
    retry_timeout: Duration,
) -> Result<ureq::Response, ureq::Error> {
    let last_err = match request.clone().send_bytes(buf) {
        Ok(res) => return Ok(res),
        Err(err) => err,
    };

    if retry_timeout.is_zero() || !is_retriable_error(&last_err) {
        return Err(last_err);
    }

    retry_http_send(request, buf, retry_timeout, last_err)
}
