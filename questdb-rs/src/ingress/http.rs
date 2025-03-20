use super::conf::ConfigSetting;
use crate::error;
use base64ct::Base64;
use base64ct::Encoding;
use rand::Rng;
use std::thread::sleep;
use std::time::Duration;
use ureq::http::Response;
use ureq::typestate::WithBody;
use ureq::{Body, RequestBuilder};

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
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            request_min_throughput: ConfigSetting::new_default(102400), // 100 KiB/s
            user_agent: concat!("questdb/rust/", env!("CARGO_PKG_VERSION")).to_string(),
            retry_timeout: ConfigSetting::new_default(Duration::from_secs(10)),
            request_timeout: ConfigSetting::new_default(Duration::from_secs(10)),
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
    fn build_request(&self) -> RequestBuilder<WithBody> {
        let request = self
            .agent
            .post(&self.url)
            .query_pairs([("precision", "n")])
            .content_type("text/plain; charset=utf-8");
        match self.auth.as_ref() {
            Some(auth) => request.header("Authorization", auth),
            None => request,
        }
    }
}

pub(super) fn is_retriable_error(err: &ureq::Error) -> bool {
    use ureq::Error::*;
    match err {
        Timeout(_) => true,
        ConnectionFailed => true,
        TooManyRedirects => true,

        // Official HTTP codes
        StatusCode(500) |  // Internal Server Error
        StatusCode(503) |  // Service Unavailable
        StatusCode(504) |  // Gateway Timeout

        // Unofficial extensions
        StatusCode(507) | // Insufficient Storage
        StatusCode(509) | // Bandwidth Limit Exceeded
        StatusCode(523) | // Origin is Unreachable
        StatusCode(524) | // A Timeout Occurred
        StatusCode(529) | // Site is overloaded
        StatusCode(599) => { // Network Connect Timeout Error
            true
        }
        _ => false
    }
}

#[allow(clippy::result_large_err)] // `ureq::Error` is large enough to cause this warning.
fn retry_http_send(
    state: &HttpHandlerState,
    buf: &[u8],
    retry_timeout: Duration,
    mut last_err: ureq::Error,
) -> Result<Response<Body>, ureq::Error> {
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
        last_err = match state.build_request().send(buf) {
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
    state: &HttpHandlerState,
    buf: &[u8],
    retry_timeout: Duration,
) -> Result<Response<Body>, ureq::Error> {
    let last_err = match state.build_request().send(buf) {
        Ok(res) => return Ok(res),
        Err(err) => err,
    };

    if retry_timeout.is_zero() || !is_retriable_error(&last_err) {
        return Err(last_err);
    }

    retry_http_send(state, buf, retry_timeout, last_err)
}
