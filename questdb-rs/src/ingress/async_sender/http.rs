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
use std::future::Future;
use std::time::Duration;

use crate::error::{fmt, Result};
use crate::ingress::conf::SETTINGS_RETRY_TIMEOUT;
use crate::ingress::http_common::{
    is_retriable_status_code, process_settings_response, ParsedResponseHeaders,
};
use crate::ingress::tls::TlsSettings;
use crate::ingress::ProtocolVersion;
use bytes::Bytes;
use rand::Rng;
use reqwest::{Body, Certificate, Client, RequestBuilder, StatusCode, Url};
use tokio::time::{sleep, Instant};

pub(super) struct HttpClient {
    tls: Option<TlsSettings>,
    auth: Option<String>,
    client: Client,
}

impl HttpClient {
    pub fn new(tls: Option<TlsSettings>, auth: Option<String>, user_agent: &str) -> Result<Self> {
        let builder = Client::builder().user_agent(user_agent);
        let client = match builder.build() {
            Ok(client) => client,
            Err(e) => return Err(fmt!(ConfigError, "Could not create http client: {}", e)),
        };
        Ok(Self { tls, auth, client })
    }

    pub async fn get(
        &self,
        url: &Url,
        request_timeout: Duration,
    ) -> (bool, Result<(StatusCode, ParsedResponseHeaders, Bytes)>) {
        let builder = self.client.get(url.clone()).timeout(request_timeout);
        perform_request(builder).await
    }

    pub async fn get_with_retries(
        &self,
        url: &Url,
        request_timeout: Duration,
        retry_timeout: Duration,
    ) -> Result<(StatusCode, ParsedResponseHeaders, Bytes)> {
        request_with_retries(|| self.get(url, request_timeout), retry_timeout).await
    }

    pub async fn post(
        &self,
        url: &Url,
        body: Bytes,
        request_timeout: Duration,
    ) -> (bool, Result<(StatusCode, ParsedResponseHeaders, Bytes)>) {
        let builder = self
            .client
            .post(url.clone())
            .timeout(request_timeout)
            .body(body);
        perform_request(builder).await
    }

    pub async fn post_with_retries(
        &self,
        url: &Url,
        body: Bytes,
        request_timeout: Duration,
        retry_timeout: Duration,
    ) -> Result<(StatusCode, ParsedResponseHeaders, Bytes)> {
        request_with_retries(
            || self.post(url, body.clone(), request_timeout),
            retry_timeout,
        )
        .await
    }
}

pub(super) fn build_url(tls: bool, host: &str, port: &str, path: &str) -> Result<Url> {
    let schema = if tls { "https" } else { "http" };
    let url_string = format!("{schema}://{host}:{port}/{path}");
    let map_url_err = |url, e| fmt!(CouldNotResolveAddr, "could not parse url {url:?}: {e}");
    Url::parse(&url_string).map_err(|e| map_url_err(&url_string, e))
}

fn map_reqwest_err(
    err: reqwest::Error,
) -> (bool, Result<(StatusCode, ParsedResponseHeaders, Bytes)>) {
    let mut need_retry = false;
    if err.is_timeout() || err.is_connect() || err.is_redirect() {
        need_retry = true;
    }
    if let Some(status) = err.status() {
        if is_retriable_status_code(status) {
            need_retry = true;
        }
    }
    (
        need_retry,
        Err(fmt!(SocketError, "Error receiving HTTP response: {err}")),
    )
}

async fn perform_request(
    builder: RequestBuilder,
) -> (bool, Result<(StatusCode, ParsedResponseHeaders, Bytes)>) {
    let response = match builder.send().await {
        Ok(response) => response,
        Err(err) => return map_reqwest_err(err),
    };
    let status = response.status();
    let header_data = ParsedResponseHeaders::parse(response.headers());
    match response.bytes().await {
        Ok(bytes) => (
            is_retriable_status_code(status),
            Ok((status, header_data, bytes)),
        ),
        Err(err) => map_reqwest_err(err),
    }
}

async fn request_with_retries<F, Fut>(
    mut do_request: F,
    retry_timeout: Duration,
) -> Result<(StatusCode, ParsedResponseHeaders, Bytes)>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = (bool, Result<(StatusCode, ParsedResponseHeaders, Bytes)>)>,
{
    let (need_retry, last_response) = do_request().await;
    if !need_retry || retry_timeout.is_zero() {
        return last_response;
    }

    let mut rng = rand::rng();
    let retry_end = Instant::now() + retry_timeout;
    let mut retry_interval_ms = 10;
    loop {
        let jitter_ms = rng.random_range(-5i32..5);
        let to_sleep_ms = retry_interval_ms + jitter_ms;
        let to_sleep = Duration::from_millis(to_sleep_ms as u64);
        if (Instant::now() + to_sleep) > retry_end {
            return last_response;
        }
        sleep(to_sleep).await;
        let (need_retry, last_response) = do_request().await;
        if !need_retry {
            return last_response;
        }
        retry_interval_ms = (retry_interval_ms * 2).min(1000);
    }
}

pub(super) async fn read_server_settings(
    client: &HttpClient,
    settings_url: &Url,
    default_max_name_len: usize,
    request_timeout: Duration,
) -> Result<(Vec<ProtocolVersion>, usize)> {
    let default_protocol_version = ProtocolVersion::V1;

    let response = client
        .get_with_retries(settings_url, request_timeout, SETTINGS_RETRY_TIMEOUT)
        .await;

    process_settings_response(
        response,
        settings_url.as_str(),
        default_protocol_version,
        default_max_name_len,
    )
}
