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

use std::time::Duration;

use crate::error::{fmt, Error, Result};
use crate::ingress::conf::{parse_server_settings, SETTINGS_RETRY_TIMEOUT};
use crate::ingress::http_common::is_retriable_status_code;
use crate::ingress::tls::TlsSettings;
use crate::ingress::ProtocolVersion;
use bytes::Bytes;
use rand::Rng;
use reqwest::{Body, Certificate, Client, StatusCode, Url};
use tokio::time::{sleep, Instant};

pub(super) struct HttpClient {
    tls: Option<TlsSettings>,
    auth: Option<String>,
    client: Client,
}

impl HttpClient {
    pub fn new(tls: Option<TlsSettings>, auth: Option<String>) -> Result<Self> {
        let builder = Client::builder();
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
    ) -> (bool, Result<(StatusCode, Bytes)>) {
        let map_reqwest_err = |err: reqwest::Error| {
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
        };

        let builder = self
            .client
            .get(url.clone())
            // TODO user agent!
            .timeout(request_timeout);
        let response = match builder.send().await {
            Ok(response) => response,
            Err(err) => return map_reqwest_err(err),
        };
        let status = response.status();
        match response.bytes().await {
            Ok(bytes) => (is_retriable_status_code(status), Ok((status, bytes))),
            Err(err) => map_reqwest_err(err),
        }
    }

    async fn retry_http_get(
        &self,
        url: &Url,
        request_timeout: Duration,
        retry_timeout: Duration,
        mut last_response: Result<(StatusCode, Bytes)>,
    ) -> Result<(StatusCode, Bytes)> {
        let mut rng = rand::rng();
        let retry_end = Instant::now() + retry_timeout;
        let mut retry_interval_ms = 10;
        let mut need_retry;
        loop {
            let jitter_ms = rng.random_range(-5i32..5);
            let to_sleep_ms = retry_interval_ms + jitter_ms;
            let to_sleep = Duration::from_millis(to_sleep_ms as u64);
            if (Instant::now() + to_sleep) > retry_end {
                return last_response;
            }
            sleep(to_sleep);
            (need_retry, last_response) = self.get(url, request_timeout).await;
            if !need_retry {
                return last_response;
            }
            retry_interval_ms = (retry_interval_ms * 2).min(1000);
        }
    }

    pub async fn get_with_retries(
        &self,
        url: &Url,
        request_timeout: Duration,
        retry_timeout: Duration,
    ) -> Result<(StatusCode, Bytes)> {
        let (need_retry, last_response) = self.get(url, request_timeout).await;
        if !need_retry || retry_timeout.is_zero() {
            return last_response;
        }

        self.retry_http_get(url, request_timeout, retry_timeout, last_response)
            .await
    }

    pub async fn post(&self, url: &Url, body: Bytes) {
        let builder = self.client.post(url.clone());
        let res = builder.body(body).send().await;
        eprintln!("POST: {res:?}");
    }
}

pub(super) fn build_url(tls: bool, host: &str, port: &str, path: &str) -> Result<Url> {
    let schema = if tls { "https" } else { "http" };
    let url_string = format!("{schema}://{host}:{port}/{path}");
    let map_url_err = |url, e| fmt!(CouldNotResolveAddr, "could not parse url {url:?}: {e}");
    Url::parse(&url_string).map_err(|e| map_url_err(&url_string, e))
}

pub(super) async fn read_server_settings(
    client: &HttpClient,
    settings_url: &Url,
    default_max_name_len: usize,
    request_timeout: Duration,
) -> Result<(Vec<ProtocolVersion>, usize)> {
    let default_protocol_version = ProtocolVersion::V1;

    let (status, response) = client
        .get_with_retries(settings_url, request_timeout, SETTINGS_RETRY_TIMEOUT)
        .await?;

    todo!();

    // let response = match http_get_with_retries(
    //     client,
    //     settings_url,
    //     request_timeout,
    //     SETTINGS_RETRY_TIMEOUT,
    // ).await {
    //     Ok(res) => {
    //         if res.status().is_client_error() || res.status().is_server_error() {
    //             let status = res.status();
    //             _ = res.into_body().read_to_vec();
    //             if status.as_u16() == 404 {
    //                 return Ok((vec![default_protocol_version], default_max_name_len));
    //             }
    //             return Err(fmt!(
    //                 ProtocolVersionError,
    //                 "Could not detect server's line protocol version, settings url: {}, status code: {}.",
    //                 settings_url,
    //                 status
    //             ));
    //         } else {
    //             res
    //         }
    //     }
    //     Err(err) => {
    //         let e = match err {
    //             ureq::Error::StatusCode(code) => {
    //                 if code == 404 {
    //                     return Ok((vec![default_protocol_version], default_max_name_len));
    //                 } else {
    //                     fmt!(
    //                         ProtocolVersionError,
    //                         "Could not detect server's line protocol version, settings url: {}, err: {}.",
    //                         settings_url,
    //                         err
    //                     )
    //                 }
    //             }
    //             e => {
    //                 fmt!(
    //                     ProtocolVersionError,
    //                     "Could not detect server's line protocol version, settings url: {}, err: {}.",
    //                     settings_url,
    //                     e
    //                 )
    //             }
    //         };
    //         return Err(e);
    //     }
    // };

    // let (_, body) = response.into_parts();
    // let body_content = body.into_with_config().read_to_string();

    // let Ok(response) = body_content else {
    //     return error::fmt!(
    //         ProtocolVersionError,
    //         "Malformed server response, settings url: {}, err: response is not valid JSON.",
    //         settings_url,
    //     );
    // };

    // parse_server_settings(
    //     response,
    //     settings_url.as_str(),
    //     default_protocol_version,
    //     default_max_name_len)
}
