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
use crate::error;
use crate::error::Result;
use crate::ingress::async_sender::http::{build_url, read_server_settings, HttpClient};
use crate::ingress::conf::{AuthParams, HttpConfig};
use crate::ingress::http_common::pick_protocol_version;
use crate::ingress::tls::TlsSettings;
use crate::ingress::{
    check_protocol_version, Buffer, FrozenBuffer, NdArrayView, ProtocolVersion, SenderBuilder,
};
use reqwest::Url;
use std::fmt::Display;
use std::ops::Deref;
use std::sync::Arc;

mod http;

pub(crate) struct AsyncSenderSettings {
    max_name_len: usize,
    max_buf_size: usize,
    protocol_version: ProtocolVersion,
    http_config: HttpConfig,
}

pub struct AsyncSender {
    descr: String,
    settings: AsyncSenderSettings,
    client: HttpClient,
    write_url: Url,
}

impl AsyncSender {
    pub async fn from_conf<T: AsRef<str>>(conf: T) -> Result<Arc<Self>> {
        SenderBuilder::from_conf(conf)?.build_async().await
    }

    pub async fn from_env() -> Result<Arc<Self>> {
        SenderBuilder::from_env()?.build_async().await
    }

    pub(crate) async fn new(
        descr: String,
        host: &str,
        port: &str,
        tls: Option<TlsSettings>,
        auth: Option<String>,
        max_name_len: usize,
        max_buf_size: usize,
        protocol_version: Option<ProtocolVersion>,
        http_config: HttpConfig,
    ) -> Result<Arc<Self>> {
        let mut settings = AsyncSenderSettings {
            max_name_len, // sniffed and overwritten, unless endpoint is old and does not support /settings
            max_buf_size,
            protocol_version: protocol_version.unwrap_or(ProtocolVersion::V2), // TODO: sniff!
            http_config,
        };

        let settings_url = build_url(tls.is_some(), host, port, "settings")?;
        let write_url = build_url(tls.is_some(), host, port, "write")?; // TODO: fixme!
        let client = HttpClient::new(tls, auth, &settings.http_config.user_agent)?;
        let (protocol_versions, max_name_len) = read_server_settings(
            &client,
            &settings_url,
            max_name_len,
            *settings.http_config.request_timeout.deref(),
        )
        .await?;

        settings.protocol_version = pick_protocol_version(&protocol_versions[..])?;
        settings.max_name_len = max_name_len;

        Ok(Arc::new(Self {
            descr,
            settings,
            client,
            write_url,
        }))
    }

    pub fn new_buffer(self: &Arc<Self>) -> Buffer {
        Buffer::with_max_name_len(self.settings.protocol_version, self.settings.max_name_len)
    }

    pub async fn flush(&self, buf: impl Into<FrozenBuffer>, transactional: bool) -> Result<()> {
        let buf = buf.into();
        buf.check_can_flush()?;
        if transactional && !buf.transactional() {
            return Err(error::fmt!(
                        InvalidApiCall,
                        "Buffer contains lines for multiple tables. \
                        Transactional flushes are only supported for buffers containing lines for a single table."
                    ));
        }

        if buf.len() > self.settings.max_buf_size {
            let buf_len = buf.len();
            return Err(error::fmt!(
                InvalidApiCall,
                "Could not flush buffer: Buffer size of {} exceeds maximum configured allowed size of {} bytes.",
                buf_len,
                self.settings.max_buf_size
            ));
        }

        check_protocol_version(self.settings.protocol_version, buf.protocol_version())?;

        if buf.is_empty() {
            return Ok(());
        }

        // Which we can freeze as something that we can send.
        let body = buf.bytes();

        // let response = match self.client.post_with_retries(
        //     &self.write_url,
        //     body.clone(),
        //     *self.settings.http_config.request_timeout.deref(),
        //     *self.settings.http_config.retry_timeout.deref()
        // ).await {
        //     Ok(response) => response,
        //     Err(err) => {
        //         buffer_core.restore_output(body);
        //         _ = buf.swap_core(buffer_core);
        //         return (buf, Err(err));
        //     }
        // };

        todo!()

        // let buffer = buffer
        // self.client.post_with_retries(body)
    }
}
