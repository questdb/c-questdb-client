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

#[cfg(feature = "_sender-qwp-ws")]
use super::QwpWsProgress;
use crate::{Error, ErrorCode, Result};
use std::ops::Deref;
#[cfg(feature = "_sender-qwp-ws")]
use std::path::PathBuf;

/// Wraps a SenderBuilder config setting with the intent of tracking
/// whether the value was user-specified or defaulted.
/// This helps the builder API ensure that a user-specified value can't
/// be changed once set.
#[derive(Debug, Clone)]
pub(crate) enum ConfigSetting<T: PartialEq> {
    Defaulted(T),
    Specified(T),
}

impl<T: PartialEq> ConfigSetting<T> {
    pub(crate) fn new_default(value: T) -> Self {
        ConfigSetting::Defaulted(value)
    }

    pub(crate) fn new_specified(value: T) -> Self {
        ConfigSetting::Specified(value)
    }

    /// Set the user-defined value.
    /// Note that it can't be changed once set.
    /// If the value is already specified, returns an error.
    pub(crate) fn set_specified(&mut self, setting_name: &str, value: T) -> Result<()> {
        match self {
            ConfigSetting::Defaulted(_) => {
                *self = ConfigSetting::Specified(value);
                Ok(())
            }
            ConfigSetting::Specified(curr_value) if *curr_value == value => Ok(()),
            _ => Err(Error::new(
                ErrorCode::ConfigError,
                format!("{setting_name:?} is already specified"),
            )),
        }
    }
}

impl<T: PartialEq> Deref for ConfigSetting<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        match self {
            ConfigSetting::Defaulted(v) => v,
            ConfigSetting::Specified(v) => v,
        }
    }
}

#[cfg(feature = "_sender-http")]
#[derive(Debug, Clone)]
pub(crate) struct HttpConfig {
    pub(crate) request_min_throughput: ConfigSetting<u64>,
    pub(crate) user_agent: String,
    pub(crate) retry_timeout: ConfigSetting<std::time::Duration>,
    pub(crate) request_timeout: ConfigSetting<std::time::Duration>,
}

#[cfg(feature = "_sender-http")]
impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            request_min_throughput: ConfigSetting::new_default(102400), // 100 KiB/s
            user_agent: concat!("questdb/rust/", env!("CARGO_PKG_VERSION")).to_string(),
            retry_timeout: ConfigSetting::new_default(std::time::Duration::from_secs(10)),
            request_timeout: ConfigSetting::new_default(std::time::Duration::from_secs(10)),
        }
    }
}

#[cfg(feature = "_sender-qwp-udp")]
#[derive(Debug, Clone)]
pub(crate) struct QwpUdpConfig {
    pub(crate) max_datagram_size: ConfigSetting<usize>,
    pub(crate) multicast_ttl: ConfigSetting<u32>,
}

#[cfg(feature = "_sender-qwp-udp")]
impl Default for QwpUdpConfig {
    fn default() -> Self {
        Self {
            max_datagram_size: ConfigSetting::new_default(1400),
            multicast_ttl: ConfigSetting::new_default(1),
        }
    }
}

#[cfg(feature = "_sender-qwp-ws")]
pub(crate) const QWP_WS_DEFAULT_SENDER_ID: &str = "default";
#[cfg(feature = "_sender-qwp-ws")]
pub(crate) const QWP_WS_DEFAULT_SF_SEGMENT_BYTES: u64 = 4 * 1024 * 1024;
#[cfg(feature = "_sender-qwp-ws")]
pub(crate) const QWP_WS_DEFAULT_SF_MEMORY_MAX_TOTAL_BYTES: u64 = 128 * 1024 * 1024;
#[cfg(feature = "_sender-qwp-ws")]
pub(crate) const QWP_WS_DEFAULT_SF_DISK_MAX_TOTAL_BYTES: u64 = 10 * 1024 * 1024 * 1024;
#[cfg(feature = "_sender-qwp-ws")]
pub(crate) const QWP_WS_DEFAULT_MAX_BACKGROUND_DRAINERS: usize = 4;
#[cfg(feature = "_sender-qwp-ws")]
pub(crate) const QWP_WS_DEFAULT_CLOSE_DRAIN_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(5);

#[cfg(feature = "_sender-qwp-ws")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SfDurability {
    Memory,
    Flush,
    Append,
}

#[cfg(feature = "_sender-qwp-ws")]
impl SfDurability {
    pub(crate) fn as_conf_value(self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::Flush => "flush",
            Self::Append => "append",
        }
    }
}

#[cfg(feature = "_sender-qwp-ws")]
pub(crate) fn is_valid_qwp_ws_sender_id(sender_id: &str) -> bool {
    !sender_id.is_empty()
        && sender_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

#[cfg(feature = "_sender-qwp-ws")]
#[derive(Debug, Clone)]
pub(crate) struct QwpWsConfig {
    pub(crate) connect_timeout: ConfigSetting<std::time::Duration>,
    pub(crate) auth_timeout: ConfigSetting<std::time::Duration>,
    pub(crate) request_timeout: ConfigSetting<std::time::Duration>,
    pub(crate) client_id: ConfigSetting<Option<String>>,
    pub(crate) max_protocol_version: ConfigSetting<u32>,
    pub(crate) request_durable_ack: ConfigSetting<bool>,
    pub(crate) durable_ack_keepalive_interval: ConfigSetting<std::time::Duration>,
    /// Maximum number of unacknowledged messages in flight on a single
    /// pipelined async sender. Matches the spec's per-connection cap.
    pub(crate) max_in_flight: ConfigSetting<usize>,
    /// Per-outage wall-clock budget for the reconnect loop.
    pub(crate) reconnect_max_duration: ConfigSetting<std::time::Duration>,
    /// Initial reconnect backoff; the reconnect loop doubles the delay up to
    /// `reconnect_max_backoff`.
    pub(crate) reconnect_initial_backoff: ConfigSetting<std::time::Duration>,
    /// Cap on the per-attempt reconnect delay.
    pub(crate) reconnect_max_backoff: ConfigSetting<std::time::Duration>,
    /// Whether the initial connect should use the reconnect policy. Default
    /// false, matching Java's fail-fast startup behavior.
    pub(crate) initial_connect_retry: ConfigSetting<bool>,
    /// Bounded wait used by Sender::close_drain().
    pub(crate) close_flush_timeout: ConfigSetting<std::time::Duration>,
    pub(crate) sf_dir: ConfigSetting<Option<PathBuf>>,
    pub(crate) sender_id: ConfigSetting<String>,
    pub(crate) sf_max_bytes: ConfigSetting<u64>,
    pub(crate) sf_max_total_bytes: ConfigSetting<Option<u64>>,
    pub(crate) sf_durability: ConfigSetting<SfDurability>,
    pub(crate) sf_append_deadline: ConfigSetting<std::time::Duration>,
    pub(crate) drain_orphans: ConfigSetting<bool>,
    pub(crate) max_background_drainers: ConfigSetting<usize>,
    pub(crate) progress: ConfigSetting<QwpWsProgress>,
}

#[cfg(feature = "_sender-qwp-ws")]
impl Default for QwpWsConfig {
    fn default() -> Self {
        Self {
            connect_timeout: ConfigSetting::new_default(std::time::Duration::from_secs(10)),
            auth_timeout: ConfigSetting::new_default(std::time::Duration::from_secs(15)),
            request_timeout: ConfigSetting::new_default(std::time::Duration::from_secs(30)),
            client_id: ConfigSetting::new_default(None),
            max_protocol_version: ConfigSetting::new_default(1),
            request_durable_ack: ConfigSetting::new_default(false),
            durable_ack_keepalive_interval: ConfigSetting::new_default(
                std::time::Duration::from_millis(200),
            ),
            max_in_flight: ConfigSetting::new_default(128),
            reconnect_max_duration: ConfigSetting::new_default(std::time::Duration::from_secs(300)),
            reconnect_initial_backoff: ConfigSetting::new_default(
                std::time::Duration::from_millis(100),
            ),
            reconnect_max_backoff: ConfigSetting::new_default(std::time::Duration::from_secs(5)),
            initial_connect_retry: ConfigSetting::new_default(false),
            close_flush_timeout: ConfigSetting::new_default(QWP_WS_DEFAULT_CLOSE_DRAIN_TIMEOUT),
            sf_dir: ConfigSetting::new_default(None),
            sender_id: ConfigSetting::new_default(QWP_WS_DEFAULT_SENDER_ID.to_owned()),
            sf_max_bytes: ConfigSetting::new_default(QWP_WS_DEFAULT_SF_SEGMENT_BYTES),
            sf_max_total_bytes: ConfigSetting::new_default(None),
            sf_durability: ConfigSetting::new_default(SfDurability::Memory),
            sf_append_deadline: ConfigSetting::new_default(std::time::Duration::from_secs(30)),
            drain_orphans: ConfigSetting::new_default(false),
            max_background_drainers: ConfigSetting::new_default(
                QWP_WS_DEFAULT_MAX_BACKGROUND_DRAINERS,
            ),
            progress: ConfigSetting::new_default(QwpWsProgress::Background),
        }
    }
}

#[cfg(feature = "_sender-qwp-ws")]
impl QwpWsConfig {
    pub(crate) fn sf_max_total_bytes(&self) -> u64 {
        if let Some(max_total_bytes) = *self.sf_max_total_bytes {
            return max_total_bytes;
        }

        let default_max_total_bytes = if self.sf_dir.is_some() {
            QWP_WS_DEFAULT_SF_DISK_MAX_TOTAL_BYTES
        } else {
            QWP_WS_DEFAULT_SF_MEMORY_MAX_TOTAL_BYTES
        };
        default_max_total_bytes.max(self.sf_max_bytes.saturating_mul(2))
    }
}

#[cfg(any(feature = "_sender-http", feature = "_sender-qwp-ws"))]
#[derive(PartialEq, Debug, Clone)]
pub(crate) struct BasicAuthParams {
    pub(crate) username: String,
    pub(crate) password: String,
}

#[cfg(any(feature = "_sender-http", feature = "_sender-qwp-ws"))]
impl BasicAuthParams {
    pub(crate) fn to_header_string(&self) -> String {
        use base64ct::{Base64, Encoding};
        let pair = format!("{}:{}", self.username, self.password);
        let encoded = Base64::encode_string(pair.as_bytes());
        format!("Basic {encoded}")
    }
}

#[cfg(any(feature = "_sender-http", feature = "_sender-qwp-ws"))]
#[derive(PartialEq, Debug, Clone)]
pub(crate) struct TokenAuthParams {
    pub(crate) token: String,
}

#[cfg(any(feature = "_sender-http", feature = "_sender-qwp-ws"))]
impl TokenAuthParams {
    pub(crate) fn to_header_string(&self) -> crate::Result<String> {
        if self.token.contains('\n') {
            return Err(crate::error::fmt!(
                AuthError,
                "Bad auth token: Should not contain new-line char."
            ));
        }
        Ok(format!("Bearer {}", self.token))
    }
}

#[cfg(feature = "_sender-tcp")]
#[derive(PartialEq, Debug, Clone)]
pub(crate) struct EcdsaAuthParams {
    pub(crate) key_id: String,
    pub(crate) priv_key: String,
    pub(crate) pub_key_x: String,
    pub(crate) pub_key_y: String,
}

#[derive(PartialEq, Debug, Clone)]
pub(crate) enum AuthParams {
    #[cfg(feature = "_sender-tcp")]
    Ecdsa(EcdsaAuthParams),

    #[cfg(any(feature = "_sender-http", feature = "_sender-qwp-ws"))]
    Basic(BasicAuthParams),

    #[cfg(any(feature = "_sender-http", feature = "_sender-qwp-ws"))]
    Token(TokenAuthParams),
}
