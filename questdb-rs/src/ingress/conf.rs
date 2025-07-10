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

use crate::error::{fmt, Error, ErrorCode, Result};
use std::ops::Deref;

#[cfg(feature = "_sender-http")]
pub(crate) const SETTINGS_RETRY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

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

#[cfg(feature = "_sender-http")]
#[derive(PartialEq, Debug, Clone)]
pub(crate) struct BasicAuthParams {
    pub(crate) username: String,
    pub(crate) password: String,
}

#[cfg(feature = "_sender-http")]
impl BasicAuthParams {
    pub(crate) fn to_header_string(&self) -> String {
        use base64ct::{Base64, Encoding};
        let pair = format!("{}:{}", self.username, self.password);
        let encoded = Base64::encode_string(pair.as_bytes());
        format!("Basic {encoded}")
    }
}

#[cfg(feature = "_sender-http")]
#[derive(PartialEq, Debug, Clone)]
pub(crate) struct TokenAuthParams {
    pub(crate) token: String,
}

#[cfg(feature = "_sender-http")]
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

    #[cfg(feature = "_sender-http")]
    Basic(BasicAuthParams),

    #[cfg(feature = "_sender-http")]
    Token(TokenAuthParams),
}

#[cfg(feature = "_sender-http")]
pub fn auth_params_to_header_string(auth: &Option<AuthParams>) -> Result<Option<String>> {
    Ok(match auth {
        Some(AuthParams::Basic(ref auth)) => Some(auth.to_header_string()),
        Some(AuthParams::Token(ref auth)) => Some(auth.to_header_string()?),

        #[cfg(feature = "sync-sender-tcp")]
        Some(AuthParams::Ecdsa(_)) => {
            return Err(fmt!(
                AuthError,
                "ECDSA authentication is not supported for ILP over HTTP. \
                Please use basic or token authentication instead."
            ));
        }
        None => None,
    })
}

#[cfg(feature = "_sender-http")]
pub(crate) fn parse_server_settings(
    response: &str,
    settings_url: &str,
    default_protocol_version: crate::ingress::ProtocolVersion,
    default_max_name_len: usize,
) -> crate::error::Result<(Vec<crate::ingress::ProtocolVersion>, usize)> {
    use crate::ingress::ProtocolVersion;

    let json: serde_json::Value = serde_json::from_str(response).map_err(|_| {
        crate::error::fmt!(
            ProtocolVersionError,
            "Malformed server response, settings url: {}, err: response is not valid JSON.",
            settings_url,
        )
    })?;

    let mut support_versions: Vec<ProtocolVersion> = vec![];
    if let Some(serde_json::Value::Array(ref values)) = json
        .get("config")
        .and_then(|v| v.get("line.proto.support.versions"))
    {
        for value in values.iter() {
            if let Some(v) = value.as_u64() {
                match v {
                    1 => support_versions.push(ProtocolVersion::V1),
                    2 => support_versions.push(ProtocolVersion::V2),
                    _ => {}
                }
            }
        }
    } else {
        support_versions.push(default_protocol_version);
    }

    let max_name_length = json
        .get("config")
        .and_then(|v| v.get("cairo.max.file.name.length"))
        .and_then(|v| v.as_u64())
        .unwrap_or(default_max_name_len as u64) as usize;
    Ok((support_versions, max_name_length))
}
