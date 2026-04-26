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

//! HTTP `Authorization` header construction for the QWP read endpoint.
//!
//! Mirrors the Java client's three modes — Basic, Bearer/OIDC, and a
//! verbatim escape hatch — and rejects any combination as a config error.

use base64ct::{Base64, Encoding};

use crate::egress::error::{Result, fmt};

/// Authentication mode for the WebSocket upgrade request.
///
/// All three forms produce a single `Authorization` header value; the
/// server (which shares its user store with the Postgres wire protocol)
/// validates from there. Modes are mutually exclusive — see
/// [`AuthMode::from_parts`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthMode {
    /// No `Authorization` header sent.
    None,
    /// HTTP Basic: `Basic base64(user:password)`.
    Basic { username: String, password: String },
    /// Bearer / OIDC: `Bearer <access_token>`.
    Bearer { token: String },
    /// Escape hatch: emit the value as-is.
    Verbatim { value: String },
}

impl AuthMode {
    /// Build from connect-string fragments. At most one may be set.
    pub fn from_parts(
        username: Option<&str>,
        password: Option<&str>,
        token: Option<&str>,
        verbatim: Option<&str>,
    ) -> Result<Self> {
        let basic_partial = username.is_some() ^ password.is_some();
        if basic_partial {
            return Err(fmt!(
                ConfigError,
                "Basic auth requires both \"username\" and \"password\""
            ));
        }
        let basic_set = username.is_some() && password.is_some();
        let token_set = token.is_some();
        let verbatim_set = verbatim.is_some();
        let count = (basic_set as u8) + (token_set as u8) + (verbatim_set as u8);
        if count > 1 {
            return Err(fmt!(
                ConfigError,
                "Auth modes are mutually exclusive; pick at most one of (username/password), token, or auth"
            ));
        }
        if basic_set {
            return Ok(AuthMode::Basic {
                username: username.unwrap().to_string(),
                password: password.unwrap().to_string(),
            });
        }
        if let Some(t) = token {
            if t.contains('\n') || t.contains('\r') {
                return Err(fmt!(
                    AuthError,
                    "Bearer token must not contain CR or LF characters"
                ));
            }
            return Ok(AuthMode::Bearer {
                token: t.to_string(),
            });
        }
        if let Some(v) = verbatim {
            if v.contains('\n') || v.contains('\r') {
                return Err(fmt!(
                    AuthError,
                    "verbatim auth value must not contain CR or LF characters"
                ));
            }
            return Ok(AuthMode::Verbatim {
                value: v.to_string(),
            });
        }
        Ok(AuthMode::None)
    }

    /// Render the `Authorization` header value, if any.
    pub fn header_value(&self) -> Option<String> {
        match self {
            AuthMode::None => None,
            AuthMode::Basic { username, password } => {
                let pair = format!("{}:{}", username, password);
                let encoded = Base64::encode_string(pair.as_bytes());
                Some(format!("Basic {}", encoded))
            }
            AuthMode::Bearer { token } => Some(format!("Bearer {}", token)),
            AuthMode::Verbatim { value } => Some(value.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress::error::ErrorCode;

    #[test]
    fn none_when_nothing_set() {
        let m = AuthMode::from_parts(None, None, None, None).unwrap();
        assert_eq!(m, AuthMode::None);
        assert_eq!(m.header_value(), None);
    }

    #[test]
    fn basic_header_format() {
        let m = AuthMode::from_parts(Some("admin"), Some("quest"), None, None).unwrap();
        // base64("admin:quest") = YWRtaW46cXVlc3Q=
        assert_eq!(m.header_value().unwrap(), "Basic YWRtaW46cXVlc3Q=");
    }

    #[test]
    fn bearer_header_format() {
        let m = AuthMode::from_parts(None, None, Some("eyJhbGciOi"), None).unwrap();
        assert_eq!(m.header_value().unwrap(), "Bearer eyJhbGciOi");
    }

    #[test]
    fn verbatim_header_format() {
        let m = AuthMode::from_parts(None, None, None, Some("Custom xyz")).unwrap();
        assert_eq!(m.header_value().unwrap(), "Custom xyz");
    }

    #[test]
    fn basic_partial_rejected() {
        let err = AuthMode::from_parts(Some("u"), None, None, None).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
        let err = AuthMode::from_parts(None, Some("p"), None, None).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
    }

    #[test]
    fn mutually_exclusive() {
        let err = AuthMode::from_parts(Some("u"), Some("p"), Some("t"), None).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
        let err = AuthMode::from_parts(None, None, Some("t"), Some("v")).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
        let err = AuthMode::from_parts(Some("u"), Some("p"), None, Some("v")).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
    }

    #[test]
    fn token_with_newline_rejected() {
        let err = AuthMode::from_parts(None, None, Some("a\nb"), None).unwrap_err();
        assert_eq!(err.code(), ErrorCode::AuthError);
    }

    #[test]
    fn verbatim_with_cr_rejected() {
        let err = AuthMode::from_parts(None, None, None, Some("a\rb")).unwrap_err();
        assert_eq!(err.code(), ErrorCode::AuthError);
    }
}
