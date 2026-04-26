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

//! Reader configuration.
//!
//! Connect-string format mirrors the ingress sender's:
//!
//! ```text
//! qwp::addr=host:port;key=value;key=value;...
//! qwps::addr=host:port;...    # TLS (wss://)
//! ```
//!
//! Recognised keys (defaults shown in parentheses):
//!
//! | Key                | Notes                                                    |
//! |--------------------|----------------------------------------------------------|
//! | `addr`             | required; `host:port` or `host`                          |
//! | `path`             | endpoint path (`/read/v1`)                               |
//! | `max_version`      | QWP version to advertise (`2`)                           |
//! | `compression`      | `raw` only for now (`zstd`/`auto` not yet decoded) (`raw`) |
//! | `max_batch_rows`   | sent only when non-zero (`0` = server default)           |
//! | `client_id`        | optional; sent only when set                             |
//! | `durable_ack`      | `true`/`false` (`false`)                                 |
//! | `target`           | `any`/`primary`/`replica` (Phase 1: parsed but unused)   |
//! | `username`         | basic auth                                               |
//! | `password`         | basic auth                                               |
//! | `token`            | bearer / OIDC                                            |
//! | `auth`             | verbatim Authorization value                             |
//! | `tls_verify`       | `on`/`unsafe_off` (`on`)                                 |
//! | `tls_roots`        | path to a PEM bundle                                     |
//! | `tls_roots_password` | password for the PEM bundle                             |

use std::str::FromStr;

use crate::egress::auth::AuthMode;
use crate::egress::error::{Result, fmt};

/// Default endpoint path (mirrors the Java client).
pub const DEFAULT_PATH: &str = "/read/v1";

/// Highest QWP version this client can speak.
pub const HIGHEST_KNOWN_VERSION: u8 = 2;

/// Default WS port (matches QuestDB HTTP / ILP-HTTP convention).
const DEFAULT_PLAIN_PORT: &str = "9000";
const DEFAULT_TLS_PORT: &str = "9000";

/// Compression negotiation vocabulary.
///
/// `Auto` advertises both `zstd,raw`; `Raw` advertises only `raw`. Only
/// `Raw` is currently usable end-to-end because the decoder hasn't
/// implemented zstd payload decompression yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    Raw,
    Zstd,
    Auto,
}

impl Compression {
    /// Wire token for the `X-QWP-Accept-Encoding` header.
    pub fn header_token(self) -> &'static str {
        match self {
            Compression::Raw => "raw",
            Compression::Zstd => "zstd",
            Compression::Auto => "zstd,raw",
        }
    }
}

/// Server-routing target hint (negotiation only — no failover yet).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Any,
    Primary,
    Replica,
}

/// TLS verification policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVerify {
    On,
    /// Insecure-skip-verify; only honoured when the `insecure-skip-verify`
    /// crate feature is enabled.
    UnsafeOff,
}

/// Fully validated reader configuration.
#[derive(Debug, Clone)]
pub struct ReaderConfig {
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub path: String,
    pub max_version: u8,
    pub compression: Compression,
    pub max_batch_rows: u64,
    pub client_id: Option<String>,
    pub durable_ack: bool,
    pub target: Target,
    pub auth: AuthMode,
    pub tls_verify: TlsVerify,
    pub tls_roots: Option<String>,
    pub tls_roots_password: Option<String>,
}

impl ReaderConfig {
    /// Construct from a connect-string.
    pub fn from_conf<T: AsRef<str>>(conf: T) -> Result<Self> {
        let conf_str = conf.as_ref();
        let conf = questdb_confstr::parse_conf_str(conf_str)
            .map_err(|e| fmt!(ConfigError, "Config parse error: {}", e))?;
        let scheme = conf.service();
        let tls = match scheme {
            "qwp" => false,
            "qwps" => true,
            other => {
                return Err(fmt!(
                    ConfigError,
                    "Unknown scheme \"{}\" — expected \"qwp\" or \"qwps\"",
                    other
                ));
            }
        };
        let params = conf.params();

        // Required: addr
        let addr = params.get("addr").ok_or_else(|| {
            fmt!(ConfigError, "Missing \"addr\" parameter in config string")
        })?;
        let (host, port_str) = match addr.split_once(':') {
            Some((h, p)) => (h.to_string(), p.to_string()),
            None => (
                addr.clone(),
                if tls {
                    DEFAULT_TLS_PORT.to_string()
                } else {
                    DEFAULT_PLAIN_PORT.to_string()
                },
            ),
        };
        if host.is_empty() {
            return Err(fmt!(ConfigError, "Empty host in \"addr\" parameter"));
        }
        let port: u16 = port_str
            .parse()
            .map_err(|_| fmt!(ConfigError, "Invalid port in \"addr\": {}", port_str))?;

        // Optional / typed
        let mut path: String = DEFAULT_PATH.to_string();
        let mut max_version: u8 = HIGHEST_KNOWN_VERSION;
        let mut compression = Compression::Raw;
        let mut max_batch_rows: u64 = 0;
        let mut client_id: Option<String> = None;
        let mut durable_ack = false;
        let mut target = Target::Any;
        let mut tls_verify = TlsVerify::On;
        let mut tls_roots: Option<String> = None;
        let mut tls_roots_password: Option<String> = None;

        let mut username: Option<String> = None;
        let mut password: Option<String> = None;
        let mut token: Option<String> = None;
        let mut auth_verbatim: Option<String> = None;

        for (key, val) in params.iter() {
            let key = key.as_str();
            let val = val.as_str();
            match key {
                "addr" => {} // already consumed
                "path" => {
                    if !val.starts_with('/') {
                        return Err(fmt!(
                            ConfigError,
                            "\"path\" must start with '/' (got {:?})",
                            val
                        ));
                    }
                    path = val.to_string();
                }
                "max_version" => {
                    let v: u8 = parse_value("max_version", val)?;
                    if v == 0 {
                        return Err(fmt!(ConfigError, "\"max_version\" must be >= 1"));
                    }
                    max_version = v;
                }
                "compression" => {
                    compression = match val {
                        "raw" => Compression::Raw,
                        "zstd" => Compression::Zstd,
                        "auto" => Compression::Auto,
                        other => {
                            return Err(fmt!(
                                ConfigError,
                                "\"compression\" must be one of raw|zstd|auto (got {:?})",
                                other
                            ));
                        }
                    };
                }
                "max_batch_rows" => {
                    max_batch_rows = parse_value("max_batch_rows", val)?;
                }
                "client_id" => {
                    if val.contains('\n') || val.contains('\r') {
                        return Err(fmt!(
                            ConfigError,
                            "\"client_id\" must not contain CR or LF"
                        ));
                    }
                    client_id = Some(val.to_string());
                }
                "durable_ack" => {
                    durable_ack = parse_bool("durable_ack", val)?;
                }
                "target" => {
                    target = match val {
                        "any" => Target::Any,
                        "primary" => Target::Primary,
                        "replica" => Target::Replica,
                        other => {
                            return Err(fmt!(
                                ConfigError,
                                "\"target\" must be one of any|primary|replica (got {:?})",
                                other
                            ));
                        }
                    };
                }
                "username" => username = Some(val.to_string()),
                "password" => password = Some(val.to_string()),
                "token" => token = Some(val.to_string()),
                "auth" => auth_verbatim = Some(val.to_string()),
                "tls_verify" => {
                    tls_verify = match val {
                        "on" => TlsVerify::On,
                        "unsafe_off" => TlsVerify::UnsafeOff,
                        other => {
                            return Err(fmt!(
                                ConfigError,
                                "\"tls_verify\" must be \"on\" or \"unsafe_off\" (got {:?})",
                                other
                            ));
                        }
                    };
                }
                "tls_roots" => tls_roots = Some(val.to_string()),
                "tls_roots_password" => tls_roots_password = Some(val.to_string()),

                // Failover keys aren't wired through Phase 1; accept and ignore.
                "failover" | "failover_max_attempts" | "failover_backoff_initial_ms"
                | "failover_backoff_max_ms" => {}

                other => {
                    return Err(fmt!(
                        ConfigError,
                        "Unknown config key \"{}\"",
                        other
                    ));
                }
            }
        }

        // Compression we can actually decode end-to-end is currently `raw` only.
        if !matches!(compression, Compression::Raw) {
            return Err(fmt!(
                ConfigError,
                "\"compression\" {:?} is not yet supported by this client; use \"raw\"",
                compression.header_token()
            ));
        }

        // tls_verify=unsafe_off needs the crate feature.
        #[cfg(not(feature = "insecure-skip-verify"))]
        {
            if matches!(tls_verify, TlsVerify::UnsafeOff) {
                return Err(fmt!(
                    ConfigError,
                    "\"tls_verify=unsafe_off\" requires the \"insecure-skip-verify\" crate feature"
                ));
            }
        }

        // tls_* knobs only make sense with TLS scheme.
        if !tls && (tls_roots.is_some() || tls_roots_password.is_some()) {
            return Err(fmt!(
                ConfigError,
                "TLS-related keys require the \"qwps\" scheme"
            ));
        }

        let auth = AuthMode::from_parts(
            username.as_deref(),
            password.as_deref(),
            token.as_deref(),
            auth_verbatim.as_deref(),
        )?;

        Ok(ReaderConfig {
            host,
            port,
            tls,
            path,
            max_version,
            compression,
            max_batch_rows,
            client_id,
            durable_ack,
            target,
            auth,
            tls_verify,
            tls_roots,
            tls_roots_password,
        })
    }

    /// Build the URL for the WebSocket upgrade.
    pub fn url(&self) -> String {
        let scheme = if self.tls { "wss" } else { "ws" };
        format!("{}://{}:{}{}", scheme, self.host, self.port, self.path)
    }

    /// Build the negotiation headers as `(name, value)` pairs in the order
    /// the Java reference client emits them. Authorization is appended last
    /// when an auth mode is set.
    pub fn upgrade_headers(&self) -> Vec<(&'static str, String)> {
        let mut headers = Vec::with_capacity(8);
        headers.push(("X-QWP-Max-Version", self.max_version.to_string()));
        if let Some(id) = &self.client_id {
            headers.push(("X-QWP-Client-Id", id.clone()));
        }
        // Always emit accept-encoding so the server knows what we'll handle;
        // raw-only today still benefits from being explicit.
        headers.push((
            "X-QWP-Accept-Encoding",
            self.compression.header_token().to_string(),
        ));
        if self.max_batch_rows > 0 {
            headers.push(("X-QWP-Max-Batch-Rows", self.max_batch_rows.to_string()));
        }
        if self.durable_ack {
            headers.push(("X-QWP-Request-Durable-Ack", "true".to_string()));
        }
        if let Some(v) = self.auth.header_value() {
            headers.push(("Authorization", v));
        }
        headers
    }
}

fn parse_value<T>(name: &str, raw: &str) -> Result<T>
where
    T: FromStr,
{
    raw.parse::<T>().map_err(|_| {
        fmt!(
            ConfigError,
            "Could not parse \"{}\" value: {:?}",
            name,
            raw
        )
    })
}

fn parse_bool(name: &str, raw: &str) -> Result<bool> {
    match raw {
        "true" | "on" | "yes" | "1" => Ok(true),
        "false" | "off" | "no" | "0" => Ok(false),
        _ => Err(fmt!(
            ConfigError,
            "\"{}\" must be a boolean (got {:?})",
            name,
            raw
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress::error::ErrorCode;

    #[test]
    fn minimal_plain_conf() {
        let c = ReaderConfig::from_conf("qwp::addr=localhost:9000").unwrap();
        assert_eq!(c.host, "localhost");
        assert_eq!(c.port, 9000);
        assert!(!c.tls);
        assert_eq!(c.path, DEFAULT_PATH);
        assert_eq!(c.max_version, HIGHEST_KNOWN_VERSION);
        assert_eq!(c.compression, Compression::Raw);
        assert_eq!(c.url(), "ws://localhost:9000/read/v1");
    }

    #[test]
    fn tls_scheme_changes_url() {
        let c = ReaderConfig::from_conf("qwps::addr=h:8443").unwrap();
        assert!(c.tls);
        assert_eq!(c.url(), "wss://h:8443/read/v1");
    }

    #[test]
    fn unknown_scheme_rejected() {
        let err = ReaderConfig::from_conf("http::addr=h:1").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
    }

    #[test]
    fn missing_addr_rejected() {
        let err = ReaderConfig::from_conf("qwp::path=/read/v1").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
    }

    #[test]
    fn unknown_key_rejected() {
        let err = ReaderConfig::from_conf("qwp::addr=h:1;mystery=x").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
    }

    #[test]
    fn basic_auth_in_conf() {
        let c =
            ReaderConfig::from_conf("qwp::addr=h:1;username=admin;password=quest").unwrap();
        assert_eq!(
            c.auth.header_value(),
            Some("Basic YWRtaW46cXVlc3Q=".to_string())
        );
    }

    #[test]
    fn bearer_in_conf() {
        let c = ReaderConfig::from_conf("qwp::addr=h:1;token=tok").unwrap();
        assert_eq!(c.auth.header_value(), Some("Bearer tok".to_string()));
    }

    #[test]
    fn auth_modes_mutually_exclusive() {
        let err = ReaderConfig::from_conf(
            "qwp::addr=h:1;username=u;password=p;token=t",
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
    }

    #[test]
    fn compression_zstd_rejected_for_now() {
        let err = ReaderConfig::from_conf("qwp::addr=h:1;compression=zstd").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
        let err = ReaderConfig::from_conf("qwp::addr=h:1;compression=auto").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
    }

    #[test]
    fn invalid_compression_value() {
        let err = ReaderConfig::from_conf("qwp::addr=h:1;compression=xyz").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
    }

    #[test]
    fn target_parses() {
        let c = ReaderConfig::from_conf("qwp::addr=h:1;target=primary").unwrap();
        assert_eq!(c.target, Target::Primary);
    }

    #[test]
    fn target_invalid_rejected() {
        let err = ReaderConfig::from_conf("qwp::addr=h:1;target=leader").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
    }

    #[test]
    fn upgrade_headers_default() {
        let c = ReaderConfig::from_conf("qwp::addr=h:1").unwrap();
        let h = c.upgrade_headers();
        // Always emit max_version + accept-encoding; nothing else by default.
        assert_eq!(h.len(), 2);
        assert_eq!(h[0], ("X-QWP-Max-Version", "2".to_string()));
        assert_eq!(h[1], ("X-QWP-Accept-Encoding", "raw".to_string()));
    }

    #[test]
    fn upgrade_headers_full_set() {
        let c = ReaderConfig::from_conf(
            "qwp::addr=h:1;client_id=app1;max_batch_rows=1000;durable_ack=true;username=u;password=p",
        )
        .unwrap();
        let h = c.upgrade_headers();
        let names: Vec<_> = h.iter().map(|(n, _)| *n).collect();
        assert!(names.contains(&"X-QWP-Max-Version"));
        assert!(names.contains(&"X-QWP-Client-Id"));
        assert!(names.contains(&"X-QWP-Accept-Encoding"));
        assert!(names.contains(&"X-QWP-Max-Batch-Rows"));
        assert!(names.contains(&"X-QWP-Request-Durable-Ack"));
        assert!(names.contains(&"Authorization"));

        // max_batch_rows omitted when 0.
        let c = ReaderConfig::from_conf("qwp::addr=h:1;max_batch_rows=0").unwrap();
        let h = c.upgrade_headers();
        assert!(h.iter().all(|(n, _)| *n != "X-QWP-Max-Batch-Rows"));
    }

    #[test]
    fn path_must_start_with_slash() {
        let err = ReaderConfig::from_conf("qwp::addr=h:1;path=read/v1").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
    }

    #[test]
    fn default_port_when_omitted() {
        let c = ReaderConfig::from_conf("qwp::addr=localhost").unwrap();
        assert_eq!(c.port, 9000);
    }

    #[test]
    fn invalid_port_rejected() {
        let err = ReaderConfig::from_conf("qwp::addr=h:notaport").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
    }

    #[test]
    fn tls_keys_with_plain_scheme_rejected() {
        let err = ReaderConfig::from_conf("qwp::addr=h:1;tls_roots=/tmp/x").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
    }

    #[test]
    fn durable_ack_synonyms() {
        for v in &["true", "on", "yes", "1"] {
            let c = ReaderConfig::from_conf(&format!("qwp::addr=h:1;durable_ack={};", v))
                .unwrap();
            assert!(c.durable_ack, "{}", v);
        }
        for v in &["false", "off", "no", "0"] {
            let c = ReaderConfig::from_conf(&format!("qwp::addr=h:1;durable_ack={};", v))
                .unwrap();
            assert!(!c.durable_ack, "{}", v);
        }
    }

    #[test]
    fn failover_keys_accepted_silently() {
        // Phase 1: parse but don't act.
        let c = ReaderConfig::from_conf(
            "qwp::addr=h:1;failover=on;failover_max_attempts=3;failover_backoff_initial_ms=100;failover_backoff_max_ms=2000",
        )
        .unwrap();
        assert_eq!(c.host, "h");
    }
}
