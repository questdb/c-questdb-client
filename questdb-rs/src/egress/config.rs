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
//! | `compression`      | `raw` / `zstd` / `auto` — `zstd`/`auto` require the `compression-zstd` feature (`raw`) |
//! | `max_batch_rows`   | sent only when non-zero (`0` = server default)           |
//! | `client_id`        | optional; sent only when set                             |
//! | `durable_ack`      | `true`/`false` (`false`)                                 |
//! | `target`           | `any`/`primary`/`replica` (default `any`)                |
//! | `failover`         | `true`/`false` — mid-query reconnect on transport failure (`true`) |
//! | `failover_max_attempts`        | retry attempts after a transport failure (`8`, must be `>= 1`); ignored when `failover=off` |
//! | `failover_backoff_initial_ms`  | initial backoff between attempts (`50`); ignored when `failover=off` |
//! | `failover_backoff_max_ms`      | max backoff between attempts (`1000`); ignored when `failover=off` |
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

/// Server-routing target hint. Drives both connect-time endpoint walking
/// and mid-query failover endpoint selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Any,
    Primary,
    Replica,
}

/// A `host:port` endpoint as parsed from a connect string. Used in
/// the [`ReaderConfig::addrs`] list and surfaced to user code via
/// [`crate::egress::FailoverEvent`] and [`crate::egress::Reader::current_addr`].
///
/// Named struct (rather than a `(String, u16)` tuple) so callers can
/// write `ev.failed_addr.host` / `ep.port` instead of the opaque `.0`
/// / `.1` accessors. Cheap to clone (small `String` plus `u16`); the
/// few hot paths that build many of these per failover go through
/// the underlying `Vec<Endpoint>` directly to avoid extra clones.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}

impl Endpoint {
    /// Construct an endpoint from any string-like host and a port.
    ///
    /// The host is taken verbatim — no DNS resolution, no
    /// IPv6 bracket-stripping. Round-tripping through
    /// [`Display`](std::fmt::Display) re-introduces brackets only
    /// when the host already contains a `:` (so an IPv6 literal
    /// formats as `[::1]:9000` while a hostname or IPv4 stays
    /// `host:port`).
    pub fn new<S: Into<String>>(host: S, port: u16) -> Self {
        Endpoint {
            host: host.into(),
            port,
        }
    }
}

/// Format as `host:port`. Hosts that contain a `:` (IPv6 literals)
/// are bracketed — `[::1]:9000` — so the output round-trips
/// unambiguously through the standard authority-component grammar
/// (RFC 3986 §3.2.2). Hostnames, IPv4 literals, and any host without
/// a colon format unbracketed for the common case.
impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

/// Default failover knobs. Match the Java `QwpQueryClient` reference
/// (`DEFAULT_FAILOVER_*` constants) so connect strings behave the same
/// in either client.
pub const DEFAULT_FAILOVER_ENABLED: bool = true;
pub const DEFAULT_FAILOVER_MAX_ATTEMPTS: u32 = 8;
pub const DEFAULT_FAILOVER_BACKOFF_INITIAL_MS: u64 = 50;
pub const DEFAULT_FAILOVER_BACKOFF_MAX_MS: u64 = 1_000;

/// Hard upper bound on `failover_max_attempts`. Defensive: at the
/// minute-scale this is far past where extending the retry budget
/// stops being useful, and combined with [`MAX_ADDRS`] it keeps the
/// address-rotation arithmetic
/// `(failed_idx + 1 + attempt as usize) % n` safely inside `usize`
/// on 32-bit targets. Java doesn't cap explicitly; this cap is well
/// above any realistic config.
pub const MAX_FAILOVER_MAX_ATTEMPTS: u32 = 1024;

/// Hard upper bound on the parsed address-list length. Real connect
/// strings target a single cluster (a handful of endpoints); this
/// cap exists so the address-rotation arithmetic in
/// [`crate::egress::Reader::reconnect_with_failover`]
/// (`(failed_idx + 1 + attempt as usize) % n`) is provably free of
/// `usize` overflow on 32-bit targets given
/// [`MAX_FAILOVER_MAX_ATTEMPTS`]. Without this cap the "32-bit
/// safety" claim was a soft assertion that nothing actually
/// enforced.
pub const MAX_ADDRS: usize = 1024;

/// Hard upper bound on `failover_backoff_max_ms`. Caps a misconfigured
/// connect string from issuing multi-hour `thread::sleep` calls
/// during a failover storm. One hour is far past any operationally
/// useful backoff — beyond this, the user wants application-level
/// circuit breaking, not transport-level retry.
pub const MAX_FAILOVER_BACKOFF_MAX_MS: u64 = 60 * 60 * 1_000;

/// TLS verification policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVerify {
    On,
    /// Insecure-skip-verify; only honoured when the `insecure-skip-verify`
    /// crate feature is enabled.
    UnsafeOff,
}

/// Fully validated reader configuration.
///
/// Marked `#[non_exhaustive]` so future config knobs (and there will
/// be more — the failover/auth/TLS surfaces are still maturing) can
/// be added without breaking downstream code that pattern-matches
/// or struct-literals this type. Construct via [`Self::from_conf`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ReaderConfig {
    /// Endpoints to walk on connect, in order. The Reader tries each
    /// until one accepts the WS handshake and (when v2) advertises a
    /// role matching `target`.
    ///
    /// Crate-private to keep external code from mutating the address
    /// list after a `Reader` has been built around an `Arc<ReaderConfig>`
    /// snapshot. Read-only access is via [`Self::addrs`].
    pub(crate) addrs: Vec<Endpoint>,
    pub tls: bool,
    pub path: String,
    pub max_version: u8,
    pub compression: Compression,
    pub max_batch_rows: u64,
    pub client_id: Option<String>,
    pub durable_ack: bool,
    pub target: Target,
    /// Mid-query failover. When `true` and the transport fails after a
    /// `QUERY_REQUEST` has been submitted, the cursor reconnects to the
    /// next endpoint (rotating, skipping the failed one first), replays
    /// the query with a fresh `request_id`, and resumes from `batch_seq=0`
    /// on the new connection. The user-side handler must reset any
    /// accumulated rows when notified via the
    /// [`ReaderQuery::on_failover_reset`](crate::egress::ReaderQuery::on_failover_reset)
    /// callback.
    ///
    /// When `false`, the `failover_*` tunables below are accepted by
    /// the parser (so configs aren't rejected on a partial enable/disable
    /// flip) but have no effect — transport failures surface immediately.
    pub failover: bool,
    /// Number of retry attempts after a transport failure (default `8`).
    /// Total of `1 + failover_max_attempts` connect attempts before the
    /// failure is propagated. Must be `>= 1`. Ignored when
    /// [`failover`](Self::failover) is `false`.
    pub failover_max_attempts: u32,
    /// Initial backoff between failover attempts, in milliseconds.
    /// Ignored when [`failover`](Self::failover) is `false`.
    pub failover_backoff_initial_ms: u64,
    /// Maximum (capped) backoff between failover attempts, in milliseconds.
    /// Ignored when [`failover`](Self::failover) is `false`.
    pub failover_backoff_max_ms: u64,
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

        // Required: addr (single `host[:port]` or comma-separated list)
        let addr = params
            .get("addr")
            .ok_or_else(|| fmt!(ConfigError, "Missing \"addr\" parameter in config string"))?;
        let default_port = if tls {
            DEFAULT_TLS_PORT
        } else {
            DEFAULT_PLAIN_PORT
        };
        let mut addrs: Vec<Endpoint> = Vec::new();
        for (i, entry) in addr.split(',').map(str::trim).enumerate() {
            if entry.is_empty() {
                return Err(fmt!(ConfigError, "Empty entry {} in \"addr\" list", i));
            }
            let (host, port_str) = match entry.rsplit_once(':') {
                Some((h, p)) => (h.to_string(), p.to_string()),
                None => (entry.to_string(), default_port.to_string()),
            };
            if host.is_empty() {
                return Err(fmt!(
                    ConfigError,
                    "Empty host in \"addr\" entry {}: {:?}",
                    i,
                    entry
                ));
            }
            let port: u16 = port_str.parse().map_err(|_| {
                fmt!(
                    ConfigError,
                    "Invalid port in \"addr\" entry {}: {:?}",
                    i,
                    entry
                )
            })?;
            addrs.push(Endpoint { host, port });
        }
        if addrs.is_empty() {
            return Err(fmt!(ConfigError, "\"addr\" parameter is empty"));
        }
        if addrs.len() > MAX_ADDRS {
            return Err(fmt!(
                ConfigError,
                "\"addr\" list length {} exceeds the hard cap of {}",
                addrs.len(),
                MAX_ADDRS
            ));
        }

        // Optional / typed
        let mut path: String = DEFAULT_PATH.to_string();
        let mut max_version: u8 = HIGHEST_KNOWN_VERSION;
        let mut compression = Compression::Raw;
        let mut max_batch_rows: u64 = 0;
        let mut client_id: Option<String> = None;
        let mut durable_ack = false;
        let mut target = Target::Any;
        let mut failover = DEFAULT_FAILOVER_ENABLED;
        let mut failover_max_attempts: u32 = DEFAULT_FAILOVER_MAX_ATTEMPTS;
        let mut failover_backoff_initial_ms: u64 = DEFAULT_FAILOVER_BACKOFF_INITIAL_MS;
        let mut failover_backoff_max_ms: u64 = DEFAULT_FAILOVER_BACKOFF_MAX_MS;
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
                        return Err(fmt!(ConfigError, "\"client_id\" must not contain CR or LF"));
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

                "failover" => {
                    failover = parse_bool("failover", val)?;
                }
                "failover_max_attempts" => {
                    failover_max_attempts = parse_value("failover_max_attempts", val)?;
                }
                "failover_backoff_initial_ms" => {
                    failover_backoff_initial_ms = parse_value("failover_backoff_initial_ms", val)?;
                }
                "failover_backoff_max_ms" => {
                    failover_backoff_max_ms = parse_value("failover_backoff_max_ms", val)?;
                }

                other => {
                    return Err(fmt!(ConfigError, "Unknown config key \"{}\"", other));
                }
            }
        }

        // zstd / auto require the compression-zstd feature.
        #[cfg(not(feature = "compression-zstd"))]
        {
            if !matches!(compression, Compression::Raw) {
                let user_token = match compression {
                    Compression::Raw => "raw",
                    Compression::Zstd => "zstd",
                    Compression::Auto => "auto",
                };
                return Err(fmt!(
                    ConfigError,
                    "\"compression={}\" requires the `compression-zstd` crate feature; \
                     either enable it or use \"raw\"",
                    user_token
                ));
            }
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

        if failover_max_attempts == 0 {
            return Err(fmt!(
                ConfigError,
                "\"failover_max_attempts\" must be >= 1 (use \"failover=off\" to disable failover entirely)"
            ));
        }
        if failover_max_attempts > MAX_FAILOVER_MAX_ATTEMPTS {
            return Err(fmt!(
                ConfigError,
                "\"failover_max_attempts\" {} exceeds the hard cap of {}",
                failover_max_attempts,
                MAX_FAILOVER_MAX_ATTEMPTS
            ));
        }
        if failover_backoff_initial_ms == 0 {
            return Err(fmt!(
                ConfigError,
                "\"failover_backoff_initial_ms\" must be > 0"
            ));
        }
        if failover_backoff_max_ms < failover_backoff_initial_ms {
            return Err(fmt!(
                ConfigError,
                "\"failover_backoff_max_ms\" ({}) must be >= \"failover_backoff_initial_ms\" ({})",
                failover_backoff_max_ms,
                failover_backoff_initial_ms
            ));
        }
        if failover_backoff_max_ms > MAX_FAILOVER_BACKOFF_MAX_MS {
            return Err(fmt!(
                ConfigError,
                "\"failover_backoff_max_ms\" {} exceeds the hard cap of {} (1 hour)",
                failover_backoff_max_ms,
                MAX_FAILOVER_BACKOFF_MAX_MS
            ));
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
            addrs,
            tls,
            path,
            max_version,
            compression,
            max_batch_rows,
            client_id,
            durable_ack,
            target,
            failover,
            failover_max_attempts,
            failover_backoff_initial_ms,
            failover_backoff_max_ms,
            auth,
            tls_verify,
            tls_roots,
            tls_roots_password,
        })
    }

    /// Read-only view of the parsed endpoint list. The list is populated
    /// by [`from_conf`](Self::from_conf) and frozen for the lifetime of
    /// the config — this getter is the only public access path.
    pub fn addrs(&self) -> &[Endpoint] {
        &self.addrs
    }

    /// Build the URL for the WebSocket upgrade against the endpoint at
    /// `idx` in [`addrs`](Self::addrs). Panics if `idx` is out of range.
    pub fn url_for(&self, idx: usize) -> String {
        let ep = &self.addrs[idx];
        let scheme = if self.tls { "wss" } else { "ws" };
        // `{ep}` formats as `host:port` (or `[host]:port` for IPv6
        // literals), giving an unambiguous URL authority component.
        format!("{}://{}{}", scheme, ep, self.path)
    }

    /// First endpoint URL — convenience for single-addr configs.
    pub fn url(&self) -> String {
        self.url_for(0)
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
    raw.parse::<T>()
        .map_err(|_| fmt!(ConfigError, "Could not parse \"{}\" value: {:?}", name, raw))
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
        assert_eq!(c.addrs.len(), 1);
        assert_eq!(c.addrs[0], Endpoint::new("localhost", 9000));
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
        let c = ReaderConfig::from_conf("qwp::addr=h:1;username=admin;password=quest").unwrap();
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
        let err =
            ReaderConfig::from_conf("qwp::addr=h:1;username=u;password=p;token=t").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
    }

    #[cfg(not(feature = "compression-zstd"))]
    #[test]
    fn compression_zstd_rejected_without_feature() {
        let err = ReaderConfig::from_conf("qwp::addr=h:1;compression=zstd").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
        let err = ReaderConfig::from_conf("qwp::addr=h:1;compression=auto").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
    }

    #[cfg(feature = "compression-zstd")]
    #[test]
    fn compression_zstd_accepted_with_feature() {
        let c = ReaderConfig::from_conf("qwp::addr=h:1;compression=zstd").unwrap();
        assert_eq!(c.compression, Compression::Zstd);
        let c = ReaderConfig::from_conf("qwp::addr=h:1;compression=auto").unwrap();
        assert_eq!(c.compression, Compression::Auto);
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
    fn multi_addr_parses() {
        let c = ReaderConfig::from_conf("qwp::addr=h1:9000,h2:9001,h3,h4:9999;").unwrap();
        assert_eq!(c.addrs.len(), 4);
        assert_eq!(c.addrs[0], Endpoint::new("h1", 9000));
        assert_eq!(c.addrs[1], Endpoint::new("h2", 9001));
        assert_eq!(c.addrs[2], Endpoint::new("h3", 9000)); // default port
        assert_eq!(c.addrs[3], Endpoint::new("h4", 9999));
    }

    #[test]
    fn empty_addr_entry_rejected() {
        let err = ReaderConfig::from_conf("qwp::addr=h1:9000,,h2:9001;").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
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
        assert_eq!(c.addrs[0].port, 9000);
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
            let c = ReaderConfig::from_conf(format!("qwp::addr=h:1;durable_ack={};", v)).unwrap();
            assert!(c.durable_ack, "{}", v);
        }
        for v in &["false", "off", "no", "0"] {
            let c = ReaderConfig::from_conf(format!("qwp::addr=h:1;durable_ack={};", v)).unwrap();
            assert!(!c.durable_ack, "{}", v);
        }
    }

    #[test]
    fn failover_defaults() {
        let c = ReaderConfig::from_conf("qwp::addr=h:1").unwrap();
        assert!(c.failover);
        assert_eq!(c.failover_max_attempts, DEFAULT_FAILOVER_MAX_ATTEMPTS);
        assert_eq!(
            c.failover_backoff_initial_ms,
            DEFAULT_FAILOVER_BACKOFF_INITIAL_MS
        );
        assert_eq!(c.failover_backoff_max_ms, DEFAULT_FAILOVER_BACKOFF_MAX_MS);
    }

    #[test]
    fn failover_keys_parsed() {
        let c = ReaderConfig::from_conf(
            "qwp::addr=h:1;failover=off;failover_max_attempts=3;failover_backoff_initial_ms=100;failover_backoff_max_ms=2000",
        )
        .unwrap();
        assert!(!c.failover);
        assert_eq!(c.failover_max_attempts, 3);
        assert_eq!(c.failover_backoff_initial_ms, 100);
        assert_eq!(c.failover_backoff_max_ms, 2000);
    }

    #[test]
    fn failover_backoff_initial_zero_rejected() {
        let err =
            ReaderConfig::from_conf("qwp::addr=h:1;failover_backoff_initial_ms=0").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
    }

    #[test]
    fn failover_backoff_max_below_initial_rejected() {
        let err = ReaderConfig::from_conf(
            "qwp::addr=h:1;failover_backoff_initial_ms=500;failover_backoff_max_ms=100",
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
    }

    #[test]
    fn failover_invalid_attempts_rejected() {
        let err = ReaderConfig::from_conf("qwp::addr=h:1;failover_max_attempts=abc").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
    }

    #[test]
    fn failover_max_attempts_above_cap_rejected() {
        let conf = format!(
            "qwp::addr=h:1;failover_max_attempts={}",
            MAX_FAILOVER_MAX_ATTEMPTS + 1
        );
        let err = ReaderConfig::from_conf(&conf).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
        assert!(err.msg().contains("exceeds the hard cap"));
    }

    #[test]
    fn failover_max_attempts_at_cap_accepted() {
        let conf = format!(
            "qwp::addr=h:1;failover_max_attempts={}",
            MAX_FAILOVER_MAX_ATTEMPTS
        );
        let c = ReaderConfig::from_conf(&conf).unwrap();
        assert_eq!(c.failover_max_attempts, MAX_FAILOVER_MAX_ATTEMPTS);
    }

    #[test]
    fn failover_backoff_max_above_cap_rejected() {
        // N6 regression guard: a misconfigured `failover_backoff_max_ms`
        // beyond `MAX_FAILOVER_BACKOFF_MAX_MS` (1 hour) must be
        // rejected at parse time so a failover storm can't burn
        // multi-hour `thread::sleep` calls inside the cursor.
        let conf = format!(
            "qwp::addr=h:1;failover_backoff_initial_ms=1;failover_backoff_max_ms={}",
            MAX_FAILOVER_BACKOFF_MAX_MS + 1
        );
        let err = ReaderConfig::from_conf(&conf).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
        assert!(
            err.msg().contains("exceeds the hard cap"),
            "msg: {}",
            err.msg()
        );
    }

    #[test]
    fn failover_backoff_max_at_cap_accepted() {
        let conf = format!(
            "qwp::addr=h:1;failover_backoff_initial_ms=1;failover_backoff_max_ms={}",
            MAX_FAILOVER_BACKOFF_MAX_MS
        );
        let c = ReaderConfig::from_conf(&conf).unwrap();
        assert_eq!(c.failover_backoff_max_ms, MAX_FAILOVER_BACKOFF_MAX_MS);
    }

    #[test]
    fn addrs_above_cap_rejected() {
        // N5 regression guard: enforce `MAX_ADDRS` so the
        // address-rotation arithmetic in
        // `Reader::reconnect_with_failover` is provably free of usize
        // overflow on 32-bit targets.
        let mut addr = String::from("qwp::addr=");
        for i in 0..(MAX_ADDRS + 1) {
            if i > 0 {
                addr.push(',');
            }
            addr.push_str(&format!("h{}:9000", i));
        }
        let err = ReaderConfig::from_conf(&addr).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
        assert!(
            err.msg().contains("exceeds the hard cap"),
            "msg: {}",
            err.msg()
        );
    }

    #[test]
    fn failover_max_attempts_zero_rejected() {
        // Matches Java QwpQueryClient.java:401 — `failover_max_attempts must be >= 1`.
        // Users who want failover entirely off should set `failover=off`.
        let err = ReaderConfig::from_conf("qwp::addr=h:1;failover_max_attempts=0").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
        assert!(
            err.msg().contains("failover_max_attempts"),
            "msg: {}",
            err.msg()
        );
    }

    #[test]
    fn endpoint_display_common_cases() {
        // Hostnames and IPv4 literals format unbracketed — `host:port`
        // is the path users will actually see in connect strings,
        // logs, and `FailoverEvent` output. This is the contract the
        // failover doctest and example rely on.
        assert_eq!(
            Endpoint::new("localhost", 9000).to_string(),
            "localhost:9000"
        );
        assert_eq!(Endpoint::new("db-a", 9000).to_string(), "db-a:9000");
        assert_eq!(
            Endpoint::new("127.0.0.1", 9000).to_string(),
            "127.0.0.1:9000"
        );
        // Round-trip into a connect string parser: an Endpoint
        // formatted via Display must parse back into an
        // equal-by-value Endpoint, which keeps log lines and
        // diagnostic output safe to feed back into a new connect
        // string without quoting/escaping bookkeeping.
        let ep = Endpoint::new("example.com", 1234);
        let conf = format!("qwp::addr={}", ep);
        let parsed = ReaderConfig::from_conf(&conf).expect("parse round-trip");
        assert_eq!(parsed.addrs(), &[ep]);
    }

    #[test]
    fn endpoint_display_ipv6_brackets() {
        // IPv6 literals contain `:` and would otherwise produce an
        // ambiguous `host:port` collision. Bracketing follows
        // RFC 3986 §3.2.2 (`IP-literal`). The connect-string parser
        // doesn't currently accept IPv6 input, but `Endpoint::new`
        // and FailoverEvent surfacing must still format losslessly
        // for diagnostics.
        assert_eq!(Endpoint::new("::1", 9000).to_string(), "[::1]:9000");
        assert_eq!(
            Endpoint::new("2001:db8::1", 443).to_string(),
            "[2001:db8::1]:443"
        );
    }

    #[test]
    fn url_for_uses_endpoint_display() {
        // `url_for` was migrated to format via `{ep}`. Lock the
        // common-case URL string so the migration didn't introduce
        // a regression for the predominant non-IPv6 path users see.
        let c = ReaderConfig::from_conf("qwp::addr=db-a:9000;path=/exec").unwrap();
        assert_eq!(c.url_for(0), "ws://db-a:9000/exec");
    }
}
