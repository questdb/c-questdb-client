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
//! ws::addr=host:port;key=value;key=value;...
//! wss::addr=host:port;...    # TLS
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
//! | `compression_level`| `zstd` level advertised in `X-QWP-Accept-Encoding` as `zstd;level=N`; `[1,22]`, default `3` (server clamps to `[1,9]`); ignored when `compression=raw` |
//! | `max_batch_rows`   | sent only when non-zero (`0` = server default)           |
//! | `client_id`        | optional; sent only when set                             |
//! | `target`           | `any`/`primary`/`replica` (default `any`)                |
//! | `failover`         | `true`/`false` — mid-query reconnect on transport failure (`true`) |
//! | `failover_max_attempts`        | retry attempts after a transport failure (`8`, must be `>= 1`); ignored when `failover=off` |
//! | `failover_backoff_initial_ms`  | initial backoff between attempts (`50`); ignored when `failover=off` |
//! | `failover_backoff_max_ms`      | max backoff between attempts (`1000`); ignored when `failover=off` |
//! | `username`         | basic auth                                               |
//! | `password`         | basic auth                                               |
//! | `token`            | OIDC access token or QuestDB REST token — sent as `Bearer <token>` |
//! | `auth`             | verbatim Authorization value                             |
//! | `tls_verify`       | `on`/`unsafe_off` (`on`)                                 |
//! | `tls_ca`           | `webpki_roots` / `os_roots` / `webpki_and_os_roots` / `pem_file` (depends on enabled features) |
//! | `tls_roots`        | path to a PEM bundle (also implies `tls_ca=pem_file`)    |
//!
//! `tls_roots_password` is intentionally not supported — rustls reads
//! unencrypted PEM-encoded bundles, and the password concept only
//! applies to JKS/PKCS12 keystores. Setting it produces a config error.

use std::path::PathBuf;
use std::str::FromStr;

use crate::egress::auth::AuthMode;
use crate::egress::error::{Result, fmt};
use crate::ingress::CertificateAuthority;

/// Default endpoint path (mirrors the Java client).
pub const DEFAULT_PATH: &str = "/read/v1";

/// Highest QWP version this client can speak.
pub const HIGHEST_KNOWN_VERSION: u8 = 2;

/// Default WS port (matches QuestDB HTTP / ILP-HTTP convention).
const DEFAULT_PLAIN_PORT: &str = "9000";
const DEFAULT_TLS_PORT: &str = "9000";

/// Compression negotiation vocabulary.
///
/// Drives the `X-QWP-Accept-Encoding` header the client sends on the
/// WebSocket upgrade ([`Self::header_token`] returns the wire token).
/// The server picks one codec from the advertised set and echoes its
/// choice back in `X-QWP-Content-Encoding`; subsequent `RESULT_BATCH`
/// frames are tagged with `FLAG_ZSTD` (or not) accordingly.
///
/// All three variants are usable end-to-end when the client is built
/// with the `compression-zstd` feature (which `almost-all-features`
/// turns on by default). Without that feature, `Zstd` / `Auto` still
/// compile but the decoder rejects any `FLAG_ZSTD` batch the server
/// sends back with [`ErrorCode::UnsupportedServer`] — surface the
/// error to the operator rather than silently mis-decoding a
/// compressed payload as raw wire bytes.
///
/// [`ErrorCode::UnsupportedServer`]: crate::egress::ErrorCode::UnsupportedServer
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Compression {
    /// Advertise `raw` only — every `RESULT_BATCH` body is
    /// uncompressed wire bytes. Works on every client build (no
    /// `compression-zstd` dependency).
    Raw,
    /// Advertise `zstd` only — the server must send compressed
    /// batches and the client must be built with the
    /// `compression-zstd` feature to decode them.
    Zstd,
    /// Advertise both `zstd,raw` — the server picks. The decoder
    /// handles either path. If the client was built without the
    /// `compression-zstd` feature and the server still selects
    /// `zstd`, the decoder rejects the first `FLAG_ZSTD` batch with
    /// `UnsupportedServer`; the operator's recovery is to enable the
    /// feature or pin `Compression::Raw`.
    Auto,
}

impl Compression {
    /// Wire value for the `X-QWP-Accept-Encoding` header. Wire-egress.md
    /// §3: `zstd` carries an optional `level=N` hint that the server
    /// clamps to `[1, 9]`; `raw` has no parameters. `Auto` advertises
    /// `zstd;level=N,raw` (first match wins, per spec). `level` is
    /// ignored for `Raw`.
    pub fn accept_encoding(self, level: u8) -> String {
        match self {
            Compression::Raw => "raw".to_string(),
            Compression::Zstd => format!("zstd;level={}", level),
            Compression::Auto => format!("zstd;level={},raw", level),
        }
    }

    /// Bare codec token without the `level=` parameter — useful for
    /// diagnostics and the (now-rare) callers that want to log just
    /// "raw" / "zstd" / "zstd,raw". The on-wire value the client
    /// actually advertises is built by [`Self::accept_encoding`].
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
#[non_exhaustive]
pub enum Target {
    /// Accept any endpoint, regardless of role. The default.
    Any,
    /// Connect only to endpoints whose `SERVER_INFO.role` is
    /// `PRIMARY`, `PRIMARY_CATCHUP`, or `STANDALONE` (single-node
    /// OSS counts as PRIMARY per the Java reference). Suitable for
    /// followers that must observe a writer's perspective.
    Primary,
    /// Connect only to endpoints whose `SERVER_INFO.role` is
    /// `REPLICA`. Suitable for read-scaling clients that prefer
    /// followers and tolerate replication lag.
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
///
/// `#[non_exhaustive]` so future fields (e.g. a TLS-SNI override or a
/// resolved-`SocketAddr` cache) can be added without breaking
/// downstream struct-literal construction or exhaustive destructuring.
/// Use [`Endpoint::new`] to construct from external code.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Endpoint {
    /// Host portion of the endpoint. Stored verbatim from the
    /// connect string — no DNS resolution. For IPv6 literals this
    /// is the bare address (`"::1"`), not the bracketed form;
    /// [`Display`](std::fmt::Display) re-introduces brackets when
    /// the host contains a `:`.
    pub host: String,
    /// TCP port. The connect-string parser defaults this to `9000`
    /// for both `ws://` and `wss://` schemes if the address omits
    /// `:<port>`.
    pub port: u16,
}

impl Endpoint {
    /// Construct an endpoint from any string-like host and a port.
    ///
    /// The host is taken verbatim — no DNS resolution. For IPv6
    /// literals pass the bare address (`"::1"`), not the bracketed form
    /// (`"[::1]"`); [`Display`](std::fmt::Display) re-introduces brackets
    /// when formatting any host that contains `:`. The connect-string
    /// parser strips brackets in the same way, so an `addr=[::1]:9000`
    /// entry stores `host = "::1"`.
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

// ---------------------------------------------------------------------------
// Default failover knobs. Match the Java `QwpQueryClient` reference
// (`DEFAULT_FAILOVER_*` constants) so connect strings behave the same
// in either client.
// ---------------------------------------------------------------------------

/// Failover-on by default: a connect string that doesn't say
/// `failover=off` retries transport-class failures across the
/// configured `addr=` list.
pub const DEFAULT_FAILOVER_ENABLED: bool = true;

/// Default cap on the number of `connect_endpoint` attempts per
/// `Execute()`-driven failover round before the cursor surfaces a
/// terminal error. Capped by [`MAX_FAILOVER_MAX_ATTEMPTS`].
pub const DEFAULT_FAILOVER_MAX_ATTEMPTS: u32 = 8;

/// Default initial backoff (milliseconds) before the first
/// failover retry. Per failover.md §3.1 the actual sleep is drawn
/// uniformly from `[0, base)` (full jitter); this value is the
/// `base` for attempt 1. Capped by [`MAX_FAILOVER_BACKOFF_MAX_MS`].
pub const DEFAULT_FAILOVER_BACKOFF_INITIAL_MS: u64 = 50;

/// Default upper bound (milliseconds) on the per-attempt backoff
/// `base` after exponential growth. Beyond this the schedule
/// saturates rather than doubling further. Capped by
/// [`MAX_FAILOVER_BACKOFF_MAX_MS`].
pub const DEFAULT_FAILOVER_BACKOFF_MAX_MS: u64 = 1_000;

/// Hard upper bound on `failover_max_attempts`. Defensive: at the
/// minute-scale this is far past where extending the retry budget
/// stops being useful, and combined with [`MAX_ADDRS`] it bounds the
/// worst-case dial count and wall-clock the failover cycle can
/// consume. With `walk_via_tracker` doing at most
/// `addr_count × 2` picks per outer attempt (the round-attempted
/// walk plus one fall-through reset walk per failover.md §11.9.3),
/// the dial ceiling per `next_batch` is
/// `(MAX_FAILOVER_MAX_ATTEMPTS + 1) × MAX_ADDRS × 2 ≈ 2.1M`. Java
/// doesn't cap explicitly; this cap is well above any realistic
/// config.
pub const MAX_FAILOVER_MAX_ATTEMPTS: u32 = 1024;

/// Hard upper bound on the parsed address-list length. Real connect
/// strings target a single cluster (a handful of endpoints); this
/// cap exists so the [`HostHealthTracker`]'s per-host state arrays
/// (state × zone × host classification bits) and the
/// `walk_via_tracker` dial budget per outer failover attempt stay
/// bounded by a constant rather than user input. Combined with
/// [`MAX_FAILOVER_MAX_ATTEMPTS`] it pins the worst-case behaviour of
/// the whole failover cycle — see that constant's docstring for the
/// arithmetic.
///
/// [`HostHealthTracker`]: crate::egress::tracker::HostHealthTracker
pub const MAX_ADDRS: usize = 1024;

/// Hard upper bound on `failover_backoff_max_ms`. Caps a misconfigured
/// connect string from issuing multi-hour `thread::sleep` calls
/// during a failover storm. One hour is far past any operationally
/// useful backoff — beyond this, the user wants application-level
/// circuit breaking, not transport-level retry.
pub const MAX_FAILOVER_BACKOFF_MAX_MS: u64 = 60 * 60 * 1_000;

/// Default per-host upper bound on the **HTTP upgrade response read**
/// during connect, in milliseconds. Failover.md §1.1 default. Catches
/// the "TCP accepts but the server never replies" blackhole that the
/// OS connect timeout misses. Does NOT cover TCP connect or TLS
/// handshake (those use the OS default).
pub const DEFAULT_AUTH_TIMEOUT_MS: u64 = 15_000;

/// Hard upper bound on `auth_timeout_ms`. One hour is far past any
/// realistic upgrade-response wait; beyond it the user is using the
/// knob for something other than its documented purpose.
pub const MAX_AUTH_TIMEOUT_MS: u64 = 60 * 60 * 1_000;

/// Default per-host upper bound on the **post-upgrade `SERVER_INFO`
/// frame read**, in milliseconds. Failover.md §1.1 calls for a
/// separate hard-coded 5 s budget on this frame alone (distinct from
/// `auth_timeout_ms`, which covers only the HTTP upgrade response).
/// Matches the Java reference's `DEFAULT_SERVER_INFO_TIMEOUT_MS`.
///
/// The frame is short (≤ ~64 KiB), and the server is supposed to
/// write it into the same kernel send buffer as the upgrade response,
/// so on a healthy connection the frame is already in the client's
/// recv buffer by the time this wait starts.
pub const DEFAULT_SERVER_INFO_TIMEOUT_MS: u64 = 5_000;

/// Hard upper bound on `server_info_timeout_ms`. Same hour cap as
/// `auth_timeout_ms` — beyond it the user is misusing the knob.
pub const MAX_SERVER_INFO_TIMEOUT_MS: u64 = 60 * 60 * 1_000;

/// Default wall-clock budget per `Execute()`-driven failover round,
/// in milliseconds. Failover.md §11.9.1 / §7. `0` means unbounded.
pub const DEFAULT_FAILOVER_MAX_DURATION_MS: u64 = 30_000;

/// Hard upper bound on `failover_max_duration_ms`. Same hour cap as
/// `failover_backoff_max_ms` — beyond it the user wants application
/// circuit breaking, not transport retry.
pub const MAX_FAILOVER_MAX_DURATION_MS: u64 = 60 * 60 * 1_000;

/// Default `zstd` compression level advertised in `X-QWP-Accept-Encoding`
/// as `zstd;level=N`. Wire-egress.md §3 fixes the server default at `3`
/// and clamps any advertised value to `[1, 9]`; we match the Java
/// reference (`compression_level=N`, default 3) so a connect string ports
/// across clients.
pub const DEFAULT_COMPRESSION_LEVEL: u8 = 3;

/// Minimum accepted `compression_level`. Matches zstd's documented range
/// and the Java reference. `0` is rejected because the spec uses absence
/// (not zero) to mean "server default".
pub const MIN_COMPRESSION_LEVEL: u8 = 1;

/// Maximum accepted `compression_level`. zstd's documented maximum and
/// the Java reference upper bound. The server still clamps to `[1, 9]`
/// per wire-egress.md §3 — anything higher is a user-side hint that the
/// server is free to ignore.
pub const MAX_COMPRESSION_LEVEL: u8 = 22;

/// TLS verification policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
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
///
/// # Validate-before-use contract
///
/// The non-`addrs` fields are deliberately `pub` so callers can tweak a
/// parsed config before handing it to
/// [`Reader::from_config`](crate::egress::Reader::from_config) (e.g. raise
/// `failover_max_attempts` for a slow-network test, swap in a different
/// `client_id`). `#[non_exhaustive]` blocks struct-literal construction
/// outside this crate but **does not** block field mutation, so a caller
/// can set `failover_backoff_max_ms = u64::MAX` after parse and bypass
/// the parse-time hard caps.
///
/// The invariant is therefore: **every code path that reads these fields
/// must run against a `ReaderConfig` that has passed [`Self::validate`]
/// since its last mutation.** `Reader::from_config` calls `validate` once,
/// defensively, before opening any socket — relying on that is the
/// supported path. If you mutate fields after `Reader::from_config` has
/// returned (or share an `&mut ReaderConfig` across threads in a way
/// that's hard to reason about), call `validate()` again yourself before
/// re-using the config.
///
/// `addrs` is `pub(crate)` to keep external code from mutating the
/// address list once a `Reader` is built around an `Arc<ReaderConfig>`
/// snapshot; read-only access is via [`Self::addrs`].
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
    /// `zstd;level=N` hint advertised in `X-QWP-Accept-Encoding` when
    /// [`compression`](Self::compression) is `Zstd` or `Auto`. Ignored
    /// for `Raw`. Range `[MIN_COMPRESSION_LEVEL, MAX_COMPRESSION_LEVEL]`;
    /// the server clamps to `[1, 9]` per wire-egress.md §3. Default
    /// [`DEFAULT_COMPRESSION_LEVEL`] (= 3).
    pub compression_level: u8,
    pub max_batch_rows: u64,
    pub client_id: Option<String>,
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
    /// Wall-clock budget per `Execute()` once failover has been triggered,
    /// in milliseconds. `0` means unbounded. Bounds failover eligibility,
    /// not total Execute wall-clock — a single `WalkTracker` round can run
    /// up to `host_count × auth_timeout_ms` after the deadline check
    /// passes. Failover.md §11.9.1 / §7.
    ///
    /// Ignored when [`failover`](Self::failover) is `false`.
    pub failover_max_duration_ms: u64,
    /// Per-host upper bound on the WS upgrade-response read, in
    /// milliseconds. Bounds the "TCP accepts but server never replies"
    /// blackhole that the OS connect timeout misses. Does NOT cover TCP
    /// connect, TLS handshake, or the post-upgrade `SERVER_INFO` frame
    /// read (those use the OS default / [`Self::server_info_timeout_ms`]
    /// respectively). Failover.md §1.1.
    pub auth_timeout_ms: u64,
    /// Per-host upper bound on the post-upgrade `SERVER_INFO` (`0x18`)
    /// frame read, in milliseconds. Bounds the case where the server
    /// accepts the WS upgrade (HTTP 101) but never sends the
    /// `SERVER_INFO` binary frame — without this, the connect would
    /// stall indefinitely after `auth_timeout_ms` has already passed.
    /// Failover.md §1.1 specifies a separate 5 s budget; the knob is
    /// programmatic-only (not a connect-string key) so it tracks the
    /// Java reference's `withServerInfoTimeout` surface.
    pub server_info_timeout_ms: u64,
    /// Client's zone identifier — opaque case-insensitive string (e.g.
    /// `eu-west-1a`, `dc-amsterdam`). When set, the host-health tracker
    /// prefers endpoints whose server-advertised `zone_id` matches
    /// (`SERVER_INFO.zone_id` gated on `CAP_ZONE`, or `X-QuestDB-Zone`
    /// header on a `421` reject). `None` collapses every host's zone tier
    /// to `Same` (zone-blind selection). `target=primary` likewise
    /// collapses tiers to `Same` regardless of this value — writers
    /// follow the master across zones. Failover.md §1.1 / §2.
    pub zone: Option<String>,
    pub auth: AuthMode,
    pub tls_verify: TlsVerify,
    pub tls_ca: CertificateAuthority,
    pub tls_roots: Option<PathBuf>,
}

impl ReaderConfig {
    /// Construct from a connect-string.
    pub fn from_conf<T: AsRef<str>>(conf: T) -> Result<Self> {
        let conf_str = conf.as_ref();
        let conf = questdb_confstr::parse_conf_str(conf_str)
            .map_err(|e| fmt!(ConfigError, "Config parse error: {}", e))?;
        let scheme = conf.service();
        let tls = match scheme {
            "ws" => false,
            "wss" => true,
            other => {
                return Err(fmt!(
                    ConfigError,
                    "Unknown scheme \"{}\" — expected \"ws\" or \"wss\"",
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
            // IPv6 literals must be bracketed per RFC 3986 §3.2.2 to
            // disambiguate the authority's port colon from the address's
            // own colons. Strip the brackets here so the canonical stored
            // form is bare; `Endpoint::Display` re-introduces them when
            // formatting any host that contains `:`. Without this the
            // brackets get re-applied on top of the stored ones,
            // producing `ws://[[::1]]:9000/...` and a URL parse error.
            let (host, port_str) = if let Some(rest) = entry.strip_prefix('[') {
                let close = rest.find(']').ok_or_else(|| {
                    fmt!(
                        ConfigError,
                        "Bracketed addr entry {} missing closing ']': {:?}",
                        i,
                        entry
                    )
                })?;
                let host = rest[..close].to_string();
                let after = &rest[close + 1..];
                let port_str = if after.is_empty() {
                    default_port.to_string()
                } else if let Some(p) = after.strip_prefix(':') {
                    p.to_string()
                } else {
                    return Err(fmt!(
                        ConfigError,
                        "Unexpected characters after ']' in addr entry {}: {:?}",
                        i,
                        entry
                    ));
                };
                (host, port_str)
            } else {
                // Reject unbracketed multi-colon entries. `rsplit_once(':')`
                // would otherwise treat `::1` as host=`::`, port=`1` and
                // `2001:db8::1` as host=`2001:db8:`, port=`1` — surprising
                // misparses for users who omit the required brackets on an
                // IPv6 literal.
                if entry.bytes().filter(|&b| b == b':').count() > 1 {
                    return Err(fmt!(
                        ConfigError,
                        "addr entry {} contains multiple ':' — IPv6 literals \
                         must be bracketed (e.g. [::1]:9000): {:?}",
                        i,
                        entry
                    ));
                }
                match entry.rsplit_once(':') {
                    Some((h, p)) => (h.to_string(), p.to_string()),
                    None => (entry.to_string(), default_port.to_string()),
                }
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
            // Port 0 is the "ephemeral pick" sentinel for *listeners*;
            // for an outbound connect target it's meaningless. The
            // kernel rejects it as `EADDRNOTAVAIL` / `ECONNREFUSED`,
            // which the egress code would surface as a `SocketError`
            // — but with a confusing message ("connection refused")
            // that hides the actual misconfiguration. Reject at parse
            // so the diagnostic names the real cause.
            if port == 0 {
                return Err(fmt!(
                    ConfigError,
                    "Port 0 is not a valid connect target in \"addr\" entry {}: {:?}",
                    i,
                    entry
                ));
            }
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
        let mut compression_level: u8 = DEFAULT_COMPRESSION_LEVEL;
        let mut max_batch_rows: u64 = 0;
        let mut client_id: Option<String> = None;
        let mut target = Target::Any;
        let mut failover = DEFAULT_FAILOVER_ENABLED;
        let mut failover_max_attempts: u32 = DEFAULT_FAILOVER_MAX_ATTEMPTS;
        let mut failover_backoff_initial_ms: u64 = DEFAULT_FAILOVER_BACKOFF_INITIAL_MS;
        let mut failover_backoff_max_ms: u64 = DEFAULT_FAILOVER_BACKOFF_MAX_MS;
        let mut failover_max_duration_ms: u64 = DEFAULT_FAILOVER_MAX_DURATION_MS;
        let mut auth_timeout_ms: u64 = DEFAULT_AUTH_TIMEOUT_MS;
        let server_info_timeout_ms: u64 = DEFAULT_SERVER_INFO_TIMEOUT_MS;
        let mut zone: Option<String> = None;
        let mut tls_verify = TlsVerify::On;
        let mut tls_ca = default_tls_ca();
        let mut tls_ca_explicit = false;
        let mut tls_roots: Option<PathBuf> = None;

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
                    if !(1..=HIGHEST_KNOWN_VERSION).contains(&v) {
                        return Err(fmt!(
                            ConfigError,
                            "\"max_version\" must be in 1..={} (got {})",
                            HIGHEST_KNOWN_VERSION,
                            v
                        ));
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
                "compression_level" => {
                    let v: u8 = parse_value("compression_level", val)?;
                    if !(MIN_COMPRESSION_LEVEL..=MAX_COMPRESSION_LEVEL).contains(&v) {
                        return Err(fmt!(
                            ConfigError,
                            "\"compression_level\" must be in {}..={} (got {})",
                            MIN_COMPRESSION_LEVEL,
                            MAX_COMPRESSION_LEVEL,
                            v
                        ));
                    }
                    compression_level = v;
                }
                "max_batch_rows" => {
                    max_batch_rows = parse_value("max_batch_rows", val)?;
                }
                "client_id" => {
                    reject_crlf("client_id", val)?;
                    client_id = Some(val.to_string());
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
                "tls_ca" => {
                    tls_ca = parse_tls_ca(val)?;
                    tls_ca_explicit = true;
                }
                "tls_roots" => {
                    let path = PathBuf::from_str(val).map_err(|e| {
                        fmt!(
                            ConfigError,
                            "Invalid path for \"tls_roots\" ({:?}): {}",
                            val,
                            e
                        )
                    })?;
                    tls_roots = Some(path);
                }
                "tls_roots_password" => {
                    return Err(fmt!(
                        ConfigError,
                        "\"tls_roots_password\" is not supported (rustls reads unencrypted PEM)"
                    ));
                }

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
                "failover_max_duration_ms" => {
                    failover_max_duration_ms = parse_value("failover_max_duration_ms", val)?;
                }
                "auth_timeout_ms" => {
                    auth_timeout_ms = parse_value("auth_timeout_ms", val)?;
                }
                "zone" => {
                    // Empty / whitespace-only is treated as unset
                    // (zone-blind). Reject CR/LF — these are headers /
                    // log values and embedding control bytes risks
                    // injection downstream.
                    reject_crlf("zone", val)?;
                    let trimmed = val.trim();
                    zone = if trimmed.is_empty() {
                        None
                    } else {
                        Some(trimmed.to_string())
                    };
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

        // The `tls_verify=unsafe_off` feature-gate check is enforced by
        // `validate()` (called below) so a post-parse mutation of
        // `cfg.tls_verify = TlsVerify::UnsafeOff` is also rejected —
        // without that, the runtime would silently downgrade to the
        // default verifier and the caller's explicit "off" intent would
        // be lost.

        // tls_* knobs only make sense with TLS scheme.
        if !tls && (tls_roots.is_some() || tls_ca_explicit) {
            return Err(fmt!(
                ConfigError,
                "TLS-related keys require the \"qwps\" scheme"
            ));
        }

        // `tls_roots=<path>` implies `tls_ca=pem_file` unless the caller
        // also explicitly set a different `tls_ca` (in which case we error
        // because the combination is contradictory).
        if tls_roots.is_some() {
            if tls_ca_explicit && tls_ca != CertificateAuthority::PemFile {
                return Err(fmt!(
                    ConfigError,
                    "\"tls_roots\" requires \"tls_ca=pem_file\" (or omit \"tls_ca\")"
                ));
            }
            tls_ca = CertificateAuthority::PemFile;
        }

        let auth = AuthMode::from_parts(
            username.as_deref(),
            password.as_deref(),
            token.as_deref(),
            auth_verbatim.as_deref(),
        )?;

        let cfg = ReaderConfig {
            addrs,
            tls,
            path,
            max_version,
            compression,
            compression_level,
            max_batch_rows,
            client_id,
            target,
            failover,
            failover_max_attempts,
            failover_backoff_initial_ms,
            failover_backoff_max_ms,
            failover_max_duration_ms,
            auth_timeout_ms,
            server_info_timeout_ms,
            zone,
            auth,
            tls_verify,
            tls_ca,
            tls_roots,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    /// Re-run the cap and consistency checks that `from_conf` enforces.
    ///
    /// This is the enforcement half of the validate-before-use contract
    /// documented on [`ReaderConfig`] itself: `pub` fields keep the
    /// config ergonomic to tweak post-parse, and `validate()` is what
    /// any reader of those fields can rely on to have run since the
    /// last mutation. `Reader::from_config` calls this defensively
    /// before opening any socket; call it explicitly after mutating
    /// a config you intend to re-use through another entry point.
    pub fn validate(&self) -> Result<()> {
        if self.addrs.is_empty() {
            return Err(fmt!(ConfigError, "\"addr\" parameter is empty"));
        }
        if self.addrs.len() > MAX_ADDRS {
            return Err(fmt!(
                ConfigError,
                "\"addr\" list length {} exceeds the hard cap of {}",
                self.addrs.len(),
                MAX_ADDRS
            ));
        }
        if !(1..=HIGHEST_KNOWN_VERSION).contains(&self.max_version) {
            return Err(fmt!(
                ConfigError,
                "\"max_version\" must be in 1..={} (got {})",
                HIGHEST_KNOWN_VERSION,
                self.max_version
            ));
        }
        if !(MIN_COMPRESSION_LEVEL..=MAX_COMPRESSION_LEVEL).contains(&self.compression_level) {
            return Err(fmt!(
                ConfigError,
                "\"compression_level\" must be in {}..={} (got {})",
                MIN_COMPRESSION_LEVEL,
                MAX_COMPRESSION_LEVEL,
                self.compression_level
            ));
        }
        if self.failover_max_attempts == 0 {
            return Err(fmt!(
                ConfigError,
                "\"failover_max_attempts\" must be >= 1 (use \"failover=off\" to disable failover entirely)"
            ));
        }
        if self.failover_max_attempts > MAX_FAILOVER_MAX_ATTEMPTS {
            return Err(fmt!(
                ConfigError,
                "\"failover_max_attempts\" {} exceeds the hard cap of {}",
                self.failover_max_attempts,
                MAX_FAILOVER_MAX_ATTEMPTS
            ));
        }
        if self.failover_backoff_initial_ms == 0 {
            return Err(fmt!(
                ConfigError,
                "\"failover_backoff_initial_ms\" must be > 0"
            ));
        }
        if self.failover_backoff_max_ms < self.failover_backoff_initial_ms {
            return Err(fmt!(
                ConfigError,
                "\"failover_backoff_max_ms\" ({}) must be >= \"failover_backoff_initial_ms\" ({})",
                self.failover_backoff_max_ms,
                self.failover_backoff_initial_ms
            ));
        }
        if self.failover_backoff_max_ms > MAX_FAILOVER_BACKOFF_MAX_MS {
            return Err(fmt!(
                ConfigError,
                "\"failover_backoff_max_ms\" {} exceeds the hard cap of {} (1 hour)",
                self.failover_backoff_max_ms,
                MAX_FAILOVER_BACKOFF_MAX_MS
            ));
        }
        // `failover_max_duration_ms = 0` is the documented "unbounded"
        // sentinel — don't reject it. Cap the upper bound the same way
        // we cap `failover_backoff_max_ms` so a misconfigured value can't
        // pin a thread waiting on failover for days.
        if self.failover_max_duration_ms > MAX_FAILOVER_MAX_DURATION_MS {
            return Err(fmt!(
                ConfigError,
                "\"failover_max_duration_ms\" {} exceeds the hard cap of {} (1 hour)",
                self.failover_max_duration_ms,
                MAX_FAILOVER_MAX_DURATION_MS
            ));
        }
        if self.auth_timeout_ms == 0 {
            return Err(fmt!(
                ConfigError,
                "\"auth_timeout_ms\" must be > 0 (no sentinel for \"unbounded\" — \
                 set a value high enough for your slowest peer's upgrade response)"
            ));
        }
        if self.auth_timeout_ms > MAX_AUTH_TIMEOUT_MS {
            return Err(fmt!(
                ConfigError,
                "\"auth_timeout_ms\" {} exceeds the hard cap of {} (1 hour)",
                self.auth_timeout_ms,
                MAX_AUTH_TIMEOUT_MS
            ));
        }
        if self.server_info_timeout_ms == 0 {
            return Err(fmt!(ConfigError, "\"server_info_timeout_ms\" must be > 0"));
        }
        if self.server_info_timeout_ms > MAX_SERVER_INFO_TIMEOUT_MS {
            return Err(fmt!(
                ConfigError,
                "\"server_info_timeout_ms\" {} exceeds the hard cap of {} (1 hour)",
                self.server_info_timeout_ms,
                MAX_SERVER_INFO_TIMEOUT_MS
            ));
        }
        // String fields & auth aren't covered by the numeric/range
        // checks above. Without these re-checks, a caller who built
        // `cfg` via `from_conf` (clean) and then mutated `client_id`,
        // `zone`, or `auth` (the struct's fields are `pub`) could
        // smuggle CRLF / control bytes into the WS upgrade headers
        // and inject downstream — `#[non_exhaustive]` blocks struct
        // literal construction but does not block field assignment.
        if let Some(id) = &self.client_id {
            reject_crlf("client_id", id)?;
        }
        if let Some(z) = &self.zone {
            reject_crlf("zone", z)?;
        }
        self.auth.validate()?;
        // tls_verify=unsafe_off needs the crate feature. Re-checked
        // here so a post-parse mutation of `cfg.tls_verify =
        // TlsVerify::UnsafeOff` is rejected too — the TLS builder
        // silently downgrades to the default verifier when the feature
        // is off (runtime is safe), so without this check the caller's
        // explicit "off" intent would be lost without diagnostic.
        #[cfg(not(feature = "insecure-skip-verify"))]
        if matches!(self.tls_verify, TlsVerify::UnsafeOff) {
            return Err(fmt!(
                ConfigError,
                "\"tls_verify=unsafe_off\" requires the \"insecure-skip-verify\" crate feature"
            ));
        }
        Ok(())
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
        // raw-only today still benefits from being explicit. `level=N` is
        // only meaningful for zstd/auto; `Compression::accept_encoding`
        // drops it for `Raw`.
        headers.push((
            "X-QWP-Accept-Encoding",
            self.compression.accept_encoding(self.compression_level),
        ));
        if self.max_batch_rows > 0 {
            headers.push(("X-QWP-Max-Batch-Rows", self.max_batch_rows.to_string()));
        }
        if let Some(v) = self.auth.header_value() {
            headers.push(("Authorization", v));
        }
        headers
    }
}

/// Default `tls_ca` mirrors the ingress sender: prefer webpki roots if
/// the bundled-certs feature is on, fall back to OS roots, and finally
/// to `pem_file` (which forces the user to supply `tls_roots`). Keeps
/// `wss://` working out of the box on the common feature combos.
fn default_tls_ca() -> CertificateAuthority {
    #[cfg(feature = "tls-webpki-certs")]
    {
        CertificateAuthority::WebpkiRoots
    }
    #[cfg(all(not(feature = "tls-webpki-certs"), feature = "tls-native-certs"))]
    {
        CertificateAuthority::OsRoots
    }
    #[cfg(not(any(feature = "tls-webpki-certs", feature = "tls-native-certs")))]
    {
        CertificateAuthority::PemFile
    }
}

fn parse_tls_ca(val: &str) -> Result<CertificateAuthority> {
    Ok(match val {
        #[cfg(feature = "tls-webpki-certs")]
        "webpki_roots" => CertificateAuthority::WebpkiRoots,
        #[cfg(not(feature = "tls-webpki-certs"))]
        "webpki_roots" => {
            return Err(fmt!(
                ConfigError,
                "\"tls_ca=webpki_roots\" requires the \"tls-webpki-certs\" feature"
            ));
        }
        #[cfg(feature = "tls-native-certs")]
        "os_roots" => CertificateAuthority::OsRoots,
        #[cfg(not(feature = "tls-native-certs"))]
        "os_roots" => {
            return Err(fmt!(
                ConfigError,
                "\"tls_ca=os_roots\" requires the \"tls-native-certs\" feature"
            ));
        }
        #[cfg(all(feature = "tls-webpki-certs", feature = "tls-native-certs"))]
        "webpki_and_os_roots" => CertificateAuthority::WebpkiAndOsRoots,
        #[cfg(not(all(feature = "tls-webpki-certs", feature = "tls-native-certs")))]
        "webpki_and_os_roots" => {
            return Err(fmt!(
                ConfigError,
                "\"tls_ca=webpki_and_os_roots\" requires both the \"tls-webpki-certs\" and \"tls-native-certs\" features"
            ));
        }
        "pem_file" => CertificateAuthority::PemFile,
        other => {
            return Err(fmt!(
                ConfigError,
                "\"tls_ca\" must be one of webpki_roots|os_roots|webpki_and_os_roots|pem_file (got {:?})",
                other
            ));
        }
    })
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

/// Reject a CR (0x0D) or LF (0x0A) in `val`. Used by parse-time
/// handling of `client_id` and `zone` and re-applied by `validate()`
/// so that post-parse field mutation (the `pub` fields on
/// `ReaderConfig` allow it) can't smuggle CRLF into the WS upgrade
/// headers — header injection would otherwise be a one-liner from a
/// caller who built a config programmatically and then assigned a
/// hostile value.
fn reject_crlf(name: &str, val: &str) -> Result<()> {
    if val.contains('\n') || val.contains('\r') {
        return Err(fmt!(ConfigError, "\"{}\" must not contain CR or LF", name));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress::error::ErrorCode;

    #[test]
    fn minimal_plain_conf() {
        let c = ReaderConfig::from_conf("ws::addr=localhost:9000").unwrap();
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
        let c = ReaderConfig::from_conf("wss::addr=h:8443").unwrap();
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
        let err = ReaderConfig::from_conf("ws::path=/read/v1").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
    }

    #[test]
    fn unknown_key_rejected() {
        let err = ReaderConfig::from_conf("ws::addr=h:1;mystery=x").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
    }

    #[test]
    fn basic_auth_in_conf() {
        let c = ReaderConfig::from_conf("ws::addr=h:1;username=admin;password=quest").unwrap();
        assert_eq!(
            c.auth.header_value(),
            Some("Basic YWRtaW46cXVlc3Q=".to_string())
        );
    }

    #[test]
    fn bearer_in_conf() {
        let c = ReaderConfig::from_conf("ws::addr=h:1;token=tok").unwrap();
        assert_eq!(c.auth.header_value(), Some("Bearer tok".to_string()));
    }

    #[test]
    fn auth_modes_mutually_exclusive() {
        let err =
            ReaderConfig::from_conf("ws::addr=h:1;username=u;password=p;token=t").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
    }

    #[cfg(not(feature = "compression-zstd"))]
    #[test]
    fn compression_zstd_rejected_without_feature() {
        let err = ReaderConfig::from_conf("ws::addr=h:1;compression=zstd").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
        let err = ReaderConfig::from_conf("ws::addr=h:1;compression=auto").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
    }

    #[cfg(feature = "compression-zstd")]
    #[test]
    fn compression_zstd_accepted_with_feature() {
        let c = ReaderConfig::from_conf("ws::addr=h:1;compression=zstd").unwrap();
        assert_eq!(c.compression, Compression::Zstd);
        let c = ReaderConfig::from_conf("ws::addr=h:1;compression=auto").unwrap();
        assert_eq!(c.compression, Compression::Auto);
    }

    #[test]
    fn invalid_compression_value() {
        let err = ReaderConfig::from_conf("ws::addr=h:1;compression=xyz").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
    }

    #[test]
    fn compression_level_default_is_three() {
        let c = ReaderConfig::from_conf("ws::addr=h:1").unwrap();
        assert_eq!(c.compression_level, DEFAULT_COMPRESSION_LEVEL);
        assert_eq!(c.compression_level, 3);
    }

    #[cfg(feature = "compression-zstd")]
    #[test]
    fn compression_level_parses_and_is_emitted() {
        let c =
            ReaderConfig::from_conf("ws::addr=h:1;compression=zstd;compression_level=9").unwrap();
        assert_eq!(c.compression_level, 9);
        let headers = c.upgrade_headers();
        let accept = headers
            .iter()
            .find(|(n, _)| *n == "X-QWP-Accept-Encoding")
            .expect("accept-encoding header present");
        assert_eq!(accept.1, "zstd;level=9");
    }

    #[cfg(feature = "compression-zstd")]
    #[test]
    fn compression_level_emitted_for_auto() {
        let c =
            ReaderConfig::from_conf("ws::addr=h:1;compression=auto;compression_level=7").unwrap();
        let headers = c.upgrade_headers();
        let accept = headers
            .iter()
            .find(|(n, _)| *n == "X-QWP-Accept-Encoding")
            .expect("accept-encoding header present");
        // First match wins per wire-egress.md §3 — zstd before raw.
        assert_eq!(accept.1, "zstd;level=7,raw");
    }

    #[test]
    fn compression_level_ignored_for_raw() {
        // Setting `compression_level` against `compression=raw` is harmless
        // (the spec says `level=N` only applies to zstd). The header value
        // collapses to the bare `raw` token.
        let c = ReaderConfig::from_conf("ws::addr=h:1;compression_level=15").unwrap();
        let headers = c.upgrade_headers();
        let accept = headers
            .iter()
            .find(|(n, _)| *n == "X-QWP-Accept-Encoding")
            .expect("accept-encoding header present");
        assert_eq!(accept.1, "raw");
    }

    #[test]
    fn compression_level_out_of_range_rejected() {
        for bad in ["0", "23", "100"] {
            let err = ReaderConfig::from_conf(format!("ws::addr=h:1;compression_level={}", bad))
                .unwrap_err();
            assert_eq!(
                err.code(),
                ErrorCode::ConfigError,
                "compression_level={} must be rejected",
                bad
            );
        }
    }

    #[test]
    fn compression_level_accepts_full_range() {
        for ok in [
            MIN_COMPRESSION_LEVEL,
            DEFAULT_COMPRESSION_LEVEL,
            MAX_COMPRESSION_LEVEL,
        ] {
            let c = ReaderConfig::from_conf(format!("ws::addr=h:1;compression_level={}", ok))
                .expect("level in-range");
            assert_eq!(c.compression_level, ok);
        }
    }

    #[test]
    fn target_parses() {
        let c = ReaderConfig::from_conf("ws::addr=h:1;target=primary").unwrap();
        assert_eq!(c.target, Target::Primary);
    }

    #[test]
    fn multi_addr_parses() {
        let c = ReaderConfig::from_conf("ws::addr=h1:9000,h2:9001,h3,h4:9999;").unwrap();
        assert_eq!(c.addrs.len(), 4);
        assert_eq!(c.addrs[0], Endpoint::new("h1", 9000));
        assert_eq!(c.addrs[1], Endpoint::new("h2", 9001));
        assert_eq!(c.addrs[2], Endpoint::new("h3", 9000)); // default port
        assert_eq!(c.addrs[3], Endpoint::new("h4", 9999));
    }

    #[test]
    fn empty_addr_entry_rejected() {
        let err = ReaderConfig::from_conf("ws::addr=h1:9000,,h2:9001;").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
    }

    #[test]
    fn target_invalid_rejected() {
        let err = ReaderConfig::from_conf("ws::addr=h:1;target=leader").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
    }

    #[test]
    fn upgrade_headers_default() {
        let c = ReaderConfig::from_conf("ws::addr=h:1").unwrap();
        let h = c.upgrade_headers();
        // Always emit max_version + accept-encoding; nothing else by default.
        assert_eq!(h.len(), 2);
        assert_eq!(h[0], ("X-QWP-Max-Version", "2".to_string()));
        assert_eq!(h[1], ("X-QWP-Accept-Encoding", "raw".to_string()));
    }

    #[test]
    fn upgrade_headers_full_set() {
        let c = ReaderConfig::from_conf(
            "ws::addr=h:1;client_id=app1;max_batch_rows=1000;username=u;password=p",
        )
        .unwrap();
        let h = c.upgrade_headers();
        let names: Vec<_> = h.iter().map(|(n, _)| *n).collect();
        assert!(names.contains(&"X-QWP-Max-Version"));
        assert!(names.contains(&"X-QWP-Client-Id"));
        assert!(names.contains(&"X-QWP-Accept-Encoding"));
        assert!(names.contains(&"X-QWP-Max-Batch-Rows"));
        assert!(names.contains(&"Authorization"));
        assert!(!names.contains(&"X-QWP-Request-Durable-Ack"));

        // max_batch_rows omitted when 0.
        let c = ReaderConfig::from_conf("ws::addr=h:1;max_batch_rows=0").unwrap();
        let h = c.upgrade_headers();
        assert!(h.iter().all(|(n, _)| *n != "X-QWP-Max-Batch-Rows"));
    }

    #[test]
    fn path_must_start_with_slash() {
        let err = ReaderConfig::from_conf("ws::addr=h:1;path=read/v1").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
    }

    #[test]
    fn default_port_when_omitted() {
        let c = ReaderConfig::from_conf("ws::addr=localhost").unwrap();
        assert_eq!(c.addrs[0].port, 9000);
    }

    #[test]
    fn invalid_port_rejected() {
        let err = ReaderConfig::from_conf("ws::addr=h:notaport").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
    }

    #[test]
    fn port_zero_rejected() {
        // Port 0 means "let the OS pick" for *listeners*; for an
        // outbound connect target it's nonsense. Parse-time rejection
        // gives a precise diagnostic instead of a downstream
        // EADDRNOTAVAIL / ECONNREFUSED with a misleading message.
        let err = ReaderConfig::from_conf("ws::addr=h:0").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
        assert!(
            err.msg().contains("Port 0"),
            "diagnostic must name the offending value; got: {}",
            err.msg()
        );
        // Reject when port 0 is one of several entries, too —
        // partial-zero lists shouldn't slip past.
        let err = ReaderConfig::from_conf("ws::addr=a:9000,b:0").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
        // And in the IPv6-bracketed path (which funnels through the
        // same `port_str.parse()` site).
        let err = ReaderConfig::from_conf("ws::addr=[::1]:0").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
    }

    #[test]
    fn tls_keys_with_plain_scheme_rejected() {
        let err = ReaderConfig::from_conf("ws::addr=h:1;tls_roots=/tmp/x").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
        let err = ReaderConfig::from_conf("ws::addr=h:1;tls_ca=pem_file").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
    }

    // `tls_verify=unsafe_off` is gated by the `insecure-skip-verify`
    // crate feature. The feature gate has to be enforced by `validate()`
    // (not just at parse time) because the field is `pub`: a caller can
    // build a clean config via `from_conf` and then assign
    // `cfg.tls_verify = TlsVerify::UnsafeOff` directly. The TLS builder
    // silently downgrades to the default verifier when the feature is
    // off, so without the validate-time check the caller's explicit
    // "off" intent would be lost without diagnostic.
    #[cfg(not(feature = "insecure-skip-verify"))]
    #[test]
    fn validate_rejects_unsafe_off_when_feature_disabled() {
        // Parse-time rejection: the existing behaviour, still in place.
        let err = ReaderConfig::from_conf("wss::addr=h:1;tls_verify=unsafe_off").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
        assert!(
            err.msg().contains("insecure-skip-verify"),
            "msg: {}",
            err.msg()
        );

        // Post-parse mutation: builds a clean config first, then flips
        // the field. Without the re-check in `validate()` this path
        // would pass silently.
        let mut cfg = ReaderConfig::from_conf("wss::addr=h:1").unwrap();
        assert_eq!(cfg.tls_verify, TlsVerify::On);
        cfg.tls_verify = TlsVerify::UnsafeOff;
        let err = cfg.validate().unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
        assert!(
            err.msg().contains("insecure-skip-verify"),
            "msg: {}",
            err.msg()
        );
    }

    #[cfg(feature = "insecure-skip-verify")]
    #[test]
    fn validate_accepts_unsafe_off_when_feature_enabled() {
        // Mirror of `validate_rejects_unsafe_off_when_feature_disabled`
        // — pins that the feature gate only fires in the off direction.
        let cfg = ReaderConfig::from_conf("wss::addr=h:1;tls_verify=unsafe_off").unwrap();
        assert_eq!(cfg.tls_verify, TlsVerify::UnsafeOff);
        cfg.validate().expect("unsafe_off must pass validate when feature is on");
    }

    #[test]
    fn tls_roots_password_rejected() {
        // PEM bundles are unencrypted under rustls; the JKS/PKCS12
        // password concept doesn't translate. Setting it must fail
        // loudly rather than silently doing nothing.
        let err = ReaderConfig::from_conf("wss::addr=h:1;tls_roots_password=secret").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
        assert!(
            err.msg().contains("tls_roots_password"),
            "msg: {}",
            err.msg()
        );
    }

    #[test]
    fn tls_roots_implies_pem_file_ca() {
        let c = ReaderConfig::from_conf("wss::addr=h:1;tls_roots=/path/to/roots.pem").unwrap();
        assert_eq!(c.tls_ca, CertificateAuthority::PemFile);
        assert_eq!(
            c.tls_roots.as_deref(),
            Some(std::path::Path::new("/path/to/roots.pem"))
        );
    }

    #[test]
    fn tls_roots_with_conflicting_ca_rejected() {
        #[cfg(feature = "tls-webpki-certs")]
        {
            let err = ReaderConfig::from_conf("wss::addr=h:1;tls_ca=webpki_roots;tls_roots=/tmp/x")
                .unwrap_err();
            assert_eq!(err.code(), ErrorCode::ConfigError);
        }
    }

    #[test]
    fn tls_ca_pem_file_explicit() {
        let c =
            ReaderConfig::from_conf("wss::addr=h:1;tls_ca=pem_file;tls_roots=/tmp/r.pem").unwrap();
        assert_eq!(c.tls_ca, CertificateAuthority::PemFile);
    }

    #[test]
    fn tls_ca_invalid_value_rejected() {
        let err = ReaderConfig::from_conf("wss::addr=h:1;tls_ca=mystery").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
    }

    #[cfg(feature = "tls-webpki-certs")]
    #[test]
    fn tls_ca_webpki_roots_default() {
        let c = ReaderConfig::from_conf("wss::addr=h:1").unwrap();
        assert_eq!(c.tls_ca, CertificateAuthority::WebpkiRoots);
        assert_eq!(c.tls_roots, None);
    }

    #[test]
    fn durable_ack_key_rejected() {
        // `durable_ack` is an ingress-spec carryover with no egress
        // semantic — the key was removed from the egress connect string
        // (spec §3 lists exactly four C->S headers; the corresponding
        // X-QWP-Request-Durable-Ack header was also removed). A connect
        // string still carrying the key now fails parsing rather than
        // being silently honoured.
        let err = ReaderConfig::from_conf("ws::addr=h:1;durable_ack=true").unwrap_err();
        assert!(
            err.msg().to_lowercase().contains("durable_ack")
                || err.msg().to_lowercase().contains("unknown")
        );
    }

    #[test]
    fn failover_defaults() {
        let c = ReaderConfig::from_conf("ws::addr=h:1").unwrap();
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
            "ws::addr=h:1;failover=off;failover_max_attempts=3;failover_backoff_initial_ms=100;failover_backoff_max_ms=2000",
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
            ReaderConfig::from_conf("ws::addr=h:1;failover_backoff_initial_ms=0").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
    }

    #[test]
    fn failover_backoff_max_below_initial_rejected() {
        let err = ReaderConfig::from_conf(
            "ws::addr=h:1;failover_backoff_initial_ms=500;failover_backoff_max_ms=100",
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
    }

    #[test]
    fn failover_invalid_attempts_rejected() {
        let err = ReaderConfig::from_conf("ws::addr=h:1;failover_max_attempts=abc").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
    }

    #[test]
    fn failover_max_attempts_above_cap_rejected() {
        let conf = format!(
            "ws::addr=h:1;failover_max_attempts={}",
            MAX_FAILOVER_MAX_ATTEMPTS + 1
        );
        let err = ReaderConfig::from_conf(&conf).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
        assert!(err.msg().contains("exceeds the hard cap"));
    }

    #[test]
    fn failover_max_attempts_at_cap_accepted() {
        let conf = format!(
            "ws::addr=h:1;failover_max_attempts={}",
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
            "ws::addr=h:1;failover_backoff_initial_ms=1;failover_backoff_max_ms={}",
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
            "ws::addr=h:1;failover_backoff_initial_ms=1;failover_backoff_max_ms={}",
            MAX_FAILOVER_BACKOFF_MAX_MS
        );
        let c = ReaderConfig::from_conf(&conf).unwrap();
        assert_eq!(c.failover_backoff_max_ms, MAX_FAILOVER_BACKOFF_MAX_MS);
    }

    // --- zone / auth_timeout_ms / failover_max_duration_ms (failover.md §1.1, §11.9.1) ---

    #[test]
    fn zone_unset_is_none_by_default() {
        let c = ReaderConfig::from_conf("ws::addr=h:1").unwrap();
        assert_eq!(c.zone, None);
    }

    #[test]
    fn zone_parses() {
        let c = ReaderConfig::from_conf("ws::addr=h:1;zone=eu-west-1a").unwrap();
        assert_eq!(c.zone.as_deref(), Some("eu-west-1a"));
    }

    #[test]
    fn zone_empty_or_whitespace_normalises_to_none() {
        let c = ReaderConfig::from_conf("ws::addr=h:1;zone=").unwrap();
        assert_eq!(c.zone, None, "empty value collapses to unset");
        let c = ReaderConfig::from_conf("ws::addr=h:1;zone=   ").unwrap();
        assert_eq!(c.zone, None, "whitespace-only collapses to unset");
    }

    #[test]
    fn zone_trims_value() {
        let c = ReaderConfig::from_conf("ws::addr=h:1;zone=  eu-west-1a  ").unwrap();
        assert_eq!(c.zone.as_deref(), Some("eu-west-1a"));
    }

    #[test]
    fn zone_rejects_cr_lf() {
        // CRLF in a zone value would smuggle into log lines and any
        // header that re-serialises it. Reject up front.
        let err = ReaderConfig::from_conf("ws::addr=h:1;zone=eu\nwest").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
        let err = ReaderConfig::from_conf("ws::addr=h:1;zone=eu\rwest").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
    }

    #[test]
    fn auth_timeout_defaults_to_15s() {
        let c = ReaderConfig::from_conf("ws::addr=h:1").unwrap();
        assert_eq!(c.auth_timeout_ms, DEFAULT_AUTH_TIMEOUT_MS);
        assert_eq!(DEFAULT_AUTH_TIMEOUT_MS, 15_000);
    }

    #[test]
    fn auth_timeout_parses() {
        let c = ReaderConfig::from_conf("ws::addr=h:1;auth_timeout_ms=3000").unwrap();
        assert_eq!(c.auth_timeout_ms, 3_000);
    }

    #[test]
    fn auth_timeout_zero_rejected() {
        // No "unbounded" sentinel — 0 is misconfiguration. Pinning a
        // thread waiting on a single peer indefinitely is what we're
        // trying to *avoid* with this knob.
        let err = ReaderConfig::from_conf("ws::addr=h:1;auth_timeout_ms=0").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
        assert!(err.msg().contains("auth_timeout_ms"), "msg: {}", err.msg());
    }

    #[test]
    fn auth_timeout_above_cap_rejected() {
        let conf = format!("ws::addr=h:1;auth_timeout_ms={}", MAX_AUTH_TIMEOUT_MS + 1);
        let err = ReaderConfig::from_conf(&conf).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
        assert!(err.msg().contains("exceeds the hard cap"));
    }

    #[test]
    fn auth_timeout_at_cap_accepted() {
        let conf = format!("ws::addr=h:1;auth_timeout_ms={}", MAX_AUTH_TIMEOUT_MS);
        let c = ReaderConfig::from_conf(&conf).unwrap();
        assert_eq!(c.auth_timeout_ms, MAX_AUTH_TIMEOUT_MS);
    }

    #[test]
    fn failover_max_duration_defaults_to_30s() {
        let c = ReaderConfig::from_conf("ws::addr=h:1").unwrap();
        assert_eq!(c.failover_max_duration_ms, DEFAULT_FAILOVER_MAX_DURATION_MS);
        assert_eq!(DEFAULT_FAILOVER_MAX_DURATION_MS, 30_000);
    }

    #[test]
    fn failover_max_duration_parses() {
        let c = ReaderConfig::from_conf("ws::addr=h:1;failover_max_duration_ms=60000").unwrap();
        assert_eq!(c.failover_max_duration_ms, 60_000);
    }

    #[test]
    fn failover_max_duration_zero_is_unbounded() {
        // `0` is the documented sentinel for "no wall-clock cap" per
        // wire-egress.md §11.9.1. Must not be rejected.
        let c = ReaderConfig::from_conf("ws::addr=h:1;failover_max_duration_ms=0").unwrap();
        assert_eq!(c.failover_max_duration_ms, 0);
    }

    #[test]
    fn failover_max_duration_above_cap_rejected() {
        let conf = format!(
            "ws::addr=h:1;failover_max_duration_ms={}",
            MAX_FAILOVER_MAX_DURATION_MS + 1
        );
        let err = ReaderConfig::from_conf(&conf).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
        assert!(err.msg().contains("exceeds the hard cap"));
    }

    // --- server_info_timeout_ms (programmatic-only; not parsed from connect-string) ---

    #[test]
    fn server_info_timeout_defaults_to_5s() {
        let c = ReaderConfig::from_conf("ws::addr=h:1").unwrap();
        assert_eq!(c.server_info_timeout_ms, DEFAULT_SERVER_INFO_TIMEOUT_MS);
        assert_eq!(DEFAULT_SERVER_INFO_TIMEOUT_MS, 5_000);
    }

    #[test]
    fn server_info_timeout_is_not_parsed_from_connect_string() {
        // Java parity: `withServerInfoTimeout` is programmatic-only. The
        // connect-string key MUST be rejected (covered by the generic
        // "unknown config key" branch) so a user typo doesn't get
        // silently ignored.
        let err = ReaderConfig::from_conf("ws::addr=h:1;server_info_timeout_ms=1000").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
        assert!(
            err.msg().contains("Unknown config key"),
            "msg: {}",
            err.msg()
        );
    }

    #[test]
    fn server_info_timeout_zero_rejected_by_validate() {
        // Programmatic mutation past the default — `validate()` is the
        // safety net before `Reader::from_config` opens any socket.
        let mut c = ReaderConfig::from_conf("ws::addr=h:1").unwrap();
        c.server_info_timeout_ms = 0;
        let err = c.validate().unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
        assert!(err.msg().contains("server_info_timeout_ms"));
    }

    #[test]
    fn server_info_timeout_above_cap_rejected_by_validate() {
        let mut c = ReaderConfig::from_conf("ws::addr=h:1").unwrap();
        c.server_info_timeout_ms = MAX_SERVER_INFO_TIMEOUT_MS + 1;
        let err = c.validate().unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
        assert!(err.msg().contains("exceeds the hard cap"));
    }

    #[test]
    fn server_info_timeout_at_cap_accepted() {
        let mut c = ReaderConfig::from_conf("ws::addr=h:1").unwrap();
        c.server_info_timeout_ms = MAX_SERVER_INFO_TIMEOUT_MS;
        c.validate().unwrap();
    }

    #[test]
    fn addrs_above_cap_rejected() {
        // N5 regression guard: enforce `MAX_ADDRS` so the
        // address-rotation arithmetic in
        // `Reader::reconnect_with_failover` is provably free of usize
        // overflow on 32-bit targets.
        let mut addr = String::from("ws::addr=");
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
        let err = ReaderConfig::from_conf("ws::addr=h:1;failover_max_attempts=0").unwrap_err();
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
        let conf = format!("ws::addr={}", ep);
        let parsed = ReaderConfig::from_conf(&conf).expect("parse round-trip");
        assert_eq!(parsed.addrs(), &[ep]);
    }

    #[test]
    fn endpoint_display_ipv6_brackets() {
        // IPv6 literals contain `:` and would otherwise produce an
        // ambiguous `host:port` collision. Bracketing follows
        // RFC 3986 §3.2.2 (`IP-literal`).
        assert_eq!(Endpoint::new("::1", 9000).to_string(), "[::1]:9000");
        assert_eq!(
            Endpoint::new("2001:db8::1", 443).to_string(),
            "[2001:db8::1]:443"
        );
    }

    #[test]
    fn ipv6_addr_parses_with_explicit_port() {
        let c = ReaderConfig::from_conf("ws::addr=[::1]:9000").unwrap();
        assert_eq!(c.addrs.len(), 1);
        // Stored host is bare; brackets re-applied only by Display.
        assert_eq!(c.addrs[0], Endpoint::new("::1", 9000));
        assert_eq!(c.url_for(0), "ws://[::1]:9000/read/v1");
    }

    #[test]
    fn ipv6_addr_default_port() {
        let c = ReaderConfig::from_conf("ws::addr=[2001:db8::1]").unwrap();
        assert_eq!(c.addrs[0], Endpoint::new("2001:db8::1", 9000));
        assert_eq!(c.url_for(0), "ws://[2001:db8::1]:9000/read/v1");
    }

    #[test]
    fn ipv6_addr_in_multi_addr_list() {
        let c = ReaderConfig::from_conf("ws::addr=[::1]:9000,h2:9001,[2001:db8::5]").unwrap();
        assert_eq!(c.addrs.len(), 3);
        assert_eq!(c.addrs[0], Endpoint::new("::1", 9000));
        assert_eq!(c.addrs[1], Endpoint::new("h2", 9001));
        assert_eq!(c.addrs[2], Endpoint::new("2001:db8::5", 9000));
    }

    #[test]
    fn ipv6_addr_missing_close_bracket_rejected() {
        let err = ReaderConfig::from_conf("ws::addr=[::1:9000").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
    }

    #[test]
    fn ipv6_addr_garbage_after_bracket_rejected() {
        let err = ReaderConfig::from_conf("ws::addr=[::1]junk").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
    }

    #[test]
    fn unbracketed_ipv6_rejected() {
        for bad in [
            "ws::addr=::1",
            "ws::addr=::1:9000",
            "ws::addr=2001:db8::1",
            "ws::addr=fe80::1%eth0",
            "ws::addr=h1:9000,::1:9001",
        ] {
            let err = ReaderConfig::from_conf(bad).unwrap_err();
            assert_eq!(
                err.code(),
                ErrorCode::ConfigError,
                "expected reject for {bad:?}"
            );
            let msg = err.msg();
            assert!(
                msg.contains("multiple ':'") || msg.contains("bracketed"),
                "expected diagnostic to mention bracketing, got {msg:?}"
            );
        }
    }

    #[test]
    fn single_colon_host_port_still_accepted() {
        let c = ReaderConfig::from_conf("ws::addr=h1:9000").unwrap();
        assert_eq!(c.addrs[0], Endpoint::new("h1", 9000));
    }

    #[test]
    fn url_for_uses_endpoint_display() {
        // `url_for` was migrated to format via `{ep}`. Lock the
        // common-case URL string so the migration didn't introduce
        // a regression for the predominant non-IPv6 path users see.
        let c = ReaderConfig::from_conf("ws::addr=db-a:9000;path=/exec").unwrap();
        assert_eq!(c.url_for(0), "ws://db-a:9000/exec");
    }

    #[test]
    fn validate_accepts_parsed_default_config() {
        let c = ReaderConfig::from_conf("ws::addr=h:9000").unwrap();
        c.validate().expect("a freshly-parsed config must validate");
    }

    #[test]
    fn validate_rejects_post_parse_backoff_overflow() {
        let mut c = ReaderConfig::from_conf("ws::addr=h:9000").unwrap();
        c.failover_backoff_max_ms = u64::MAX;
        let err = c.validate().unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
        assert!(
            err.msg().contains("failover_backoff_max_ms"),
            "got: {}",
            err.msg()
        );
    }

    #[test]
    fn validate_rejects_post_parse_max_attempts_overflow() {
        let mut c = ReaderConfig::from_conf("ws::addr=h:9000").unwrap();
        c.failover_max_attempts = MAX_FAILOVER_MAX_ATTEMPTS + 1;
        let err = c.validate().unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
    }

    #[test]
    fn validate_rejects_post_parse_max_attempts_zero() {
        let mut c = ReaderConfig::from_conf("ws::addr=h:9000").unwrap();
        c.failover_max_attempts = 0;
        let err = c.validate().unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
    }

    #[test]
    fn validate_rejects_post_parse_backoff_zero_initial() {
        let mut c = ReaderConfig::from_conf("ws::addr=h:9000").unwrap();
        c.failover_backoff_initial_ms = 0;
        let err = c.validate().unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
    }

    #[test]
    fn validate_rejects_post_parse_backoff_inversion() {
        let mut c = ReaderConfig::from_conf("ws::addr=h:9000").unwrap();
        c.failover_backoff_initial_ms = 1000;
        c.failover_backoff_max_ms = 50;
        let err = c.validate().unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
    }

    #[test]
    fn validate_rejects_post_parse_max_version_out_of_range() {
        let mut c = ReaderConfig::from_conf("ws::addr=h:9000").unwrap();
        c.max_version = 0;
        let err = c.validate().unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
        c.max_version = HIGHEST_KNOWN_VERSION + 1;
        let err = c.validate().unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
    }

    // ---------------------------------------------------------------
    // Post-parse string-field mutation: the parse-time CRLF /
    // control-byte guards must be re-applied by `validate()` so that
    // a hostile or careless caller can't bypass them by mutating the
    // `pub` fields after a clean `from_conf`. The threat is HTTP
    // header injection into the WS upgrade.
    // ---------------------------------------------------------------

    #[test]
    fn validate_rejects_post_parse_client_id_with_crlf() {
        // Clean parse, then mutate to inject a CRLF + a forged
        // Authorization line into the X-QuestDB-Client-Id header.
        let mut c = ReaderConfig::from_conf("ws::addr=h:9000").unwrap();
        c.client_id = Some("foo\r\nAuthorization: Bearer attacker".into());
        let err = c.validate().unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
        assert!(
            err.msg().contains("client_id"),
            "error message must name the offending field; got: {}",
            err.msg()
        );
        // Bare LF and bare CR both rejected.
        c.client_id = Some("foo\nbar".into());
        assert_eq!(c.validate().unwrap_err().code(), ErrorCode::ConfigError);
        c.client_id = Some("foo\rbar".into());
        assert_eq!(c.validate().unwrap_err().code(), ErrorCode::ConfigError);
    }

    #[test]
    fn validate_rejects_post_parse_zone_with_crlf() {
        let mut c = ReaderConfig::from_conf("ws::addr=h:9000").unwrap();
        c.zone = Some("eu-west-1a\r\nX-Injected: 1".into());
        let err = c.validate().unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
        assert!(err.msg().contains("zone"));
    }

    #[test]
    fn validate_rejects_post_parse_verbatim_auth_with_control_bytes() {
        // Verbatim is the highest-risk variant: the value flows
        // unchanged into the `Authorization` header. The parse-time
        // `reject_control_bytes` lives in `AuthMode::from_parts`; the
        // `pub` `auth` field on ReaderConfig lets a caller skip that
        // path entirely.
        let mut c = ReaderConfig::from_conf("ws::addr=h:9000").unwrap();
        c.auth = AuthMode::Verbatim {
            value: "Bearer xx\r\nX-Injected: 1".into(),
        };
        let err = c.validate().unwrap_err();
        assert_eq!(err.code(), ErrorCode::AuthError);
        // Bare LF likewise.
        c.auth = AuthMode::Verbatim {
            value: "Bearer\nyy".into(),
        };
        assert_eq!(c.validate().unwrap_err().code(), ErrorCode::AuthError);
    }

    #[test]
    fn validate_rejects_post_parse_bearer_token_with_control_bytes() {
        let mut c = ReaderConfig::from_conf("ws::addr=h:9000").unwrap();
        c.auth = AuthMode::Bearer {
            token: "abc\r\ndef".into(),
        };
        let err = c.validate().unwrap_err();
        assert_eq!(err.code(), ErrorCode::AuthError);
    }

    #[test]
    fn validate_rejects_post_parse_basic_auth_with_control_bytes() {
        let mut c = ReaderConfig::from_conf("ws::addr=h:9000").unwrap();
        c.auth = AuthMode::Basic {
            username: "user\nfoo".into(),
            password: "pw".into(),
        };
        assert_eq!(c.validate().unwrap_err().code(), ErrorCode::AuthError);
        c.auth = AuthMode::Basic {
            username: "user".into(),
            password: "pw\r\nX-Injected: 1".into(),
        };
        assert_eq!(c.validate().unwrap_err().code(), ErrorCode::AuthError);
    }

    #[test]
    fn validate_rejects_post_parse_basic_username_with_colon() {
        // The colon-in-username check ships in `from_parts` because
        // the server splits credentials on the first ':'. The same
        // hazard re-emerges if the caller assigns a Basic AuthMode
        // directly to the parsed config.
        let mut c = ReaderConfig::from_conf("ws::addr=h:9000").unwrap();
        c.auth = AuthMode::Basic {
            username: "admin:override".into(),
            password: "real".into(),
        };
        let err = c.validate().unwrap_err();
        assert_eq!(err.code(), ErrorCode::AuthError);
    }

    #[test]
    fn validate_accepts_post_parse_clean_string_fields() {
        // Sanity counterpart: clean string fields after a clean parse
        // must still pass — the new validate hooks must not be
        // overzealous.
        let mut c = ReaderConfig::from_conf("ws::addr=h:9000").unwrap();
        c.client_id = Some("benign-id".into());
        c.zone = Some("eu-west-1a".into());
        c.auth = AuthMode::Bearer {
            token: "benign.token.value".into(),
        };
        c.validate().expect("clean string fields must validate");
    }
}
