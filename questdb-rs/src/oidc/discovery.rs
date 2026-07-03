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

//! OIDC configuration discovery.
//!
//! Resolution order:
//! 1. `GET {questdb_url}/settings` (public) → QuestDB-authoritative `acl.oidc.*`
//!    values (client id, scope, endpoints, groups mode).
//! 2. If QuestDB doesn't advertise the device-authorization endpoint, fall back
//!    to the IdP discovery document
//!    (`{issuer}/.well-known/openid-configuration`).
//!
//! The endpoints from `/settings` are only as trustworthy as the channel that
//! delivered them, so this module pins them to an out-of-band `issuer` when one
//! is given, requires the two credential endpoints to share one origin, and
//! rejects a "confusable" authority the HTTP transport might resolve differently
//! than it parses. See the [`oidc`](crate::oidc) module docs.

use ureq::http::Uri;

use crate::oidc::error::{OidcError, Result};
use crate::oidc::http::HttpClient;

// QuestDB /settings keys (see EntPropServerConfiguration.exportConfiguration()).
const K_ENABLED: &str = "acl.oidc.enabled";
const K_CLIENT_ID: &str = "acl.oidc.client.id";
const K_SCOPE: &str = "acl.oidc.scope";
const K_TOKEN_ENDPOINT: &str = "acl.oidc.token.endpoint";
const K_DEVICE_ENDPOINT: &str = "acl.oidc.device.authorization.endpoint";
const K_GROUPS_IN_TOKEN: &str = "acl.oidc.groups.encoded.in.token";
const K_AUDIENCE: &str = "acl.oidc.audience";

/// The resolved OIDC parameters needed to run the device flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcConfig {
    /// The OIDC public-client id registered with the identity provider.
    pub client_id: String,
    /// IdP token endpoint — where the device-code and refresh grants are POSTed.
    pub token_endpoint: String,
    /// IdP device-authorization endpoint (RFC 8628 §3.1).
    pub device_authorization_endpoint: String,
    /// Space-separated scopes. `openid` is added by
    /// [`OidcDeviceAuth`](crate::oidc::OidcDeviceAuth) in groups mode.
    pub scope: String,
    /// When true, present the `id_token` (groups encoded in it) rather than the
    /// `access_token` — mirroring QuestDB's own selection.
    pub groups_in_token: bool,
    /// Optional `audience` sent on the device-code / refresh requests.
    pub audience: Option<String>,
    /// Optional out-of-band IdP pin (its origin / issuer path).
    pub issuer: Option<String>,
}

/// Inputs to [`resolve_config`]: explicit overrides plus the discovery source.
///
/// Any field left `None` is filled from QuestDB `/settings` and, as a last
/// resort for the device endpoint, the IdP discovery document.
#[derive(Debug, Default, Clone)]
pub(crate) struct DiscoveryParams {
    pub(crate) questdb_url: Option<String>,
    pub(crate) client_id: Option<String>,
    pub(crate) scope: Option<String>,
    pub(crate) audience: Option<String>,
    pub(crate) groups_in_token: Option<bool>,
    pub(crate) token_endpoint: Option<String>,
    pub(crate) device_authorization_endpoint: Option<String>,
    pub(crate) issuer: Option<String>,
    /// Allow plaintext http to the QuestDB `/settings` server (never the IdP).
    pub(crate) allow_insecure: bool,
}

const DEFAULT_HTTPS_PORT: u16 = 443;
const DEFAULT_HTTP_PORT: u16 = 80;

fn default_port(scheme: &str) -> Option<u16> {
    match scheme {
        "https" => Some(DEFAULT_HTTPS_PORT),
        "http" => Some(DEFAULT_HTTP_PORT),
        _ => None,
    }
}

/// `(scheme, host, port)` with default ports filled in, for origin comparison.
fn normalized_origin(url: &str) -> Result<(String, String, Option<u16>)> {
    let uri: Uri = url
        .parse()
        .map_err(|e| OidcError::config(format!("Malformed endpoint URL {url:?}: {e}")))?;
    let scheme = uri.scheme_str().unwrap_or("").to_ascii_lowercase();
    let host = uri.host().unwrap_or("").to_ascii_lowercase();
    let port = uri.port_u16().or_else(|| default_port(&scheme));
    Ok((scheme, host, port))
}

fn origin_str(url: &str) -> String {
    match normalized_origin(url) {
        Ok((scheme, host, Some(port))) => format!("{scheme}://{host}:{port}"),
        Ok((scheme, host, None)) => format!("{scheme}://{host}"),
        Err(_) => url.to_string(),
    }
}

/// True if the `/settings` channel is plaintext http to a non-loopback host — a
/// MITM-tamperable channel (only reachable with `allow_insecure_transport`).
fn settings_channel_is_plaintext(questdb_url: &str) -> bool {
    let Ok(uri) = questdb_url.parse::<Uri>() else {
        return false;
    };
    if !uri
        .scheme_str()
        .is_some_and(|s| s.eq_ignore_ascii_case("http"))
    {
        return false;
    }
    let host = uri.host().unwrap_or("");
    !is_loopback_host(host)
}

fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    bare.parse::<std::net::IpAddr>()
        .map(|a| a.is_loopback())
        .unwrap_or(false)
}

/// Reject a credential URL whose authority the HTTP transport may resolve unlike
/// the way it parses (userinfo `@`, a non-ASCII / confusable host, a backslash,
/// whitespace, a control character, or `%`), or that carries a raw tab / newline
/// / CR anywhere. A real endpoint host is plain ASCII and never carries these.
pub(crate) fn reject_confusable_authority(url: &str, label: &str) -> Result<()> {
    // Tab / newline / CR are silently removed by URI parsers but kept by some
    // HTTP transports, so the authority validated would diverge from the one
    // connected to. Check the RAW url.
    if url.contains(['\t', '\n', '\r']) {
        return Err(confusable_error(url, label));
    }
    let uri: Uri = url.parse().map_err(|_| confusable_error(url, label))?;
    let authority = uri.authority().map(|a| a.as_str()).unwrap_or("");
    let unsafe_byte = authority
        .bytes()
        .any(|b| b == b'\\' || b == b'%' || b == b'@' || b <= 0x20 || b == 0x7f || b >= 0x80);
    if authority.is_empty() || unsafe_byte {
        return Err(confusable_error(url, label));
    }
    Ok(())
}

fn confusable_error(url: &str, label: &str) -> OidcError {
    OidcError::config(format!(
        "The OIDC {label} URL {url:?} has an unsafe authority (userinfo '@', a \
         non-ASCII character, a backslash, whitespace, a control character, or \
         '%'). A real endpoint host is plain ASCII (a DNS name, an xn-- punycode \
         label, or an IP literal); refusing to send credentials to a host the \
         HTTP transport may resolve differently than the one validated. Pass the \
         punycode (xn--) form for an internationalized domain."
    ))
}

/// Require the two credential endpoints to share a single origin.
///
/// The device code and long-lived refresh token are POSTed to these two
/// endpoints, which RFC 8628 always co-locates on one authorization server. A
/// configuration that splits them across origins is malformed or tampered.
pub(crate) fn validate_endpoint_origins(
    token_endpoint: &str,
    device_authorization_endpoint: &str,
) -> Result<()> {
    // Reject a confusable authority FIRST, so the origin comparison can't
    // validate a host different from the one the transport will connect to.
    reject_confusable_authority(token_endpoint, "token endpoint")?;
    reject_confusable_authority(
        device_authorization_endpoint,
        "device-authorization endpoint",
    )?;
    if normalized_origin(token_endpoint)? != normalized_origin(device_authorization_endpoint)? {
        return Err(OidcError::config(format!(
            "OIDC token and device-authorization endpoints are on different \
             origins ({} vs {}); refusing to send credentials. This indicates a \
             misconfigured or tampered OIDC configuration.",
            origin_str(token_endpoint),
            origin_str(device_authorization_endpoint)
        )));
    }
    Ok(())
}

/// True if `endpoint`'s path is the issuer's path or a sub-path of it.
///
/// Segment-aware, so `/realms/prod` does not match `/realms/production`. A root
/// issuer (no path) constrains the origin only and matches any path. Compared on
/// fully percent-decoded, matrix-param-stripped segments; a `.` / `..` /
/// still-encoded / non-ASCII / control segment is rejected outright, so a
/// tampered `/settings` can't redirect credentials to a different tenant on a
/// path-based multi-tenant IdP (e.g. Keycloak `https://host/realms/{realm}`).
pub(crate) fn endpoint_path_under_issuer(endpoint: &str, issuer: &str) -> bool {
    let Ok(issuer_uri) = issuer.parse::<Uri>() else {
        return false;
    };
    let base = issuer_uri.path().trim_end_matches('/');
    if base.is_empty() {
        return true;
    }
    let base_segs: Vec<String> = decode_path_segments(base)
        .iter()
        .map(|s| strip_matrix_params(s))
        .collect();
    let Ok(ep_uri) = endpoint.parse::<Uri>() else {
        return false;
    };
    let ep_segs: Vec<String> = decode_path_segments(ep_uri.path())
        .iter()
        .map(|s| strip_matrix_params(s))
        .collect();
    for seg in &ep_segs {
        // A `.` / `..` (the server normalizes it away, so a naive prefix test
        // passes yet the real path differs), a residual `%` (did not fully
        // decode — a server may decode it further to a dot-segment), a non-ASCII
        // segment (a homoglyph dot could NFKC-fold to a real `..`), or a control
        // char all fail closed.
        if seg == "."
            || seg == ".."
            || seg.contains('%')
            || !seg.is_ascii()
            || has_control_char(seg)
        {
            return false;
        }
    }
    ep_segs.len() >= base_segs.len() && ep_segs[..base_segs.len()] == base_segs[..]
}

/// Percent-decode a path (repeatedly, bounded) and split into `/` segments.
/// Backslash is treated as a separator (some proxies fold `\` to `/`).
fn decode_path_segments(path: &str) -> Vec<String> {
    let mut decoded = path.to_string();
    for _ in 0..10 {
        let next = percent_decode(&decoded);
        if next == decoded {
            break;
        }
        decoded = next;
    }
    decoded
        .replace('\\', "/")
        .split('/')
        .map(|s| s.to_string())
        .collect()
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2]))
        {
            out.push(h * 16 + l);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Reduce a decoded path segment the way a server normalizes it before
/// dot-segment removal: drop a `;` matrix-parameter suffix and trim whitespace.
fn strip_matrix_params(segment: &str) -> String {
    segment.split(';').next().unwrap_or("").trim().to_string()
}

fn has_control_char(segment: &str) -> bool {
    segment.bytes().any(|b| b < 0x20 || b == 0x7f)
}

fn well_known_url(issuer: &str) -> String {
    format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    )
}

/// A `/settings` value as a non-empty string, else `None` (drops a non-string
/// value so it can't reach the cache-key join as a raw object).
fn str_setting(value: Option<&serde_json::Value>) -> Option<String> {
    match value {
        Some(serde_json::Value::String(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

/// A `/settings` endpoint, trusted only as a complete `http(s)` URL. A path-only
/// (or non-string) value is treated as absent, so resolution falls back to IdP
/// discovery (which requires an `issuer` pin).
fn resolve_endpoint(value: Option<&serde_json::Value>) -> Option<String> {
    let s = str_setting(value)?;
    if s.starts_with("https://") || s.starts_with("http://") {
        Some(s)
    } else {
        None
    }
}

fn as_bool(value: Option<&serde_json::Value>, default: Option<bool>) -> Option<bool> {
    match value {
        None | Some(serde_json::Value::Null) => default,
        Some(serde_json::Value::Bool(b)) => Some(*b),
        Some(serde_json::Value::Number(n)) => Some(n.as_f64().map(|f| f != 0.0).unwrap_or(false)),
        Some(serde_json::Value::String(s)) => match s.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => Some(true),
            "false" | "0" | "no" | "off" | "" => Some(false),
            _ => default,
        },
        _ => default,
    }
}

/// The trusted config map from a `/settings` response.
///
/// Modern QuestDB nests server-authoritative values under `"config"`, alongside
/// a user-writable `"preferences"` sibling. Read only `"config"` so a user who
/// can write a preference can't smuggle an `acl.oidc.*` key (e.g. a redirected
/// `token.endpoint`) into the resolved config. A genuinely flat legacy response
/// is still tolerated.
fn settings_config(settings: &serde_json::Value) -> serde_json::Value {
    let obj = match settings.as_object() {
        Some(o) => o,
        None => return serde_json::Value::Object(Default::default()),
    };
    if let Some(cfg) = obj.get("config")
        && cfg.is_object()
    {
        return cfg.clone();
    }
    // Either marker present => structured response: read "config" or nothing,
    // never the user-writable top level.
    if obj.contains_key("config") || obj.contains_key("preferences") {
        return serde_json::Value::Object(Default::default());
    }
    settings.clone()
}

fn settings_url(questdb_url: &str) -> Result<String> {
    let uri: Uri = questdb_url
        .parse()
        .map_err(|e| OidcError::config(format!("Malformed QuestDB URL {questdb_url:?}: {e}")))?;
    let scheme = uri.scheme_str().unwrap_or("").to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(OidcError::config(format!(
            "The QuestDB URL {questdb_url:?} needs an explicit http(s):// scheme, \
             e.g. \"https://questdb.example.com:9000\"."
        )));
    }
    let authority = uri
        .authority()
        .map(|a| a.as_str())
        .ok_or_else(|| OidcError::config(format!("QuestDB URL {questdb_url:?} has no host.")))?;
    let path = uri.path().trim_end_matches('/');
    Ok(format!("{scheme}://{authority}{path}/settings"))
}

/// Fetch the IdP `.well-known/openid-configuration`, verifying its self-declared
/// issuer matches the pinned one. Always held to https/loopback.
fn discover_from_idp(http: &HttpClient, issuer: &str) -> Result<serde_json::Value> {
    let doc = http.get_json(&well_known_url(issuer), false)?;
    if !doc.is_object() {
        return Ok(serde_json::Value::Object(Default::default()));
    }
    // RFC 8414: the document's own `issuer` MUST match the one it was fetched
    // from. We fetched over TLS from the pinned issuer's origin, so this turns a
    // wrong-tenant IdP into a clear failure rather than silently trusting its
    // endpoints.
    if let Some(doc_issuer) = str_setting(doc.get("issuer"))
        && doc_issuer.trim_end_matches('/') != issuer.trim_end_matches('/')
    {
        return Err(OidcError::config(format!(
            "The IdP discovery document declares issuer {doc_issuer:?}, which \
                 does not match the pinned issuer {issuer:?}; refusing to use its \
                 endpoints. Pass the endpoints explicitly to skip discovery."
        )));
    }
    Ok(doc)
}

/// Resolve a complete [`OidcConfig`]. Explicit `params` always win; anything
/// left `None` is filled from QuestDB `/settings` and, as a last resort for the
/// device endpoint, the IdP discovery document.
pub(crate) fn resolve_config(http: &HttpClient, params: &DiscoveryParams) -> Result<OidcConfig> {
    let mut cfg = serde_json::Value::Object(Default::default());
    if let Some(url) = params.questdb_url.as_deref() {
        let settings = http.get_json(&settings_url(url)?, params.allow_insecure)?;
        cfg = settings_config(&settings);
        if as_bool(cfg.get(K_ENABLED), None) == Some(false) {
            return Err(OidcError::config(format!(
                "QuestDB at {url} reports OIDC is disabled ({K_ENABLED}=false). \
                 Nothing to authenticate against."
            )));
        }
    }

    let client_id = params
        .client_id
        .clone()
        .or_else(|| str_setting(cfg.get(K_CLIENT_ID)))
        .ok_or_else(|| {
            OidcError::config(format!(
                "Missing OIDC client_id. QuestDB did not advertise {K_CLIENT_ID:?} \
                 via /settings; pass client_id(...) explicitly."
            ))
        })?;

    let scope = params
        .scope
        .clone()
        .filter(|s| !s.is_empty())
        .or_else(|| str_setting(cfg.get(K_SCOPE)))
        .unwrap_or_else(|| "openid".to_string());
    let groups_in_token = params
        .groups_in_token
        .or_else(|| as_bool(cfg.get(K_GROUPS_IN_TOKEN), Some(false)))
        .unwrap_or(false);
    let audience = params
        .audience
        .clone()
        .filter(|a| !a.is_empty())
        .or_else(|| str_setting(cfg.get(K_AUDIENCE)));
    let issuer = params.issuer.clone().filter(|s| !s.is_empty());

    // Track provenance: caller-explicit endpoints are trusted; /settings ones
    // are only as trustworthy as the channel that delivered them.
    let explicit_token = params.token_endpoint.is_some();
    let explicit_device = params.device_authorization_endpoint.is_some();

    let mut token_endpoint = params
        .token_endpoint
        .clone()
        .or_else(|| resolve_endpoint(cfg.get(K_TOKEN_ENDPOINT)));
    let mut device_endpoint = params
        .device_authorization_endpoint
        .clone()
        .or_else(|| resolve_endpoint(cfg.get(K_DEVICE_ENDPOINT)));

    let token_from_settings = token_endpoint.is_some() && !explicit_token;
    let device_from_settings = device_endpoint.is_some() && !explicit_device;

    // Over a plaintext /settings channel a tampered response can advertise both
    // credential endpoints at one attacker origin, with every later check
    // passing trivially. Demand an out-of-band issuer pin first.
    let settings_supplied = token_from_settings || device_from_settings;
    if let Some(url) = params.questdb_url.as_deref()
        && settings_supplied
        && issuer.is_none()
        && settings_channel_is_plaintext(url)
    {
        return Err(OidcError::config(
            "QuestDB was reached over plaintext http, so its /settings \
                 response — and the OIDC endpoints it advertises — can be tampered \
                 in transit and used to redirect the device-code and \
                 refresh-token requests to an attacker. Pin the identity provider \
                 out-of-band with issuer(\"https://your-idp\"), pass the endpoints \
                 explicitly, or connect to QuestDB over https.",
        ));
    }

    // Vet the issuer authority before it is used to build the discovery URL.
    if let Some(iss) = issuer.as_deref() {
        reject_confusable_authority(iss, "issuer")?;
    }

    let mut doc_token_endpoint: Option<String> = None;
    let mut doc_device_endpoint: Option<String> = None;

    // Fall back to IdP discovery when QuestDB doesn't advertise an endpoint. The
    // IdP is always held to https/loopback (never the allow_insecure flag).
    if token_endpoint.is_none() || device_endpoint.is_none() {
        let Some(iss) = issuer.as_deref() else {
            return Err(OidcError::config(
                "QuestDB did not advertise the OIDC device-authorization endpoint \
                 (and/or the token endpoint), so it must be discovered from the \
                 identity provider, but the IdP is not pinned. Pass \
                 issuer(\"https://your-idp\") so a tampered or intercepted \
                 /settings response cannot redirect the device-code and \
                 refresh-token requests to an attacker. Alternatively pass the \
                 endpoint(s) explicitly to skip discovery.",
            ));
        };
        let doc = discover_from_idp(http, iss)?;
        doc_token_endpoint = str_setting(doc.get("token_endpoint"));
        doc_device_endpoint = str_setting(doc.get("device_authorization_endpoint"));
        if device_endpoint.is_none() {
            device_endpoint = doc_device_endpoint.clone();
        }
        if token_endpoint.is_none() {
            token_endpoint = doc_token_endpoint.clone();
        }
    }

    let token_endpoint = token_endpoint.ok_or_else(|| {
        OidcError::config(
            "Could not resolve the OIDC token endpoint from QuestDB /settings or \
             IdP discovery. Pass token_endpoint(...) explicitly.",
        )
    })?;
    let device_endpoint = device_endpoint.ok_or_else(|| {
        OidcError::config(
            "Could not resolve the device-authorization endpoint. The IdP \
             discovery document did not contain \"device_authorization_endpoint\". \
             Ensure the IdP supports the device grant, or pass \
             device_authorization_endpoint(...) explicitly.",
        )
    })?;

    // Pin /settings-sourced endpoints to the out-of-band issuer (origin AND, for
    // a path-based multi-tenant IdP, path). Waived for an endpoint the IdP's own
    // discovery document confirmed. Caller-explicit / IdP-discovered endpoints
    // are authoritative and skip this (the issuer is an OIDC identifier, not
    // necessarily the endpoints' host).
    if let Some(iss) = issuer.as_deref() {
        let issuer_origin = normalized_origin(iss)?;
        for (label, url, from_settings, confirmed) in [
            (
                "token endpoint",
                &token_endpoint,
                token_from_settings,
                &doc_token_endpoint,
            ),
            (
                "device-authorization endpoint",
                &device_endpoint,
                device_from_settings,
                &doc_device_endpoint,
            ),
        ] {
            if !from_settings || confirmed.as_deref() == Some(url.as_str()) {
                continue;
            }
            if normalized_origin(url)? != issuer_origin {
                return Err(OidcError::config(format!(
                    "The OIDC {label} advertised by QuestDB /settings ({url:?}) is \
                     not on the pinned issuer origin ({}) and was not confirmed by \
                     the IdP discovery document; refusing to send credentials \
                     outside the trusted issuer. If your IdP serves tokens from a \
                     different origin than its issuer, pass the endpoint(s) \
                     explicitly.",
                    origin_str(iss)
                )));
            }
            if !endpoint_path_under_issuer(url, iss) {
                return Err(OidcError::config(format!(
                    "The OIDC {label} advertised by QuestDB /settings ({url:?}) is \
                     not under the pinned issuer ({iss:?}) and was not confirmed by \
                     the IdP discovery document; refusing to send credentials to a \
                     different tenant on the same host. If your IdP places \
                     endpoints outside the issuer path, pass them explicitly."
                )));
            }
        }
    }

    // The credential-endpoint co-location check is enforced centrally by the
    // caller (OidcDeviceAuth builder) via validate_endpoint_origins.
    Ok(OidcConfig {
        client_id,
        token_endpoint,
        device_authorization_endpoint: device_endpoint,
        scope,
        groups_in_token,
        audience,
        issuer,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn co_located_endpoints_ok() {
        assert!(
            validate_endpoint_origins(
                "https://idp.example.com/token",
                "https://idp.example.com/device"
            )
            .is_ok()
        );
    }

    #[test]
    fn cross_origin_endpoints_rejected() {
        let err = validate_endpoint_origins(
            "https://idp.example.com/token",
            "https://evil.example.com/device",
        )
        .unwrap_err();
        assert_eq!(err.kind(), crate::oidc::error::OidcErrorKind::Config);
    }

    #[test]
    fn default_port_folds_into_origin() {
        // Explicit :443 vs implicit default must compare equal.
        assert!(
            validate_endpoint_origins(
                "https://idp.example.com:443/token",
                "https://idp.example.com/device"
            )
            .is_ok()
        );
    }

    #[test]
    fn confusable_authority_userinfo_rejected() {
        assert!(
            reject_confusable_authority("https://trusted.io@evil.example/token", "token").is_err()
        );
    }

    #[test]
    fn confusable_authority_backslash_rejected() {
        assert!(
            reject_confusable_authority("https://evil.example\\@idp.good/token", "token").is_err()
        );
    }

    #[test]
    fn confusable_authority_non_ascii_rejected() {
        assert!(reject_confusable_authority("https://exa\u{0430}mple.com/token", "token").is_err());
    }

    #[test]
    fn confusable_authority_newline_rejected() {
        assert!(reject_confusable_authority("https://idp\n.example.com/token", "token").is_err());
    }

    #[test]
    fn confusable_authority_plain_ok() {
        assert!(reject_confusable_authority("https://idp.example.com:8443/token", "token").is_ok());
    }

    #[test]
    fn issuer_path_pin_matches_subpath() {
        assert!(endpoint_path_under_issuer(
            "https://host/realms/prod/protocol/openid-connect/token",
            "https://host/realms/prod"
        ));
    }

    #[test]
    fn issuer_path_pin_rejects_sibling_tenant() {
        assert!(!endpoint_path_under_issuer(
            "https://host/realms/production/token",
            "https://host/realms/prod"
        ));
    }

    #[test]
    fn issuer_path_pin_rejects_traversal() {
        assert!(!endpoint_path_under_issuer(
            "https://host/realms/prod/../attacker/token",
            "https://host/realms/prod"
        ));
        // Percent-encoded traversal decodes and is caught too.
        assert!(!endpoint_path_under_issuer(
            "https://host/realms/prod/%2e%2e/attacker/token",
            "https://host/realms/prod"
        ));
    }

    #[test]
    fn root_issuer_matches_any_path() {
        assert!(endpoint_path_under_issuer(
            "https://host/anything/token",
            "https://host"
        ));
    }

    #[test]
    fn settings_config_prefers_config_object() {
        let settings = serde_json::json!({
            "config": {"acl.oidc.client.id": "real"},
            "preferences": {"acl.oidc.client.id": "attacker"}
        });
        let cfg = settings_config(&settings);
        assert_eq!(str_setting(cfg.get(K_CLIENT_ID)).as_deref(), Some("real"));
    }

    #[test]
    fn settings_config_ignores_top_level_when_structured() {
        // A structured response (has "preferences") must not leak top-level keys.
        let settings = serde_json::json!({
            "preferences": {},
            "acl.oidc.client.id": "attacker"
        });
        let cfg = settings_config(&settings);
        assert_eq!(str_setting(cfg.get(K_CLIENT_ID)), None);
    }

    #[test]
    fn settings_config_tolerates_legacy_flat() {
        let settings = serde_json::json!({"acl.oidc.client.id": "legacy"});
        let cfg = settings_config(&settings);
        assert_eq!(str_setting(cfg.get(K_CLIENT_ID)).as_deref(), Some("legacy"));
    }

    #[test]
    fn settings_url_appends_path() {
        assert_eq!(
            settings_url("https://host:9000").unwrap(),
            "https://host:9000/settings"
        );
        assert_eq!(
            settings_url("https://host:9000/").unwrap(),
            "https://host:9000/settings"
        );
    }

    #[test]
    fn settings_url_requires_scheme() {
        assert!(settings_url("host:9000").is_err());
    }

    #[test]
    fn plaintext_non_loopback_settings_channel_flagged() {
        // The guard that (absent an issuer pin) rejects settings-supplied
        // endpoints fires only for a non-loopback plaintext http channel — the
        // MITM-tamperable case. https and loopback http are never flagged. (The
        // full resolve_config rejection needs a non-loopback server, so the guard
        // logic is asserted here directly.)
        assert!(settings_channel_is_plaintext(
            "http://questdb.example.com:9000"
        ));
        assert!(!settings_channel_is_plaintext(
            "https://questdb.example.com:9000"
        ));
        assert!(!settings_channel_is_plaintext("http://localhost:9000"));
        assert!(!settings_channel_is_plaintext("http://127.0.0.1:9000"));
        assert!(!settings_channel_is_plaintext("http://[::1]:9000"));
    }
}
