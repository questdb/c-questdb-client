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

//! The OAuth 2.0 device authorization grant (RFC 8628) token manager.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::oidc::discovery::{
    DiscoveryParams, OidcConfig, resolve_config, validate_endpoint_origins,
};
use crate::oidc::error::{OidcError, Result};
use crate::oidc::http::HttpClient;
use crate::oidc::render::{DeviceCodeChallenge, Renderer, TerminalRenderer, maybe_open_browser};
use crate::oidc::token::{DEFAULT_SKEW_SECONDS, TokenSet, now_epoch};

const DEVICE_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
const REFRESH_GRANT: &str = "refresh_token";

// Clamp the token lifetime (access/id-token TTL). An absent or non-positive
// `expires_in` is non-conformant; fall back to a short lifetime so a token with
// no stated lifetime is refreshed promptly. A very long (or hostile) lifetime is
// capped so a cached token is re-checked at least hourly — silently when a
// refresh token is available, otherwise by re-prompting (see the module docs on
// `offline_access`).
const DEFAULT_EXPIRES_IN: i64 = 300;
const MAX_EXPIRES_IN: i64 = 3600;

// Clamp the device-authorization timing fields so a hostile / buggy response
// can't time the flow out before its first poll, pin the polling thread in one
// huge sleep, or keep the loop alive indefinitely.
const DEFAULT_DEVICE_CODE_LIFETIME: u64 = 600;
const MAX_DEVICE_CODE_LIFETIME: u64 = 1800;
const MIN_POLL_INTERVAL: u64 = 5;
const MAX_POLL_INTERVAL: u64 = 60;

// A token-endpoint round-trip never needs longer; bounding it keeps a stalled
// IdP from pinning the acquisition lock. Matches the reference clients.
const MAX_TIMEOUT: Duration = Duration::from_secs(120);
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_INTERVAL: u64 = 5;

type SleepFn = Arc<dyn Fn(Duration) + Send + Sync>;

/// The RFC 8628 device-authorization response (device code is a secret used only
/// in the poll body, never displayed).
struct DeviceResponse {
    device_code: String,
    challenge: DeviceCodeChallenge,
    expires_in: u64,
    interval: u64,
}

/// Builds an [`OidcDeviceAuth`], either from QuestDB `/settings` discovery
/// ([`OidcDeviceAuth::from_questdb`]) or from explicit IdP configuration
/// ([`OidcDeviceAuth::builder`]).
pub struct OidcDeviceAuthBuilder {
    questdb_url: Option<String>,
    client_id: Option<String>,
    scope: Option<String>,
    audience: Option<String>,
    groups_in_token: Option<bool>,
    issuer: Option<String>,
    token_endpoint: Option<String>,
    device_authorization_endpoint: Option<String>,
    allow_insecure: bool,
    ca_bundle: Option<PathBuf>,
    open_browser: bool,
    interactive: Option<bool>,
    default_interval: u64,
    timeout: Duration,
    renderer: Option<Box<dyn Renderer>>,
    sleep: Option<SleepFn>,
}

impl OidcDeviceAuthBuilder {
    fn new(questdb_url: Option<String>) -> Self {
        OidcDeviceAuthBuilder {
            questdb_url,
            client_id: None,
            scope: None,
            audience: None,
            groups_in_token: None,
            issuer: None,
            token_endpoint: None,
            device_authorization_endpoint: None,
            allow_insecure: false,
            ca_bundle: None,
            open_browser: true,
            interactive: None,
            default_interval: DEFAULT_INTERVAL,
            timeout: DEFAULT_TIMEOUT,
            renderer: None,
            sleep: None,
        }
    }

    /// Override the discovered OAuth client id (required when not discovered).
    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// Override the discovered scopes (space-separated). `openid` is added
    /// automatically in groups mode.
    pub fn scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    /// Override the discovered OAuth `audience` (some IdPs, e.g. Auth0, require
    /// it to mint a token QuestDB accepts).
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// Override the discovered groups-in-token mode (`true` selects the
    /// `id_token` and forces the `openid` scope).
    pub fn groups_in_token(mut self, groups_in_token: bool) -> Self {
        self.groups_in_token = Some(groups_in_token);
        self
    }

    /// Pin the token issuer out-of-band. **Required** when the server does not
    /// advertise the device-authorization endpoint (so it is discovered from the
    /// IdP), so a tampered `/settings` cannot redirect the credential requests.
    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Set the IdP token endpoint explicitly (skips discovering it).
    pub fn token_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.token_endpoint = Some(endpoint.into());
        self
    }

    /// Set the IdP device-authorization endpoint explicitly (skips discovery).
    pub fn device_authorization_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.device_authorization_endpoint = Some(endpoint.into());
        self
    }

    /// Allow plaintext `http` to the QuestDB `/settings` server (local dev only).
    /// The identity provider is always held to `https` (or loopback `http`), so
    /// the device code and refresh token are never sent in cleartext.
    pub fn allow_insecure_transport(mut self, allow: bool) -> Self {
        self.allow_insecure = allow;
        self
    }

    /// Verify TLS to QuestDB and the IdP against this PEM CA bundle (e.g. a
    /// private/corporate CA) instead of the system trust store.
    pub fn ca_bundle(mut self, path: impl Into<PathBuf>) -> Self {
        self.ca_bundle = Some(path.into());
        self
    }

    /// Attempt to open the verification URL in a browser (default `true`). When
    /// `false`, the URL is only printed.
    pub fn open_browser(mut self, open: bool) -> Self {
        self.open_browser = open;
        self
    }

    /// Force interactive (`true`) or non-interactive (`false`) mode; the default
    /// auto-detects a terminal on `stderr`. A non-interactive context errors
    /// rather than starting a prompt no one can answer.
    pub fn interactive(mut self, interactive: bool) -> Self {
        self.interactive = Some(interactive);
        self
    }

    /// Fallback poll interval in seconds when the IdP's response omits one
    /// (default 5; clamped to the RFC 8628 range).
    pub fn default_interval(mut self, seconds: u64) -> Self {
        self.default_interval = seconds;
        self
    }

    /// Per-request HTTP timeout for each IdP call (default 30s; must not exceed
    /// 120s).
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Use a custom [`Renderer`] for the device-code prompt (default:
    /// [`TerminalRenderer`]). Its callbacks must not re-enter this instance's
    /// [`token`](OidcDeviceAuth::token) / [`clear`](OidcDeviceAuth::clear).
    pub fn renderer(mut self, renderer: impl Renderer + 'static) -> Self {
        self.renderer = Some(Box::new(renderer));
        self
    }

    #[cfg(test)]
    pub(crate) fn sleep_hook(mut self, sleep: SleepFn) -> Self {
        self.sleep = Some(sleep);
        self
    }

    /// Resolve the configuration (running discovery if needed) and build the
    /// [`OidcDeviceAuth`].
    pub fn build(self) -> Result<OidcDeviceAuth> {
        if self.timeout > MAX_TIMEOUT || self.timeout.is_zero() {
            return Err(OidcError::config(format!(
                "timeout must be positive and must not exceed {}s.",
                MAX_TIMEOUT.as_secs()
            )));
        }

        let http = HttpClient::new(self.ca_bundle.as_deref(), self.timeout)?;
        let params = DiscoveryParams {
            questdb_url: self.questdb_url,
            client_id: self.client_id,
            scope: self.scope,
            audience: self.audience,
            groups_in_token: self.groups_in_token,
            token_endpoint: self.token_endpoint,
            device_authorization_endpoint: self.device_authorization_endpoint,
            issuer: self.issuer,
            allow_insecure: self.allow_insecure,
        };
        let mut config = resolve_config(&http, &params)?;

        // Sending the id_token requires the `openid` scope.
        if config.groups_in_token && !config.scope.split_whitespace().any(|s| s == "openid") {
            config.scope = format!("openid {}", config.scope).trim().to_string();
        }

        // Enforce credential-endpoint co-location centrally (every construction
        // path goes through here).
        validate_endpoint_origins(
            &config.token_endpoint,
            &config.device_authorization_endpoint,
        )?;

        Ok(OidcDeviceAuth {
            config,
            http,
            renderer: self
                .renderer
                .unwrap_or_else(|| Box::new(TerminalRenderer::new())),
            open_browser: self.open_browser,
            interactive: self.interactive,
            default_interval: self.default_interval,
            sleep: self.sleep.unwrap_or_else(|| Arc::new(std::thread::sleep)),
            tokens: Mutex::new(None),
            acquire: Mutex::new(()),
        })
    }
}

/// Acquires and silently refreshes an OIDC token via the device authorization
/// grant (RFC 8628).
///
/// Most users call [`token`](Self::token) (or build a sender with a token
/// provider). The first call runs the interactive device flow; later calls
/// return the cached token. Once it nears expiry it is refreshed silently when
/// the IdP issued a refresh token (request the `offline_access` scope — see the
/// [module docs](crate::oidc)), otherwise a fresh interactive sign-in is run.
/// Acquisition is serialized so concurrent callers don't double-prompt, while a
/// valid cached token is returned without blocking on another's sign-in.
///
/// Token state is in-memory only and does not survive a process restart.
///
/// # Concurrency
///
/// The acquisition lock is held for a whole interactive sign-in: a caller with a
/// *valid* cached token never blocks, but one whose token is missing/expired
/// waits behind the signer. When sharing an instance across threads (e.g. a
/// long-lived sender), call [`sign_in`](Self::sign_in) once up front. A custom
/// [`Renderer`]'s callbacks run while this lock is held, so they must not call
/// back into the same instance's [`token`](Self::token) / [`clear`](Self::clear)
/// (that would deadlock).
pub struct OidcDeviceAuth {
    config: OidcConfig,
    http: HttpClient,
    renderer: Box<dyn Renderer>,
    open_browser: bool,
    interactive: Option<bool>,
    default_interval: u64,
    sleep: SleepFn,
    /// The cached token; short critical sections only.
    tokens: Mutex<Option<TokenSet>>,
    /// Held across a silent refresh or interactive sign-in.
    acquire: Mutex<()>,
}

impl std::fmt::Debug for OidcDeviceAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the cached token; report only the resolved config.
        f.debug_struct("OidcDeviceAuth")
            .field("config", &self.config)
            .field("open_browser", &self.open_browser)
            .field("interactive", &self.interactive)
            .finish_non_exhaustive()
    }
}

impl OidcDeviceAuth {
    /// Build an [`OidcDeviceAuth`] by discovering config from a QuestDB server's
    /// `/settings` (client id, scope, endpoints, groups mode), falling back to
    /// the IdP `.well-known` document for the device-authorization endpoint when
    /// QuestDB doesn't advertise it (which requires [`issuer`](OidcDeviceAuthBuilder::issuer)).
    pub fn from_questdb(url: impl Into<String>) -> OidcDeviceAuthBuilder {
        OidcDeviceAuthBuilder::new(Some(url.into()))
    }

    /// Build an [`OidcDeviceAuth`] from explicit IdP configuration (no server
    /// discovery). At minimum set [`client_id`](OidcDeviceAuthBuilder::client_id),
    /// [`token_endpoint`](OidcDeviceAuthBuilder::token_endpoint) and
    /// [`device_authorization_endpoint`](OidcDeviceAuthBuilder::device_authorization_endpoint).
    pub fn builder() -> OidcDeviceAuthBuilder {
        OidcDeviceAuthBuilder::new(None)
    }

    /// The resolved OIDC configuration.
    pub fn config(&self) -> &OidcConfig {
        &self.config
    }

    /// Return a valid token for QuestDB, acquiring or refreshing as needed.
    ///
    /// Returns the `id_token` when the server expects groups encoded in the
    /// token (`acl.oidc.groups.encoded.in.token=true`), else the `access_token`
    /// — mirroring QuestDB's own selection.
    pub fn token(&self) -> Result<String> {
        let tokens = self.obtain_tokens()?;
        self.select(&tokens)
    }

    /// Return the full `Authorization` header value: `Bearer <token>`.
    pub fn authorization_header_value(&self) -> Result<String> {
        Ok(format!("Bearer {}", self.token()?))
    }

    /// Sign in now (prompting if needed), caching the token for later use.
    ///
    /// Call this once up front when sharing the instance across threads, so the
    /// interactive prompt runs on the main thread rather than on a busy worker.
    pub fn sign_in(&self) -> Result<()> {
        self.obtain_tokens().map(|_| ())
    }

    /// Forget the cached token, forcing a fresh sign-in next time. Resets the
    /// local cache only — it does not revoke the token at the IdP.
    pub fn clear(&self) {
        let _acq = self.lock_acquire();
        *self.lock_tokens() = None;
    }

    /// The currently cached [`TokenSet`], or `None` if no sign-in has completed
    /// yet (or the cache was [`clear`](Self::clear)ed).
    ///
    /// A read-only snapshot for inspecting token metadata (expiry, scope, type)
    /// — this never prompts, acquires, or refreshes, and never blocks behind an
    /// in-flight sign-in. The returned set may be at or past expiry; check
    /// [`expires_at`](TokenSet::expires_at) if that matters.
    ///
    /// ```no_run
    /// # use questdb::oidc::OidcDeviceAuth;
    /// # fn main() -> questdb::Result<()> {
    /// let auth = OidcDeviceAuth::from_questdb("https://questdb.example.com:9000")
    ///     .issuer("https://idp.example.com")
    ///     .build()?;
    /// if let Some(tokens) = auth.token_set() {
    ///     println!("token expires at epoch {}", tokens.expires_at());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn token_set(&self) -> Option<TokenSet> {
        self.lock_tokens().clone()
    }

    // -- token lifecycle ----------------------------------------------------

    fn select(&self, tokens: &TokenSet) -> Result<String> {
        if self.config.groups_in_token {
            tokens.id_token.clone().ok_or_else(|| {
                OidcError::config(format!(
                    "Server expects groups encoded in the token but the IdP \
                     returned no id_token. Ensure the \"openid\" scope is \
                     requested (current scope: {:?}).",
                    self.config.scope
                ))
            })
        } else {
            tokens
                .access_token
                .clone()
                .ok_or_else(|| OidcError::config("IdP returned no access_token."))
        }
    }

    fn has_required_token(&self, tokens: &TokenSet) -> bool {
        if self.config.groups_in_token {
            tokens.id_token.is_some()
        } else {
            tokens.access_token.is_some()
        }
    }

    // Recover from a poisoned lock rather than propagate the panic: the guarded
    // data (`()` and `Option<TokenSet>`) is always consistent, and a panic in a
    // user-supplied renderer / sleep hook while `acquire` is held must not brick
    // every later `token()` / `clear()` on a long-lived shared instance.
    fn lock_acquire(&self) -> std::sync::MutexGuard<'_, ()> {
        self.acquire.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn lock_tokens(&self) -> std::sync::MutexGuard<'_, Option<TokenSet>> {
        self.tokens.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn cached_if_valid(&self) -> Option<TokenSet> {
        let guard = self.lock_tokens();
        let tokens = guard.as_ref()?;
        if tokens.is_valid(now_epoch(), DEFAULT_SKEW_SECONDS) && self.has_required_token(tokens) {
            Some(tokens.clone())
        } else {
            None
        }
    }

    fn obtain_tokens(&self) -> Result<TokenSet> {
        // Fast path: a valid cached token never blocks behind another sign-in.
        if let Some(tokens) = self.cached_if_valid() {
            return Ok(tokens);
        }
        // Slow path: serialize acquisition so concurrent callers don't overlap
        // refreshes or double-prompt.
        let _acq = self.lock_acquire();
        if let Some(tokens) = self.cached_if_valid() {
            return Ok(tokens);
        }

        // Try a silent refresh with any cached refresh token.
        let existing = self.lock_tokens().clone();
        if let Some(tokens) = &existing
            && tokens.refresh_token.is_some()
        {
            match self.refresh(tokens) {
                Ok(refreshed) if self.has_required_token(&refreshed) => {
                    *self.lock_tokens() = Some(refreshed.clone());
                    return Ok(refreshed);
                }
                // Refresh succeeded but didn't yield the required kind: some
                // IdPs don't re-issue the id_token on refresh. Fall through to
                // a fresh sign-in.
                Ok(_) => {}
                // Transient failure: the refresh token is still valid, so
                // propagate rather than re-prompt needlessly.
                Err(e) if e.kind() == crate::oidc::error::OidcErrorKind::Network => {
                    return Err(e);
                }
                // Refresh token rejected (expired/revoked): fall through.
                Err(_) => {}
            }
            // The refresh path is exhausted; drop the stale token before the
            // interactive flow so a failure doesn't leave it cached.
            *self.lock_tokens() = None;
        }

        let fresh = self.run_device_flow()?;
        *self.lock_tokens() = Some(fresh.clone());
        Ok(fresh)
    }

    // -- device flow (RFC 8628) ---------------------------------------------

    fn is_interactive(&self) -> bool {
        if let Some(v) = self.interactive {
            return v;
        }
        use std::io::IsTerminal;
        std::io::stderr().is_terminal()
    }

    fn run_device_flow(&self) -> Result<TokenSet> {
        if !self.is_interactive() {
            return Err(OidcError::interaction_required(
                "Interactive sign-in is required, but no interactive terminal was \
                 detected (e.g. a CI job or a redirected process). Use a QuestDB \
                 service-account REST token or the OAuth2 client-credentials grant \
                 for non-interactive contexts.",
            ));
        }

        let resp = self.request_device_code()?;
        self.renderer.on_prompt(&resp.challenge);
        if self.open_browser
            && let Some(target) = resp.challenge.safe_target()
        {
            maybe_open_browser(&target);
        }
        let tokens = self.poll_for_token(&resp)?;

        // Rendering the success message is purely cosmetic and must never abort an
        // authorized sign-in.
        let identity = identity_from_tokens(&tokens);
        self.renderer
            .on_success(identity.as_deref(), tokens.remaining_secs(now_epoch()));
        Ok(tokens)
    }

    fn request_device_code(&self) -> Result<DeviceResponse> {
        let mut form: Vec<(&str, &str)> = vec![
            ("client_id", self.config.client_id.as_str()),
            ("scope", self.config.scope.as_str()),
        ];
        if let Some(audience) = &self.config.audience {
            form.push(("audience", audience.as_str()));
        }
        let result =
            self.http
                .post_form(&self.config.device_authorization_endpoint, &form, false)?;
        let body = &result.body;

        if result.status == 200 {
            let device_code = str_field(body, "device_code");
            let user_code = str_field(body, "user_code");
            let verification_uri =
                str_field(body, "verification_uri").or_else(|| str_field(body, "verification_url"));
            if let (Some(device_code), Some(user_code), Some(verification_uri)) =
                (device_code, user_code, verification_uri)
            {
                let complete = str_field(body, "verification_uri_complete")
                    .or_else(|| str_field(body, "verification_url_complete"));
                // Require the displayed fields non-blank AFTER control-stripping:
                // a value of only invisible characters would render an empty prompt.
                let uc_visible = !crate::oidc::render::strip_control(&user_code)
                    .trim()
                    .is_empty();
                let vu_visible = !crate::oidc::render::strip_control(&verification_uri)
                    .trim()
                    .is_empty();
                if uc_visible && vu_visible {
                    return Ok(DeviceResponse {
                        device_code,
                        challenge: DeviceCodeChallenge {
                            user_code,
                            verification_uri,
                            verification_uri_complete: complete,
                        },
                        expires_in: clamp_lifetime(int_field(body, "expires_in")),
                        interval: clamp_interval(
                            int_field(body, "interval").unwrap_or(self.default_interval as i64),
                        ),
                    });
                }
            }
            return Err(OidcError::device_flow(
                "The IdP returned a 200 device-authorization response with a \
                 missing or blank required field (device_code, user_code, or \
                 verification_uri); cannot start the device flow.",
            )
            .with_status(Some(200)));
        }

        let error = body.get("error").and_then(Value::as_str);
        Err(OidcError::device_flow(format!(
            "The IdP rejected the device-authorization request (HTTP {}). Ensure \
             the OIDC client {:?} has the device grant enabled and is registered \
             as a public client.",
            result.status, self.config.client_id
        ))
        .with_idp_error(error, body.get("error_description").and_then(Value::as_str))
        .with_status(Some(result.status)))
    }

    fn poll_for_token(&self, resp: &DeviceResponse) -> Result<TokenSet> {
        let mut interval = resp.interval;
        let deadline = Instant::now() + Duration::from_secs(resp.expires_in);
        let form: Vec<(&str, &str)> = vec![
            ("grant_type", DEVICE_CODE_GRANT),
            ("device_code", resp.device_code.as_str()),
            ("client_id", self.config.client_id.as_str()),
        ];

        loop {
            let now = Instant::now();
            if now >= deadline {
                self.renderer
                    .on_failure("Code expired — run the sign-in again to retry.");
                return Err(OidcError::timeout(
                    "The device code expired before authorization completed. Run \
                     the sign-in again.",
                )
                .with_idp_error(Some("expired_token"), None));
            }
            let remaining = deadline - now;
            self.renderer.on_waiting(remaining.as_secs_f64());
            (self.sleep)(remaining.min(Duration::from_secs(interval)));

            let result = match self
                .http
                .post_form(&self.config.token_endpoint, &form, false)
            {
                Ok(result) => result,
                Err(e) => {
                    // A non-JSON, non-transient status is a terminal rejection (a
                    // WAF/proxy error page); a conformant poll reply is JSON, so
                    // it can never be authorization_pending / slow_down.
                    if is_terminal_status(e.status()) {
                        self.renderer.on_failure(
                            "Sign-in failed: the identity provider rejected the request.",
                        );
                        return Err(OidcError::device_flow(format!(
                            "Device flow failed: the IdP rejected the token request ({e})."
                        ))
                        .with_status(e.status()));
                    }
                    // Transient (dropped connection / 5xx / 429): keep polling.
                    if e.status() == Some(429) || e.retry_after_secs().is_some() {
                        interval = backoff(interval, e.retry_after_secs(), false);
                    }
                    continue;
                }
            };

            let status = result.status;
            let body = result.body;
            let retry_after = result.retry_after;

            if status == 200 {
                let tokens = self.tokenset_from_response(&body);
                if self.has_required_token(&tokens) {
                    return Ok(tokens);
                }
                self.renderer.on_failure(
                    "Sign-in failed: the identity provider did not return the token \
                     this server requires.",
                );
                return Err(self.missing_required_token_error());
            }

            // A 5xx/429 with a JSON body is transient (server error or
            // rate-limit): keep polling. Honor Retry-After; apply the +5s
            // slow-down step only to a 429 with no header.
            if status >= 500 || status == 429 {
                if status == 429 || retry_after.is_some() {
                    interval = backoff(interval, retry_after, false);
                }
                continue;
            }

            // A 3xx these endpoints never legitimately return is terminal.
            if (300..400).contains(&status) {
                self.renderer
                    .on_failure("Sign-in failed: the identity provider rejected the request.");
                return Err(OidcError::device_flow(format!(
                    "Device flow failed: the IdP returned an unexpected redirect (HTTP {status})."
                ))
                .with_status(Some(status)));
            }

            match body.get("error").and_then(Value::as_str) {
                Some("authorization_pending") => continue,
                Some("slow_down") => {
                    interval = backoff(interval, retry_after, true);
                    continue;
                }
                Some("expired_token") => {
                    self.renderer
                        .on_failure("Code expired — run the sign-in again to retry.");
                    return Err(OidcError::timeout(
                        "The device code expired before authorization completed. Run \
                         the sign-in again.",
                    )
                    .with_idp_error(Some("expired_token"), None));
                }
                error => {
                    let description = body
                        .get("error_description")
                        .and_then(Value::as_str)
                        .or(error)
                        .unwrap_or("unknown error");
                    self.renderer
                        .on_failure(&format!("Sign-in failed: {description}"));
                    return Err(OidcError::device_flow(format!(
                        "Device flow failed: {description}"
                    ))
                    .with_idp_error(error, body.get("error_description").and_then(Value::as_str))
                    .with_status(Some(status)));
                }
            }
        }
    }

    fn refresh(&self, tokens: &TokenSet) -> Result<TokenSet> {
        let refresh_token = tokens
            .refresh_token
            .as_deref()
            .expect("refresh() called without a refresh token");
        let mut form: Vec<(&str, &str)> = vec![
            ("grant_type", REFRESH_GRANT),
            ("refresh_token", refresh_token),
            ("client_id", self.config.client_id.as_str()),
            ("scope", self.config.scope.as_str()),
        ];
        if let Some(audience) = &self.config.audience {
            form.push(("audience", audience.as_str()));
        }
        let result = match self
            .http
            .post_form(&self.config.token_endpoint, &form, false)
        {
            Ok(result) => result,
            Err(e) => {
                // A transient 5xx/429 (even non-JSON) keeps the refresh token
                // usable → surface as a network error so the caller retries; a
                // genuine 4xx rejection propagates to a fresh sign-in.
                if is_transient_status(e.status()) {
                    return Err(OidcError::network(e.to_string()).with_status(e.status()));
                }
                return Err(e);
            }
        };

        if result.status == 200 {
            let mut refreshed = self.tokenset_from_response(&result.body);
            // Many IdPs don't rotate the refresh token; keep the old one.
            if refreshed.refresh_token.is_none() {
                refreshed.refresh_token = tokens.refresh_token.clone();
            }
            return Ok(refreshed);
        }
        if is_transient_status(Some(result.status)) {
            return Err(OidcError::network(format!(
                "Token refresh hit a transient IdP error (HTTP {}); the refresh \
                 token is still valid — retry later.",
                result.status
            ))
            .with_status(Some(result.status)));
        }
        let error = result.body.get("error").and_then(Value::as_str);
        Err(OidcError::device_flow(format!(
            "Token refresh failed: {}",
            error.unwrap_or("unknown error")
        ))
        .with_idp_error(
            error,
            result.body.get("error_description").and_then(Value::as_str),
        )
        .with_status(Some(result.status)))
    }

    fn missing_required_token_error(&self) -> OidcError {
        if self.config.groups_in_token {
            OidcError::device_flow(format!(
                "Device authorization completed but the IdP returned no id_token, \
                 which this server requires (it expects groups encoded in the \
                 token). Ensure the \"openid\" scope is requested (current scope: \
                 {:?}).",
                self.config.scope
            ))
        } else {
            OidcError::device_flow(
                "Device authorization completed but the IdP returned no access_token.",
            )
        }
    }

    fn tokenset_from_response(&self, body: &Value) -> TokenSet {
        let mut expires_in = int_field(body, "expires_in").unwrap_or(DEFAULT_EXPIRES_IN);
        if expires_in <= 0 {
            expires_in = DEFAULT_EXPIRES_IN;
        }
        expires_in = expires_in.min(MAX_EXPIRES_IN);

        let access_token = safe_token(body.get("access_token"));
        let id_token = safe_token(body.get("id_token"));
        let refresh_token = str_field_val(body.get("refresh_token"));
        let claims = decode_jwt_claims(id_token.as_deref())
            .or_else(|| decode_jwt_claims(access_token.as_deref()));
        let sub = claims
            .as_ref()
            .and_then(|c| c.get("sub"))
            .and_then(Value::as_str)
            .map(String::from);
        let now = now_epoch();
        TokenSet {
            access_token,
            id_token,
            refresh_token,
            expires_at: now + expires_in as f64,
            issued_at: now,
            token_type: str_field_val(body.get("token_type")).unwrap_or_else(|| "Bearer".into()),
            scope: str_field_val(body.get("scope")).or_else(|| Some(self.config.scope.clone())),
            sub,
        }
    }
}

// -- free helpers -----------------------------------------------------------

fn clamp_interval(interval: i64) -> u64 {
    (interval.max(0) as u64).clamp(MIN_POLL_INTERVAL, MAX_POLL_INTERVAL)
}

fn clamp_lifetime(expires_in: Option<i64>) -> u64 {
    let secs = match expires_in {
        Some(v) if v > 0 => v as u64,
        _ => DEFAULT_DEVICE_CODE_LIFETIME,
    };
    secs.min(MAX_DEVICE_CODE_LIFETIME)
}

/// The next poll interval after a 429 / `slow_down`. Honors a `Retry-After`
/// (delta-seconds) when present, else the RFC 8628 +5s step. `at_least_increment`
/// enforces slow_down's MUST-increase, so a contradictory low Retry-After can't
/// make the client poll faster right after being told to slow down.
fn backoff(interval: u64, retry_after: Option<u64>, at_least_increment: bool) -> u64 {
    let mut target = retry_after.unwrap_or(interval + 5);
    if at_least_increment {
        target = target.max(interval + 5);
    }
    target.clamp(MIN_POLL_INTERVAL, MAX_POLL_INTERVAL)
}

fn is_terminal_status(status: Option<u16>) -> bool {
    matches!(status, Some(s) if s < 500 && s != 429)
}

fn is_transient_status(status: Option<u16>) -> bool {
    matches!(status, Some(s) if s >= 500 || s == 429)
}

/// A `/settings`/response value as a non-empty string.
fn str_field(body: &Value, key: &str) -> Option<String> {
    str_field_val(body.get(key))
}

fn str_field_val(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

/// A wire-bound credential token (access/id) from an untrusted response: a
/// printable-ASCII, non-blank string, else `None`. A control / non-ASCII / blank
/// value would be smuggled verbatim into an `Authorization: Bearer` header (a
/// decoded CR/LF is a header-injection vector), so it is dropped rather than sent.
fn safe_token(value: Option<&Value>) -> Option<String> {
    let s = match value {
        Some(Value::String(s)) => s,
        _ => return None,
    };
    if s.trim().is_empty() || !s.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        return None;
    }
    Some(s.clone())
}

fn int_field(body: &Value, key: &str) -> Option<i64> {
    match body.get(key) {
        Some(Value::Number(n)) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)),
        Some(Value::String(s)) => s.trim().parse::<i64>().ok(),
        _ => None,
    }
}

/// Best-effort decode of a JWT payload **without signature verification**, used
/// only to show a friendly identity in the sign-in message. `None` for
/// opaque/invalid tokens.
fn decode_jwt_claims(token: Option<&str>) -> Option<Value> {
    let token = token?;
    let payload = token.split('.').nth(1)?;
    let bytes = base64_url_decode(payload)?;
    serde_json::from_slice::<Value>(&bytes)
        .ok()
        .filter(Value::is_object)
}

/// Decode unpadded base64url (JWT segments omit `=` padding).
fn base64_url_decode(input: &str) -> Option<Vec<u8>> {
    use base64ct::{Base64UrlUnpadded, Encoding};
    Base64UrlUnpadded::decode_vec(input).ok()
}

fn identity_from_tokens(tokens: &TokenSet) -> Option<String> {
    let claims = decode_jwt_claims(tokens.id_token.as_deref())
        .or_else(|| decode_jwt_claims(tokens.access_token.as_deref()))?;
    for key in ["email", "preferred_username", "upn", "name", "sub"] {
        if let Some(value) = claims.get(key).and_then(Value::as_str)
            && !value.is_empty()
        {
            return Some(value.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests;
