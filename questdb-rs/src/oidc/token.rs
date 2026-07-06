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

//! The token state cached and refreshed by [`OidcDeviceAuth`](crate::oidc::OidcDeviceAuth).

use std::fmt::{Debug, Formatter};
use std::time::{SystemTime, UNIX_EPOCH};

/// Refresh a little before the real expiry to absorb clock skew / latency.
pub(crate) const DEFAULT_SKEW_SECONDS: f64 = 30.0;

/// The current wall-clock time as epoch seconds (fractional).
pub(crate) fn now_epoch() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// True if `s` is safe to send verbatim as a wire-bound credential: non-blank
/// and printable-ASCII only. A control / non-ASCII byte (a decoded CR/LF is a
/// header-injection vector) or a blank value must never reach an `Authorization:
/// Bearer` header, whether it came from an IdP response or a persisted file.
pub(crate) fn is_safe_token_str(s: &str) -> bool {
    !s.trim().is_empty() && s.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

/// The set of IdP tokens (access / id / refresh) plus their expiry.
///
/// The secret fields are excluded from the [`Debug`] representation so a token
/// can't leak into a log or a panic message.
#[derive(Clone, PartialEq)]
pub struct TokenSet {
    pub(crate) access_token: Option<String>,
    pub(crate) id_token: Option<String>,
    pub(crate) refresh_token: Option<String>,
    /// Epoch seconds; `0` == unknown.
    pub(crate) expires_at: f64,
    pub(crate) token_type: String,
    pub(crate) scope: Option<String>,
    /// Subject id derived from the (unverified) JWT — PII, kept out of `Debug`.
    pub(crate) sub: Option<String>,
    /// Epoch seconds; `0` == unknown.
    pub(crate) issued_at: f64,
}

impl TokenSet {
    /// True if the token is present and not within `skew` seconds of expiry.
    pub(crate) fn is_valid(&self, now: f64, skew: f64) -> bool {
        if self.expires_at <= 0.0 {
            return false;
        }
        // Cap skew at half the token lifetime, so a short-lived (< 2*skew) token
        // isn't reported expired the instant it's issued. issued_at == 0 means
        // the issue time is unknown; treat it as `now` so the cap still applies
        // to a short-lived token that arrives without one.
        let issued = if self.issued_at > 0.0 {
            self.issued_at
        } else {
            now
        };
        let lifetime = self.expires_at - issued;
        let skew = if lifetime > 0.0 {
            skew.min(lifetime / 2.0)
        } else {
            skew
        };
        now < (self.expires_at - skew)
    }

    /// The token's remaining lifetime in seconds (clamped at 0).
    pub(crate) fn remaining_secs(&self, now: f64) -> f64 {
        (self.expires_at - now).max(0.0)
    }

    /// The expiry as epoch seconds; `0.0` when unknown.
    pub fn expires_at(&self) -> f64 {
        self.expires_at
    }

    /// The OAuth `token_type` (`"Bearer"` unless the IdP said otherwise).
    pub fn token_type(&self) -> &str {
        &self.token_type
    }

    /// The space-separated scope the token was issued for.
    pub fn scope(&self) -> Option<&str> {
        self.scope.as_deref()
    }
}

impl Debug for TokenSet {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // Redact every secret; report only presence and the non-sensitive fields.
        f.debug_struct("TokenSet")
            .field(
                "access_token",
                &self.access_token.as_ref().map(|_| "<redacted>"),
            )
            .field("id_token", &self.id_token.as_ref().map(|_| "<redacted>"))
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("expires_at", &self.expires_at)
            .field("token_type", &self.token_type)
            .field("scope", &self.scope)
            .field("sub", &self.sub.as_ref().map(|_| "<redacted>"))
            .field("issued_at", &self.issued_at)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(expires_at: f64, issued_at: f64) -> TokenSet {
        TokenSet {
            access_token: Some("a".to_string()),
            id_token: None,
            refresh_token: None,
            expires_at,
            token_type: "Bearer".to_string(),
            scope: None,
            sub: None,
            issued_at,
        }
    }

    #[test]
    fn expiry_unknown_is_invalid() {
        assert!(!token(0.0, 0.0).is_valid(100.0, DEFAULT_SKEW_SECONDS));
    }

    #[test]
    fn valid_before_skew_window() {
        // Long-lived token (issued 500, expires 1000 -> lifetime 500), so the
        // skew stays the full 30s: now 900 -> 900 < 970 -> valid.
        assert!(token(1000.0, 500.0).is_valid(900.0, DEFAULT_SKEW_SECONDS));
        // now 980 -> 980 < 970 is false -> invalid (inside skew window).
        assert!(!token(1000.0, 500.0).is_valid(980.0, DEFAULT_SKEW_SECONDS));
    }

    #[test]
    fn short_lived_token_not_instantly_expired() {
        // A 40s token (< 2*skew) issued at 1000: skew capped at 20, so it is
        // valid right after issue.
        let t = token(1040.0, 1000.0);
        assert!(t.is_valid(1000.0, DEFAULT_SKEW_SECONDS));
        // ...and invalid once inside the (capped) skew window.
        assert!(!t.is_valid(1025.0, DEFAULT_SKEW_SECONDS));
    }

    #[test]
    fn debug_redacts_secrets() {
        let mut t = token(1000.0, 0.0);
        t.access_token = Some("super-secret-access".to_string());
        t.refresh_token = Some("super-secret-refresh".to_string());
        t.sub = Some("user@example.com".to_string());
        let shown = format!("{t:?}");
        assert!(!shown.contains("super-secret-access"));
        assert!(!shown.contains("super-secret-refresh"));
        assert!(!shown.contains("user@example.com"));
        assert!(shown.contains("<redacted>"));
    }
}
