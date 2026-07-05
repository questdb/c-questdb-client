//! Interactive OIDC sign-in (OAuth 2.0 Device Authorization Grant, RFC 8628)
//! against a QuestDB Enterprise instance secured with OIDC.
//!
//! On first run it prints a verification URL and a short code (and opens the URL
//! in a browser when one is available); authorize on any device, then the token
//! is cached in memory and refreshed silently on later calls.
//!
//! Run with:
//!
//! ```sh
//! cargo run --features oidc,sync-sender-http --example oidc_device_auth -- \
//!     https://questdb.example.com:9000 https://idp.example.com
//! ```
//!
//! The second argument (the issuer) is required when the server does not
//! advertise its device-authorization endpoint, so the client can discover it
//! from the issuer's `.well-known/openid-configuration` — and so a tampered
//! `/settings` cannot redirect the sign-in.

use std::sync::Arc;

use questdb::Result;
use questdb::ingress::{Protocol, SenderBuilder, TimestampNanos};
use questdb::oidc::OidcDeviceAuth;

fn main() -> Result<()> {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "https://localhost:9000".to_string());
    let issuer = std::env::args().nth(2);

    // Discover the client id, scope and endpoints from the QuestDB server's
    // /settings. Pin the identity provider with the issuer when given.
    let mut builder = OidcDeviceAuth::from_questdb(&url);
    if let Some(issuer) = issuer {
        builder = builder.issuer(issuer);
    }
    let auth = Arc::new(builder.build()?);

    // Sign in once up front (prompts on first use, then caches; refreshes
    // silently if the IdP issued a refresh token — request the `offline_access`
    // scope for that, otherwise an expired token triggers a fresh prompt).
    auth.sign_in()?;

    // Parse host:port out of the QuestDB URL for the sender.
    let (host, port) = split_host_port(&url);

    // Pass a token provider, not a fixed string: the sender pulls a freshly
    // refreshed token on each request, so a long-lived sender keeps working as
    // the token rotates.
    let mut sender = SenderBuilder::new(Protocol::Https, host, port)
        .http_token_provider({
            let auth = Arc::clone(&auth);
            move || auth.token()
        })?
        .build()?;

    let mut buffer = sender.new_buffer();
    buffer
        .table("trades")?
        .symbol("symbol", "ETH-USD")?
        .symbol("side", "sell")?
        .column_f64("price", 2615.54)?
        .column_f64("amount", 0.00044)?
        .at(TimestampNanos::now())?;
    sender.flush(&mut buffer)?;

    println!("Row sent to {url} using an OIDC device-flow token.");
    Ok(())
}

/// Best-effort `host:port` split from an `https://host:port` URL for the example.
/// Keeps an IPv6 literal bracketed (`[::1]`, as the sender interpolates
/// `host:port` verbatim) and drops any `user@` userinfo.
fn split_host_port(url: &str) -> (String, u16) {
    let without_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let authority = without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(without_scheme);
    // Drop any `user[:pass]@` userinfo: the host starts after the last '@'.
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, hp)| hp);
    // An IPv6 literal is bracketed; its `:port` (if any) follows the ']'.
    if let Some((v6, after)) = host_port.strip_prefix('[').and_then(|r| r.split_once(']')) {
        let port = after
            .strip_prefix(':')
            .and_then(|p| p.parse().ok())
            .unwrap_or(9000);
        return (format!("[{v6}]"), port);
    }
    match host_port.rsplit_once(':') {
        Some((host, port)) => (host.to_string(), port.parse().unwrap_or(9000)),
        None => (host_port.to_string(), 9000),
    }
}
