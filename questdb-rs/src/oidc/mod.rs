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

//! Interactive OIDC sign-in for QuestDB Enterprise via the OAuth 2.0 Device
//! Authorization Grant ([RFC 8628](https://www.rfc-editor.org/rfc/rfc8628)).
//!
//! [`OidcDeviceAuth`] signs a user in interactively without needing a local
//! browser on the machine running the client: it prints a short code and a
//! verification URL (and opens it in a browser when one is available), the user
//! authorizes on any device, and the client — which only ever makes outbound
//! calls to the identity provider (IdP) — receives the token. This works from
//! headless or remote environments (containers, remote notebook kernels, CI
//! jobs).
//!
//! The acquired token is presented to QuestDB as an HTTP
//! `Authorization: Bearer <token>` header. The flow runs entirely client-side;
//! QuestDB is never in the token-acquisition path.
//!
//! # Example
//!
//! ```no_run
//! use std::sync::Arc;
//! use questdb::oidc::OidcDeviceAuth;
//! use questdb::ingress::{Protocol, SenderBuilder};
//!
//! # fn main() -> questdb::Result<()> {
//! // Discover the client id, scope and endpoints from the QuestDB server's
//! // /settings. When the server doesn't advertise its device-authorization
//! // endpoint, pin the IdP out-of-band with `.issuer(...)`.
//! let auth = Arc::new(
//!     OidcDeviceAuth::from_questdb("https://questdb.example.com:9000")
//!         .issuer("https://idp.example.com")
//!         .build()?,
//! );
//! auth.sign_in()?; // prompts on first use, then caches (and refreshes silently
//!                  // if the IdP issued a refresh token — see below)
//!
//! // Pass a token provider (not a fixed string): the sender pulls a freshly
//! // refreshed token on each request, so a long-lived sender keeps working as
//! // the token rotates.
//! let mut sender = SenderBuilder::new(Protocol::Https, "questdb.example.com", 9000)
//!     .http_token_provider({
//!         let auth = Arc::clone(&auth);
//!         move || auth.token()
//!     })?
//!     .build()?;
//! # let _ = &mut sender;
//! # Ok(())
//! # }
//! ```
//!
//! # Token lifetime and refresh
//!
//! A cached token is refreshed **silently only when the IdP issued a refresh
//! token**. Most IdPs issue one only when the `offline_access` scope is
//! requested; the default scope is just `openid`, so without it an expired token
//! is re-acquired by a *fresh interactive sign-in* rather than a silent refresh.
//! To get silent refresh, include `offline_access` in the scope — via QuestDB's
//! `acl.oidc.scope` setting, or [`scope`](OidcDeviceAuthBuilder::scope):
//!
//! ```no_run
//! # use questdb::oidc::OidcDeviceAuth;
//! # fn main() -> questdb::Result<()> {
//! let auth = OidcDeviceAuth::from_questdb("https://questdb.example.com:9000")
//!     .scope("openid offline_access")
//!     .build()?;
//! # let _ = auth;
//! # Ok(())
//! # }
//! ```
//!
//! Independently, **when a refresh token is available** a cached token's believed
//! lifetime is capped at one hour, so it is silently rotated at least that often
//! even if the IdP issued a very long-lived (or hostile) token. Without a refresh
//! token the cap is not applied: shortening the client's *belief* about expiry
//! can't shorten the token's real validity at the server, so it would only force
//! a needless interactive re-prompt. Because a token provider is pulled on the
//! flush path, a re-prompt — when the token *genuinely* expires and no refresh
//! token is available to rotate it silently — can still surface during a
//! [`Sender::flush`](crate::ingress::Sender::flush); request `offline_access`
//! (above) for unattended, long-running senders.
//!
//! # Security
//!
//! The IdP device-authorization and token endpoints must use `https` (a
//! loopback endpoint may use `http`, since the request never leaves the host),
//! so the device code and refresh token are never sent in cleartext.
//! [`OidcDeviceAuthBuilder::allow_insecure_transport`] relaxes only the QuestDB
//! `/settings` link (for local development against an `http` server); it never
//! relaxes the IdP endpoints.
//!
//! [`from_questdb`](OidcDeviceAuth::from_questdb) takes the IdP endpoints from
//! the server's unauthenticated `/settings`, so it trusts that server to
//! designate where you sign in. Passing [`issuer`](OidcDeviceAuthBuilder::issuer)
//! hardens this: the endpoints are then pinned to the issuer's origin (and, when
//! the issuer has a path, an endpoint advertised by `/settings` must also be
//! under that path), and an endpoint outside it is rejected.

mod device;
mod discovery;
mod error;
mod http;
mod render;
mod token;

pub use device::{OidcDeviceAuth, OidcDeviceAuthBuilder};
pub use discovery::OidcConfig;
pub use error::{OidcError, OidcErrorKind};
pub use render::{DeviceCodeChallenge, Renderer, TerminalRenderer};
pub use token::TokenSet;
