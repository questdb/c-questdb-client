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

//! Presentation of the device-flow prompt.
//!
//! The device-authorization response fields ([`user_code`](DeviceCodeChallenge::user_code),
//! the verification URL) are **untrusted** — a MITM'd or hostile IdP could embed
//! ANSI escapes, bidi overrides or zero-width characters to spoof the prompt or
//! hide the real sign-in URL. Everything shown here is passed through
//! [`sanitize_display_text`] first, and any URL made clickable / opened in a
//! browser is additionally vetted by [`safe_target`].

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};

/// The parts of an RFC 8628 device-authorization response shown to the user.
///
/// The `device_code` itself is deliberately absent — it is a secret used only in
/// the poll request, never displayed.
///
/// The text fields are raw, untrusted IdP response values (they are *not*
/// pre-sanitized); the timing fields are the bounded values used by the polling
/// loop. The built-in [`TerminalRenderer`] passes text through its internal
/// sanitization and URL-validation helpers at display time. A custom
/// [`Renderer`] that echoes [`user_code`](Self::user_code) /
/// [`verification_uri`](Self::verification_uri) to a terminal or DOM MUST
/// sanitize them itself, or it re-opens the ANSI / bidi / zero-width
/// prompt-spoofing surface.
#[derive(Debug, Clone)]
pub struct DeviceCodeChallenge {
    pub(crate) user_code: String,
    pub(crate) verification_uri: String,
    pub(crate) verification_uri_complete: Option<String>,
    pub(crate) expires_in_seconds: u64,
    pub(crate) interval_seconds: u64,
}

impl DeviceCodeChallenge {
    /// The raw, untrusted short code returned by the IdP.
    ///
    /// Do not render this value directly. Use
    /// [`display_user_code`](Self::display_user_code) for terminal or UI text.
    pub fn user_code(&self) -> &str {
        &self.user_code
    }

    /// The raw, untrusted verification URL returned by the IdP.
    ///
    /// Use [`display_verification_uri`](Self::display_verification_uri) for
    /// display and [`browser_target`](Self::browser_target) for a URL that may
    /// be made clickable or opened.
    pub fn verification_uri(&self) -> &str {
        &self.verification_uri
    }

    /// The verification URL with the code pre-filled (RFC 8628
    /// `verification_uri_complete`), when the IdP provides one.
    pub fn verification_uri_complete(&self) -> Option<&str> {
        self.verification_uri_complete.as_deref()
    }

    /// Number of seconds for which the device code remains valid.
    ///
    /// This is the bounded value used by the polling loop.
    pub fn expires_in_seconds(&self) -> u64 {
        self.expires_in_seconds
    }

    /// Minimum number of seconds between token-endpoint polls.
    ///
    /// This is the bounded initial interval used by the polling loop. It can
    /// increase later when the identity provider responds with `slow_down` or
    /// HTTP 429.
    pub fn interval_seconds(&self) -> u64 {
        self.interval_seconds
    }

    /// The user code rendered as inert, single-line ASCII display text.
    ///
    /// Control, bidi, and zero-width characters are removed. Every remaining
    /// non-ASCII character is escaped visibly so a homoglyph cannot masquerade
    /// as an ordinary code character.
    pub fn display_user_code(&self) -> String {
        ascii_visible(&strip_control_capped(
            &self.user_code,
            MAX_DISPLAY_FIELD_CHARS,
        ))
    }

    /// The verification URL rendered as inert, single-line ASCII text.
    ///
    /// This value is safe to print, but it is not a browser target. Use
    /// [`browser_target`](Self::browser_target) before making a URL clickable
    /// or opening it.
    pub fn display_verification_uri(&self) -> String {
        display_url(&self.verification_uri)
    }

    /// The pre-filled verification URL rendered as inert, single-line ASCII
    /// text, when the IdP supplied one.
    pub fn display_verification_uri_complete(&self) -> Option<String> {
        self.verification_uri_complete
            .as_deref()
            .map(display_url)
            .filter(|value| !value.is_empty())
    }

    /// The single vetted `http(s)` target to open in a browser / make clickable:
    /// the pre-filled `verification_uri_complete` when it is safe **and shares
    /// the origin of** `verification_uri`, otherwise the plain
    /// `verification_uri`.
    ///
    /// `verification_uri_complete` is a target the user does not read
    /// character-by-character — it is auto-opened, encoded into a QR, and can
    /// back a fixed-label "authorize directly" link whose host is never shown.
    /// RFC 8628 §3.3.1 makes it the same URL as `verification_uri` with the user
    /// code added, so a legitimate pair shares an origin. A tampered or hostile
    /// device response could instead pair a trusted-looking `verification_uri`
    /// with a `complete` on a DIFFERENT host, silently steering the
    /// opened/scanned target to the attacker while the displayed host still
    /// reads as trusted. The origin check refuses such a `complete` and falls
    /// back to the shown `verification_uri`; when `verification_uri` itself is
    /// not a safe target (so there is no trusted host to anchor against), no
    /// target is offered at all.
    ///
    /// The returned URL is control-stripped and has no userinfo; its host is
    /// non-empty ASCII. It remains separate from the display accessors so UI
    /// code cannot accidentally open a merely printable, untrusted value.
    pub fn browser_target(&self) -> Option<String> {
        let plain = safe_target(Some(&self.verification_uri))?;
        match safe_target(self.verification_uri_complete.as_deref()) {
            Some(complete) if crate::oidc::discovery::same_origin(&complete, &plain) => {
                Some(complete)
            }
            _ => Some(plain),
        }
    }
}

/// Receives device-flow sign-in events so they can be presented to the user.
///
/// Every method has a no-op default, so a custom renderer overrides only what it
/// needs. The callbacks receive **untrusted, MITM-tamperable IdP fields**; a
/// custom renderer that writes them to a terminal must sanitise them itself;
/// echoing them raw re-opens the prompt-spoofing
/// surface the built-in [`TerminalRenderer`] closes.
pub trait Renderer: Send + Sync {
    /// Show the sign-in prompt at the start of the device flow.
    fn on_prompt(&self, challenge: &DeviceCodeChallenge) {
        let _ = challenge;
    }

    /// Report progress while polling; `seconds_left` is the time remaining
    /// before the device code expires.
    fn on_waiting(&self, seconds_left: f64) {
        let _ = seconds_left;
    }

    /// Report a completed sign-in. `identity` is a best-effort, unverified
    /// display name from the token's claims (or `None`); `expires_in_secs` is
    /// the token's remaining lifetime.
    fn on_success(&self, identity: Option<&str>, expires_in_secs: f64) {
        let _ = (identity, expires_in_secs);
    }

    /// Report a failed or expired sign-in.
    fn on_failure(&self, message: &str) {
        let _ = message;
    }
}

/// Plain-text rendering for terminals (writes to `stderr`).
#[derive(Debug, Default)]
pub struct TerminalRenderer {
    countdown_active: AtomicBool,
}

impl TerminalRenderer {
    /// Create a terminal renderer that writes to `stderr`.
    pub fn new() -> Self {
        Self::default()
    }

    fn write(&self, text: &str) {
        // Best-effort: a write / flush failure must never abort the flow.
        let mut stderr = std::io::stderr();
        let _ = stderr.write_all(text.as_bytes());
        let _ = stderr.flush();
    }
}

/// Build the terminal sign-in prompt for `challenge`.
///
/// The pre-filled "open directly" shortcut is offered only when it is the
/// origin-vetted [`browser_target`](DeviceCodeChallenge::browser_target). A
/// hostile or tampered device response can pair a trusted-looking
/// `verification_uri` with a cross-origin `verification_uri_complete`; echoing
/// the raw `display_verification_uri_complete()` here would present that attacker
/// URL as an actionable link (auto-linkified by many terminals) — the exact
/// steering `browser_target()` exists to refuse. `browser_target()` returns the
/// `complete` only when it is safe and shares the origin of `verification_uri`,
/// otherwise it falls back to the plain URI already shown above, which is then
/// suppressed here as redundant.
fn format_prompt(challenge: &DeviceCodeChallenge) -> String {
    let uri = challenge.display_verification_uri();
    let code = challenge.display_user_code();
    let mut msg = format!("🔐 Sign in to QuestDB\n   Open {uri}  and enter code:  {code}\n");
    // browser_target() yields the pre-filled `complete` only when it is safe and
    // shares verification_uri's origin; otherwise it returns the plain URI shown
    // above. Offer the shortcut only for a distinct, vetted complete.
    let plain = safe_target(Some(&challenge.verification_uri));
    if let Some(target) = challenge
        .browser_target()
        .filter(|target| Some(target) != plain.as_ref())
    {
        msg.push_str(&format!("   (or open directly: {target})\n"));
    }
    msg
}

impl Renderer for TerminalRenderer {
    fn on_prompt(&self, challenge: &DeviceCodeChallenge) {
        self.write(&format_prompt(challenge));
    }

    fn on_waiting(&self, seconds_left: f64) {
        self.countdown_active.store(true, Ordering::Relaxed);
        self.write(&format!(
            "\r   ⏳ waiting for authorization… ({} left)   ",
            format_mmss(seconds_left)
        ));
    }

    fn on_success(&self, identity: Option<&str>, expires_in_secs: f64) {
        if self.countdown_active.swap(false, Ordering::Relaxed) {
            self.write("\n");
        }
        let who = match identity {
            Some(id) => format!(
                " as {}",
                ascii_visible(&strip_control_capped(id, MAX_DISPLAY_FIELD_CHARS))
            ),
            None => String::new(),
        };
        let mins = ((expires_in_secs / 60.0).round() as i64).max(1);
        self.write(&format!(
            "✅ Signed in{who} — token cached, expires in {mins} min\n"
        ));
    }

    fn on_failure(&self, message: &str) {
        if self.countdown_active.swap(false, Ordering::Relaxed) {
            self.write("\n");
        }
        self.write(&format!("❌ {}\n", strip_control(message)));
    }
}

/// Build the platform browser-opener command for `target`.
///
/// The URL is always passed as a **single argv element**, never concatenated
/// into a shell command line. On Windows this uses `rundll32` (not `cmd /C
/// start`): routing an untrusted verification URL through `cmd.exe` would let an
/// attacker-controlled query string (`?a=1&calc.exe`, `%VAR%`) be re-parsed by
/// the shell — the URL is untrusted IdP data. `rundll32`'s FileProtocolHandler
/// receives the URL as a plain argument (no shell tokenization), so `&` / `%`
/// stay part of the URL.
fn browser_command(target: &str) -> std::process::Command {
    use std::process::Command;
    #[cfg(target_os = "macos")]
    {
        let mut c = Command::new("open");
        c.arg(target);
        c
    }
    #[cfg(target_os = "windows")]
    {
        let mut c = Command::new("rundll32.exe");
        c.args(["url.dll,FileProtocolHandler", target]);
        c
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let mut c = Command::new("xdg-open");
        c.arg(target);
        c
    }
}

/// Open `target` in the user's default browser, best-effort.
///
/// `target` MUST be a [`safe_target`]-vetted `http(s)` URL. Spawns the platform
/// opener as a direct child (never via a shell) and never blocks or fails the
/// sign-in.
///
/// Compiled out under `cfg(test)`: the in-crate device-flow tests drive the full
/// sign-in against a mock IdP, and actually launching the opener would spray a
/// real browser tab per test across the developer's desktop. The command
/// construction (the part with real logic) keeps its own test via
/// [`browser_command`].
pub(crate) fn maybe_open_browser(target: &str) {
    #[cfg(test)]
    let _ = target;
    #[cfg(not(test))]
    {
        use std::process::Stdio;
        if let Ok(mut child) = browser_command(target)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            // Reap the opener so it doesn't linger as a zombie on Unix. It exits
            // promptly once it has handed the URL to the browser. Use
            // `Builder::spawn` (not `thread::spawn`) and swallow the error so a
            // failure to create the reaper thread — OS thread exhaustion — can't
            // panic the sign-in; the worst case is one unreaped opener child,
            // itself reaped at process exit.
            let _ = std::thread::Builder::new()
                .name("questdb-oidc-open".to_string())
                .spawn(move || {
                    let _ = child.wait();
                });
        }
    }
}

/// Format a duration in seconds as `M:SS`.
fn format_mmss(seconds: f64) -> String {
    let s = if seconds.is_finite() {
        seconds.max(0.0) as u64
    } else {
        0
    };
    format!("{}:{:02}", s / 60, s % 60)
}

/// True for a format / bidi / zero-width character that must never be echoed to
/// a terminal: it is invisible or can reorder / hide adjacent text, spoofing the
/// prompt or masking the real sign-in URL.
fn is_format_or_bidi(ch: char) -> bool {
    matches!(ch,
        '\u{00AD}'                    // soft hyphen
        | '\u{061C}'                  // arabic letter mark
        | '\u{180E}'                  // mongolian vowel separator
        | '\u{200B}'..='\u{200F}'     // zero-width space/joiner/non-joiner + LRM/RLM
        | '\u{202A}'..='\u{202E}'     // bidi embeddings / overrides
        | '\u{2060}'..='\u{2064}'     // word joiner + invisible math operators
        | '\u{2066}'..='\u{206F}'     // bidi isolates + deprecated format controls
        | '\u{FEFF}'                  // zero-width no-break space / BOM
        | '\u{FFF9}'..='\u{FFFB}'     // interlinear annotation anchors
        | '\u{115F}' | '\u{1160}' | '\u{3164}' | '\u{FFA0}' // hangul fillers (render blank)
        | '\u{FE00}'..='\u{FE0F}'     // variation selectors
        | '\u{1BCA0}'..='\u{1BCA3}'   // shorthand format controls
        | '\u{E0000}'..='\u{E007F}'   // tag characters
        | '\u{E0100}'..='\u{E01EF}'   // variation selectors supplement
    )
}

/// Convert untrusted text to inert, single-line display text.
///
/// C0/C1 controls and DEL (including ANSI, tabs, and line breaks), bidi
/// controls, zero-width characters, and other invisible formatting are
/// removed. Non-ASCII whitespace is folded to an ordinary space. This is
/// suitable for human-readable labels and messages; URLs and short
/// authentication codes need the stricter display accessors on
/// [`DeviceCodeChallenge`] so confusable non-ASCII characters are also made
/// visible. This sanitizer never fails.
pub fn sanitize_display_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        // is_control() covers C0 (incl. tab/newline/CR), DEL and C1.
        if ch.is_control() || is_format_or_bidi(ch) {
            continue;
        }
        if ch != ' ' && ch.is_whitespace() {
            // Fold an exotic space / line separator (NBSP, U+2028, ...) to a
            // plain ASCII space: it renders invisible-as-space and can hide
            // trailing text, but the ordinary U+0020 must survive.
            out.push(' ');
        } else {
            out.push(ch);
        }
    }
    out
}

// Internal name retained for the error-rendering helpers below, where the
// operation is specifically control stripping rather than a public API choice.
pub(crate) fn strip_control(text: &str) -> String {
    sanitize_display_text(text)
}

/// Cap for untrusted device-flow fields shown to the user -- the code, the
/// verification URLs, and the signed-in identity. A conformant value is short;
/// this only bounds a hostile IdP field (otherwise limited only by the 4 MiB
/// response cap) before it reaches a terminal or a notebook DOM, matching the
/// cap the error path already applies. Well above any real code / URL / name.
pub(crate) const MAX_DISPLAY_FIELD_CHARS: usize = 256;

/// [`strip_control`], but bounded to `max_chars` visible characters (with a
/// trailing `…` when truncated).
///
/// For interpolating an untrusted IdP `error` / `error_description` into a
/// message: a conformant value is short, but a hostile JSON `error_description`
/// can be megabytes (it parses fine, so it slips past the non-JSON body-snippet
/// cap in `oidc::http`). The raw input is truncated *before* stripping so a
/// multi-MB field is never copied in full just to be discarded.
pub(crate) fn strip_control_capped(text: &str, max_chars: usize) -> String {
    let mut chars = text.chars();
    // Take at most `max_chars` raw chars; strip_control only ever drops/folds
    // chars, so the stripped result is also <= max_chars.
    let bounded: String = chars.by_ref().take(max_chars).collect();
    let mut out = strip_control(&bounded);
    if chars.next().is_some() {
        // There was more input beyond `max_chars`; mark the truncation.
        out.push('…');
    }
    out
}

/// Escape every non-ASCII character to a visible `\u{XXXX}` so a homoglyph /
/// confusable can't slip through a display path unchanged.
fn ascii_visible(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        if ch.is_ascii() {
            out.push(ch);
        } else {
            out.push_str(&format!("\\u{{{:04X}}}", ch as u32));
        }
    }
    out
}

/// A verification URL rendered safe to *show* as text: control-stripped, with
/// any non-ASCII escaped to a visible `\u{XXXX}` so a homoglyph host can't
/// masquerade as a trusted one in the prompt. Clickability is decided
/// separately by [`safe_target`].
pub(crate) fn display_url(url: &str) -> String {
    let text = strip_control_capped(url, MAX_DISPLAY_FIELD_CHARS);
    if text.is_ascii() {
        text
    } else {
        ascii_visible(&text)
    }
}

/// The control-stripped, scheme/userinfo/host-vetted URL safe to open in a
/// browser (or `None` if it can't be trusted).
///
/// Rejects any URL that is not `http(s)`, carries userinfo (`user@host`, which
/// connects to `host` while *reading* as the trusted user part), or whose host
/// is not plain ASCII letters/digits/`.`/`-`/`:` (a homoglyph / confusable host,
/// or a `%` percent-encoding / IPv6 zone-id). A rejected URL is still *shown* as
/// inert text via [`display_url`]; it is just never opened.
pub(crate) fn safe_target(url: Option<&str>) -> Option<String> {
    let raw = url?;
    // Strip first so a control char can't survive into the opened URL, then trim
    // (a leading space would make the scheme parse fail or shift).
    let cleaned = strip_control(raw);
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        return None;
    }
    let uri: ureq::http::Uri = trimmed.parse().ok()?;
    match uri.scheme_str() {
        Some("http") | Some("https") => {}
        _ => return None,
    }
    let authority = uri.authority()?;
    // Reject userinfo: `https://trusted@evil/` connects to `evil`.
    if authority.as_str().contains('@') {
        return None;
    }
    let host = authority.host();
    if host.is_empty()
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'))
    {
        return None;
    }
    Some(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_control_removes_ansi_and_newlines() {
        // The ESC (0x1b) that arms an ANSI sequence, plus tab / newline / CR, are
        // dropped; only the ESC byte is needed to neutralize the escape.
        assert_eq!(strip_control("a\x1bb\nc\r\td"), "abcd");
    }

    #[test]
    fn strip_control_drops_bidi_and_zero_width() {
        // U+202E right-to-left override, U+200B zero-width space.
        assert_eq!(
            strip_control("code\u{202e}reversed\u{200b}"),
            "codereversed"
        );
    }

    #[test]
    fn strip_control_folds_exotic_space() {
        // NBSP and ideographic space fold to a plain space; plain space survives.
        assert_eq!(strip_control("a\u{00a0}b\u{3000}c d"), "a b c d");
    }

    #[test]
    fn strip_control_capped_bounds_length() {
        // A short value is returned untouched (no ellipsis).
        assert_eq!(strip_control_capped("short", 200), "short");
        // A huge value is truncated and marked; the result never approaches the
        // input length (a hostile multi-MB error_description can't be echoed raw).
        let huge = "x".repeat(1_000_000);
        let capped = strip_control_capped(&huge, 120);
        assert_eq!(capped.chars().count(), 121); // 120 chars + the '…' marker
        assert!(capped.ends_with('…'));
        // Still strips control chars within the kept prefix.
        assert_eq!(strip_control_capped("a\x1bb\nc", 200), "abc");
    }

    #[test]
    fn display_url_escapes_non_ascii() {
        let shown = display_url("https://exa\u{0430}mple.com"); // Cyrillic 'а'
        assert!(!shown.contains('\u{0430}'));
        assert!(shown.contains("\\u{0430}"));
    }

    #[test]
    fn challenge_exposes_safe_display_text_and_separate_browser_target() {
        let challenge = DeviceCodeChallenge {
            user_code: "AB\x1b[31m\u{202e}\u{0430}".into(),
            verification_uri: "https://exa\u{0430}mple.com/\nactivate".into(),
            verification_uri_complete: Some("https://idp.example.com/activate?code=ABCD\n".into()),
            expires_in_seconds: 600,
            interval_seconds: 5,
        };

        assert_eq!(challenge.display_user_code(), "AB[31m\\u{0430}");
        assert_eq!(
            challenge.display_verification_uri(),
            "https://exa\\u{0430}mple.com/activate"
        );
        assert_eq!(
            challenge.display_verification_uri_complete().as_deref(),
            Some("https://idp.example.com/activate?code=ABCD")
        );
        assert_eq!(challenge.expires_in_seconds(), 600);
        assert_eq!(challenge.interval_seconds(), 5);
        // The verification_uri host is a non-ASCII confusable, so it is not a
        // vettable browser target. With no trusted host to anchor against, the
        // cross-host `complete` is refused rather than silently opened/QR'd, so
        // no browser target is offered.
        assert_eq!(challenge.browser_target(), None);
    }

    #[test]
    fn display_accessors_bound_hostile_length() {
        // A hostile IdP field is bounded only by the multi-MB response cap; the
        // display accessors must cap it so a huge code / URL can't be copied
        // whole into a terminal or a notebook DOM. The output length stays a
        // small constant independent of the (here 1 MB) input.
        let huge = "A".repeat(1_000_000);
        let challenge = DeviceCodeChallenge {
            user_code: huge.clone(),
            verification_uri: format!("https://idp.example.com/{huge}"),
            verification_uri_complete: Some(format!("https://idp.example.com/c/{huge}")),
            expires_in_seconds: 600,
            interval_seconds: 5,
        };
        assert!(challenge.display_user_code().len() < 4_096);
        assert!(challenge.display_verification_uri().len() < 4_096);
        assert!(challenge.display_verification_uri_complete().unwrap().len() < 4_096);
    }

    #[test]
    fn browser_target_uses_same_origin_complete() {
        // The pre-filled complete shares verification_uri's origin, so it is the
        // browser target (the user code is pre-filled for a one-click open/QR).
        let challenge = DeviceCodeChallenge {
            user_code: "WXYZ".into(),
            verification_uri: "https://idp.example.com/activate".into(),
            verification_uri_complete: Some(
                "https://idp.example.com/activate?user_code=WXYZ".into(),
            ),
            expires_in_seconds: 600,
            interval_seconds: 5,
        };
        assert_eq!(
            challenge.browser_target().as_deref(),
            Some("https://idp.example.com/activate?user_code=WXYZ")
        );
    }

    #[test]
    fn browser_target_ignores_default_port_difference() {
        // An explicit default port on one side is still the same origin.
        let challenge = DeviceCodeChallenge {
            user_code: "WXYZ".into(),
            verification_uri: "https://idp.example.com/activate".into(),
            verification_uri_complete: Some(
                "https://idp.example.com:443/activate?user_code=WXYZ".into(),
            ),
            expires_in_seconds: 600,
            interval_seconds: 5,
        };
        assert_eq!(
            challenge.browser_target().as_deref(),
            Some("https://idp.example.com:443/activate?user_code=WXYZ")
        );
    }

    #[test]
    fn browser_target_rejects_cross_origin_complete() {
        // A tampered device response pairs a trusted-looking verification_uri
        // with a `complete` on a different origin. The complete must NOT become
        // the browser / QR / auto-open target (that would silently steer the
        // user to the attacker while the shown host still reads as trusted);
        // fall back to the vetted, same-host verification_uri.
        for evil in [
            "https://evil.example/?code=WXYZ",            // different host
            "https://login.questdb.io.evil.example/?x=1", // suffix trick
            "http://login.questdb.io/device",             // scheme downgrade
            "https://login.questdb.io:8443/device",       // different port
            "https://trusted@login.questdb.io/device",    // userinfo (safe_target rejects)
        ] {
            let challenge = DeviceCodeChallenge {
                user_code: "WXYZ".into(),
                verification_uri: "https://login.questdb.io/device".into(),
                verification_uri_complete: Some(evil.into()),
                expires_in_seconds: 600,
                interval_seconds: 5,
            };
            assert_eq!(
                challenge.browser_target().as_deref(),
                Some("https://login.questdb.io/device"),
                "cross-origin complete {evil:?} must fall back to verification_uri"
            );
        }
    }

    #[test]
    fn terminal_prompt_offers_only_origin_vetted_complete() {
        // A same-origin complete is offered as the one-click shortcut (the user
        // code is pre-filled).
        let same = DeviceCodeChallenge {
            user_code: "WXYZ".into(),
            verification_uri: "https://idp.example.com/activate".into(),
            verification_uri_complete: Some(
                "https://idp.example.com/activate?user_code=WXYZ".into(),
            ),
            expires_in_seconds: 600,
            interval_seconds: 5,
        };
        let shown = format_prompt(&same);
        assert!(shown.contains("or open directly"));
        assert!(shown.contains("user_code=WXYZ"));

        // A tampered device response pairs a trusted-looking verification_uri
        // with a cross-origin `complete`. The shortcut must not be offered, and
        // the attacker host must never reach the terminal — otherwise a terminal
        // that auto-linkifies URLs would present the attacker link as clickable.
        let cross = DeviceCodeChallenge {
            user_code: "WXYZ".into(),
            verification_uri: "https://login.questdb.io/device".into(),
            verification_uri_complete: Some(
                "https://login.questdb.io@evil.example/?user_code=WXYZ".into(),
            ),
            expires_in_seconds: 600,
            interval_seconds: 5,
        };
        let shown = format_prompt(&cross);
        assert!(
            !shown.contains("or open directly"),
            "cross-origin complete must not be offered as a shortcut; got: {shown}"
        );
        assert!(
            !shown.contains("evil.example"),
            "attacker host leaked into the terminal prompt: {shown}"
        );
    }

    #[test]
    fn safe_target_accepts_plain_https() {
        assert_eq!(
            safe_target(Some("https://idp.example.com/device?code=ABCD")),
            Some("https://idp.example.com/device?code=ABCD".to_string())
        );
    }

    #[test]
    fn safe_target_rejects_userinfo() {
        assert_eq!(safe_target(Some("https://trusted.io@evil.example/")), None);
    }

    #[test]
    fn safe_target_rejects_non_http_scheme() {
        assert_eq!(safe_target(Some("javascript:alert(1)")), None);
        assert_eq!(safe_target(Some("data:text/html,x")), None);
    }

    #[test]
    fn safe_target_rejects_non_ascii_host() {
        assert_eq!(safe_target(Some("https://exa\u{0430}mple.com/")), None);
    }

    #[test]
    fn safe_target_strips_then_vets() {
        // An embedded newline is stripped; the result is still a valid target.
        assert_eq!(
            safe_target(Some("https://idp.example.com/\n")),
            Some("https://idp.example.com/".to_string())
        );
    }

    #[test]
    fn browser_command_passes_url_as_single_argv_element_no_shell() {
        // An untrusted verification URL with shell metacharacters must reach the
        // opener as exactly one argv element — never spliced into a `cmd.exe`
        // command line where `&` would start a second command.
        let url = "https://idp.example/activate?user_code=WXYZ&calc.exe";
        let cmd = browser_command(url);
        let program = cmd.get_program().to_string_lossy().into_owned();
        assert_ne!(program, "cmd", "must not route the URL through cmd.exe");
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(
            args.iter().any(|a| a == url),
            "the URL must be a single argv element, got args: {args:?}"
        );
    }

    #[test]
    fn format_mmss_examples() {
        assert_eq!(format_mmss(0.0), "0:00");
        assert_eq!(format_mmss(65.0), "1:05");
        assert_eq!(format_mmss(600.0), "10:00");
        assert_eq!(format_mmss(f64::INFINITY), "0:00");
    }
}
