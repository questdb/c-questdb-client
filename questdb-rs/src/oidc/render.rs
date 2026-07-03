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
//! [`strip_control`] first, and any URL made clickable / opened in a browser is
//! additionally vetted by [`safe_target`].

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};

/// The parts of an RFC 8628 device-authorization response shown to the user.
///
/// The `device_code` itself is deliberately absent — it is a secret used only in
/// the poll request, never displayed.
///
/// **These fields are the raw, untrusted IdP response values** (they are *not*
/// pre-sanitized). The built-in [`TerminalRenderer`] passes them through
/// [`strip_control`] / [`safe_target`] at display time; a custom [`Renderer`]
/// that echoes [`user_code`](Self::user_code) / [`verification_uri`](Self::verification_uri)
/// to a terminal or DOM MUST sanitize them itself, or it re-opens the ANSI /
/// bidi / zero-width prompt-spoofing surface.
#[derive(Debug, Clone)]
pub struct DeviceCodeChallenge {
    pub(crate) user_code: String,
    pub(crate) verification_uri: String,
    pub(crate) verification_uri_complete: Option<String>,
}

impl DeviceCodeChallenge {
    /// The short code the user types on the verification page.
    pub fn user_code(&self) -> &str {
        &self.user_code
    }

    /// The URL the user opens to authorize the device.
    pub fn verification_uri(&self) -> &str {
        &self.verification_uri
    }

    /// The verification URL with the code pre-filled (RFC 8628
    /// `verification_uri_complete`), when the IdP provides one.
    pub fn verification_uri_complete(&self) -> Option<&str> {
        self.verification_uri_complete.as_deref()
    }

    /// The single vetted `http(s)` target to open in a browser / make clickable:
    /// the pre-filled URL when safe, else the plain verification URL.
    pub(crate) fn safe_target(&self) -> Option<String> {
        safe_target(self.verification_uri_complete.as_deref())
            .or_else(|| safe_target(Some(&self.verification_uri)))
    }
}

/// Receives device-flow sign-in events so they can be presented to the user.
///
/// Every method has a no-op default, so a custom renderer overrides only what it
/// needs. The callbacks receive **untrusted, MITM-tamperable IdP fields**; a
/// custom renderer that writes them to a terminal must sanitise them itself
/// (see [`strip_control`]) — echoing them raw re-opens the prompt-spoofing
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

impl Renderer for TerminalRenderer {
    fn on_prompt(&self, challenge: &DeviceCodeChallenge) {
        let uri = display_url(&challenge.verification_uri);
        let code = strip_control(&challenge.user_code);
        let mut msg = format!("🔐 Sign in to QuestDB\n   Open {uri}  and enter code:  {code}\n");
        if let Some(complete) = &challenge.verification_uri_complete {
            let complete = display_url(complete);
            if !complete.is_empty() {
                msg.push_str(&format!("   (or open directly: {complete})\n"));
            }
        }
        self.write(&msg);
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
            Some(id) => format!(" as {}", strip_control(id)),
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
            // promptly once it has handed the URL to the browser.
            std::thread::spawn(move || {
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

/// Strip control / format characters from an untrusted string before display.
///
/// The verification URL, user code and IdP error strings are untrusted: raw ANSI
/// escapes or bidi / zero-width / line-separator characters could spoof the
/// prompt or hide the real sign-in URL. C0/C1 controls and DEL are dropped
/// (covers ANSI, tab, newline, CR), a curated set of invisible format / bidi
/// characters is dropped, and every non-ASCII-space whitespace (NBSP, line /
/// paragraph separators, ...) is folded to a plain space so it can't hide
/// trailing text or inject a line break. This sanitizer never fails.
pub(crate) fn strip_control(text: &str) -> String {
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
    let text = strip_control(url);
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
    fn display_url_escapes_non_ascii() {
        let shown = display_url("https://exa\u{0430}mple.com"); // Cyrillic 'а'
        assert!(!shown.contains('\u{0430}'));
        assert!(shown.contains("\\u{0430}"));
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
