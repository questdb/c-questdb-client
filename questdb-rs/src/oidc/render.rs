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
        | '\u{0600}'..='\u{0605}'     // arabic number/subtending marks (Cf)
        | '\u{061C}'                  // arabic letter mark
        | '\u{06DD}'                  // arabic end of ayah (Cf)
        | '\u{070F}'                  // syriac abbreviation mark (Cf)
        | '\u{0890}'..='\u{0891}'     // arabic pound/piastre marks (Cf)
        | '\u{08E2}'                  // arabic disputed end of ayah (Cf)
        | '\u{180E}'                  // mongolian vowel separator
        | '\u{200B}'..='\u{200F}'     // zero-width space/joiner/non-joiner + LRM/RLM
        | '\u{202A}'..='\u{202E}'     // bidi embeddings / overrides
        | '\u{2060}'..='\u{2064}'     // word joiner + invisible math operators
        | '\u{2066}'..='\u{206F}'     // bidi isolates + deprecated format controls
        | '\u{FEFF}'                  // zero-width no-break space / BOM
        | '\u{FFF9}'..='\u{FFFB}'     // interlinear annotation anchors
        | '\u{110BD}' | '\u{110CD}'   // kaithi number signs (Cf)
        | '\u{13430}'..='\u{1343F}'   // egyptian hieroglyph format controls (Cf)
        | '\u{1D173}'..='\u{1D17A}'   // musical symbol beams/slurs (Cf)
        | '\u{115F}' | '\u{1160}' | '\u{3164}' | '\u{FFA0}' // hangul fillers (render blank)
        | '\u{FE00}'..='\u{FE0F}'     // variation selectors
        | '\u{1BCA0}'..='\u{1BCA3}'   // shorthand format controls
        | '\u{E0000}'..='\u{E007F}'   // tag characters
        | '\u{E0100}'..='\u{E01EF}'   // variation selectors supplement
    )
}

/// Invisible or overlaying characters that `is_control` / [`is_format_or_bidi`]
/// do not reach.
///
/// Enclosing combining marks (category `Me`) overlay the *preceding* glyph with
/// a circle, slash or keycap, so they rewrite a character the reader has already
/// accepted -- never part of a legitimate identity, URL or user code. The rest
/// are individually invisible: the combining grapheme joiner, the Mongolian free
/// variation selectors, the Khmer inherent vowels (all `Mn`, so the accent-
/// keeping rule below would otherwise let them through), and the braille blank,
/// which is category `So` and renders as an empty cell -- the same hidden-
/// padding primitive as the Hangul fillers above.
fn is_invisible_or_enclosing(ch: char) -> bool {
    matches!(ch,
        // Category Me, in full.
        '\u{0488}'..='\u{0489}'
        | '\u{1ABE}'
        | '\u{20DD}'..='\u{20E0}'
        | '\u{20E2}'..='\u{20E4}'
        | '\u{A670}'..='\u{A672}'
        // Invisible Default_Ignorable non-spacing marks.
        | '\u{034F}'                  // combining grapheme joiner
        | '\u{17B4}'..='\u{17B5}'     // khmer inherent vowels
        | '\u{180B}'..='\u{180D}'     // mongolian free variation selectors
        | '\u{180F}'
        // Renders as a blank cell.
        | '\u{2800}'                  // braille pattern blank
        // Private use: no defined glyph, renders at the font's discretion.
        | '\u{E000}'..='\u{F8FF}'
        | '\u{F0000}'..='\u{FFFFD}'
        | '\u{100000}'..='\u{10FFFD}'
    )
}

/// Non-spacing combining marks (category `Mn`) that stack on the preceding
/// glyph -- the "Zalgo" surface.
///
/// Only the stacking blocks are listed. A general-category table would be
/// exhaustive, but it means a Unicode data dependency in a client library that
/// deliberately has none, for a defence-in-depth display filter; these blocks
/// carry the marks that actually pile up vertically. Anything missed is kept
/// and merely counted against the run cap by its base character instead.
fn is_stacking_mark(ch: char) -> bool {
    matches!(ch,
        '\u{0300}'..='\u{036F}'       // combining diacritical marks
        | '\u{0483}'..='\u{0487}'     // cyrillic
        | '\u{0591}'..='\u{05BD}'     // hebrew points / cantillation
        | '\u{05BF}' | '\u{05C1}'..='\u{05C2}'
        | '\u{05C4}'..='\u{05C5}' | '\u{05C7}'
        | '\u{0610}'..='\u{061A}'     // arabic
        | '\u{064B}'..='\u{065F}'
        | '\u{0670}'
        | '\u{06D6}'..='\u{06DC}'
        | '\u{06DF}'..='\u{06E4}'
        | '\u{06E7}'..='\u{06E8}'
        | '\u{06EA}'..='\u{06ED}'
        | '\u{1AB0}'..='\u{1ACE}'     // combining diacritical marks extended
        | '\u{1DC0}'..='\u{1DFF}'     // combining diacritical marks supplement
        | '\u{20D0}'..='\u{20DC}'     // combining marks for symbols (Mn part)
        | '\u{20E1}'
        | '\u{20E5}'..='\u{20F0}'
        | '\u{FE20}'..='\u{FE2F}'     // combining half marks
    )
}

/// Consecutive [stacking marks](is_stacking_mark) kept on one base character.
///
/// They pile up vertically, so a long run smears across the lines above and
/// below and can obscure the real sign-in URL or code in a terminal prompt.
/// Real accented text never needs more than a couple (decomposed Vietnamese and
/// Hebrew nikud+cantillation reach about two), so this is generous for
/// legitimate input while neutralising a runaway stack. Matches the cap the
/// Python client applies to the same fields.
const MAX_STACKING_MARK_RUN: usize = 4;

/// Convert untrusted text to inert, single-line display text.
///
/// C0/C1 controls and DEL (including ANSI, tabs, and line breaks), bidi
/// controls, zero-width characters, enclosing combining marks, private-use
/// characters, and other invisible formatting are removed. Non-ASCII whitespace
/// is folded to an ordinary space, and a run of stacking combining marks is
/// truncated to [`MAX_STACKING_MARK_RUN`]. This is suitable for human-readable
/// labels and messages; URLs and short authentication codes need the stricter
/// display accessors on [`DeviceCodeChallenge`] so confusable non-ASCII
/// characters are also made visible. This sanitizer never fails.
///
/// The character classes are enumerated rather than taken from a general-
/// category table, so this is a strong filter and not a proof: an unassigned
/// codepoint (category `Cn`) that a future Unicode version gives invisible
/// semantics to would pass until the ranges here are updated. It is the last
/// line before a terminal or a notebook DOM, not the only one -- the fields it
/// guards are separately length-capped, and the actionable URL is vetted by
/// [`safe_target`] rather than merely sanitized.
pub fn sanitize_display_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut mark_run = 0usize;
    for ch in text.chars() {
        // is_control() covers C0 (incl. tab/newline/CR), DEL and C1.
        if ch.is_control() || is_format_or_bidi(ch) || is_invisible_or_enclosing(ch) {
            continue;
        }
        if is_stacking_mark(ch) {
            // Count against the current base character; drop the overflow
            // rather than the whole run, so a legitimately accented name keeps
            // its accents.
            mark_run += 1;
            if mark_run > MAX_STACKING_MARK_RUN {
                continue;
            }
        } else {
            mark_run = 0;
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
/// connects to `host` while *reading* as the trusted user part), whose host is
/// not plain ASCII letters/digits/`.`/`-`/`:` (a homoglyph / confusable host,
/// or a `%` percent-encoding / IPv6 zone-id), or whose host carries an IDNA
/// A-label (`xn--`), which is a confusable that is already ASCII-encoded and so
/// invisible to the previous test. A rejected URL is still *shown* as inert
/// text via [`display_url`]; it is just never opened.
pub(crate) fn safe_target(url: Option<&str>) -> Option<String> {
    let raw = url?;
    // Strip first so a control char can't survive into the opened URL, then trim
    // (a leading space would make the scheme parse fail or shift).
    let cleaned = strip_control(raw);
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        return None;
    }
    // Reject rather than truncate. Every other untrusted display field is
    // capped at MAX_DISPLAY_FIELD_CHARS, but this one is actionable -- it is
    // opened in a browser and encoded into the QR code -- and a truncated URL
    // can still parse as a perfectly valid *different* URL, which would send the
    // user somewhere the identity provider never named. A genuine
    // verification_uri_complete is far below this bound; anything past it is
    // shown as inert text by `display_url` (which does truncate) and simply
    // never offered as a target. Without this the only bound was
    // `Uri::MAX_LEN`, so a ~64 KB same-origin URL reached stderr, the C event
    // callback, a notebook DOM and an `xdg-open` argv.
    if trimmed.chars().count() > MAX_DISPLAY_FIELD_CHARS {
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
    // `Authority::host()` hands back an IPv6 literal in its bracketed form,
    // `[::1]`, and the byte allowlist below has no brackets -- so every IPv6
    // verification URI was refused outright: no link, no QR, no browser open,
    // on a host that is about as un-confusable as one gets. Unwrap it and
    // require the inside to parse as an address, which is stricter than the
    // allowlist would have been: a zone id (`%eth0`) is rejected with it.
    let host = match host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        Some(inner) => {
            if inner.parse::<std::net::Ipv6Addr>().is_err() {
                return None;
            }
            inner
        }
        None => host,
    };
    if host.is_empty()
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'))
    {
        return None;
    }
    // The ASCII test above cannot see a homoglyph that arrives already encoded.
    // An IDNA A-label is plain ASCII by construction, so `xn--80ak6aa92e.com`
    // and `xn--pple-43d.com` pass it -- and then render as `аррӏе.com` and
    // `àpple.com` in the address bar, which is exactly the confusable host this
    // function promises to refuse. Rejecting the encoded form is the only way
    // to keep that promise here: this is the sole URL vetted for opening in a
    // browser and for QR encoding, and a QR is never read by a human before it
    // is followed. A device-flow verification URI has no business being an IDN.
    if host
        .split('.')
        .any(|label| label.len() >= 4 && label[..4].eq_ignore_ascii_case("xn--"))
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
    fn strip_control_caps_a_stacking_mark_run() {
        // A "Zalgo" stack piles up vertically and smears across the lines above
        // and below -- in a terminal prompt those lines carry the real sign-in
        // URL and the user code. The run is truncated rather than dropped
        // whole, so a legitimately accented name keeps its accents.
        let zalgo = format!("A{}B", "\u{0301}".repeat(200));
        let cleaned = strip_control(&zalgo);
        assert_eq!(
            cleaned,
            format!("A{}B", "\u{0301}".repeat(MAX_STACKING_MARK_RUN))
        );
        // Each base character gets its own allowance.
        assert_eq!(strip_control("e\u{0301}a\u{0300}"), "e\u{0301}a\u{0300}");
        // Decomposed Vietnamese (base + horn + tone) is well inside the cap.
        assert_eq!(strip_control("o\u{031b}\u{0301}"), "o\u{031b}\u{0301}");
    }

    #[test]
    fn strip_control_drops_enclosing_and_invisible_marks() {
        // Enclosing marks (Me) overlay the *preceding* glyph with a circle,
        // slash or keycap, rewriting a character the reader already accepted.
        assert_eq!(strip_control("7\u{20e0}"), "7"); // combining enclosing slash
        assert_eq!(strip_control("A\u{0489}"), "A"); // cyrillic million sign
        // Individually invisible characters the category-free control and
        // format tests do not reach.
        assert_eq!(strip_control("a\u{2800}b"), "ab"); // braille blank
        assert_eq!(strip_control("a\u{034f}b"), "ab"); // grapheme joiner
        assert_eq!(strip_control("a\u{17b4}b"), "ab"); // khmer inherent vowel
        assert_eq!(strip_control("a\u{180b}b"), "ab"); // mongolian FVS
        // Private use has no defined glyph.
        assert_eq!(strip_control("a\u{e000}b"), "ab");
        // Format characters outside the previously enumerated runs.
        assert_eq!(strip_control("a\u{0600}b"), "ab"); // arabic number sign
        assert_eq!(strip_control("a\u{110bd}b"), "ab"); // kaithi number sign
        assert_eq!(strip_control("a\u{1d173}b"), "ab"); // musical beam
    }

    #[test]
    fn strip_control_keeps_legitimate_text() {
        // The filter must not eat real identities: accents, Indic spacing
        // marks (Mc), CJK, emoji and ordinary punctuation all survive.
        for text in [
            "Ana Gómez",
            "Ann-Marie O'Neill",
            "北京用户",
            "user@example.com",
            "\u{0915}\u{094b}", // devanagari ko (base + Mc vowel sign)
            "Ελένη",
            "Пользователь",
        ] {
            assert_eq!(strip_control(text), text, "mangled legitimate text");
        }
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
    fn safe_target_rejects_an_oversized_url() {
        // The actionable target is opened in a browser and encoded into the QR
        // code, so an over-long one is refused rather than truncated: a cut URL
        // can still parse as a valid *different* URL. Bounded only by
        // Uri::MAX_LEN before, a ~64 KB same-origin value reached stderr, the C
        // event callback, a notebook DOM and an xdg-open argv.
        let long_path = "a".repeat(MAX_DISPLAY_FIELD_CHARS);
        let url = format!("https://idp.example.com/{long_path}");
        assert!(url.chars().count() > MAX_DISPLAY_FIELD_CHARS);
        assert_eq!(safe_target(Some(&url)), None);

        // ...while it is still shown, inert and truncated, as text.
        let shown = display_url(&url);
        assert!(
            shown.chars().count() < url.chars().count(),
            "an oversized URL must not be echoed raw"
        );
        // The truncation marker is non-ASCII, so display_url escapes it.
        assert!(shown.ends_with("\\u{2026}"));

        // A realistic verification_uri_complete is unaffected.
        let ok = "https://idp.example.com/device?user_code=ABCD-EFGH";
        assert_eq!(safe_target(Some(ok)), Some(ok.to_string()));
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
    fn safe_target_rejects_an_idna_a_label_host() {
        // The plain-ASCII host test cannot see a confusable that arrives
        // already encoded: an A-label is ASCII by construction. These two are
        // `аррӏе.com` (Cyrillic) and `àpple.com`, and the browser renders them
        // in their Unicode form in the address bar -- so the check that claims
        // to reject "a homoglyph / confusable host" did not.
        //
        // This field is the one that is *acted on* rather than read: it is
        // launched by `maybe_open_browser` and encoded into the QR, and a QR is
        // never read by a human before it is followed. Showing the punycode --
        // the mitigation `display_url` relies on -- protects nobody here.
        for host in ["xn--80ak6aa92e.com", "xn--pple-43d.com", "XN--PPLE-43D.com"] {
            assert_eq!(
                safe_target(Some(&format!("https://{host}/device"))),
                None,
                "{host} must not be offered as an actionable target"
            );
        }
        // A sub-domain A-label is equally confusable.
        assert_eq!(
            safe_target(Some("https://xn--pple-43d.idp.example.com/device")),
            None
        );
        // Degrades gracefully rather than hiding the URL: the prompt still
        // shows it, just never opens it or encodes it into a QR.
        assert!(!display_url("https://xn--pple-43d.com/device").is_empty());
        // A host that merely *contains* those letters is not an A-label.
        assert!(safe_target(Some("https://xnotxn.example.com/device")).is_some());
        assert!(safe_target(Some("https://example.com/xn--path")).is_some());
    }

    #[test]
    fn safe_target_accepts_an_ipv6_literal_host() {
        // Regression: `Authority::host()` returns the bracketed form, and the
        // byte allowlist had no brackets, so EVERY IPv6 verification URI was
        // refused -- no link, no QR, no browser open -- on a host that cannot
        // be a homoglyph.
        assert_eq!(
            safe_target(Some("https://[::1]:8443/device")),
            Some("https://[::1]:8443/device".to_string())
        );
        assert!(safe_target(Some("http://[fe80::1]/device")).is_some());
        // A zone id is still refused: `%` can misrepresent the destination, and
        // the address parse rejects it.
        assert_eq!(safe_target(Some("https://[fe80::1%25eth0]/device")), None);
        // Brackets are not a way past the host allowlist for a name.
        assert_eq!(safe_target(Some("https://[not-an-address]/device")), None);
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
