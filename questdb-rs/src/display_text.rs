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

//! Display-safe text for untrusted strings.
//!
//! Shared by the OIDC prompt renderer, which shows untrusted identity-provider
//! fields, and by token-provider error redaction, which puts untrusted
//! token-source and library text into client errors and log lines
//! (design/qwp-token-provider-spec.md §9).

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
pub(crate) const MAX_STACKING_MARK_RUN: usize = 4;

/// Convert untrusted text to inert, single-line display text.
///
/// C0/C1 controls and DEL (including ANSI, tabs, and line breaks), bidi
/// controls, zero-width characters, enclosing combining marks, private-use
/// characters, and other invisible formatting are removed. Non-ASCII whitespace
/// is folded to an ordinary space, and a run of stacking combining marks is
/// truncated to a bounded length. This is suitable for human-readable
/// labels and messages; URLs and short authentication codes need the stricter
/// display accessors on the OIDC `DeviceCodeChallenge` so confusable non-ASCII
/// characters are also made visible. This sanitizer never fails.
///
/// The character classes are enumerated rather than taken from a general-
/// category table, so this is a strong filter and not a proof: an unassigned
/// codepoint (category `Cn`) that a future Unicode version gives invisible
/// semantics to would pass until the ranges here are updated. It is the last
/// line before a terminal or a notebook DOM, not the only one -- the fields it
/// guards are separately length-capped, and the actionable URL is vetted by
/// the crate's URL vetter rather than merely sanitized.
pub(crate) fn sanitize_display_text(text: &str) -> String {
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
