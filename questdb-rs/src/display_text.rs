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

/// Non-spacing combining marks (general category `Mn`) as sorted, inclusive
/// code point ranges: every code point whose Unicode 16.0.0 category is `Mn`,
/// as Python's `unicodedata.category` reports it, merged into ranges.
///
/// They stack on the preceding glyph -- the "Zalgo" surface -- and all of them
/// count against [`MAX_STACKING_MARK_RUN`], as in the Python client, which
/// counts the same category. A subset would not do: a mark left out of the
/// count ends a run like a base character, so interleaving one between counted
/// marks would lift the cap. The table is data, not a dependency; a mark that a
/// later Unicode version adds is kept and ends a run until it is regenerated.
#[rustfmt::skip]
const NONSPACING_MARKS: &[(u32, u32)] = &[
    (0x0300, 0x036F), (0x0483, 0x0487), (0x0591, 0x05BD), (0x05BF, 0x05BF),
    (0x05C1, 0x05C2), (0x05C4, 0x05C5), (0x05C7, 0x05C7), (0x0610, 0x061A),
    (0x064B, 0x065F), (0x0670, 0x0670), (0x06D6, 0x06DC), (0x06DF, 0x06E4),
    (0x06E7, 0x06E8), (0x06EA, 0x06ED), (0x0711, 0x0711), (0x0730, 0x074A),
    (0x07A6, 0x07B0), (0x07EB, 0x07F3), (0x07FD, 0x07FD), (0x0816, 0x0819),
    (0x081B, 0x0823), (0x0825, 0x0827), (0x0829, 0x082D), (0x0859, 0x085B),
    (0x0897, 0x089F), (0x08CA, 0x08E1), (0x08E3, 0x0902), (0x093A, 0x093A),
    (0x093C, 0x093C), (0x0941, 0x0948), (0x094D, 0x094D), (0x0951, 0x0957),
    (0x0962, 0x0963), (0x0981, 0x0981), (0x09BC, 0x09BC), (0x09C1, 0x09C4),
    (0x09CD, 0x09CD), (0x09E2, 0x09E3), (0x09FE, 0x09FE), (0x0A01, 0x0A02),
    (0x0A3C, 0x0A3C), (0x0A41, 0x0A42), (0x0A47, 0x0A48), (0x0A4B, 0x0A4D),
    (0x0A51, 0x0A51), (0x0A70, 0x0A71), (0x0A75, 0x0A75), (0x0A81, 0x0A82),
    (0x0ABC, 0x0ABC), (0x0AC1, 0x0AC5), (0x0AC7, 0x0AC8), (0x0ACD, 0x0ACD),
    (0x0AE2, 0x0AE3), (0x0AFA, 0x0AFF), (0x0B01, 0x0B01), (0x0B3C, 0x0B3C),
    (0x0B3F, 0x0B3F), (0x0B41, 0x0B44), (0x0B4D, 0x0B4D), (0x0B55, 0x0B56),
    (0x0B62, 0x0B63), (0x0B82, 0x0B82), (0x0BC0, 0x0BC0), (0x0BCD, 0x0BCD),
    (0x0C00, 0x0C00), (0x0C04, 0x0C04), (0x0C3C, 0x0C3C), (0x0C3E, 0x0C40),
    (0x0C46, 0x0C48), (0x0C4A, 0x0C4D), (0x0C55, 0x0C56), (0x0C62, 0x0C63),
    (0x0C81, 0x0C81), (0x0CBC, 0x0CBC), (0x0CBF, 0x0CBF), (0x0CC6, 0x0CC6),
    (0x0CCC, 0x0CCD), (0x0CE2, 0x0CE3), (0x0D00, 0x0D01), (0x0D3B, 0x0D3C),
    (0x0D41, 0x0D44), (0x0D4D, 0x0D4D), (0x0D62, 0x0D63), (0x0D81, 0x0D81),
    (0x0DCA, 0x0DCA), (0x0DD2, 0x0DD4), (0x0DD6, 0x0DD6), (0x0E31, 0x0E31),
    (0x0E34, 0x0E3A), (0x0E47, 0x0E4E), (0x0EB1, 0x0EB1), (0x0EB4, 0x0EBC),
    (0x0EC8, 0x0ECE), (0x0F18, 0x0F19), (0x0F35, 0x0F35), (0x0F37, 0x0F37),
    (0x0F39, 0x0F39), (0x0F71, 0x0F7E), (0x0F80, 0x0F84), (0x0F86, 0x0F87),
    (0x0F8D, 0x0F97), (0x0F99, 0x0FBC), (0x0FC6, 0x0FC6), (0x102D, 0x1030),
    (0x1032, 0x1037), (0x1039, 0x103A), (0x103D, 0x103E), (0x1058, 0x1059),
    (0x105E, 0x1060), (0x1071, 0x1074), (0x1082, 0x1082), (0x1085, 0x1086),
    (0x108D, 0x108D), (0x109D, 0x109D), (0x135D, 0x135F), (0x1712, 0x1714),
    (0x1732, 0x1733), (0x1752, 0x1753), (0x1772, 0x1773), (0x17B4, 0x17B5),
    (0x17B7, 0x17BD), (0x17C6, 0x17C6), (0x17C9, 0x17D3), (0x17DD, 0x17DD),
    (0x180B, 0x180D), (0x180F, 0x180F), (0x1885, 0x1886), (0x18A9, 0x18A9),
    (0x1920, 0x1922), (0x1927, 0x1928), (0x1932, 0x1932), (0x1939, 0x193B),
    (0x1A17, 0x1A18), (0x1A1B, 0x1A1B), (0x1A56, 0x1A56), (0x1A58, 0x1A5E),
    (0x1A60, 0x1A60), (0x1A62, 0x1A62), (0x1A65, 0x1A6C), (0x1A73, 0x1A7C),
    (0x1A7F, 0x1A7F), (0x1AB0, 0x1ABD), (0x1ABF, 0x1ACE), (0x1B00, 0x1B03),
    (0x1B34, 0x1B34), (0x1B36, 0x1B3A), (0x1B3C, 0x1B3C), (0x1B42, 0x1B42),
    (0x1B6B, 0x1B73), (0x1B80, 0x1B81), (0x1BA2, 0x1BA5), (0x1BA8, 0x1BA9),
    (0x1BAB, 0x1BAD), (0x1BE6, 0x1BE6), (0x1BE8, 0x1BE9), (0x1BED, 0x1BED),
    (0x1BEF, 0x1BF1), (0x1C2C, 0x1C33), (0x1C36, 0x1C37), (0x1CD0, 0x1CD2),
    (0x1CD4, 0x1CE0), (0x1CE2, 0x1CE8), (0x1CED, 0x1CED), (0x1CF4, 0x1CF4),
    (0x1CF8, 0x1CF9), (0x1DC0, 0x1DFF), (0x20D0, 0x20DC), (0x20E1, 0x20E1),
    (0x20E5, 0x20F0), (0x2CEF, 0x2CF1), (0x2D7F, 0x2D7F), (0x2DE0, 0x2DFF),
    (0x302A, 0x302D), (0x3099, 0x309A), (0xA66F, 0xA66F), (0xA674, 0xA67D),
    (0xA69E, 0xA69F), (0xA6F0, 0xA6F1), (0xA802, 0xA802), (0xA806, 0xA806),
    (0xA80B, 0xA80B), (0xA825, 0xA826), (0xA82C, 0xA82C), (0xA8C4, 0xA8C5),
    (0xA8E0, 0xA8F1), (0xA8FF, 0xA8FF), (0xA926, 0xA92D), (0xA947, 0xA951),
    (0xA980, 0xA982), (0xA9B3, 0xA9B3), (0xA9B6, 0xA9B9), (0xA9BC, 0xA9BD),
    (0xA9E5, 0xA9E5), (0xAA29, 0xAA2E), (0xAA31, 0xAA32), (0xAA35, 0xAA36),
    (0xAA43, 0xAA43), (0xAA4C, 0xAA4C), (0xAA7C, 0xAA7C), (0xAAB0, 0xAAB0),
    (0xAAB2, 0xAAB4), (0xAAB7, 0xAAB8), (0xAABE, 0xAABF), (0xAAC1, 0xAAC1),
    (0xAAEC, 0xAAED), (0xAAF6, 0xAAF6), (0xABE5, 0xABE5), (0xABE8, 0xABE8),
    (0xABED, 0xABED), (0xFB1E, 0xFB1E), (0xFE00, 0xFE0F), (0xFE20, 0xFE2F),
    (0x101FD, 0x101FD), (0x102E0, 0x102E0), (0x10376, 0x1037A),
    (0x10A01, 0x10A03), (0x10A05, 0x10A06), (0x10A0C, 0x10A0F),
    (0x10A38, 0x10A3A), (0x10A3F, 0x10A3F), (0x10AE5, 0x10AE6),
    (0x10D24, 0x10D27), (0x10D69, 0x10D6D), (0x10EAB, 0x10EAC),
    (0x10EFC, 0x10EFF), (0x10F46, 0x10F50), (0x10F82, 0x10F85),
    (0x11001, 0x11001), (0x11038, 0x11046), (0x11070, 0x11070),
    (0x11073, 0x11074), (0x1107F, 0x11081), (0x110B3, 0x110B6),
    (0x110B9, 0x110BA), (0x110C2, 0x110C2), (0x11100, 0x11102),
    (0x11127, 0x1112B), (0x1112D, 0x11134), (0x11173, 0x11173),
    (0x11180, 0x11181), (0x111B6, 0x111BE), (0x111C9, 0x111CC),
    (0x111CF, 0x111CF), (0x1122F, 0x11231), (0x11234, 0x11234),
    (0x11236, 0x11237), (0x1123E, 0x1123E), (0x11241, 0x11241),
    (0x112DF, 0x112DF), (0x112E3, 0x112EA), (0x11300, 0x11301),
    (0x1133B, 0x1133C), (0x11340, 0x11340), (0x11366, 0x1136C),
    (0x11370, 0x11374), (0x113BB, 0x113C0), (0x113CE, 0x113CE),
    (0x113D0, 0x113D0), (0x113D2, 0x113D2), (0x113E1, 0x113E2),
    (0x11438, 0x1143F), (0x11442, 0x11444), (0x11446, 0x11446),
    (0x1145E, 0x1145E), (0x114B3, 0x114B8), (0x114BA, 0x114BA),
    (0x114BF, 0x114C0), (0x114C2, 0x114C3), (0x115B2, 0x115B5),
    (0x115BC, 0x115BD), (0x115BF, 0x115C0), (0x115DC, 0x115DD),
    (0x11633, 0x1163A), (0x1163D, 0x1163D), (0x1163F, 0x11640),
    (0x116AB, 0x116AB), (0x116AD, 0x116AD), (0x116B0, 0x116B5),
    (0x116B7, 0x116B7), (0x1171D, 0x1171D), (0x1171F, 0x1171F),
    (0x11722, 0x11725), (0x11727, 0x1172B), (0x1182F, 0x11837),
    (0x11839, 0x1183A), (0x1193B, 0x1193C), (0x1193E, 0x1193E),
    (0x11943, 0x11943), (0x119D4, 0x119D7), (0x119DA, 0x119DB),
    (0x119E0, 0x119E0), (0x11A01, 0x11A0A), (0x11A33, 0x11A38),
    (0x11A3B, 0x11A3E), (0x11A47, 0x11A47), (0x11A51, 0x11A56),
    (0x11A59, 0x11A5B), (0x11A8A, 0x11A96), (0x11A98, 0x11A99),
    (0x11C30, 0x11C36), (0x11C38, 0x11C3D), (0x11C3F, 0x11C3F),
    (0x11C92, 0x11CA7), (0x11CAA, 0x11CB0), (0x11CB2, 0x11CB3),
    (0x11CB5, 0x11CB6), (0x11D31, 0x11D36), (0x11D3A, 0x11D3A),
    (0x11D3C, 0x11D3D), (0x11D3F, 0x11D45), (0x11D47, 0x11D47),
    (0x11D90, 0x11D91), (0x11D95, 0x11D95), (0x11D97, 0x11D97),
    (0x11EF3, 0x11EF4), (0x11F00, 0x11F01), (0x11F36, 0x11F3A),
    (0x11F40, 0x11F40), (0x11F42, 0x11F42), (0x11F5A, 0x11F5A),
    (0x13440, 0x13440), (0x13447, 0x13455), (0x1611E, 0x16129),
    (0x1612D, 0x1612F), (0x16AF0, 0x16AF4), (0x16B30, 0x16B36),
    (0x16F4F, 0x16F4F), (0x16F8F, 0x16F92), (0x16FE4, 0x16FE4),
    (0x1BC9D, 0x1BC9E), (0x1CF00, 0x1CF2D), (0x1CF30, 0x1CF46),
    (0x1D167, 0x1D169), (0x1D17B, 0x1D182), (0x1D185, 0x1D18B),
    (0x1D1AA, 0x1D1AD), (0x1D242, 0x1D244), (0x1DA00, 0x1DA36),
    (0x1DA3B, 0x1DA6C), (0x1DA75, 0x1DA75), (0x1DA84, 0x1DA84),
    (0x1DA9B, 0x1DA9F), (0x1DAA1, 0x1DAAF), (0x1E000, 0x1E006),
    (0x1E008, 0x1E018), (0x1E01B, 0x1E021), (0x1E023, 0x1E024),
    (0x1E026, 0x1E02A), (0x1E08F, 0x1E08F), (0x1E130, 0x1E136),
    (0x1E2AE, 0x1E2AE), (0x1E2EC, 0x1E2EF), (0x1E4EC, 0x1E4EF),
    (0x1E5EE, 0x1E5EF), (0x1E8D0, 0x1E8D6), (0x1E944, 0x1E94A),
    (0xE0100, 0xE01EF),
];

/// Whether `ch` is a non-spacing combining mark (category `Mn`).
fn is_nonspacing_mark(ch: char) -> bool {
    let cp = u32::from(ch);
    NONSPACING_MARKS
        .binary_search_by(|&(first, last)| {
            if last < cp {
                std::cmp::Ordering::Less
            } else if first > cp {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// Consecutive [non-spacing marks](is_nonspacing_mark) kept on one base
/// character.
///
/// They pile up vertically, so a long run smears across the lines above and
/// below and can obscure the real sign-in URL or code in a terminal prompt.
/// Real accented text never needs more than a couple (decomposed Vietnamese and
/// Hebrew nikud+cantillation reach about two), so this is generous for
/// legitimate input while neutralising a runaway stack. Matches the cap the
/// Python client applies to the same fields, counting the same marks.
pub(crate) const MAX_STACKING_MARK_RUN: usize = 4;

/// Convert untrusted text to inert, single-line display text.
///
/// C0/C1 controls and DEL (including ANSI, tabs, and line breaks), bidi
/// controls, zero-width characters, enclosing combining marks, private-use
/// characters, and other invisible formatting are removed. Non-ASCII whitespace
/// is folded to an ordinary space, and a run of non-spacing combining marks is
/// truncated to a bounded length. This is suitable for human-readable
/// labels and messages; URLs and short authentication codes need the stricter
/// display accessors on the OIDC `DeviceCodeChallenge` so confusable non-ASCII
/// characters are also made visible. This sanitizer never fails.
///
/// The removed character classes are enumerated rather than taken from a
/// general-category table, so this is a strong filter and not a proof: an
/// unassigned codepoint (category `Cn`) that a future Unicode version gives
/// invisible semantics to would pass until the ranges here are updated. It is
/// the last line before a terminal or a notebook DOM, not the only one -- the
/// fields it guards are separately length-capped, and the actionable URL is
/// vetted by the crate's URL vetter rather than merely sanitized.
pub(crate) fn sanitize_display_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut mark_run = 0usize;
    for ch in text.chars() {
        // is_control() covers C0 (incl. tab/newline/CR), DEL and C1.
        if ch.is_control() || is_format_or_bidi(ch) || is_invisible_or_enclosing(ch) {
            continue;
        }
        if is_nonspacing_mark(ch) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonspacing_marks_are_sorted_and_disjoint() {
        // `is_nonspacing_mark` binary-searches the table.
        for &(first, last) in NONSPACING_MARKS {
            assert!(first <= last, "{first:#x}..={last:#x}");
        }
        for pair in NONSPACING_MARKS.windows(2) {
            assert!(pair[0].1 < pair[1].0, "{:#x?}", pair);
        }
        assert!(is_nonspacing_mark('\u{0300}'));
        assert!(is_nonspacing_mark('\u{0951}'));
        assert!(is_nonspacing_mark('\u{E01EF}'));
        assert!(!is_nonspacing_mark('a'));
        assert!(!is_nonspacing_mark('\u{0939}'));
    }
}
