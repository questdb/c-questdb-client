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

//! Credential redaction (design/qwp-token-provider-spec.md §9).
//!
//! A token never appears in a log line, an error message, an event or the
//! `Debug` rendering of any object. The most a rendering shows is the token's
//! length and the first 8 hex digits of its SHA-256, enough to correlate
//! rotations across log lines. Untrusted error text from a token source or an
//! identity library passes through [`sanitize_error_text`] before it reaches a
//! client error or a log line.

use crate::display_text::sanitize_display_text;

/// Upper bound, in characters, on sanitized error text from a token source.
pub(crate) const MAX_ERROR_TEXT_LENGTH: usize = 256;

const TRUNCATION_MARKER: &str = "...";

/// Render a token as `<redacted, N chars, sha256:xxxxxxxx>`. Never the token.
pub(crate) fn describe_token(token: &str) -> String {
    format!(
        "<redacted, {} chars, sha256:{}>",
        token.len(),
        fingerprint(token)
    )
}

/// The first 8 hex digits of the SHA-256 of `token`.
pub(crate) fn fingerprint(token: &str) -> String {
    use std::fmt::Write as _;
    let digest = sha256(token.as_bytes());
    let mut out = String::with_capacity(8);
    for byte in &digest[..4] {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Prepare untrusted error text for a client error or a log line.
///
/// Removes control, bidirectional, zero-width and other non-displayable
/// characters, and caps the result at [`MAX_ERROR_TEXT_LENGTH`] characters,
/// ending in `...` when it had to cut. Text that fits exactly is kept whole.
///
/// This cannot remove a secret the text already carries: keeping tokens and
/// response bodies out of error text is the job of whoever produces it.
pub(crate) fn sanitize_error_text(text: &str) -> String {
    let clean = sanitize_display_text(text);
    if clean.chars().count() <= MAX_ERROR_TEXT_LENGTH {
        return clean;
    }
    let keep = MAX_ERROR_TEXT_LENGTH - TRUNCATION_MARKER.len();
    let mut out: String = clean.chars().take(keep).collect();
    out.push_str(TRUNCATION_MARKER);
    out
}

/// FIPS 180-4 SHA-256, used only for the non-secret token fingerprint above.
///
/// Inlined, like the handshake's SHA-1 in `ws::crypto`, so this module does not
/// depend on which crypto provider (`ring` or `aws-lc-rs`) the build enabled.
fn sha256(input: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut message = Vec::with_capacity(input.len() + 72);
    message.extend_from_slice(input);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());

    let mut w = [0u32; 64];
    let (blocks, _) = message.as_chunks::<64>();
    for block in blocks {
        for (i, word) in block.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(*word);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (state, value) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *state = state.wrapping_add(value);
        }
    }

    let mut out = [0u8; 32];
    for (chunk, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(h) {
        *chunk = word.to_be_bytes();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn sha256_matches_fips_180_4_examples() {
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // 56 bytes: the length field no longer fits, so padding adds a block.
        assert_eq!(
            hex(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        // Several blocks.
        assert_eq!(
            hex(&sha256(&[b'a'; 1_000])),
            "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3"
        );
    }

    #[test]
    fn describe_token_shows_length_and_fingerprint_only() {
        let token = "eyJhbGciOiJSUzI1NiJ9.sentinel-secret.sig";
        let described = describe_token(token);
        assert_eq!(
            described,
            format!(
                "<redacted, {} chars, sha256:{}>",
                token.len(),
                fingerprint(token)
            )
        );
        assert!(!described.contains("sentinel"));
        assert_eq!(fingerprint("abc"), "ba7816bf");
    }

    #[test]
    fn sanitize_error_text_strips_unsafe_characters_and_caps_length() {
        assert_eq!(
            sanitize_error_text("bad\r\n\u{1b}[31mthing\u{202e}"),
            "bad[31mthing"
        );
        let exact = "x".repeat(MAX_ERROR_TEXT_LENGTH);
        assert_eq!(sanitize_error_text(&exact), exact);
        let long = "y".repeat(MAX_ERROR_TEXT_LENGTH + 1);
        let capped = sanitize_error_text(&long);
        assert_eq!(capped.chars().count(), MAX_ERROR_TEXT_LENGTH);
        assert!(capped.ends_with("..."));
        // Removed characters do not count against the cap.
        let padded = format!("{}{}", "\u{200b}".repeat(500), "z".repeat(10));
        assert_eq!(sanitize_error_text(&padded), "z".repeat(10));
    }
}
