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

//! RFC 6455 §4.2.2 Sec-WebSocket-Accept primitives.
//!
//! The Accept dance is `base64(SHA1(client_key || WS_MAGIC_GUID))`. The
//! SHA-1 here is *not* a security primitive — it exists solely to make
//! accidental cross-protocol upgrade replies (e.g. an HTTP server that
//! happens to return 101) fail loudly during handshake validation. We
//! ship an inline RFC 3174 implementation rather than route through
//! `ring` / `aws-lc-rs` so this module compiles regardless of which
//! crypto provider the wider crate has enabled.

use base64ct::{Base64, Encoding};

/// RFC 6455 §4.1 magic GUID concatenated with the client-generated
/// Sec-WebSocket-Key before SHA1, then base64-encoded for the
/// Sec-WebSocket-Accept response header.
pub(crate) const WS_MAGIC_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Base64-encode `input` to a `String`. Thin wrapper around `base64ct`
/// to keep callers from depending on it directly.
pub(crate) fn b64_encode(input: &[u8]) -> String {
    Base64::encode_string(input)
}

/// Compute `base64(SHA1(key_b64 || WS_MAGIC_GUID))` per RFC 6455 §4.2.2.
/// `key_b64` is the value the client sent in `Sec-WebSocket-Key`.
pub(crate) fn compute_accept(key_b64: &str) -> String {
    let mut buf = String::with_capacity(key_b64.len() + WS_MAGIC_GUID.len());
    buf.push_str(key_b64);
    buf.push_str(WS_MAGIC_GUID);
    b64_encode(&sha1(buf.as_bytes()))
}

/// RFC 3174 SHA-1. Used only for [`compute_accept`]; not exposed
/// elsewhere. Inlining lets this module avoid a hard crypto-provider
/// dependency for the handshake (entropy seeding still needs one — see
/// [`super::mask`]).
fn sha1(input: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xEFCDAB89;
    let mut h2: u32 = 0x98BADCFE;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xC3D2E1F0;

    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity(input.len() + 64);
    padded.extend_from_slice(input);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut w = [0u32; 80];
    for chunk in padded.chunks_exact(64) {
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32),
                _ => (b ^ c ^ d, 0xCA62C1D6u32),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0u8; 20];
    for (i, h) in [h0, h1, h2, h3, h4].iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&h.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sec_websocket_accept_matches_rfc6455_example() {
        // RFC 6455 §1.3 worked example: client key
        // "dGhlIHNhbXBsZSBub25jZQ==" must yield Accept
        // "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=".
        assert_eq!(
            compute_accept("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn sha1_empty_input_matches_rfc3174_example() {
        // RFC 3174 Appendix A: SHA-1 of the empty string is
        // da39a3ee 5e6b4b0d 3255bfef 95601890 afd80709.
        let d = sha1(b"");
        assert_eq!(
            d,
            [
                0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60,
                0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09,
            ]
        );
    }

    #[test]
    fn b64_encode_round_trips_simple_bytes() {
        // base64ct is already exercised elsewhere; this is a smoke test
        // that the re-export here doesn't drop the trailing padding.
        assert_eq!(b64_encode(b"hello"), "aGVsbG8=");
        assert_eq!(b64_encode(b""), "");
    }
}
