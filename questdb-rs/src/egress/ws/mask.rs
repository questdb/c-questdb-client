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

//! WebSocket masking helpers.
//!
//! RFC 6455 §10.3: "The masking key needs to be unpredictable; thus, the
//! masking key MUST be derived from a strong source of entropy, and the
//! masking key for a given frame MUST NOT make it simple for a
//! server/proxy to predict the masking key for a subsequent frame. The
//! unpredictability of the masking key is essential to prevent authors
//! of malicious applications from selecting the bytes that appear on
//! the wire."
//!
//! We seed a per-connection xorshift64 PRNG from the crypto provider's
//! `SystemRandom` (the same one rustls uses for TLS). The seed is the
//! "strong source of entropy"; xorshift gives us a cheap stream of
//! per-frame keys after that. Mask keys are not used for confidentiality
//! — they exist to defeat cache-poisoning attacks against intermediary
//! proxies that misparse WS bytes — so per-frame syscalls are not
//! required. Tungstenite uses the same shape (seed once, generate fast).

/// Per-connection mask key generator. Constructed once at WS upgrade
/// time and consumed by every outbound frame.
#[derive(Debug)]
pub(crate) struct MaskRng {
    state: u64,
}

impl MaskRng {
    /// Build a generator from a 64-bit seed. Caller is responsible for
    /// drawing the seed from a strong entropy source. See
    /// [`Self::from_system_random`] for the production path.
    pub(crate) fn from_seed(seed: u64) -> Self {
        // xorshift64 stalls on all-zero state; force a non-zero seed.
        let state = if seed == 0 {
            0xDEAD_BEEF_CAFE_BABE
        } else {
            seed
        };
        Self { state }
    }

    /// Draw a 32-bit key for the next frame. Cheap, branch-free.
    pub(crate) fn next_key(&mut self) -> [u8; 4] {
        // xorshift64 (Marsaglia) — passes BigCrush, no syscalls, ~3 ns.
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        // Take the high 32 bits — historically better statistical
        // properties than the low 32 on xorshift64.
        ((x >> 32) as u32).to_le_bytes()
    }
}

/// Build a `MaskRng` whose seed is drawn from the crate's active
/// crypto provider's `SystemRandom`. Both backends expose a
/// `SecureRandom::fill(&mut [u8])` API; we ask for 8 bytes once and
/// reinterpret as `u64`.
///
/// Fails only if the underlying entropy source itself fails — which on
/// the supported targets means `getrandom`/`BCryptGenRandom` returned
/// an error, i.e. something is very wrong. We surface this as
/// `ConfigError` since there's nothing the user can fix at runtime.
#[cfg(feature = "ring-crypto")]
pub(crate) fn build_from_system_random() -> crate::egress::error::Result<MaskRng> {
    use crate::egress::error::fmt;
    use ring::rand::{SecureRandom, SystemRandom};
    let mut seed_bytes = [0u8; 8];
    SystemRandom::new()
        .fill(&mut seed_bytes)
        .map_err(|e| fmt!(ConfigError, "system entropy source unavailable: {:?}", e))?;
    Ok(MaskRng::from_seed(u64::from_ne_bytes(seed_bytes)))
}

#[cfg(all(feature = "aws-lc-crypto", not(feature = "ring-crypto")))]
pub(crate) fn build_from_system_random() -> crate::egress::error::Result<MaskRng> {
    use crate::egress::error::fmt;
    use aws_lc_rs::rand::{SecureRandom, SystemRandom};
    let mut seed_bytes = [0u8; 8];
    SystemRandom::new()
        .fill(&mut seed_bytes)
        .map_err(|e| fmt!(ConfigError, "system entropy source unavailable: {:?}", e))?;
    Ok(MaskRng::from_seed(u64::from_ne_bytes(seed_bytes)))
}

// If neither crypto provider feature is on, `sync-reader-ws` cannot
// build anyway — `tls.rs` requires one of them for rustls. The
// `cfg_attr` here ensures a clear compile error rather than a silent
// fallback.
#[cfg(not(any(feature = "ring-crypto", feature = "aws-lc-crypto")))]
compile_error!(
    "`sync-reader-ws` requires one of `ring-crypto` or `aws-lc-crypto` for TLS \
     and WebSocket mask-key entropy"
);

/// XOR `buf` against the 4-byte mask key. `start_offset` is the position
/// in the conceptual payload where `buf` starts — used when masking is
/// applied in chunks rather than to the full payload at once. Per RFC
/// 6455 §5.3: `transformed[i] = original[i] XOR mask[i & 3]`.
///
/// Implementation: scalar XOR. The compiler reliably auto-vectorises
/// this on x86_64 / aarch64 to 16- or 32-byte XOR over SIMD registers.
/// A previous hand-rolled `align_to_mut::<u64>` variant had a subtle
/// rotation bug for non-4-aligned head lengths (the body broadcast
/// assumed mask phase 0 regardless of head length) — keeping the
/// inner loop simple eliminates that class of bug.
#[inline]
pub(crate) fn apply_mask(buf: &mut [u8], mask_key: [u8; 4], start_offset: usize) {
    for (i, b) in buf.iter_mut().enumerate() {
        *b ^= mask_key[(i + start_offset) & 3];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xorshift_is_deterministic_for_same_seed() {
        let mut a = MaskRng::from_seed(42);
        let mut b = MaskRng::from_seed(42);
        for _ in 0..1000 {
            assert_eq!(a.next_key(), b.next_key());
        }
    }

    #[test]
    fn xorshift_avoids_zero_seed_lockup() {
        let mut rng = MaskRng::from_seed(0);
        // First few keys must not all be the same — confirms we
        // overrode the zero seed.
        let k0 = rng.next_key();
        let k1 = rng.next_key();
        let k2 = rng.next_key();
        assert!(k0 != k1 || k1 != k2);
    }

    #[test]
    fn xorshift_does_not_repeat_quickly() {
        // 10k consecutive keys should not contain a duplicate at typical
        // mask-key cadence. Not a proof of uniformity — just a smoke
        // check that we're not silently stuck.
        let mut rng = MaskRng::from_seed(0xDEAD_BEEF);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..10_000 {
            let k = rng.next_key();
            assert!(seen.insert(k), "duplicate mask key {k:?}");
        }
    }

    #[test]
    fn apply_mask_round_trips() {
        let key = [0x11, 0x22, 0x33, 0x44];
        let plaintext = b"the quick brown fox jumps over the lazy dog";
        let mut buf = plaintext.to_vec();
        apply_mask(&mut buf, key, 0);
        assert_ne!(buf, plaintext); // got masked
        apply_mask(&mut buf, key, 0); // XOR is its own inverse
        assert_eq!(buf, plaintext);
    }

    #[test]
    fn apply_mask_chunks_match_full() {
        let key = [0xAA, 0xBB, 0xCC, 0xDD];
        let plaintext: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();

        // Full mask in one shot.
        let mut full = plaintext.clone();
        apply_mask(&mut full, key, 0);

        // Mask in 7-byte chunks (deliberately non-4-aligned so phase
        // matters). Concatenate and confirm parity.
        let mut chunked = plaintext.clone();
        let mut off = 0;
        for c in chunked.chunks_mut(7) {
            apply_mask(c, key, off);
            off += c.len();
        }
        assert_eq!(full, chunked);
    }

    #[test]
    fn apply_mask_handles_short_buffers() {
        // Buffers shorter than 8 bytes hit the scalar fallback path.
        for len in 0..16 {
            let key = [0x5A; 4];
            let mut buf = vec![0u8; len];
            apply_mask(&mut buf, key, 0);
            for (i, b) in buf.iter().enumerate() {
                assert_eq!(*b, key[i & 3], "len={len} i={i}");
            }
        }
    }
}
