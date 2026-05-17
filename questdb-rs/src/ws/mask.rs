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

/// Error returned by [`build_from_system_random`] when the OS entropy
/// source itself fails. Callers usually surface this as a configuration
/// error — at runtime there's nothing the user can do about it.
#[derive(Debug)]
pub(crate) struct EntropyUnavailable(pub String);

/// Per-connection mask key generator. Constructed once at WS upgrade
/// time and consumed by every outbound frame.
#[derive(Debug)]
pub(crate) struct MaskRng {
    state: u64,
}

impl MaskRng {
    /// Build a generator from a 64-bit seed. Caller is responsible for
    /// drawing the seed from a strong entropy source. See
    /// [`build_from_system_random`] for the production path.
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
/// an error, i.e. something is very wrong.
#[cfg(feature = "ring-crypto")]
pub(crate) fn build_from_system_random() -> Result<MaskRng, EntropyUnavailable> {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut seed_bytes = [0u8; 8];
    SystemRandom::new()
        .fill(&mut seed_bytes)
        .map_err(|e| EntropyUnavailable(format!("system entropy source unavailable: {e:?}")))?;
    Ok(MaskRng::from_seed(u64::from_ne_bytes(seed_bytes)))
}

#[cfg(all(feature = "aws-lc-crypto", not(feature = "ring-crypto")))]
pub(crate) fn build_from_system_random() -> Result<MaskRng, EntropyUnavailable> {
    use aws_lc_rs::rand::{SecureRandom, SystemRandom};
    let mut seed_bytes = [0u8; 8];
    SystemRandom::new()
        .fill(&mut seed_bytes)
        .map_err(|e| EntropyUnavailable(format!("system entropy source unavailable: {e:?}")))?;
    Ok(MaskRng::from_seed(u64::from_ne_bytes(seed_bytes)))
}

/// XOR `buf` against the 4-byte mask key. `start_offset` is the position
/// in the conceptual payload where `buf` starts — used when masking is
/// applied in chunks rather than to the full payload at once. Per RFC
/// 6455 §5.3: `transformed[i] = original[i] XOR mask[(i + start_offset) & 3]`.
///
/// Strategy: absorb `start_offset` into a rotated copy of the mask key
/// so the inner loop only ever sees a phase-0 mask, then dispatch to
/// the widest SIMD path the target supports. The dispatch is:
///
/// - `aarch64`: NEON (always available on AArch64 baseline).
/// - `x86_64` with AVX2 detected at runtime: 32-byte XOR.
/// - `x86_64` baseline (SSE2): 16-byte XOR.
/// - everything else: scalar (auto-vectorised by LLVM in practice,
///   but explicit so the behaviour is the same on uncommon targets).
///
/// The previous hand-rolled `align_to_mut::<u64>` variant had a subtle
/// rotation bug for non-4-aligned head lengths (the body broadcast
/// assumed mask phase 0 regardless of head length) — the up-front
/// rotation here eliminates that class of bug without falling back to
/// per-byte scalar XOR.
#[inline]
pub(crate) fn apply_mask(buf: &mut [u8], mask_key: [u8; 4], start_offset: usize) {
    let phase = start_offset & 3;
    let rotated_mask = [
        mask_key[phase],
        mask_key[(phase + 1) & 3],
        mask_key[(phase + 2) & 3],
        mask_key[(phase + 3) & 3],
    ];
    apply_mask_rotated(buf, rotated_mask);
}

/// Inner loop: `buf` is masked as if it started at mask phase 0. The
/// caller has already absorbed `start_offset` into `mask`.
#[inline]
fn apply_mask_rotated(buf: &mut [u8], mask: [u8; 4]) {
    #[cfg(target_arch = "x86_64")]
    {
        // `is_x86_feature_detected!` reads from a `std`-cached flag, so
        // the runtime check is a single relaxed atomic load on the hot
        // path. AVX2 has been baseline on Haswell (2013) / Zen (2017),
        // so most production hosts pick the AVX2 branch.
        if std::is_x86_feature_detected!("avx2") {
            // SAFETY: gated by runtime AVX2 detection above.
            unsafe { apply_mask_avx2(buf, mask) };
        } else {
            // SSE2 is mandatory on x86_64 — the System V x86_64 ABI
            // requires it, and Rust's x86_64 baseline target enables
            // it. No detection needed.
            // SAFETY: SSE2 is baseline on x86_64.
            unsafe { apply_mask_sse2(buf, mask) };
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        // NEON (Advanced SIMD) is mandatory on ARMv8-A, which is what
        // `aarch64-*-*` targets. No detection needed.
        // SAFETY: NEON is baseline on aarch64.
        unsafe { apply_mask_neon(buf, mask) };
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    apply_mask_scalar(buf, mask);
}

/// Portable scalar fallback. Used directly on targets without SIMD
/// dispatch, and reached for the tail of every SIMD path after the
/// bulk 16/32-byte chunks are done.
#[inline]
fn apply_mask_scalar(buf: &mut [u8], mask: [u8; 4]) {
    for (i, b) in buf.iter_mut().enumerate() {
        *b ^= mask[i & 3];
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn apply_mask_sse2(buf: &mut [u8], mask: [u8; 4]) {
    use std::arch::x86_64::{
        __m128i, _mm_loadu_si128, _mm_set1_epi32, _mm_storeu_si128, _mm_xor_si128,
    };
    // Broadcast the 4-byte mask into all four 32-bit lanes. Stored as a
    // little-endian u32 so the in-memory byte pattern is exactly
    // `[mask[0], mask[1], mask[2], mask[3]]` repeated four times.
    // SAFETY: SSE2 is baseline on x86_64; the function is marked with
    // `#[target_feature(enable = "sse2")]` to be explicit.
    let mask_vec = unsafe { _mm_set1_epi32(i32::from_le_bytes(mask)) };
    let len = buf.len();
    let mut i = 0;
    while i + 16 <= len {
        // SAFETY: `i + 16 <= len` per the loop guard. `_mm_loadu_si128`
        // / `_mm_storeu_si128` are explicitly unaligned, so no
        // alignment requirement on `buf.as_ptr().add(i)`.
        unsafe {
            let p = buf.as_mut_ptr().add(i) as *mut __m128i;
            let v = _mm_loadu_si128(p);
            let x = _mm_xor_si128(v, mask_vec);
            _mm_storeu_si128(p, x);
        }
        i += 16;
    }
    apply_mask_scalar(&mut buf[i..], mask);
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn apply_mask_avx2(buf: &mut [u8], mask: [u8; 4]) {
    use std::arch::x86_64::{
        __m128i, __m256i, _mm_loadu_si128, _mm_set1_epi32, _mm_storeu_si128, _mm_xor_si128,
        _mm256_loadu_si256, _mm256_set1_epi32, _mm256_storeu_si256, _mm256_xor_si256,
    };
    let mask_u32 = i32::from_le_bytes(mask);
    // SAFETY: AVX2 detected at the dispatch site; SSE2 is baseline.
    let mask256 = unsafe { _mm256_set1_epi32(mask_u32) };
    let mask128 = unsafe { _mm_set1_epi32(mask_u32) };

    let len = buf.len();
    let mut i = 0;
    while i + 32 <= len {
        // SAFETY: `i + 32 <= len` per the loop guard. Unaligned
        // load/store; Haswell+ handles unaligned 32-byte access with
        // no perf penalty when the access is naturally aligned to a
        // cache-line boundary, and the worst case (split across two
        // lines) is still faster than the SSE2 fallback for this kind
        // of streaming load.
        unsafe {
            let p = buf.as_mut_ptr().add(i) as *mut __m256i;
            let v = _mm256_loadu_si256(p);
            let x = _mm256_xor_si256(v, mask256);
            _mm256_storeu_si256(p, x);
        }
        i += 32;
    }
    // Pick up any leftover 16-byte chunk with SSE2 before the scalar tail.
    while i + 16 <= len {
        // SAFETY: same loop-guard reasoning as the 32-byte case; SSE2
        // is baseline on x86_64.
        unsafe {
            let p = buf.as_mut_ptr().add(i) as *mut __m128i;
            let v = _mm_loadu_si128(p);
            let x = _mm_xor_si128(v, mask128);
            _mm_storeu_si128(p, x);
        }
        i += 16;
    }
    apply_mask_scalar(&mut buf[i..], mask);
}

#[cfg(target_arch = "aarch64")]
unsafe fn apply_mask_neon(buf: &mut [u8], mask: [u8; 4]) {
    use std::arch::aarch64::{
        uint8x16_t, vdupq_n_u32, veorq_u8, vld1q_u8, vreinterpretq_u8_u32, vst1q_u8,
    };
    // Broadcast the mask into a 16-byte vector. Stored as four u32
    // lanes that get reinterpreted as 16 bytes — same in-memory layout
    // as the SSE2 path.
    // SAFETY: NEON is baseline on aarch64.
    let mask_vec: uint8x16_t =
        unsafe { vreinterpretq_u8_u32(vdupq_n_u32(u32::from_le_bytes(mask))) };
    let len = buf.len();
    let mut i = 0;
    while i + 16 <= len {
        // SAFETY: `i + 16 <= len` per the loop guard. `vld1q_u8` /
        // `vst1q_u8` are 1-byte aligned (no alignment requirement on
        // `buf.as_ptr().add(i)`).
        unsafe {
            let p = buf.as_mut_ptr().add(i);
            let v = vld1q_u8(p);
            let x = veorq_u8(v, mask_vec);
            vst1q_u8(p, x);
        }
        i += 16;
    }
    apply_mask_scalar(&mut buf[i..], mask);
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

    /// Reference implementation: byte-by-byte XOR as written in the
    /// RFC. SIMD outputs are checked against this.
    fn apply_mask_reference(buf: &mut [u8], mask_key: [u8; 4], start_offset: usize) {
        for (i, b) in buf.iter_mut().enumerate() {
            *b ^= mask_key[(i + start_offset) & 3];
        }
    }

    #[test]
    fn apply_mask_simd_matches_scalar_across_lengths() {
        // Walk the length space across the SSE2 16-byte boundary, the
        // AVX2 32-byte boundary, and a couple of full SIMD strides
        // above. Catches any off-by-one in the head / tail split.
        let key = [0xAA, 0xBB, 0xCC, 0xDD];
        for len in 0..=160usize {
            for phase in 0..4 {
                let plaintext: Vec<u8> = (0..len).map(|i| (i * 7 + 11) as u8).collect();

                let mut expected = plaintext.clone();
                apply_mask_reference(&mut expected, key, phase);

                let mut actual = plaintext.clone();
                apply_mask(&mut actual, key, phase);

                assert_eq!(actual, expected, "len={len} phase={phase}");
            }
        }
    }

    #[test]
    fn apply_mask_simd_matches_scalar_at_size_boundaries() {
        // Spot-check the exact byte indices where a different code path
        // takes over: SSE2 wants `len % 16`, AVX2 wants `len % 32`. A
        // bug in the bulk loop usually shows up first at len = 15/16/17,
        // 31/32/33, 47/48/49.
        let key = [0x01, 0x23, 0x45, 0x67];
        for len in [
            0_usize, 1, 3, 4, 7, 8, 15, 16, 17, 31, 32, 33, 47, 48, 49, 63, 64, 65, 95, 96, 97,
            127, 128, 129,
        ] {
            for phase in 0..4 {
                let plaintext: Vec<u8> = (0..len).map(|i| i as u8).collect();
                let mut expected = plaintext.clone();
                apply_mask_reference(&mut expected, key, phase);
                let mut actual = plaintext.clone();
                apply_mask(&mut actual, key, phase);
                assert_eq!(actual, expected, "len={len} phase={phase}");
            }
        }
    }

    #[test]
    fn apply_mask_simd_matches_scalar_for_large_payload() {
        // Exercises the SIMD bulk path well past the SSE2 16-byte and
        // AVX2 32-byte strides. Length is deliberately not a multiple
        // of either so the tail handler is also covered.
        let key = [0xDE, 0xAD, 0xBE, 0xEF];
        let len = (1 << 20) + 37; // 1 MiB + 37 bytes
        let plaintext: Vec<u8> = (0..len).map(|i| ((i * 13) ^ 0x5A) as u8).collect();
        let mut expected = plaintext.clone();
        apply_mask_reference(&mut expected, key, 0);
        let mut actual = plaintext.clone();
        apply_mask(&mut actual, key, 0);
        assert_eq!(actual.len(), expected.len());
        assert_eq!(&actual[..256], &expected[..256], "head mismatch");
        assert_eq!(
            &actual[len - 256..],
            &expected[len - 256..],
            "tail mismatch"
        );
        assert!(actual == expected, "bulk mismatch in 1 MiB payload");
    }

    /// Reference scalar implementation routed through the
    /// post-rotation `apply_mask_scalar` so the comparison isolates
    /// "SIMD bulk vs scalar bulk", not "scalar with phase rotation vs
    /// no phase rotation".
    fn apply_mask_dispatched_scalar(buf: &mut [u8], mask_key: [u8; 4], start_offset: usize) {
        let phase = start_offset & 3;
        let rotated = [
            mask_key[phase],
            mask_key[(phase + 1) & 3],
            mask_key[(phase + 2) & 3],
            mask_key[(phase + 3) & 3],
        ];
        apply_mask_scalar(buf, rotated);
    }

    /// Opt-in micro-bench, ignored by default so it doesn't drag the
    /// normal test run. Run with:
    ///
    /// ```text
    /// cargo test --release --features almost-all-features \
    ///     apply_mask_bench -- --ignored --nocapture
    /// ```
    ///
    /// Compares the dispatched (SIMD-enabled) `apply_mask` against the
    /// scalar fallback over several realistic payload sizes. Prints
    /// ns/byte and a relative speed-up so the perf claim in the
    /// commit message is replayable.
    #[test]
    #[ignore]
    fn apply_mask_bench() {
        use std::time::Instant;

        let key = [0x10, 0x20, 0x30, 0x40];
        let sizes_kib = [1, 4, 16, 64, 256, 1024];
        let iterations = 100;

        println!("\napply_mask bench (single-threaded, {iterations} iterations per size)");
        println!(
            "  {:>10} {:>14} {:>14} {:>10}",
            "size", "scalar GB/s", "simd GB/s", "speedup"
        );
        for &kib in &sizes_kib {
            let len = kib * 1024;
            let plaintext: Vec<u8> = (0..len).map(|i| (i ^ 0x5A) as u8).collect();

            let mut buf = plaintext.clone();
            let start = Instant::now();
            for _ in 0..iterations {
                apply_mask_dispatched_scalar(&mut buf, key, 0);
            }
            let scalar_elapsed = start.elapsed();

            let mut buf = plaintext.clone();
            let start = Instant::now();
            for _ in 0..iterations {
                apply_mask(&mut buf, key, 0);
            }
            let simd_elapsed = start.elapsed();

            let total_bytes = (len * iterations) as f64;
            let scalar_gbps = total_bytes / scalar_elapsed.as_secs_f64() / 1e9;
            let simd_gbps = total_bytes / simd_elapsed.as_secs_f64() / 1e9;
            let speedup = scalar_elapsed.as_secs_f64() / simd_elapsed.as_secs_f64();
            println!(
                "  {:>8} K {:>14.2} {:>14.2} {:>9.2}x",
                kib, scalar_gbps, simd_gbps, speedup
            );
        }
    }

    #[test]
    fn apply_mask_simd_matches_scalar_under_chunked_calls() {
        // Same scenario as `apply_mask_chunks_match_full` but exercised
        // across enough call shapes to hit the SIMD bulk path inside
        // each chunk too. Chunk sizes 1..=33 cover sub-SIMD, exact
        // SSE2, exact AVX2, and just-past-AVX2.
        let key = [0x10, 0x20, 0x30, 0x40];
        let plaintext: Vec<u8> = (0..2048u32).map(|i| (i ^ 0x37) as u8).collect();
        let mut full = plaintext.clone();
        apply_mask(&mut full, key, 0);

        for chunk_size in [1usize, 3, 7, 13, 16, 17, 31, 32, 33] {
            let mut chunked = plaintext.clone();
            let mut off = 0;
            for c in chunked.chunks_mut(chunk_size) {
                apply_mask(c, key, off);
                off += c.len();
            }
            assert_eq!(full, chunked, "chunk_size={chunk_size}");
        }
    }
}
