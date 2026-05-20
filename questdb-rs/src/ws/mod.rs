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

//! Shared RFC 6455 WebSocket plumbing used by both the QWP ingress sender
//! and the QWP egress reader.
//!
//! Each transport built its own hand-rolled WebSocket layer when it
//! dropped the `tungstenite` dependency, so the Sec-WebSocket-Accept
//! dance, the frame header bit layout, the masking transform, and the
//! HTTP/1.1 Upgrade request/response parser were each written twice.
//! This module owns the genuinely-shared primitives so neither side has
//! to drift on its own.
//!
//! Surface (all `pub(crate)`):
//! - [`crypto`]: `compute_accept`, `WS_MAGIC_GUID`, `b64_encode`, and a
//!   hand-rolled SHA-1. The SHA-1 use here is the Sec-WebSocket-Accept
//!   handshake authenticity marker per RFC §4.2.2 — not a security
//!   primitive — so an inline RFC 3174 implementation is fine and avoids
//!   pulling in `ring` / `aws-lc-rs` on every code path that touches WS.
//! - [`frame`]: `Opcode`, `FrameHeader::parse`, `encode_client_frame`,
//!   `FrameError`, and the RFC 6455 frame-header bit constants.
//! - [`mask`]: `apply_mask` (in-place XOR with phase tracking) plus
//!   `MaskKeySource`, a per-connection wrapper around the crypto
//!   provider's `SystemRandom` that draws a fresh 4-byte mask key on
//!   every outbound frame. RFC 6455 §10.3 forbids per-frame mask-key
//!   predictability; we satisfy that by sampling directly from the OS
//!   CSPRNG per frame rather than via a seeded user-space PRNG.
//! - [`handshake`]: `upgrade`, `Headers`, `Handshake`, `HandshakeError`,
//!   `HttpReject`. The HTTP/1.1 GET + 101 dance, including slow-loris
//!   defence on the response prefix read.
//!
//! Out of scope:
//! - Async runtime support — both transports are sync today.
//! - Fragmentation: QWP frames are always FIN=1 in both directions.
//! - WS extensions (permessage-deflate): QWP runs zstd at the protocol
//!   layer instead.
//! - Text frames: QWP is binary-only.
//! - Per-transport state machines (post-handshake frame dispatch policy
//!   for control frames, recv buffer sizing, response codecs) — those
//!   live in `egress/ws/client.rs` and `ingress/sender/qwp_ws_codec.rs`
//!   respectively because they encode each transport's specific
//!   behaviour.

// Both crypto provider feature gates are checked here once, at the
// shared module level, so neither ingress nor egress has to repeat the
// check at their own callsite. `MaskKeySource::new` and `.fill` are
// the only APIs in this module that need the crypto provider; everything
// else (SHA-1, frame parser, HTTP parser) is implemented inline and
// works under any feature combination.
#[cfg(not(any(feature = "ring-crypto", feature = "aws-lc-crypto")))]
compile_error!(
    "questdb::ws requires one of `ring-crypto` or `aws-lc-crypto` for \
     the WebSocket mask-key entropy source (also needed by rustls for TLS)"
);

pub(crate) mod crypto;
pub(crate) mod frame;
pub(crate) mod handshake;
pub(crate) mod mask;
