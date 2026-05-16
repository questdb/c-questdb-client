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

//! Minimal WebSocket client for QWP egress.
//!
//! Replaces the previous `tungstenite` dependency with a hand-rolled
//! RFC 6455 client tuned for streaming binary frames. The general-purpose
//! library defaults (128 KiB recv buffer, eager `BytesMut::resize` with
//! zero-fill before every syscall, full opcode-dispatch state machine)
//! are not what high-throughput QWP wants — see the perf investigation
//! in PR 140 for the measurement that motivated the rewrite.
//!
//! Surface (all `pub(crate)`):
//! - [`handshake::upgrade`]: HTTP/1.1 Upgrade client. Connects on a
//!   caller-provided TCP/TLS stream, sends the request with our
//!   X-QWP-* headers, validates the 101 response (status, Upgrade,
//!   Connection, Sec-WebSocket-Accept), surfaces 4xx as
//!   `UpgradeReject`.
//! - [`frame::FrameHeader`] / [`frame::Opcode`]: RFC 6455 frame header
//!   parser and outbound-frame writer with masking.
//! - [`client::WsClient`]: owns the stream plus a recv buffer, hides
//!   control-frame dispatch from callers, exposes
//!   `read_binary_frame()` / `write_binary_frame()`.
//!
//! Out of scope (by design):
//! - Async runtime support — the crate's reader is sync.
//! - Fragmentation: QWP frames are always FIN=1 in both directions.
//! - WS extensions (permessage-deflate): we have zstd at the protocol
//!   layer.
//! - Text frames: QWP is binary-only.

pub(crate) mod client;
pub(crate) mod frame;
pub(crate) mod handshake;
pub(crate) mod mask;
