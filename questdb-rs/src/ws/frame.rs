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

//! RFC 6455 frame header parser + outbound-frame writer.
//!
//! Parser covers the four opcodes QWP actually uses (Binary, Close,
//! Ping, Pong); Text, continuation, and reserved opcodes are protocol
//! errors. Reserved bits (rsv1/2/3) must all be zero — we negotiated no
//! extensions at upgrade time.
//!
//! Writer always sets FIN=1 and MASK=1 (client→server frames MUST be
//! masked per RFC 6455 §5.3). Mask key generation is the caller's job
//! (see [`crate::ws::mask::MaskRng`]).

// Egress is the only side that parses incoming frames; the ingress
// QWP/WS sender uses just the writer. Suppress the avalanche of
// dead-code warnings on the writer-only builds (`questdb-rs-ffi`
// without `sync-reader-qwp-ws`, for example) — the items are still
// load-bearing for tests in this module.
#![cfg_attr(not(feature = "_egress"), allow(dead_code))]

use super::mask::apply_mask;

/// Opcodes used by QWP. The byte values are fixed by RFC 6455 §5.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Opcode {
    Binary = 0x2,
    Close = 0x8,
    Ping = 0x9,
    Pong = 0xA,
}

impl Opcode {
    fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Parsed RFC 6455 frame header. `payload_len` is the unmasked payload
/// length in bytes (mask bit MUST be 0 in server→client frames per
/// §5.1, which is why we don't surface a mask key here). `header_len`
/// is the on-wire byte count for the header itself (2, 4, or 10) so the
/// caller knows where the payload begins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FrameHeader {
    pub fin: bool,
    pub opcode: Opcode,
    pub payload_len: u64,
    pub header_len: usize,
}

/// Errors from parsing a server→client frame header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FrameError {
    /// Need more bytes to make a decision. Caller should read more from
    /// the stream and retry.
    Incomplete,
    /// Wire-format violation. The associated string is the reason; suitable
    /// for surfacing as a `ProtocolError` to the user.
    Protocol(&'static str),
}

const FIN_BIT: u8 = 0x80;
const RSV_BITS: u8 = 0x70;
const OPCODE_MASK: u8 = 0x0F;
const MASK_BIT: u8 = 0x80;
const LEN_MASK: u8 = 0x7F;

// Opcode byte values per RFC 6455 §5.2. Exposed as `pub(crate)` so
// callers comparing raw header bytes (e.g. the ingress driver's
// inbound-frame dispatch) can use the same constants the parser does
// rather than redeclaring them.
pub(crate) const OPCODE_CONTINUATION: u8 = 0x0;
pub(crate) const OPCODE_TEXT: u8 = 0x1;
pub(crate) const OPCODE_BINARY: u8 = 0x2;
pub(crate) const OPCODE_CLOSE: u8 = 0x8;
pub(crate) const OPCODE_PING: u8 = 0x9;
pub(crate) const OPCODE_PONG: u8 = 0xA;

// Header-size constants documented for readers but not currently
// referenced outside tests — the inline `[0u8; 14]` upper bound in
// `encode_client_frame` is the single load-bearing site. Kept here as
// comments so a future refactor (e.g. stack-allocated header writer)
// has the spec values ready.
//
//   Server→client header max: 1 (flags) + 1 (len) + 8 (ext len) = 10 bytes
//   Client→server header max: 10 + 4 (mask key) = 14 bytes

impl FrameHeader {
    /// Parse a server-to-client frame header from `bytes`. Returns
    /// `Err(Incomplete)` if more bytes are needed; otherwise advances
    /// internal cursors via the returned `header_len`.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, FrameError> {
        if bytes.len() < 2 {
            return Err(FrameError::Incomplete);
        }
        let b0 = bytes[0];
        let b1 = bytes[1];

        // Reserved bits must be 0 unless extensions were negotiated. We
        // don't negotiate any.
        if b0 & RSV_BITS != 0 {
            return Err(FrameError::Protocol("WS frame has reserved bits set"));
        }

        let fin = b0 & FIN_BIT != 0;
        let opcode = match b0 & OPCODE_MASK {
            OPCODE_BINARY => Opcode::Binary,
            OPCODE_CLOSE => Opcode::Close,
            OPCODE_PING => Opcode::Ping,
            OPCODE_PONG => Opcode::Pong,
            OPCODE_CONTINUATION => {
                return Err(FrameError::Protocol(
                    "WS continuation frame from server (QWP never fragments)",
                ));
            }
            OPCODE_TEXT => {
                return Err(FrameError::Protocol("WS text frame (QWP is binary-only)"));
            }
            _ => {
                return Err(FrameError::Protocol("WS frame has reserved opcode"));
            }
        };

        // Per RFC 6455 §5.5, control frames (Close/Ping/Pong) MUST be FIN=1
        // and have payloads ≤ 125 bytes. We enforce both upfront.
        let is_control = matches!(opcode, Opcode::Close | Opcode::Ping | Opcode::Pong);
        if is_control && !fin {
            return Err(FrameError::Protocol("fragmented control frame"));
        }

        // Server-to-client frames MUST NOT be masked (§5.1). A client that
        // sees a masked server frame is required to fail the connection.
        if b1 & MASK_BIT != 0 {
            return Err(FrameError::Protocol("masked frame from server"));
        }

        let len_field = b1 & LEN_MASK;
        let (payload_len, header_len) = match len_field {
            0..=125 => (len_field as u64, 2),
            126 => {
                if bytes.len() < 4 {
                    return Err(FrameError::Incomplete);
                }
                let l = u16::from_be_bytes([bytes[2], bytes[3]]) as u64;
                // §5.2: 16-bit length is REQUIRED to be ≥ 126. Lower
                // values are wire-format violations; smaller payloads
                // belong in the 7-bit form.
                if l < 126 {
                    return Err(FrameError::Protocol(
                        "16-bit WS length < 126 (must use 7-bit form)",
                    ));
                }
                (l, 4)
            }
            127 => {
                if bytes.len() < 10 {
                    return Err(FrameError::Incomplete);
                }
                let l = u64::from_be_bytes([
                    bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9],
                ]);
                // §5.2: 64-bit length MUST have the high bit clear.
                if l >> 63 != 0 {
                    return Err(FrameError::Protocol("64-bit WS length has high bit set"));
                }
                // §5.2: 64-bit length is REQUIRED to be > 0xFFFF.
                if l <= 0xFFFF {
                    return Err(FrameError::Protocol(
                        "64-bit WS length ≤ 0xFFFF (must use 16-bit form)",
                    ));
                }
                (l, 10)
            }
            _ => unreachable!("len_field is 7 bits"),
        };

        if is_control && payload_len > 125 {
            return Err(FrameError::Protocol("control frame payload > 125 bytes"));
        }

        Ok(FrameHeader {
            fin,
            opcode,
            payload_len,
            header_len,
        })
    }
}

/// Serialise a complete client-to-server frame into `out`, masking the
/// payload in place. Always sets FIN=1 and the MASK bit. The caller
/// provides the 4-byte mask key (see [`crate::ws::mask`]).
///
/// `out` is grown by `header_len + payload.len()` bytes. The returned
/// slice covers exactly those new bytes — useful for tests; production
/// callers usually just call `stream.write_all(&out)`.
pub(crate) fn encode_client_frame<'a>(
    out: &'a mut Vec<u8>,
    opcode: Opcode,
    mask_key: [u8; 4],
    payload: &[u8],
) -> &'a [u8] {
    let start = out.len();

    // Byte 0: FIN=1, RSV=0, opcode.
    out.push(FIN_BIT | opcode.as_u8());

    let len = payload.len();
    // Byte 1: MASK=1, length field.
    if len <= 125 {
        out.push(MASK_BIT | (len as u8));
    } else if len <= 0xFFFF {
        out.push(MASK_BIT | 126);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(MASK_BIT | 127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }

    // Mask key (4 bytes).
    out.extend_from_slice(&mask_key);

    // Payload (XORed with the mask key in place).
    let payload_start = out.len();
    out.extend_from_slice(payload);
    apply_mask(&mut out[payload_start..], mask_key, 0);

    &out[start..]
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------------
    // Parser
    // ---------------------------------------------------------------------

    #[test]
    fn parse_binary_short() {
        // FIN=1, opcode=Binary, mask=0, len=5.
        let bytes = [0x82, 0x05, 0, 0, 0, 0, 0];
        let h = FrameHeader::parse(&bytes).unwrap();
        assert!(h.fin);
        assert_eq!(h.opcode, Opcode::Binary);
        assert_eq!(h.payload_len, 5);
        assert_eq!(h.header_len, 2);
    }

    #[test]
    fn parse_binary_16bit_length() {
        // len = 1000, encoded as 0x03E8 big-endian.
        let bytes = [0x82, 126, 0x03, 0xE8];
        let h = FrameHeader::parse(&bytes).unwrap();
        assert_eq!(h.payload_len, 1000);
        assert_eq!(h.header_len, 4);
    }

    #[test]
    fn parse_binary_64bit_length() {
        // len = 0x10_0000 (≈1 MiB).
        let bytes = [0x82, 127, 0, 0, 0, 0, 0, 0x10, 0, 0];
        let h = FrameHeader::parse(&bytes).unwrap();
        assert_eq!(h.payload_len, 0x10_0000);
        assert_eq!(h.header_len, 10);
    }

    #[test]
    fn parse_incomplete_returns_incomplete() {
        assert_eq!(
            FrameHeader::parse(&[0x82]).unwrap_err(),
            FrameError::Incomplete
        );
        assert_eq!(
            FrameHeader::parse(&[0x82, 126, 0]).unwrap_err(),
            FrameError::Incomplete
        );
        assert_eq!(
            FrameHeader::parse(&[0x82, 127, 0, 0, 0, 0]).unwrap_err(),
            FrameError::Incomplete
        );
    }

    #[test]
    fn parse_rejects_reserved_bits() {
        // RSV1 set.
        let bytes = [0xC2, 0x05];
        assert!(matches!(
            FrameHeader::parse(&bytes),
            Err(FrameError::Protocol(_))
        ));
    }

    #[test]
    fn parse_rejects_mask_from_server() {
        // FIN=1, Binary, MASK=1.
        let bytes = [0x82, 0x80 | 0x05, 0, 0, 0, 0, 1, 2, 3, 4];
        assert!(matches!(
            FrameHeader::parse(&bytes),
            Err(FrameError::Protocol(_))
        ));
    }

    #[test]
    fn parse_rejects_text() {
        let bytes = [0x81, 0x05];
        assert!(matches!(
            FrameHeader::parse(&bytes),
            Err(FrameError::Protocol(_))
        ));
    }

    #[test]
    fn parse_rejects_continuation() {
        let bytes = [0x80, 0x05];
        assert!(matches!(
            FrameHeader::parse(&bytes),
            Err(FrameError::Protocol(_))
        ));
    }

    #[test]
    fn parse_rejects_reserved_opcode() {
        // Opcode 0xB is reserved.
        let bytes = [0x8B, 0x05];
        assert!(matches!(
            FrameHeader::parse(&bytes),
            Err(FrameError::Protocol(_))
        ));
    }

    #[test]
    fn parse_rejects_non_minimal_16bit_length() {
        // len_field=126 with actual length 100 (< 126).
        let bytes = [0x82, 126, 0, 100];
        assert!(matches!(
            FrameHeader::parse(&bytes),
            Err(FrameError::Protocol(_))
        ));
    }

    #[test]
    fn parse_rejects_non_minimal_64bit_length() {
        // len_field=127 with actual length 1000 (≤ 0xFFFF).
        let bytes = [0x82, 127, 0, 0, 0, 0, 0, 0, 0x03, 0xE8];
        assert!(matches!(
            FrameHeader::parse(&bytes),
            Err(FrameError::Protocol(_))
        ));
    }

    #[test]
    fn parse_rejects_64bit_high_bit() {
        // 64-bit length with the high bit set is a wire violation.
        let bytes = [0x82, 127, 0x80, 0, 0, 0, 0, 0, 0, 0];
        assert!(matches!(
            FrameHeader::parse(&bytes),
            Err(FrameError::Protocol(_))
        ));
    }

    #[test]
    fn parse_rejects_fragmented_control() {
        // FIN=0, opcode=Ping.
        let bytes = [0x09, 0x00];
        assert!(matches!(
            FrameHeader::parse(&bytes),
            Err(FrameError::Protocol(_))
        ));
    }

    #[test]
    fn parse_rejects_oversized_control() {
        // FIN=1, opcode=Ping, len=200 — control frames are ≤ 125.
        let bytes = [0x89, 126, 0, 200];
        assert!(matches!(
            FrameHeader::parse(&bytes),
            Err(FrameError::Protocol(_))
        ));
    }

    #[test]
    fn parse_close_and_ping() {
        let close = FrameHeader::parse(&[0x88, 0x02, 0x03, 0xE8]).unwrap();
        assert_eq!(close.opcode, Opcode::Close);
        let ping = FrameHeader::parse(&[0x89, 0x00]).unwrap();
        assert_eq!(ping.opcode, Opcode::Ping);
        let pong = FrameHeader::parse(&[0x8A, 0x00]).unwrap();
        assert_eq!(pong.opcode, Opcode::Pong);
    }

    // ---------------------------------------------------------------------
    // Writer
    // ---------------------------------------------------------------------

    #[test]
    fn encode_small_binary_frame() {
        let mut out = Vec::new();
        let payload = b"hello";
        let mask = [0x11, 0x22, 0x33, 0x44];
        let frame = encode_client_frame(&mut out, Opcode::Binary, mask, payload);

        // Byte 0: FIN=1, Binary -> 0x82.
        assert_eq!(frame[0], 0x82);
        // Byte 1: MASK=1, len=5 -> 0x85.
        assert_eq!(frame[1], 0x85);
        // Mask key.
        assert_eq!(&frame[2..6], &mask);
        // Masked payload — XOR back to recover the plaintext.
        let mut payload_check = frame[6..].to_vec();
        apply_mask(&mut payload_check, mask, 0);
        assert_eq!(payload_check, payload);
    }

    #[test]
    fn encode_medium_frame_uses_16bit_length() {
        let mut out = Vec::new();
        let payload = vec![0xAB; 1000];
        let mask = [0, 0, 0, 0]; // zero key keeps the payload unchanged
        let frame = encode_client_frame(&mut out, Opcode::Binary, mask, &payload);

        assert_eq!(frame[0], 0x82);
        assert_eq!(frame[1], 0x80 | 126);
        assert_eq!(u16::from_be_bytes([frame[2], frame[3]]), 1000);
        assert_eq!(&frame[8..], &payload[..]);
    }

    #[test]
    fn encode_large_frame_uses_64bit_length() {
        let mut out = Vec::new();
        let payload = vec![0u8; 0x1_0000]; // exactly 64 KiB
        let mask = [0, 0, 0, 0];
        let frame = encode_client_frame(&mut out, Opcode::Binary, mask, &payload);

        assert_eq!(frame[0], 0x82);
        assert_eq!(frame[1], 0x80 | 127);
        assert_eq!(
            u64::from_be_bytes([
                frame[2], frame[3], frame[4], frame[5], frame[6], frame[7], frame[8], frame[9]
            ]),
            0x1_0000
        );
    }

    #[test]
    fn encode_close_frame_zero_payload() {
        let mut out = Vec::new();
        let frame = encode_client_frame(&mut out, Opcode::Close, [1, 2, 3, 4], b"");
        // FIN=1, Close=0x8 -> 0x88. MASK=1, len=0 -> 0x80.
        assert_eq!(frame[0], 0x88);
        assert_eq!(frame[1], 0x80);
        // Mask key still present even for zero-length payloads (§5.3).
        assert_eq!(frame.len(), 6);
        assert_eq!(&frame[2..6], &[1, 2, 3, 4]);
    }

    #[test]
    fn round_trip_parser_against_writer() {
        // Encode then strip mask manually, then parse. Confirms the
        // writer's header bytes are interpretable by the parser modulo
        // the mask-from-client check (parser is server-only; we strip
        // the mask bit before handing the bytes back).
        let payload = vec![0u8; 200_000];
        let mut out = Vec::new();
        let mask = [0xAA, 0xBB, 0xCC, 0xDD];
        encode_client_frame(&mut out, Opcode::Binary, mask, &payload);

        // Strip the MASK bit so the server-only parser accepts the
        // bytes. Real servers do this check; we mimic it here.
        let mut server_view = out.clone();
        server_view[1] &= !MASK_BIT;
        // Also remove the 4 mask bytes — server frame layout has no
        // mask key. They live between the extended-length field and
        // the payload (here: bytes 10..14 for 64-bit length).
        server_view.drain(10..14);

        let header = FrameHeader::parse(&server_view).unwrap();
        assert_eq!(header.opcode, Opcode::Binary);
        assert_eq!(header.payload_len as usize, payload.len());
    }
}
