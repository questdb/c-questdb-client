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

//! Java/Rust golden payload parity for QWP/WebSocket replay-mode bytes.
//!
//! These constants are unmasked QWP application payloads in the inline-schema
//! wire format (no schema-mode byte, no schema id), captured from the Java
//! client's inline-schema replay encoder. The Rust replay encoder must
//! reproduce them byte-for-byte, so the assertions below prove cross-client
//! wire parity rather than asserting a hand-derived expectation.

use crate::ingress::{Buffer, QwpWsEncodeScratch, SymbolGlobalDict, TimestampNanos};

const SYMBOL_COUNT: usize = 10;
const BASE_TS_NANOS: i64 = 1_700_000_000_000_000_000;

const JAVA_FIRST_REPLAY_HEX: &str = "\
515750310108010069010000000a0753594d5f3030300753594d5f3030310753594d5f3030320753594d5f\
3030330753594d5f3030340753594d5f3030350753594d5f3030360753594d5f3030370753594d5f303038\
0753594d5f303039067472616465730a040373796d0903717479050270780700100000010203040506\
07080900000000000000000001000000000000000200000000000000030000000000000004000000000000\
00050000000000000006000000000000000700000000000000080000000000000009000000000000000000\
00000000005940000000000040594000000000008059400000000000c059400000000000005a4000000000\
00405a400000000000805a400000000000c05a400000000000005b400000000000405b400000002a36fe9c\
971701002a36fe9c971702002a36fe9c971703002a36fe9c971704002a36fe9c971705002a36fe9c971706\
002a36fe9c971707002a36fe9c971708002a36fe9c971709002a36fe9c9717";

const JAVA_SECOND_REPLAY_HEX: &str = "\
515750310108010088000000000a0753594d5f3030300753594d5f3030310753594d5f3030320753594d5f\
3030330753594d5f3030340753594d5f3030350753594d5f3030360753594d5f3030370753594d5f303038\
0753594d5f3030390674726164657301040373796d0903717479050270780700100009006300000000\
0000000000000000003c8f4000e8032a36fe9c9717";

#[test]
fn qwp_ws_replay_payloads_match_java_golden_bytes() {
    let (first, second) = rust_replay_payloads();

    assert_eq!(first, hex_to_bytes(JAVA_FIRST_REPLAY_HEX));
    assert_eq!(second, hex_to_bytes(JAVA_SECOND_REPLAY_HEX));
}

/// The column-major (chunk) encoder must produce the SAME 12-byte QWP header and
/// delta symbol-dict section as the row encoder — which is locked to the Java
/// golden above. `wire.rs` documents this byte-compatibility, and the persisted
/// side-file / reconnect catch-up splice these exact delta bytes verbatim, so a
/// framing drift between the column and row encoders would be an invisible wire
/// bug the row-only golden could never catch. Encode the same 10-symbol
/// dictionary column-major and assert its header + delta section equal the Java
/// golden's.
#[test]
fn column_encoder_delta_dict_section_matches_the_java_golden() {
    use crate::ingress::column_sender::Chunk;
    use crate::ingress::column_sender::encoder::{EncodeScratch, encode_chunk_into};

    // Build the 10-symbol dictionary column-major: one distinct symbol per row,
    // so slots 0..10 are all referenced and interned in id order (SYM_000..009),
    // matching the row encoder's reference order in the golden.
    let mut dict_bytes = Vec::new();
    let mut dict_offsets = vec![0i32];
    for idx in 0..SYMBOL_COUNT {
        dict_bytes.extend_from_slice(format!("SYM_{idx:03}").as_bytes());
        dict_offsets.push(dict_bytes.len() as i32);
    }
    let codes: Vec<i32> = (0..SYMBOL_COUNT as i32).collect();
    let ts: Vec<i64> = (0..SYMBOL_COUNT as i64)
        .map(|i| BASE_TS_NANOS + i)
        .collect();

    let mut chunk = Chunk::new("trades");
    chunk
        .symbol_i32("sym", &codes, &dict_offsets, &dict_bytes, None)
        .unwrap();
    chunk.at_nanos(&ts).unwrap();

    let mut out = Vec::new();
    let mut dict = SymbolGlobalDict::new();
    let mut scratch = EncodeScratch::new();
    encode_chunk_into(&mut out, &chunk, &mut dict, &mut scratch, false).unwrap();

    let golden = hex_to_bytes(JAVA_FIRST_REPLAY_HEX);

    // Header magic/version/flags/table_count (bytes 0..8) must match; the
    // payload-length field (8..12) legitimately differs (different column layout).
    assert_eq!(
        &out[0..8],
        &golden[0..8],
        "column frame header (magic/version/flags/table_count) must match the Java golden"
    );

    // Delta section: [delta_start varint][count varint][entries], right after the
    // 12-byte header. For 10 one-byte-len entries it is 2 + 10 * (1 + 7) = 82 bytes.
    const HEADER: usize = 12;
    const DELTA_SECTION_LEN: usize = 2 + SYMBOL_COUNT * (1 + 7);
    assert_eq!(
        &out[HEADER..HEADER + DELTA_SECTION_LEN],
        &golden[HEADER..HEADER + DELTA_SECTION_LEN],
        "column encoder delta symbol-dict section must be byte-identical to the row/Java golden"
    );
}

fn rust_replay_payloads() -> (Vec<u8>, Vec<u8>) {
    let mut scratch = QwpWsEncodeScratch::new();
    let mut global_dict = SymbolGlobalDict::new();

    let mut first = Buffer::qwp_ws_with_max_name_len(127);
    for idx in 0..SYMBOL_COUNT {
        let sym = format!("SYM_{idx:03}");
        first
            .table("trades")
            .unwrap()
            .symbol("sym", sym)
            .unwrap()
            .column_i64("qty", idx as i64)
            .unwrap()
            .column_f64("px", 100.0 + idx as f64)
            .unwrap()
            .at(TimestampNanos::new(BASE_TS_NANOS + idx as i64))
            .unwrap();
    }
    first
        .as_qwp_ws()
        .unwrap()
        .encode_ws_replay_message(&mut scratch, &mut global_dict, 1)
        .unwrap();
    let first_payload = scratch.message.clone();

    let mut second = Buffer::qwp_ws_with_max_name_len(127);
    second
        .table("trades")
        .unwrap()
        .symbol("sym", "SYM_009")
        .unwrap()
        .column_i64("qty", 99)
        .unwrap()
        .column_f64("px", 999.5)
        .unwrap()
        .at(TimestampNanos::new(BASE_TS_NANOS + 1_000))
        .unwrap();
    second
        .as_qwp_ws()
        .unwrap()
        .encode_ws_replay_message(&mut scratch, &mut global_dict, 1)
        .unwrap();
    let second_payload = scratch.message.clone();

    (first_payload, second_payload)
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let hex = hex.as_bytes();
    assert_eq!(hex.len() % 2, 0, "hex input must contain whole bytes");
    let mut out = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.chunks_exact(2) {
        let hi = hex_value(chunk[0]);
        let lo = hex_value(chunk[1]);
        out.push((hi << 4) | lo);
    }
    out
}

fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid hex byte: {byte}"),
    }
}
