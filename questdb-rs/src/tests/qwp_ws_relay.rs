/*******************************************************************************
 *     ___                  _   ____  ____
 *    / _ \ _   _  ___  ___| |_|  _ \| __ )
 *   | | | | | | |/ _ \/ __| __| | | |  _ \
 *   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
 *    \__\_\\__,_|\___||___/\__|____/|____/
 *
 *  Copyright (c) 2014-2019 Appsicle
 *  Copyright (c) 2019-2026 QuestDB
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

use std::net::TcpListener;
use std::thread;
use std::time::Duration;

use crate::ErrorCode;
use crate::ingress::sender::delta_encoded_frame_fixture;
use crate::ingress::{
    AckLevel, Buffer, Protocol, QwpWsProgress, Sender, SenderBuilder, TimestampNanos,
};

use super::qwp_ws::{perform_server_upgrade, read_frame, write_qwp_ok_response};

fn self_contained_frame(symbol: &str, seq: i64) -> Vec<u8> {
    let mut buffer = Buffer::new_qwp_ws();
    buffer
        .table("readings")
        .unwrap()
        .symbol("site", symbol)
        .unwrap()
        .column_i64("value", seq)
        .unwrap()
        .column_i64("_seq", seq)
        .unwrap();
    buffer.at(TimestampNanos::new(seq)).unwrap();
    buffer.encode_self_contained().unwrap()
}

fn connectionless_sender() -> Sender {
    Sender::from_conf("ws::addr=127.0.0.1:1;initial_connect_retry=async;").unwrap()
}

fn persistent_connectionless_sender(sf_dir: &std::path::Path) -> Sender {
    Sender::from_conf(format!(
        "ws::addr=127.0.0.1:1;initial_connect_retry=async;\
         reconnect_max_duration_millis=5000;sf_dir={};sender_id=relay-test;",
        sf_dir.display()
    ))
    .unwrap()
}

/// A self-contained frame must carry every symbol it references and declare
/// dictionary base 0. Removing dense encoding from `encode_self_contained`
/// must fail this test.
#[test]
fn a_self_contained_frame_carries_its_own_dictionary() {
    let frame = self_contained_frame("alpha", 1);
    assert!(!frame.is_empty());
    assert!(
        crate::ingress::is_self_contained(&frame),
        "a self-contained frame must declare dictionary base 0"
    );
    assert!(
        frame.windows(5).any(|window| window == b"alpha"),
        "the symbol literal must travel with the frame"
    );
}

/// Returning a constant `true` from `is_self_contained` must fail this test.
#[test]
fn a_delta_encoded_frame_is_not_reported_self_contained() {
    let frame = delta_encoded_frame_fixture();
    assert!(!crate::ingress::is_self_contained(&frame));
}

/// Reusing connection-global encoder state between calls must fail this test:
/// the second result has to be independently decodable.
#[test]
fn two_self_contained_frames_do_not_share_dictionary_state() {
    let first = self_contained_frame("alpha", 1);
    let second = self_contained_frame("beta", 2);

    assert!(crate::ingress::is_self_contained(&first));
    assert!(crate::ingress::is_self_contained(&second));
    assert!(
        second.windows(4).any(|window| window == b"beta"),
        "the second frame must carry its own symbol literal"
    );
}

/// The cheap check still owns its framing contract. Weakening it to inspect
/// only magic/base must fail these malformed or inconsistent headers; tenant
/// table and column semantics remain deliberately unparsed.
#[test]
fn self_contained_validation_rejects_invalid_framing_markers() {
    let valid = self_contained_frame("alpha", 1);
    let mut bad_payload_len = valid.clone();
    bad_payload_len[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    let mut bad_magic = valid.clone();
    bad_magic[0] = b'X';
    let mut bad_version = valid.clone();
    bad_version[4] = 2;
    let truncated = &valid[..12];

    for malformed in [
        &[][..],
        &[0xff, 0xff, 0xff, 0xff][..],
        bad_magic.as_slice(),
        bad_version.as_slice(),
        bad_payload_len.as_slice(),
        truncated,
    ] {
        assert!(
            !crate::ingress::is_self_contained(malformed),
            "malformed bytes were accepted: {malformed:?}"
        );
    }
}

#[test]
fn encode_self_contained_rejects_non_websocket_and_empty_buffers() {
    let ilp = Buffer::new(crate::ingress::ProtocolVersion::V2);
    assert_eq!(
        ilp.encode_self_contained().unwrap_err().code(),
        ErrorCode::InvalidApiCall
    );

    let empty = Buffer::new_qwp_ws();
    assert_eq!(
        empty.encode_self_contained().unwrap_err().code(),
        ErrorCode::InvalidApiCall
    );
}

#[test]
fn flush_encoded_rejects_non_self_contained_bytes_before_io() {
    let mut sender = connectionless_sender();
    for invalid in [
        &[0xff, 0xff, 0xff, 0xff][..],
        delta_encoded_frame_fixture().as_slice(),
    ] {
        let err = sender.flush_encoded(invalid).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall, "got {err:?}");
        assert!(err.msg().contains("self-contained"), "got {err:?}");
    }
}

/// A file-backed slot survives the `Sender` that chose its dictionary regime,
/// while `qwp_ws_ingress_mode` does not. Accepting relay bytes here could put a
/// base-0 relay frame behind recovered typed deltas (or interpret recovered
/// relay bytes as typed history). The rejection must be local: this endpoint is
/// unreachable and the caller must not publish anything while the background
/// runner is still trying to dial it.
#[test]
fn flush_encoded_rejects_persistent_store_before_mode_claim_or_io() {
    let dir = tempfile::tempdir().unwrap();
    let mut sender = persistent_connectionless_sender(dir.path());
    let frame = self_contained_frame("alpha", 1);

    let err = sender.flush_encoded(&frame).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidApiCall, "got {err:?}");
    assert!(err.msg().contains("persistent"), "got {err:?}");
    assert_eq!(
        sender.published_fsn().unwrap(),
        None,
        "a locally rejected relay frame must not enter the persistent queue"
    );
}

fn spawn_two_frame_server() -> (u16, thread::JoinHandle<Vec<Vec<u8>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        perform_server_upgrade(&mut stream).unwrap();
        let mut frames = Vec::new();
        for wire_seq in 0..2 {
            let (_fin, _opcode, payload) = read_frame(&mut stream).unwrap();
            frames.push(payload);
            write_qwp_ok_response(&mut stream, wire_seq).unwrap();
        }
        frames
    });
    (port, handle)
}

/// Removing relay mode from the send core makes the second frame conflict with
/// the first frame's connection dictionary (both define id 0 differently).
#[test]
fn two_self_contained_frames_relay_verbatim_on_one_connection() {
    for progress in [QwpWsProgress::Background, QwpWsProgress::Manual] {
        let first = self_contained_frame("alpha", 1);
        let second = self_contained_frame("beta", 2);
        let (port, server) = spawn_two_frame_server();
        let mut sender = SenderBuilder::new(Protocol::Ws, "127.0.0.1", port)
            .qwp_ws_progress(progress)
            .unwrap()
            .build()
            .unwrap();

        sender.flush_encoded(&first).unwrap();
        sender.wait(AckLevel::Ok, Duration::from_secs(5)).unwrap();
        sender.flush_encoded(&second).unwrap();
        sender.wait(AckLevel::Ok, Duration::from_secs(5)).unwrap();
        drop(sender);

        assert_eq!(server.join().unwrap(), vec![first, second]);
    }
}

/// Allowing typed rows and independent base-0 dictionaries to share one
/// connection can silently resolve a row frame's ids against relay symbols.
#[test]
fn a_qwp_websocket_sender_cannot_mix_row_and_relay_modes() {
    let encoded = self_contained_frame("alpha", 1);

    let mut relay_first = connectionless_sender();
    relay_first.flush_encoded(&encoded).unwrap();
    let mut row = relay_first.new_buffer();
    row.table("readings")
        .unwrap()
        .column_i64("_seq", 2)
        .unwrap();
    row.at(TimestampNanos::new(2)).unwrap();
    let err = relay_first.flush(&mut row).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidApiCall);
    assert!(err.msg().contains("relay"), "got {err:?}");

    let mut row_first = connectionless_sender();
    let mut row = row_first.new_buffer();
    row.table("readings")
        .unwrap()
        .column_i64("_seq", 1)
        .unwrap();
    row.at(TimestampNanos::new(1)).unwrap();
    row_first.flush(&mut row).unwrap();
    let err = row_first.flush_encoded(&encoded).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidApiCall);
    assert!(err.msg().contains("row"), "got {err:?}");
}
