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

use std::io::Read;
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::ErrorCode;
use crate::ingress::sender::delta_encoded_frame_fixture;
use crate::ingress::{
    AckLevel, Buffer, Protocol, QwpWsErrorCategory, QwpWsErrorPolicy, QwpWsProgress, Sender,
    SenderBuilder, TimestampNanos,
};

use super::qwp_ws::{
    perform_server_upgrade, read_frame, write_qwp_error_response, write_qwp_ok_response,
};

const FIRST_WIRE_SEQUENCE: u64 = 0;
const QWP_STATUS_PARSE_ERROR: u8 = 0x05;

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

fn size_limited_connectionless_sender(max_buf_size: usize) -> Sender {
    Sender::from_conf(format!(
        "ws::addr=127.0.0.1:1;initial_connect_retry=async;max_buf_size={max_buf_size};"
    ))
    .unwrap()
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

    // The other half of the contract: claiming relay mode before the persistent
    // check would leave the sender permanently unable to flush typed rows.
    let mut row = sender.new_buffer();
    row.table("readings")
        .unwrap()
        .column_i64("_seq", 2)
        .unwrap();
    row.at(TimestampNanos::new(2)).unwrap();
    sender.flush(&mut row).unwrap();
}

#[cfg(feature = "sync-sender-http")]
#[test]
fn rejected_transactional_row_flush_does_not_claim_row_mode() {
    let mut sender = connectionless_sender();
    let mut row = sender.new_buffer();
    row.table("readings")
        .unwrap()
        .column_i64("_seq", 1)
        .unwrap();
    row.at(TimestampNanos::new(1)).unwrap();

    let err = sender.flush_and_keep_with_flags(&row, true).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidApiCall, "got {err:?}");
    assert!(err.msg().contains("Transactional"), "got {err:?}");

    sender
        .flush_encoded(&self_contained_frame("alpha", 2))
        .expect("a local row rejection must leave relay mode available");
}

#[test]
fn rejected_oversized_relay_does_not_claim_relay_mode() {
    let mut buffer = Buffer::new_qwp_ws();
    let oversized = "x".repeat(2048);
    buffer
        .table("readings")
        .unwrap()
        .column_str("payload", &oversized)
        .unwrap()
        .column_i64("_seq", 1)
        .unwrap();
    buffer.at(TimestampNanos::new(1)).unwrap();
    let frame = buffer.encode_self_contained().unwrap();
    assert!(frame.len() > 1024, "fixture must exceed the sender limit");

    let mut sender = size_limited_connectionless_sender(1024);
    let err = sender.flush_encoded(&frame).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidApiCall, "got {err:?}");
    assert!(err.msg().contains("exceeds"), "got {err:?}");
    assert_eq!(sender.published_fsn().unwrap(), None);

    let mut row = sender.new_buffer();
    row.table("readings")
        .unwrap()
        .column_i64("_seq", 2)
        .unwrap();
    row.at(TimestampNanos::new(2)).unwrap();
    sender
        .flush(&mut row)
        .expect("an oversized relay rejection must leave row mode available");
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

/// Accepts one connection, rejects its first frame with a terminal parse error,
/// then holds the socket open so the client observes the rejection rather than a
/// torn connection.
fn spawn_rejecting_server() -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        perform_server_upgrade(&mut stream).unwrap();
        read_frame(&mut stream).unwrap();
        write_qwp_error_response(
            &mut stream,
            QWP_STATUS_PARSE_ERROR,
            FIRST_WIRE_SEQUENCE,
            b"bad column",
        )
        .unwrap();
        let mut sink = [0u8; 256];
        while matches!(stream.read(&mut sink), Ok(n) if n > 0) {}
    });
    (port, handle)
}

/// A relay-only caller has no reason to call `wait`, `drive_once`, or
/// `close_drain`, so a rejected `flush_encoded` is its only delivery point for
/// the registered error handler. Returning the terminal error without draining
/// the notification inbox first must fail this test.
#[test]
fn a_rejected_relay_flush_still_notifies_the_error_handler() {
    let (port, _server) = spawn_rejecting_server();
    let (error_tx, error_rx) = mpsc::channel();
    let mut sender = SenderBuilder::new(Protocol::Ws, "127.0.0.1", port)
        .qwp_ws_error_handler(move |error| {
            let _ = error_tx.send(error.clone());
        })
        .unwrap()
        .build()
        .unwrap();

    sender
        .flush_encoded(&self_contained_frame("alpha", 1))
        .unwrap();

    // Bounded pump instead of a sleep: the runner thread applies the rejection
    // in the background. `qwp_ws_terminal_error` probes the diagnostic without
    // consuming it, so the handler assertion below stays intact.
    let deadline = Instant::now() + Duration::from_secs(5);
    while sender.qwp_ws_terminal_error().unwrap().is_none() {
        assert!(
            Instant::now() < deadline,
            "the server rejection was not applied within 5s"
        );
        thread::sleep(Duration::from_millis(1));
    }

    let err = sender
        .flush_encoded(&self_contained_frame("beta", 2))
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::ServerRejection, "got {err:?}");

    let notified = error_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("a rejected relay flush must hand the diagnostic to the error handler");
    assert_eq!(notified.category, QwpWsErrorCategory::ParseError);
    assert_eq!(notified.applied_policy, QwpWsErrorPolicy::Terminal);
}
