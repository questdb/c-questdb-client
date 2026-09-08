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
    AckLevel, Buffer, Protocol, QwpWsErrorCategory, QwpWsErrorPolicy, QwpWsProgress, RelaySender,
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

fn connectionless_relay() -> RelaySender {
    RelaySender::from_conf("ws::addr=127.0.0.1:1;initial_connect_retry=async;").unwrap()
}

fn size_limited_connectionless_relay(max_buf_size: usize) -> RelaySender {
    RelaySender::from_conf(format!(
        "ws::addr=127.0.0.1:1;initial_connect_retry=async;max_buf_size={max_buf_size};"
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
    let mut sender = connectionless_relay();
    for invalid in [
        &[0xff, 0xff, 0xff, 0xff][..],
        delta_encoded_frame_fixture().as_slice(),
    ] {
        let err = sender.flush_encoded(invalid).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall, "got {err:?}");
        assert!(err.msg().contains("self-contained"), "got {err:?}");
    }
}

/// A file-backed slot survives the process that chose its dictionary regime,
/// so a later typed-row `Sender` could recover base-0 relay frames as typed
/// history (or vice versa). The rejection is a build-time config error: no
/// connection is dialled and no slot is minted under `sf_dir`.
#[test]
fn build_relay_rejects_persistent_store_before_opening_a_slot() {
    let dir = tempfile::tempdir().unwrap();
    let err = SenderBuilder::from_conf(format!(
        "ws::addr=127.0.0.1:1;initial_connect_retry=async;\
         reconnect_max_duration_millis=5000;sf_dir={};sender_id=relay-test;",
        dir.path().display()
    ))
    .unwrap()
    .build_relay()
    .unwrap_err();
    assert_eq!(err.code(), ErrorCode::ConfigError, "got {err:?}");
    assert!(err.msg().contains("sf_dir"), "got {err:?}");
    assert_eq!(
        std::fs::read_dir(dir.path()).unwrap().count(),
        0,
        "a rejected relay build must not mint a store-and-forward slot"
    );
}

/// Relay is a QWP/WebSocket-only regime; any other protocol is a config error
/// before a socket is opened, so this needs no server.
#[cfg(feature = "sync-sender-http")]
#[test]
fn build_relay_rejects_non_websocket_protocols() {
    let err = SenderBuilder::new(Protocol::Http, "127.0.0.1", 1)
        .build_relay()
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::ConfigError, "got {err:?}");
    assert!(err.msg().contains("ws"), "got {err:?}");
}

#[test]
fn oversized_relay_frame_is_rejected_before_publication() {
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

    let mut sender = size_limited_connectionless_relay(1024);
    let err = sender.flush_encoded(&frame).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidApiCall, "got {err:?}");
    assert!(err.msg().contains("exceeds"), "got {err:?}");
    assert_eq!(
        sender.published_fsn().unwrap(),
        None,
        "an oversized frame must be rejected before it enters the replay queue"
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
            .build_relay()
            .unwrap();

        sender.flush_encoded(&first).unwrap();
        sender.wait(AckLevel::Ok, Duration::from_secs(5)).unwrap();
        sender.flush_encoded(&second).unwrap();
        sender.wait(AckLevel::Ok, Duration::from_secs(5)).unwrap();
        drop(sender);

        assert_eq!(server.join().unwrap(), vec![first, second]);
    }
}

/// The FSN is allocated locally when the frame enters the replay queue, so
/// this needs no server and nothing can race the assertions. Each relay frame
/// gets its own consecutive FSN, and the returned value is the same watermark
/// `published_fsn` reports while the sender is healthy.
#[test]
fn flush_encoded_returns_the_published_frame_sequence_number() {
    let mut sender = connectionless_relay();

    let first = sender
        .flush_encoded(&self_contained_frame("alpha", 1))
        .unwrap();
    assert_eq!(sender.published_fsn().unwrap(), Some(first));

    let second = sender
        .flush_encoded(&self_contained_frame("beta", 2))
        .unwrap();
    assert_eq!(second, first + 1);
    assert_eq!(sender.published_fsn().unwrap(), Some(second));
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
        .build_relay()
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

/// A store-and-forward relay keeps each frame's FSN so it can map a later
/// `QwpWsSenderError` span back to the frames it relayed. Once the runner
/// latches terminal, `published_fsn` is gated behind the terminal error, so
/// the FSN returned by `flush_encoded` is the only copy the caller can get.
/// The FSN is captured from the synchronous return value before any I/O, so
/// the bounded pump below only orders the terminal latch, not the FSN.
#[test]
fn flush_encoded_fsn_outlives_the_terminal_error_and_matches_the_error_span() {
    let (port, _server) = spawn_rejecting_server();
    let (error_tx, error_rx) = mpsc::channel();
    let mut sender = SenderBuilder::new(Protocol::Ws, "127.0.0.1", port)
        .qwp_ws_error_handler(move |error| {
            let _ = error_tx.send(error.clone());
        })
        .unwrap()
        .build_relay()
        .unwrap();

    let fsn = sender
        .flush_encoded(&self_contained_frame("alpha", 1))
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(5);
    while sender.qwp_ws_terminal_error().unwrap().is_none() {
        assert!(
            Instant::now() < deadline,
            "the server rejection was not applied within 5s"
        );
        thread::sleep(Duration::from_millis(1));
    }

    // The watermark accessor is no substitute: it fails once terminal.
    let err = sender.published_fsn().unwrap_err();
    assert_eq!(err.code(), ErrorCode::ServerRejection, "got {err:?}");

    // Drain the diagnostic to the handler through the relay-only path.
    let err = sender
        .flush_encoded(&self_contained_frame("beta", 2))
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::ServerRejection, "got {err:?}");

    let notified = error_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("a rejected relay flush must hand the diagnostic to the error handler");
    assert!(
        (notified.from_fsn..=notified.to_fsn).contains(&fsn),
        "relayed frame {fsn} is not covered by the rejected span {}..={}",
        notified.from_fsn,
        notified.to_fsn
    );
}
