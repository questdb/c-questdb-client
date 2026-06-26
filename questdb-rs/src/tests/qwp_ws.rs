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

//! Integration tests for the QWP/WebSocket sync sender. Stands up a minimal
//! in-process server that performs the HTTP upgrade and round-trips a single
//! QWP message, and asserts the wire bytes for the simplest case.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::ErrorCode;
use crate::ingress::{
    Buffer, ColumnName, Protocol, QwpWsEncodeScratch, QwpWsErrorCategory, QwpWsErrorPolicy,
    QwpWsProgress, SenderBuilder, SymbolGlobalDict, TableName, TimestampNanos,
};

pub(crate) const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const FIRST_WIRE_SEQUENCE: u64 = 0;
const QWP_STATUS_OK: u8 = 0x00;
const QWP_STATUS_DURABLE_ACK: u8 = 0x02;
const QWP_STATUS_SCHEMA_MISMATCH: u8 = 0x03;
const QWP_STATUS_PARSE_ERROR: u8 = 0x05;
const QWP_WS_PUBLIC_BENCH_DEFAULT_ROWS: usize = 20_000_000;
const QWP_WS_PUBLIC_BENCH_DEFAULT_BATCH_SIZE: usize = 1000;
const QWP_WS_PUBLIC_BENCH_DEFAULT_IN_FLIGHT: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProgressCase {
    Background,
    Manual,
}

impl ProgressCase {
    fn name(self) -> &'static str {
        match self {
            Self::Background => "background",
            Self::Manual => "manual",
        }
    }
}

fn build_qwp_ws_sender_from_builder(
    progress: ProgressCase,
    builder: SenderBuilder,
) -> crate::ingress::Sender {
    match progress {
        ProgressCase::Background => builder.build().unwrap(),
        ProgressCase::Manual => builder
            .qwp_ws_progress(QwpWsProgress::Manual)
            .unwrap()
            .build()
            .unwrap(),
    }
}

fn build_qwp_ws_sender(progress: ProgressCase, port: u16) -> crate::ingress::Sender {
    build_qwp_ws_sender_from_builder(
        progress,
        SenderBuilder::new(Protocol::QwpWs, "127.0.0.1", port),
    )
}

// ---------- mock server ----------

struct MockResult {
    request_lines: Vec<String>,
    received_frames: Vec<Vec<u8>>,
}

pub(crate) fn read_request_until_blank<R: Read>(stream: &mut R) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 256];
    loop {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    Ok(buf)
}

pub(crate) fn parse_header(req: &str, name: &str) -> Option<String> {
    for line in req.split("\r\n").skip(1) {
        if let Some((k, v)) = line.split_once(':')
            && k.trim().eq_ignore_ascii_case(name)
        {
            return Some(v.trim().to_string());
        }
    }
    None
}

pub(crate) fn read_frame(stream: &mut TcpStream) -> std::io::Result<(bool, u8, Vec<u8>)> {
    let mut hdr = [0u8; 2];
    stream.read_exact(&mut hdr)?;
    let fin = (hdr[0] & 0x80) != 0;
    let opcode = hdr[0] & 0x0F;
    let masked = (hdr[1] & 0x80) != 0;
    let len_short = hdr[1] & 0x7F;
    let payload_len = match len_short {
        126 => {
            let mut b = [0u8; 2];
            stream.read_exact(&mut b)?;
            u16::from_be_bytes(b) as usize
        }
        127 => {
            let mut b = [0u8; 8];
            stream.read_exact(&mut b)?;
            u64::from_be_bytes(b) as usize
        }
        n => n as usize,
    };
    let mut mask = [0u8; 4];
    if masked {
        stream.read_exact(&mut mask)?;
    }
    let mut payload = vec![0u8; payload_len];
    stream.read_exact(&mut payload)?;
    if masked {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask[i & 3];
        }
    }
    Ok((fin, opcode, payload))
}

pub(crate) fn write_server_binary_frame(
    stream: &mut TcpStream,
    payload: &[u8],
) -> std::io::Result<()> {
    // FIN | binary, no mask (server→client).
    let mut frame = vec![0x82];
    let plen = payload.len();
    if plen <= 125 {
        frame.push(plen as u8);
    } else if plen <= 0xFFFF {
        frame.push(126);
        frame.extend_from_slice(&(plen as u16).to_be_bytes());
    } else {
        frame.push(127);
        frame.extend_from_slice(&(plen as u64).to_be_bytes());
    }
    frame.extend_from_slice(payload);
    stream.write_all(&frame)
}

pub(crate) fn perform_server_upgrade(stream: &mut TcpStream) -> std::io::Result<Vec<String>> {
    perform_server_upgrade_with_version(stream, 1)
}

/// Like [`perform_server_upgrade`] but advertises an arbitrary
/// `X-QWP-Version`. The egress reader skips the `SERVER_INFO` read and the
/// role check when the negotiated version is `0`, which lets a park-only
/// mock satisfy `Reader::from_conf` without emitting a `SERVER_INFO` frame.
pub(crate) fn perform_server_upgrade_with_version(
    stream: &mut TcpStream,
    version: u8,
) -> std::io::Result<Vec<String>> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    let req_bytes = read_request_until_blank(stream)?;
    let req = String::from_utf8_lossy(&req_bytes).to_string();
    let request_lines: Vec<String> = req
        .split("\r\n")
        .take_while(|l| !l.is_empty())
        .map(String::from)
        .collect();

    let key = parse_header(&req, "Sec-WebSocket-Key").expect("missing Sec-WebSocket-Key");
    let accept = compute_accept(&key);

    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {accept}\r\n\
         X-QWP-Version: {version}\r\n\
         \r\n"
    );
    stream.write_all(response.as_bytes())?;
    Ok(request_lines)
}

/// Write a minimal `SERVER_INFO` frame: the first server→client frame an
/// egress [`crate::egress::Reader`] consumes after the upgrade when the
/// negotiated version is `>= 1`. Role is `Standalone` with `capabilities=0`
/// (no zone trailer), which a `target=any` reader accepts. Emitted as an
/// unmasked WS binary message. Bytes are written by hand (mirroring
/// `egress::server_event::decode_server_info` + `egress::wire::header`) so
/// the helper stays self-contained.
#[cfg(feature = "sync-reader-qwp-ws")]
pub(crate) fn write_server_info_frame(stream: &mut TcpStream) -> std::io::Result<()> {
    // SERVER_INFO payload.
    let mut payload = Vec::new();
    payload.push(0x18); // MsgKind::ServerInfo
    payload.push(0x00); // role = Standalone
    payload.extend_from_slice(&1u64.to_le_bytes()); // epoch
    payload.extend_from_slice(&0u32.to_le_bytes()); // capabilities (no CAP_ZONE)
    payload.extend_from_slice(&0i64.to_le_bytes()); // server_wall_ns
    payload.extend_from_slice(&0u16.to_le_bytes()); // cluster_id length = 0
    payload.extend_from_slice(&0u16.to_le_bytes()); // node_id length = 0

    // 12-byte QWP1 frame header wrapping the payload.
    let mut frame = Vec::with_capacity(12 + payload.len());
    frame.extend_from_slice(b"QWP1");
    frame.push(1); // version
    frame.push(0); // flags
    frame.extend_from_slice(&0u16.to_le_bytes()); // table_count = 0
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(&payload);

    write_server_frame(stream, 0x2, &frame, false)
}

fn write_server_frame(
    stream: &mut TcpStream,
    opcode: u8,
    payload: &[u8],
    masked: bool,
) -> std::io::Result<()> {
    let mut frame = vec![0x80 | (opcode & 0x0F)];
    let mask_bit = if masked { 0x80 } else { 0 };
    let plen = payload.len();
    if plen <= 125 {
        frame.push(mask_bit | plen as u8);
    } else if plen <= 0xFFFF {
        frame.push(mask_bit | 126);
        frame.extend_from_slice(&(plen as u16).to_be_bytes());
    } else {
        frame.push(mask_bit | 127);
        frame.extend_from_slice(&(plen as u64).to_be_bytes());
    }

    if masked {
        let mask = [0u8; 4];
        frame.extend_from_slice(&mask);
        for (index, byte) in payload.iter().enumerate() {
            frame.push(*byte ^ mask[index & 3]);
        }
    } else {
        frame.extend_from_slice(payload);
    }

    stream.write_all(&frame)
}

fn write_server_close_frame(
    stream: &mut TcpStream,
    code: u16,
    reason: &str,
) -> std::io::Result<()> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&code.to_be_bytes());
    payload.extend_from_slice(reason.as_bytes());

    let mut frame = vec![0x88];
    let plen = payload.len();
    if plen <= 125 {
        frame.push(plen as u8);
    } else {
        frame.push(126);
        frame.extend_from_slice(&(plen as u16).to_be_bytes());
    }
    frame.extend_from_slice(&payload);
    stream.write_all(&frame)
}

/// Write a server-origin frame with a caller-controlled first byte
/// (FIN | RSV1..3 | opcode). Used to construct deliberately malformed frames
/// — FIN=0 for fragmentation, RSV bits set without extensions, exotic
/// opcodes, undersized close payloads, etc.
fn write_raw_ws_frame(stream: &mut TcpStream, byte0: u8, payload: &[u8]) -> std::io::Result<()> {
    let mut frame = vec![byte0];
    let plen = payload.len();
    if plen <= 125 {
        frame.push(plen as u8);
    } else if plen <= 0xFFFF {
        frame.push(126);
        frame.extend_from_slice(&(plen as u16).to_be_bytes());
    } else {
        frame.push(127);
        frame.extend_from_slice(&(plen as u64).to_be_bytes());
    }
    frame.extend_from_slice(payload);
    stream.write_all(&frame)
}

pub(crate) fn write_qwp_ok_response(stream: &mut TcpStream, wire_seq: u64) -> std::io::Result<()> {
    let mut ok = Vec::new();
    ok.push(QWP_STATUS_OK);
    ok.extend_from_slice(&wire_seq.to_le_bytes());
    append_table_seq_txns(&mut ok, &[]);
    write_server_binary_frame(stream, &ok)
}

fn write_qwp_ok_response_with_table_entries(
    stream: &mut TcpStream,
    wire_seq: u64,
    entries: &[(&str, i64)],
) -> std::io::Result<()> {
    let mut ok = Vec::new();
    ok.push(QWP_STATUS_OK);
    ok.extend_from_slice(&wire_seq.to_le_bytes());
    append_table_seq_txns(&mut ok, entries);
    write_server_binary_frame(stream, &ok)
}

fn write_qwp_durable_ack_response(
    stream: &mut TcpStream,
    entries: &[(&str, i64)],
) -> std::io::Result<()> {
    let mut ack = Vec::new();
    ack.push(QWP_STATUS_DURABLE_ACK);
    append_table_seq_txns(&mut ack, entries);
    write_server_binary_frame(stream, &ack)
}

fn append_table_seq_txns(payload: &mut Vec<u8>, entries: &[(&str, i64)]) {
    payload.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    for (table, seq_txn) in entries {
        payload.extend_from_slice(&(table.len() as u16).to_le_bytes());
        payload.extend_from_slice(table.as_bytes());
        payload.extend_from_slice(&seq_txn.to_le_bytes());
    }
}

pub(crate) fn write_qwp_error_response(
    stream: &mut TcpStream,
    status: u8,
    wire_seq: u64,
    msg: &[u8],
) -> std::io::Result<()> {
    let mut err = Vec::new();
    err.push(status);
    err.extend_from_slice(&wire_seq.to_le_bytes());
    err.extend_from_slice(&(msg.len() as u16).to_le_bytes());
    err.extend_from_slice(msg);
    write_server_binary_frame(stream, &err)
}

pub(crate) fn compute_accept(key_b64: &str) -> String {
    use base64ct::{Base64, Encoding};
    let combined = format!("{key_b64}{WS_GUID}");
    let digest = sha1(combined.as_bytes());
    Base64::encode_string(&digest)
}

fn upgrade_mock_stream(stream: &mut TcpStream) -> Vec<String> {
    upgrade_mock_stream_with_durable_ack(stream, false)
}

fn upgrade_mock_stream_with_durable_ack(
    stream: &mut TcpStream,
    durable_ack_enabled: bool,
) -> Vec<String> {
    let req_bytes = read_request_until_blank(stream).unwrap();
    let req = String::from_utf8_lossy(&req_bytes).to_string();
    let request_lines: Vec<String> = req
        .split("\r\n")
        .take_while(|l| !l.is_empty())
        .map(String::from)
        .collect();
    let key = parse_header(&req, "Sec-WebSocket-Key").expect("missing Sec-WebSocket-Key");
    let accept = compute_accept(&key);
    let durable_ack_header = if durable_ack_enabled {
        "X-QWP-Durable-Ack: enabled\r\n"
    } else {
        ""
    };
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {accept}\r\n\
         X-QWP-Version: 1\r\n\
         {durable_ack_header}\
         \r\n"
    );
    stream.write_all(response.as_bytes()).unwrap();
    request_lines
}

fn upgrade_mock_stream_with_version(stream: &mut TcpStream, version: u8) -> Vec<String> {
    let req_bytes = read_request_until_blank(stream).unwrap();
    let req = String::from_utf8_lossy(&req_bytes).to_string();
    let request_lines: Vec<String> = req
        .split("\r\n")
        .take_while(|l| !l.is_empty())
        .map(String::from)
        .collect();
    let key = parse_header(&req, "Sec-WebSocket-Key").expect("missing Sec-WebSocket-Key");
    let accept = compute_accept(&key);
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {accept}\r\n\
         X-QWP-Version: {version}\r\n\
         \r\n"
    );
    stream.write_all(response.as_bytes()).unwrap();
    request_lines
}

fn upgrade_mock_stream_without_upgrade_header(stream: &mut TcpStream) {
    let req_bytes = read_request_until_blank(stream).unwrap();
    let req = String::from_utf8_lossy(&req_bytes).to_string();
    let key = parse_header(&req, "Sec-WebSocket-Key").expect("missing Sec-WebSocket-Key");
    let accept = compute_accept(&key);
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {accept}\r\n\
         X-QWP-Version: 1\r\n\
         \r\n"
    );
    stream.write_all(response.as_bytes()).unwrap();
}

// Mirror of the production SHA-1 used by the sender, reproduced here to
// validate the upgrade handshake from the server side without poking at
// internals. ~50 lines is cheaper than another dependency.
pub(crate) fn sha1(input: &[u8]) -> [u8; 20] {
    let (mut h0, mut h1, mut h2, mut h3, mut h4) = (
        0x67452301u32,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476,
        0xC3D2E1F0,
    );
    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut p = Vec::with_capacity(input.len() + 64);
    p.extend_from_slice(input);
    p.push(0x80);
    while p.len() % 64 != 56 {
        p.push(0);
    }
    p.extend_from_slice(&bit_len.to_be_bytes());
    let mut w = [0u32; 80];
    for chunk in p.chunks_exact(64) {
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
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let t = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
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

/// Accept exactly one connection, do the upgrade, read frames, and return them
/// to the test thread. The first frame received is replied to with an OK
/// response (status=0x00, sequence=0, table_count=0).
fn spawn_mock_server() -> (u16, mpsc::Receiver<MockResult>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request_lines = perform_server_upgrade(&mut stream).unwrap();

        // Tolerate a client that closes after the handshake without sending a
        // frame (locally-rejected flush, teardown on drop): a hangup is a clean
        // end-of-client, not a reason to panic this detached thread.
        let mut received_frames = Vec::new();
        if let Ok((_fin, _opcode, payload)) = read_frame(&mut stream) {
            received_frames.push(payload);
            let _ = write_qwp_ok_response(&mut stream, FIRST_WIRE_SEQUENCE);
        }

        let _ = tx.send(MockResult {
            request_lines,
            received_frames,
        });
        // Hold the connection open briefly so the client side reads the reply.
        thread::sleep(Duration::from_millis(50));
    });

    (port, rx)
}

fn spawn_one_response_server(response: MockQwpResponse) -> (u16, mpsc::Receiver<MockResult>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request_lines = perform_server_upgrade(&mut stream).unwrap();

        let mut received_frames = Vec::new();
        if let Ok((_fin, _opcode, payload)) = read_frame(&mut stream) {
            received_frames.push(payload);
            let _ = write_mock_qwp_response(&mut stream, response);
        }

        let _ = tx.send(MockResult {
            request_lines,
            received_frames,
        });
        thread::sleep(Duration::from_millis(50));
    });

    (port, rx)
}

#[derive(Clone, Copy)]
enum MockQwpResponse {
    Ok {
        wire_seq: u64,
    },
    Error {
        status: u8,
        wire_seq: u64,
        message: &'static [u8],
    },
}

fn write_mock_qwp_response(
    stream: &mut TcpStream,
    response: MockQwpResponse,
) -> std::io::Result<()> {
    match response {
        MockQwpResponse::Ok { wire_seq } => write_qwp_ok_response(stream, wire_seq),
        MockQwpResponse::Error {
            status,
            wire_seq,
            message,
        } => write_qwp_error_response(stream, status, wire_seq, message),
    }
}

fn spawn_two_response_server(
    first_response: MockQwpResponse,
    second_response: MockQwpResponse,
) -> (u16, mpsc::Receiver<MockResult>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request_lines = perform_server_upgrade(&mut stream).unwrap();

        let mut received_frames = Vec::new();
        if let Ok((_fin, _opcode, first)) = read_frame(&mut stream) {
            received_frames.push(first);
            let _ = write_mock_qwp_response(&mut stream, first_response);
            if let Ok((_fin, _opcode, second)) = read_frame(&mut stream) {
                received_frames.push(second);
                let _ = write_mock_qwp_response(&mut stream, second_response);
            }
        }

        let _ = tx.send(MockResult {
            request_lines,
            received_frames,
        });
        thread::sleep(Duration::from_millis(50));
    });

    (port, rx)
}

fn spawn_stalled_after_first_frame_server() -> (u16, mpsc::Receiver<Vec<u8>>, mpsc::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (frame_tx, frame_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        perform_server_upgrade(&mut stream).unwrap();
        let (_fin, _opcode, payload) = read_frame(&mut stream).unwrap();
        frame_tx.send(payload).unwrap();
        let _ = release_rx.recv_timeout(Duration::from_secs(5));
    });

    (port, frame_rx, release_tx)
}

fn spawn_ack_each_frame_server() -> (u16, thread::JoinHandle<usize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        perform_server_upgrade(&mut stream).unwrap();

        let mut next_wire_seq = FIRST_WIRE_SEQUENCE;
        let mut binary_frames = 0usize;
        loop {
            match read_frame(&mut stream) {
                Ok((_fin, 0x2, _payload)) => {
                    write_qwp_ok_response(&mut stream, next_wire_seq).unwrap();
                    next_wire_seq += 1;
                    binary_frames += 1;
                }
                Ok((_fin, 0x8, _payload)) => break,
                Ok((_fin, 0x9, payload)) => {
                    write_server_frame(&mut stream, 0xA, &payload, false).unwrap();
                }
                Ok((_fin, _opcode, _payload)) => {}
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::UnexpectedEof
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::BrokenPipe
                    ) =>
                {
                    break;
                }
                Err(err) => panic!("benchmark ACK server failed to read frame: {err}"),
            }
        }
        binary_frames
    });

    (port, handle)
}

fn spawn_upgrade_only_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        perform_server_upgrade(&mut stream).unwrap();
        thread::sleep(Duration::from_millis(50));
    });

    port
}

fn qwp_ws_replay_encoded_len(buf: &Buffer) -> usize {
    let mut scratch = QwpWsEncodeScratch::new();
    let mut global_dict = SymbolGlobalDict::new();
    buf.as_qwp_ws()
        .unwrap()
        .encode_ws_replay_message(&mut scratch, &mut global_dict, 1)
        .unwrap();
    scratch.message.len()
}

fn qwp_ws_public_bench_env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn qwp_ws_public_bench_env_bool(name: &str) -> bool {
    matches!(
        std::env::var(name).as_deref(),
        Ok("1" | "on" | "true" | "yes")
    )
}

#[derive(Clone, Copy)]
enum QwpWsPublicBenchWorkload {
    Base,
    Numeric,
    Symbol,
    String,
    Full,
}

impl QwpWsPublicBenchWorkload {
    fn from_env() -> Self {
        match std::env::var("QWP_WS_PUBLIC_BENCH_WORKLOAD")
            .unwrap_or_else(|_| "full".to_string())
            .as_str()
        {
            "base" => Self::Base,
            "numeric" => Self::Numeric,
            "symbol" => Self::Symbol,
            "string" => Self::String,
            "full" => Self::Full,
            other => panic!("unknown QWP_WS_PUBLIC_BENCH_WORKLOAD: {other}"),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Base => "base",
            Self::Numeric => "numeric",
            Self::Symbol => "symbol",
            Self::String => "string",
            Self::Full => "full",
        }
    }
}

fn fill_qwp_ws_public_benchmark_batch(
    buffer: &mut Buffer,
    workload: QwpWsPublicBenchWorkload,
    prevalidated_names: bool,
    batch_idx: usize,
    batch_size: usize,
    rows_in_batch: usize,
) {
    const SYMBOLS: [&str; 8] = [
        "SYM000", "SYM001", "SYM002", "SYM003", "SYM004", "SYM005", "SYM006", "SYM007",
    ];
    const VENUES: [&str; 8] = ["ldn", "nyc", "ams", "fra", "sin", "hkg", "tyo", "sfo"];

    for row_idx in 0..rows_in_batch {
        let seq = (batch_idx * batch_size + row_idx) as i64;
        match workload {
            QwpWsPublicBenchWorkload::Base => {
                bench_table(buffer, prevalidated_names).unwrap();
                bench_qty(buffer, prevalidated_names, seq).unwrap();
                buffer.at(TimestampNanos::new(seq)).unwrap();
            }
            QwpWsPublicBenchWorkload::Numeric => {
                bench_table(buffer, prevalidated_names).unwrap();
                bench_qty(buffer, prevalidated_names, seq).unwrap();
                bench_px(buffer, prevalidated_names, 100.0 + (seq & 1023) as f64).unwrap();
                buffer.at(TimestampNanos::new(seq)).unwrap();
            }
            QwpWsPublicBenchWorkload::Symbol => {
                bench_table(buffer, prevalidated_names).unwrap();
                bench_symbol(buffer, prevalidated_names, SYMBOLS[row_idx & 7]).unwrap();
                bench_qty(buffer, prevalidated_names, seq).unwrap();
                buffer.at(TimestampNanos::new(seq)).unwrap();
            }
            QwpWsPublicBenchWorkload::String => {
                bench_table(buffer, prevalidated_names).unwrap();
                bench_qty(buffer, prevalidated_names, seq).unwrap();
                bench_venue(buffer, prevalidated_names, VENUES[row_idx & 7]).unwrap();
                buffer.at(TimestampNanos::new(seq)).unwrap();
            }
            QwpWsPublicBenchWorkload::Full => {
                bench_table(buffer, prevalidated_names).unwrap();
                bench_symbol(buffer, prevalidated_names, SYMBOLS[row_idx & 7]).unwrap();
                bench_qty(buffer, prevalidated_names, seq).unwrap();
                bench_px(buffer, prevalidated_names, 100.0 + (seq & 1023) as f64).unwrap();
                bench_venue(buffer, prevalidated_names, VENUES[row_idx & 7]).unwrap();
                bench_event_ts(buffer, prevalidated_names, TimestampNanos::new(seq)).unwrap();
                buffer.at(TimestampNanos::new(seq)).unwrap();
            }
        }
    }
}

fn bench_table(buffer: &mut Buffer, prevalidated_names: bool) -> crate::Result<&mut Buffer> {
    if prevalidated_names {
        buffer.table(TableName::new_unchecked("trades"))
    } else {
        buffer.table("trades")
    }
}

fn bench_symbol<'a>(
    buffer: &'a mut Buffer,
    prevalidated_names: bool,
    value: &str,
) -> crate::Result<&'a mut Buffer> {
    if prevalidated_names {
        buffer.symbol(ColumnName::new_unchecked("sym"), value)
    } else {
        buffer.symbol("sym", value)
    }
}

fn bench_qty(
    buffer: &mut Buffer,
    prevalidated_names: bool,
    value: i64,
) -> crate::Result<&mut Buffer> {
    if prevalidated_names {
        buffer.column_i64(ColumnName::new_unchecked("qty"), value)
    } else {
        buffer.column_i64("qty", value)
    }
}

fn bench_px(
    buffer: &mut Buffer,
    prevalidated_names: bool,
    value: f64,
) -> crate::Result<&mut Buffer> {
    if prevalidated_names {
        buffer.column_f64(ColumnName::new_unchecked("px"), value)
    } else {
        buffer.column_f64("px", value)
    }
}

fn bench_venue<'a>(
    buffer: &'a mut Buffer,
    prevalidated_names: bool,
    value: &str,
) -> crate::Result<&'a mut Buffer> {
    if prevalidated_names {
        buffer.column_str(ColumnName::new_unchecked("venue"), value)
    } else {
        buffer.column_str("venue", value)
    }
}

fn bench_event_ts(
    buffer: &mut Buffer,
    prevalidated_names: bool,
    value: TimestampNanos,
) -> crate::Result<&mut Buffer> {
    if prevalidated_names {
        buffer.column_ts(ColumnName::new_unchecked("event_ts"), value)
    } else {
        buffer.column_ts("event_ts", value)
    }
}

fn no_symbol_frame_at_local_hint_overcount_boundary(max: usize) -> Buffer {
    for len in 0..max {
        let mut buf = Buffer::qwp_ws_with_max_name_len(127);
        let note = "x".repeat(len);
        buf.table("trades")
            .unwrap()
            .column_str("note", note.as_str())
            .unwrap()
            .at_now()
            .unwrap();

        let encoded_len = qwp_ws_replay_encoded_len(&buf);
        if buf.len() > max && encoded_len <= max {
            return buf;
        }
    }
    panic!("no QWP/WS size-boundary frame found for max={max}");
}

fn spawn_manual_orphan_drain_server() -> (u16, mpsc::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let (mut foreground, _) = listener.accept().unwrap();
        perform_server_upgrade(&mut foreground).unwrap();

        let (mut orphan, _) = listener.accept().unwrap();
        perform_server_upgrade(&mut orphan).unwrap();
        let (_fin, _opcode, payload) = read_frame(&mut orphan).unwrap();
        write_qwp_ok_response(&mut orphan, FIRST_WIRE_SEQUENCE).unwrap();
        tx.send(payload).unwrap();

        thread::sleep(Duration::from_millis(50));
    });

    (port, rx)
}

fn spawn_manual_orphan_reject_server(status: u8) -> (u16, mpsc::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let (mut foreground, _) = listener.accept().unwrap();
        perform_server_upgrade(&mut foreground).unwrap();

        let (mut orphan, _) = listener.accept().unwrap();
        perform_server_upgrade(&mut orphan).unwrap();
        let (_fin, _opcode, payload) = read_frame(&mut orphan).unwrap();
        write_qwp_error_response(&mut orphan, status, FIRST_WIRE_SEQUENCE, b"bad orphan").unwrap();
        tx.send(payload).unwrap();

        thread::sleep(Duration::from_millis(50));
    });

    (port, rx)
}

fn spawn_stalled_background_orphan_drain_server() -> (u16, mpsc::Receiver<Vec<u8>>, mpsc::Sender<()>)
{
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();

    thread::spawn(move || {
        let (mut foreground, _) = listener.accept().unwrap();
        perform_server_upgrade(&mut foreground).unwrap();

        let (mut orphan, _) = listener.accept().unwrap();
        perform_server_upgrade(&mut orphan).unwrap();
        let (_fin, _opcode, payload) = read_frame(&mut orphan).unwrap();
        tx.send(payload).unwrap();

        // Keep the orphan connection open until the test releases it. A
        // regression that waits for stalled orphan work would block close.
        let _ = release_rx.recv_timeout(Duration::from_secs(6));
    });

    (port, rx, release_tx)
}

fn spawn_role_reject_upgrade_server(
    expected_attempts: usize,
    role: &'static str,
) -> (u16, thread::JoinHandle<usize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();

    let handle = thread::spawn(move || {
        let started = Instant::now();
        let mut attempts = 0usize;
        while attempts < expected_attempts && started.elapsed() < Duration::from_secs(5) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    attempts += 1;
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    stream
                        .set_write_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    let _ = read_request_until_blank(&mut stream).unwrap();
                    let response = format!(
                        "HTTP/1.1 421 Misdirected Request\r\n\
                         Connection: close\r\n\
                         Content-Length: 0\r\n\
                         X-QuestDB-Role: {role}\r\n\
                         \r\n"
                    );
                    stream.write_all(response.as_bytes()).unwrap();
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(err) => panic!("role-reject listener failed: {err}"),
            }
        }
        attempts
    });

    (port, handle)
}

fn slot_has_sfa_file(slot_dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(slot_dir) else {
        return false;
    };
    entries.flatten().any(|entry| {
        entry
            .path()
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(".sfa"))
    })
}

fn seed_orphan_slot(sf_dir: &Path) {
    let seed_port = spawn_upgrade_only_server();
    let seed_conf = format!(
        "qwpws::addr=127.0.0.1:{seed_port};qwp_ws_progress=manual;\
         sf_dir={};sender_id=orphan;sf_max_bytes=256;sf_max_total_bytes=1024;",
        sf_dir.display()
    );
    let mut seed_sender = SenderBuilder::from_conf(&seed_conf)
        .unwrap()
        .build()
        .unwrap();
    let mut seed_buf = seed_sender.new_buffer();
    seed_buf
        .table("orphaned")
        .unwrap()
        .symbol("src", "old")
        .unwrap()
        .column_i64("value", 42)
        .unwrap()
        .at_now()
        .unwrap();

    seed_sender.flush(&mut seed_buf).unwrap();
    drop(seed_sender);
}

// ---------- tests ----------

#[test]
fn qwp_ws_round_trip_minimal_message() {
    let (port, rx) = spawn_mock_server();

    let mut sender = SenderBuilder::new(Protocol::QwpWs, "127.0.0.1", port)
        .build()
        .unwrap();
    let mut buf = sender.new_buffer();
    buf.table("trades")
        .unwrap()
        .symbol("sym", "ETH-USD")
        .unwrap()
        .column_i64("qty", 7)
        .unwrap()
        .at_now()
        .unwrap();

    sender.flush(&mut buf).unwrap();

    let result = rx.recv_timeout(Duration::from_secs(5)).unwrap();

    // Validate the upgrade request basics.
    assert!(
        result
            .request_lines
            .first()
            .unwrap()
            .contains("/api/v4/write"),
        "request line: {:?}",
        result.request_lines.first()
    );
    let has_max_version = result
        .request_lines
        .iter()
        .any(|l| l.eq_ignore_ascii_case("X-QWP-Max-Version: 1"));
    assert!(has_max_version, "expected X-QWP-Max-Version header");

    // Validate the QWP message header on the wire.
    let frame = result.received_frames.first().expect("frame received");
    assert!(frame.len() >= 12, "frame too small: {}", frame.len());
    assert_eq!(&frame[0..4], b"QWP1");
    assert_eq!(frame[4], 1, "version");
    assert_eq!(frame[5] & 0x08, 0x08, "FLAG_DELTA_SYMBOL_DICT must be set");
    let table_count = u16::from_le_bytes([frame[6], frame[7]]);
    assert_eq!(table_count, 1);
    let payload_len = u32::from_le_bytes([frame[8], frame[9], frame[10], frame[11]]) as usize;
    assert_eq!(12 + payload_len, frame.len());

    // The payload starts with the delta dictionary section. delta_start = 0,
    // delta_count = 1 (the symbol "ETH-USD") on the first message.
    let payload = &frame[12..];
    assert_eq!(payload[0], 0x00, "delta_start = 0 (varint)");
    assert_eq!(payload[1], 0x01, "delta_count = 1 (varint)");
    // followed by varint(7) "ETH-USD"
    assert_eq!(payload[2], 0x07);
    assert_eq!(&payload[3..10], b"ETH-USD");
}

#[test]
fn qwp_ws_max_buf_size_allows_frame_when_encoded_replay_len_fits_in_all_progress_modes() {
    for progress in [ProgressCase::Background, ProgressCase::Manual] {
        let max = 1024;
        let (port, rx) = spawn_mock_server();
        let builder = SenderBuilder::new(Protocol::QwpWs, "127.0.0.1", port)
            .max_buf_size(max)
            .unwrap();
        let mut sender = match progress {
            ProgressCase::Background => builder.build().unwrap(),
            ProgressCase::Manual => builder
                .qwp_ws_progress(QwpWsProgress::Manual)
                .unwrap()
                .build()
                .unwrap(),
        };
        let mut buf = no_symbol_frame_at_local_hint_overcount_boundary(max);
        let local_hint = buf.len();
        let encoded_len = qwp_ws_replay_encoded_len(&buf);
        assert!(local_hint > max, "local_hint={local_hint}, max={max}");
        assert!(encoded_len <= max, "encoded_len={encoded_len}, max={max}");

        sender.flush(&mut buf).unwrap();
        if progress == ProgressCase::Manual {
            assert!(
                sender.drive_once().unwrap(),
                "{} mode did not report foreground progress",
                progress.name()
            );
        }

        let result = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let frame = result.received_frames.first().expect("frame received");
        assert_eq!(frame.len(), encoded_len, "mode={}", progress.name());
        assert!(frame.len() <= max, "mode={}", progress.name());
    }
}

#[test]
fn qwp_ws_max_buf_size_rejects_oversized_replay_frame_in_all_progress_modes() {
    for progress in [ProgressCase::Background, ProgressCase::Manual] {
        let mut buf = Buffer::qwp_ws_with_max_name_len(127);
        for idx in 0..131 {
            buf.table(format!("t{idx}").as_str())
                .unwrap()
                .column_i64(format!("c{idx}").as_str(), idx)
                .unwrap()
                .at_now()
                .unwrap();
        }
        let encoded_len = qwp_ws_replay_encoded_len(&buf);
        // Strictly greater than 1024 so `encoded_len - 1` is still >= 1024,
        // the `max_buf_size` floor (see `ingress.rs`). At exactly 1024 the
        // builder would reject `max_buf_size(1023)` and the `.unwrap()` below
        // would panic before the flush ever measures the oversized frame.
        assert!(encoded_len > 1024, "encoded_len={encoded_len}");
        // Cap one byte below the actual replay-encoded size so the flush is
        // rejected once the encoder measures the full frame.
        let max = encoded_len - 1;

        let port = spawn_upgrade_only_server();
        let builder = SenderBuilder::new(Protocol::QwpWs, "127.0.0.1", port)
            .max_buf_size(max)
            .unwrap();
        let mut sender = match progress {
            ProgressCase::Background => builder.build().unwrap(),
            ProgressCase::Manual => builder
                .qwp_ws_progress(QwpWsProgress::Manual)
                .unwrap()
                .build()
                .unwrap(),
        };
        let err = sender.flush(&mut buf).unwrap_err();
        assert_eq!(
            err.code(),
            crate::ErrorCode::InvalidApiCall,
            "mode={}",
            progress.name()
        );
        assert_eq!(
            err.msg(),
            format!(
                "Could not flush buffer: QWP/WebSocket encoded message size of {encoded_len} exceeds maximum configured allowed size of {max} bytes."
            ),
            "mode={}",
            progress.name()
        );
        assert!(!buf.is_empty(), "mode={}", progress.name());
    }
}

#[test]
fn qwp_ws_publish_ack_completes_in_all_progress_modes() {
    for progress in [ProgressCase::Background, ProgressCase::Manual] {
        let (port, rx) = spawn_mock_server();
        let mut sender = build_qwp_ws_sender(progress, port);

        let mut buf = sender.new_buffer();
        buf.table("trades")
            .unwrap()
            .symbol("sym", "ETH-USD")
            .unwrap()
            .column_i64("qty", 7)
            .unwrap()
            .at_now()
            .unwrap();

        assert!(!sender.must_close(), "mode={}", progress.name());

        let fsn = sender.flush_and_get_fsn(&mut buf).unwrap().unwrap();
        assert_eq!(fsn, 0, "mode={}", progress.name());
        assert!(buf.is_empty(), "mode={}", progress.name());
        assert!(
            sender.await_acked_fsn(fsn, Duration::from_secs(5)).unwrap(),
            "mode={}",
            progress.name()
        );
        assert_eq!(sender.published_fsn().unwrap(), Some(fsn));
        assert_eq!(sender.acked_fsn().unwrap(), Some(fsn));
        assert!(!sender.must_close(), "mode={}", progress.name());

        let result = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(result.received_frames.len(), 1, "mode={}", progress.name());
        assert_eq!(&result.received_frames[0][0..4], b"QWP1");
    }
}

#[test]
fn qwp_ws_drop_reject_reports_error_and_continues_in_all_progress_modes() {
    for progress in [ProgressCase::Background, ProgressCase::Manual] {
        let (port, rx) = spawn_two_response_server(
            MockQwpResponse::Error {
                status: QWP_STATUS_SCHEMA_MISMATCH,
                wire_seq: FIRST_WIRE_SEQUENCE,
                message: b"bad schema",
            },
            MockQwpResponse::Ok {
                wire_seq: FIRST_WIRE_SEQUENCE + 1,
            },
        );
        let mut sender = build_qwp_ws_sender(progress, port);

        let mut buf = sender.new_buffer();
        buf.table("trades")
            .unwrap()
            .column_i64("qty", 1)
            .unwrap()
            .at_now()
            .unwrap();
        let first_fsn = sender.flush_and_get_fsn(&mut buf).unwrap().unwrap();

        buf.table("trades")
            .unwrap()
            .column_i64("qty", 2)
            .unwrap()
            .at_now()
            .unwrap();
        let second_fsn = sender.flush_and_get_fsn(&mut buf).unwrap().unwrap();

        assert_eq!(first_fsn, 0, "mode={}", progress.name());
        assert_eq!(second_fsn, 1, "mode={}", progress.name());
        assert!(
            sender
                .await_acked_fsn(second_fsn, Duration::from_secs(5))
                .unwrap(),
            "mode={}",
            progress.name()
        );
        assert_eq!(sender.acked_fsn().unwrap(), Some(second_fsn));

        let received = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(
            received.received_frames.len(),
            2,
            "mode={}",
            progress.name()
        );

        let qwp_error = sender.poll_qwp_ws_error().unwrap().unwrap();
        assert_eq!(qwp_error.category, QwpWsErrorCategory::SchemaMismatch);
        assert_eq!(qwp_error.applied_policy, QwpWsErrorPolicy::DropAndContinue);
        assert_eq!(qwp_error.status, Some(QWP_STATUS_SCHEMA_MISMATCH));
        assert_eq!(qwp_error.message.as_deref(), Some("bad schema"));
        assert_eq!(qwp_error.message_sequence, Some(FIRST_WIRE_SEQUENCE));
        assert_eq!(qwp_error.from_fsn, first_fsn);
        assert_eq!(qwp_error.to_fsn, first_fsn);
        assert_eq!(sender.poll_qwp_ws_error().unwrap(), None);
    }
}

#[test]
fn qwp_ws_halt_reject_terminalizes_in_all_progress_modes() {
    for progress in [ProgressCase::Background, ProgressCase::Manual] {
        let (port, rx) = spawn_one_response_server(MockQwpResponse::Error {
            status: QWP_STATUS_PARSE_ERROR,
            wire_seq: FIRST_WIRE_SEQUENCE,
            message: b"bad column",
        });
        let mut sender = build_qwp_ws_sender(progress, port);

        let mut buf = sender.new_buffer();
        buf.table("trades")
            .unwrap()
            .column_i64("qty", 1)
            .unwrap()
            .at_now()
            .unwrap();
        let fsn = sender.flush_and_get_fsn(&mut buf).unwrap().unwrap();
        assert_eq!(fsn, 0, "mode={}", progress.name());

        let err = sender
            .await_acked_fsn(fsn, Duration::from_secs(5))
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::ServerRejection);
        assert!(
            err.msg().contains("bad column"),
            "mode={}, got: {}",
            progress.name(),
            err.msg()
        );
        assert_eq!(
            err.qwp_ws_rejection().map(|error| error.category),
            Some(QwpWsErrorCategory::ParseError),
            "mode={}",
            progress.name()
        );

        let result = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(result.received_frames.len(), 1, "mode={}", progress.name());

        let qwp_error = sender.poll_qwp_ws_error().unwrap().unwrap();
        assert_eq!(qwp_error.category, QwpWsErrorCategory::ParseError);
        assert_eq!(qwp_error.applied_policy, QwpWsErrorPolicy::Halt);
        assert_eq!(qwp_error.status, Some(QWP_STATUS_PARSE_ERROR));
        assert_eq!(qwp_error.message.as_deref(), Some("bad column"));
        assert_eq!(qwp_error.message_sequence, Some(FIRST_WIRE_SEQUENCE));
        assert_eq!(qwp_error.from_fsn, fsn);
        assert_eq!(qwp_error.to_fsn, fsn);

        let mut later = sender.new_buffer();
        later
            .table("trades")
            .unwrap()
            .column_i64("qty", 2)
            .unwrap()
            .at_now()
            .unwrap();
        let later_err = sender.flush(&mut later).unwrap_err();
        assert_eq!(later_err.code(), ErrorCode::ServerRejection);
        assert!(
            later_err.msg().contains("bad column"),
            "mode={}, got: {}",
            progress.name(),
            later_err.msg()
        );
        assert!(!later.is_empty(), "mode={}", progress.name());
        assert!(sender.must_close(), "mode={}", progress.name());
    }
}

#[test]
fn qwp_ws_backpressure_timeout_matches_in_all_progress_modes() {
    for progress in [ProgressCase::Background, ProgressCase::Manual] {
        let (port, frame_rx, release_tx) = spawn_stalled_after_first_frame_server();
        let conf = format!(
            "qwpws::addr=127.0.0.1:{port};\
             qwp_ws_progress={};\
             max_in_flight=1;\
             sf_append_deadline_millis=20;",
            progress.name()
        );
        let mut sender = SenderBuilder::from_conf(conf).unwrap().build().unwrap();

        let mut first = sender.new_buffer();
        first
            .table("trades")
            .unwrap()
            .column_i64("qty", 1)
            .unwrap()
            .at_now()
            .unwrap();
        let first_fsn = sender.flush_and_get_fsn(&mut first).unwrap().unwrap();
        assert_eq!(first_fsn, 0, "mode={}", progress.name());
        if progress == ProgressCase::Manual {
            assert!(sender.drive_once().unwrap(), "mode={}", progress.name());
        }
        assert_eq!(
            &frame_rx.recv_timeout(Duration::from_secs(5)).unwrap()[0..4],
            b"QWP1"
        );

        let mut second = sender.new_buffer();
        second
            .table("trades")
            .unwrap()
            .column_i64("qty", 2)
            .unwrap()
            .at_now()
            .unwrap();
        let err = sender.flush(&mut second).unwrap_err();
        assert_eq!(err.code(), ErrorCode::SocketError);
        assert_eq!(
            err.msg(),
            "QWP/WebSocket flush timed out waiting for local queue capacity",
            "mode={}",
            progress.name()
        );
        assert!(!second.is_empty(), "mode={}", progress.name());
        let _ = release_tx.send(());
    }
}

#[test]
fn qwp_ws_durable_ack_requires_upgrade_echo() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (request_tx, request_rx) = mpsc::channel();

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request_lines = upgrade_mock_stream(&mut stream);
        request_tx.send(request_lines).unwrap();
    });

    let conf = format!("qwpws::addr=127.0.0.1:{port};request_durable_ack=on;");
    let err = SenderBuilder::from_conf(conf).unwrap().build().unwrap_err();
    assert!(
        err.msg().contains("server did not enable durable ACK"),
        "got: {}",
        err.msg()
    );

    let request_lines = request_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(
        request_lines
            .iter()
            .any(|line| line.eq_ignore_ascii_case("X-QWP-Request-Durable-Ack: true"))
    );
    server.join().unwrap();
}

#[test]
fn qwp_ws_durable_ack_completion_waits_for_durable_confirmation_in_all_progress_modes() {
    for progress in [ProgressCase::Background, ProgressCase::Manual] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (allow_ack_tx, allow_ack_rx) = mpsc::channel();
        let (ping_tx, ping_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let request_lines = upgrade_mock_stream_with_durable_ack(&mut stream, true);
            assert!(
                request_lines
                    .iter()
                    .any(|line| line.eq_ignore_ascii_case("X-QWP-Request-Durable-Ack: true"))
            );

            let (_, opcode, payload) = read_frame(&mut stream).unwrap();
            assert_eq!(opcode, 0x2);
            assert_eq!(&payload[0..4], b"QWP1");
            write_qwp_ok_response_with_table_entries(
                &mut stream,
                FIRST_WIRE_SEQUENCE,
                &[("trades", 10)],
            )
            .unwrap();

            allow_ack_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            loop {
                let (_, opcode, payload) = read_frame(&mut stream).unwrap();
                if opcode == 0x9 {
                    write_server_frame(&mut stream, 0xA, &payload, false).unwrap();
                    write_qwp_durable_ack_response(&mut stream, &[("trades", 10)]).unwrap();
                    ping_tx.send(payload).unwrap();
                    break;
                }
            }

            let _ = done_rx.recv_timeout(Duration::from_secs(5));
        });

        let conf = format!(
            "qwpws::addr=127.0.0.1:{port};\
             qwp_ws_progress={};\
             request_durable_ack=on;\
             durable_ack_keepalive_interval_millis=1;",
            progress.name()
        );
        let mut sender = SenderBuilder::from_conf(conf).unwrap().build().unwrap();
        let mut buf = sender.new_buffer();
        buf.table("trades")
            .unwrap()
            .symbol("sym", "ETH-USD")
            .unwrap()
            .column_i64("qty", 7)
            .unwrap()
            .at_now()
            .unwrap();

        let fsn = sender.flush_and_get_fsn(&mut buf).unwrap().unwrap();
        assert!(
            !sender
                .await_acked_fsn(fsn, Duration::from_millis(50))
                .unwrap(),
            "mode={}",
            progress.name()
        );
        assert_eq!(
            sender.acked_fsn().unwrap(),
            None,
            "mode={}",
            progress.name()
        );

        allow_ack_tx.send(()).unwrap();
        assert!(
            sender.await_acked_fsn(fsn, Duration::from_secs(5)).unwrap(),
            "mode={}",
            progress.name()
        );
        assert_eq!(ping_rx.recv_timeout(Duration::from_secs(5)).unwrap(), b"");
        assert_eq!(sender.acked_fsn().unwrap(), Some(fsn));
        done_tx.send(()).unwrap();
        server.join().unwrap();
    }
}

#[test]
fn qwp_ws_sender_fsn_watermarks_and_close_drain_work_in_all_progress_modes() {
    for progress in [ProgressCase::Background, ProgressCase::Manual] {
        let (port, rx) = spawn_mock_server();
        let mut sender = build_qwp_ws_sender(progress, port);
        assert_eq!(sender.published_fsn().unwrap(), None);
        assert_eq!(sender.acked_fsn().unwrap(), None);

        let mut buf = sender.new_buffer();
        buf.table("trades")
            .unwrap()
            .column_i64("qty", 7)
            .unwrap()
            .at_now()
            .unwrap();

        let fsn = sender.flush_and_get_fsn(&mut buf).unwrap().unwrap();
        assert_eq!(fsn, 0, "mode={}", progress.name());
        assert!(buf.is_empty(), "mode={}", progress.name());
        assert_eq!(sender.published_fsn().unwrap(), Some(fsn));

        sender.close_drain().unwrap();
        assert_eq!(sender.acked_fsn().unwrap(), Some(fsn));

        let result = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(result.received_frames.len(), 1, "mode={}", progress.name());
    }
}

#[test]
fn qwp_ws_close_flush_timeout_minus_one_skips_close_drain_wait() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (frame_tx, frame_rx) = mpsc::channel();

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        upgrade_mock_stream(&mut stream);
        let (_fin, _opcode, payload) = read_frame(&mut stream).unwrap();
        frame_tx.send(payload).unwrap();
        thread::sleep(Duration::from_millis(500));
    });

    let conf = format!("qwpws::addr=127.0.0.1:{port};close_flush_timeout_millis=-1;");
    let mut sender = SenderBuilder::from_conf(&conf).unwrap().build().unwrap();
    let mut buf = sender.new_buffer();
    buf.table("trades")
        .unwrap()
        .column_i64("qty", 7)
        .unwrap()
        .at_now()
        .unwrap();

    let fsn = sender.flush_and_get_fsn(&mut buf).unwrap().unwrap();
    assert_eq!(fsn, 0);
    let frame = frame_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(&frame[0..4], b"QWP1");

    let started = Instant::now();
    sender.close_drain().unwrap();
    assert!(
        started.elapsed() < Duration::from_millis(250),
        "close_drain waited despite close_flush_timeout_millis=-1"
    );
    drop(sender);
    server.join().unwrap();
}

/// Run with:
/// `QWP_WS_PUBLIC_BENCH_ROWS=20000000 cargo test --release --manifest-path questdb-rs/Cargo.toml --features sync-sender-qwp-ws qwp_ws_public_sender_batch_throughput_benchmark --lib -- --ignored --nocapture --test-threads=1`
#[test]
#[ignore = "performance benchmark"]
fn qwp_ws_public_sender_batch_throughput_benchmark() {
    let rows =
        qwp_ws_public_bench_env_usize("QWP_WS_PUBLIC_BENCH_ROWS", QWP_WS_PUBLIC_BENCH_DEFAULT_ROWS);
    let batch_size = qwp_ws_public_bench_env_usize(
        "QWP_WS_PUBLIC_BENCH_BATCH_SIZE",
        QWP_WS_PUBLIC_BENCH_DEFAULT_BATCH_SIZE,
    );
    let in_flight = qwp_ws_public_bench_env_usize(
        "QWP_WS_PUBLIC_BENCH_IN_FLIGHT",
        QWP_WS_PUBLIC_BENCH_DEFAULT_IN_FLIGHT,
    );
    let workload = QwpWsPublicBenchWorkload::from_env();
    let prevalidated_names = qwp_ws_public_bench_env_bool("QWP_WS_PUBLIC_BENCH_PREVALIDATED_NAMES");
    assert!(rows > 0);
    assert!(batch_size > 0);
    assert!(in_flight > 1);

    let (port, server) = spawn_ack_each_frame_server();
    let conf = format!("qwpws::addr=127.0.0.1:{port};in_flight_window={in_flight};");
    let mut sender = SenderBuilder::from_conf(conf).unwrap().build().unwrap();
    let mut buffer = sender.new_buffer();

    fill_qwp_ws_public_benchmark_batch(
        &mut buffer,
        workload,
        prevalidated_names,
        0,
        batch_size,
        batch_size,
    );
    sender.flush(&mut buffer).unwrap();

    let started = Instant::now();
    let mut build_elapsed = Duration::ZERO;
    let mut flush_elapsed = Duration::ZERO;
    let mut published_rows = 0usize;
    let mut batch_idx = 0usize;
    while published_rows < rows {
        let rows_in_batch = (rows - published_rows).min(batch_size);

        let build_started = Instant::now();
        fill_qwp_ws_public_benchmark_batch(
            &mut buffer,
            workload,
            prevalidated_names,
            batch_idx,
            batch_size,
            rows_in_batch,
        );
        build_elapsed += build_started.elapsed();

        let flush_started = Instant::now();
        sender.flush(&mut buffer).unwrap();
        flush_elapsed += flush_started.elapsed();

        published_rows += rows_in_batch;
        batch_idx += 1;
    }

    let close_started = Instant::now();
    sender.close_drain().unwrap();
    let close_elapsed = close_started.elapsed();
    let elapsed = started.elapsed();
    drop(sender);

    let binary_frames = server.join().unwrap();
    let expected_frames = rows.div_ceil(batch_size) + 1;
    assert_eq!(binary_frames, expected_frames);

    eprintln!(
        "qwp_ws_public_sender_batch_throughput workload={} prevalidated_names={} rows={} batch_size={} in_flight_window={} frames={} total_ms={} build_ms={} flush_ms={} close_ms={} rows_per_sec={:.2}",
        workload.as_str(),
        prevalidated_names,
        rows,
        batch_size,
        in_flight,
        binary_frames,
        elapsed.as_millis(),
        build_elapsed.as_millis(),
        flush_elapsed.as_millis(),
        close_elapsed.as_millis(),
        rows as f64 / elapsed.as_secs_f64()
    );
    eprintln!(
        "qwp_ws_public_sender_batch_build workload={} prevalidated_names={} rows={} batch_size={} in_flight_window={} elapsed_ms={} rows_per_sec={:.2}",
        workload.as_str(),
        prevalidated_names,
        rows,
        batch_size,
        in_flight,
        build_elapsed.as_millis(),
        rows as f64 / build_elapsed.as_secs_f64()
    );
    eprintln!(
        "qwp_ws_public_sender_batch_flush workload={} prevalidated_names={} rows={} batch_size={} in_flight_window={} elapsed_ms={} rows_per_sec={:.2}",
        workload.as_str(),
        prevalidated_names,
        rows,
        batch_size,
        in_flight,
        flush_elapsed.as_millis(),
        rows as f64 / flush_elapsed.as_secs_f64()
    );
}

#[test]
fn qwp_ws_manual_sender_can_pipeline_before_waiting() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (frames_tx, frames_rx) = mpsc::channel();

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let req_bytes = read_request_until_blank(&mut stream).unwrap();
        let req = String::from_utf8_lossy(&req_bytes).to_string();
        let key = parse_header(&req, "Sec-WebSocket-Key").unwrap();
        let accept = compute_accept(&key);
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: {accept}\r\n\
             X-QWP-Version: 1\r\n\
             \r\n"
        );
        stream.write_all(response.as_bytes()).unwrap();

        let mut received = Vec::new();
        let (_fin, _opcode, first) = read_frame(&mut stream).unwrap();
        received.push(first);
        let (_fin, _opcode, second) = read_frame(&mut stream).unwrap();
        received.push(second);
        frames_tx.send(received).unwrap();

        write_qwp_ok_response(&mut stream, FIRST_WIRE_SEQUENCE + 1).unwrap();
        thread::sleep(Duration::from_millis(50));
    });

    let mut sender = SenderBuilder::new(Protocol::QwpWs, "127.0.0.1", port)
        .max_in_flight(2)
        .unwrap()
        .qwp_ws_progress(QwpWsProgress::Manual)
        .unwrap()
        .build()
        .unwrap();

    let mut first = sender.new_buffer();
    first
        .table("trades")
        .unwrap()
        .symbol("sym", "ETH-USD")
        .unwrap()
        .column_i64("qty", 7)
        .unwrap()
        .at_now()
        .unwrap();
    let first_fsn = sender.flush_and_get_fsn(&mut first).unwrap().unwrap();
    assert!(first.is_empty());
    assert_eq!(first_fsn, 0);

    let mut second = sender.new_buffer();
    second
        .table("trades")
        .unwrap()
        .symbol("sym", "BTC-USD")
        .unwrap()
        .column_i64("qty", 11)
        .unwrap()
        .at_now()
        .unwrap();
    let second_fsn = sender.flush_and_get_fsn(&mut second).unwrap().unwrap();
    assert!(second.is_empty());
    assert_eq!(second_fsn, 1);
    assert_eq!(sender.published_fsn().unwrap(), Some(second_fsn));
    assert_eq!(sender.acked_fsn().unwrap(), None);

    assert!(sender.drive_once().unwrap());
    assert!(sender.drive_once().unwrap());

    let frames = frames_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(frames.len(), 2);
    assert_eq!(&frames[0][0..4], b"QWP1");
    assert_eq!(&frames[1][0..4], b"QWP1");

    assert!(
        sender
            .await_acked_fsn(second_fsn, Duration::from_secs(5))
            .unwrap()
    );
    assert_eq!(sender.acked_fsn().unwrap(), Some(second_fsn));
}

#[test]
fn qwp_ws_manual_sender_advances_ack_watermark_across_rejections() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let req_bytes = read_request_until_blank(&mut stream).unwrap();
        let req = String::from_utf8_lossy(&req_bytes).to_string();
        let key = parse_header(&req, "Sec-WebSocket-Key").unwrap();
        let accept = compute_accept(&key);
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: {accept}\r\n\
             X-QWP-Version: 1\r\n\
             \r\n"
        );
        stream.write_all(response.as_bytes()).unwrap();

        let (_fin, _opcode, _first) = read_frame(&mut stream).unwrap();
        let (_fin, _opcode, _second) = read_frame(&mut stream).unwrap();
        write_qwp_error_response(
            &mut stream,
            QWP_STATUS_SCHEMA_MISMATCH,
            FIRST_WIRE_SEQUENCE,
            b"first bad",
        )
        .unwrap();
        write_qwp_error_response(
            &mut stream,
            QWP_STATUS_SCHEMA_MISMATCH,
            FIRST_WIRE_SEQUENCE + 1,
            b"second bad",
        )
        .unwrap();
        thread::sleep(Duration::from_millis(50));
    });

    let mut sender = SenderBuilder::new(Protocol::QwpWs, "127.0.0.1", port)
        .max_in_flight(2)
        .unwrap()
        .qwp_ws_progress(QwpWsProgress::Manual)
        .unwrap()
        .build()
        .unwrap();

    let mut first = sender.new_buffer();
    first
        .table("trades")
        .unwrap()
        .column_i64("qty", 1)
        .unwrap()
        .at_now()
        .unwrap();
    let first_fsn = sender.flush_and_get_fsn(&mut first).unwrap().unwrap();

    let mut second = sender.new_buffer();
    second
        .table("trades")
        .unwrap()
        .column_i64("qty", 2)
        .unwrap()
        .at_now()
        .unwrap();
    let second_fsn = sender.flush_and_get_fsn(&mut second).unwrap().unwrap();

    assert_eq!(first_fsn, 0);
    assert_eq!(second_fsn, 1);
    assert!(sender.drive_once().unwrap());
    assert!(sender.drive_once().unwrap());
    assert!(
        sender
            .await_acked_fsn(second_fsn, Duration::from_secs(5))
            .unwrap()
    );
    assert_eq!(sender.acked_fsn().unwrap(), Some(second_fsn));

    let first_error = sender.poll_qwp_ws_error().unwrap().unwrap();
    assert_eq!(first_error.category, QwpWsErrorCategory::SchemaMismatch);
    assert_eq!(
        first_error.applied_policy,
        QwpWsErrorPolicy::DropAndContinue
    );
    assert_eq!(first_error.status, Some(QWP_STATUS_SCHEMA_MISMATCH));
    assert_eq!(first_error.message.as_deref(), Some("first bad"));
    assert_eq!(first_error.message_sequence, Some(FIRST_WIRE_SEQUENCE));
    assert_eq!(first_error.from_fsn, first_fsn);
    assert_eq!(first_error.to_fsn, first_fsn);

    let second_error = sender.poll_qwp_ws_error().unwrap().unwrap();
    assert_eq!(second_error.category, QwpWsErrorCategory::SchemaMismatch);
    assert_eq!(
        second_error.applied_policy,
        QwpWsErrorPolicy::DropAndContinue
    );
    assert_eq!(second_error.status, Some(QWP_STATUS_SCHEMA_MISMATCH));
    assert_eq!(second_error.message.as_deref(), Some("second bad"));
    assert_eq!(second_error.message_sequence, Some(FIRST_WIRE_SEQUENCE + 1));
    assert_eq!(second_error.from_fsn, second_fsn);
    assert_eq!(second_error.to_fsn, second_fsn);
    assert_eq!(sender.poll_qwp_ws_error().unwrap(), None);
    assert_eq!(sender.qwp_ws_errors_dropped().unwrap(), 0);
}

#[test]
fn qwp_ws_store_and_forward_config_opens_java_slot_layout() {
    let (port, rx) = spawn_mock_server();
    let sf_dir = tempfile::TempDir::new().unwrap();
    let conf = format!(
        "qwpws::addr=127.0.0.1:{port};sf_dir={};sender_id=primary;",
        sf_dir.path().display()
    );

    let mut sender = SenderBuilder::from_conf(conf).unwrap().build().unwrap();
    let mut buf = sender.new_buffer();
    buf.table("trades")
        .unwrap()
        .column_i64("qty", 7)
        .unwrap()
        .at_now()
        .unwrap();

    sender.flush(&mut buf).unwrap();

    let _ = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(sf_dir.path().join("primary").join(".lock").exists());
}

#[test]
fn qwp_ws_store_and_forward_rejects_one_segment_total_capacity() {
    let sf_dir = tempfile::TempDir::new().unwrap();
    let conf = format!(
        "qwpws::addr=127.0.0.1:1;sf_dir={};sender_id=primary;\
         sf_max_bytes=256;sf_max_total_bytes=256;",
        sf_dir.path().display()
    );

    let err = SenderBuilder::from_conf(conf).unwrap().build().unwrap_err();
    assert_eq!(err.code(), crate::ErrorCode::SocketError);
    assert!(
        err.msg().contains("Store-and-Forward queue") && err.msg().contains("InvalidCapacity"),
        "got: {}",
        err.msg()
    );
    assert!(
        !sf_dir
            .path()
            .join("primary")
            .join("sf-initial.sfa")
            .exists()
    );
}

#[test]
fn qwp_ws_manual_orphan_drainer_replays_sibling_slot() {
    let seed_port = spawn_upgrade_only_server();
    let sf_dir = tempfile::TempDir::new().unwrap();
    let seed_conf = format!(
        "qwpws::addr=127.0.0.1:{seed_port};qwp_ws_progress=manual;\
         sf_dir={};sender_id=orphan;sf_max_bytes=256;sf_max_total_bytes=1024;",
        sf_dir.path().display()
    );
    let mut seed_sender = SenderBuilder::from_conf(&seed_conf)
        .unwrap()
        .build()
        .unwrap();
    let mut seed_buf = seed_sender.new_buffer();
    seed_buf
        .table("orphaned")
        .unwrap()
        .symbol("src", "old")
        .unwrap()
        .column_i64("value", 42)
        .unwrap()
        .at_now()
        .unwrap();

    seed_sender.flush(&mut seed_buf).unwrap();
    drop(seed_sender);

    let (port, rx) = spawn_manual_orphan_drain_server();
    let drain_conf = format!(
        "qwpws::addr=127.0.0.1:{port};qwp_ws_progress=manual;\
         sf_dir={};sender_id=primary;drain_orphans=on;\
         max_background_drainers=1;sf_max_bytes=256;sf_max_total_bytes=1024;",
        sf_dir.path().display()
    );
    let mut sender = SenderBuilder::from_conf(&drain_conf)
        .unwrap()
        .build()
        .unwrap();

    let mut orphan_payload = None;
    for _ in 0..20 {
        let _ = sender.drive_once().unwrap();
        if let Ok(payload) = rx.try_recv() {
            orphan_payload = Some(payload);
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    let payload = orphan_payload.expect("orphan payload was not replayed");
    assert!(!payload.is_empty());
    let orphan_slot = sf_dir.path().join("orphan");
    for _ in 0..20 {
        let _ = sender.drive_once().unwrap();
        if !slot_has_sfa_file(&orphan_slot) {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(!slot_has_sfa_file(&orphan_slot));
    assert!(!sf_dir.path().join("primary").join(".failed").exists());
    assert!(!orphan_slot.join(".failed").exists());
}

#[test]
fn qwp_ws_manual_orphan_drainer_walks_endpoint_list() {
    let sf_dir = tempfile::TempDir::new().unwrap();
    seed_orphan_slot(sf_dir.path());

    let bad_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let bad_port = bad_listener.local_addr().unwrap().port();
    drop(bad_listener);
    let (port, rx) = spawn_manual_orphan_drain_server();
    let drain_conf = format!(
        "qwpws::addr=127.0.0.1:{bad_port},127.0.0.1:{port};qwp_ws_progress=manual;\
         sf_dir={};sender_id=primary;drain_orphans=on;\
         max_background_drainers=1;sf_max_bytes=256;sf_max_total_bytes=1024;",
        sf_dir.path().display()
    );
    let mut sender = SenderBuilder::from_conf(&drain_conf)
        .unwrap()
        .build()
        .unwrap();

    let mut orphan_payload = None;
    for _ in 0..20 {
        let _ = sender.drive_once().unwrap();
        if let Ok(payload) = rx.try_recv() {
            orphan_payload = Some(payload);
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    assert!(
        !orphan_payload
            .expect("orphan payload was not replayed")
            .is_empty()
    );
    assert!(!sf_dir.path().join("orphan").join(".failed").exists());
}

#[test]
fn qwp_ws_manual_orphan_drainer_role_reject_tries_next_endpoint() {
    let sf_dir = tempfile::TempDir::new().unwrap();
    seed_orphan_slot(sf_dir.path());

    let (reject_port, reject_handle) = spawn_role_reject_upgrade_server(2, "REPLICA");
    let (port, rx) = spawn_manual_orphan_drain_server();
    let drain_conf = format!(
        "qwpws::addr=127.0.0.1:{reject_port},127.0.0.1:{port};qwp_ws_progress=manual;\
         sf_dir={};sender_id=primary;drain_orphans=on;\
         max_background_drainers=1;sf_max_bytes=256;sf_max_total_bytes=1024;",
        sf_dir.path().display()
    );
    let mut sender = SenderBuilder::from_conf(&drain_conf)
        .unwrap()
        .build()
        .unwrap();

    let mut orphan_payload = None;
    for _ in 0..20 {
        let _ = sender.drive_once().unwrap();
        if let Ok(payload) = rx.try_recv() {
            orphan_payload = Some(payload);
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    assert!(
        !orphan_payload
            .expect("orphan payload was not replayed")
            .is_empty()
    );
    assert_eq!(reject_handle.join().unwrap(), 2);
    assert!(!sf_dir.path().join("orphan").join(".failed").exists());
}

#[test]
fn qwp_ws_manual_orphan_drainer_terminal_reject_leaves_slot_recoverable() {
    let sf_dir = tempfile::TempDir::new().unwrap();
    seed_orphan_slot(sf_dir.path());

    let (port, rx) = spawn_manual_orphan_reject_server(QWP_STATUS_PARSE_ERROR);
    let drain_conf = format!(
        "qwpws::addr=127.0.0.1:{port};qwp_ws_progress=manual;\
         sf_dir={};sender_id=primary;drain_orphans=on;\
         max_background_drainers=1;sf_max_bytes=256;sf_max_total_bytes=1024;",
        sf_dir.path().display()
    );
    let mut sender = SenderBuilder::from_conf(&drain_conf)
        .unwrap()
        .build()
        .unwrap();

    let orphan_slot = sf_dir.path().join("orphan");
    let mut orphan_payload = None;
    for _ in 0..20 {
        let _ = sender.drive_once().unwrap();
        if orphan_payload.is_none()
            && let Ok(payload) = rx.try_recv()
        {
            orphan_payload = Some(payload);
        }
        if orphan_payload.is_some() && orphan_slot.join(".last_error").exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    assert!(
        !orphan_payload
            .expect("orphan payload was not replayed")
            .is_empty()
    );
    assert!(!orphan_slot.join(".failed").exists());
    assert!(orphan_slot.join(".last_error").exists());
    assert!(slot_has_sfa_file(&orphan_slot));
}

#[test]
fn qwp_ws_background_orphan_close_is_bounded_and_leaves_orphan_recoverable() {
    let seed_port = spawn_upgrade_only_server();
    let sf_dir = tempfile::TempDir::new().unwrap();
    let seed_conf = format!(
        "qwpws::addr=127.0.0.1:{seed_port};qwp_ws_progress=manual;\
         sf_dir={};sender_id=orphan;sf_max_bytes=256;sf_max_total_bytes=1024;",
        sf_dir.path().display()
    );
    let mut seed_sender = SenderBuilder::from_conf(&seed_conf)
        .unwrap()
        .build()
        .unwrap();
    let mut seed_buf = seed_sender.new_buffer();
    seed_buf
        .table("orphaned")
        .unwrap()
        .symbol("src", "old")
        .unwrap()
        .column_i64("value", 42)
        .unwrap()
        .at_now()
        .unwrap();

    seed_sender.flush(&mut seed_buf).unwrap();
    drop(seed_sender);
    let orphan_slot = sf_dir.path().join("orphan");
    assert!(slot_has_sfa_file(&orphan_slot));

    let (port, rx, release_stalled_orphan) = spawn_stalled_background_orphan_drain_server();
    let drain_conf = format!(
        "qwpws::addr=127.0.0.1:{port};\
         sf_dir={};sender_id=primary;drain_orphans=on;\
         max_background_drainers=1;sf_max_bytes=256;sf_max_total_bytes=1024;",
        sf_dir.path().display()
    );
    let mut sender = SenderBuilder::from_conf(&drain_conf)
        .unwrap()
        .build()
        .unwrap();

    let orphan_payload = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(!orphan_payload.is_empty());

    let started = Instant::now();
    sender.close_drain().unwrap();
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_secs(5),
        "background orphan shutdown took {elapsed:?}"
    );
    assert!(!orphan_slot.join(".failed").exists());

    release_stalled_orphan.send(()).unwrap();

    let (recover_port, recover_rx) = spawn_mock_server();
    let recover_conf = format!(
        "qwpws::addr=127.0.0.1:{recover_port};\
         sf_dir={};sender_id=orphan;sf_max_bytes=256;sf_max_total_bytes=1024;",
        sf_dir.path().display()
    );
    let retry_deadline = Instant::now() + Duration::from_secs(5);
    let mut recover_sender = loop {
        match SenderBuilder::from_conf(&recover_conf).unwrap().build() {
            Ok(sender) => break sender,
            Err(err) if Instant::now() < retry_deadline => {
                let _ = err;
                thread::sleep(Duration::from_millis(10));
            }
            Err(err) => panic!("orphan slot was not reusable after close: {err}"),
        }
    };
    recover_sender.close_drain().unwrap();
    let recovered = recover_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(recovered.received_frames.len(), 1);
    assert!(!recovered.received_frames[0].is_empty());
}

#[test]
fn qwp_ws_subsequent_message_reemits_replay_dictionary_and_full_schema() {
    // Run two consecutive flushes against a server that processes both. We
    // build a slightly extended mock inline.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let req_bytes = read_request_until_blank(&mut stream).unwrap();
        let req = String::from_utf8_lossy(&req_bytes).to_string();
        let key = parse_header(&req, "Sec-WebSocket-Key").unwrap();
        let accept = compute_accept(&key);
        let resp = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: {accept}\r\n\
             X-QWP-Version: 1\r\n\
             \r\n"
        );
        stream.write_all(resp.as_bytes()).unwrap();

        for seq in 0u64..2 {
            let (_fin, _op, payload) = read_frame(&mut stream).unwrap();
            tx.send(payload).unwrap();
            let mut ok = vec![0u8];
            ok.extend_from_slice(&seq.to_le_bytes());
            ok.extend_from_slice(&0u16.to_le_bytes());
            write_server_binary_frame(&mut stream, &ok).unwrap();
        }
        thread::sleep(Duration::from_millis(50));
    });

    let mut sender = SenderBuilder::new(Protocol::QwpWs, "127.0.0.1", port)
        .build()
        .unwrap();
    let mut buf = sender.new_buffer();
    buf.table("trades")
        .unwrap()
        .symbol("sym", "BTC-USD")
        .unwrap()
        .column_i64("qty", 1)
        .unwrap()
        .at_now()
        .unwrap();
    sender.flush(&mut buf).unwrap();

    // Second flush reuses the same global symbol. The replay-safe public path
    // still re-emits the dense dictionary prefix so the frame can stand alone
    // after Store-and-Forward recovery or reconnect.
    buf.table("trades")
        .unwrap()
        .symbol("sym", "BTC-USD")
        .unwrap()
        .column_i64("qty", 2)
        .unwrap()
        .at_now()
        .unwrap();
    sender.flush(&mut buf).unwrap();

    let first = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let second = rx.recv_timeout(Duration::from_secs(5)).unwrap();

    assert!(second.len() >= 12);
    let payload = &second[12..];
    // delta_start = 0, delta_count = 1, followed by "BTC-USD".
    assert_eq!(payload[0], 0x00);
    assert_eq!(payload[1], 0x01);
    assert_eq!(payload[2], 0x07);
    assert_eq!(&payload[3..10], b"BTC-USD");

    // Replay-safe public QWP/WS frames always carry the full inline schema
    // (sym, qty) on every frame (at_now() carries no timestamp column).
    assert_eq!(first_table_column_count(&first), 2);
    assert_eq!(first_table_column_count(&second), 2);
}

#[test]
fn qwp_ws_replay_full_schema_used_when_columns_match() {
    // Public QWP/WS now uses the replay-safe encoder. Even when schemas match,
    // every frame carries its full schema so it can be delivered independently.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let req_bytes = read_request_until_blank(&mut stream).unwrap();
        let req = String::from_utf8_lossy(&req_bytes).to_string();
        let key = parse_header(&req, "Sec-WebSocket-Key").unwrap();
        let accept = compute_accept(&key);
        let resp = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: {accept}\r\n\
             X-QWP-Version: 1\r\n\
             \r\n"
        );
        stream.write_all(resp.as_bytes()).unwrap();
        for seq in 0u64..3 {
            let (_fin, _op, payload) = read_frame(&mut stream).unwrap();
            tx.send(payload).unwrap();
            let mut ok = vec![0u8];
            ok.extend_from_slice(&seq.to_le_bytes());
            ok.extend_from_slice(&0u16.to_le_bytes());
            write_server_binary_frame(&mut stream, &ok).unwrap();
        }
        thread::sleep(Duration::from_millis(50));
    });

    let mut sender = SenderBuilder::new(Protocol::QwpWs, "127.0.0.1", port)
        .build()
        .unwrap();

    for qty in 1..=3 {
        let mut buf = sender.new_buffer();
        buf.table("trades")
            .unwrap()
            .column_i64("qty", qty)
            .unwrap()
            .column_f64("price", qty as f64 + 0.5)
            .unwrap()
            .at_now()
            .unwrap();
        sender.flush(&mut buf).unwrap();
    }

    let m1 = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let m2 = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let m3 = rx.recv_timeout(Duration::from_secs(5)).unwrap();

    // Every frame carries its full inline schema (qty, price) so it can be
    // delivered independently.
    assert_eq!(
        first_table_column_count(&m1),
        2,
        "first message: full schema"
    );
    assert_eq!(
        first_table_column_count(&m2),
        2,
        "second message: full schema"
    );
    assert_eq!(
        first_table_column_count(&m3),
        2,
        "third message: full schema"
    );
}

#[test]
fn qwp_ws_full_schema_re_emitted_when_columns_change() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let req_bytes = read_request_until_blank(&mut stream).unwrap();
        let req = String::from_utf8_lossy(&req_bytes).to_string();
        let key = parse_header(&req, "Sec-WebSocket-Key").unwrap();
        let accept = compute_accept(&key);
        let resp = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: {accept}\r\n\
             X-QWP-Version: 1\r\n\
             \r\n"
        );
        stream.write_all(resp.as_bytes()).unwrap();
        for seq in 0u64..2 {
            let (_fin, _op, payload) = read_frame(&mut stream).unwrap();
            tx.send(payload).unwrap();
            let mut ok = vec![0u8];
            ok.extend_from_slice(&seq.to_le_bytes());
            ok.extend_from_slice(&0u16.to_le_bytes());
            write_server_binary_frame(&mut stream, &ok).unwrap();
        }
        thread::sleep(Duration::from_millis(50));
    });

    let mut sender = SenderBuilder::new(Protocol::QwpWs, "127.0.0.1", port)
        .build()
        .unwrap();

    let mut buf = sender.new_buffer();
    buf.table("trades")
        .unwrap()
        .column_i64("qty", 1)
        .unwrap()
        .at_now()
        .unwrap();
    sender.flush(&mut buf).unwrap();

    // Second message has an extra column → fresh schema id, full mode again.
    let mut buf = sender.new_buffer();
    buf.table("trades")
        .unwrap()
        .column_i64("qty", 2)
        .unwrap()
        .column_f64("price", 99.9)
        .unwrap()
        .at_now()
        .unwrap();
    sender.flush(&mut buf).unwrap();

    let m1 = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let m2 = rx.recv_timeout(Duration::from_secs(5)).unwrap();

    // First message: qty only. Second message adds price, so its inline schema
    // re-emits with the new, wider column set.
    assert_eq!(first_table_column_count(&m1), 1);
    assert_eq!(
        first_table_column_count(&m2),
        2,
        "different column set must re-emit the full inline schema"
    );
}

// ---------- wire helpers ----------

fn read_varint(buf: &[u8], pos: &mut usize) -> u64 {
    let mut shift = 0;
    let mut result: u64 = 0;
    loop {
        let b = buf[*pos];
        *pos += 1;
        result |= ((b & 0x7F) as u64) << shift;
        if b & 0x80 == 0 {
            return result;
        }
        shift += 7;
    }
}

/// Skip past message header + delta dictionary section + first table header,
/// returning the inline column count declared in the first table block. The
/// column descriptors ride inline right after this count (no schema-mode byte,
/// no schema id).
fn first_table_column_count(frame: &[u8]) -> u64 {
    let mut pos = 12; // header
    let _delta_start = read_varint(frame, &mut pos);
    let delta_count = read_varint(frame, &mut pos);
    for _ in 0..delta_count {
        let name_len = read_varint(frame, &mut pos) as usize;
        pos += name_len;
    }
    // Table header: name (varint+bytes), row_count varint, column_count varint.
    let name_len = read_varint(frame, &mut pos) as usize;
    pos += name_len;
    let _row_count = read_varint(frame, &mut pos);
    read_varint(frame, &mut pos)
}

#[test]
fn qwp_ws_server_error_response_is_surfaced() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (error_tx, error_rx) = mpsc::channel();

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let req_bytes = read_request_until_blank(&mut stream).unwrap();
        let req = String::from_utf8_lossy(&req_bytes).to_string();
        let key = parse_header(&req, "Sec-WebSocket-Key").unwrap();
        let accept = compute_accept(&key);
        let resp = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: {accept}\r\n\
             X-QWP-Version: 1\r\n\
             \r\n"
        );
        stream.write_all(resp.as_bytes()).unwrap();
        let _ = read_frame(&mut stream).unwrap();

        write_qwp_error_response(
            &mut stream,
            QWP_STATUS_PARSE_ERROR,
            FIRST_WIRE_SEQUENCE,
            b"bad column",
        )
        .unwrap();
        thread::sleep(Duration::from_millis(50));
    });

    let mut sender = SenderBuilder::new(Protocol::QwpWs, "127.0.0.1", port)
        .qwp_ws_error_handler(move |error| {
            error_tx.send(error.clone()).unwrap();
        })
        .unwrap()
        .build()
        .unwrap();
    let mut buf = sender.new_buffer();
    buf.table("trades")
        .unwrap()
        .column_i64("qty", 1)
        .unwrap()
        .at_now()
        .unwrap();

    let first_fsn = sender.flush_and_get_fsn(&mut buf).unwrap().unwrap();
    assert!(buf.is_empty());
    assert_eq!(first_fsn, 0);

    thread::sleep(Duration::from_millis(100));

    buf.table("trades")
        .unwrap()
        .column_i64("qty", 2)
        .unwrap()
        .at_now()
        .unwrap();
    let err = sender.flush(&mut buf).unwrap_err();
    assert_eq!(err.code(), ErrorCode::ServerRejection);
    assert!(
        err.msg().contains("bad column"),
        "expected server error in message, got: {}",
        err.msg()
    );
    assert_eq!(
        err.qwp_ws_rejection().map(|error| error.category),
        Some(QwpWsErrorCategory::ParseError)
    );
    assert!(
        !buf.is_empty(),
        "terminal async error must not clear a newly prepared buffer"
    );

    let callback_error = error_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(callback_error.category, QwpWsErrorCategory::ParseError);
    assert_eq!(callback_error.applied_policy, QwpWsErrorPolicy::Halt);
    assert_eq!(callback_error.from_fsn, first_fsn);

    let qwp_error = sender.poll_qwp_ws_error().unwrap().unwrap();
    assert_eq!(qwp_error.category, QwpWsErrorCategory::ParseError);
    assert_eq!(qwp_error.applied_policy, QwpWsErrorPolicy::Halt);
    assert_eq!(qwp_error.status, Some(QWP_STATUS_PARSE_ERROR));
    assert_eq!(qwp_error.message.as_deref(), Some("bad column"));
    assert_eq!(qwp_error.message_sequence, Some(FIRST_WIRE_SEQUENCE));
    assert_eq!(qwp_error.from_fsn, first_fsn);
    assert_eq!(qwp_error.to_fsn, first_fsn);
    assert_eq!(sender.poll_qwp_ws_error().unwrap(), None);
    assert_eq!(sender.qwp_ws_errors_dropped().unwrap(), 0);
}

#[test]
fn qwp_ws_schema_rejection_drops_and_sender_continues() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    let (error_tx, error_rx) = mpsc::channel();

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let req_bytes = read_request_until_blank(&mut stream).unwrap();
        let req = String::from_utf8_lossy(&req_bytes).to_string();
        let key = parse_header(&req, "Sec-WebSocket-Key").unwrap();
        let accept = compute_accept(&key);
        let resp = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: {accept}\r\n\
             X-QWP-Version: 1\r\n\
             \r\n"
        );
        stream.write_all(resp.as_bytes()).unwrap();

        let mut received_frames = Vec::new();
        let (_fin, _opcode, first) = read_frame(&mut stream).unwrap();
        received_frames.push(first);
        write_qwp_error_response(
            &mut stream,
            QWP_STATUS_SCHEMA_MISMATCH,
            FIRST_WIRE_SEQUENCE,
            b"bad schema",
        )
        .unwrap();

        let (_fin, _opcode, second) = read_frame(&mut stream).unwrap();
        received_frames.push(second);
        write_qwp_ok_response(&mut stream, FIRST_WIRE_SEQUENCE + 1).unwrap();

        tx.send(received_frames).unwrap();
        thread::sleep(Duration::from_millis(50));
    });

    let mut sender = SenderBuilder::new(Protocol::QwpWs, "127.0.0.1", port)
        .qwp_ws_error_handler(move |error| {
            error_tx.send(error.clone()).unwrap();
        })
        .unwrap()
        .build()
        .unwrap();
    let mut buf = sender.new_buffer();
    buf.table("trades")
        .unwrap()
        .column_i64("qty", 1)
        .unwrap()
        .at_now()
        .unwrap();

    let first_fsn = sender.flush_and_get_fsn(&mut buf).unwrap().unwrap();
    assert!(buf.is_empty());
    assert_eq!(first_fsn, 0);

    buf.table("trades")
        .unwrap()
        .column_i64("qty", 2)
        .unwrap()
        .at_now()
        .unwrap();
    let second_fsn = sender.flush_and_get_fsn(&mut buf).unwrap().unwrap();
    assert!(buf.is_empty());
    assert_eq!(second_fsn, 1);

    let received_frames = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(received_frames.len(), 2);
    assert!(
        sender
            .await_acked_fsn(second_fsn, Duration::from_secs(5))
            .unwrap()
    );
    let qwp_error = sender.poll_qwp_ws_error().unwrap().unwrap();
    assert_eq!(qwp_error.category, QwpWsErrorCategory::SchemaMismatch);
    assert_eq!(qwp_error.applied_policy, QwpWsErrorPolicy::DropAndContinue);
    assert_eq!(qwp_error.status, Some(QWP_STATUS_SCHEMA_MISMATCH));
    assert_eq!(qwp_error.message.as_deref(), Some("bad schema"));
    assert_eq!(qwp_error.message_sequence, Some(FIRST_WIRE_SEQUENCE));
    assert_eq!(qwp_error.from_fsn, first_fsn);
    assert_eq!(qwp_error.to_fsn, first_fsn);
    assert_eq!(sender.poll_qwp_ws_error().unwrap(), None);
    assert_eq!(sender.qwp_ws_errors_dropped().unwrap(), 0);

    sender.flush(&mut buf).unwrap();
    let callback_error = error_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(callback_error.category, QwpWsErrorCategory::SchemaMismatch);
    assert_eq!(
        callback_error.applied_policy,
        QwpWsErrorPolicy::DropAndContinue
    );
    assert_eq!(callback_error.from_fsn, first_fsn);
}

#[test]
fn qwp_ws_terminal_close_is_pollable_as_protocol_violation() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (frame_tx, frame_rx) = mpsc::channel();

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        upgrade_mock_stream(&mut stream);

        let (_fin, _opcode, payload) = read_frame(&mut stream).unwrap();
        frame_tx.send(payload).unwrap();
        write_server_close_frame(&mut stream, 1002, "bad frame").unwrap();
        thread::sleep(Duration::from_millis(50));
    });

    let mut sender = SenderBuilder::new(Protocol::QwpWs, "127.0.0.1", port)
        .build()
        .unwrap();
    let mut buf = sender.new_buffer();
    buf.table("trades")
        .unwrap()
        .column_i64("qty", 1)
        .unwrap()
        .at_now()
        .unwrap();

    let fsn = sender.flush_and_get_fsn(&mut buf).unwrap().unwrap();
    assert!(buf.is_empty());
    assert_eq!(fsn, 0);

    let frame = frame_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(&frame[0..4], b"QWP1");

    let mut observed = None;
    for _ in 0..500 {
        if let Some(error) = sender.poll_qwp_ws_error().unwrap() {
            observed = Some(error);
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let close_error = observed.expect("expected terminal close diagnostic");
    assert_eq!(close_error.category, QwpWsErrorCategory::ProtocolViolation);
    assert_eq!(close_error.applied_policy, QwpWsErrorPolicy::Halt);
    assert_eq!(close_error.status, None);
    assert_eq!(close_error.message_sequence, None);
    assert_eq!(
        close_error.message.as_deref(),
        Some("ws-close[1002]: bad frame")
    );
    assert_eq!(close_error.from_fsn, fsn);
    assert_eq!(close_error.to_fsn, fsn);
    assert_eq!(sender.poll_qwp_ws_error().unwrap(), None);
    assert_eq!(sender.qwp_ws_errors_dropped().unwrap(), 0);

    let err = sender.flush(&mut buf).unwrap_err();
    assert!(
        err.msg().contains("ws-close[1002]: bad frame"),
        "expected terminal close in empty flush message, got: {}",
        err.msg()
    );
    assert!(
        buf.is_empty(),
        "empty terminal flush must leave buffer empty"
    );

    buf.table("trades").unwrap().column_i64("qty", 2).unwrap();
    let err = sender.flush(&mut buf).unwrap_err();
    assert!(
        err.msg().contains("ws-close[1002]: bad frame"),
        "expected terminal close to dominate incomplete-row validation, got: {}",
        err.msg()
    );
    assert!(
        !err.msg().contains("Bad call to `flush`"),
        "local buffer validation must not mask terminal close: {}",
        err.msg()
    );
    assert!(
        !buf.is_empty(),
        "terminal async error must not clear a newly prepared buffer"
    );

    buf.at_now().unwrap();
    let err = sender.flush(&mut buf).unwrap_err();
    assert!(
        err.msg().contains("ws-close[1002]: bad frame"),
        "expected terminal close in message, got: {}",
        err.msg()
    );
    assert!(
        !buf.is_empty(),
        "terminal async error must not clear a newly prepared buffer"
    );
    assert!(sender.must_close());
}

fn assert_server_protocol_violation<F>(write_bad_response: F, expected_message: &'static str)
where
    F: FnOnce(&mut TcpStream) -> std::io::Result<()> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (frame_tx, frame_rx) = mpsc::channel();

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        upgrade_mock_stream(&mut stream);

        let (_fin, _opcode, payload) = read_frame(&mut stream).unwrap();
        frame_tx.send(payload).unwrap();
        write_bad_response(&mut stream).unwrap();
        thread::sleep(Duration::from_millis(50));
    });

    let mut sender = SenderBuilder::new(Protocol::QwpWs, "127.0.0.1", port)
        .build()
        .unwrap();
    let mut buf = sender.new_buffer();
    buf.table("trades")
        .unwrap()
        .column_i64("qty", 1)
        .unwrap()
        .at_now()
        .unwrap();

    let fsn = sender.flush_and_get_fsn(&mut buf).unwrap().unwrap();
    let frame = frame_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(&frame[0..4], b"QWP1");

    let mut observed = None;
    for _ in 0..500 {
        if let Some(error) = sender.poll_qwp_ws_error().unwrap() {
            observed = Some(error);
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let protocol_error = observed.expect("expected protocol violation diagnostic");
    assert_eq!(
        protocol_error.category,
        QwpWsErrorCategory::ProtocolViolation
    );
    assert_eq!(protocol_error.applied_policy, QwpWsErrorPolicy::Halt);
    assert_eq!(protocol_error.status, None);
    assert_eq!(protocol_error.message_sequence, None);
    assert_eq!(protocol_error.message.as_deref(), Some(expected_message));
    assert_eq!(protocol_error.from_fsn, fsn);
    assert_eq!(protocol_error.to_fsn, fsn);

    let err = sender.flush(&mut buf).unwrap_err();
    assert!(
        err.msg().contains(expected_message),
        "expected protocol violation in terminal message, got: {}",
        err.msg()
    );
    assert!(sender.must_close());
}

#[test]
fn qwp_ws_masked_server_frame_is_pollable_as_protocol_violation() {
    assert_server_protocol_violation(
        |stream| write_server_frame(stream, 0x2, b"masked", true),
        "WebSocket server frame must not be masked",
    );
}

#[test]
fn qwp_ws_unknown_opcode_is_pollable_as_protocol_violation() {
    assert_server_protocol_violation(
        |stream| write_server_frame(stream, 0x0B, b"", false),
        "Unknown WebSocket opcode: 0xb",
    );
}

#[test]
fn qwp_ws_text_response_is_pollable_as_protocol_violation() {
    assert_server_protocol_violation(
        |stream| write_server_frame(stream, 0x1, b"not-qwp", false),
        "QWP/WebSocket server response was not a binary frame",
    );
}

#[test]
fn qwp_ws_rsv_bits_set_is_protocol_violation() {
    // FIN=1, RSV1=1, opcode=BINARY (0x2) -> 0xC2. No extensions were
    // negotiated during the upgrade, so any RSV bit is a violation.
    assert_server_protocol_violation(
        |stream| write_raw_ws_frame(stream, 0xC2, b"hello"),
        "WebSocket RSV bits are set but no extensions were negotiated",
    );
}

#[test]
fn qwp_ws_continuation_without_prior_data_is_protocol_violation() {
    // FIN=1, opcode=CONTINUATION (0x0) -> 0x80. The client has nothing
    // to continue, so this is a hard violation.
    assert_server_protocol_violation(
        |stream| write_raw_ws_frame(stream, 0x80, b""),
        "Continuation frame without prior data frame",
    );
}

#[test]
fn qwp_ws_new_data_frame_mid_fragment_is_protocol_violation() {
    // FIN=0 BINARY (0x02) starts a fragmented message; the next frame is
    // another FIN=1 BINARY (0x82) instead of a continuation -> violation.
    assert_server_protocol_violation(
        |stream| {
            write_raw_ws_frame(stream, 0x02, b"frag1")?;
            write_raw_ws_frame(stream, 0x82, b"frag2")
        },
        "Unexpected new data frame mid-message",
    );
}

#[test]
fn qwp_ws_fragmented_control_frame_is_protocol_violation() {
    // FIN=0 CLOSE (0x08). RFC 6455 forbids fragmenting control frames.
    // Payload is the close code so it's a syntactically plausible close.
    assert_server_protocol_violation(
        |stream| write_raw_ws_frame(stream, 0x08, &1000u16.to_be_bytes()),
        "WebSocket control frame must not be fragmented",
    );
}

#[test]
fn qwp_ws_close_frame_with_one_byte_payload_is_protocol_violation() {
    // FIN=1 CLOSE (0x88) with a 1-byte payload. Close payloads must be
    // 0 bytes (no code) or >= 2 bytes (code + optional reason).
    assert_server_protocol_violation(
        |stream| write_raw_ws_frame(stream, 0x88, &[0x00]),
        "WebSocket close frame payload length must be 0 or at least 2 bytes",
    );
}

// RFC 6455 §7.4.1 reserves close code 1004 with no defined meaning. It must
// not appear on the wire.
#[test]
fn qwp_ws_close_code_1004_reserved_is_protocol_violation() {
    assert_server_protocol_violation(
        |stream| write_server_close_frame(stream, 1004, ""),
        "WebSocket close frame uses reserved or out-of-range close code: 1004",
    );
}

// 1005 is a sentinel meaning "no status code was received" — only legal in
// application APIs, never on the wire.
#[test]
fn qwp_ws_close_code_1005_sentinel_is_protocol_violation() {
    assert_server_protocol_violation(
        |stream| write_server_close_frame(stream, 1005, ""),
        "WebSocket close frame uses reserved or out-of-range close code: 1005",
    );
}

// 1006 is a sentinel for "abnormal closure" — only legal in application APIs,
// never on the wire.
#[test]
fn qwp_ws_close_code_1006_sentinel_is_protocol_violation() {
    assert_server_protocol_violation(
        |stream| write_server_close_frame(stream, 1006, ""),
        "WebSocket close frame uses reserved or out-of-range close code: 1006",
    );
}

// 1015 is a sentinel for "TLS handshake failure" — only legal in application
// APIs, never on the wire.
#[test]
fn qwp_ws_close_code_1015_sentinel_is_protocol_violation() {
    assert_server_protocol_violation(
        |stream| write_server_close_frame(stream, 1015, ""),
        "WebSocket close frame uses reserved or out-of-range close code: 1015",
    );
}

// Close codes below 1000 are unassigned.
#[test]
fn qwp_ws_close_code_below_1000_is_protocol_violation() {
    assert_server_protocol_violation(
        |stream| write_server_close_frame(stream, 999, ""),
        "WebSocket close frame uses reserved or out-of-range close code: 999",
    );
}

// 1016–2999 are reserved for future protocol-level WebSocket extensions and
// must not appear on the wire today.
#[test]
fn qwp_ws_close_code_reserved_future_range_is_protocol_violation() {
    assert_server_protocol_violation(
        |stream| write_server_close_frame(stream, 1016, ""),
        "WebSocket close frame uses reserved or out-of-range close code: 1016",
    );
}

// Codes >= 5000 are outside the IANA / framework / private-use ranges.
#[test]
fn qwp_ws_close_code_above_4999_is_protocol_violation() {
    assert_server_protocol_violation(
        |stream| write_server_close_frame(stream, 5000, ""),
        "WebSocket close frame uses reserved or out-of-range close code: 5000",
    );
}

// Close reason after the 2-byte code must be valid UTF-8 per RFC 6455 §5.5.1.
// The bytes 0xC3 0x28 are a well-known invalid UTF-8 sequence (overlong /
// incomplete continuation).
#[test]
fn qwp_ws_close_frame_with_invalid_utf8_reason_is_protocol_violation() {
    assert_server_protocol_violation(
        |stream| {
            let mut payload = Vec::new();
            payload.extend_from_slice(&1000u16.to_be_bytes());
            payload.extend_from_slice(&[0xC3, 0x28]);
            write_raw_ws_frame(stream, 0x88, &payload)
        },
        "WebSocket close frame reason is not valid UTF-8",
    );
}

#[test]
fn qwp_ws_high_level_flush_returns_before_ack() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (frame_tx, frame_rx) = mpsc::channel();
    let (ack_tx, ack_rx) = mpsc::channel();

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        upgrade_mock_stream(&mut stream);

        let (_fin, _opcode, payload) = read_frame(&mut stream).unwrap();
        frame_tx.send(payload).unwrap();
        ack_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        write_qwp_ok_response(&mut stream, FIRST_WIRE_SEQUENCE).unwrap();
        thread::sleep(Duration::from_millis(50));
    });

    let mut sender = SenderBuilder::new(Protocol::QwpWs, "127.0.0.1", port)
        .build()
        .unwrap();
    let mut buf = sender.new_buffer();
    buf.table("trades")
        .unwrap()
        .column_i64("qty", 1)
        .unwrap()
        .at_now()
        .unwrap();

    sender.flush(&mut buf).unwrap();
    assert!(buf.is_empty());
    let frame = frame_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(&frame[0..4], b"QWP1");
    ack_tx.send(()).unwrap();
}

#[test]
fn qwp_ws_high_level_flush_and_keep_returns_before_ack_and_preserves_buffer() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (frame_tx, frame_rx) = mpsc::channel();
    let (ack_tx, ack_rx) = mpsc::channel();

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        upgrade_mock_stream(&mut stream);

        let (_fin, _opcode, payload) = read_frame(&mut stream).unwrap();
        frame_tx.send(payload).unwrap();
        ack_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        write_qwp_ok_response(&mut stream, FIRST_WIRE_SEQUENCE).unwrap();
        thread::sleep(Duration::from_millis(50));
    });

    let mut sender = SenderBuilder::new(Protocol::QwpWs, "127.0.0.1", port)
        .build()
        .unwrap();
    let mut buf = sender.new_buffer();
    buf.table("trades")
        .unwrap()
        .column_i64("qty", 1)
        .unwrap()
        .at_now()
        .unwrap();

    sender.flush_and_keep(&buf).unwrap();
    assert!(!buf.is_empty());
    let frame = frame_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(&frame[0..4], b"QWP1");
    ack_tx.send(()).unwrap();
}

#[test]
fn qwp_ws_high_level_flushes_pipeline_before_ack() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (frames_tx, frames_rx) = mpsc::channel();
    let (ack_tx, ack_rx) = mpsc::channel();

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        upgrade_mock_stream(&mut stream);

        let mut frames = Vec::new();
        let (_fin, _opcode, first) = read_frame(&mut stream).unwrap();
        frames.push(first);
        let (_fin, _opcode, second) = read_frame(&mut stream).unwrap();
        frames.push(second);
        frames_tx.send(frames).unwrap();
        ack_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        write_qwp_ok_response(&mut stream, FIRST_WIRE_SEQUENCE + 1).unwrap();
        thread::sleep(Duration::from_millis(50));
    });

    let mut sender = SenderBuilder::new(Protocol::QwpWs, "127.0.0.1", port)
        .max_in_flight(2)
        .unwrap()
        .build()
        .unwrap();

    let mut buf = sender.new_buffer();
    buf.table("trades")
        .unwrap()
        .column_i64("qty", 1)
        .unwrap()
        .at_now()
        .unwrap();
    sender.flush(&mut buf).unwrap();

    buf.table("trades")
        .unwrap()
        .column_i64("qty", 2)
        .unwrap()
        .at_now()
        .unwrap();
    sender.flush(&mut buf).unwrap();

    let frames = frames_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(frames.len(), 2);
    assert!(frames.iter().all(|frame| &frame[0..4] == b"QWP1"));
    ack_tx.send(()).unwrap();
}

// ---------- reconnect tests ----------

/// Two-connection mock: accept one upgrade, drop after reading the first
/// frame (simulating mid-stream socket failure), then accept a *second*
/// upgrade on retry, drain the replayed frame, ack it.
fn spawn_dropping_then_recovering_server() -> (u16, std::sync::mpsc::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = std::sync::mpsc::channel();

    thread::spawn(move || {
        let do_upgrade = |stream: &mut TcpStream| {
            let req_bytes = read_request_until_blank(stream).unwrap();
            let req = String::from_utf8_lossy(&req_bytes).to_string();
            let key = parse_header(&req, "Sec-WebSocket-Key").unwrap();
            let accept = compute_accept(&key);
            let resp = format!(
                "HTTP/1.1 101 Switching Protocols\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Accept: {accept}\r\n\
                 X-QWP-Version: 1\r\n\
                 \r\n"
            );
            stream.write_all(resp.as_bytes()).unwrap();
        };

        // First connection: upgrade, read frame, then drop without acking.
        let (mut s1, _) = listener.accept().unwrap();
        s1.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s1.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        do_upgrade(&mut s1);
        let (_fin, _op, payload) = read_frame(&mut s1).unwrap();
        tx.send(payload).unwrap();
        drop(s1);

        // Second connection: upgrade, read replayed frame, ack it.
        let (mut s2, _) = listener.accept().unwrap();
        s2.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s2.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        do_upgrade(&mut s2);
        let (_fin, _op, payload) = read_frame(&mut s2).unwrap();
        tx.send(payload).unwrap();
        let mut ok = vec![0u8];
        // First post-reconnect message gets sequence 0 from a fresh counter.
        ok.extend_from_slice(&FIRST_WIRE_SEQUENCE.to_le_bytes());
        ok.extend_from_slice(&0u16.to_le_bytes());
        write_server_binary_frame(&mut s2, &ok).unwrap();
        thread::sleep(Duration::from_millis(50));
    });

    (port, rx)
}

#[test]
fn qwp_ws_reconnects_and_replays_in_all_progress_modes() {
    for progress in [ProgressCase::Background, ProgressCase::Manual] {
        let (port, rx) = spawn_dropping_then_recovering_server();
        let builder = SenderBuilder::new(Protocol::QwpWs, "127.0.0.1", port)
            .reconnect_initial_backoff(Duration::from_millis(20))
            .unwrap()
            .reconnect_max_backoff(Duration::from_millis(50))
            .unwrap();
        let mut sender = build_qwp_ws_sender_from_builder(progress, builder);

        let mut buf = sender.new_buffer();
        buf.table("trades")
            .unwrap()
            .symbol("sym", "ETH-USD")
            .unwrap()
            .column_i64("qty", 7)
            .unwrap()
            .at_now()
            .unwrap();

        let fsn = sender.flush_and_get_fsn(&mut buf).unwrap().unwrap();
        assert!(
            sender.await_acked_fsn(fsn, Duration::from_secs(5)).unwrap(),
            "mode={}",
            progress.name()
        );

        // Both wire dumps should be identical QWP messages — replay re-encodes
        // against fresh state but with the same row, so the bytes match.
        let frame1 = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let frame2 = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(&frame1[0..4], b"QWP1");
        assert_eq!(frame1, frame2, "mode={}", progress.name());
    }
}

#[test]
fn qwp_ws_midstream_failure_reconnects_to_next_endpoint() {
    let first_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let first_port = first_listener.local_addr().unwrap().port();
    let second_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let second_port = second_listener.local_addr().unwrap().port();
    let (tx, rx) = std::sync::mpsc::channel();

    let first_tx = tx.clone();
    thread::spawn(move || {
        let (mut stream, _) = first_listener.accept().unwrap();
        perform_server_upgrade(&mut stream).unwrap();
        let (_fin, _op, payload) = read_frame(&mut stream).unwrap();
        first_tx.send(payload).unwrap();
        drop(stream);
    });

    thread::spawn(move || {
        let (mut stream, _) = second_listener.accept().unwrap();
        perform_server_upgrade(&mut stream).unwrap();
        let (_fin, _op, payload) = read_frame(&mut stream).unwrap();
        tx.send(payload).unwrap();
        write_qwp_ok_response(&mut stream, FIRST_WIRE_SEQUENCE).unwrap();
        thread::sleep(Duration::from_millis(50));
    });

    let conf = format!(
        "qwpws::addr=127.0.0.1:{first_port},127.0.0.1:{second_port};\
         reconnect_initial_backoff_millis=1;\
         reconnect_max_backoff_millis=1;\
         reconnect_max_duration_millis=5000;"
    );
    let mut sender = SenderBuilder::from_conf(&conf).unwrap().build().unwrap();

    let mut buf = sender.new_buffer();
    buf.table("trades")
        .unwrap()
        .symbol("sym", "ETH-USD")
        .unwrap()
        .column_i64("qty", 7)
        .unwrap()
        .at_now()
        .unwrap();
    sender.flush(&mut buf).unwrap();

    let frame1 = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let frame2 = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(&frame1[0..4], b"QWP1");
    assert_eq!(frame1, frame2);
}

#[test]
fn qwp_ws_sync_reconnect_retries_failed_attempt() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (payload_tx, payload_rx) = mpsc::channel();
    let (event_tx, event_rx) = mpsc::channel();

    thread::spawn(move || {
        let do_upgrade = |stream: &mut TcpStream| {
            let req_bytes = read_request_until_blank(stream).unwrap();
            let req = String::from_utf8_lossy(&req_bytes).to_string();
            let key = parse_header(&req, "Sec-WebSocket-Key").unwrap();
            let accept = compute_accept(&key);
            let resp = format!(
                "HTTP/1.1 101 Switching Protocols\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Accept: {accept}\r\n\
                 X-QWP-Version: 1\r\n\
                 \r\n"
            );
            stream.write_all(resp.as_bytes()).unwrap();
        };

        let (mut s1, _) = listener.accept().unwrap();
        s1.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s1.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        do_upgrade(&mut s1);
        let (_fin, _op, payload) = read_frame(&mut s1).unwrap();
        payload_tx.send(payload).unwrap();
        drop(s1);

        let (s2, _) = listener.accept().unwrap();
        event_tx.send("failed_reconnect").unwrap();
        drop(s2);

        let (mut s3, _) = listener.accept().unwrap();
        s3.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s3.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        do_upgrade(&mut s3);
        let (_fin, _op, payload) = read_frame(&mut s3).unwrap();
        payload_tx.send(payload).unwrap();
        let mut ok = vec![0u8];
        ok.extend_from_slice(&FIRST_WIRE_SEQUENCE.to_le_bytes());
        ok.extend_from_slice(&0u16.to_le_bytes());
        write_server_binary_frame(&mut s3, &ok).unwrap();
        thread::sleep(Duration::from_millis(50));
    });

    let mut sender = SenderBuilder::new(Protocol::QwpWs, "127.0.0.1", port)
        .reconnect_initial_backoff(Duration::from_millis(1))
        .unwrap()
        .reconnect_max_backoff(Duration::from_millis(1))
        .unwrap()
        .reconnect_max_duration(Duration::from_secs(5))
        .unwrap()
        .build()
        .unwrap();

    let mut buf = sender.new_buffer();
    buf.table("trades")
        .unwrap()
        .symbol("sym", "ETH-USD")
        .unwrap()
        .column_i64("qty", 7)
        .unwrap()
        .at_now()
        .unwrap();

    sender.flush(&mut buf).unwrap();

    assert_eq!(
        event_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        "failed_reconnect"
    );
    let frame1 = payload_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let frame2 = payload_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(&frame1[0..4], b"QWP1");
    assert_eq!(frame1, frame2);
}

#[test]
fn qwp_ws_sync_initial_connect_retry_survives_dropped_upgrade() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (payload_tx, payload_rx) = mpsc::channel();
    let (event_tx, event_rx) = mpsc::channel();

    thread::spawn(move || {
        let (mut first, _) = listener.accept().unwrap();
        first
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        first
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let _ = read_request_until_blank(&mut first).unwrap();
        event_tx.send("dropped_initial_upgrade").unwrap();
        drop(first);

        let (mut second, _) = listener.accept().unwrap();
        second
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        second
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let req_bytes = read_request_until_blank(&mut second).unwrap();
        let req = String::from_utf8_lossy(&req_bytes).to_string();
        let key = parse_header(&req, "Sec-WebSocket-Key").unwrap();
        let accept = compute_accept(&key);
        let resp = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: {accept}\r\n\
             X-QWP-Version: 1\r\n\
             \r\n"
        );
        second.write_all(resp.as_bytes()).unwrap();
        let (_fin, _op, payload) = read_frame(&mut second).unwrap();
        payload_tx.send(payload).unwrap();
        let mut ok = vec![0u8];
        ok.extend_from_slice(&FIRST_WIRE_SEQUENCE.to_le_bytes());
        ok.extend_from_slice(&0u16.to_le_bytes());
        write_server_binary_frame(&mut second, &ok).unwrap();
        thread::sleep(Duration::from_millis(50));
    });

    let mut sender = SenderBuilder::new(Protocol::QwpWs, "127.0.0.1", port)
        .initial_connect_retry(true)
        .unwrap()
        .reconnect_initial_backoff(Duration::from_millis(1))
        .unwrap()
        .reconnect_max_backoff(Duration::from_millis(1))
        .unwrap()
        .reconnect_max_duration(Duration::from_secs(5))
        .unwrap()
        .build()
        .unwrap();

    assert_eq!(
        event_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        "dropped_initial_upgrade"
    );

    let mut buf = sender.new_buffer();
    buf.table("trades")
        .unwrap()
        .symbol("sym", "ETH-USD")
        .unwrap()
        .column_i64("qty", 7)
        .unwrap()
        .at_now()
        .unwrap();
    sender.flush(&mut buf).unwrap();

    let frame = payload_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(&frame[0..4], b"QWP1");
}

#[test]
fn qwp_ws_initial_connect_walks_endpoint_list_in_off_mode() {
    let bad_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let bad_port = bad_listener.local_addr().unwrap().port();
    drop(bad_listener);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let good_port = listener.local_addr().unwrap().port();
    let (payload_tx, payload_rx) = mpsc::channel();

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        perform_server_upgrade(&mut stream).unwrap();
        let (_fin, _op, payload) = read_frame(&mut stream).unwrap();
        payload_tx.send(payload).unwrap();
        write_qwp_ok_response(&mut stream, FIRST_WIRE_SEQUENCE).unwrap();
        thread::sleep(Duration::from_millis(50));
    });

    let conf = format!("qwpws::addr=127.0.0.1:{bad_port},127.0.0.1:{good_port};");
    let mut sender = SenderBuilder::from_conf(&conf).unwrap().build().unwrap();

    let mut buf = sender.new_buffer();
    buf.table("trades")
        .unwrap()
        .symbol("sym", "ETH-USD")
        .unwrap()
        .column_i64("qty", 7)
        .unwrap()
        .at_now()
        .unwrap();
    sender.flush(&mut buf).unwrap();

    let frame = payload_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(&frame[0..4], b"QWP1");
}

#[test]
fn qwp_ws_initial_connect_role_reject_tries_next_endpoint() {
    let first_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let first_port = first_listener.local_addr().unwrap().port();
    let second_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let second_port = second_listener.local_addr().unwrap().port();
    let (payload_tx, payload_rx) = mpsc::channel();

    thread::spawn(move || {
        let (mut stream, _) = first_listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let _ = read_request_until_blank(&mut stream).unwrap();
        stream
            .write_all(
                b"HTTP/1.1 421 Misdirected Request\r\n\
                  Connection: close\r\n\
                  Content-Length: 0\r\n\
                  X-QuestDB-Role: PRIMARY_CATCHUP\r\n\
                  \r\n",
            )
            .unwrap();
    });

    thread::spawn(move || {
        let (mut stream, _) = second_listener.accept().unwrap();
        perform_server_upgrade(&mut stream).unwrap();
        let (_fin, _op, payload) = read_frame(&mut stream).unwrap();
        payload_tx.send(payload).unwrap();
        write_qwp_ok_response(&mut stream, FIRST_WIRE_SEQUENCE).unwrap();
        thread::sleep(Duration::from_millis(50));
    });

    let conf = format!("qwpws::addr=127.0.0.1:{first_port},127.0.0.1:{second_port};");
    let mut sender = SenderBuilder::from_conf(&conf).unwrap().build().unwrap();

    let mut buf = sender.new_buffer();
    buf.table("trades")
        .unwrap()
        .symbol("sym", "ETH-USD")
        .unwrap()
        .column_i64("qty", 7)
        .unwrap()
        .at_now()
        .unwrap();
    sender.flush(&mut buf).unwrap();

    let frame = payload_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(&frame[0..4], b"QWP1");
}

#[test]
fn qwp_ws_initial_connect_retryable_status_tries_next_endpoint() {
    let first_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let first_port = first_listener.local_addr().unwrap().port();
    let second_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let second_port = second_listener.local_addr().unwrap().port();
    let (payload_tx, payload_rx) = mpsc::channel();

    thread::spawn(move || {
        let (mut stream, _) = first_listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let _ = read_request_until_blank(&mut stream).unwrap();
        stream
            .write_all(
                b"HTTP/1.1 500 Internal Server Error\r\n\
                  Connection: close\r\n\
                  Content-Length: 0\r\n\
                  \r\n",
            )
            .unwrap();
    });

    thread::spawn(move || {
        let (mut stream, _) = second_listener.accept().unwrap();
        perform_server_upgrade(&mut stream).unwrap();
        let (_fin, _op, payload) = read_frame(&mut stream).unwrap();
        payload_tx.send(payload).unwrap();
        write_qwp_ok_response(&mut stream, FIRST_WIRE_SEQUENCE).unwrap();
        thread::sleep(Duration::from_millis(50));
    });

    let conf = format!("qwpws::addr=127.0.0.1:{first_port},127.0.0.1:{second_port};");
    let mut sender = SenderBuilder::from_conf(&conf).unwrap().build().unwrap();

    let mut buf = sender.new_buffer();
    buf.table("trades")
        .unwrap()
        .symbol("sym", "ETH-USD")
        .unwrap()
        .column_i64("qty", 7)
        .unwrap()
        .at_now()
        .unwrap();
    sender.flush(&mut buf).unwrap();

    let frame = payload_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(&frame[0..4], b"QWP1");
}

#[test]
fn qwp_ws_initial_connect_mixed_role_and_transport_prefers_role_mismatch() {
    let (role_port, role_handle) = spawn_role_reject_upgrade_server(1, "PRIMARY_CATCHUP");
    let status_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    status_listener.set_nonblocking(true).unwrap();
    let status_port = status_listener.local_addr().unwrap().port();
    let status_handle = thread::spawn(move || {
        let started = Instant::now();
        let mut attempts = 0usize;
        while attempts < 1 && started.elapsed() < Duration::from_secs(5) {
            match status_listener.accept() {
                Ok((mut stream, _)) => {
                    attempts += 1;
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    stream
                        .set_write_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    let _ = read_request_until_blank(&mut stream).unwrap();
                    stream
                        .write_all(
                            b"HTTP/1.1 500 Internal Server Error\r\n\
                              Connection: close\r\n\
                              Content-Length: 0\r\n\
                              \r\n",
                        )
                        .unwrap();
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(err) => panic!("status listener failed: {err}"),
            }
        }
        attempts
    });

    let conf = format!(
        "qwpws::addr=127.0.0.1:{role_port},127.0.0.1:{status_port};\
         initial_connect_retry=off;"
    );
    let result = SenderBuilder::from_conf(&conf).unwrap().build();

    assert_eq!(role_handle.join().unwrap(), 1);
    assert_eq!(status_handle.join().unwrap(), 1);

    let err = result.unwrap_err();
    assert_eq!(err.code(), ErrorCode::RoleMismatch);
    assert!(err.msg().contains("role mismatch"), "got: {}", err.msg());
    assert!(err.msg().contains("PRIMARY_CATCHUP"), "got: {}", err.msg());
    assert!(!err.msg().contains("HTTP status 500"), "got: {}", err.msg());
}

#[test]
fn qwp_ws_initial_connect_unsupported_version_tries_next_endpoint() {
    let first_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let first_port = first_listener.local_addr().unwrap().port();
    let second_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let second_port = second_listener.local_addr().unwrap().port();
    let (payload_tx, payload_rx) = mpsc::channel();

    thread::spawn(move || {
        let (mut stream, _) = first_listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let _ = upgrade_mock_stream_with_version(&mut stream, 2);
    });

    thread::spawn(move || {
        let (mut stream, _) = second_listener.accept().unwrap();
        perform_server_upgrade(&mut stream).unwrap();
        let (_fin, _op, payload) = read_frame(&mut stream).unwrap();
        payload_tx.send(payload).unwrap();
        write_qwp_ok_response(&mut stream, FIRST_WIRE_SEQUENCE).unwrap();
        thread::sleep(Duration::from_millis(50));
    });

    let conf = format!("qwpws::addr=127.0.0.1:{first_port},127.0.0.1:{second_port};");
    let mut sender = SenderBuilder::from_conf(&conf).unwrap().build().unwrap();

    let mut buf = sender.new_buffer();
    buf.table("trades")
        .unwrap()
        .symbol("sym", "ETH-USD")
        .unwrap()
        .column_i64("qty", 7)
        .unwrap()
        .at_now()
        .unwrap();
    sender.flush(&mut buf).unwrap();

    let frame = payload_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(&frame[0..4], b"QWP1");
}

#[test]
fn qwp_ws_sync_initial_retry_unsupported_version_retries_next_round() {
    let first_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let first_port = first_listener.local_addr().unwrap().port();
    let second_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let second_port = second_listener.local_addr().unwrap().port();
    let first_attempts = Arc::new(AtomicUsize::new(0));
    let second_attempts = Arc::new(AtomicUsize::new(0));
    let (payload_tx, payload_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();

    let first_handle = {
        let first_attempts = Arc::clone(&first_attempts);
        thread::spawn(move || {
            let (mut stream, _) = first_listener.accept().unwrap();
            first_attempts.fetch_add(1, Ordering::AcqRel);
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let _ = upgrade_mock_stream_with_version(&mut stream, 2);

            let (mut stream, _) = first_listener.accept().unwrap();
            first_attempts.fetch_add(1, Ordering::AcqRel);
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            perform_server_upgrade(&mut stream).unwrap();
            let (_fin, _op, payload) = read_frame(&mut stream).unwrap();
            payload_tx.send(payload).unwrap();
            write_qwp_ok_response(&mut stream, FIRST_WIRE_SEQUENCE).unwrap();
            let _ = done_rx.recv_timeout(Duration::from_secs(5));
        })
    };
    let second_handle = {
        let second_attempts = Arc::clone(&second_attempts);
        thread::spawn(move || {
            let (mut stream, _) = second_listener.accept().unwrap();
            second_attempts.fetch_add(1, Ordering::AcqRel);
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let _ = upgrade_mock_stream_with_version(&mut stream, 2);
        })
    };

    let conf = format!(
        "qwpws::addr=127.0.0.1:{first_port},127.0.0.1:{second_port};\
         initial_connect_retry=sync;\
         reconnect_initial_backoff_millis=1;\
         reconnect_max_backoff_millis=1;\
         reconnect_max_duration_millis=2000;"
    );
    let mut sender = SenderBuilder::from_conf(&conf).unwrap().build().unwrap();
    let mut buf = sender.new_buffer();
    buf.table("trades")
        .unwrap()
        .symbol("sym", "ETH-USD")
        .unwrap()
        .column_i64("qty", 7)
        .unwrap()
        .at_now()
        .unwrap();
    sender.flush(&mut buf).unwrap();
    done_tx.send(()).unwrap();

    let frame = payload_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    first_handle.join().unwrap();
    second_handle.join().unwrap();

    assert_eq!(&frame[0..4], b"QWP1");
    assert_eq!(first_attempts.load(Ordering::Acquire), 2);
    assert_eq!(second_attempts.load(Ordering::Acquire), 1);
}

#[test]
fn qwp_ws_sync_initial_retry_malformed_101_retries_after_round_exhaustion() {
    let first_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let first_port = first_listener.local_addr().unwrap().port();
    let second_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let second_port = second_listener.local_addr().unwrap().port();
    let first_attempts = Arc::new(AtomicUsize::new(0));
    let second_attempts = Arc::new(AtomicUsize::new(0));
    let (payload_tx, payload_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();

    let first_handle = {
        let first_attempts = Arc::clone(&first_attempts);
        thread::spawn(move || {
            let (mut stream, _) = first_listener.accept().unwrap();
            first_attempts.fetch_add(1, Ordering::AcqRel);
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            upgrade_mock_stream_without_upgrade_header(&mut stream);

            let (mut stream, _) = first_listener.accept().unwrap();
            first_attempts.fetch_add(1, Ordering::AcqRel);
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            perform_server_upgrade(&mut stream).unwrap();
            let (_fin, _op, payload) = read_frame(&mut stream).unwrap();
            payload_tx.send(payload).unwrap();
            write_qwp_ok_response(&mut stream, FIRST_WIRE_SEQUENCE).unwrap();
            let _ = done_rx.recv_timeout(Duration::from_secs(5));
        })
    };
    let second_handle = {
        let second_attempts = Arc::clone(&second_attempts);
        thread::spawn(move || {
            let (mut stream, _) = second_listener.accept().unwrap();
            second_attempts.fetch_add(1, Ordering::AcqRel);
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            upgrade_mock_stream_without_upgrade_header(&mut stream);
        })
    };

    let conf = format!(
        "qwpws::addr=127.0.0.1:{first_port},127.0.0.1:{second_port};\
         initial_connect_retry=sync;\
         reconnect_initial_backoff_millis=1;\
         reconnect_max_backoff_millis=1;\
         reconnect_max_duration_millis=2000;"
    );
    let mut sender = SenderBuilder::from_conf(&conf).unwrap().build().unwrap();
    let mut buf = sender.new_buffer();
    buf.table("trades")
        .unwrap()
        .symbol("sym", "ETH-USD")
        .unwrap()
        .column_i64("qty", 7)
        .unwrap()
        .at_now()
        .unwrap();
    sender.flush(&mut buf).unwrap();
    done_tx.send(()).unwrap();

    let frame = payload_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    first_handle.join().unwrap();
    second_handle.join().unwrap();

    assert_eq!(&frame[0..4], b"QWP1");
    assert_eq!(first_attempts.load(Ordering::Acquire), 2);
    assert_eq!(second_attempts.load(Ordering::Acquire), 1);
}

#[test]
fn qwp_ws_sync_initial_retry_mixed_role_and_transport_prefers_role_mismatch() {
    let (role_port, role_handle) = spawn_role_reject_upgrade_server(1, "PRIMARY_CATCHUP");
    let status_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    status_listener.set_nonblocking(true).unwrap();
    let status_port = status_listener.local_addr().unwrap().port();
    let status_handle = thread::spawn(move || {
        let started = Instant::now();
        let mut attempts = 0usize;
        while attempts < 1 && started.elapsed() < Duration::from_secs(5) {
            match status_listener.accept() {
                Ok((mut stream, _)) => {
                    attempts += 1;
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    stream
                        .set_write_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    let _ = read_request_until_blank(&mut stream).unwrap();
                    stream
                        .write_all(
                            b"HTTP/1.1 500 Internal Server Error\r\n\
                              Connection: close\r\n\
                              Content-Length: 0\r\n\
                              \r\n",
                        )
                        .unwrap();
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(err) => panic!("status listener failed: {err}"),
            }
        }
        attempts
    });

    let conf = format!(
        "qwpws::addr=127.0.0.1:{role_port},127.0.0.1:{status_port};\
         initial_connect_retry=sync;\
         reconnect_initial_backoff_millis=10;\
         reconnect_max_backoff_millis=10;\
         reconnect_max_duration_millis=1;"
    );
    let result = SenderBuilder::from_conf(&conf).unwrap().build();

    assert_eq!(role_handle.join().unwrap(), 1);
    assert_eq!(status_handle.join().unwrap(), 1);

    let err = result.unwrap_err();
    assert_eq!(err.code(), ErrorCode::RoleMismatch);
    assert!(
        err.msg()
            .contains("QWP/WebSocket initial connect retry budget exhausted"),
        "got: {}",
        err.msg()
    );
    assert!(err.msg().contains("role mismatch"), "got: {}", err.msg());
    assert!(err.msg().contains("PRIMARY_CATCHUP"), "got: {}", err.msg());
    assert!(!err.msg().contains("HTTP status 500"), "got: {}", err.msg());
}

#[test]
fn qwp_ws_initial_connect_durable_ack_mismatch_tries_next_endpoint() {
    let first_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let first_port = first_listener.local_addr().unwrap().port();
    let second_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let second_port = second_listener.local_addr().unwrap().port();
    let (payload_tx, payload_rx) = mpsc::channel();

    thread::spawn(move || {
        let (mut stream, _) = first_listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let _ = upgrade_mock_stream_with_durable_ack(&mut stream, false);
    });

    thread::spawn(move || {
        let (mut stream, _) = second_listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let _ = upgrade_mock_stream_with_durable_ack(&mut stream, true);
        let (_fin, _op, payload) = read_frame(&mut stream).unwrap();
        payload_tx.send(payload).unwrap();
        write_qwp_ok_response(&mut stream, FIRST_WIRE_SEQUENCE).unwrap();
        write_qwp_durable_ack_response(&mut stream, &[]).unwrap();
        thread::sleep(Duration::from_millis(50));
    });

    let conf = format!(
        "qwpws::addr=127.0.0.1:{first_port},127.0.0.1:{second_port};\
         request_durable_ack=on;"
    );
    let mut sender = SenderBuilder::from_conf(&conf).unwrap().build().unwrap();

    let mut buf = sender.new_buffer();
    buf.table("trades")
        .unwrap()
        .symbol("sym", "ETH-USD")
        .unwrap()
        .column_i64("qty", 7)
        .unwrap()
        .at_now()
        .unwrap();
    sender.flush(&mut buf).unwrap();

    let frame = payload_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(&frame[0..4], b"QWP1");
}

#[test]
fn qwp_ws_sync_initial_retry_durable_ack_all_role_rejects_terminalize() {
    let (first_port, first_handle) = spawn_role_reject_upgrade_server(1, "REPLICA");
    let (second_port, second_handle) = spawn_role_reject_upgrade_server(1, "REPLICA");

    let conf = format!(
        "qwpws::addr=127.0.0.1:{first_port},127.0.0.1:{second_port};\
         request_durable_ack=on;\
         initial_connect_retry=sync;\
         reconnect_initial_backoff_millis=100;\
         reconnect_max_backoff_millis=100;\
         reconnect_max_duration_millis=500;"
    );
    let err = SenderBuilder::from_conf(&conf)
        .unwrap()
        .build()
        .unwrap_err();

    assert_eq!(err.code(), ErrorCode::ProtocolVersionError);
    assert!(
        err.msg().contains("server did not enable durable ACK"),
        "got: {}",
        err.msg()
    );
    assert_eq!(first_handle.join().unwrap(), 1);
    assert_eq!(second_handle.join().unwrap(), 1);
}

#[test]
fn qwp_ws_sync_initial_retry_budget_exhaustion_reports_context() {
    let probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);

    let conf = format!(
        "qwpws::addr=127.0.0.1:{port};\
         initial_connect_retry=sync;\
         reconnect_initial_backoff_millis=10;\
         reconnect_max_backoff_millis=10;\
         reconnect_max_duration_millis=1;"
    );
    let err = SenderBuilder::from_conf(&conf)
        .unwrap()
        .build()
        .unwrap_err();

    assert_eq!(err.code(), ErrorCode::SocketError);
    assert!(
        err.msg()
            .contains("QWP/WebSocket initial connect retry budget exhausted"),
        "got: {}",
        err.msg()
    );
    assert!(err.msg().contains("attempts=1"), "got: {}", err.msg());
    assert!(err.msg().contains("elapsed_ms="), "got: {}", err.msg());
    assert!(
        err.msg()
            .contains("last_error=QWP/WebSocket all endpoints unreachable"),
        "got: {}",
        err.msg()
    );
}

#[test]
fn qwp_ws_sync_initial_retry_resets_non_healthy_between_rounds() {
    let first_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    first_listener.set_nonblocking(true).unwrap();
    let first_port = first_listener.local_addr().unwrap().port();
    let second_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    second_listener.set_nonblocking(true).unwrap();
    let second_port = second_listener.local_addr().unwrap().port();

    let first_attempts = Arc::new(AtomicUsize::new(0));
    let second_attempts = Arc::new(AtomicUsize::new(0));
    let done = Arc::new(AtomicBool::new(false));
    let (payload_tx, payload_rx) = mpsc::channel();
    let first_attempts_thread = Arc::clone(&first_attempts);
    let done_first_thread = Arc::clone(&done);
    let first_thread = thread::spawn(move || {
        while !done_first_thread.load(Ordering::Acquire) {
            match first_listener.accept() {
                Ok((mut stream, _)) => {
                    let attempt = first_attempts_thread.fetch_add(1, Ordering::AcqRel) + 1;
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    stream
                        .set_write_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    if attempt == 1 {
                        let _ = read_request_until_blank(&mut stream).unwrap();
                        stream
                            .write_all(
                                b"HTTP/1.1 421 Misdirected Request\r\n\
                                  Connection: close\r\n\
                                  Content-Length: 0\r\n\
                                  X-QuestDB-Role: REPLICA\r\n\
                                  \r\n",
                            )
                            .unwrap();
                    } else {
                        perform_server_upgrade(&mut stream).unwrap();
                        let (_fin, _op, payload) = read_frame(&mut stream).unwrap();
                        payload_tx.send(payload).unwrap();
                        write_qwp_ok_response(&mut stream, FIRST_WIRE_SEQUENCE).unwrap();
                        thread::sleep(Duration::from_millis(50));
                        done_first_thread.store(true, Ordering::Release);
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(err) => panic!("first listener failed: {err}"),
            }
        }
    });

    let second_attempts_thread = Arc::clone(&second_attempts);
    let done_second_thread = Arc::clone(&done);
    let second_thread = thread::spawn(move || {
        while !done_second_thread.load(Ordering::Acquire) {
            match second_listener.accept() {
                Ok((mut stream, _)) => {
                    second_attempts_thread.fetch_add(1, Ordering::AcqRel);
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    stream
                        .set_write_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    let _ = read_request_until_blank(&mut stream).unwrap();
                    stream
                        .write_all(
                            b"HTTP/1.1 500 Internal Server Error\r\n\
                              Connection: close\r\n\
                              Content-Length: 0\r\n\
                              \r\n",
                        )
                        .unwrap();
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(err) => panic!("second listener failed: {err}"),
            }
        }
    });

    let conf = format!(
        "qwpws::addr=127.0.0.1:{first_port},127.0.0.1:{second_port};\
         initial_connect_retry=sync;\
         reconnect_initial_backoff_millis=100;\
         reconnect_max_backoff_millis=100;\
         reconnect_max_duration_millis=5000;"
    );
    let mut sender = SenderBuilder::from_conf(&conf).unwrap().build().unwrap();

    let mut buf = sender.new_buffer();
    buf.table("trades")
        .unwrap()
        .symbol("sym", "ETH-USD")
        .unwrap()
        .column_i64("qty", 7)
        .unwrap()
        .at_now()
        .unwrap();
    sender.flush(&mut buf).unwrap();

    let frame = payload_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(&frame[0..4], b"QWP1");
    done.store(true, Ordering::Release);
    first_thread.join().unwrap();
    second_thread.join().unwrap();
    assert_eq!(first_attempts.load(Ordering::Acquire), 2);
    assert_eq!(second_attempts.load(Ordering::Acquire), 1);
}

#[test]
fn qwp_ws_async_initial_connect_background_can_flush() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (payload_tx, payload_rx) = mpsc::channel();

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        perform_server_upgrade(&mut stream).unwrap();
        let (_fin, _op, payload) = read_frame(&mut stream).unwrap();
        payload_tx.send(payload).unwrap();
        write_qwp_ok_response(&mut stream, FIRST_WIRE_SEQUENCE).unwrap();
        thread::sleep(Duration::from_millis(50));
    });

    let conf = format!("qwpws::addr=127.0.0.1:{port};initial_connect_retry=async;");
    let mut sender = SenderBuilder::from_conf(&conf).unwrap().build().unwrap();

    let mut buf = sender.new_buffer();
    buf.table("trades")
        .unwrap()
        .symbol("sym", "ETH-USD")
        .unwrap()
        .column_i64("qty", 7)
        .unwrap()
        .at_now()
        .unwrap();
    sender.flush(&mut buf).unwrap();

    let frame = payload_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(&frame[0..4], b"QWP1");
}

#[test]
fn qwp_ws_async_initial_connect_rejects_manual_progress() {
    let conf = "qwpws::addr=127.0.0.1:1;\
                initial_connect_retry=async;\
                qwp_ws_progress=manual;";
    let err = SenderBuilder::from_conf(conf).unwrap().build().unwrap_err();
    assert!(
        err.msg().contains("initial_connect_retry=async")
            && err.msg().contains("background progress"),
        "got: {}",
        err.msg()
    );
}

#[test]
fn qwp_ws_from_conf_parses_java_reconnect_keys() {
    // Just exercises the parser surface: every new key is accepted. Building
    // would also work but isn't necessary for parser coverage.
    let conf = "qwpws::addr=localhost:9000;\
                max_in_flight=64;\
                reconnect_max_duration_millis=20000;\
                reconnect_initial_backoff_millis=200;\
                reconnect_max_backoff_millis=2000;\
                initial_connect_retry=on;\
                close_flush_timeout_millis=120000;\
                request_durable_ack=on;\
                durable_ack_keepalive_interval_millis=250;";
    SenderBuilder::from_conf(conf).unwrap();

    let disabled_keepalive = "qwpws::addr=localhost:9000;durable_ack_keepalive_interval_millis=0;";
    SenderBuilder::from_conf(disabled_keepalive).unwrap();

    let conf_sync = "qwpws::addr=localhost:9000;initial_connect_retry=sync;";
    SenderBuilder::from_conf(conf_sync).unwrap();

    let conf_false = "qwpws::addr=localhost:9000;initial_connect_retry=false;";
    SenderBuilder::from_conf(conf_false).unwrap();

    let conf_multi = "qwpws::addr=localhost:9000, localhost:9001;addr=localhost:9002;";
    SenderBuilder::from_conf(conf_multi).unwrap();

    let zone_ignored = "qwpws::addr=localhost:9000;zone=dc-amsterdam;";
    SenderBuilder::from_conf(zone_ignored).unwrap();

    #[cfg(feature = "sync-sender-tcp")]
    {
        let tcp_zone = "tcp::addr=localhost:9009;zone=dc-amsterdam;";
        SenderBuilder::from_conf(tcp_zone).unwrap();
    }

    // Java Sender ignores unknown keys; this is parser compatibility, not
    // target-selection support.
    let target_ignored = "qwpws::addr=localhost:9000;target=primary;";
    SenderBuilder::from_conf(target_ignored).unwrap();

    let duplicate = "qwpws::addr=localhost:9000,localhost:9000;";
    let err = SenderBuilder::from_conf(duplicate).unwrap_err();
    assert!(err.msg().contains("duplicate"), "got: {}", err.msg());

    let duplicate_effective_port = "qwpws::addr=localhost:9000,localhost:09000;";
    let err = SenderBuilder::from_conf(duplicate_effective_port).unwrap_err();
    assert!(
        err.msg().contains("duplicate") && err.msg().contains("localhost:9000"),
        "got: {}",
        err.msg()
    );

    let empty_entry = "qwpws::addr=localhost:9000,,localhost:9001;";
    let err = SenderBuilder::from_conf(empty_entry).unwrap_err();
    assert!(err.msg().contains("empty entry"), "got: {}", err.msg());

    let empty_host = "qwpws::addr=:9000;";
    let err = SenderBuilder::from_conf(empty_host).unwrap_err();
    assert!(err.msg().contains("empty host"), "got: {}", err.msg());

    let invalid_port = "qwpws::addr=localhost:notaport;";
    let err = SenderBuilder::from_conf(invalid_port).unwrap_err();
    assert!(err.msg().contains("invalid port"), "got: {}", err.msg());

    let zero_port = "qwpws::addr=localhost:0;";
    let err = SenderBuilder::from_conf(zero_port).unwrap_err();
    assert!(err.msg().contains("invalid port"), "got: {}", err.msg());

    #[cfg(feature = "sync-sender-tcp")]
    {
        let repeated_tcp_addr = "tcp::addr=localhost:9009;addr=localhost:9010;";
        let err = SenderBuilder::from_conf(repeated_tcp_addr).unwrap_err();
        assert!(
            err.msg().contains("DuplicateKey") || err.msg().contains("duplicate"),
            "got: {}",
            err.msg()
        );
    }

    let conf_async = "qwpws::addr=localhost:9000;initial_connect_retry=async;";
    SenderBuilder::from_conf(conf_async).unwrap();

    let bad = "qwpws::addr=localhost:9000;initial_connect_retry=maybe;";
    let err = SenderBuilder::from_conf(bad).unwrap_err();
    assert!(
        err.msg().contains("initial_connect_retry"),
        "got: {}",
        err.msg()
    );
}

// ---------- X-QWP-Max-Batch-Size handling ----------

fn upgrade_mock_stream_with_max_batch_size(
    stream: &mut TcpStream,
    max_batch_size: Option<usize>,
) -> Vec<String> {
    let req_bytes = read_request_until_blank(stream).unwrap();
    let req = String::from_utf8_lossy(&req_bytes).to_string();
    let request_lines: Vec<String> = req
        .split("\r\n")
        .take_while(|l| !l.is_empty())
        .map(String::from)
        .collect();
    let key = parse_header(&req, "Sec-WebSocket-Key").expect("missing Sec-WebSocket-Key");
    let accept = compute_accept(&key);
    let batch_size_header = match max_batch_size {
        Some(n) => format!("X-QWP-Max-Batch-Size: {n}\r\n"),
        None => String::new(),
    };
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {accept}\r\n\
         X-QWP-Version: 1\r\n\
         {batch_size_header}\
         \r\n"
    );
    stream.write_all(response.as_bytes()).unwrap();
    request_lines
}

fn spawn_max_batch_size_server(max_batch_size: Option<usize>) -> (u16, mpsc::Receiver<MockResult>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request_lines = upgrade_mock_stream_with_max_batch_size(&mut stream, max_batch_size);
        let mut received_frames = Vec::new();
        if let Ok((_fin, _opcode, payload)) = read_frame(&mut stream) {
            received_frames.push(payload);
            let _ = write_qwp_ok_response(&mut stream, FIRST_WIRE_SEQUENCE);
        }
        let _ = tx.send(MockResult {
            request_lines,
            received_frames,
        });
        thread::sleep(Duration::from_millis(50));
    });
    (port, rx)
}

fn spawn_max_batch_size_upgrade_only_server(max_batch_size: Option<usize>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        upgrade_mock_stream_with_max_batch_size(&mut stream, max_batch_size);
        thread::sleep(Duration::from_millis(200));
    });
    port
}

fn build_buffer_with_payload_bytes(target_encoded_len: usize) -> Buffer {
    let mut buf = Buffer::qwp_ws_with_max_name_len(127);
    buf.table("t").unwrap();
    let col_name = "v";
    let value_len = target_encoded_len;
    let big_value: String = "x".repeat(value_len);
    buf.column_str(col_name, big_value.as_str())
        .unwrap()
        .at_now()
        .unwrap();
    buf
}

#[test]
fn server_max_batch_size_clamps_flush_below_configured_max_in_all_progress_modes() {
    for progress in [ProgressCase::Background, ProgressCase::Manual] {
        let server_cap: usize = 512;
        let port = spawn_max_batch_size_upgrade_only_server(Some(server_cap));
        let builder = SenderBuilder::new(Protocol::QwpWs, "127.0.0.1", port)
            .max_buf_size(100 * 1024 * 1024)
            .unwrap();
        let mut sender = build_qwp_ws_sender_from_builder(progress, builder);

        let mut buf = build_buffer_with_payload_bytes(server_cap + 200);
        let encoded_len = qwp_ws_replay_encoded_len(&buf);
        assert!(
            encoded_len > server_cap,
            "mode={}: encoded_len={encoded_len} must exceed server_cap={server_cap}",
            progress.name()
        );

        let err = sender.flush(&mut buf).unwrap_err();
        assert_eq!(
            err.code(),
            crate::ErrorCode::InvalidApiCall,
            "mode={}",
            progress.name()
        );
        assert!(
            err.msg()
                .contains("exceeds maximum configured allowed size"),
            "mode={}: got: {}",
            progress.name(),
            err.msg()
        );
        assert!(
            err.msg().contains(&server_cap.to_string()),
            "mode={}: error should reference server cap {server_cap}, got: {}",
            progress.name(),
            err.msg()
        );
    }
}

#[test]
fn server_max_batch_size_allows_flush_when_encoded_fits_in_all_progress_modes() {
    for progress in [ProgressCase::Background, ProgressCase::Manual] {
        let server_cap: usize = 100 * 1024;
        let (port, rx) = spawn_max_batch_size_server(Some(server_cap));
        let builder = SenderBuilder::new(Protocol::QwpWs, "127.0.0.1", port)
            .max_buf_size(100 * 1024 * 1024)
            .unwrap();
        let mut sender = build_qwp_ws_sender_from_builder(progress, builder);

        let mut buf = Buffer::qwp_ws_with_max_name_len(127);
        buf.table("t")
            .unwrap()
            .column_i64("v", 42)
            .unwrap()
            .at_now()
            .unwrap();
        let encoded_len = qwp_ws_replay_encoded_len(&buf);
        assert!(
            encoded_len < server_cap,
            "mode={}: encoded_len={encoded_len} must be under server_cap={server_cap}",
            progress.name()
        );

        sender.flush(&mut buf).unwrap();
        if progress == ProgressCase::Manual {
            assert!(sender.drive_once().unwrap());
        }
        let result = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(result.received_frames.len(), 1, "mode={}", progress.name());
    }
}

#[test]
fn absent_server_max_batch_size_falls_back_to_configured_max_in_all_progress_modes() {
    for progress in [ProgressCase::Background, ProgressCase::Manual] {
        let configured_max: usize = 1024;
        let port = spawn_max_batch_size_upgrade_only_server(None);
        let builder = SenderBuilder::new(Protocol::QwpWs, "127.0.0.1", port)
            .max_buf_size(configured_max)
            .unwrap();
        let mut sender = build_qwp_ws_sender_from_builder(progress, builder);

        let mut buf = build_buffer_with_payload_bytes(configured_max + 200);
        let encoded_len = qwp_ws_replay_encoded_len(&buf);
        assert!(
            encoded_len > configured_max,
            "mode={}: encoded_len={encoded_len} must exceed configured_max={configured_max}",
            progress.name()
        );

        let err = sender.flush(&mut buf).unwrap_err();
        assert_eq!(
            err.code(),
            crate::ErrorCode::InvalidApiCall,
            "mode={}",
            progress.name()
        );
        assert!(
            err.msg().contains(&configured_max.to_string()),
            "mode={}: error should reference configured max {configured_max}, got: {}",
            progress.name(),
            err.msg()
        );
    }
}

#[test]
fn configured_max_wins_when_smaller_than_server_cap_in_all_progress_modes() {
    for progress in [ProgressCase::Background, ProgressCase::Manual] {
        let configured_max: usize = 1024;
        let server_cap: usize = 16 * 1024 * 1024;
        let port = spawn_max_batch_size_upgrade_only_server(Some(server_cap));
        let builder = SenderBuilder::new(Protocol::QwpWs, "127.0.0.1", port)
            .max_buf_size(configured_max)
            .unwrap();
        let mut sender = build_qwp_ws_sender_from_builder(progress, builder);

        let mut buf = build_buffer_with_payload_bytes(configured_max + 200);
        let encoded_len = qwp_ws_replay_encoded_len(&buf);
        assert!(
            encoded_len > configured_max,
            "mode={}: encoded_len={encoded_len} must exceed configured_max={configured_max}",
            progress.name()
        );
        assert!(
            encoded_len < server_cap,
            "mode={}: encoded_len={encoded_len} must be under server_cap={server_cap}",
            progress.name()
        );

        let err = sender.flush(&mut buf).unwrap_err();
        assert_eq!(
            err.code(),
            crate::ErrorCode::InvalidApiCall,
            "mode={}",
            progress.name()
        );
        assert!(
            err.msg().contains(&configured_max.to_string()),
            "mode={}: error should reference configured max {configured_max}, got: {}",
            progress.name(),
            err.msg()
        );
    }
}

#[test]
fn server_cap_prevents_message_too_big_by_rejecting_locally_in_all_progress_modes() {
    for progress in [ProgressCase::Background, ProgressCase::Manual] {
        let server_cap: usize = 2048;
        let (port, _rx) = spawn_max_batch_size_server(Some(server_cap));
        let builder = SenderBuilder::new(Protocol::QwpWs, "127.0.0.1", port)
            .max_buf_size(100 * 1024 * 1024)
            .unwrap();
        let mut sender = build_qwp_ws_sender_from_builder(progress, builder);

        let mut small_buf = Buffer::qwp_ws_with_max_name_len(127);
        small_buf
            .table("t")
            .unwrap()
            .column_i64("v", 1)
            .unwrap()
            .at_now()
            .unwrap();
        sender.flush(&mut small_buf).unwrap();
        if progress == ProgressCase::Manual {
            assert!(sender.drive_once().unwrap());
        }

        let mut big_buf = build_buffer_with_payload_bytes(server_cap + 500);
        let encoded_len = qwp_ws_replay_encoded_len(&big_buf);
        assert!(
            encoded_len > server_cap,
            "mode={}: encoded_len={encoded_len} must exceed server_cap={server_cap}",
            progress.name()
        );

        let err = sender.flush(&mut big_buf).unwrap_err();
        assert_eq!(
            err.code(),
            crate::ErrorCode::InvalidApiCall,
            "mode={}: must get local InvalidApiCall, not a server error",
            progress.name()
        );
    }
}

#[test]
fn server_cap_at_exact_boundary_allows_flush_in_all_progress_modes() {
    for progress in [ProgressCase::Background, ProgressCase::Manual] {
        let mut buf = Buffer::qwp_ws_with_max_name_len(127);
        buf.table("t")
            .unwrap()
            .column_i64("v", 42)
            .unwrap()
            .at_now()
            .unwrap();
        let encoded_len = qwp_ws_replay_encoded_len(&buf);

        let server_cap = encoded_len;
        let (port, rx) = spawn_max_batch_size_server(Some(server_cap));
        let builder = SenderBuilder::new(Protocol::QwpWs, "127.0.0.1", port)
            .max_buf_size(100 * 1024 * 1024)
            .unwrap();
        let mut sender = build_qwp_ws_sender_from_builder(progress, builder);

        sender.flush(&mut buf).unwrap();
        if progress == ProgressCase::Manual {
            assert!(sender.drive_once().unwrap());
        }
        let result = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(result.received_frames.len(), 1, "mode={}", progress.name());
        assert_eq!(
            result.received_frames[0].len(),
            encoded_len,
            "mode={}",
            progress.name()
        );
    }
}

#[test]
fn server_cap_one_byte_below_encoded_len_rejects_flush_in_all_progress_modes() {
    for progress in [ProgressCase::Background, ProgressCase::Manual] {
        let mut buf = Buffer::qwp_ws_with_max_name_len(127);
        buf.table("t")
            .unwrap()
            .column_i64("v", 42)
            .unwrap()
            .at_now()
            .unwrap();
        let encoded_len = qwp_ws_replay_encoded_len(&buf);

        let server_cap = encoded_len - 1;
        let port = spawn_max_batch_size_upgrade_only_server(Some(server_cap));
        let builder = SenderBuilder::new(Protocol::QwpWs, "127.0.0.1", port)
            .max_buf_size(100 * 1024 * 1024)
            .unwrap();
        let mut sender = build_qwp_ws_sender_from_builder(progress, builder);

        let err = sender.flush(&mut buf).unwrap_err();
        assert_eq!(
            err.code(),
            crate::ErrorCode::InvalidApiCall,
            "mode={}",
            progress.name()
        );
        assert!(
            err.msg().contains(&server_cap.to_string()),
            "mode={}: error should reference server cap {server_cap}, got: {}",
            progress.name(),
            err.msg()
        );
    }
}
