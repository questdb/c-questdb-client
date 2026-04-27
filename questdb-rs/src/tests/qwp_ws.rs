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
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use crate::ingress::{Protocol, SenderBuilder};

const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

// ---------- mock server ----------

#[allow(dead_code)]
struct MockResult {
    request_lines: Vec<String>,
    received_frames: Vec<Vec<u8>>,
}

fn read_request_until_blank<R: Read>(stream: &mut R) -> std::io::Result<Vec<u8>> {
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

fn parse_header(req: &str, name: &str) -> Option<String> {
    for line in req.split("\r\n").skip(1) {
        if let Some((k, v)) = line.split_once(':')
            && k.trim().eq_ignore_ascii_case(name)
        {
            return Some(v.trim().to_string());
        }
    }
    None
}

fn read_frame(stream: &mut TcpStream) -> std::io::Result<(bool, u8, Vec<u8>)> {
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

fn write_server_binary_frame(stream: &mut TcpStream, payload: &[u8]) -> std::io::Result<()> {
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

fn compute_accept(key_b64: &str) -> String {
    use base64ct::{Base64, Encoding};
    let combined = format!("{key_b64}{WS_GUID}");
    let digest = sha1(combined.as_bytes());
    Base64::encode_string(&digest)
}

// Mirror of the production SHA-1 used by the sender, reproduced here to
// validate the upgrade handshake from the server side without poking at
// internals. ~50 lines is cheaper than another dependency.
fn sha1(input: &[u8]) -> [u8; 20] {
    let (mut h0, mut h1, mut h2, mut h3, mut h4) =
        (0x67452301u32, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0);
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
/// response (status=0x00, sequence=1, table_count=0).
fn spawn_mock_server() -> (u16, mpsc::Receiver<MockResult>) {
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
             X-QWP-Version: 1\r\n\
             \r\n"
        );
        stream.write_all(response.as_bytes()).unwrap();

        let mut received_frames = Vec::new();
        let (_fin, _opcode, payload) = read_frame(&mut stream).unwrap();
        received_frames.push(payload);

        // Reply: OK status, sequence=1, table_count=0
        let mut ok = Vec::new();
        ok.push(0x00u8);
        ok.extend_from_slice(&1u64.to_le_bytes());
        ok.extend_from_slice(&0u16.to_le_bytes());
        write_server_binary_frame(&mut stream, &ok).unwrap();

        let _ = tx.send(MockResult {
            request_lines,
            received_frames,
        });
        // Hold the connection open briefly so the client side reads the reply.
        thread::sleep(Duration::from_millis(50));
    });

    (port, rx)
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
        result.request_lines.first().unwrap().contains("/api/v4/write"),
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
fn qwp_ws_subsequent_message_has_empty_delta() {
    // Run two consecutive flushes against a server that processes both. We
    // build a slightly extended mock inline.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();

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

        for seq in 1u64..=2 {
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

    // Second flush reuses the same global symbol -- delta_count must be 0.
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
    // delta_start = 1 (one symbol already global), delta_count = 0.
    assert_eq!(payload[0], 0x01);
    assert_eq!(payload[1], 0x00);

    // First message: full schema (0x00). Second: reference schema (0x01).
    assert_eq!(read_schema_mode(&first), 0x00);
    assert_eq!(read_schema_mode(&second), 0x01);
}

#[test]
fn qwp_ws_reference_schema_used_when_columns_match() {
    // Two flushes with identical schema → second message must use ref mode and
    // omit the column definitions, even though the rows differ.
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
        for seq in 1u64..=3 {
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

    // First message must register the schema in full mode.
    assert_eq!(read_schema_mode(&m1), 0x00, "first message: full schema");
    // Subsequent messages with the same column set use reference mode.
    assert_eq!(read_schema_mode(&m2), 0x01, "second message: ref schema");
    assert_eq!(read_schema_mode(&m3), 0x01, "third message: ref schema");

    // Sanity check: both ref-mode messages reference id 0 (the first id minted).
    let (_, m2_id) = read_schema_mode_and_id(&m2);
    let (_, m3_id) = read_schema_mode_and_id(&m3);
    assert_eq!(m2_id, 0);
    assert_eq!(m3_id, 0);

    // The ref-mode payload must be smaller than the full-mode one despite
    // carrying the same row count: ref mode drops the column-definition bytes.
    assert!(
        m2.len() < m1.len(),
        "ref-mode message ({} bytes) should be smaller than full-mode ({} bytes)",
        m2.len(),
        m1.len()
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
        for seq in 1u64..=2 {
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

    let (mode1, id1) = read_schema_mode_and_id(&m1);
    let (mode2, id2) = read_schema_mode_and_id(&m2);
    assert_eq!(mode1, 0x00);
    assert_eq!(mode2, 0x00, "different column set must re-register full schema");
    assert_ne!(id1, id2, "new schema must get a fresh id");
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
/// returning the offset of the schema mode byte.
fn schema_mode_offset(frame: &[u8]) -> usize {
    let mut pos = 12; // header
    let _delta_start = read_varint(frame, &mut pos);
    let delta_count = read_varint(frame, &mut pos);
    for _ in 0..delta_count {
        let name_len = read_varint(frame, &mut pos) as usize;
        pos += name_len;
    }
    // Table header: name (varint+bytes), row_count varint, column_count varint
    let name_len = read_varint(frame, &mut pos) as usize;
    pos += name_len;
    let _row_count = read_varint(frame, &mut pos);
    let _column_count = read_varint(frame, &mut pos);
    pos
}

fn read_schema_mode(frame: &[u8]) -> u8 {
    frame[schema_mode_offset(frame)]
}

fn read_schema_mode_and_id(frame: &[u8]) -> (u8, u64) {
    let mut pos = schema_mode_offset(frame);
    let mode = frame[pos];
    pos += 1;
    let id = read_varint(frame, &mut pos);
    (mode, id)
}

#[test]
fn qwp_ws_server_error_response_is_surfaced() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();

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

        let msg = b"bad column";
        let mut err = Vec::new();
        err.push(0x05u8); // PARSE_ERROR
        err.extend_from_slice(&1u64.to_le_bytes());
        err.extend_from_slice(&(msg.len() as u16).to_le_bytes());
        err.extend_from_slice(msg);
        write_server_binary_frame(&mut stream, &err).unwrap();
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

    let err = sender.flush(&mut buf).unwrap_err();
    assert!(
        err.msg().contains("bad column"),
        "expected server error in message, got: {}",
        err.msg()
    );
}

// ---------- failover tests ----------

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
        // First post-reconnect message gets sequence 1 from a fresh counter.
        ok.extend_from_slice(&1u64.to_le_bytes());
        ok.extend_from_slice(&0u16.to_le_bytes());
        write_server_binary_frame(&mut s2, &ok).unwrap();
        thread::sleep(Duration::from_millis(50));
    });

    (port, rx)
}

#[test]
fn qwp_ws_sync_failover_reconnects_and_replays() {
    let (port, rx) = spawn_dropping_then_recovering_server();
    let callback_fired = Arc::new(AtomicBool::new(false));
    let cb_flag = callback_fired.clone();

    let mut sender = SenderBuilder::new(Protocol::QwpWs, "127.0.0.1", port)
        .failover_initial_backoff(Duration::from_millis(20))
        .unwrap()
        .failover_max_backoff(Duration::from_millis(50))
        .unwrap()
        .on_failover_reset(crate::ingress::FailoverCallback::new(move || {
            cb_flag.store(true, std::sync::atomic::Ordering::SeqCst);
        }))
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
    assert!(callback_fired.load(std::sync::atomic::Ordering::SeqCst));

    // Both wire dumps should be identical QWP messages — replay re-encodes
    // against fresh state but with the same row, so the bytes match.
    let frame1 = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let frame2 = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(&frame1[0..4], b"QWP1");
    assert_eq!(frame1, frame2);
}

#[test]
fn qwp_ws_from_conf_parses_failover_keys() {
    // Just exercises the parser surface: every new key is accepted. Building
    // would also work but isn't necessary for parser coverage.
    let conf = "qwpws::addr=localhost:9000;\
                max_in_flight=64;\
                failover=on;\
                max_failover_attempts=5;\
                failover_initial_backoff=200;\
                failover_max_backoff=2000;\
                failover_total_budget=20000;";
    SenderBuilder::from_conf(conf).unwrap();

    let conf_off = "qwpws::addr=localhost:9000;failover=off;";
    SenderBuilder::from_conf(conf_off).unwrap();

    let bad = "qwpws::addr=localhost:9000;failover=maybe;";
    let err = SenderBuilder::from_conf(bad).unwrap_err();
    assert!(
        err.msg().contains("\"failover\""),
        "got: {}",
        err.msg()
    );
}

#[test]
fn qwp_ws_sync_failover_disabled_latches_terminal_error() {
    // Server accepts upgrade then drops. With failover off, the first flush
    // returns SocketError; subsequent flushes return the same error.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        let req_bytes = read_request_until_blank(&mut s).unwrap();
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
        s.write_all(resp.as_bytes()).unwrap();
        let _ = read_frame(&mut s).unwrap();
        drop(s); // close mid-flight
    });

    let mut sender = SenderBuilder::new(Protocol::QwpWs, "127.0.0.1", port)
        .failover(false)
        .unwrap()
        .build()
        .unwrap();
    let mut buf = sender.new_buffer();
    buf.table("t").unwrap().column_i64("v", 1).unwrap().at_now().unwrap();

    let err1 = sender.flush(&mut buf).unwrap_err();
    assert_eq!(err1.code(), crate::ErrorCode::SocketError);

    // A second attempt sees the latched error directly without trying I/O.
    let mut buf2 = sender.new_buffer();
    buf2.table("t").unwrap().column_i64("v", 2).unwrap().at_now().unwrap();
    let err2 = sender.flush(&mut buf2).unwrap_err();
    assert_eq!(err2.code(), crate::ErrorCode::SocketError);
}
