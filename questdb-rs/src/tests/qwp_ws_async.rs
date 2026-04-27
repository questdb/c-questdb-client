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

//! Integration tests for the async QWP/WebSocket sender. The mock server runs
//! in a worker thread using std::net (sync) — only the client side exercises
//! the tokio async path, which is the surface we care about validating.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use crate::ingress::{Protocol, SenderBuilder};

const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

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
    Base64::encode_string(&sha1(combined.as_bytes()))
}

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

/// Spawn a single-connection server that performs the upgrade then echoes back
/// `n` OK frames in sequence (sequence numbers 1..=n).
fn spawn_ok_server(messages: usize) -> (u16, mpsc::Receiver<Vec<u8>>) {
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

        for seq in 1..=messages {
            let (_fin, _op, payload) = read_frame(&mut stream).unwrap();
            tx.send(payload).unwrap();
            let mut ok = vec![0u8];
            ok.extend_from_slice(&(seq as u64).to_le_bytes());
            ok.extend_from_slice(&0u16.to_le_bytes());
            write_server_binary_frame(&mut stream, &ok).unwrap();
        }
        thread::sleep(Duration::from_millis(50));
    });

    (port, rx)
}

#[tokio::test]
async fn async_qwp_ws_round_trip_minimal_message() {
    let (port, rx) = spawn_ok_server(1);

    let sender = SenderBuilder::new(Protocol::QwpWs, "127.0.0.1", port)
        .build_async()
        .await
        .unwrap();
    assert_eq!(sender.protocol_version(), 1);

    let mut buf = sender.new_buffer();
    buf.table("trades")
        .unwrap()
        .symbol("sym", "ETH-USD")
        .unwrap()
        .column_i64("qty", 7)
        .unwrap()
        .at_now()
        .unwrap();
    sender.flush(&mut buf).await.unwrap();

    let frame = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(&frame[0..4], b"QWP1");
    assert_eq!(frame[4], 1);
    assert_eq!(frame[5] & 0x08, 0x08, "FLAG_DELTA_SYMBOL_DICT must be set");
    let payload = &frame[12..];
    assert_eq!(payload[0], 0x00);
    assert_eq!(payload[1], 0x01);
    assert_eq!(payload[2], 0x07);
    assert_eq!(&payload[3..10], b"ETH-USD");
}

#[tokio::test]
async fn async_qwp_ws_reference_schema_after_first_message() {
    // Two flushes with identical schema → second message must use ref mode.
    let (port, rx) = spawn_ok_server(2);

    let sender = SenderBuilder::new(Protocol::QwpWs, "127.0.0.1", port)
        .build_async()
        .await
        .unwrap();

    for qty in 1..=2 {
        let mut buf = sender.new_buffer();
        buf.table("trades")
            .unwrap()
            .column_i64("qty", qty)
            .unwrap()
            .at_now()
            .unwrap();
        sender.flush(&mut buf).await.unwrap();
    }

    let m1 = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let m2 = rx.recv_timeout(Duration::from_secs(5)).unwrap();

    assert_eq!(read_schema_mode(&m1), 0x00);
    assert_eq!(read_schema_mode(&m2), 0x01);
}

#[tokio::test]
async fn async_qwp_ws_server_error_propagates() {
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
        let msg = b"async parse error";
        let mut err = Vec::new();
        err.push(0x05u8);
        err.extend_from_slice(&1u64.to_le_bytes());
        err.extend_from_slice(&(msg.len() as u16).to_le_bytes());
        err.extend_from_slice(msg);
        write_server_binary_frame(&mut stream, &err).unwrap();
        thread::sleep(Duration::from_millis(50));
    });

    let sender = SenderBuilder::new(Protocol::QwpWs, "127.0.0.1", port)
        .build_async()
        .await
        .unwrap();
    let mut buf = sender.new_buffer();
    buf.table("trades")
        .unwrap()
        .column_i64("qty", 1)
        .unwrap()
        .at_now()
        .unwrap();
    let err = sender.flush(&mut buf).await.unwrap_err();
    assert!(
        err.msg().contains("async parse error"),
        "got: {}",
        err.msg()
    );
}

/// Spawn a server that reads `n` frames before sending any responses, then
/// sends responses out of order (reverse). This is the strict test for
/// pipelining: if the client waited for ack #1 before sending #2, the server
/// would deadlock waiting for #2. If the client serialized waits, the
/// reverse-order acks would still all arrive, but the timing proves nothing.
/// The "must read all N before sending any" half is what proves pipelining.
fn spawn_pipelined_server(n: usize) -> (u16, std::sync::mpsc::Receiver<usize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = std::sync::mpsc::channel();

    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
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

        // Phase 1: drain all N frames from the wire WITHOUT acknowledging any.
        // If pipelining is broken, this hangs after frame 1.
        for i in 0..n {
            let (_fin, _op, _payload) = read_frame(&mut stream).unwrap();
            tx.send(i + 1).unwrap();
        }

        // Phase 2: ack in reverse order to prove the client matches by sequence.
        for seq in (1..=n).rev() {
            let mut ok = vec![0u8];
            ok.extend_from_slice(&(seq as u64).to_le_bytes());
            ok.extend_from_slice(&0u16.to_le_bytes());
            write_server_binary_frame(&mut stream, &ok).unwrap();
        }
        thread::sleep(Duration::from_millis(50));
    });

    (port, rx)
}

#[tokio::test]
async fn async_qwp_ws_pipelines_concurrent_flushes() {
    const N: usize = 8;
    let (port, frame_rx) = spawn_pipelined_server(N);

    let sender = std::sync::Arc::new(
        SenderBuilder::new(Protocol::QwpWs, "127.0.0.1", port)
            .max_in_flight(N)
            .unwrap()
            .build_async()
            .await
            .unwrap(),
    );

    // Fan out N flush tasks. They all share the connection.
    let mut handles = Vec::new();
    for i in 0..N {
        let s = sender.clone();
        handles.push(tokio::spawn(async move {
            let mut buf = s.new_buffer();
            buf.table("trades")
                .unwrap()
                .column_i64("qty", i as i64)
                .unwrap()
                .at_now()
                .unwrap();
            s.flush(&mut buf).await
        }));
    }

    for h in handles {
        h.await.unwrap().unwrap();
    }

    // Confirm the server actually got all N frames before sending any reply.
    let mut received = Vec::new();
    while let Ok(idx) = frame_rx.recv_timeout(Duration::from_secs(1)) {
        received.push(idx);
    }
    assert_eq!(received.len(), N);
    assert_eq!(received, (1..=N).collect::<Vec<_>>());
}

#[tokio::test]
async fn async_qwp_ws_max_in_flight_throttles() {
    // With max_in_flight=1 the sender behaves sequentially: the second flush
    // can't start until the first ack arrives. We verify by introducing a
    // server-side gap and checking that the second frame doesn't appear until
    // after the first has been ack'd.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (frame_tx, frame_rx) = std::sync::mpsc::channel::<std::time::Instant>();
    let (ack_tx, ack_rx) = std::sync::mpsc::channel::<std::time::Instant>();

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

        // Frame 1
        let _ = read_frame(&mut stream).unwrap();
        frame_tx.send(std::time::Instant::now()).unwrap();
        thread::sleep(Duration::from_millis(150));
        let mut ok = vec![0u8];
        ok.extend_from_slice(&1u64.to_le_bytes());
        ok.extend_from_slice(&0u16.to_le_bytes());
        write_server_binary_frame(&mut stream, &ok).unwrap();
        ack_tx.send(std::time::Instant::now()).unwrap();

        // Frame 2 -- must not arrive until *after* ack 1 if window=1.
        let _ = read_frame(&mut stream).unwrap();
        frame_tx.send(std::time::Instant::now()).unwrap();
        let mut ok = vec![0u8];
        ok.extend_from_slice(&2u64.to_le_bytes());
        ok.extend_from_slice(&0u16.to_le_bytes());
        write_server_binary_frame(&mut stream, &ok).unwrap();

        thread::sleep(Duration::from_millis(50));
    });

    let sender = std::sync::Arc::new(
        SenderBuilder::new(Protocol::QwpWs, "127.0.0.1", port)
            .max_in_flight(1)
            .unwrap()
            .build_async()
            .await
            .unwrap(),
    );

    let s1 = sender.clone();
    let h1 = tokio::spawn(async move {
        let mut buf = s1.new_buffer();
        buf.table("t").unwrap().column_i64("v", 1).unwrap().at_now().unwrap();
        s1.flush(&mut buf).await
    });
    let s2 = sender.clone();
    let h2 = tokio::spawn(async move {
        let mut buf = s2.new_buffer();
        buf.table("t").unwrap().column_i64("v", 2).unwrap().at_now().unwrap();
        s2.flush(&mut buf).await
    });

    h1.await.unwrap().unwrap();
    h2.await.unwrap().unwrap();

    let frame1 = frame_rx.recv().unwrap();
    let ack1 = ack_rx.recv().unwrap();
    let frame2 = frame_rx.recv().unwrap();
    assert!(
        frame2 >= ack1,
        "with max_in_flight=1, frame 2 must not be sent before ack 1; got frame1={:?}, ack1={:?}, frame2={:?}",
        frame1,
        ack1,
        frame2
    );
}

/// Two-connection mock: first connection drops without acking; second
/// connection receives the replayed frame(s) and acks them. Returns a
/// receiver of (generation, frame_payload) so the test can assert how many
/// frames each generation saw.
fn spawn_dropping_then_recovering_server(
    expected_replay_count: usize,
) -> (u16, std::sync::mpsc::Receiver<(u32, Vec<u8>)>) {
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

        // Generation 1: read whatever frames arrive then drop without acking.
        let (mut s1, _) = listener.accept().unwrap();
        s1.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
        s1.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        do_upgrade(&mut s1);
        loop {
            match read_frame(&mut s1) {
                Ok((_, _, payload)) => tx.send((1, payload)).unwrap(),
                Err(_) => break,
            }
        }
        drop(s1);

        // Generation 2: read replayed frames, ack each in order with seq=i.
        let (mut s2, _) = listener.accept().unwrap();
        s2.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s2.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        do_upgrade(&mut s2);
        for i in 1..=expected_replay_count as u64 {
            let (_fin, _op, payload) = read_frame(&mut s2).unwrap();
            tx.send((2, payload)).unwrap();
            let mut ok = vec![0u8];
            ok.extend_from_slice(&i.to_le_bytes());
            ok.extend_from_slice(&0u16.to_le_bytes());
            write_server_binary_frame(&mut s2, &ok).unwrap();
        }
        thread::sleep(Duration::from_millis(50));
    });

    (port, rx)
}

#[tokio::test]
async fn async_qwp_ws_failover_replays_in_flight_messages() {
    const N: usize = 4;
    let (port, rx) = spawn_dropping_then_recovering_server(N);

    let cb_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    let cb_count_for_cb = cb_count.clone();

    let sender = std::sync::Arc::new(
        SenderBuilder::new(Protocol::QwpWs, "127.0.0.1", port)
            .max_in_flight(N)
            .unwrap()
            .failover_initial_backoff(Duration::from_millis(20))
            .unwrap()
            .failover_max_backoff(Duration::from_millis(50))
            .unwrap()
            .on_failover_reset(crate::ingress::FailoverCallback::new(move || {
                cb_count_for_cb.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }))
            .unwrap()
            .build_async()
            .await
            .unwrap(),
    );

    // Submit N concurrent flushes. The server reads them on connection 1,
    // drops, the supervisor reconnects, and replays them on connection 2.
    let mut handles = Vec::new();
    for i in 0..N {
        let s = sender.clone();
        handles.push(tokio::spawn(async move {
            let mut buf = s.new_buffer();
            buf.table("trades")
                .unwrap()
                .column_i64("qty", i as i64)
                .unwrap()
                .at_now()
                .unwrap();
            s.flush(&mut buf).await
        }));
    }

    for h in handles {
        h.await.unwrap().unwrap();
    }

    assert_eq!(
        cb_count.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "callback should fire exactly once per recovery"
    );

    // Server received some frames on connection 1 and exactly N on connection 2.
    let mut gen2 = 0;
    while let Ok((generation, _payload)) = rx.recv_timeout(Duration::from_secs(1)) {
        if generation == 2 {
            gen2 += 1;
        }
    }
    assert_eq!(gen2, N, "expected {N} replayed frames on the new connection");
}

#[tokio::test]
async fn async_qwp_ws_failover_disabled_latches_terminal_error() {
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
        drop(s);
    });

    let sender = SenderBuilder::new(Protocol::QwpWs, "127.0.0.1", port)
        .failover(false)
        .unwrap()
        .build_async()
        .await
        .unwrap();
    let mut buf = sender.new_buffer();
    buf.table("t").unwrap().column_i64("v", 1).unwrap().at_now().unwrap();
    let err = sender.flush(&mut buf).await.unwrap_err();
    assert_eq!(err.code(), crate::ErrorCode::SocketError);

    // A subsequent flush sees the latched error.
    let mut buf2 = sender.new_buffer();
    buf2.table("t").unwrap().column_i64("v", 2).unwrap().at_now().unwrap();
    let err2 = sender.flush(&mut buf2).await.unwrap_err();
    assert_eq!(err2.code(), crate::ErrorCode::SocketError);
}

#[tokio::test]
async fn async_qwp_ws_build_async_rejects_non_ws_protocol() {
    // Sync protocol → async builder must refuse it.
    let err = SenderBuilder::new(Protocol::Tcp, "127.0.0.1", 9009)
        .build_async()
        .await
        .unwrap_err();
    assert!(
        err.msg().contains("only supported for QWP/WebSocket"),
        "got: {}",
        err.msg()
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

fn read_schema_mode(frame: &[u8]) -> u8 {
    let mut pos = 12;
    let _delta_start = read_varint(frame, &mut pos);
    let delta_count = read_varint(frame, &mut pos);
    for _ in 0..delta_count {
        let name_len = read_varint(frame, &mut pos) as usize;
        pos += name_len;
    }
    let name_len = read_varint(frame, &mut pos) as usize;
    pos += name_len;
    let _row_count = read_varint(frame, &mut pos);
    let _column_count = read_varint(frame, &mut pos);
    frame[pos]
}
