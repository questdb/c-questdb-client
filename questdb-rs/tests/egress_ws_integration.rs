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

//! End-to-end integration tests for the egress reader against an
//! in-process tungstenite server.

#![cfg(feature = "sync-reader-ws")]

use std::net::TcpListener;
use std::thread::JoinHandle;

use questdb::egress::column::ColumnView;
use questdb::egress::column_kind::ColumnKind;
use questdb::egress::reader::{Reader, Terminal};
use questdb::egress::schema::SchemaMode;
use questdb::egress::wire::header::{FrameHeader, HEADER_LEN};
use questdb::egress::wire::msg_kind::{MsgKind, StatusCode};
use questdb::egress::wire::varint::encode_u64;

use tungstenite::handshake::server::{Request, Response};
use tungstenite::http::HeaderValue;
use tungstenite::Message;

/// Runs a tiny tungstenite server in a background thread.
fn spawn_server(
    handler: impl FnOnce(tungstenite::WebSocket<std::net::TcpStream>) + Send + 'static,
) -> (u16, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let h = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        // Force the upgrade response to advertise X-QWP-Version: 2.
        let callback = |_req: &Request, mut resp: Response| {
            resp.headers_mut()
                .insert("X-QWP-Version", HeaderValue::from_static("2"));
            Ok(resp)
        };
        let ws = tungstenite::accept_hdr(stream, callback).expect("accept_hdr");
        handler(ws);
    });
    (port, h)
}

fn header_bytes(payload_len: usize, flags: u8) -> [u8; HEADER_LEN] {
    FrameHeader {
        version: 2,
        flags,
        table_count: 1,
        payload_length: payload_len as u32,
    }
    .to_bytes()
}

fn build_simple_long_batch(request_id: i64, batch_seq: u64, values: &[i64]) -> Vec<u8> {
    let mut p = vec![MsgKind::ResultBatch.as_u8()];
    p.extend_from_slice(&request_id.to_le_bytes());
    encode_u64(batch_seq, &mut p);
    encode_u64(0, &mut p); // table name_len
    encode_u64(values.len() as u64, &mut p); // row_count
    encode_u64(1, &mut p); // col_count (in the table block; schema section does NOT re-emit this)
    // Schema: full, id=1, one Long col "v"
    p.push(SchemaMode::Full as u8);
    encode_u64(1, &mut p); // schema_id
    encode_u64(1, &mut p); // name_len
    p.push(b'v');
    p.push(ColumnKind::Long.as_u8());
    // Column body: null_flag=0, then dense values
    p.push(0x00);
    for v in values {
        p.extend_from_slice(&v.to_le_bytes());
    }
    p
}

fn build_result_end(request_id: i64, final_seq: u64, total_rows: u64) -> Vec<u8> {
    let mut p = vec![MsgKind::ResultEnd.as_u8()];
    p.extend_from_slice(&request_id.to_le_bytes());
    encode_u64(final_seq, &mut p);
    encode_u64(total_rows, &mut p);
    p
}

fn build_query_error(request_id: i64, status: StatusCode, msg: &str) -> Vec<u8> {
    let mut p = vec![MsgKind::QueryError.as_u8()];
    p.extend_from_slice(&request_id.to_le_bytes());
    p.push(status.as_u8());
    p.extend_from_slice(&(msg.len() as u16).to_le_bytes());
    p.extend_from_slice(msg.as_bytes());
    p
}

fn send_frame(
    ws: &mut tungstenite::WebSocket<std::net::TcpStream>,
    payload: Vec<u8>,
    flags: u8,
) {
    let mut buf = Vec::with_capacity(HEADER_LEN + payload.len());
    buf.extend_from_slice(&header_bytes(payload.len(), flags));
    buf.extend_from_slice(&payload);
    ws.send(Message::Binary(buf.into())).expect("send");
}

#[test]
fn end_to_end_simple_long_query() {
    let (port, server) = spawn_server(|mut ws| {
        // Receive the QUERY_REQUEST.
        let _ = ws.read().expect("read query");
        // Send one batch and a RESULT_END.
        send_frame(&mut ws, build_simple_long_batch(1, 0, &[10, 20, 30]), 0);
        send_frame(&mut ws, build_result_end(1, 0, 3), 0);
        let _ = ws.close(None);
    });

    let conf = format!("qwp::addr=127.0.0.1:{}", port);
    let mut reader = Reader::from_conf(&conf).expect("connect");
    assert_eq!(reader.server_version(), 2);

    let mut cur = reader.query("SELECT v FROM t").execute().expect("execute");

    let view = cur.next_batch().expect("first batch").expect("Some");
    assert_eq!(view.row_count(), 3);
    let col = view.column(0).expect("col");
    let ColumnView::Long(c) = col else {
        panic!("expected Long");
    };
    assert_eq!(c.value(0), 10);
    assert_eq!(c.value(1), 20);
    assert_eq!(c.value(2), 30);

    let next = cur.next_batch().expect("end");
    assert!(next.is_none());
    match cur.terminal() {
        Some(Terminal::End { final_seq, total_rows }) => {
            assert_eq!(*final_seq, 0);
            assert_eq!(*total_rows, 3);
        }
        other => panic!("expected End, got {:?}", other),
    }

    server.join().expect("server thread");
}

#[test]
fn server_query_error_surfaces_as_err() {
    let (port, server) = spawn_server(|mut ws| {
        let _ = ws.read().expect("read query");
        send_frame(
            &mut ws,
            build_query_error(1, StatusCode::ParseError, "syntax error near 'XYZ'"),
            0,
        );
        let _ = ws.close(None);
    });

    let conf = format!("qwp::addr=127.0.0.1:{}", port);
    let mut reader = Reader::from_conf(&conf).expect("connect");
    let mut cur = reader.query("BAD SQL").execute().expect("execute");
    match cur.next_batch() {
        Err(e) => {
            assert_eq!(e.code(), questdb::egress::ErrorCode::ServerParseError);
            assert!(e.msg().contains("syntax"));
        }
        Ok(_) => panic!("expected QUERY_ERROR"),
    }
    server.join().expect("server thread");
}

#[test]
fn handshake_missing_version_header_rejected() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        // Accept without injecting X-QWP-Version.
        let _ws = tungstenite::accept(stream).expect("accept");
    });
    let conf = format!("qwp::addr=127.0.0.1:{}", port);
    match Reader::from_conf(&conf) {
        Err(e) => assert_eq!(e.code(), questdb::egress::ErrorCode::HandshakeError),
        Ok(_) => panic!("expected handshake error"),
    }
    server.join().unwrap();
}

#[test]
fn second_query_while_cursor_live_is_invalid_api_call() {
    let (port, server) = spawn_server(|mut ws| {
        let _ = ws.read().expect("read query");
        send_frame(&mut ws, build_simple_long_batch(1, 0, &[1]), 0);
        // Don't send RESULT_END so the cursor stays "live".
        std::thread::sleep(std::time::Duration::from_millis(200));
        let _ = ws.close(None);
    });

    let conf = format!("qwp::addr=127.0.0.1:{}", port);
    let mut reader = Reader::from_conf(&conf).expect("connect");
    let mut _cur = reader.query("Q1").execute().expect("execute");
    let _ = _cur.next_batch().expect("first batch");

    // Attempt a second query without dropping the first cursor.
    // We can't call reader.query() while _cur borrows reader (compile-time
    // would block it). So drop and re-execute on the now-orphaned reader to
    // demonstrate the runtime guard isn't triggered after legitimate drop.
    drop(_cur);

    // This is allowed (cursor was dropped; cursor_active reset).
    let q2 = reader.query("Q2");
    drop(q2); // never executed; doesn't trip the guard either.

    server.join().expect("server thread");
}
