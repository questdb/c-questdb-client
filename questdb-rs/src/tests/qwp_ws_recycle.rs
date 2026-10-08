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

//! Publication-boundary dictionary recycling through the public sender APIs.
use super::qwp_ws::{
    perform_server_upgrade, read_frame, write_qwp_error_response, write_qwp_ok_response,
};
use crate::ingress::{AckLevel, QwpWsProgress, SenderBuilder, TimestampNanos};
use std::net::TcpListener;
use std::sync::atomic::AtomicUsize;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::thread;
use std::time::Duration;

pub(crate) struct Server {
    pub(crate) port: u16,
    frames: mpsc::Receiver<(usize, Vec<u8>)>,
    stop: Arc<AtomicBool>,
    acks_released: Arc<AtomicBool>,
    connections: Arc<AtomicUsize>,
    upgrade_fault: Arc<AtomicUsize>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Server {
    pub(crate) fn new() -> Self {
        Self::with_ack_delay(Duration::ZERO)
    }
    fn with_ack_delay(ack_delay: Duration) -> Self {
        Self::with_behavior(ack_delay, None)
    }
    fn with_behavior(ack_delay: Duration, terminal_at: Option<(usize, u64)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&stop);
        let acks_released = Arc::new(AtomicBool::new(true));
        let release_acks = Arc::clone(&acks_released);
        let (tx, frames) = mpsc::channel();
        let connections = Arc::new(AtomicUsize::new(0));
        let accepted = Arc::clone(&connections);
        let upgrade_fault = Arc::new(AtomicUsize::new(0));
        let faults = Arc::clone(&upgrade_fault);
        let worker = thread::spawn(move || {
            let mut connection = 0;
            let mut workers = Vec::new();
            while !stopped.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let tx = tx.clone();
                        let fault = faults.load(Ordering::Acquire);
                        let wire_fault = Arc::clone(&faults);
                        let release_acks = Arc::clone(&release_acks);
                        let stop = Arc::clone(&stopped);
                        let id = connection;
                        connection += 1;
                        accepted.fetch_add(1, Ordering::Release);
                        workers.push(thread::spawn(move || {
                            stream.set_nonblocking(false).unwrap();
                            if fault == 1 { return; }
                            if fault == 2 {
                                use std::io::{Read, Write};
                                let mut request = Vec::new();
                                while !request.ends_with(b"\r\n\r\n") {
                                    let mut byte = [0];
                                    if stream.read_exact(&mut byte).is_err() { return; }
                                    request.push(byte[0]);
                                }
                                let _ = stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n");
                                return;
                            }

                            if perform_server_upgrade(&mut stream).is_err() {
                                return;
                            }
                            let mut seq = 0;
                            while let Ok((_, opcode, frame)) = read_frame(&mut stream) {
                                if opcode != 2 {
                                    break;
                                }
                                let frame_deferred = frame[5] & 1 != 0;
                                if tx.send((id, frame)).is_err() {
                                    break;
                                }
                                if wire_fault.compare_exchange(3, 1, Ordering::AcqRel, Ordering::Acquire).is_ok() {
                                    return; // Received, deliberately unacknowledged, then disconnected.
                                }
                                if frame_deferred {
                                    seq += 1;
                                    continue;
                                }
                                while !release_acks.load(Ordering::Acquire) {
                                    if stop.load(Ordering::Acquire) {
                                        return;
                                    }
                                    thread::sleep(Duration::from_millis(1));
                                }
                                thread::sleep(ack_delay);
                                let response = if terminal_at == Some((id, seq)) {
                                    write_qwp_error_response(
                                        &mut stream,
                                        0x05,
                                        seq,
                                        b"bad recycle row",
                                    )
                                } else {
                                    write_qwp_ok_response(&mut stream, seq)
                                };
                                if response.is_err() {
                                    break;
                                }
                                seq += 1;
                            }
                        }));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1))
                    }
                    Err(e) => panic!("accept failed: {e}"),
                }
            }
            for worker in workers {
                worker.join().unwrap();
            }
        });
        Self {
            port,
            frames,
            stop,
            acks_released,
            connections,
            upgrade_fault,
            worker: Some(worker),
        }
    }
    pub(crate) fn connection_count(&self) -> usize {
        self.connections.load(Ordering::Acquire)
    }
    pub(crate) fn frame(&self) -> (usize, Vec<u8>) {
        self.frames.recv_timeout(Duration::from_secs(5)).unwrap()
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.worker.take().unwrap().join().unwrap();
    }
}
fn varint(frame: &[u8], pos: &mut usize) -> usize {
    let mut value = 0;
    let mut shift = 0;
    loop {
        let byte = frame[*pos];
        *pos += 1;
        value |= ((byte & 0x7f) as usize) << shift;
        if byte & 0x80 == 0 {
            return value;
        }
        shift += 7;
    }
}

fn assert_fresh(frame: &[u8], symbol: &str) {
    assert_symbol(frame, symbol, 0);
}

fn assert_symbol(frame: &[u8], symbol: &str, expected_id: usize) {
    assert_eq!(frame[5] & 8, 8);
    assert_eq!(
        frame[12] as usize, expected_id,
        "new namespace IDs must be dense"
    );
    assert_eq!(frame[13], 1);
    assert_eq!(frame[14] as usize, symbol.len());
    assert_eq!(&frame[15..15 + symbol.len()], symbol.as_bytes());
    // Decode the actual first row's symbol ID against the frame dictionary.
    let mut pos = 15 + symbol.len();
    let table_len = varint(frame, &mut pos);
    pos += table_len;
    assert_eq!(varint(frame, &mut pos), 1);
    let columns = varint(frame, &mut pos);
    for column in 0..columns {
        let name_len = varint(frame, &mut pos);
        pos += name_len;
        if column == 0 {
            assert_eq!(frame[pos], 9);
        }
        pos += 1;
    }
    assert_eq!(frame[pos], 0, "non-null symbol column");
    pos += 1;
    let id = varint(frame, &mut pos);
    assert_eq!(id, expected_id);
    let dictionary = [std::str::from_utf8(&frame[15..15 + symbol.len()]).unwrap()];
    assert_eq!(dictionary[id - expected_id], symbol);
}
#[test]
fn recycle_boundary_preserves_buffer_and_symbols() {
    for progress in [QwpWsProgress::Background, QwpWsProgress::Manual] {
        for disk in [false, true] {
            let server = Server::new();
            let dir = tempfile::TempDir::new().unwrap();
            let storage = if disk {
                format!("sf_dir={};sender_id=recycle;", dir.path().display())
            } else {
                String::new()
            };
            let conf = format!(
                "ws::addr=127.0.0.1:{};symbol_dict_reset_threshold=1;symbol_dict_reset_max_wait_millis=0;{storage}",
                server.port
            );
            let mut sender = SenderBuilder::from_conf(conf)
                .unwrap()
                .qwp_ws_progress(progress)
                .unwrap()
                .build()
                .unwrap();
            let mut buffer = sender.new_buffer();
            buffer
                .table("trades")
                .unwrap()
                .symbol("sym", "alpha")
                .unwrap()
                .at(TimestampNanos::new(1))
                .unwrap();
            sender.flush_and_keep(&buffer).unwrap();
            assert_eq!(sender.published_fsn().unwrap(), Some(0));
            assert!(!buffer.is_empty());
            sender.wait(AckLevel::Ok, Duration::from_secs(5)).unwrap();
            let (first_connection, first) = server.frame();
            assert_fresh(&first, "alpha");
            let mut retained = buffer;
            let mut buffer = sender.new_buffer();
            buffer
                .table("trades")
                .unwrap()
                .symbol("sym", "beta")
                .unwrap()
                .at(TimestampNanos::new(2))
                .unwrap();
            assert_eq!(sender.flush_and_get_fsn(&mut buffer).unwrap(), Some(1));
            assert!(buffer.is_empty());
            sender.wait(AckLevel::Ok, Duration::from_secs(5)).unwrap();
            let (second_connection, second) = server.frame();
            assert_fresh(&second, "beta");
            assert_ne!(first_connection, second_connection);
            // Reuse the original kept Buffer, whose local symbol table predates
            // the recycle. Its alpha must now resolve to global ID one.
            sender.flush(&mut retained).unwrap();
            assert!(retained.is_empty());
            assert_eq!(sender.published_fsn().unwrap(), Some(2));
            sender.wait(AckLevel::Ok, Duration::from_secs(5)).unwrap();
            let (same, third) = server.frame();
            assert_eq!(same, second_connection);
            assert_symbol(&third, "alpha", 1);
        }
    }
}

#[test]
fn recycle_boundary_all_publishers() {
    use crate::{QuestDb, ingress::column_sender::Chunk};
    for disk in [false, true] {
        let server = Server::new();
        let dir = tempfile::TempDir::new().unwrap();
        let storage = if disk {
            format!("sf_dir={};sender_id=recycle;", dir.path().display())
        } else {
            String::new()
        };
        let db = QuestDb::connect(&format!("ws::addr=127.0.0.1:{};lazy_connect=true;sender_pool_max=1;pool_reap=manual;symbol_dict_reset_threshold=1;symbol_dict_reset_max_wait_millis=0;{storage}", server.port)).unwrap();
        let mut sender = db.borrow_sender().unwrap();
        let mut buffer = db.new_buffer();
        buffer
            .table("trades")
            .unwrap()
            .symbol("sym", "alpha")
            .unwrap()
            .at_now()
            .unwrap();
        sender
            .flush_buffer_and_wait(&mut buffer, AckLevel::Ok)
            .unwrap();
        let (old, first) = server.frame();
        assert_fresh(&first, "alpha");
        // A pool return cannot lose the policy or change foreground ownership.
        drop(sender);
        let mut sender = db.borrow_sender().unwrap();
        let mut chunk = Chunk::new("trades");
        chunk
            .symbol_i32("sym", &[0], &[0, 4], b"beta", None)
            .unwrap()
            .at_now()
            .unwrap();
        sender.flush_and_wait(&mut chunk, AckLevel::Ok).unwrap();
        let (new, second) = server.frame();
        assert_fresh(&second, "beta");
        assert_ne!(old, new);
        assert_eq!(sender.published_fsn().unwrap(), Some(1));
        // The floor is now two: this row joins the chunk's namespace as ID one.
        buffer
            .table("trades")
            .unwrap()
            .symbol("sym", "gamma")
            .unwrap()
            .at_now()
            .unwrap();
        sender
            .flush_buffer_and_wait(&mut buffer, AckLevel::Ok)
            .unwrap();
        let (same, third) = server.frame();
        assert_eq!(same, new);
        assert_eq!(third[12], 1);
        #[cfg(feature = "arrow-ingress")]
        {
            use arrow::array::{ArrayRef, DictionaryArray, RecordBatch, types::Int32Type};
            let symbols = DictionaryArray::<Int32Type>::from_iter([Some("delta")]);
            let batch =
                RecordBatch::try_from_iter(vec![("sym", Arc::new(symbols) as ArrayRef)]).unwrap();
            sender
                .flush_arrow_batch_at_now_and_wait("trades", &batch, &[], AckLevel::Ok)
                .unwrap();
            let (arrow_connection, fourth) = server.frame();
            assert_ne!(arrow_connection, new);
            assert_fresh(&fourth, "delta");
            assert_eq!(sender.published_fsn().unwrap(), Some(3));
        }
    }
}

#[test]
fn recycle_boundary_split_and_deferred() {
    use crate::{QuestDb, ingress::column_sender::Chunk};
    let server = Server::new();
    let db = QuestDb::connect(&format!("ws::addr=127.0.0.1:{};lazy_connect=true;pool_reap=manual;max_buf_size=2048;symbol_dict_reset_threshold=1;symbol_dict_reset_max_wait_millis=0;", server.port)).unwrap();
    let mut sender = db.borrow_sender().unwrap();
    let mut bytes = vec![];
    let mut offsets = vec![0];
    for row in 0..16 {
        bytes.extend(std::iter::repeat_n(b'x', if row >= 8 { 4000 } else { 1 }));
        offsets.push(bytes.len() as i32);
    }
    let codes = [0; 16];
    let mut chunk = Chunk::new("trades");
    chunk
        .symbol_i32("sym", &codes, &[0, 5], b"alpha", None)
        .unwrap();
    chunk
        .column_str("s", &offsets, &bytes, None)
        .unwrap()
        .at_now()
        .unwrap();
    let err = sender.flush(&mut chunk).unwrap_err();
    assert_eq!(err.code(), crate::ErrorCode::BatchTooLarge);
    assert!(err.in_doubt());
    assert!(!chunk.is_empty());
    sender.wait(AckLevel::Ok, Duration::from_secs(5)).unwrap();
    let (connection, prefix) = server.frame();
    let (same, commit) = server.frame();
    assert_eq!(connection, same);
    assert_ne!(prefix[5] & 1, 0);
    assert_eq!(commit[5] & 1, 0);
    assert_eq!(&commit[6..8], &[0, 0]);
    assert_eq!(sender.published_fsn().unwrap(), Some(1));
    // Refresh arming at an empty successful publication, without starting recycling.
    let mut empty = Chunk::new("");
    sender.flush_and_wait(&mut empty, AckLevel::Ok).unwrap();
    let (same, empty_frame) = server.frame();
    assert_eq!(same, connection);
    assert_eq!(&empty_frame[6..8], &[0, 0]);
    let mut buffer = db.new_buffer();
    buffer
        .table("trades")
        .unwrap()
        .symbol("sym", "beta")
        .unwrap()
        .at_now()
        .unwrap();
    sender
        .flush_buffer_and_wait(&mut buffer, AckLevel::Ok)
        .unwrap();
    let (fresh, frame) = server.frame();
    assert_ne!(fresh, connection);
    assert_fresh(&frame, "beta");
    assert_eq!(sender.published_fsn().unwrap(), Some(3));
}

#[test]
fn recycle_boundary_bounded_wait_times_out_without_changing_namespace() {
    for progress in [QwpWsProgress::Background, QwpWsProgress::Manual] {
        let server = Server::with_ack_delay(Duration::from_millis(150));
        let mut sender = SenderBuilder::from_conf(format!("ws::addr=127.0.0.1:{};symbol_dict_reset_threshold=1;symbol_dict_reset_max_wait_millis=20;", server.port)).unwrap().qwp_ws_progress(progress).unwrap().build().unwrap();
        let mut buffer = sender.new_buffer();
        buffer
            .table("trades")
            .unwrap()
            .symbol("sym", "alpha")
            .unwrap()
            .at_now()
            .unwrap();
        sender.flush(&mut buffer).unwrap();
        if progress == QwpWsProgress::Manual {
            sender.drive_once().unwrap();
        }
        let (old, _) = server.frame();
        thread::sleep(Duration::from_millis(25));
        buffer
            .table("trades")
            .unwrap()
            .symbol("sym", "beta")
            .unwrap()
            .at_now()
            .unwrap();
        let started = std::time::Instant::now();
        assert_eq!(sender.flush_and_get_fsn(&mut buffer).unwrap(), Some(1));
        assert!(started.elapsed() < Duration::from_millis(100));
        sender.wait(AckLevel::Ok, Duration::from_secs(5)).unwrap();
        let (same, second) = server.frame();
        assert_eq!(old, same);
        assert_eq!(second[12], 1, "timeout retains the old namespace");
        buffer
            .table("trades")
            .unwrap()
            .symbol("sym", "gamma")
            .unwrap()
            .at_now()
            .unwrap();
        assert_eq!(sender.flush_and_get_fsn(&mut buffer).unwrap(), Some(2));
        sender.wait(AckLevel::Ok, Duration::from_secs(5)).unwrap();
        let (fresh, third) = server.frame();
        assert_ne!(
            fresh, old,
            "a spent wait still allows natural drained recycling"
        );
        assert_fresh(&third, "gamma");
    }
}

#[test]
fn recycle_boundary_manual_wait_drives_queued_frames() {
    let server = Server::new();
    let mut sender = SenderBuilder::from_conf(format!("ws::addr=127.0.0.1:{};symbol_dict_reset_threshold=1;symbol_dict_reset_max_wait_millis=100;", server.port)).unwrap().qwp_ws_progress(QwpWsProgress::Manual).unwrap().build().unwrap();
    let mut buffer = sender.new_buffer();
    buffer
        .table("trades")
        .unwrap()
        .symbol("sym", "alpha")
        .unwrap()
        .at_now()
        .unwrap();
    sender.flush(&mut buffer).unwrap();
    thread::sleep(Duration::from_millis(110));
    buffer
        .table("trades")
        .unwrap()
        .symbol("sym", "beta")
        .unwrap()
        .at_now()
        .unwrap();
    sender.flush(&mut buffer).unwrap();
    sender.wait(AckLevel::Ok, Duration::from_secs(5)).unwrap();
    let (old, first) = server.frame();
    let (new, second) = server.frame();
    assert_fresh(&first, "alpha");
    assert_fresh(&second, "beta");
    assert_ne!(
        old, new,
        "manual bounded wait must send and receive queued backlog"
    );
}

#[test]
fn recycle_boundary_split_completes_before_arming() {
    use crate::{QuestDb, ingress::column_sender::Chunk};
    let server = Server::new();
    let db = QuestDb::connect(&format!("ws::addr=127.0.0.1:{};lazy_connect=true;pool_reap=manual;max_buf_size=1024;symbol_dict_reset_threshold=1;symbol_dict_reset_max_wait_millis=0;", server.port)).unwrap();
    let mut sender = db.borrow_sender().unwrap();
    let codes = vec![0; 512];
    let values: Vec<i64> = (0..512).collect();
    let mut chunk = Chunk::new("trades");
    chunk
        .symbol_i32("sym", &codes, &[0, 5], b"alpha", None)
        .unwrap();
    chunk
        .column_i64("value", &values, None)
        .unwrap()
        .at_now()
        .unwrap();
    let last = sender.flush_and_get_fsn(&mut chunk).unwrap().unwrap();
    assert!(
        last > 0,
        "premise: one input must split into multiple frames"
    );
    sender.wait(AckLevel::Ok, Duration::from_secs(5)).unwrap();
    let mut connection = None;
    for index in 0..=last {
        let (current, frame) = server.frame();
        assert_eq!(*connection.get_or_insert(current), current);
        if index == 0 {
            assert_eq!(&frame[12..14], &[0, 1]);
        } else {
            assert_eq!(&frame[12..14], &[1, 0]);
        }
    }
    let mut buffer = db.new_buffer();
    buffer
        .table("trades")
        .unwrap()
        .symbol("sym", "beta")
        .unwrap()
        .at_now()
        .unwrap();
    assert_eq!(
        sender.flush_buffer_and_get_fsn(&mut buffer).unwrap(),
        Some(last + 1)
    );
    sender.wait(AckLevel::Ok, Duration::from_secs(5)).unwrap();
    let (fresh, frame) = server.frame();
    assert_ne!(Some(fresh), connection);
    assert_fresh(&frame, "beta");
}

#[cfg(feature = "polars-ingress")]
#[test]
fn recycle_boundary_polars_batches_use_pooled_arrow_boundary() {
    use crate::ingress::column_sender::ArrowColumnOverride;
    use crate::ingress::polars::dataframe_to_batches;
    use polars::prelude::{IntoColumn, NamedFrom, Series};
    let server = Server::new();
    let db = crate::QuestDb::connect(&format!("ws::addr=127.0.0.1:{};lazy_connect=true;pool_reap=manual;symbol_dict_reset_threshold=1;symbol_dict_reset_max_wait_millis=0;", server.port)).unwrap();
    let mut sender = db.borrow_sender().unwrap();
    let series = Series::new("sym".into(), &["alpha", "beta"]);
    let df = crate::polars_ffi::df_from_columns(vec![series.into_column()]).unwrap();
    let mut old_connection = None;
    for (index, batch) in dataframe_to_batches(&df, std::num::NonZeroUsize::new(1)).enumerate() {
        sender
            .flush_arrow_batch_at_now_and_wait(
                "trades",
                &batch.unwrap(),
                &[ArrowColumnOverride::Symbol { column: "sym" }],
                AckLevel::Ok,
            )
            .unwrap();
        let (connection, frame) = server.frame();
        assert_fresh(&frame, ["alpha", "beta"][index]);
        if let Some(old) = old_connection {
            assert_ne!(connection, old);
        }
        old_connection = Some(connection);
        assert_eq!(sender.published_fsn().unwrap(), Some(index as u64));
    }
    assert_eq!(sender.published_fsn().unwrap(), Some(1));
}

#[cfg(feature = "arrow-ingress")]
pub(crate) fn invalid_arrow_values() -> Vec<(arrow::array::RecordBatch, bool)> {
    use arrow::array::*;
    let cases: Vec<(ArrayRef, bool)> = vec![
        (Arc::new(TimestampMicrosecondArray::from(vec![None])), true),
        (Arc::new(TimestampNanosecondArray::from(vec![-1])), true),
        (
            Arc::new(TimestampMillisecondArray::from(vec![i64::MAX])),
            true,
        ),
        (Arc::new(TimestampSecondArray::from(vec![i64::MAX])), true),
        (Arc::new(DurationSecondArray::from(vec![i64::MAX])), false),
        (Arc::new(TimestampSecondArray::from(vec![i64::MAX])), false),
    ];
    cases
        .into_iter()
        .map(|(value, designated)| {
            (
                RecordBatch::try_from_iter(vec![
                    ("value", value),
                    ("payload", Arc::new(Int64Array::from(vec![1])) as ArrayRef),
                ])
                .unwrap(),
                designated,
            )
        })
        .collect()
}

#[cfg(feature = "arrow-ingress")]
#[test]
fn recycle_boundary_invalid_arrow_values_keep_connection() {
    use crate::ingress::{Buffer, ColumnName};
    use crate::{ErrorCode, QuestDb};
    for (batch, designated) in invalid_arrow_values() {
        let server = Server::new();
        let db = QuestDb::connect(&format!(
            "ws::addr=127.0.0.1:{};symbol_dict_reset_threshold=1;symbol_dict_reset_max_wait_millis=0;lazy_connect=true;pool_reap=manual;", server.port
        )).unwrap();
        let mut sender = db.borrow_sender().unwrap();
        let mut buffer = Buffer::new_qwp_ws();
        buffer
            .table("trades")
            .unwrap()
            .symbol("sym", "alpha")
            .unwrap()
            .at_now()
            .unwrap();
        sender
            .flush_buffer_and_wait(&mut buffer, AckLevel::Ok)
            .unwrap();
        server.frame();
        let error = if designated {
            sender.flush_arrow_batch_at_column(
                "trades",
                &batch,
                ColumnName::new("value").unwrap(),
                &[],
            )
        } else {
            sender.flush_arrow_batch_at_now("trades", &batch, &[])
        }
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::ArrowIngest);
        assert!(!error.in_doubt());
        assert_eq!(sender.published_fsn().unwrap(), Some(0));
        assert_eq!(server.connection_count(), 1);
    }
}

fn symbol_buffer(buffer: &mut crate::ingress::Buffer, symbol: &str) {
    buffer
        .table("trades")
        .unwrap()
        .symbol("sym", symbol)
        .unwrap()
        .at_now()
        .unwrap();
}

#[test]
fn recycle_api_advisory_and_pool_scope() {
    for progress in [QwpWsProgress::Background, QwpWsProgress::Manual] {
        for disk in [false, true] {
            for enabled in [false, true] {
                let server = Server::new();
                let dir = tempfile::TempDir::new().unwrap();
                let storage = if disk {
                    format!("sf_dir={};sender_id=advisory;", dir.path().display())
                } else {
                    String::new()
                };
                let mut sender = SenderBuilder::from_conf(format!("ws::addr=127.0.0.1:{};symbol_dict_reset={};symbol_dict_reset_threshold=100000;symbol_dict_reset_max_wait_millis=0;{storage}", server.port, if enabled {"on"} else {"off"})).unwrap().qwp_ws_progress(progress).unwrap().build().unwrap();
                let mut buffer = sender.new_buffer();
                symbol_buffer(&mut buffer, "alpha");
                sender.flush(&mut buffer).unwrap();
                sender.wait(AckLevel::Ok, Duration::from_secs(5)).unwrap();
                let (old, _) = server.frame();
                let dict_before = if disk {
                    Some(std::fs::read(dir.path().join("advisory/.symbol-dict")).unwrap())
                } else {
                    None
                };
                for _ in 0..3 {
                    sender.reset_symbol_dictionary().unwrap();
                }
                assert_eq!(sender.published_fsn().unwrap(), Some(0));
                assert_eq!(sender.acked_fsn().unwrap(), Some(0));
                assert_eq!(server.connection_count(), 1);
                assert!(matches!(
                    server.frames.try_recv(),
                    Err(mpsc::TryRecvError::Empty)
                ));
                if let Some(bytes) = dict_before {
                    assert_eq!(
                        std::fs::read(dir.path().join("advisory/.symbol-dict")).unwrap(),
                        bytes
                    );
                }
                assert_eq!(sender.flush_and_get_fsn(&mut buffer).unwrap(), None);
                assert_eq!(server.connection_count(), 1);
                symbol_buffer(&mut buffer, "beta");
                assert_eq!(sender.flush_and_get_fsn(&mut buffer).unwrap(), Some(1));
                sender.wait(AckLevel::Ok, Duration::from_secs(5)).unwrap();
                let (new, frame) = server.frame();
                if enabled {
                    assert_ne!(old, new);
                    assert_fresh(&frame, "beta");
                } else {
                    assert_eq!(old, new);
                    assert_symbol(&frame, "beta", 1);
                }
                symbol_buffer(&mut buffer, "gamma");
                sender.flush(&mut buffer).unwrap();
                sender.wait(AckLevel::Ok, Duration::from_secs(5)).unwrap();
                assert_eq!(
                    server.frame().0,
                    new,
                    "repeated advisory requests must coalesce"
                );
                sender.close_drain().unwrap();
                assert!(
                    sender.reset_symbol_dictionary().is_err(),
                    "closed SF state must surface its existing error"
                );
            }
        }
    }
    let server = Server::new();
    let db = crate::QuestDb::connect(&format!("ws::addr=127.0.0.1:{};lazy_connect=true;sender_pool_max=2;pool_reap=manual;symbol_dict_reset_threshold=100000;symbol_dict_reset_max_wait_millis=0;", server.port)).unwrap();
    let mut first = db.borrow_sender().unwrap();
    let mut other = db.borrow_sender().unwrap();
    let mut buffer = db.new_buffer();
    symbol_buffer(&mut buffer, "alpha");
    first
        .flush_buffer_and_wait(&mut buffer, AckLevel::Ok)
        .unwrap();
    let (old, _) = server.frame();
    symbol_buffer(&mut buffer, "alpha");
    other
        .flush_buffer_and_wait(&mut buffer, AckLevel::Ok)
        .unwrap();
    let (unaffected, _) = server.frame();
    first.reset_symbol_dictionary().unwrap();
    first.reset_symbol_dictionary().unwrap();
    drop(first);
    let mut first = db.borrow_sender().unwrap();
    first.wait(AckLevel::Ok, Duration::from_millis(1)).unwrap();
    symbol_buffer(&mut buffer, "beta");
    first
        .flush_buffer_and_wait(&mut buffer, AckLevel::Ok)
        .unwrap();
    let (new, frame) = server.frame();
    assert_ne!(old, new);
    assert_fresh(&frame, "beta");
    assert_eq!(first.published_fsn().unwrap(), Some(1));
    symbol_buffer(&mut buffer, "beta");
    other
        .flush_buffer_and_wait(&mut buffer, AckLevel::Ok)
        .unwrap();
    let (same, frame) = server.frame();
    assert_eq!(same, unaffected);
    assert_symbol(&frame, "beta", 1);
    drop(first);
    drop(other);
    db.close();
}

#[test]
fn recycle_observation_three_epochs() {
    use crate::ingress::{QwpWsErrorCategory, QwpWsErrorPolicy};
    for progress in [QwpWsProgress::Background, QwpWsProgress::Manual] {
        let server = Server::with_behavior(Duration::ZERO, Some((2, 2)));
        let (tx, rx) = mpsc::channel();
        let caller = thread::current().id();
        let mut sender = SenderBuilder::from_conf(format!("ws::addr=127.0.0.1:{};symbol_dict_reset_threshold=100000;symbol_dict_reset_max_wait_millis=0;", server.port)).unwrap().qwp_ws_progress(progress).unwrap().qwp_ws_error_handler(move |error| { tx.send((thread::current().id(), error.clone())).unwrap(); }).unwrap().build().unwrap();
        let mut buffer = sender.new_buffer();
        let mut prior_acks = 0;
        let mut prior_replayed = 0;
        for epoch in 0..3 {
            if epoch > 0 {
                sender.reset_symbol_dictionary().unwrap();
            }
            for row in 0..2 {
                server.acks_released.store(false, Ordering::Release);
                symbol_buffer(&mut buffer, if row == 0 { "alpha" } else { "beta" });
                let fsn = epoch * 2 + row;
                assert_eq!(sender.flush_and_get_fsn(&mut buffer).unwrap(), Some(fsn));
                let timeout = sender
                    .wait(AckLevel::Ok, Duration::from_millis(1))
                    .unwrap_err();
                assert_eq!(timeout.code(), crate::ErrorCode::FailoverRetry);
                assert!(timeout.msg().contains(&format!("{fsn}")));
                server.acks_released.store(true, Ordering::Release);
                sender.wait(AckLevel::Ok, Duration::from_secs(5)).unwrap();
                let (connection, frame) = server.frame();
                assert_eq!(connection, epoch as usize);
                if row == 0 {
                    assert_fresh(&frame, "alpha");
                }
                assert_eq!(sender.published_fsn().unwrap(), Some(fsn));
                assert_eq!(sender.acked_fsn().unwrap(), Some(fsn));
                assert_eq!(sender.completed_fsn(AckLevel::Ok).unwrap(), Some(fsn));
                assert!(sender.poll_qwp_ws_error().unwrap().is_none());
                let totals = sender.qwp_ws_totals().unwrap();
                assert_eq!(totals.frames_sent, fsn + 1);
                assert!(totals.frames_replayed >= prior_replayed);
                assert!(totals.frames_replayed <= totals.frames_sent);
                prior_replayed = totals.frames_replayed;
                assert_eq!(totals.server_errors, 0);
                assert!(
                    totals.acks >= prior_acks,
                    "retain existing background ACK accounting"
                );
                if progress == QwpWsProgress::Manual {
                    assert_eq!(totals.acks, fsn + 1);
                }
                prior_acks = totals.acks;
            }
        }
        // The terminal diagnostic belongs to public FSN six, wire sequence two
        // of the third session. Completed older boundaries cannot hide it.
        symbol_buffer(&mut buffer, "bad");
        assert_eq!(sender.flush_and_get_fsn(&mut buffer).unwrap(), Some(6));
        assert_eq!(
            sender
                .wait(AckLevel::Ok, Duration::from_secs(5))
                .unwrap_err()
                .code(),
            crate::ErrorCode::ServerRejection
        );
        assert_eq!(server.frame().0, 2);
        let error = sender.poll_qwp_ws_error().unwrap().unwrap();
        assert_eq!(
            (error.from_fsn, error.to_fsn, error.message_sequence),
            (6, 6, Some(2))
        );
        assert_eq!(error.category, QwpWsErrorCategory::ParseError);
        assert_eq!(error.applied_policy, QwpWsErrorPolicy::Terminal);
        let (callback_thread, callback) = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(
            callback_thread, caller,
            "standalone diagnostics run on the API caller"
        );
        assert_eq!(callback, error);
        assert!(sender.poll_qwp_ws_error().unwrap().is_none());
        assert_eq!(sender.qwp_ws_terminal_error().unwrap().unwrap(), error);
        assert_eq!(
            sender.reset_symbol_dictionary().unwrap_err().code(),
            crate::ErrorCode::ServerRejection
        );
        assert_eq!(
            sender
                .wait(AckLevel::Ok, Duration::from_millis(1))
                .unwrap_err()
                .code(),
            crate::ErrorCode::ServerRejection
        );
        assert_eq!(
            sender.close_drain().unwrap_err().code(),
            crate::ErrorCode::ServerRejection
        );
        assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
    }
}

#[test]
fn recycle_observation_three_epochs_pool_dispatchers() {
    use crate::{
        db::ConnectHandlers,
        ingress::{ConnectionEventKind, QwpWsErrorHandler},
    };
    let server = Server::with_behavior(Duration::from_millis(20), Some((2, 2)));
    let (events_tx, events_rx) = mpsc::channel();
    let (errors_tx, errors_rx) = mpsc::channel();
    let caller = thread::current().id();
    let db = crate::QuestDb::connect_with_handlers(&format!("ws::addr=127.0.0.1:{};lazy_connect=true;sender_pool_max=1;pool_reap=manual;symbol_dict_reset_threshold=100000;symbol_dict_reset_max_wait_millis=0;", server.port), ConnectHandlers {
        connection_listener: Some(Arc::new(move |event| { events_tx.send((thread::current().id(), event.kind)).unwrap(); })),
        error_handler: Some(QwpWsErrorHandler::new(move |error| { errors_tx.send((thread::current().id(), error.clone())).unwrap(); })),
        ..Default::default()
    }).unwrap();
    let mut buffer = db.new_buffer();
    let mut connection_dispatcher = None;
    for epoch in 0..3 {
        let mut sender = db.borrow_sender().unwrap();
        for row in 0..2 {
            symbol_buffer(&mut buffer, if row == 0 { "alpha" } else { "beta" });
            assert_eq!(
                sender.flush_buffer_and_get_fsn(&mut buffer).unwrap(),
                Some(epoch * 2 + row)
            );
            sender.wait(AckLevel::Ok, Duration::from_secs(5)).unwrap();
            assert_eq!(sender.acked_fsn().unwrap(), Some(epoch * 2 + row));
            assert_eq!(server.frame().0, epoch as usize);
            assert!(!sender.must_close_for_test());
        }
        loop {
            let (dispatcher, kind) = events_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            assert_ne!(dispatcher, caller);
            if let Some(previous) = connection_dispatcher {
                assert_eq!(dispatcher, previous);
            }
            connection_dispatcher = Some(dispatcher);
            if matches!(
                kind,
                ConnectionEventKind::Connected | ConnectionEventKind::Reconnected
            ) {
                break;
            }
        }
        if epoch < 2 {
            sender.reset_symbol_dictionary().unwrap();
        } else {
            symbol_buffer(&mut buffer, "bad");
            assert_eq!(
                sender.flush_buffer_and_get_fsn(&mut buffer).unwrap(),
                Some(6)
            );
            assert_eq!(
                sender
                    .wait(AckLevel::Ok, Duration::from_secs(5))
                    .unwrap_err()
                    .code(),
                crate::ErrorCode::ServerRejection
            );
            server.frame();
            let (dispatcher, error) = errors_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            assert_ne!(
                dispatcher, caller,
                "pooled diagnostics run on the pool dispatcher"
            );
            assert_eq!(
                (error.from_fsn, error.to_fsn, error.message_sequence),
                (6, 6, Some(2))
            );
            assert!(sender.must_close_for_test());
            assert!(sender.reset_symbol_dictionary().is_err());
        }
    }
    let mut sender = db.borrow_sender().unwrap();
    assert_eq!(
        sender.published_fsn().unwrap(),
        None,
        "terminal slot must be discarded on return"
    );
    assert!(!sender.must_close_for_test());
    symbol_buffer(&mut buffer, "replacement");
    sender
        .flush_buffer_and_wait(&mut buffer, AckLevel::Ok)
        .unwrap();
    assert_eq!(server.frame().0, 3);
    drop(sender);
    assert_eq!(db.connection_events_dropped(), 0);
    assert_eq!(db.rejection_events_dropped(), 0);
    assert!(matches!(
        errors_rx.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    db.close();
}

#[test]
fn recycle_api_pending_pool_return_and_close() {
    for disk in [false, true] {
        let server = Server::new();
        let dir = tempfile::TempDir::new().unwrap();
        let storage = if disk {
            format!("sf_dir={};sender_id=pending;", dir.path().display())
        } else {
            String::new()
        };
        let db = crate::QuestDb::connect(&format!("ws::addr=127.0.0.1:{};lazy_connect=true;sender_pool_max=1;pool_reap=manual;symbol_dict_reset_threshold=100000;symbol_dict_reset_max_wait_millis=0;{storage}", server.port)).unwrap();
        let mut buffer = db.new_buffer();
        let mut sender = db.borrow_sender().unwrap();
        symbol_buffer(&mut buffer, "alpha");
        sender
            .flush_buffer_and_wait(&mut buffer, AckLevel::Ok)
            .unwrap();
        let (old, _) = server.frame();
        sender.reset_symbol_dictionary().unwrap();
        crate::ingress::sender::fail_next_recycle_storage_for_test();
        symbol_buffer(&mut buffer, "beta");
        assert!(
            sender
                .flush_buffer(&mut buffer)
                .unwrap_err()
                .msg()
                .contains("injected recycle failure")
        );
        assert!(
            !sender.must_close_for_test(),
            "maintenance is not an unhealthy endpoint"
        );
        assert!(!buffer.is_empty());
        drop(sender);
        let mut sender = db.borrow_sender().unwrap();
        assert_eq!(sender.published_fsn().unwrap(), Some(0));
        sender.reset_symbol_dictionary().unwrap();
        sender
            .flush_buffer_and_wait(&mut buffer, AckLevel::Ok)
            .unwrap();
        let (fresh, frame) = server.frame();
        assert_ne!(fresh, old);
        assert_fresh(&frame, "beta");
        assert_eq!(sender.acked_fsn().unwrap(), Some(1));
        sender.reset_symbol_dictionary().unwrap();
        crate::ingress::sender::fail_next_recycle_storage_for_test();
        symbol_buffer(&mut buffer, "gamma");
        assert!(sender.flush_buffer(&mut buffer).is_err());
        drop(sender);
        db.close();
        if disk {
            // Final pool close releases every managed slot even with maintenance pending.
            let db = crate::QuestDb::connect(&format!("ws::addr=127.0.0.1:{};lazy_connect=true;sender_pool_max=1;pool_reap=manual;{storage}", server.port)).unwrap();
            let mut sender = db.borrow_sender().unwrap();
            buffer.clear();
            symbol_buffer(&mut buffer, "after_close");
            sender
                .flush_buffer_and_wait(&mut buffer, AckLevel::Ok)
                .unwrap();
            server.frame();
            drop(sender);
            db.close();
        }
    }
}

#[test]
fn recycle_api_disabled_pool_is_noop() {
    let server = Server::new();
    let db = crate::QuestDb::connect(&format!("ws::addr=127.0.0.1:{};lazy_connect=true;sender_pool_max=1;pool_reap=manual;symbol_dict_reset=off;symbol_dict_reset_threshold=1;symbol_dict_reset_max_wait_millis=0;", server.port)).unwrap();
    let mut sender = db.borrow_sender().unwrap();
    let mut buffer = db.new_buffer();
    symbol_buffer(&mut buffer, "alpha");
    sender
        .flush_buffer_and_wait(&mut buffer, AckLevel::Ok)
        .unwrap();
    let (old, _) = server.frame();
    sender.reset_symbol_dictionary().unwrap();
    drop(sender);
    let mut sender = db.borrow_sender().unwrap();
    symbol_buffer(&mut buffer, "beta");
    sender
        .flush_buffer_and_wait(&mut buffer, AckLevel::Ok)
        .unwrap();
    let (same, frame) = server.frame();
    assert_eq!(same, old);
    assert_symbol(&frame, "beta", 1);
    drop(sender);
    db.close();
}

#[test]
fn recycle_api_disabled_terminal_still_errors() {
    for progress in [QwpWsProgress::Background, QwpWsProgress::Manual] {
        let server = Server::with_behavior(Duration::ZERO, Some((0, 0)));
        let mut sender = SenderBuilder::from_conf(format!(
            "ws::addr=127.0.0.1:{};symbol_dict_reset=off;",
            server.port
        ))
        .unwrap()
        .qwp_ws_progress(progress)
        .unwrap()
        .build()
        .unwrap();
        let mut buffer = sender.new_buffer();
        symbol_buffer(&mut buffer, "bad");
        sender.flush(&mut buffer).unwrap();
        assert_eq!(
            sender
                .wait(AckLevel::Ok, Duration::from_secs(5))
                .unwrap_err()
                .code(),
            crate::ErrorCode::ServerRejection
        );
        server.frame();
        let error = sender.reset_symbol_dictionary().unwrap_err();
        assert_eq!(error.code(), crate::ErrorCode::ServerRejection);
        let rejection = error.qwp_ws_rejection().unwrap();
        assert_eq!((rejection.from_fsn, rejection.to_fsn), (0, 0));
    }
}

fn terminal_during_park_sender(
    server: &Server,
) -> (
    crate::ingress::Sender,
    mpsc::Receiver<crate::ingress::QwpWsSenderError>,
) {
    let (tx, rx) = mpsc::channel();
    let mut sender = SenderBuilder::from_conf(format!(
        "ws::addr=127.0.0.1:{};symbol_dict_reset_threshold=1;symbol_dict_reset_max_wait_millis=0;",
        server.port
    ))
    .unwrap()
    .qwp_ws_error_handler(move |error| {
        tx.send(error.clone()).unwrap();
    })
    .unwrap()
    .build()
    .unwrap();
    let mut buffer = sender.new_buffer();
    symbol_buffer(&mut buffer, "old");
    sender.flush(&mut buffer).unwrap();
    sender.wait(AckLevel::Ok, Duration::from_secs(5)).unwrap();
    server.frame();
    crate::ingress::sender::terminal_after_recycle_park_for_test();
    symbol_buffer(&mut buffer, "forbidden");
    let error = sender.flush(&mut buffer).unwrap_err();
    assert_eq!(error.code(), crate::ErrorCode::ServerRejection);
    assert!(!buffer.is_empty());
    (sender, rx)
}

fn assert_park_terminal(error: &crate::ingress::QwpWsSenderError) {
    assert_eq!(
        error.category,
        crate::ingress::QwpWsErrorCategory::ProtocolViolation
    );
    assert_eq!(
        error.applied_policy,
        crate::ingress::QwpWsErrorPolicy::Terminal
    );
    assert_eq!(
        (error.from_fsn, error.to_fsn, error.message_sequence),
        (1, 1, None)
    );
    assert_eq!(
        error.message.as_deref(),
        Some("ws-close[1002]: terminal during accepted park")
    );
}

#[test]
fn recycle_terminal_then_immediate_close() {
    // No API inspection after the first failing flush may repair bookkeeping.
    let server = Server::new();
    let (mut sender, rx) = terminal_during_park_sender(&server);
    assert_eq!(
        sender.close_drain().unwrap_err().code(),
        crate::ErrorCode::ServerRejection
    );
    drop(sender);
    assert_park_terminal(&rx.recv_timeout(Duration::from_secs(5)).unwrap());
    assert!(matches!(
        rx.try_recv(),
        Err(mpsc::TryRecvError::Disconnected)
    ));
    assert_eq!(server.connection_count(), 1);
    assert!(server.frames.try_recv().is_err());
}

#[test]
fn recycle_terminal_remains_sticky() {
    let server = Server::new();
    let (mut sender, rx) = terminal_during_park_sender(&server);
    let original = sender.poll_qwp_ws_error().unwrap().unwrap();
    assert_park_terminal(&original);
    let mut buffer = sender.new_buffer();
    symbol_buffer(&mut buffer, "forbidden");
    for _ in 0..3 {
        assert_eq!(
            sender.flush(&mut buffer).unwrap_err().code(),
            crate::ErrorCode::ServerRejection
        );
        assert_eq!(
            sender
                .wait(AckLevel::Ok, Duration::ZERO)
                .unwrap_err()
                .code(),
            crate::ErrorCode::ServerRejection
        );
        assert_eq!(sender.qwp_ws_terminal_error().unwrap().unwrap(), original);
    }
    assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), original);
    assert!(sender.poll_qwp_ws_error().unwrap().is_none());
    assert_eq!(
        sender.close_drain().unwrap_err().code(),
        crate::ErrorCode::ServerRejection
    );
    drop(sender);
    assert!(matches!(
        rx.try_recv(),
        Err(mpsc::TryRecvError::Disconnected)
    ));
    assert_eq!(server.connection_count(), 1);

    let db = crate::QuestDb::connect(&format!("ws::addr=127.0.0.1:{};lazy_connect=true;sender_pool_max=1;pool_reap=manual;symbol_dict_reset_threshold=1;symbol_dict_reset_max_wait_millis=0;", server.port)).unwrap();
    let mut buffer = db.new_buffer();
    let mut lease = db.borrow_sender().unwrap();
    symbol_buffer(&mut buffer, "old");
    lease
        .flush_buffer_and_wait(&mut buffer, AckLevel::Ok)
        .unwrap();
    server.frame();
    crate::ingress::sender::terminal_after_recycle_park_for_test();
    symbol_buffer(&mut buffer, "forbidden");
    assert_eq!(
        lease.flush_buffer(&mut buffer).unwrap_err().code(),
        crate::ErrorCode::ServerRejection
    );
    assert!(lease.must_close_for_test());
    drop(lease);
    let mut replacement = db.borrow_sender().unwrap();
    assert_eq!(replacement.published_fsn().unwrap(), None);
    replacement
        .flush_buffer_and_wait(&mut buffer, AckLevel::Ok)
        .unwrap();
    assert_fresh(&server.frame().1, "forbidden");
    drop(replacement);
    db.close();
}

#[test]
fn recycle_outage_after_commit() {
    for (initial, progress) in [
        ("off", QwpWsProgress::Background),
        ("sync", QwpWsProgress::Background),
        ("async", QwpWsProgress::Background),
        ("off", QwpWsProgress::Manual),
        ("sync", QwpWsProgress::Manual),
    ] {
        for fault in [1, 2] {
            let server = Server::new();
            let mut sender = SenderBuilder::from_conf(format!("ws::addr=127.0.0.1:{};initial_connect_retry={initial};symbol_dict_reset_threshold=100000;symbol_dict_reset_max_wait_millis=0;", server.port)).unwrap().qwp_ws_progress(progress).unwrap().build().unwrap();
            let mut buffer = sender.new_buffer();
            symbol_buffer(&mut buffer, "retired");
            sender.flush(&mut buffer).unwrap();
            sender.wait(AckLevel::Ok, Duration::from_secs(5)).unwrap();
            server.frame();
            server.upgrade_fault.store(fault, Ordering::Release);
            sender.reset_symbol_dictionary().unwrap();
            symbol_buffer(&mut buffer, "current");
            assert_eq!(sender.flush_and_get_fsn(&mut buffer).unwrap(), Some(1));
            assert!(
                sender
                    .wait(AckLevel::Ok, Duration::from_millis(50))
                    .is_err()
            );
            assert!(
                server.connection_count() >= 2,
                "must exercise the injected upgrade/socket fault"
            );
            symbol_buffer(&mut buffer, "queued");
            assert_eq!(sender.flush_and_get_fsn(&mut buffer).unwrap(), Some(2));
            assert_eq!(sender.acked_fsn().unwrap(), Some(0));
            server.upgrade_fault.store(0, Ordering::Release);
            sender.wait(AckLevel::Ok, Duration::from_secs(5)).unwrap();
            assert_fresh(&server.frame().1, "current");
            assert_symbol(&server.frame().1, "queued", 1);
            assert_eq!(sender.acked_fsn().unwrap(), Some(2));
            // Reconnect once more after the fresh mirror has accumulated symbols.
            server.upgrade_fault.store(3, Ordering::Release);
            symbol_buffer(&mut buffer, "lost");
            assert_eq!(sender.flush_and_get_fsn(&mut buffer).unwrap(), Some(3));
            assert!(
                sender
                    .wait(AckLevel::Ok, Duration::from_millis(50))
                    .is_err()
            );
            let (_, unacked) = server.frame();
            assert_symbol(&unacked, "lost", 2);
            assert_eq!(server.upgrade_fault.load(Ordering::Acquire), 1);
            server.upgrade_fault.store(0, Ordering::Release);
            sender.wait(AckLevel::Ok, Duration::from_secs(5)).unwrap();
            let (_, catchup) = server.frame();
            assert_eq!(&catchup[6..8], &[0, 0], "catch-up contains no table rows");
            let mut pos = 12;
            assert_eq!(varint(&catchup, &mut pos), 0);
            assert_eq!(varint(&catchup, &mut pos), 3);
            for expected in ["current", "queued", "lost"] {
                let len = varint(&catchup, &mut pos);
                assert_eq!(&catchup[pos..pos + len], expected.as_bytes());
                pos += len;
            }
            assert_eq!(
                pos,
                catchup.len(),
                "no retired symbols may survive in catch-up"
            );
            assert_eq!(
                server.frame().1,
                unacked,
                "replay preserves exactly the retained row"
            );
            assert_eq!(sender.acked_fsn().unwrap(), Some(3));
        }
    }
}

#[test]
fn recycle_resources_repeated() {
    for disk in [false, true] {
        for pooled in [false, true] {
            let server = Server::new();
            let dir = tempfile::TempDir::new().unwrap();
            let storage = if disk {
                format!("sf_dir={};sender_id=resources;", dir.path().display())
            } else {
                String::new()
            };
            let conf = format!(
                "ws::addr=127.0.0.1:{};symbol_dict_reset_threshold=1;symbol_dict_reset_max_wait_millis=0;sf_max_segment_bytes=4096;sf_max_total_bytes=32768;{storage}",
                server.port
            );
            // Exercise the same assertions through both real facades.
            macro_rules! cycles {
                ($sender:ident, $flush:ident) => {{
                    let mut buffer = crate::ingress::Buffer::new_qwp_ws();
                    symbol_buffer(&mut buffer, "old");
                    $sender.$flush(&mut buffer).unwrap();
                    $sender.wait(AckLevel::Ok, Duration::from_secs(5)).unwrap();
                    server.frame();
                    let probe = $sender.recycle_allocation_probe();
                    let baseline = probe().unwrap();
                    for cycle in 0..80 {
                        // Cycle zero is naturally armed; all later cycles use the advisory API.
                        if cycle > 0 {
                            $sender.reset_symbol_dictionary().unwrap();
                        }
                        symbol_buffer(&mut buffer, "fresh");
                        if cycle >= 40 {
                            crate::ingress::sender::fail_next_recycle_storage_for_test();
                            let error = $sender.$flush(&mut buffer).unwrap_err();
                            assert!(error.msg().contains("injected recycle failure"));
                            assert_eq!($sender.published_fsn().unwrap(), Some(cycle));
                            assert!(!buffer.is_empty());
                        }
                        $sender.$flush(&mut buffer).unwrap();
                        $sender.wait(AckLevel::Ok, Duration::from_secs(5)).unwrap();
                        let (connection, frame) = server.frame();
                        assert_eq!(connection, cycle as usize + 1);
                        assert_fresh(&frame, "fresh");
                        assert_eq!($sender.published_fsn().unwrap(), Some(cycle + 1));
                        assert!(
                            probe().unwrap() <= baseline,
                            "segment budget must return after each resumed commit"
                        );
                    }
                    probe
                }};
            }
            if pooled {
                let db = crate::QuestDb::connect(&format!("{conf}lazy_connect=true;sender_pool_max=1;pool_reap=manual;acquire_timeout_ms=0;")).unwrap();
                let mut sender = db.borrow_sender().unwrap();
                let probe = cycles!(sender, flush_buffer);
                assert!(
                    db.borrow_sender().is_err(),
                    "a live lease still occupies exactly one slot"
                );
                drop(sender);
                let returned = db.borrow_sender().unwrap();
                assert_eq!(returned.published_fsn().unwrap(), Some(80));
                assert!(!returned.must_close_for_test());
                drop(returned);
                db.close();
                assert_eq!(
                    probe(),
                    None,
                    "pool close must release the queue, allocations and worker ownership"
                );
            } else {
                let mut sender = SenderBuilder::from_conf(&conf).unwrap().build().unwrap();
                let probe = cycles!(sender, flush);
                sender.close_drain().unwrap();
                drop(sender);
                assert_eq!(
                    probe(),
                    None,
                    "close must release the queue, allocations and worker ownership"
                );
            }
            // The exact slot can be owned again only after close; no handle leaks.
            if disk {
                let suffix = if pooled {
                    "resources-ingest-0"
                } else {
                    "resources"
                };
                let mut sender = SenderBuilder::from_conf(format!(
                    "ws::addr=127.0.0.1:{};sf_dir={};sender_id={suffix};",
                    server.port,
                    dir.path().display()
                ))
                .unwrap()
                .build()
                .unwrap();
                sender.close_drain().unwrap();
            }
        }
    }
}
