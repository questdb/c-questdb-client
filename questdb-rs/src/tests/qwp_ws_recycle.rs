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
use super::qwp_ws::{perform_server_upgrade, read_frame, write_qwp_ok_response};
use crate::ingress::{AckLevel, QwpWsProgress, SenderBuilder, TimestampNanos};
use std::net::TcpListener;
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
    worker: Option<thread::JoinHandle<()>>,
}
impl Server {
    pub(crate) fn new() -> Self {
        Self::with_ack_delay(Duration::ZERO)
    }
    fn with_ack_delay(ack_delay: Duration) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&stop);
        let (tx, frames) = mpsc::channel();
        let worker = thread::spawn(move || {
            let mut connection = 0;
            let mut workers = Vec::new();
            while !stopped.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let tx = tx.clone();
                        let id = connection;
                        connection += 1;
                        workers.push(thread::spawn(move || {
                            stream.set_nonblocking(false).unwrap();
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
                                if frame_deferred {
                                    seq += 1;
                                    continue;
                                }
                                thread::sleep(ack_delay);
                                if write_qwp_ok_response(&mut stream, seq).is_err() {
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
            worker: Some(worker),
        }
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
