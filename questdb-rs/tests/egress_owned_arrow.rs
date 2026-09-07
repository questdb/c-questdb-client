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

//! `OwnedArrowReader`: the owned counterpart of `CursorRecordBatchReader`.
//!
//! This is the exact shape ADBC needs: an owned `Box<dyn RecordBatchReader +
//! Send>`, with a valid schema before iteration, consumed by value. Protocol
//! behaviour (failover, decode, drift) is already covered against the same
//! mock by `egress_failover.rs` and the `arrow::reader` unit tests; these
//! tests are about ownership shape, same as `egress_owned.rs`.

#![cfg(all(feature = "sync-reader-qwp-ws", feature = "arrow-egress"))]

#[path = "common/qwp_mock.rs"]
mod qwp_mock;

use arrow::array::RecordBatchReader;
use questdb::QuestDb;
use questdb::egress::ServerRole;
use qwp_mock::*;

fn server_info() -> Action {
    Action::SendServerInfo {
        role: ServerRole::Primary,
        node_id: "n1".into(),
    }
}

/// One complete query round: await the `QUERY_REQUEST`, stream one
/// `RESULT_BATCH` per `(batch_seq, rows)` pair, terminate cleanly.
fn batches_script(rounds: &[(u64, Vec<i64>)]) -> Script {
    let mut s = vec![server_info(), Action::AwaitQueryRequest];
    for (batch_seq, rows) in rounds {
        s.push(Action::SendBatch {
            batch_seq: *batch_seq,
            column: BatchColumn::Long(rows.clone()),
        });
    }
    s.push(Action::SendResultEnd);
    s
}

/// The exact shape ADBC needs: an owned `Box<dyn RecordBatchReader + Send>`,
/// with a valid schema before iteration, consumed by value.
#[test]
fn boxed_dyn_record_batch_reader_streams_to_completion() {
    let script = batches_script(&[(0, vec![1, 2, 3]), (1, vec![4, 5])]);
    let server = MockServer::start(vec![script]);
    let conf = format!("ws::addr={};", server.url());
    let db = QuestDb::connect(&conf).expect("connect");

    let reader: Box<dyn RecordBatchReader + Send> = Box::new(
        db.take_reader()
            .expect("take_reader")
            .query("SELECT 1")
            .execute()
            .expect("execute")
            .into_arrow_reader()
            .expect("into_arrow_reader"),
    );

    // Schema must be available before any iteration.
    assert!(
        !reader.schema().fields().is_empty(),
        "schema must be known up front"
    );

    let rows: usize = reader.map(|b| b.expect("batch").num_rows()).sum();
    assert_eq!(rows, 5, "expected all scripted rows");
}

/// Abandoning the stream part-way is what a LIMIT or an error does. It must
/// not panic, and must release the reader back to the pool.
#[test]
fn abandoning_the_stream_releases_the_pooled_reader() {
    let abandoned = batches_script(&[(0, vec![1, 2, 3]), (1, vec![4, 5])]);
    let follow_up = batches_script(&[(0, vec![9])]);
    let server = MockServer::start(vec![abandoned, follow_up]);
    let conf = format!("ws::addr={};query_pool_max=1;", server.url());
    let db = QuestDb::connect(&conf).expect("connect");

    {
        let mut reader = db
            .take_reader()
            .expect("take_reader")
            .query("SELECT 1")
            .execute()
            .expect("execute")
            .into_arrow_reader()
            .expect("into_arrow_reader");
        let _first = reader.next();
        // dropped mid-stream: the second scripted batch is never consumed.
    }

    // Only succeeds if the abandoned reader was released (or retired,
    // freeing pool capacity for a fresh dial).
    let _again = db.take_reader().expect("reader must be available again");
}

/// A statement that produces no batch at all (DDL) must not be treated as
/// an error: it yields an empty schema and an immediately-exhausted stream.
#[test]
fn no_batch_at_all_yields_empty_schema_and_exhausted_stream() {
    let server = MockServer::start(vec![happy_script(ServerRole::Primary, "n1")]);
    let conf = format!("ws::addr={};", server.url());
    let db = QuestDb::connect(&conf).expect("connect");

    let mut reader = db
        .take_reader()
        .expect("take_reader")
        .query("SELECT 1")
        .execute()
        .expect("execute")
        .into_arrow_reader()
        .expect("into_arrow_reader");

    assert!(
        reader.schema().fields().is_empty(),
        "no batch at all must yield an empty schema, not an error"
    );
    assert!(
        reader.next().is_none(),
        "stream must be immediately exhausted"
    );
}

/// `OwnedCursor::next_arrow_batch` (no drift check) must be reachable
/// independently of `into_arrow_reader`, mirroring
/// `Cursor::next_arrow_batch`.
#[test]
fn next_arrow_batch_is_reachable_without_the_reader_adapter() {
    let script = batches_script(&[(0, vec![7, 8])]);
    let server = MockServer::start(vec![script]);
    let conf = format!("ws::addr={};", server.url());
    let db = QuestDb::connect(&conf).expect("connect");

    let mut cursor = db
        .take_reader()
        .expect("take_reader")
        .query("SELECT 1")
        .execute()
        .expect("execute");

    let batch = cursor
        .next_arrow_batch()
        .expect("next_arrow_batch")
        .expect("a batch");
    assert_eq!(batch.num_rows(), 2);
    assert!(
        cursor.next_arrow_batch().expect("drain").is_none(),
        "stream must end after RESULT_END"
    );
}

/// Compile-time assertion: `OwnedArrowReader<OwnedReader>` (the pooled,
/// `'static` shape ADBC actually uses) must be `Send`. Gated separately on
/// `sync-sender-qwp-ws` (not part of this file's top-level `cfg`) because
/// that is what makes `questdb::OwnedReader` / `PooledCursor` exist at all.
#[test]
#[cfg(feature = "sync-sender-qwp-ws")]
fn pooled_arrow_reader_is_send() {
    fn assert_send<T: Send>() {}
    assert_send::<questdb::egress::PooledCursor>();
    assert_send::<questdb::egress::OwnedArrowReader<questdb::OwnedReader>>();
}
