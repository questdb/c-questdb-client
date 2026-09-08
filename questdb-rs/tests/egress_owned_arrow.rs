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
use questdb::ErrorCode;
use questdb::QuestDb;
use questdb::egress::{FailoverResetEvent, Reader, ServerRole};
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
/// not panic, and must retire the connection rather than recycle it with an
/// unread remainder still on the wire.
///
/// `lazy_connect=on` is load-bearing: without it the pool dials eagerly at
/// `connect()` time and `server.accepts()` stops being a usable signal for
/// *this* test's dials. With it, the accept count is the observable — a
/// regression that recycled the torn connection instead of retiring it would
/// leave `accepts() == 1`, whereas merely asserting that a later
/// `take_reader()` succeeds cannot tell the two apart. Same shape as
/// `dropping_an_owned_cursor_mid_stream_retires_the_connection` in
/// `egress_owned.rs`.
#[test]
fn abandoning_the_stream_releases_the_pooled_reader() {
    let abandoned = batches_script(&[(0, vec![1, 2, 3]), (1, vec![4, 5])]);
    let follow_up = batches_script(&[(0, vec![9])]);
    let server = MockServer::start(vec![abandoned, follow_up]);
    let conf = format!(
        "ws::addr={};lazy_connect=on;query_pool_max=1;",
        server.url()
    );
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
    // freeing pool capacity for a fresh dial). Driving the follow-up query
    // to completion proves the connection it ran on is intact, not a
    // recycled half-read one.
    let mut again = db
        .take_reader()
        .expect("reader must be available again")
        .query("SELECT 1")
        .execute()
        .expect("execute on a fresh connection")
        .into_arrow_reader()
        .expect("into_arrow_reader");
    let rows: usize = (&mut again).map(|b| b.expect("batch").num_rows()).sum();
    assert_eq!(rows, 1, "the follow-up script's single row must arrive");
    assert_eq!(
        server.accepts(),
        2,
        "the abandoned connection must have been retired, forcing a redial"
    );
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

// ---------------------------------------------------------------------------
// Post-failover replay through the owned adapter.
//
// Threading `on_failover_reset` into `OwnedCursor` made this path reachable:
// the callback clears the silent-duplicate guard, so a failover *after* a
// batch has been delivered replays from `batch_seq 0` on the new endpoint and
// the replayed frame reaches `OwnedArrowReader`. It carries the new node's
// inline schema, which the pinned-schema drift check would reject out of hand
// — hence the `resets_at_pin` dance mirrored from `CursorRecordBatchReader`.
// ---------------------------------------------------------------------------

/// A serves one batch and drops; B replays the query from `batch_seq 0`.
/// `b_column` is B's replayed batch, so the caller picks whether the replay
/// carries the same schema as A's LONG batch or a divergent one.
fn replay_servers(b_column: BatchColumn) -> (MockServer, MockServer) {
    let a = MockServer::start(vec![vec![
        Action::SendServerInfo {
            role: ServerRole::Standalone,
            node_id: "a".into(),
        },
        Action::AwaitQueryRequest,
        Action::SendBatch {
            batch_seq: 0,
            column: BatchColumn::Long(vec![1, 2]),
        },
        Action::HardDrop,
    ]]);
    let b = MockServer::start(vec![vec![
        Action::SendServerInfo {
            role: ServerRole::Standalone,
            node_id: "b".into(),
        },
        Action::AwaitQueryRequest,
        Action::SendBatch {
            batch_seq: 0,
            column: b_column,
        },
        Action::SendResultEnd,
    ]]);
    (a, b)
}

fn replay_conf(a: &MockServer, b: &MockServer) -> String {
    format!(
        "ws::addr={};failover_backoff_initial_ms=1;failover_backoff_max_ms=10",
        build_addr_list(&[a, b])
    )
}

/// With a reset callback installed, a post-delivery failover replays through
/// the owned adapter. The replayed `batch_seq 0` frame re-sends the new node's
/// schema, so the pinned-schema drift check must be relaxed for exactly that
/// frame — otherwise every authorised replay surfaces as a spurious
/// `SchemaDrift` and the reader poisons on a perfectly healthy stream.
///
/// The owning counterpart of `egress_failover.rs`'s
/// `failover_arrow_reader_same_schema_continues`.
#[test]
fn failover_replay_with_the_same_schema_keeps_streaming() {
    let (srv_a, srv_b) = replay_servers(BatchColumn::Long(vec![3, 4, 5]));
    let owner = Reader::from_conf(replay_conf(&srv_a, &srv_b)).expect("connect to A");

    let mut reader = owner
        .into_query("select 1")
        .on_failover_reset(|_: &FailoverResetEvent| {})
        .execute()
        .expect("execute")
        .into_arrow_reader()
        .expect("into_arrow_reader");
    let pinned = reader.schema();

    // A's pre-drop batch, pinned at construction.
    let b1 = reader.next().expect("first item").expect("first batch ok");
    assert_eq!(b1.num_rows(), 2);
    assert_eq!(b1.schema(), pinned);

    // A is gone: this call observes the close, fails over, and replays. B's
    // batch 0 carries the same schema, so it must be yielded, not rejected.
    let b2 = reader
        .next()
        .expect("post-failover item")
        .expect("post-failover batch must not be rejected as drift");
    assert_eq!(b2.num_rows(), 3);
    assert_eq!(b2.schema(), pinned);
    assert_eq!(
        reader.schema(),
        pinned,
        "RecordBatchReader::schema must stay stable across the replay"
    );

    assert!(
        reader.next().is_none(),
        "B's RESULT_END terminates the reader cleanly"
    );
}

/// Negative control for the test above: relaxing the drift check for the
/// replayed frame must not become "accept whatever the new node sends". A
/// `RecordBatchReader`'s schema is fixed for its lifetime, so a genuinely
/// different post-failover schema has to poison with `SchemaDrift` rather
/// than be silently swapped in.
///
/// The owning counterpart of `egress_failover.rs`'s
/// `failover_arrow_reader_schema_drift_poisons`.
#[test]
fn failover_replay_with_a_different_schema_poisons() {
    let (srv_a, srv_b) = replay_servers(BatchColumn::Double(vec![1.5, 2.5, 3.5]));
    let owner = Reader::from_conf(replay_conf(&srv_a, &srv_b)).expect("connect to A");

    let mut reader = owner
        .into_query("select 1")
        .on_failover_reset(|_: &FailoverResetEvent| {})
        .execute()
        .expect("execute")
        .into_arrow_reader()
        .expect("into_arrow_reader");

    let b1 = reader.next().expect("first item").expect("first batch ok");
    assert_eq!(b1.num_rows(), 2);

    let err = reader
        .next()
        .expect("post-failover item present")
        .expect_err("divergent post-failover schema must yield an error");
    let qerr = questdb::egress::arrow::try_downcast_questdb(&err)
        .expect("adapter error downcasts to a questdb Error");
    assert_eq!(qerr.code(), ErrorCode::SchemaDrift);

    assert!(reader.next().is_none(), "reader is poisoned after drift");
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
