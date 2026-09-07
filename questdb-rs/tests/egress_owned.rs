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

//! Owning egress handles: `OwnedQuery` / `OwnedCursor` and their
//! pool-backed aliases `PooledQuery` / `PooledCursor`.
//!
//! The point of these types is that they carry **no lifetime**, so a
//! consumer that must own its result stream — a C ABI with nowhere to put a
//! lifetime, or ADBC's `Statement::execute` returning
//! `Box<dyn RecordBatchReader + Send + 'static>` — does not have to
//! hand-roll a self-referential struct with `transmute` + `ManuallyDrop`.
//! Every test here is therefore about *ownership shape*, not about protocol
//! behaviour (which `egress_failover.rs` already covers on the borrowing
//! path against the same mock).

// `QuestDb` / `OwnedReader` (and hence `PooledQuery` / `PooledCursor`) are
// gated on the QWP/WS sender as well as the reader.
#![cfg(all(feature = "sync-reader-qwp-ws", feature = "sync-sender-qwp-ws"))]

#[path = "common/qwp_mock.rs"]
mod qwp_mock;

use questdb::QuestDb;
use questdb::egress::{PooledCursor, ServerRole};
use qwp_mock::*;

/// `happy_script` replies `SERVER_INFO`, awaits the query and sends
/// `RESULT_END` — it never scripts a `RESULT_BATCH`, so a query against it
/// always yields zero batches. These tests want to prove rows actually
/// crossed the wire into an *owned* cursor, so they script the batch.
fn server_info() -> Action {
    Action::SendServerInfo {
        role: ServerRole::Primary,
        node_id: "n1".into(),
    }
}

/// One complete query round on an already-handshaken connection: await the
/// QUERY_REQUEST, stream a single-column batch, terminate.
fn one_batch_round(rows: Vec<i64>) -> Vec<Action> {
    vec![
        Action::AwaitQueryRequest,
        Action::SendBatch {
            batch_seq: 0,
            column: BatchColumn::Long(rows),
        },
        Action::SendResultEnd,
    ]
}

fn script(rounds: usize) -> Script {
    let mut s = vec![server_info()];
    for i in 0..rounds {
        s.extend(one_batch_round(vec![10 * (i as i64 + 1)]));
    }
    s
}

/// `lazy_connect=on` stops `QuestDb::connect` pre-opening `sender_pool_min`
/// ingest senders and `query_pool_min` readers against a mock that only
/// speaks the egress side. Every accept these tests observe is then a reader
/// connection the test itself asked for, which is what makes
/// `MockServer::accepts()` a usable assertion.
fn pool_conf(server: &MockServer) -> String {
    format!("ws::addr={};lazy_connect=on;", server.url())
}

/// The shape every owning consumer needs: a cursor with no lifetime, still
/// usable after the function that made it — and the `QuestDb` handle it was
/// made from — has returned.
///
/// This test would not compile against `Cursor<'r>` at all: that is the
/// point.
#[test]
fn an_owned_cursor_outlives_the_scope_that_made_it() {
    let server = MockServer::start(vec![script(1)]);
    let conf = pool_conf(&server);

    fn make_cursor(conf: &str) -> PooledCursor {
        let db = QuestDb::connect(conf).expect("connect");
        let reader = db.take_reader().expect("take_reader");
        reader.query("SELECT 1").execute().expect("execute")
        // `db` and `reader` both go out of scope here; the cursor owns
        // everything it needs to keep streaming.
    }

    let mut cursor = make_cursor(&conf);
    let mut batches = 0;
    while cursor.next_batch().expect("next_batch") {
        batches += 1;
    }
    assert_eq!(
        batches, 1,
        "the scripted RESULT_BATCH must reach a cursor whose creator has returned"
    );
    assert!(
        cursor.terminal().is_some(),
        "stream should have terminated on RESULT_END"
    );
    assert!(
        cursor.request_id() > 0,
        "the cursor must expose the request_id it submitted under"
    );
    assert!(
        cursor.connection_reusable(),
        "a cleanly drained cursor leaves its connection reusable"
    );
}

/// An owned cursor must be movable across threads — a
/// `Box<dyn RecordBatchReader + Send>` consumer will do exactly this.
#[test]
fn an_owned_cursor_can_be_moved_across_threads() {
    let server = MockServer::start(vec![script(1)]);
    let db = QuestDb::connect(&pool_conf(&server)).expect("connect");
    let cursor = db
        .take_reader()
        .expect("take_reader")
        .query("SELECT 1")
        .execute()
        .expect("execute");

    let batches = std::thread::spawn(move || {
        let mut cursor = cursor;
        let mut n = 0;
        while cursor.next_batch().expect("next_batch") {
            n += 1;
        }
        n
    })
    .join()
    .expect("thread");

    assert_eq!(batches, 1, "the moved cursor must drive the same stream");
}

/// `PooledCursor` must satisfy the bounds an ADBC / FFI consumer needs:
/// `Send + 'static`. Compile-time assertion, no runtime behaviour.
#[test]
fn pooled_cursor_is_send_and_static() {
    fn assert_send_static<T: Send + 'static>() {}
    assert_send_static::<PooledCursor>();
    assert_send_static::<questdb::egress::PooledQuery>();
}

/// `into_owner` hands the connection back so the caller can run another
/// query on it — the same *physical* connection, which is what makes the
/// owning handle usable in a pool.
#[test]
fn into_owner_returns_a_reusable_reader() {
    let server = MockServer::start(vec![script(2)]);
    let db = QuestDb::connect(&pool_conf(&server)).expect("connect");

    let mut cursor = db
        .take_reader()
        .expect("take_reader")
        .query("SELECT 1")
        .execute()
        .expect("execute");
    while cursor.next_batch().expect("drain") {}
    let first_request_id = cursor.request_id();
    let reader = cursor.into_owner();

    let mut second = reader
        .query("SELECT 2")
        .execute()
        .expect("second execute on the handed-back reader");
    while second.next_batch().expect("drain") {}
    assert!(second.terminal().is_some());
    assert_ne!(
        second.request_id(),
        first_request_id,
        "the second query must allocate a fresh request_id"
    );
    assert_eq!(
        server.accepts(),
        1,
        "into_owner must hand back the live connection, not force a reconnect"
    );
}

/// Dropping an owned cursor mid-stream must run the same teardown the
/// borrowing `Cursor`'s `Drop` runs: CANCEL + close, so the connection is
/// retired rather than recycled with a half-read result on it.
///
/// Observable proof: the retired reader cannot be reused, so the next
/// `take_reader` has to dial a second connection.
#[test]
fn dropping_an_owned_cursor_mid_stream_retires_the_connection() {
    let abandoned = vec![
        server_info(),
        Action::AwaitQueryRequest,
        Action::SendBatch {
            batch_seq: 0,
            column: BatchColumn::Long(vec![1, 2, 3]),
        },
        Action::SendBatch {
            batch_seq: 1,
            column: BatchColumn::Long(vec![4, 5, 6]),
        },
    ];
    let server = MockServer::start(vec![abandoned, script(1)]);
    let db = QuestDb::connect(&pool_conf(&server)).expect("connect");

    {
        let mut cursor = db
            .take_reader()
            .expect("take_reader")
            .query("SELECT 1")
            .execute()
            .expect("execute");
        assert!(
            cursor.next_batch().expect("first batch"),
            "the scripted batch must arrive"
        );
        assert!(
            !cursor.connection_reusable(),
            "a mid-stream cursor's connection is not reusable"
        );
        // Dropped here, mid-stream, with a second batch still en route.
    }

    let mut fresh = db
        .take_reader()
        .expect("take_reader after abandonment")
        .query("SELECT 1")
        .execute()
        .expect("execute on a fresh connection");
    while fresh.next_batch().expect("drain") {}
    assert!(fresh.terminal().is_some());
    assert_eq!(
        server.accepts(),
        2,
        "the abandoned connection must have been retired, forcing a redial"
    );
}

// ---------------------------------------------------------------------------
// Batch accessors on `OwnedCursor`
// ---------------------------------------------------------------------------

use questdb::egress::{ColumnView, Reader};

/// Hand-build a two-column, multi-row `RESULT_BATCH` frame.
///
/// `Action::SendBatch` / `BatchColumn` (in `qwp_mock.rs`, which this task
/// must not modify) only carries a single named column per frame — see its
/// own doc comment ("single-table, single-column RESULT_BATCH"). The parity
/// test below needs a batch with *more than one column* so that comparing
/// column 0 alone couldn't hide a bug in how the accessors index into
/// `DecodedBatch::columns`. This builds the frame by hand from the same
/// public wire helpers (`framed`, `encode_varint_u64`, `MSG_RESULT_BATCH`)
/// that `qwp_mock::result_batch_frame` itself uses, then delivers it with
/// `Action::SendRaw` — the escape hatch the mock already exposes for
/// scripts it can't otherwise express (see the malformed-frame tests in
/// `egress_failover.rs`).
///
/// `request_id` must match what the client allocates for its query. Every
/// test below opens exactly one fresh `Reader` and issues exactly one
/// query on it, so per `Reader::from_config` / `CursorState::alloc_request_id`
/// the id is deterministically `1`.
fn two_column_batch_frame(
    request_id: i64,
    batch_seq: u64,
    longs: &[i64],
    doubles: &[f64],
) -> Vec<u8> {
    const KIND_LONG: u8 = 0x05;
    const KIND_DOUBLE: u8 = 0x07;
    assert_eq!(
        longs.len(),
        doubles.len(),
        "test fixture: row counts must match"
    );
    let row_count = longs.len();

    let mut payload = Vec::new();
    payload.push(MSG_RESULT_BATCH);
    payload.extend_from_slice(&request_id.to_le_bytes());
    encode_varint_u64(batch_seq, &mut payload);
    encode_varint_u64(0, &mut payload); // empty table name
    encode_varint_u64(row_count as u64, &mut payload);
    if batch_seq == 0 {
        encode_varint_u64(2, &mut payload); // col_count
        encode_varint_u64(1, &mut payload);
        payload.push(b'v');
        payload.push(KIND_LONG);
        encode_varint_u64(1, &mut payload);
        payload.push(b'd');
        payload.push(KIND_DOUBLE);
    }
    // Column 0 (LONG "v"): null_flag=0x00 (no bitmap), then raw i64 LE values.
    payload.push(0x00);
    for v in longs {
        payload.extend_from_slice(&v.to_le_bytes());
    }
    // Column 1 (DOUBLE "d"): same shape.
    payload.push(0x00);
    for v in doubles {
        payload.extend_from_slice(&v.to_le_bytes());
    }
    framed(1, 0, 1, &payload)
}

/// One complete query round delivering the hand-built two-column batch,
/// then a clean `RESULT_END`.
fn two_column_script(role: ServerRole, node_id: &str, longs: &[i64], doubles: &[f64]) -> Script {
    vec![
        Action::SendServerInfo {
            role,
            node_id: node_id.into(),
        },
        Action::AwaitQueryRequest,
        Action::SendRaw(two_column_batch_frame(1, 0, longs, doubles)),
        Action::SendResultEnd,
    ]
}

/// Read column `v` (LONG, index 0) and column `d` (DOUBLE, index 1) out of
/// whichever `ColumnView`-yielding accessor the caller supplies, returning
/// every row so the parity test compares actual decoded values rather than
/// just counts.
fn read_long_column(view: &ColumnView<'_>) -> Vec<i64> {
    match view {
        ColumnView::Long(c) => (0..c.len()).map(|i| c.value(i)).collect(),
        other => panic!("expected a LONG column, got {:?}", other.kind()),
    }
}

fn read_double_column(view: &ColumnView<'_>) -> Vec<f64> {
    match view {
        ColumnView::Double(c) => (0..c.len()).map(|i| c.value(i)).collect(),
        other => panic!("expected a DOUBLE column, got {:?}", other.kind()),
    }
}

/// The accessors must return exactly what `BatchView` returns on the
/// borrowing path — same script, same assertions, two APIs. The script
/// carries two columns (LONG, DOUBLE) and three rows so that a bug which
/// swapped columns, dropped rows, or misindexed `DecodedBatch::columns`
/// would show up as a value mismatch, not just a count mismatch.
#[test]
fn owned_batch_accessors_match_the_borrowing_batchview() {
    let longs = vec![10_i64, 20, 30];
    let doubles = vec![1.5_f64, 2.5, 3.5];
    let script = two_column_script(ServerRole::Primary, "n1", &longs, &doubles);

    // Borrowing path: read the first batch through BatchView.
    let server_a = MockServer::start(vec![script.clone()]);
    let conf_a = format!("ws::addr={};", server_a.url());
    let mut reader = Reader::from_conf(&conf_a).expect("connect");
    let mut cursor = reader.execute("SELECT 1").expect("execute");
    let view = cursor.next_batch().expect("next_batch").expect("a batch");
    let expected_rows = view.row_count();
    let expected_cols = view.column_count();
    let expected_long = read_long_column(&view.column(0).expect("column 0"));
    let expected_double = read_double_column(&view.column(1).expect("column 1"));
    let expected_batch_seq = view.batch_seq();
    let expected_schema_len = view.schema().len();
    drop(cursor);

    // Owning path: the same, through the accessors.
    let server_b = MockServer::start(vec![script]);
    let conf_b = format!("ws::addr={};", server_b.url());
    let db = QuestDb::connect(&conf_b).expect("connect");
    let mut owned = db
        .take_reader()
        .expect("take_reader")
        .query("SELECT 1")
        .execute()
        .expect("execute");
    assert!(owned.next_batch().expect("next_batch"), "expected a batch");

    assert_eq!(owned.batch_row_count(), expected_rows, "row count differs");
    assert_eq!(
        owned.batch_column_count(),
        expected_cols,
        "column count differs"
    );
    let actual_long = read_long_column(&owned.batch_column(0).expect("column 0"));
    let actual_double = read_double_column(&owned.batch_column(1).expect("column 1"));
    assert_eq!(actual_long, expected_long, "column 0 (LONG) values differ");
    assert_eq!(
        actual_double, expected_double,
        "column 1 (DOUBLE) values differ"
    );
    assert_eq!(
        owned.batch_seq(),
        Some(expected_batch_seq),
        "batch_seq differs"
    );
    assert_eq!(
        owned.batch_schema().map(|s| s.len()),
        Some(expected_schema_len),
        "schema column count differs"
    );
}

/// Accessors before the first `next_batch` must not panic.
#[test]
fn owned_batch_accessors_are_safe_before_the_first_batch() {
    let server = MockServer::start(vec![happy_script(ServerRole::Primary, "n1")]);
    let conf = format!("ws::addr={};", server.url());
    let db = QuestDb::connect(&conf).expect("connect");
    let cursor = db
        .take_reader()
        .expect("take_reader")
        .query("SELECT 1")
        .execute()
        .expect("execute");

    assert_eq!(cursor.batch_row_count(), 0);
    assert_eq!(cursor.batch_column_count(), 0);
    assert!(cursor.batch_schema().is_none());
    assert!(
        cursor.batch_column(0).is_err(),
        "column access must error, not panic"
    );
}
