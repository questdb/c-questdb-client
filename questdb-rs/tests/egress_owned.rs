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

/// `into_owner` on a *still-active* cursor must run the same teardown as
/// `Drop`: the stream is abandoned mid-flight, so the connection handed back
/// has to be a retired one, not a live one carrying an unread remainder.
///
/// This is the sibling of `dropping_an_owned_cursor_mid_stream_retires_the_connection`
/// for the hand-back path, and it is deliberately distinct from
/// `into_owner_returns_a_reusable_reader`: that test drains first, which
/// clears `cursor_active` and makes `into_owner`'s cleanup call a no-op. Only
/// an undrained cursor exercises it. The C ABI reaches this path through
/// `qwp_reader_cursor_free`, but `questdb-rs` ships standalone on crates.io,
/// so the contract has to be pinned here too.
///
/// Observable proof, same as the drop sibling: the retired reader cannot be
/// recycled, so the next `take_reader` has to dial a second connection.
#[test]
fn into_owner_mid_stream_retires_the_connection() {
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

    // Handed back mid-stream, with a second batch still en route.
    let reader = cursor.into_owner();
    drop(reader);

    let mut fresh = db
        .take_reader()
        .expect("take_reader after hand-back")
        .query("SELECT 1")
        .execute()
        .expect("execute on a fresh connection");
    while fresh.next_batch().expect("drain") {}
    assert!(fresh.terminal().is_some());
    assert_eq!(
        server.accepts(),
        2,
        "into_owner on an undrained cursor must retire the connection, forcing a redial"
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

    // Anti-vacuity: every "expected" above is read off the *borrowing* path,
    // so a regression in the shared `DecodedBatch::column_view` would move
    // both arms together and the parity assertions below would still pass.
    // Pin the borrowing arm against the fixture's absolute values first, so a
    // shared-decoder regression fails here rather than sailing through.
    assert_eq!(
        expected_long, longs,
        "borrowing path must decode the fixture's LONG column, else the parity check below is vacuous"
    );
    assert_eq!(
        expected_double, doubles,
        "borrowing path must decode the fixture's DOUBLE column, else the parity check below is vacuous"
    );
    assert_eq!(
        (expected_rows, expected_cols, expected_schema_len),
        (3, 2, 2),
        "fixture shape must be 3 rows x 2 columns, else the parity check below is vacuous"
    );

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

// ---------------------------------------------------------------------------
// Batch metadata the FFI reads through the batch handle
// ---------------------------------------------------------------------------

/// `batch_request_id`, `batch_flags` and `symbol_dict` complete the set of
/// things `BatchView` exposes, and the C ABI's `qwp_reader_batch_*`
/// accessors need every one of them. Assert parity with the borrowing path
/// against a SYMBOL batch, which is the only shape that makes the
/// connection-scoped dictionary non-empty and sets a frame flag
/// (`FLAG_DELTA_SYMBOL_DICT`) — so a stubbed-out `batch_flags` returning
/// `0` would fail here rather than pass by coincidence.
#[test]
fn owned_batch_metadata_matches_the_borrowing_batchview() {
    let symbols = || BatchColumn::Symbol {
        dict: vec!["alpha".into(), "beta".into()],
        codes: vec![0, 1, 0],
    };
    let script = || {
        vec![
            server_info(),
            Action::AwaitQueryRequest,
            Action::SendBatch {
                batch_seq: 0,
                column: symbols(),
            },
            Action::SendResultEnd,
        ]
    };

    // Borrowing path.
    let server_a = MockServer::start(vec![script()]);
    let mut reader = Reader::from_conf(format!("ws::addr={};", server_a.url())).expect("connect");
    let mut cursor = reader.execute("SELECT s").expect("execute");
    let view = cursor.next_batch().expect("next_batch").expect("a batch");
    let expected_request_id = view.request_id();
    let expected_flags = view.flags();
    let expected_dict: Vec<String> = (0..view.dict().len())
        .map(|i| view.dict().get(i as u32).expect("dict entry").to_owned())
        .collect();
    drop(cursor);

    assert_ne!(
        expected_flags, 0,
        "fixture must set a frame flag, else the parity check below is vacuous"
    );
    assert_eq!(expected_dict, ["alpha", "beta"]);

    // Owning path.
    let server_b = MockServer::start(vec![script()]);
    let owner = Reader::from_conf(format!("ws::addr={};", server_b.url())).expect("connect");
    let mut owned = owner.into_query("SELECT s").execute().expect("execute");
    assert!(owned.next_batch().expect("next_batch"), "expected a batch");

    assert_eq!(owned.batch_request_id(), Some(expected_request_id));
    assert_eq!(owned.batch_flags(), Some(expected_flags));
    let actual_dict: Vec<String> = (0..owned.symbol_dict().len())
        .map(|i| {
            owned
                .symbol_dict()
                .get(i as u32)
                .expect("dict entry")
                .to_owned()
        })
        .collect();
    assert_eq!(actual_dict, expected_dict);
}

/// The per-batch metadata accessors must be `None` — not `0`, and not a
/// panic — before the first batch, so a caller cannot mistake "no batch
/// yet" for "batch 0 with no flags".
#[test]
fn owned_batch_metadata_is_none_before_the_first_batch() {
    let server = MockServer::start(vec![happy_script(ServerRole::Primary, "n1")]);
    let owner = Reader::from_conf(format!("ws::addr={};", server.url())).expect("connect");
    let cursor = owner.into_query("SELECT 1").execute().expect("execute");
    assert_eq!(cursor.batch_request_id(), None);
    assert_eq!(cursor.batch_flags(), None);
    assert_eq!(cursor.symbol_dict().len(), 0);
}

// ---------------------------------------------------------------------------
// Typed binds
// ---------------------------------------------------------------------------

/// The typed bind forwarders must produce a byte-identical
/// `QUERY_REQUEST` to the borrowing path's.
///
/// Byte-equality rather than "it didn't error" because several of these are
/// not plain `Bind` constructors: `bind_uuid` reverses the caller's
/// canonical RFC-4122 bytes into QWP wire order. A forwarder that reached
/// for `Bind::Uuid(v)` directly would compile, run, and silently transmit a
/// byte-swapped UUID — this assertion is what catches that.
///
/// `bind_binary` / `bind_null_binary` / `bind_ipv4` are absent because
/// `check_bindable` rejects BINARY and IPV4 as bind kinds on both paths;
/// their forwarders are covered by
/// `owned_binds_reject_the_same_kinds_as_the_borrowing_path` below.
#[test]
fn owned_typed_binds_encode_identically_to_the_borrowing_path() {
    const UUID: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF,
    ];
    const LONG256: [u8; 32] = [0xA5; 32];
    const DEC256: [u8; 32] = [0x5A; 32];

    let server_a = MockServer::start(vec![happy_script(ServerRole::Primary, "n1")]);
    let mut reader = Reader::from_conf(format!("ws::addr={};", server_a.url())).expect("connect");
    let mut borrowed = reader
        .prepare("SELECT $1")
        .initial_credit(4096)
        .bind_bool(true)
        .bind_i8(-1)
        .bind_i16(-2)
        .bind_i32(-3)
        .bind_i64(-4)
        .bind_f32(1.5)
        .bind_f64(2.5)
        .bind_varchar("hello")
        .bind_timestamp_micros(111)
        .bind_timestamp_nanos(222)
        .bind_date_millis(333)
        .bind_uuid(UUID)
        .bind_long256(LONG256)
        .bind_char(b'q' as u16)
        .bind_decimal64(1234, 2)
        .bind_decimal128(-5678, 3)
        .bind_decimal256(DEC256, 4)
        .bind_geohash(0xABCD, 20)
        .bind_null(questdb::egress::SimpleNullKind::Long)
        .bind_null_varchar()
        .bind_null_decimal64(2)
        .bind_null_decimal128(3)
        .bind_null_decimal256(4)
        .bind_null_geohash(20)
        .execute()
        .expect("borrowing execute");
    while borrowed.next_batch().expect("drain").is_some() {}
    drop(borrowed);

    let server_b = MockServer::start(vec![happy_script(ServerRole::Primary, "n1")]);
    let owner = Reader::from_conf(format!("ws::addr={};", server_b.url())).expect("connect");
    let mut owned = owner
        .into_query("SELECT $1")
        .initial_credit(4096)
        .bind_bool(true)
        .bind_i8(-1)
        .bind_i16(-2)
        .bind_i32(-3)
        .bind_i64(-4)
        .bind_f32(1.5)
        .bind_f64(2.5)
        .bind_varchar("hello")
        .bind_timestamp_micros(111)
        .bind_timestamp_nanos(222)
        .bind_date_millis(333)
        .bind_uuid(UUID)
        .bind_long256(LONG256)
        .bind_char(b'q' as u16)
        .bind_decimal64(1234, 2)
        .bind_decimal128(-5678, 3)
        .bind_decimal256(DEC256, 4)
        .bind_geohash(0xABCD, 20)
        .bind_null(questdb::egress::SimpleNullKind::Long)
        .bind_null_varchar()
        .bind_null_decimal64(2)
        .bind_null_decimal128(3)
        .bind_null_decimal256(4)
        .bind_null_geohash(20)
        .execute()
        .expect("owning execute");
    while owned.next_batch().expect("drain") {}

    let borrowed_bytes = server_a.captured_requests();
    let owned_bytes = server_b.captured_requests();
    assert_eq!(borrowed_bytes.len(), 1, "one QUERY_REQUEST per path");
    assert_eq!(owned_bytes.len(), 1, "one QUERY_REQUEST per path");
    // Both readers are fresh and issue exactly one query, so both requests
    // carry request_id 1 and the buffers are comparable byte for byte.
    assert_eq!(
        borrowed_bytes[0], owned_bytes[0],
        "the owning path must encode the same QUERY_REQUEST as the borrowing path"
    );
    // Guard against a vacuous pass: the UUID's wire bytes must be the
    // reversal of the caller's input, present somewhere in the request.
    let mut reversed = UUID;
    reversed.reverse();
    assert!(
        owned_bytes[0].windows(16).any(|w| w == reversed.as_slice()),
        "bind_uuid must emit the reversed byte order on the wire"
    );
}

// ---------------------------------------------------------------------------
// try_execute
// ---------------------------------------------------------------------------

/// A submit that fails before anything reaches the wire must hand the
/// connection back intact, not close it. The C ABI depends on this: its
/// `qwp_reader` handle is still held by the caller and is where the
/// connection lives between queries, so an `execute` that swallowed the
/// connection on failure would strand a pool slot and leave the handle's
/// `_close` with nothing to return.
#[test]
fn try_execute_hands_the_connection_back_on_a_pre_wire_failure() {
    let server = MockServer::start(vec![happy_script(ServerRole::Primary, "n1")]);
    let owner = Reader::from_conf(format!("ws::addr={};", server.url())).expect("connect");

    // Over `MAX_SQL_BYTES`, rejected by `QueryRequestBuilder::build` before
    // the encode, let alone the write.
    let too_long = "x".repeat(1024 * 1024 + 1);
    let (err, owner) = owner
        .into_query(too_long)
        .try_execute()
        .err()
        .expect("an over-long SQL must be rejected");
    assert_eq!(err.code(), questdb::ErrorCode::InvalidApiCall);
    assert!(
        !owner.transport_torn_down(),
        "a pre-wire rejection must leave the connection usable"
    );

    // The proof that it is usable: run a real query on the same connection.
    let mut cursor = owner.into_query("SELECT 1").execute().expect("execute");
    while cursor.next_batch().expect("drain") {}
    assert!(cursor.terminal().is_some());
    assert_eq!(
        server.accepts(),
        1,
        "the handed-back connection must be reused, not redialled"
    );
}

// ---------------------------------------------------------------------------
// Failover callbacks on the owning path
// ---------------------------------------------------------------------------

use std::sync::{Arc, Mutex};

use questdb::ErrorCode;
use questdb::egress::{FailoverPhase, FailoverResetEvent};

/// Server A serves one batch then dies; server B serves a different batch
/// and terminates. This is the post-delivery failover shape: rows have
/// already reached the caller when the connection drops, so replaying from
/// `batch_seq=0` would duplicate them.
fn post_delivery_failover_servers() -> (MockServer, MockServer) {
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
            column: BatchColumn::Long(vec![7, 8, 9]),
        },
        Action::SendResultEnd,
    ]]);
    (a, b)
}

fn failover_conf(a: &MockServer, b: &MockServer) -> String {
    format!(
        "ws::addr={};failover_backoff_initial_ms=1;failover_backoff_max_ms=10",
        build_addr_list(&[a, b])
    )
}

/// Installing `on_failover_reset` on an `OwnedQuery` must do what it does
/// on a `ReaderQuery`: fire with the new endpoint, and thereby authorise
/// the replay that would otherwise be refused.
#[test]
fn owned_failover_reset_callback_fires_and_authorises_replay() {
    let (srv_a, srv_b) = post_delivery_failover_servers();
    let owner = Reader::from_conf(failover_conf(&srv_a, &srv_b)).expect("connect to A");

    let observed: Arc<Mutex<Vec<FailoverResetEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&observed);
    let mut cursor = owner
        .into_query("select 1")
        .on_failover_reset(move |ev: &FailoverResetEvent| {
            sink.lock().unwrap().push(ev.clone());
        })
        .execute()
        .expect("execute");

    // A's batch, delivered before the drop.
    assert!(cursor.next_batch().expect("first batch"));
    assert_eq!(cursor.batch_row_count(), 2);
    // A is gone: this call observes the close, fails over, replays, and
    // yields B's batch — which only happens because the callback is
    // installed.
    assert!(cursor.next_batch().expect("post-failover batch"));
    assert_eq!(cursor.batch_row_count(), 3);
    assert_eq!(cursor.failover_resets(), 1);
    assert!(!cursor.next_batch().expect("terminal"));

    let events = observed.lock().unwrap();
    assert_eq!(events.len(), 1, "reset callback fired exactly once");
    assert_eq!(events[0].new_addr.port, srv_b.addr.port());
    assert_eq!(events[0].failed_addr.port, srv_a.addr.port());
}

/// The negative control for the test above: the identical script with no
/// callback installed must surface `FailoverWouldDuplicate` instead of
/// silently replaying. Without this, a callback field that was stored but
/// never threaded through to `CursorState` would still pass the positive
/// test if the guard happened to be off.
#[test]
fn owned_cursor_without_a_reset_callback_refuses_post_delivery_replay() {
    let (srv_a, srv_b) = post_delivery_failover_servers();
    let owner = Reader::from_conf(failover_conf(&srv_a, &srv_b)).expect("connect to A");
    let mut cursor = owner.into_query("select 1").execute().expect("execute");

    assert!(cursor.next_batch().expect("first batch"));
    let err = cursor
        .next_batch()
        .expect_err("post-delivery failover must be refused without a reset callback");
    assert_eq!(err.code(), ErrorCode::FailoverWouldDuplicate);
}

/// `on_failover_progress` is telemetry-only, so it must fire through every
/// phase of the same failover — including on a cursor that also has a reset
/// callback, which is how the C ABI installs them.
#[test]
fn owned_failover_progress_callback_observes_every_phase() {
    let (srv_a, srv_b) = post_delivery_failover_servers();
    let owner = Reader::from_conf(failover_conf(&srv_a, &srv_b)).expect("connect to A");

    let phases: Arc<Mutex<Vec<FailoverPhase>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&phases);
    let mut cursor = owner
        .into_query("select 1")
        .on_failover_reset(|_: &FailoverResetEvent| {})
        .on_failover_progress(move |ev: &questdb::egress::FailoverProgressEvent| {
            sink.lock().unwrap().push(ev.phase);
        })
        .execute()
        .expect("execute");

    assert!(cursor.next_batch().expect("first batch"));
    assert!(cursor.next_batch().expect("post-failover batch"));

    let seen = phases.lock().unwrap();
    assert!(
        seen.contains(&FailoverPhase::Disconnected),
        "expected a Disconnected phase, saw {seen:?}"
    );
    assert!(
        seen.contains(&FailoverPhase::Reset),
        "expected a Reset phase, saw {seen:?}"
    );
}

/// BINARY and IPV4 are not bindable (`check_bindable`), so their
/// forwarders must fail on the owning path exactly as they do on the
/// borrowing one — same code, same message. Without this the three
/// forwarders the byte-parity test above has to skip would be untested.
#[test]
fn owned_binds_reject_the_same_kinds_as_the_borrowing_path() {
    fn borrowed_err(
        f: impl FnOnce(questdb::egress::ReaderQuery<'_>) -> questdb::egress::ReaderQuery<'_>,
    ) -> questdb::Error {
        let server = MockServer::start(vec![happy_script(ServerRole::Primary, "n1")]);
        let mut reader = Reader::from_conf(format!("ws::addr={};", server.url())).expect("connect");
        f(reader.prepare("SELECT $1"))
            .execute()
            .err()
            .expect("must be rejected")
    }
    fn owned_err(
        f: impl FnOnce(questdb::egress::OwnedQuery<Reader>) -> questdb::egress::OwnedQuery<Reader>,
    ) -> questdb::Error {
        let server = MockServer::start(vec![happy_script(ServerRole::Primary, "n1")]);
        let owner = Reader::from_conf(format!("ws::addr={};", server.url())).expect("connect");
        f(owner.into_query("SELECT $1"))
            .execute()
            .err()
            .expect("must be rejected")
    }

    let cases: Vec<(&str, questdb::Error, questdb::Error)> = vec![
        (
            "binary",
            borrowed_err(|q| q.bind_binary(vec![1u8, 2, 3])),
            owned_err(|q| q.bind_binary(vec![1u8, 2, 3])),
        ),
        (
            "null_binary",
            borrowed_err(|q| q.bind_null_binary()),
            owned_err(|q| q.bind_null_binary()),
        ),
        (
            "ipv4",
            borrowed_err(|q| q.bind_ipv4(std::net::Ipv4Addr::new(10, 0, 0, 1))),
            owned_err(|q| q.bind_ipv4(std::net::Ipv4Addr::new(10, 0, 0, 1))),
        ),
    ];
    for (name, borrowed, owned) in cases {
        assert_eq!(
            borrowed.code(),
            ErrorCode::InvalidBind,
            "{name}: borrowing code"
        );
        assert_eq!(owned.code(), borrowed.code(), "{name}: code differs");
        assert_eq!(owned.msg(), borrowed.msg(), "{name}: message differs");
    }
}
