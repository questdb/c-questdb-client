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

#![cfg(feature = "sync-reader-qwp-ws")]

#[path = "common/qwp_mock.rs"]
mod qwp_mock;

use questdb::egress::{ColumnView, Reader, ServerRole};
use qwp_mock::*;

/// Proves the extracted harness is usable from a file other than
/// egress_failover.rs — the whole point of Task 1.
///
/// Two adjustments from the task-1 brief's example, per its own
/// fallback instruction ("adjust this test to the real one"):
/// - `MockServer`'s connect-string accessor is `url()`, not `addr()`
///   (no `addr()` method exists on this type).
/// - `happy_script` replies `SendServerInfo, AwaitQueryRequest,
///   SendResultEnd` — it never sends a `SendBatch` action, so a
///   successful query against it always yields zero batches (see
///   `happy_path_no_failover` in egress_failover.rs for the same
///   assertion). Asserting `batches > 0` here would never pass.
#[test]
fn mock_server_is_reusable_from_another_test_binary() {
    let server = MockServer::start(vec![happy_script(ServerRole::Primary, "n1")]);
    let conf = format!("ws::addr={};", server.url());
    let mut reader = Reader::from_conf(&conf).expect("connect");
    let mut cursor = reader.execute("SELECT 1").expect("execute");
    assert!(
        cursor.next_batch().expect("next_batch").is_none(),
        "happy_script sends no SendBatch action, so the query completes with zero batches"
    );
}

/// Companion to the no-batch test above: proves the harness can also
/// script a server that sends a real `RESULT_BATCH` before
/// `RESULT_END`, and that the client decodes its actual contents —
/// row count, column count, and values — when driven from a test
/// binary other than `egress_failover.rs`.
///
/// Script shape and decode style (`ColumnView::Long` + `FixedColumn::value`)
/// follow `stale_cached_plan_internal_error_is_transparently_retried` in
/// `egress_failover.rs`, which is the idiomatic non-polars way this repo
/// asserts on a scripted batch's payload.
#[test]
fn mock_server_streams_a_batch_with_decodable_rows() {
    let server = MockServer::start(vec![vec![
        Action::SendServerInfo {
            role: ServerRole::Primary,
            node_id: "n1".into(),
        },
        Action::AwaitQueryRequest,
        Action::SendBatch {
            batch_seq: 0,
            column: BatchColumn::Long(vec![10, 20, 30]),
        },
        Action::SendResultEnd,
    ]]);
    let conf = format!("ws::addr={};", server.url());
    let mut reader = Reader::from_conf(&conf).expect("connect");
    let mut cursor = reader.execute("SELECT 1").expect("execute");

    let view = cursor
        .next_batch()
        .expect("next_batch")
        .expect("scripted SendBatch must yield one batch before RESULT_END");
    assert_eq!(view.row_count(), 3, "batch carried 3 rows on the wire");
    assert_eq!(view.column_count(), 1, "batch carried a single LONG column");
    let ColumnView::Long(c) = view.column(0).expect("col 0") else {
        panic!("column 0 should decode as Long");
    };
    assert_eq!(
        (c.value(0), c.value(1), c.value(2)),
        (10, 20, 30),
        "decoded values must match what the mock server put on the wire"
    );

    assert!(
        cursor.next_batch().expect("terminal").is_none(),
        "RESULT_END must terminate the cursor cleanly after the one batch"
    );
}
