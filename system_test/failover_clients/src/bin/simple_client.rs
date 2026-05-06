//! Minimal QWP egress client for `system_test/test_egress_failover.py`'s
//! connect-time endpoint-walk test.
//!
//! Unlike its sibling `failover_client`, this binary does NOT pause
//! after the first batch and does NOT synchronize with the test
//! harness over stdin/stdout. It just connects, runs the query,
//! drains, and prints stats — useful for tests that exercise
//! `Reader::from_conf` or end-to-end query execution against a healthy
//! endpoint without interleaving a kill.
//!
//! Build (alongside `failover_client`, in the same Cargo project):
//!     cd system_test/failover_clients
//!     cargo build --release
//!     ./target/release/simple_client \
//!         "qwp::addr=h:p" "select 1"
//!
//! Output format intentionally matches `failover_client`'s `connected
//! to ...` and `completed: batches=N rows=M failover_resets=K
//! final_endpoint=...` lines, so the Python test's parsing code is
//! shared between both binaries.

use questdb::egress::Reader;

fn main() {
    let conf = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "qwp::addr=localhost:9000".into());
    let sql: String = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "SELECT 1".into());

    let mut reader = Reader::from_conf(&conf).expect("connect");
    eprintln!(
        "connected to {} (cluster role: {:?})",
        reader.current_addr(),
        reader.server_info().map(|i| i.role)
    );

    let mut cursor = reader.query(&sql).execute().expect("execute");
    let mut total_batches = 0u64;
    let mut total_rows = 0u64;
    while let Some(batch) = cursor.next_batch().expect("next") {
        total_batches += 1;
        total_rows += batch.row_count() as u64;
    }
    let resets = cursor.failover_resets();
    drop(cursor);

    eprintln!(
        "completed: batches={} rows={} failover_resets={} final_endpoint={}",
        total_batches,
        total_rows,
        resets,
        reader.current_addr(),
    );
}
