//! Helper for `system_test/test_egress_failover.py`'s
//! `test_reader_poisoned_after_failover_exhaustion` test.
//!
//! Drives the same scenario as
//! `reader_poisoned_after_failover_exhaustion_returns_err_not_panic`
//! in `questdb-rs/tests/egress_failover.rs`:
//!
//!   1. Connect with multi-addr + `failover_max_attempts=1`.
//!   2. Read first batch from server #1.
//!   3. Synchronise with the test harness via stdout/stdin (so Python
//!      kills BOTH servers before we attempt the next batch).
//!   4. Call `next_batch()` again — expect Err (the failover budget
//!      exhausts because every reachable endpoint is now dead).
//!   5. Drop the cursor; the Reader is now "poisoned" (transport=None).
//!   6. Call `reader.server_version()` — must return SocketError, not
//!      panic.
//!   7. Call `reader.prepare("select 2").execute()` — must return
//!      SocketError, not panic.
//!
//! Each phase prints its observed `ErrorCode` to stderr on its own
//! line so the Python harness can parse the result. Wrong codes /
//! panics surface as a non-zero exit status.
//!
//! Build (alongside `failover_client` and `simple_client`):
//!     cd system_test/failover_clients
//!     cargo build --release
//!     ./target/release/exhaustion_client \
//!         "qwp::addr=h1:p1,h2:p2;failover_max_attempts=1;\
//!          failover_backoff_initial_ms=1;failover_backoff_max_ms=2" \
//!         "select 1"

use std::io::{BufRead, Write};

use questdb::egress::Reader;

const INITIAL_CREDIT_BYTES: u64 = 4 * 1024;

/// Emit an error code line and abort with a descriptive non-zero
/// status. Doubles as documentation: the helper exit codes map 1:1 to
/// the test phase that broke.
fn die(phase: &str, code: i32, msg: String) -> ! {
    eprintln!("FAIL [{}]: {}", phase, msg);
    std::process::exit(code);
}

fn main() {
    let conf = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "qwp::addr=localhost:9000".into());
    let sql: String = std::env::args().nth(2).unwrap_or_else(|| "select 1".into());

    let mut reader = Reader::from_conf(&conf).expect("connect");
    eprintln!(
        "connected to {} (cluster role: {:?})",
        reader.current_addr(),
        reader.server_info().map(|i| i.role)
    );

    // Scope the cursor so it's dropped before we probe the poisoned
    // reader — same shape as the Rust test.
    let exhausted_code = {
        let mut cursor = reader
            .prepare(&sql)
            .initial_credit(INITIAL_CREDIT_BYTES)
            .execute()
            .expect("execute");

        // Phase 1: drain exactly one batch so the harness has a clean
        // anchor for killing all endpoints.
        match cursor.next_batch() {
            Ok(Some(_)) => {}
            Ok(None) => die(
                "first-batch",
                10,
                "cursor terminated before first batch arrived".into(),
            ),
            Err(e) => die(
                "first-batch",
                11,
                format!("first next_batch errored: {:?}: {}", e.code(), e.msg()),
            ),
        }

        // Phase 2: signal the harness, then block waiting for the kill
        // of every endpoint + green light. STDOUT is reserved for this
        // signal; everything else goes to STDERR.
        println!("BATCH_RECEIVED");
        std::io::stdout().flush().expect("flush stdout");

        let mut line = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .expect("read stdin signal");

        // Phase 3: next_batch must surface the exhaustion error. Any
        // Ok variant means the failover machinery either silently
        // succeeded (which it can't — every endpoint is dead) or
        // returned a clean terminal (impossible without a healthy
        // server delivering RESULT_END).
        match cursor.next_batch() {
            Ok(_) => die(
                "exhaustion",
                12,
                "next_batch returned Ok after every endpoint was killed".into(),
            ),
            Err(e) => {
                eprintln!("exhausted_code={:?} exhausted_msg={}", e.code(), e.msg());
                e.code()
            }
        }
    };
    // Cursor dropped here. cursor_active=false so Drop skips its
    // close path; Reader.transport stays None — i.e. "poisoned".

    // Phase 4: server_version() on a poisoned Reader must surface a
    // transport-layer error, not panic.
    match reader.server_version() {
        Ok(v) => die(
            "server-version",
            13,
            format!("server_version returned Ok({}) on poisoned reader", v),
        ),
        Err(e) => {
            eprintln!(
                "poisoned_server_version_code={:?} poisoned_server_version_msg={}",
                e.code(),
                e.msg()
            );
        }
    }

    // Phase 5: a fresh query.execute() on a poisoned Reader must also
    // surface a transport-layer error, not panic.
    match reader.prepare("select 2").execute() {
        Ok(_) => die(
            "execute",
            14,
            "query.execute returned Ok on poisoned reader".into(),
        ),
        Err(e) => {
            eprintln!(
                "poisoned_execute_code={:?} poisoned_execute_msg={}",
                e.code(),
                e.msg()
            );
        }
    }

    eprintln!("completed: exhausted_code={:?}", exhausted_code);
}
