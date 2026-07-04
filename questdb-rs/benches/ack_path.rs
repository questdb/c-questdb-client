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

//! Ack-path overhead microbenchmark for the `received_fsn` watermark.
//!
//! # What this proves
//!
//! Tasks 1–6 of the `received-fsn-watermark` branch added `received_fsn`
//! tracking to the driver's ack-processing hot path. Per applied response the
//! added work is:
//!
//!   1. One monotonic `Option<u64>` compare-store (`persist_received_fsn`).
//!   2. One advance-gated `ReceivedThrough` event push into a pre-sized ring
//!      (a `VecDeque::push_back` that never allocates once the ring is at
//!      capacity; older events are dropped instead).
//!   3. Two `debug_assert!` watermark-ordering checks — compiled out in
//!      release builds.
//!
//! This benchmark drives both the full ack-application path and the
//! `record_received_through_event` function in isolation to confirm the cost
//! is negligible.
//!
//! # Two benchmark groups
//!
//! ## `ack_path/full_N_responses`
//!
//! Submits N frames into an in-memory `SfaFrameQueue`, then drives
//! `QwpWsSendCore::drive_once` for each frame against an inline transport
//! that immediately returns an `Ack` response. This exercises the complete
//! hot path:
//!
//!   ```text
//!   drive_once → send_frame (AckOnSend) → apply_response (Ack)
//!             → complete_ack_through → record_received_through_event
//!             → persist_received_fsn + ReceivedThrough push
//!             → record_completed_through_event
//!   ```
//!
//! No sockets, no threads, no allocations inside the measured loop
//! (the event ring is pre-sized).
//!
//! ## `ack_path/received_tracking_isolated_N`
//!
//! Calls `record_received_through_event` N times in a tight loop, isolating
//! exactly the two operations added by `received_fsn` tracking:
//!   - `persist_received_fsn` (one `Option<u64>` compare-store)
//!   - one `ReceivedThrough` event push into the pre-sized ring
//!
//! The delta between the two groups gives an upper bound on the per-response
//! overhead attributable to `received_fsn` tracking.
//!
//! # Baseline (recorded on 2026-07-04, Intel i7-1360P, `--release`)
//!
//! ```text
//! ack_path/full_10000_responses             thrpt: 11.403 Melem/s  (≈ 11.4 M responses/sec)
//! ack_path/received_tracking_isolated_10000 thrpt: 507.73 Melem/s  (≈ 508 M calls/sec)
//! ```
//!
//! The isolated `record_received_through_event` cost is ~44× cheaper than the
//! full round-trip, confirming that `received_fsn` tracking contributes < 2.3%
//! of the total per-response cycle time. The full path cost is dominated by
//! SFA queue bookkeeping (segment cursor advance, completed-watermark CAS,
//! receipt-state update), not by the two operations added for received_fsn
//! (one `Option<u64>` compare-store + one pre-sized ring push).
//!
//! # How to run
//!
//! ```text
//! cargo bench --features sync-sender-qwp-ws --bench ack_path
//! ```

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};

use questdb::ingress::_bench_internals_sender::{bench_ack_path, bench_received_tracking_isolated};

// Default response count.  Large enough that criterion's sampling converges
// quickly; small enough that one iteration completes in single-digit ms.
const N: usize = 10_000;

// ---------------------------------------------------------------------------
// Criterion harness
// ---------------------------------------------------------------------------

fn bench_ack_path_full(c: &mut Criterion) {
    let n: usize = std::env::var("QWP_WS_ACK_BENCH_N")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(N);

    // Sanity-check once before criterion starts iterating so a logic bug
    // surfaces as a clear panic rather than a silent wrong measurement.
    let (processed, _) = bench_ack_path(n);
    assert_eq!(processed as usize, n, "all submitted frames must be acked");

    let mut group = c.benchmark_group("ack_path");
    group.throughput(Throughput::Elements(n as u64));
    group.bench_function(format!("full_{n}_responses"), |b| {
        b.iter(|| {
            let (processed, elapsed) = bench_ack_path(black_box(n));
            black_box((processed, elapsed))
        });
    });
    group.finish();
}

fn bench_received_tracking(c: &mut Criterion) {
    let n: u64 = std::env::var("QWP_WS_ACK_BENCH_N")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(N as u64);

    let mut group = c.benchmark_group("ack_path");
    group.throughput(Throughput::Elements(n));
    group.bench_function(format!("received_tracking_isolated_{n}"), |b| {
        b.iter(|| {
            let (calls, elapsed) = bench_received_tracking_isolated(black_box(n));
            black_box((calls, elapsed))
        });
    });
    group.finish();
}

criterion_group!(benches, bench_ack_path_full, bench_received_tracking);
criterion_main!(benches);
