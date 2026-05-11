# QWP/WebSocket Vlad review tracker

Collected: 2026-05-11 from PR #141.

Source: Vlad's top-level PR review comment as GitHub user `bluestreak01`.

Status legend:

- `[ ]` open
- `[x]` resolved in code/docs and verified
- `[-]` skipped, stale, or intentionally not applicable

This tracker is intentionally split by Vlad's severity groups. Keep items open
until the finding has been re-checked against the current tree; a few items may
turn into documentation decisions rather than code changes.

## Critical, Blocks Merge

### VL-C1 - Add real-server `system_test/` coverage for QWP/WebSocket

- Status: [ ]
- Validation, 2026-05-11: still partially valid, but not valid as originally
  stated. The current tree has real-server QWP/WebSocket system-test classes:
  `TestQwpWsSender` and `TestQwpWsRestart`. The shim exposes `QWPWS` and
  `QWPWSS`, and `run_with_fixtures()` selects `qwp_ws_smoke` and
  `qwp_ws_restart` suites. Covered now: round-trip smoke, `close_drain`,
  HTTP-auth rejection in the smoke matrix, TLS smoke through the TLS proxy,
  same-sender restart, new-sender SFA recovery, reconnect-cap failure,
  continuous server bounces, and multi-epoch restart recovery. Still missing
  from this item's requested breadth: QWP/WebSocket schema-evolution system
  tests, explicit durable-ACK-ordering system tests, and server-side reject
  drop-and-continue / halt system tests.
- Implementation note, 2026-05-11: added behavior-level `system_test/` coverage
  through the public sender API for schema evolution across batches and
  schema-mismatch drop-and-continue diagnostics. Durable ACK ordering remains
  open because the current OSS QuestDB fixture does not enable durable ACK; a
  permanently skipped system test would not prove the behavior. Deliberately
  did not add raw WebSocket frame corruption for halt behavior under this item;
  that belongs in lower-level protocol/probe coverage unless a natural public
  API behavior exposes it.
- Verification, 2026-05-11: `TestQwpWsProtocol` passes against the local
  QWP-capable QuestDB checkout at `/home/jara/devel/oss/questdb-arrays` with
  JDK 25; 2 tests run, 0 skipped. The same suite against released QuestDB 9.2.0
  skips because that fixture returns HTTP 404 for the QWP/WebSocket upgrade.
- Source area: `system_test/test.py`, `system_test/fixture.py`,
  `system_test/questdb_line_sender.py`
- Action: Keep the existing real-server QWP/WebSocket smoke/restart coverage and
  run the new real-server protocol scenarios. Decide separately whether a
  behavior-level terminal halt path exists for `system_test/`, or leave halt
  coverage to lower-level protocol/probe tests.
- Acceptance: `system_test/` keeps enabled `qwpws` / `qwpwss` coverage and the
  remaining protocol-correctness scenarios are represented in real-server tests,
  not only mock-driver or ignored probes.

### VL-C2 - Add `qwpwss` TLS coverage

- Status: [ ]
- Source area: Rust tests, C++ tests, and `system_test/`
- Action: Add TLS coverage for `qwpwss`, including connection, handshake,
  certificate handling, and proxy or fixture wiring.
- Acceptance: `qwpwss` is tested beyond config-string acceptance.

### VL-C3 - Add QWP/WebSocket authentication coverage

- Status: [ ]
- Source area: WebSocket upgrade path and mock or system tests
- Action: Test that the `Authorization` header is sent and validated for
  QWP/WebSocket.
- Acceptance: A test fails if auth is missing or malformed on upgrade.

### VL-C4 - Add QWP/WebSocket example programs

- Status: [ ]
- Source area: `examples/`
- Action: Add customer-facing examples for QWP/WebSocket, covering the public
  APIs that differ from UDP: `flush_and_get_fsn`, `await_acked_fsn`,
  `poll_qwp_ws_error`, `close_drain`, and manual `drive_once` where applicable.
- Acceptance: Example manifest and build cover `qwpws` and, if supported,
  `qwpwss`.

### VL-C5 - Make orphan-drainer shutdown joinable and bounded

- Status: [ ]
- Source area: `questdb-rs/src/ingress/sender/qwp_ws_orphan.rs:187-200`
- Action: Prevent detached orphan-drainer workers from outliving sender Drop
  while still holding TCP/TLS handles, SFA locks, FDs, or mmap state. Store a
  shutdown handle such as a cloned stream, unblock syscalls, then join workers.
- Acceptance: A slow or hostile network cannot leave an orphan slot
  permanently locked after sender shutdown.

## Moderate, P1

### VL-M1 - Wrap bare flush family in panic guards

- Status: [ ]
- Source area: `questdb-rs-ffi/src/lib.rs:2819`, `2847`, `2883`
- Action: Wrap `line_sender_flush`, `line_sender_flush_and_keep`, and
  `line_sender_flush_and_keep_with_flags` in `catch_unwind` now that QWP/WS can
  flow through them.
- Acceptance: Panics cannot cross these C ABI boundaries.

### VL-M2 - Make `await_acked_fsn` wait on notifier instead of busy polling

- Status: [ ]
- Source area: `questdb-rs/src/ingress/sender.rs:561-591`,
  `questdb-rs/src/ingress/sender/qwp_ws.rs:425-451`
- Action: Reuse `BackpressureNotifier::wait_for_change` or equivalent ACK
  notification instead of sleeping and polling every 50 microseconds.
- Acceptance: Waiting for ACKs does not repeatedly take the publication lock in
  a tight sleep loop.

### VL-M3 - Bound impossible `await_acked_fsn` requests

- Status: [ ]
- Source area: `questdb-rs/src/ingress/sender.rs:572-590`
- Action: Reject or immediately error when the requested FSN is greater than
  the sender's published FSN. Also define or reject `Duration::MAX` semantics so
  the wait cannot accidentally become infinite.
- Acceptance: Cross-sender FSN mistakes fail fast or have explicitly documented
  infinite-wait behavior.

### VL-M4 - Treat too-large server ACK or reject sequence as protocol violation

- Status: [ ]
- Source area: `questdb-rs/src/ingress/sender/qwp_ws_driver.rs:1785-1797`
- Action: Stop silently capping server `wire_seq` values above the highest sent
  sequence. Return a protocol error instead.
- Acceptance: A server cannot advance completion or durable ACK state for data
  the client never sent.

### VL-M5 - Avoid locking publication state just to read completed FSN

- Status: [ ]
- Source area: `questdb-rs/src/ingress/sender/qwp_ws.rs:337-341`,
  `questdb-rs/src/ingress/sender/qwp_ws_sfa_queue.rs:1014-1019`
- Action: Read `completed_upper` through the existing atomic path without
  taking the publication mutex.
- Acceptance: `acked_fsn` remains correct and avoids needless hot-path
  contention.

### VL-M6 - Decide cleanup policy for non-drained SFA files

- Status: [ ]
- Source area: `questdb-rs/src/ingress/sender/qwp_ws_sfa_queue.rs:805-820`
- Action: Document and/or implement operator cleanup for `.sfa` segment and
  hot-spare files left by non-drained Drop, terminal error, or abandoned sender.
- Acceptance: Operators have a clear purge story and disk usage cannot grow
  forever without visibility.

### VL-M7 - Make `close_drain` timeout terminalize the runner

- Status: [ ]
- Source area: `questdb-rs/src/ingress/sender/qwp_ws.rs:901-908`,
  `2028-2036`
- Action: On close-drain timeout, terminalize lifecycle state, shut down the
  underlying stream to unblock I/O, and join the runner.
- Acceptance: The close-drain timeout bounds the actual close cost rather than
  deferring the stall to Drop.

### VL-M8 - Gate `crc32c` and `memmap2` behind QWP/WebSocket

- Status: [ ]
- Source area: `questdb-rs/Cargo.toml:44-45`
- Action: Make these dependencies optional and enable them only for the
  QWP/WebSocket feature set.
- Acceptance: ILP-only consumers do not compile QWP/WebSocket-only
  dependencies.

### VL-M9 - Remove file-scope `allow(dead_code)` from QWP/WS modules

- Status: [ ]
- Source area: `qwp_ws_driver.rs`, `qwp_ws_queue.rs`, `qwp_ws_sfa_queue.rs`,
  `qwp_ws_sfa_segment.rs`, `qwp_ws_sfa_slot.rs`
- Action: Delete broad file-level dead-code allowances or replace them with
  targeted allowances on intentionally retained items.
- Acceptance: Unused code in these modules is visible to normal compiler
  warnings again.

### VL-M10 - Document new C QWP/WebSocket types and view ownership

- Status: [ ]
- Source area: `include/questdb/ingress/line_sender.h:881-924`
- Action: Add docblocks for new QWP/WebSocket enums and structs, including
  whether `line_sender_qwpws_error_view.message` is null-terminated.
- Acceptance: C and Cython callers can safely consume all new public types.

### VL-M11 - Align C enum naming and avoid prefix collisions

- Status: [ ]
- Source area: `include/questdb/ingress/line_sender.h`
- Action: Revisit new QWP/WebSocket enum variant naming. Either align with the
  existing lowercase C style or split category and policy prefixes so `HALT`
  cannot read as an error category.
- Acceptance: Public C names are internally consistent and unambiguous.

### VL-M12 - Add changelog entry and version bump

- Status: [ ]
- Source area: `questdb-rs/Cargo.toml`, `questdb-rs-ffi/Cargo.toml`, release
  notes
- Action: Decide release version for new transports and public APIs, then add
  changelog or release-note coverage.
- Acceptance: Public API additions are reflected in package metadata and
  release documentation.

### VL-M13 - Add QWP/WebSocket docs to public README surfaces

- Status: [ ]
- Source area: `README.md`, `questdb-rs/README.md`, `doc/C.md`, `doc/CPP.md`
- Action: Document QWP/WebSocket alongside existing ILP and QWP/UDP transports.
- Acceptance: First-time readers can discover the new transport and its basic
  usage path.

### VL-M14 - Resolve high-priority open self-review TODOs before shipping

- Status: [ ]
- Source area: `doc/QWP_WEBSOCKET_SELF_REVIEW_TODOS.md`
- Action: Address or explicitly defer protocol parser parity, too-large ACK/NACK
  behavior, and shutdown/close-drain TODOs.
- Acceptance: The PR no longer ships a self-review ledger with unresolved
  high-priority protocol-correctness gaps.

### VL-M15 - Revisit C++ `flush_and_keep` null-buffer fallback

- Status: [ ]
- Source area: `include/questdb/ingress/line_sender.hpp:1422-1436`,
  `1461-1482`, `1519`
- Action: Decide whether C++ should silently allocate an empty buffer when
  `buffer._impl == nullptr`, or instead align with the C API's null-buffer
  contract.
- Acceptance: C++ behavior is intentional, documented, and compatible with the
  C surface.

### VL-M16 - Check null from C++ `new_buffer`

- Status: [ ]
- Source area: `include/questdb/ingress/line_sender.hpp:1351-1368`
- Action: Handle a null return from `line_sender_buffer_new_for_sender` before
  calling `line_sender_buffer_reserve`.
- Acceptance: Allocation failure or future null-producing paths cannot
  immediately dereference null in C++.

### VL-M17 - Reduce per-row allocation for reordered QWP columns

- Status: [ ]
- Source area: `questdb-rs/src/ingress/buffer/qwp.rs:3050-3062`,
  `3730-3739`
- Action: Avoid heap-allocating a lowercase `String` for each out-of-order
  column lookup. Consider byte-keyed lookup, a faster hasher, stack scratch for
  short names, or reuse of cached lowercase names.
- Acceptance: Reordered or optional-column workloads avoid per-row heap
  allocation on lookup.

### VL-M18 - Avoid per-row `Vec<u8>` allocation for QWP/WS arrays

- Status: [ ]
- Source area: `questdb-rs/src/ingress/buffer/qwp.rs:2543-2563`,
  `2824-2856`
- Action: Encode QWP/WebSocket array values directly into the destination column
  data buffer, mirroring the QWP/UDP direct-append path.
- Acceptance: Array column writes avoid an owned temporary vector and extra copy
  per row.

### VL-M19 - Pad cross-thread hot atomics

- Status: [ ]
- Source area: `questdb-rs/src/ingress/sender/qwp_ws_sfa_queue.rs:247-256`,
  `1111-1112`
- Action: Separate producer- and consumer-written atomics such as
  `published_upper` and `completed_upper` onto separate cache lines.
- Acceptance: Cross-thread queue progress avoids avoidable false sharing.

### VL-M20 - Improve WebSocket masking allocation and XOR path

- Status: [ ]
- Source area: `questdb-rs/src/ingress/sender/qwp_ws_codec.rs:154-159`,
  `questdb-rs/src/ingress/sender/qwp_ws.rs:1899`
- Action: Increase send buffer capacity for realistic batch frames and mask
  payloads in wider chunks instead of scalar byte-by-byte XOR.
- Acceptance: Large frames avoid avoidable reallocations and masking overhead.

### VL-M21 - Add Criterion benches for QWP hot paths

- Status: [ ]
- Source area: `questdb-rs/benches/`
- Action: Add microbenchmarks for QWP/UDP encoding, QWP/WebSocket columnar
  encoding and row build, replay encoding, SFA submit, and driver send-loop
  hot paths.
- Acceptance: QWP hot paths have repeatable benchmark coverage beyond a
  live-server example.

### VL-M22 - Add missing `SAFETY` comments

- Status: [ ]
- Source area: `questdb-rs/src/ingress/buffer/ilp.rs:60-73`,
  `questdb-rs/src/ingress/sender/qwp_ws_sfa_slot.rs:244`
- Action: Document the safety preconditions for unchecked ILP buffer writes and
  the `libc::flock` call.
- Acceptance: Unsafe blocks describe the invariants they rely on.

### VL-M23 - Restore disjoint-payload aliasing regression test

- Status: [ ]
- Source area: `questdb-rs/src/ingress/sender/qwp_ws_queue.rs`
- Action: Reintroduce the Miri-oriented regression test for publishing a
  disjoint payload while a previous payload view is still live.
- Acceptance: The aliasing regression has an explicit test again.

### VL-M24 - Document or fix QWP/UDP partial flush retry semantics

- Status: [ ]
- Source area: `questdb-rs/src/ingress/sender.rs:494-498`,
  `questdb-rs/src/ingress/buffer/qwp.rs:1738-1824`
- Action: Either document at-least-once retry behavior after a partial
  multi-datagram send failure, or track a send cursor to avoid resending
  already-sent datagrams.
- Acceptance: Retry semantics are intentional and visible to users.

## Minor, P2

### VL-P2-01 - Bound or reset `SymbolGlobalDict`

- Status: [ ]
- Source area: `questdb-rs/src/ingress/buffer/qwp.rs:3776-3845`
- Action: Expose or use a reset path so high-cardinality symbol values cannot
  grow the dictionary without bound indefinitely.

### VL-P2-02 - Wrap QWP/WS error-view getters for consistency

- Status: [ ]
- Source area: `questdb-rs-ffi/src/lib.rs:2687-2723`
- Action: Consider wrapping the panic-free field-copy getters in the same
  panic-catching pattern as the rest of the QWP/WebSocket FFI surface.

### VL-P2-03 - Align null `opts` handling conventions

- Status: [ ]
- Source area: `questdb-rs-ffi/src/lib.rs:1705-1729`
- Action: Decide whether `line_sender_opts_max_datagram_size`,
  `line_sender_opts_multicast_ttl`, and `line_sender_opts_qwpws_progress` should
  all null-check or all follow the documented null-UB convention.

### VL-P2-04 - Validate non-negative server `seq_txn`

- Status: [ ]
- Source area: `questdb-rs/src/ingress/sender/qwp_ws_driver.rs:2441-2453`,
  `questdb-rs/src/ingress/sender/qwp_ws_codec.rs:471`
- Action: Reject negative sequence transaction values from the server.

### VL-P2-05 - Check `entry.offset + entry.len`

- Status: [ ]
- Source area: `questdb-rs/src/ingress/buffer/qwp.rs:2250`
- Action: Replace unchecked addition with checked arithmetic like the sister
  function.

### VL-P2-06 - Avoid `usize` truncation in SFA segment size path

- Status: [ ]
- Source area: `questdb-rs/src/ingress/sender/qwp_ws_sfa_segment.rs:249`
- Action: Handle `size_bytes as usize` safely on 32-bit targets or document the
  target assumption.

### VL-P2-07 - Strengthen Java reconnect key parse test

- Status: [ ]
- Source area: `questdb-rs/src/tests/qwp_ws.rs:2507-2527`
- Action: Assert the parsed fields in `qwp_ws_from_conf_parses_java_reconnect_keys`.

### VL-P2-08 - Replace sleeps in QWP/WS tests with explicit synchronization

- Status: [ ]
- Source area: `questdb-rs/src/tests/qwp_ws.rs`
- Action: Replace post-write `thread::sleep` waits with explicit ACK/progress
  synchronization.

### VL-P2-09 - Consider inlining QWP/WS column appenders

- Status: [ ]
- Source area: `questdb-rs/src/ingress/buffer/qwp.rs:3168-3289`
- Action: Add `#[inline]` where it helps per-row append hot paths.

### VL-P2-10 - Remove committed `.codex` artifact

- Status: [ ]
- Source area: `.codex`
- Action: Remove the zero-byte repo-root artifact if it is not intentionally
  part of the project.

### VL-P2-11 - Fix rustdoc typo

- Status: [ ]
- Source area: `questdb-rs/src/ingress/sender.rs:728`
- Action: Replace "maxinum" with "maximum".

### VL-P2-12 - Move design-journal docs out of public doc root

- Status: [ ]
- Source area: `doc/QWP_WEBSOCKET_*.md`
- Action: Decide whether design journals belong in `doc/internal/`, a wiki, or
  another non-user-facing location.

### VL-P2-13 - Document or remove `ws` and `wss` config aliases

- Status: [ ]
- Source area: `questdb-rs/src/ingress.rs:363`, `365`
- Action: Expose the aliases in public docs and headers or remove them.

### VL-P2-14 - Ensure Drop can unblock in-flight `write_frame`

- Status: [ ]
- Source area: `questdb-rs/src/ingress/sender/qwp_ws.rs:901-908`
- Action: Shut down the stream or otherwise unblock writes during Drop so
  shutdown is not held hostage by request timeout.

### VL-P2-15 - Revisit Rust API naming for WS-only methods

- Status: [ ]
- Source area: `questdb-rs/src/ingress/sender.rs`
- Action: Decide whether WS-only methods such as `flush_and_get_fsn`,
  `await_acked_fsn`, `drive_once`, and `close_drain` should use a `qwp_ws_`
  prefix like `poll_qwp_ws_error`.

## Downgraded Or Reference-Only Notes

These were called out as false positives, already-tested paths, or overstated
risks in Vlad's review. Keep them here so they are not re-triaged as new work
without fresh evidence.

- `sf_durability=memory` plus `sf_dir` was downgraded to a documentation gap:
  non-memory durability modes are rejected today.
- Backward-moving `complete_through` watermark was considered false-positive;
  current code guards stale ACKs as no-ops.
- `drive_once` in background mode returning invalid API call is already tested.
- QWP/WS error-view getters are panic-free today, but may still get consistency
  wrapping under `VL-P2-02`.
- `published_frame_count(&self)` was judged safe in the current call path.
- Real-server QWP/WS probes exist but CI activation is still missing.
- Per-row lowercase allocation is workload-sensitive rather than universal;
  tracked as `VL-M17`.
- Pre-existing null-deref convention on `unwrap_sender*` and `unwrap_buffer*`
  was not treated as a PR regression.
