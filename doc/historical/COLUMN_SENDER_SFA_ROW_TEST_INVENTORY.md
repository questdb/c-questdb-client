# Unified QWP ingress migration inventory

**Status:** frozen Milestone 0 historical inventory; not a current API
reference. See [`README.md`](README.md).

This is the Milestone 0 migration inventory for
`QWP_UNIFIED_SENDER_DESIGN.md`. It replaces the earlier row-versus-column SFA
test-gap checklist. The inventory is frozen against c-questdb-client commit
`72a6b52fa84fbe702ab2037d7d799569587156a0` and the py-questdb-client checkout
whose `c-questdb-client` submodule points at that commit.

## Release and naming decisions

The split pooled APIs and managed slot layout are unreleased. Tag `6.1.0` is an
ancestor of the baseline by 403 commits, and this command has no matches:

```sh
git grep -n -E 'BorrowedRowSender|BorrowedColumnSender|borrow_row_sender|borrow_column_sender|-row-|-col-' 6.1.0 -- ':!doc/**'
```

There is therefore no compatibility surface to preserve. The final names are:

| Surface | Final name |
|---|---|
| Rust lease | `BorrowedSender` |
| Rust borrow | `QuestDb::borrow_sender()` |
| Rust owned FFI support handle | `OwnedSender` |
| Rust internal SFA core | `PooledSenderCore` |
| C opaque handle | `qwp_sender` |
| C borrow | `questdb_db_borrow_sender()` |
| C buffer factory | `questdb_db_new_buffer()` |
| C operations | `qwp_sender_*` |
| C++ lease | `borrowed_sender` |
| C++ borrow | `questdb_pool::borrow_sender()` |
| Disk managed slot | `<sender-id>-ingest-N` |
| Soak pool key | `ingress` |

Old `-row-N` and `-col-N` development slots are neither adopted nor scanned.

## Rust production surfaces

### Public pool API and lifecycle

- `questdb-rs/src/db.rs`
  - rename `borrow_column_sender()` to `borrow_sender()`;
  - rename `BorrowedColumnSender` to `BorrowedSender`;
  - add the Buffer methods and `QuestDb::new_buffer()`;
  - remove `borrow_row_sender()`, `BorrowedRowSender`, `OwnedRowSender`, and
    `PooledRowSender`;
  - remove the row pool state, condvar, slot reservations, return/reborrow,
    recovery, reaper, close, and debug-count branches;
  - merge the SFA pool cap and managed slot namespace;
  - keep the direct dataframe and reader pools separate.
- `questdb-rs/src/db/ffi_support.rs`: rename the owned SFA handle and borrow
  escape hatch; remove the owned row handle.
- `questdb-rs/src/lib.rs`: replace public row/column lease exports with
  `BorrowedSender`; keep `Chunk`, Arrow types, and direct whole-source methods.
- `questdb-rs/Cargo.toml` and `questdb-rs/README.md`: update feature/API prose,
  doctests, examples, and the compile-time surface.

### Shared SFA publication and encoders

- `questdb-rs/src/ingress/column_sender/sender.rs`: rename the SFA backend and
  extract one foreground transaction for Chunk, Arrow, and Buffer. Preserve the
  existing dictionary write-ahead, torn-dictionary guard, queue append, input
  clearing, split, and retry classifications.
- `questdb-rs/src/ingress/column_sender/mod.rs`: retain payload modules but stop
  naming the physical SFA sender by input orientation.
- `questdb-rs/src/ingress/column_sender/encoder.rs`: retain zero-copy Chunk
  encoding and retained scratch.
- `questdb-rs/src/ingress/column_sender/arrow_batch.rs`: retain Arrow
  classification, metadata overrides, C Data Interface ownership, and split
  encoding.
- `questdb-rs/src/ingress/column_sender/chunk.rs` and `validity.rs`: payload
  names remain column-oriented and do not migrate.
- `questdb-rs/src/ingress/buffer/qwp.rs`: change only
  `encode_ws_replay_message_with_defer()` so output is a separate retained
  `Vec<u8>`; keep the Buffer representation and encoder behavior.
- `questdb-rs/src/ingress/sender/qwp_ws_publisher.rs`: preserve the queue append
  and rollback contract used by standalone `ingress::Sender`.
- `questdb-rs/src/ingress/sender/qwp_ws.rs`: pooled construction releases the
  dormant replay dictionary, while standalone `flush_qwp_ws` and manual
  driving continue to own `QwpWsReplayEncoder` unchanged.
- `questdb-rs/src/ingress/sender/qwp_ws_driver.rs` and
  `qwp_ws_sfa_catchup.rs`: keep the driver mirror in lockstep with foreground
  symbol deltas.
- `questdb-rs/src/ingress/sender/qwp_ws_sfa_symbol_dict.rs`: preserve persisted
  dictionary marks, commits, rollback, recovery validation, and torn-file
  handling.
- `questdb-rs/src/ingress/sender.rs`: standalone `ingress::Sender` remains;
  only references to the pooled split and the encoder signature migrate.

## Rust test surfaces

### Row-pool tests to retarget, never delete

All are in `questdb-rs/src/tests/column_sender_pool.rs` unless noted. The M2
equivalent flushes a Buffer through the current SFA core; the M4 equivalent
uses the final `BorrowedSender` name.

- `row_sender_pool_borrows_recycles_and_caps`
- `row_sender_pool_flush_round_trip`
- `row_sender_flush_and_wait_commits_at_boundary`
- `row_sender_flush_and_wait_durable_without_opt_in_keeps_buffer`
- `row_sender_owned_borrow_flushes_and_recycles`
- `row_sender_owned_mark_must_close_drops_not_recycles`
- `owned_row_sender_observes_pool_close_and_drops_after_close`
- `manual_reap_closes_idle_row_senders`
- `reaper_keeps_undelivered_recovery_row_sender`
- `disk_store_and_forward_restart_preopens_dirty_row_slot`
- `row_sender_pool_grows_and_reuses_physical_connections`
- `row_sender_drop_on_return_drops_instead_of_recycling`
- `row_and_column_senders_borrowed_together_are_independent` becomes one-cap
  mixed-shape borrowing/return coverage.
- `concurrent_row_borrow_and_return_does_not_deadlock_or_leak`
- `auto_reaper_closes_idle_row_senders`
- `row_sender_build_failure_releases_in_use_slot`

The row-side disk tests at the start of the file also migrate rather than
disappear: combined row/column slot use becomes one `-ingest-N` namespace,
duplicate-process collision remains covered, and dirty Buffer frames are
recovered through the unified core.

### Existing SFA core tests to preserve and rename where needed

- Pool: lazy open, offline borrow, reuse, auto-grow, exhaustion, concurrent
  borrow/return, forced drop, manual/auto reaping, close/join, and bounded
  close-drain.
- Disk slots: distinct indices, connect-time pre-open, at-cap close wakeup,
  cross-process flock collision, same-`pool_max` restart, out-of-range orphan,
  unsuffixed orphan, and lock release.
- Publication: empty input, queue capacity, append timeout, max-frame split,
  partial split acceptance, FSN, OK/durable wait, timeout, terminal rejection,
  reconnect, and failover.
- Dictionary: side-file write-ahead, value corruption healing, mid-stream
  delta recovery, torn side-file terminalization, and Arrow symbol write-ahead.
- Arrow: split boundary, server-stamped and timestamp-column modes, ownership
  restoration, metadata override, and wait/FSN contracts.
- Direct path: every `direct_*` pool and dataframe retry test remains separate;
  it is not migrated into the public SFA lease.

Additional test modules:

- `questdb-rs/src/tests/qwp_ws_java_golden.rs` plus
  `src/tests/interop/qwp-unified-ingress/`: full Buffer and Chunk payload
  goldens.
- `questdb-rs/src/tests/qwp_ws.rs`, `qwp_ws_publication_probe.rs`, and
  `qwp_ws_replay_probe.rs`: standalone sender regressions remain unchanged.
- `questdb-rs/src/tests.rs`: module registration and compile-time assertions.
- New compile-fail coverage in M4 pins the borrow lifetime and `!Send`/`!Sync`.

## C FFI surfaces

### Remove or rename in Milestone 4

- `questdb-rs-ffi/src/lib.rs`: remove opaque `row_sender` and every pooled
  `row_sender_*` function; expose Buffer operations on `qwp_sender`.
- `questdb-rs-ffi/src/column_sender.rs`: rename opaque `column_sender`, owned
  borrow/return/drop, Chunk/Arrow flush, FSN, ACK, wait, and error plumbing to
  `qwp_sender`; keep `column_sender_chunk_*`, `column_sender_validity`, Arrow
  import, NumPy, and override names because they describe payloads.
- `questdb-rs-ffi/Cargo.toml`: update FFI-support documentation and test names.

### Headers and ABI tests

- `include/questdb/ingress/line_sender.h`: remove pooled row declarations and
  cross-references; standalone line sender declarations remain.
- `include/questdb/ingress/column_sender.h`: introduce `qwp_sender`, unified
  borrow/return/drop, Buffer and Chunk flush variants, FSN/ACK/wait, and pool
  lifetime documentation.
- `include/questdb/ingress/line_sender_core.hpp`: replace row/column friend
  leases with the unified lease.
- `include/questdb/ingress/line_sender.hpp`: retain standalone Buffer and Sender;
  remove pooled row wrapper hooks.
- `include/questdb/ingress/column_sender.hpp`: rename the pooled RAII lease and
  add Buffer overloads; keep `column_sender_chunk` and direct dataframe types.
- `cpp_test/test_column_sender.cpp`: retarget row lease tests and add one lease
  sending Buffer then Chunk.
- `cpp_test/test_arrow_c.c`, `test_arrow_ingress.cpp`, and
  `test_reader_mock.cpp`: update unified opaque-handle names and pool counts.
- `cpp_test/qwp_mock_c.h`: update test-only declarations.

The M4 ABI gate inspects the built shared library and requires no exported
pooled `row_sender_*` symbols or old column lease borrow/return/drop symbols.

## C and C++ examples and docs

The following contain the split borrow names or pooled sender identity and must
migrate in M4/M6:

- root `README.md`;
- `questdb-rs/README.md`;
- `examples/qwp_ingress_c.c`;
- `examples/qwp_egress_c.c`;
- `examples/line_sender_cpp_example_arrow.cpp`;
- `examples/bench_ingest_c.c` and `bench_ingest_c.h` where the direct sender
  distinction must remain explicit;
- `questdb-rs/examples/qwp_ingress_polars.rs` and `qwp_ws_l1_quotes.rs`;
- `doc/historical/COLUMN_SENDER_PLAN.md`;
- `doc/historical/COLUMN_SENDER_STORE_AND_FORWARD.md`;
- `doc/historical/COLUMN_SENDER_FFI_ABI.md`;
- `doc/historical/COLUMN_SENDER_ACK_BOUNDARY_FLUSH.md`;
- `doc/historical/COLUMN_SENDER_PERF.md`;
- `doc/historical/QWP_DATAFRAME_BENCH_PLAN.md`.

Historical design documents may describe the old split only when prominently
marked superseded; normal examples and rustdoc must not.

## Python repository surfaces

Milestone 5 is a coordinated change in the sibling `py-questdb-client`
repository. Its c-questdb-client submodule currently points at the M0 baseline.

Hand-edited sources:

- `src/questdb/line_sender.pxd`: bind `qwp_sender` and unified Buffer calls;
- `src/questdb/_client.pyx` and `_client.pyi`: add `Client.sender()`, its
  context-managed active-use lease, and deprecate `Sender.dataframe()` and
  `Buffer.dataframe()`;
- `src/questdb/dataframe.pxi`: keep `Client.dataframe()` on direct Chunk/Arrow
  routing and remove recommendations to the row dataframe route;
- `CHANGELOG.rst`: warning, replacement, and chosen removal release;
- `test/system_test.py`, `test/test_dataframe.py`, and
  `test/test_dataframe_leaks.py`: unified row ingestion, warning stacklevel,
  direct dataframe routing, lifetime, and leak coverage.

Generated `src/questdb/_client.c`, `_client.html`, `dataframe.html`,
`ingress.c`, and `ingress.html` are regenerated by the Python build; they are
not edited by hand.

## Soak and CI surfaces

The row workload is retargeted, not removed.

- `system_test/soak/workload_rs/src/legs.rs`: `run_row_leg` becomes the Buffer
  leg on `borrow_sender()` and remains responsible for the Buffer-expressible
  type set, ACK journal, re-drive, and pool return.
- `system_test/soak/workload_rs/src/column_leg.rs`: the Chunk leg borrows the
  same public sender and retains zero-copy batch construction.
- `system_test/soak/workload_rs/src/dataframe_leg.rs`: remains on the hidden
  direct whole-source route.
- `system_test/soak/workload_rs/src/stats.rs`: replace `column_sf` and
  `row_sender` with one `ingress` count; keep `column_direct` and `reader`.
- `system_test/soak/soak.py`: update the pool-counter parser/self-test and make
  the former row leg feed the M6 mixed Buffer/Chunk/Arrow sequence.
- `ci/run_soak_pipeline.yaml`: retain the pre-gate and long-running job; update
  names and assertions, never delete the row/Buffer leg.

## Live/system-test surfaces

- `system_test/arrow_ffi.py`, `arrow_fuzz_common.py`, and
  `arrow_ingress_fuzz.py`: rename the leased handle and recognize only
  `-ingest-N` managed slots.
- `system_test/failover_clients/src/bin/qwp_column_sidecar.rs`: use
  `borrow_sender()` for Chunk; keep direct dataframe sidecars separate.
- `system_test/questdb_line_sender.py` and the QWP row system tests: retarget
  pooled row building to the unified C handle while standalone Sender tests
  remain standalone.
- `system_test/c_sidecars/qwp_c_sidecar.c` and `qwp_cpp_sidecar.cpp`: migrate
  only if they use the pooled API; standalone failover sidecars retain their
  existing transport surface.

## Frozen payload behavior matrices

### Input ownership and validation

| Contract | Buffer | Chunk | Arrow RecordBatch |
|---|---|---|---|
| Storage | owns cells | borrows typed slices | borrows immutable Arrow arrays |
| Tables per logical input | multiple | one | one |
| Empty input | no publication | no publication | no publication |
| Incomplete row | reject before encode | not representable | not representable |
| Length validation | row completion | equal logical lengths | Arrow schema/array lengths |
| Timestamp | per row, table-local | now/scalar/slice | now/scalar/timestamp column |
| Symbols | per-cell strings | dictionary codes + bytes | dictionary or Utf8 override |
| Oversize | reject whole Buffer | zero-copy row-range split | zero-copy/Arrow slice split |
| On local success | clear unless keep form | clear descriptors | RecordBatch unchanged |
| On local failure before append | unchanged/retryable | unchanged/retryable | ownership restored/retryable |
| After split prefix accepted | n/a | delivery unknown; no blind retry | delivery unknown; ownership contract preserved |

### Publication and error contract

| Event | Frozen result |
|---|---|
| Empty payload | `None` FSN; no dictionary or queue mutation |
| Encode validation failure | input unchanged; dictionary and side-file roll back |
| Effective max-size failure | no queue append; dictionary and side-file roll back |
| Symbol side-file append failure | no queue append; memory and file roll back to marks |
| Queue append failure/timeout | input unchanged; memory and file roll back to marks |
| Local append success | return final FSN; clear mutable Buffer/Chunk as applicable |
| Wait timeout after append | input stays cleared; queued frame continues; call `wait`, do not reflush |
| Drop-and-continue server rejection | completed watermark advances; diagnostic reported once |
| Terminal rejection | sender is not recycled; next borrower gets a fresh healthy core |
| Reconnect/restart | recovered frame dictionary IDs and driver mirror stay in lockstep |

The full scalar/null/omitted Buffer matrix remains covered by Buffer unit tests;
the full Chunk width/validity/timestamp matrix remains in `chunk.rs` and
`encoder.rs`; Arrow classification, metadata, ownership, and retry restoration
remain in `arrow_batch.rs` plus FFI/system tests. Unification changes ownership
of publication state, not these payload contracts.

## M0 fixtures and reproducibility

- `questdb-rs/src/tests/interop/qwp-unified-ingress/m0-equivalent-buffer.hex`
- `questdb-rs/src/tests/interop/qwp-unified-ingress/m0-equivalent-chunk.hex`
- `qwp_ws_java_golden::equivalent_buffer_and_chunk_payloads_match_checked_in_goldens`
- `questdb-rs/examples/qwp_ws_unified_sfa_bench.rs`
- `doc/QWP_UNIFIED_SENDER_M0_BASELINE.md`

The checked-in Buffer and Chunk payloads encode the same ten-row mixed-symbol
fixture. The benchmark covers Buffer, Chunk, and Arrow through the current SFA
pools and reports local publish throughput, queue latency percentiles,
allocation deltas, ACK drain time, and close time.
