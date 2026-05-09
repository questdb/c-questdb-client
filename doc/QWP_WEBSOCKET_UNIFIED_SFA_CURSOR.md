# QWP/WebSocket Unified SFA Cursor Design

Date: 2026-05-09

Status: implemented in the current worktree. The real-server benchmark protocol
below was run against a local development QuestDB server.
Owner: QWP/WebSocket storage cleanup implementation agent.

Implementation notes:

- memory mode now opens `SfaSlotQueue::open_memory(...)` and uses
  memory-backed `SfaFrameQueue` segments;
- disk mode still opens `SfaSlotQueue::open(...)` with slot locks and
  file-backed `.sfa` segments;
- the production lock-free volatile queue and the old test-only
  `VolatileFrameQueue` have been removed;
- `PublicationLog::take_sfa_producer()` has been renamed to
  `take_producer()`;
- the send cursor now holds its current SFA segment handle directly, so replay
  across rotated sealed segments does not clone the sealed segment list per
  frame;
- focused Rust tests, zero-allocation checks, clippy, formatting, and
  `git diff --check` passed after the implementation;
- the refreshed real-server benchmark below shows Rust memory mode faster than
  the pre-refactor `HEAD` baseline, while Rust `sf_dir` remains within the
  accepted less-than-5% threshold.

## Goal

Unify Rust QWP/WebSocket publication storage around one cursor engine, matching
the Java client model:

- no `sf_dir`: memory-backed SFA cursor segments;
- `sf_dir`: mmap-file-backed SFA cursor segments;
- both modes share FSN assignment, frame layout, send cursor, ACK handling,
  rejection handling, backpressure, segment rotation, and trim mechanics.

The unification should remove both volatile queue implementations:

- the production `LockFreeVolatilePublicationLog` / `LockFreeVolatileFrameQueue`;
- the old test/prototype-only `VolatileFrameQueue`.

After this refactor, Rust should not have a separate volatile QWP/WebSocket
publication engine.

## Implementation Principles

This is primarily a simplification refactor, not an abstraction exercise.

Prefer reusing and extending existing types over introducing new concepts. In
particular:

- keep `SfaFrameQueue` as the cursor engine;
- keep `SfaSlotQueue` as the configured sender wrapper;
- add memory-backed segment support to the existing SFA path;
- remove the volatile queues instead of wrapping them behind another layer.

Do not add a new enum, trait, wrapper, or ownership concept unless the code
cannot stay correct without it. If a new abstraction is proposed during
implementation, it should replace existing complexity rather than sit above it.

Performance is also a hard requirement. The steady-state publish path must
remain suitable for high-throughput ingestion:

- no heap allocation after warmup on the common active-segment append path;
- no filesystem work on the common append path;
- no publication-store mutex on the common append path;
- no `SfaEngine.state` mutex on the common active-segment append path;
- no segment or hot-spare allocation from the producer on the common append
  path;
- all storage/spare/trim work remains in the runner or manual `drive_once()`
  maintenance path.

"Common append path" means appending a payload that fits in the current active
segment while a hot spare already exists for the next rotation. Segment
rotation may take the SFA state lock, and maintenance may allocate or perform
filesystem work, but those are not the steady-state byte-copy path.

## Java Reference

The Java client already uses one cursor architecture for both backing modes.

Reference paths:

```text
/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/CursorSendEngine.java
/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/MmapSegment.java
/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/SegmentRing.java
```

Important Java facts:

- `CursorSendEngine` treats `sfDir == null` as memory-only mode and
  `sfDir != null` as Store-and-Forward mode, but both use the same cursor
  architecture.
- Memory mode uses memory-backed segments with the same frame layout as file
  segments.
- File mode uses mmap-backed `.sfa` segments that recover across sender
  restarts.
- The append hot path writes an SFA frame and publishes the cursor last.
- Rotation and sealed-segment list mutation are rare structural paths, not the
  common append path.

## Current Rust State

Rust now has one production configured queue shape: `SfaSlotQueue`.

Relevant Rust paths:

```text
questdb-rs/src/ingress/sender/qwp_ws.rs
questdb-rs/src/ingress/sender/qwp_ws_driver.rs
questdb-rs/src/ingress/sender/qwp_ws_queue.rs
questdb-rs/src/ingress/sender/qwp_ws_sfa_queue.rs
questdb-rs/src/ingress/sender/qwp_ws_sfa_segment.rs
questdb-rs/src/ingress/sender/qwp_ws_sfa_slot.rs
```

The configured sender opens memory mode through `SfaSlotQueue::open_memory(...)`
when `sf_dir` is absent. That constructor uses memory-backed `SfaFrameQueue`
segments, not the old lock-free byte ring.

Both memory mode and `sf_dir` mode store Java-compatible SFA frames through the
same cursor engine. The shared engine owns:

- segment-backed payload replay;
- CRC-last append ordering;
- segment rotation;
- send cursor positioning;
- reconnect replay;
- trim;
- hot-spare provisioning;
- recovery diagnostics;
- orphan replay integration.

## What The Split Bought Before

The removed separate memory queue gave memory mode a stripped-down hot path:

- no 8-byte SFA frame envelope;
- no CRC32C pass;
- no segment rotation machinery;
- no storage maintenance hooks;
- one raw byte ring sized from `sf_max_total_bytes`;
- a direct lock-free SPSC byte-range publication path.

That was the only meaningful advantage.

It also created real costs:

- duplicated FSN, completion, ACK, rejection, receipt, and payload lookup
  semantics;
- two detached producer handles in the runner;
- forwarding glue in `ConfiguredQwpWsQueue`;
- `PublicationLog` methods that exist only for one implementation;
- driver tests that use a third queue shape (`VolatileFrameQueue`) that is not
  the production queue;
- Java parity risk, because memory mode did not exercise the same cursor
  mechanics as durable mode.

## Validated Deletion Surface

The pre-implementation removable surface was large enough to justify the
cleanup.

Conservative production cleanup:

- about 470 lines for `LockFreeVolatileFrameQueue`,
  `LockFreeVolatileProducer`, `LockFreeVolatilePublicationLog`,
  `LockFreeByteRing`, lock-free slots, impls, and debug output in
  `qwp_ws_queue.rs`;
- about 24 lines for `PendingPayload::LockFreeQueue` and its read helper;
- about 45 lines for `PublicationLog for LockFreeVolatilePublicationLog` in
  `qwp_ws_driver.rs`;
- about 147 lines for `ConfiguredQwpWsQueue` forwarding that exists only
  because memory and SFA are different concrete queue types;
- about 30 additional lines for the runner's separate lock-free producer field
  and branch in `publish_replay_payload()`.

Expected production gross removal: roughly 716 lines, rounded to about 700
lines because the exact diff depends on how much forwarding code disappears
when tests are migrated.

Full unification also targeted removal of the old test/prototype queue:

- about 235 lines for `VolatileFrameQueue`, `FrameSlot`, and `FrameState`;
- about 37 lines for `PublicationLog for VolatileFrameQueue`;
- about 532 lines of volatile-queue-specific tests.

Expected gross removal if test scaffolding is also migrated: roughly 1,520
lines, before adding memory-backed SFA support and replacement tests.

These were pre-implementation gross counts. The net diff is smaller because
memory-backed SFA segments and migrated tests were added.

## Implemented Design

### One Configured Queue Type, Existing Types Only

`ConfiguredQwpWsQueue` is gone. The configured sender uses `SfaSlotQueue` as the
`PublicationLog` type.

This does not mean memory mode takes a slot lock. `SfaSlotQueue` already stores
its lock as `Option<SlotLock>`:

```rust
pub(crate) struct SfaSlotQueue {
    queue: SfaFrameQueue,
    lock: Option<SlotLock>,
}
```

The implementation uses that existing shape:

- disk mode: `SfaSlotQueue { queue, lock: Some(lock) }`;
- memory mode: `SfaSlotQueue { queue, lock: None }`.

`SfaFrameQueue` remains the cursor engine. `SfaSlotQueue` remains the configured
wrapper used by the sender. That avoids a new configured wrapper and avoids
pushing disk slot-lock concerns into memory mode.

The queue constructors should be simple:

```rust
impl SfaFrameQueue {
    fn open_memory(options: SfaMemoryQueueOptions) -> Result<Self, SfaQueueError>;
    fn open(options: SfaQueueOptions) -> Result<Self, SfaQueueError>; // existing disk queue
}

impl SfaSlotQueue {
    fn open(options: SfaSlotOptions) -> Result<Self, SfaQueueError>; // existing disk slot
    fn open_memory(options: SfaMemoryQueueOptions) -> Result<Self, SfaQueueError>;
}
```

Then configured open becomes:

```rust
if let Some(sf_dir) = qwp_ws.sf_dir.as_ref() {
    SfaSlotQueue::open(SfaSlotOptions { ... })
} else {
    SfaSlotQueue::open_memory(SfaMemoryQueueOptions { ... })
}
```

- memory mode must not touch slot locks, `.sfa` file discovery, `.failed`,
  orphan scanning, or disk recovery;
- disk mode keeps the existing slot/disk behavior;
- both modes share active segment append, hot-spare promotion, send cursor,
  ACK/reject handling, and trim state.

### Disk Slot Wrapper

`qwp_ws_sfa_slot.rs` should be kept. It owns the disk-only surface:

- `sf_dir` / `sender_id` validation;
- slot directory selection;
- `.lock` acquisition;
- `.lock.pid` diagnostics;
- slot-lock release on close/drop.

Memory mode should enter this wrapper only through `SfaSlotQueue::open_memory`.
That constructor should not validate `sf_dir`, create directories, take locks,
write pid files, scan `.sfa` files, or participate in orphan adoption.

This keeps the external configured type simple without making memory mode pay
for disk-only behavior.

### Memory-Backed Segment

`SfaSegment` currently owns a `File` and an mmap mapping. It needs a memory
backing variant.

Keep this minimal. Prefer optional fields over introducing a new backing enum:

```rust
pub(crate) struct SfaSegment {
    file: Option<File>,
    mapping: Arc<SfaSegmentMapping>,
    path: Option<PathBuf>,
    ...
}
```

Add:

```rust
impl SfaSegment {
    fn create_memory(base_seq: u64, size_bytes: u64, created_us: u64)
        -> Result<Self, SfaSegmentError>;
}
```

Use anonymous `MmapMut` for the first implementation if the existing dependency
supports it cleanly. Java uses malloc-backed memory segments, but anonymous mmap
keeps Rust on the existing `MmapMut` plus raw-pointer mapping discipline. That
is the simpler Rust implementation because it avoids adding a second byte-access
model beside `SfaSegmentMapping`.

Memory-backed segment allocation must happen during queue setup or maintenance,
not inside the successful active-segment append path.

Memory-backed segments must keep the Java-compatible SFA layout:

```text
[segment header][crc32c][payload_len_le][payload]...
```

Memory mode should still compute CRC and write the frame envelope. That is the
point of Java parity and test unification.

### Segment Paths

Memory-backed segments should not have real filesystem paths.

Avoid fake path strings leaking into diagnostics. The first step should make
`SfaSegment::path` optional and keep path-requiring code disk-only.

Only add a display helper later if the code becomes noisy. Do not add a new
identity enum up front.

### Storage Maintenance

Keep storage maintenance as a queue operation, but make it backing-aware.

Memory mode still needs logical maintenance:

- provision a hot spare if missing and capacity allows;
- retire fully ACKed sealed segments;
- release memory capacity.

Memory mode must not perform filesystem cleanup. A memory trim should drop the
segment and return no cleanup task.

Disk mode keeps the current two-phase behavior:

- detach logical ownership under the queue state lock;
- perform file creation/unlink outside the publication-store mutex;
- relock only to install the result or record cleanup diagnostics.

Avoid adding a new maintenance abstraction. Make the existing maintenance types
path-aware:

- memory segment cleanup: drop the detached segment, no path, no unlink;
- disk segment cleanup: drop the detached segment, then unlink the path;
- memory hot spare creation: create `SfaSegment::create_memory(...)`;
- disk hot spare creation: create the existing file-backed segment.

Publication must not secretly perform missing hot-spare creation. If the
producer reaches the end of the active segment and no spare is ready, it should
report backpressure and let the existing wait/drive loop make progress.

### Producer Path

The runner should keep only one producer field:

```rust
producer: Option<SfaProducer>
```

Remove:

- `LockFreeVolatileProducer`;
- `take_lock_free_producer`;
- the lock-free branch in `publish_replay_payload()`;
- fallback publication through the shared store for configured senders, except
  where tests explicitly use a fake `PublicationLog`.

Rename `take_sfa_producer()` to `take_producer()` once it is the only detached
producer accessor. Do not keep an SFA-specific trait method name after the
volatile producer is gone.

The common publish path should be:

1. check lifecycle;
2. call `SfaProducer::try_submit(payload)`;
3. on capacity backpressure, wait for the backpressure generation/deadline;
4. retry.

The successful active-segment `try_submit` path should only validate, copy the
payload into the mapped segment, compute/write the frame CRC, update
producer-owned cursors, and publish the atomic upper watermark. It must not
allocate, lock the publication store, create segments, unlink files, or perform
disk I/O.

### Manual Driver Tests

The old `VolatileFrameQueue` must not survive as the default test queue.

Current default:

```rust
pub(crate) struct ManualDriverPrototype<Q = VolatileFrameQueue, T = FakeOrderedServer>
```

Target:

```rust
pub(crate) struct ManualDriverPrototype<Q = SfaFrameQueue, T = FakeOrderedServer>
```

or no default queue type at all, if explicit test construction is clearer.

Driver tests should use memory-backed SFA queues unless a test specifically
needs a tiny fake. If a fake is needed, it should be a small test-local
`PublicationLog` implementation, not a reusable second production-like queue.

This is a hard cleanup requirement. Keeping `VolatileFrameQueue` would preserve
the duplicate semantic surface this refactor is supposed to remove.

Do not delete logical coverage. Rewrite tests that validate unified semantics
against memory-backed SFA:

- FSN assignment and ordering;
- ACK and rejection transitions;
- max-in-flight backpressure;
- byte/segment capacity backpressure;
- reconnect send-cursor positioning;
- close-drain completion.

Only delete tests whose sole purpose was proving `LockFreeByteRing` internals.

## Correctness Requirements

The unified memory path must preserve current public behavior:

- FSNs start at 0 for a fresh memory queue.
- ACKs and rejections report the same `QwpReceiptStatus` transitions.
- `max_in_flight` still bounds outstanding frames.
- `sf_max_total_bytes` still bounds queued memory.
- `sf_max_bytes` now matters in memory mode as segment size. This is a
  user-visible change from the old flat byte ring. A single payload must fit in
  one memory-backed SFA segment, and rotation granularity follows
  `sf_max_bytes`.
- Fresh publish-capable memory and disk queues reject
  `sf_max_total_bytes < 2 * sf_max_bytes`. Publication needs one active segment
  plus one prepared hot spare; allowing a one-segment cap can dead-end rotation
  after ACK progress.
- `sf_append_deadline_millis` still controls publication backpressure.
- manual `drive_once()` still reports progress consistently.
- background publication must not take the publication-store mutex on the hot
  append path.

The unified memory path intentionally changes internal behavior:

- memory mode writes SFA frame envelopes;
- memory mode computes CRC32C;
- memory mode rotates memory-backed segments;
- memory mode exercises SFA send-cursor code.

Those internal changes are acceptable because they align Rust with Java and
remove duplicate semantics.

Add a milestone-2 test that pins `max_in_flight`: with `max_in_flight = N`, a
memory-mode producer must report backpressure after N unacked frames regardless
of remaining segment capacity.

## Performance Expectations

Expected cost:

- one CRC32C pass per published QWP payload in memory mode;
- 8 bytes of SFA frame envelope per payload;
- producer-side lock contention on segment rotation if the runner is
  concurrently snapshotting segments or performing storage maintenance;
- possible extra cache pressure from segment metadata.

Be explicit about the tradeoff: the current `LockFreeVolatileFrameQueue` has no
producer-side mutex on memory-mode publication. The unified SFA path keeps the
common active-segment append mutex-free, but rotation takes `SfaEngine.state`.
Benchmarks must include workloads that rotate frequently enough to expose that
cost.

The no-allocation/no-lock steady-state requirement is not optional. If the first
implementation regresses it, the implementation is not complete. The target is:

- warmed memory-mode `Sender::flush(...)` publication has zero heap allocations
  on the queue append path;
- warmed disk-SFA `Sender::flush(...)` publication has zero heap allocations on
  the queue append path when the active segment has room;
- neither mode locks `QwpWsPublicationStore` to publish from the background
  sender path;
- neither mode locks `SfaEngine.state` while appending to a non-full active
  segment.

Expected wins:

- less code;
- one correctness path;
- memory and disk mode benchmark more similarly;
- fewer hidden memory-vs-SFA behavior gaps;
- future durability-mode work has one place to hook `flush` / `append` sync.

This refactor should be benchmarked, not assumed free. The comparison should
include:

- current Rust memory mode before the refactor;
- unified Rust memory mode after the refactor;
- Rust disk SFA mode before/after to catch accidental regressions;
- Java memory mode with the public `Sender` API.

## Real-Server Benchmark Protocol

Benchmarking is mandatory for this refactor. The implementation agent must
record BEFORE results in this document before changing the queue implementation,
then record AFTER results in the same table before handing the work back.

Use a real running QuestDB server and the public end-user `Sender` API. Do not
benchmark internal queue helpers as the primary performance signal. The goal is
to measure what users experience through normal `Sender` usage.

Required workload:

- 50,000,000 rows total;
- 1,000 rows per flush batch;
- 50,000 total flush batches;
- one table per run unless explicitly documenting a different table-shape
  experiment;
- fixed row shape for the primary comparison:
  - table: `qwp_ws_unified_sfa_bench`;
  - symbols: `sym` with a small bounded cardinality such as 1,000 distinct
    values;
  - numeric columns: at least one integer and one floating-point value;
  - timestamp: one designated timestamp per row;
  - no schema changes between BEFORE and AFTER;
- same row schema, host, port, auth, TLS mode, server build, client build,
  CPU governor, and filesystem for BEFORE and AFTER;
- record whether the run is memory mode or `sf_dir` mode;
- for `sf_dir` mode, use the same SFA root before and after. Prefer
  `/mnt/pcie5` on the local workstation when available, and clean the benchmark
  sender slot between runs.

Build and run rules:

- use optimized/release client builds only;
- do not benchmark with temporary debug logging, allocation tracing, profilers,
  or sanitizers enabled unless the run is explicitly marked diagnostic;
- paste the exact Rust and Java command lines and config strings into the
  result notes;
- run one unrecorded warmup first, or a smaller warmup with the same row shape,
  then run the recorded measurements;
- run each recorded case at least three times and report median, min, and max;
- clean only the benchmark sender slot before each `sf_dir` run. Do not delete
  unrelated SFA directories.

Run at least these Rust client cases:

1. Memory mode: no `sf_dir`.
2. Store-and-Forward mode: `sf_dir` configured, `sf_durability=memory`.

Run Java memory mode with the same public `Sender` workload as a reference
comparison. Java disk SFA is useful too, but Rust BEFORE/AFTER is the hard
regression gate for this refactor.

Capture at minimum:

- publish-loop elapsed wall-clock time, covering row building and
  `Sender::flush()` calls;
- total elapsed wall-clock time, including final close/drain;
- rows/second from publish-loop elapsed time;
- rows/second from total elapsed time;
- batches/second from publish-loop elapsed time;
- client CPU utilization if available;
- server CPU utilization if available;
- resident memory high-water mark if available;
- notes about server state, table cleanup, and any retries/reconnects.

Correctness validation:

- after each recorded run, verify that the server table contains exactly
  50,000,000 rows;
- record the validation query/result in the notes;
- if validation is skipped, mark the run as diagnostic only. Do not use it as a
  regression gate.

Use this table. Fill BEFORE before implementation starts.

| Case | Client commit/build | Server build | Mode | Runs | Rows | Rows/batch | Publish s median/min/max | Total s median/min/max | Publish rows/s | Total rows/s | Batches/s | Row-count validation | Notes |
|------|---------------------|--------------|------|------|------|------------|--------------------------|------------------------|----------------|--------------|-----------|----------------------|-------|
| Rust BEFORE | `90cb5fd7af848eb40016b113df171e029b266b27` detached worktree plus benchmark harness | `build() = Build Information: unknown [DEVELOPMENT], JDK unknown, Commit Hash unknown` | memory | 3 | 50,000,000 | 1,000 | 4.027 / 3.635 / 4.172 | 4.028 / 3.636 / 4.190 | 12,413,974.77 | 12,410,220.96 | 12,413.97 | `select count() ...` returned `50,000,000` after each run | Exact conf: `qwpws::addr=127.0.0.1:9000;in_flight_window=128;`. |
| Rust BEFORE | `90cb5fd7af848eb40016b113df171e029b266b27` detached worktree plus benchmark harness | `build() = Build Information: unknown [DEVELOPMENT], JDK unknown, Commit Hash unknown` | `sf_dir`, `sf_durability=memory` | 3 | 50,000,000 | 1,000 | 4.248 / 4.194 / 4.308 | 4.252 / 4.195 / 4.310 | 11,769,232.04 | 11,756,657.86 | 11,769.23 | `select count() ...` returned `50,000,000` after each run | Exact confs used `/mnt/pcie5/qdb-rust-sfa-unified-bench` with fresh sender IDs `rust_before_sf_run1..3`. |
| Java reference | `java-questdb-client` `387fe91`, `questdb-client-1.2.1-SNAPSHOT.jar` | `build() = Build Information: unknown [DEVELOPMENT], JDK unknown, Commit Hash unknown` | memory | 3 | 50,000,000 | 1,000 | 5.241 / 5.189 / 5.386 | 5.298 / 5.245 / 5.440 | 9,538,639.06 | 9,435,760.33 | 9,538.64 | `select count() ...` returned `50,000,000` after each run | Exact conf: `ws::addr=127.0.0.1:9000;in_flight_window=128;`. |
| Rust AFTER | `90cb5fd7af848eb40016b113df171e029b266b27` plus current unified-SFA worktree | `build() = Build Information: unknown [DEVELOPMENT], JDK unknown, Commit Hash unknown` | memory | 3 | 50,000,000 | 1,000 | 3.858 / 3.733 / 4.021 | 3.863 / 3.734 / 4.023 | 12,958,373.98 | 12,940,416.07 | 12,958.37 | `select count() ...` returned `50,000,000` after each run | Exact conf: `qwpws::addr=127.0.0.1:9000;in_flight_window=128;`. Refreshed after the send-cursor allocation fix. Median publish time is 4.2% faster than Rust BEFORE memory. |
| Rust AFTER | `90cb5fd7af848eb40016b113df171e029b266b27` plus current unified-SFA worktree | `build() = Build Information: unknown [DEVELOPMENT], JDK unknown, Commit Hash unknown` | `sf_dir`, `sf_durability=memory` | 3 | 50,000,000 | 1,000 | 4.322 / 4.022 / 4.359 | 4.323 / 4.023 / 4.361 | 11,567,711.33 | 11,565,115.98 | 11,567.71 | `select count() ...` returned `50,000,000` after each run | Exact confs used `/mnt/pcie5/qdb-rust-sfa-unified-bench` with fresh sender IDs `rust_after_sf_cursor_run1..3`. Refreshed after the send-cursor allocation fix. Median publish time is 1.7% slower than Rust BEFORE `sf_dir`. |

Recorded command shapes:

```bash
curl -sS 'http://127.0.0.1:9000/exec?query=drop%20table%20if%20exists%20qwp_ws_unified_sfa_bench'

QWP_WS_UNIFIED_SFA_BENCH_ROWS=50000000 \
QWP_WS_UNIFIED_SFA_BENCH_BATCH_SIZE=1000 \
QWP_WS_UNIFIED_SFA_BENCH_LABEL=<label> \
QWP_WS_UNIFIED_SFA_BENCH_CONF='<rust-conf>' \
cargo run --release --manifest-path questdb-rs/Cargo.toml \
  --features sync-sender-qwp-ws \
  --example qwp_ws_unified_sfa_bench

java --enable-native-access=ALL-UNNAMED \
  -cp /tmp:/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/target/questdb-client-1.2.1-SNAPSHOT.jar:/home/jara/.m2/repository/org/slf4j/slf4j-api/2.0.17/slf4j-api-2.0.17.jar \
  -Dqwp.unified.rows=50000000 \
  -Dqwp.unified.batchSize=1000 \
  -Dqwp.unified.label=<label> \
  -Dqwp.unified.conf='<java-conf>' \
  QwpWsUnifiedSfaJavaBench

curl -sS 'http://127.0.0.1:9000/exec?query=select%20count%28%29%20from%20qwp_ws_unified_sfa_bench'
```

Run notes:

- A 1,000-row smoke run was executed for Rust memory mode, Rust `sf_dir` mode,
  and Java memory mode before the recorded 50,000,000-row runs.
- The table was dropped before every recorded run.
- The primary row shape was fixed across Rust and Java: table
  `qwp_ws_unified_sfa_bench`, symbol column `sym` with 1,000 distinct values,
  integer column `qty`, floating column `px`, and designated timestamp.
- `cpu0` scaling governor reported `performance` after the run. Rust `sf_dir`
  used `/mnt/pcie5/qdb-rust-sfa-unified-bench`; `findmnt -T /mnt/pcie5`
  reported an ext4 filesystem on `/dev/nvme1n1p2`.
- Client/server CPU utilization and resident-memory high-water marks were not
  captured by the local run. No retries or reconnects were observed in the
  benchmark output.
- Rust BEFORE was measured from a detached worktree at `90cb5fd7...` because
  the implementation had already been applied in the main worktree before the
  benchmark was run. The benchmark harness itself was added to both worktrees
  so the measured driver shape matched.

Regression rule:

- If unified memory mode is slower than Rust BEFORE memory mode, quantify the
  regression and explain it from evidence before deciding whether to proceed.
- Less than 5% slower: acceptable if the code simplification is real and the
  no-allocation/no-hot-lock requirements still hold.
- 5-15% slower: requires evidence, explanation, and explicit discussion before
  handoff.
- More than 15% slower: blocker unless the user explicitly accepts it.
- Disk SFA mode should not regress materially; this refactor should mostly
  affect memory mode.
- If AFTER is materially slower, collect a CPU profile before changing code
  further. Do not guess at the cause.

## Completed Implementation Milestones

### Milestone 1: Introduce Memory-Backed SFA Segments

- Added `SfaSegment::create_memory(...)`.
- Changed `SfaSegment::file` and `SfaSegment::path` to optional fields to
  support no-file segments.
- Kept existing disk segment behavior unchanged.
- Added unit tests that append/read frames from memory-backed segments and verify
  they use the same frame scanner/layout as disk segments.

### Milestone 2: Add Memory-Backed SFA Queue Constructor

- Added `SfaFrameQueue::open_memory(...)`.
- Reused SFA producer, send cursor, completion, rejection, and storage
  maintenance.
- Made memory trim drop segments without filesystem cleanup.
- Added queue tests for rotation, ACK trim, backpressure, and replay payload
  reads in memory mode.
- Added a max-in-flight test proving memory mode backpressures after N unacked
  frames even if segment capacity remains.

### Milestone 3: Route Configured Memory Mode Through SFA

- Added `SfaSlotQueue::open_memory(...)` with `lock: None`.
- Changed configured QWP/WebSocket open so `sf_dir=None` creates
  `SfaSlotQueue::open_memory(...)`.
- Removed `LockFreeVolatilePublicationLog` from the configured path.
- Kept disk mode unchanged.
- Ran existing QWP/WebSocket driver and queue tests.

### Milestone 4: Delete Lock-Free Volatile Queue

Removed from `qwp_ws_queue.rs`:

- `LockFreeVolatileFrameQueue`;
- `LockFreeVolatileProducer`;
- `LockFreeVolatilePublicationLog`;
- `LockFreeVolatileFrameQueueInner`;
- `LockFreeByteRing`;
- `LockFreeFrameSlot`;
- `PendingPayload::LockFreeQueue`.

Removed from `qwp_ws_driver.rs` and `qwp_ws.rs`:

- `take_lock_free_producer`;
- renamed `take_sfa_producer` to `take_producer`;
- `PublicationLog for LockFreeVolatilePublicationLog`;
- runner `producer: Option<LockFreeVolatileProducer>`;
- lock-free branch in `publish_replay_payload()`;
- `ConfiguredQwpWsQueue`.

### Milestone 5: Delete Test-Only `VolatileFrameQueue`

Removed from `qwp_ws_queue.rs`:

- `VolatileFrameQueue`;
- `FrameSlot`;
- `FrameState`;
- volatile-queue-specific tests.

Removed from `qwp_ws_driver.rs`:

- `PublicationLog for VolatileFrameQueue`;
- default `ManualDriverPrototype<Q = VolatileFrameQueue>`;
- helper constructors that implicitly create `VolatileFrameQueue`.

Migrated driver tests to memory-backed SFA queues or minimal test-local fakes.
Preserved logical coverage for FSN ordering, ACK/reject, capacity, reconnect,
and close-drain behavior.

### Milestone 6: Clean Docs And Parity Notes

- Updated `doc/QWP_WEBSOCKET_SPEC_COMPLIANCE_GAPS.md` to remove the memory
  architecture mismatch.
- Updated older volatile queue prototype docs or marked them historical.
- Updated performance notes with before/after measurements.

## Validation Plan

Focused Rust tests:

```text
cargo test --manifest-path questdb-rs/Cargo.toml qwp_ws_queue --features sync-sender-qwp-ws --lib
cargo test --manifest-path questdb-rs/Cargo.toml qwp_ws_sfa_queue --features sync-sender-qwp-ws --lib
cargo test --manifest-path questdb-rs/Cargo.toml qwp_ws_driver --features sync-sender-qwp-ws --lib
cargo test --manifest-path questdb-rs/Cargo.toml qwp_ws --features sync-sender-qwp-ws --lib
```

Performance/correctness regression tests:

```text
cargo test --manifest-path questdb-rs/Cargo.toml sfa_tiny_frame_publish_zero_alloc_after_warmup --features sync-sender-qwp-ws --lib -- --ignored --test-threads=1
cargo test --manifest-path questdb-rs/Cargo.toml sfa_memory_tiny_frame_publish_zero_alloc_after_warmup --features sync-sender-qwp-ws --lib -- --ignored --test-threads=1
cargo test --manifest-path questdb-rs/Cargo.toml sfa_send_cursor_after_rotation_zero_alloc_after_warmup --features sync-sender-qwp-ws --lib -- --ignored --test-threads=1
cargo test --manifest-path questdb-rs/Cargo.toml publisher_memory_sfa_zero_alloc_after_warmup --features sync-sender-qwp-ws --lib -- --ignored --test-threads=1
```

Add or update a memory-mode equivalent of the warmed zero-allocation test after
memory mode routes through SFA. The test should exercise successful active
segment appends after setup has installed a hot spare. It should not count
setup, segment creation, rotation, or maintenance allocations as hot-path
publication allocations.

Quality checks:

```text
cargo clippy --manifest-path questdb-rs/Cargo.toml --features sync-sender-qwp-ws --lib --tests -- -D warnings
cargo fmt --manifest-path questdb-rs/Cargo.toml --check
git diff --check
```

Behavioral checks:

- real-server public `Sender` benchmark in memory mode using the protocol
  above;
- real-server public `Sender` benchmark with `sf_dir` using the protocol above;
- manual progress mode e2e;
- background progress mode e2e;
- close-drain with pending frames;
- reconnect replay after forced transport failure.

## Non-Goals

This refactor should not implement:

- `sf_durability=flush`;
- `sf_durability=append`;
- Java callback-style progress handlers;
- Java error inbox semantics;
- close-flush timeout parity;
- failover/multi-address support.

Those are separate parity gaps. This change should make them easier by
collapsing publication storage onto one engine.

## Resolved Design Decisions

1. `SfaFrameQueue` is the cursor engine. `SfaSlotQueue` is the configured sender
   wrapper. Memory mode uses `SfaSlotQueue::open_memory(...)` with `lock: None`.

2. Do not add `SfaBacking`, `SfaSegmentIdentity`, a new queue trait, or a new
   configured wrapper unless implementation proves they are necessary.

3. Prefer anonymous mmap for memory-backed segments in Rust because it reuses
   the existing mapping/raw-pointer discipline. Java uses malloc-backed memory,
   but matching that allocation primitive is less important than sharing the
   SFA cursor mechanics.

4. `sf_max_bytes` becoming memory-mode segment size is an intentional
   Java-parity behavior change. Test it and call it out in release notes.

5. Delete `VolatileFrameQueue`. Do not retain it as a shared fake.

## Remaining Questions

1. If anonymous mmap is unavailable or awkward on a supported platform, should
   memory-backed segments fall back to a heap allocation using the same
   `UnsafeCell` aliasing discipline?

2. Should memory mode expose any internal diagnostic counters for segment
   rotation/backpressure, or should diagnostics stay disk/recovery-only?
