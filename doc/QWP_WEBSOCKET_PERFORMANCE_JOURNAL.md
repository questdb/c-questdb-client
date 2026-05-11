# QWP/WebSocket Rust/Java Performance Journal

Status: current working tree closes the measured Java/Rust public Sender gap.

Goal: close the public `Sender` QWP/WebSocket throughput gap between the Rust
and Java clients using measured evidence. Quick hacks are allowed while testing
hypotheses, but the checked-in end state must not keep benchmark-only shortcuts.

## Unified SFA Cursor Real-Server Gate

The unified memory/disk SFA cursor refactor in
`QWP_WEBSOCKET_UNIFIED_SFA_CURSOR.md` was benchmarked against a local QuestDB
development server on `127.0.0.1:9000`.

Benchmark shape:

- 50,000,000 rows per run;
- 1,000 rows per flush batch;
- table `qwp_ws_unified_sfa_bench`;
- symbol column `sym` with 1,000 distinct values;
- integer column `qty`;
- floating column `px`;
- designated timestamp per row;
- three recorded runs per case, with `select count()` validation after every
  run.

| Case | Mode | Publish s median/min/max | Total s median/min/max | Publish rows/s | Total rows/s | Count validation |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| Rust BEFORE `90cb5fd7` | memory | 4.027 / 3.635 / 4.172 | 4.028 / 3.636 / 4.190 | 12,413,974.77 | 12,410,220.96 | 50,000,000 after each run |
| Rust BEFORE `90cb5fd7` | `sf_dir`, `sf_durability=memory` | 4.248 / 4.194 / 4.308 | 4.252 / 4.195 / 4.310 | 11,769,232.04 | 11,756,657.86 | 50,000,000 after each run |
| Java reference `387fe91` | memory | 5.241 / 5.189 / 5.386 | 5.298 / 5.245 / 5.440 | 9,538,639.06 | 9,435,760.33 | 50,000,000 after each run |
| Rust AFTER current worktree | memory | 3.858 / 3.733 / 4.021 | 3.863 / 3.734 / 4.023 | 12,958,373.98 | 12,940,416.07 | 50,000,000 after each run |
| Rust AFTER current worktree | `sf_dir`, `sf_durability=memory` | 4.322 / 4.022 / 4.359 | 4.323 / 4.023 / 4.361 | 11,567,711.33 | 11,565,115.98 | 50,000,000 after each run |

Verdict: acceptable. Rust AFTER memory mode was 4.2% faster than Rust BEFORE
memory mode by median publish time. Rust AFTER `sf_dir` mode was 1.7% slower than Rust
BEFORE `sf_dir` mode by median publish time.

Notes:

- Rust BEFORE was measured from a detached worktree at `90cb5fd7...` with the
  same temporary benchmark harness added.
- Rust AFTER was refreshed after fixing the rotated-segment send-cursor
  allocation path.
- Rust `sf_dir` runs used `/mnt/pcie5/qdb-rust-sfa-unified-bench` with fresh
  sender IDs per run.
- Server build reported
  `Build Information: unknown [DEVELOPMENT], JDK unknown, Commit Hash unknown`.
- `cpu0` scaling governor reported `performance` after the run, and
  `/mnt/pcie5` reported as ext4 on `/dev/nvme1n1p2`.
- CPU utilization and resident-memory high-water marks were not captured in
  this local run.

## Benchmark Shape

Rust command shape:

```bash
QWP_WS_PUBLIC_BENCH_ROWS=20000000 \
QWP_WS_PUBLIC_BENCH_BATCH_SIZE=1000 \
QWP_WS_PUBLIC_BENCH_IN_FLIGHT=128 \
QWP_WS_PUBLIC_BENCH_WORKLOAD=<base|symbol|full> \
cargo test --release --manifest-path questdb-rs/Cargo.toml \
  --features sync-sender-qwp-ws \
  qwp_ws_public_sender_batch_throughput_benchmark \
  --lib -- --ignored --nocapture --test-threads=1
```

The benchmark uses the public Rust `Sender` and `Buffer` API. It measures row
construction separately from `flush()` and `close_drain()`.

CPU profile command shape:

```bash
QWP_WS_PUBLIC_BENCH_ROWS=20000000 \
QWP_WS_PUBLIC_BENCH_BATCH_SIZE=1000 \
QWP_WS_PUBLIC_BENCH_IN_FLIGHT=128 \
QWP_WS_PUBLIC_BENCH_WORKLOAD=full \
perf record -F 999 -g -o /tmp/qwp-rust-<label>-full.perf.data -- \
  cargo test --release --manifest-path questdb-rs/Cargo.toml \
  --features sync-sender-qwp-ws \
  qwp_ws_public_sender_batch_throughput_benchmark \
  --lib -- --ignored --nocapture --test-threads=1
```

## Baseline Evidence

Earlier same-shape Rust public `Sender` measurements:

| Workload | Total ms | Build ms | Flush ms | Close ms |
| --- | ---: | ---: | ---: | ---: |
| base | 685 | 594 | 49 | 40 |
| symbol | 1173 | 1060 | 69 | 41 |
| full | 1975-2008 | 1798-1831 | 135 | 40-41 |

Earlier same-shape Java public `Sender` measurements:

| Workload | Total ms | Build ms | Flush ms | Close ms |
| --- | ---: | ---: | ---: | ---: |
| base | 694 | 553 | 1 | 137 |
| symbol | 698 | 653 | 1 | 41 |
| full | 1460 | 1199 | 1 | 258 |

Initial Rust `perf stat` for the full workload showed CPU work, not lock/off-CPU
waiting:

- elapsed: `2.066s`
- task-clock: `2.567s`
- CPUs utilized: `1.242`
- instructions: `65.3B`
- cycles: `13.48B`

Initial full-workload CPU profile highlights:

- `QwpWsTableBuffer::lookup_column`: `16.31%`
- `Vec<T>::from_iter`: `7.35%`
- `write_frame_to_buf`: `6.33%`
- `BuildHasher::hash_one`: `4.27%`
- `QwpWsColumnarBuffer::table`: `3.91%`
- `QwpWsColumnBuffer::append_symbol`: `3.72%`
- `encode_ws_replay_message`: `3.62%`

Counter experiment on 20M full rows:

- `table_calls=20000000`
- `table_current_hits=19980000`
- `table_validate_or_lookup=20000`
- `column_lookup_calls=120000000`
- all 120M column lookups were exact cursor hits
- `symbol_calls=20000000`
- `symbol_lookup_hits=19840000`
- `symbol_lookup_misses=160000`
- `symbol_lookup_clears=20000`

Interpretation: the main full-workload row-build cost is CPU instructions on the
producer thread. The top column lookup cost is paid even when the schema order is
perfectly stable.

## Experiment Log

### Exact-name Branch Before Case-Insensitive Compare

Hypothesis: an exact byte comparison before case-insensitive comparison would
avoid lowercasing for stable lowercase names.

Result: rejected. Earlier quick hack worsened full build time from roughly
`1.8s` to roughly `3.6s`.

Interpretation: the extra branch/comparison shape was worse than the existing
loop. Do not reintroduce this without assembly evidence.

### QWP/WS Symbol Fast Hasher

Hypothesis: Rust's default SipHash is too expensive for tiny QWP/WebSocket
symbol dictionaries. Java uses specialized non-cryptographic maps and cached
`String.hashCode()`.

Change tested:

- QWP/WebSocket-only `HashMap<Vec<u8>, _>` for symbol dictionaries uses a small
  deterministic byte hasher.
- Applied only to local symbol dictionaries and the connection global symbol
  dictionary.
- Does not introduce sender-shared state, so detached buffers remain
  independently fillable from different threads.

Measurements:

| Workload | Before build ms | After build ms | Notes |
| --- | ---: | ---: | --- |
| symbol | ~1060 | 996-998 | repeated |
| full | 1807-1831 | 1807-1831 | no material movement |

Verdict: keep as a small symbol-only win if review accepts the non-crypto hash
choice for this private QWP/WS map. It does not explain the main full-workload
gap.

### Lowercase-ASCII Stored Column Name

Hypothesis: `lookup_column` is hot because Rust folds both stored and incoming
column-name bytes on every row. Java stores `String` column names and often gets
an identity fast path for string literals through `Chars.equalsIgnoreCase(l, r)`
returning on `l == r`.

Change tested:

- Store `lower_ascii_name` in `QwpWsColumnBuffer`.
- Cursor fast path compares the incoming bytes against stored lowercase ASCII.
- Slow hash-map lookup remains unchanged, so the change does not remove existing
  Unicode fallback behavior for non-cursor cases.

Measurements:

| Workload | Before build ms | After build ms |
| --- | ---: | ---: |
| full | 1807-1831 | 1690 |

Fresh profile after this change:

- `lookup_column`: `11.71%`, down from `15.44%` in the immediately preceding
  profile.

Verdict: real win, but still leaves `lookup_column` as the top row-build cost.

### Packed Lowercase-ASCII Short Column Names

Hypothesis: all hot benchmark column names are short (`sym`, `qty`, `px`,
`venue`, `event_ts`). Packing lowercase ASCII names into a `u64` removes most of
the byte-by-byte comparison loop on the cursor fast path.

Change tested:

- Store `packed_lower_ascii_name` for column names of length up to 8.
- Cursor fast path compares packed lowercase ASCII for short incoming names.
- Longer names fall back to the stored lowercase byte comparison.

Measurements:

| Workload | Before build ms | After build ms |
| --- | ---: | ---: |
| full | 1690 | 1643-1664 |

Fresh profile after this change:

- `lookup_column`: `10.02%`
- `Vec<T>::from_iter`: `7.75%`
- `write_frame_to_buf`: `6.79%`
- `encode_ws_replay_message`: `5.09%`
- `table`: `5.08%`

Verdict: real win. This is still a normal implementation, not a benchmark-only
shortcut, because short column names are common in production ingestion.

### Prevalidated Public Names

Hypothesis: after skipping validation for existing names, the remaining gap might
still be dominated by the public `TryInto<TableName>` / `TryInto<ColumnName>`
validation path.

Change tested: no code change; ran the benchmark with
`QWP_WS_PUBLIC_BENCH_PREVALIDATED_NAMES=1`, which calls
`TableName::new_unchecked(...)` and `ColumnName::new_unchecked(...)` in the
benchmark.

Measurements:

| Workload | Ordinary build ms | Prevalidated build ms |
| --- | ---: | ---: |
| full | 1664 | 1675 |

Verdict: rejected as the next target. Name validation is not the remaining main
cost in the current working tree.

### Packed Current Table Name

Hypothesis: after reducing column-name cursor comparison, `table()` remained a
visible hot method. The stable single-table benchmark repeatedly compares the
same short current table name (`trades`), so the same packed short-name approach
should remove a small exact byte-compare cost.

Change tested:

- Store `packed_table_name` in `QwpWsTableBuffer`.
- Current-table fast path compares packed names for table names up to 8 bytes.
- Longer table names fall back to exact slice equality.

Measurements:

| Workload | Before build ms | After build ms |
| --- | ---: | ---: |
| full | 1643-1664 | 1619-1625 |

Verdict: real but smaller win. This keeps exact table-name semantics and only
special-cases the common short-name representation.

Current post-revert confirmation after rejecting later symbol-cache experiments:

- full total: `1797 ms`
- full build: `1625 ms`
- full flush: `129 ms`
- full close: `41 ms`

### Buffer-Persistent Local Symbol Dictionary

Hypothesis: Rust rebuilds the per-buffer local symbol dictionary after every
flush, while Java assigns sender-global symbol IDs on append. Keeping local
symbol IDs stable inside a detached Rust buffer might reduce per-batch symbol
allocation without adding cross-buffer synchronization.

Change tested:

- `clear_rows()` kept symbol `dict`, `lookup`, and `data`; only symbol cells were
  cleared.
- Encoder mapped only current cells' local IDs to connection-global IDs.

Measurements:

| Workload | Before build ms | After build ms | Flush impact |
| --- | ---: | ---: | ---: |
| full | 1643-1644 | 1651 | flush worsened to 149 ms |
| symbol | 998 | 976 | flush worsened to 85 ms |

Verdict: rejected. It moves a small amount of cost from row build to flush and
does not improve total/full workload behavior. It also complicates local
dictionary lifetime. Reverted.

### Buffer-Persistent Symbol Lookup Cache

Hypothesis: keep the per-frame local symbol dictionary semantics, but cache
symbol lookup keys across flushes. On a repeated symbol after `clear_rows()`, the
cache would avoid allocating another `Vec<u8>` key while still creating a fresh
per-frame local dictionary entry.

Change tested:

- `lookup` stored `{ local_id, epoch }`.
- `clear_rows()` advanced the epoch and cleared only per-frame cells/dict/data.
- A stale cache hit created a new per-frame local dictionary entry without
  allocating a new lookup key.

Measurements:

| Workload | Before build ms | After build ms |
| --- | ---: | ---: |
| full | 1619-1621 | 1683 |

Verdict: rejected. The extra cache metadata and branch cost outweighed avoided
key allocation in the full workload. Reverted.

### QWP/WS Row-Builder Inlining

Hypothesis: after removing much of the column-name comparison cost, the hot
QWP/WebSocket row-builder path still paid enough call overhead that LLVM was not
seeing through the small forwarding/value-append layers.

Change tested:

- Marked the hot QWP/WS row-builder methods and packed-name helpers
  `#[inline(always)]`.
- Did not change behavior or data layout.

Measurements:

| Benchmark | Before build ms | After build ms | Notes |
| --- | ---: | ---: | --- |
| internal row-build only | 1577 | 1217 | no public `Buffer` wrapper |
| public full Sender | 1625 | 1421-1423 | full public API path |

Profile after the broader row-builder inlining:

- `QwpWsColumnarBuffer::column_f64`: `8.33%`
- `Vec<T>::from_iter`: `7.45%`
- `write_frame_to_buf`: `6.81%`
- `QwpWsColumnarBuffer::column_ts`: `5.46%`
- `QwpWsColumnarBuffer::table`: `5.09%`
- `QwpWsColumnBuffer::append_symbol`: `5.01%`
- public `Buffer::column_i64`: `2.20%`
- public `Buffer::column_str`: `1.82%`

Verdict: keep. It materially improves the internal row builder, but the public
Sender benchmark still showed public `Buffer` wrapper methods, so the next
experiment had to target the actual user-facing API path.

### Public Buffer Wrapper Inlining

Hypothesis: the public `Buffer` API adds enough generic wrapper/match dispatch
around QWP/WS row building that the full public Sender benchmark still lags the
internal row-builder benchmark.

Change tested:

- Marked the hot public `Buffer` row-building wrappers `#[inline(always)]`:
  `table`, `symbol`, `column_i64`, `column_f64`, `column_str`, `column_ts`,
  `at`, and `at_now`.
- Did not change API behavior or buffer ownership.

Measurements:

| Workload | Earlier total ms | Earlier build ms | After total ms | After build ms |
| --- | ---: | ---: | ---: | ---: |
| base | 685 | 594 | 614 | 524 |
| symbol | 1173 | 1060 | 967 | 862 |
| full | 1596-1597 | 1421-1423 | 1558 | 1386 |

Perf-recorded full run after wrapper inlining:

- total: `1534 ms`
- build: `1362 ms`
- flush: `130 ms`
- close: `41 ms`

Top profile rows after wrapper inlining:

- `QwpWsColumnarBuffer::column_f64`: `8.84%`
- `Vec<T>::from_iter`: `8.16%`
- `write_frame_to_buf`: `7.57%`
- `QwpWsColumnBuffer::append_symbol`: `5.50%`
- `QwpWsColumnarBuffer::column_ts`: `5.30%`
- `QwpWsColumnarBuffer::table`: `5.23%`
- `QwpWsColumnarBuffer::column_i64`: `4.75%`

Verdict: keep. This improves the actual public API path and removes the public
`Buffer::column_*` wrappers from the hot profile. It is an optimizer hint on
tiny forwarding functions, not a benchmark-specific shortcut.

### Arena-Backed Local Symbol Lookup

Hypothesis: `append_symbol` still allocates a `Vec<u8>` key for every new local
symbol in each frame, even though the same bytes are already stored in the local
symbol data arena. The local lookup can key by the symbol byte hash and compare
against the arena bytes on collision.

Change tested:

- Replaced the per-column local symbol `HashMap<Vec<u8>, u32>` with a private
  `HashMap<u64, bucket>`.
- The bucket stores local symbol IDs and resolves hash collisions by comparing
  the candidate bytes against the existing dictionary/data arena.
- No sender-shared state was added; detached buffers remain independently
  fillable.

Measurements:

| Workload | Before total ms | Before build ms | After total ms | After build ms |
| --- | ---: | ---: | ---: | ---: |
| symbol | 967 | 862 | 922 | 807 |
| full | 1558 | 1386 | 1525 | 1346 |

Perf-recorded full run after arena-backed lookup:

- total: `1510 ms`
- build: `1329 ms`
- flush: `140 ms`
- close: `40 ms`

Profile shift:

- `Vec<T>::from_iter` remained visible overall at `7.72%`, but its
  `append_symbol` child fell from `4.73%` to `2.26%`.
- `append_symbol` self moved from `5.50%` to `4.86%`.

Verdict: keep. This removes duplicated local-symbol key storage and improves
both the full and symbol-only public workloads. A collision test covers the
non-unique-hash path.

### Lazy Current-Row Rollback

Hypothesis: the remaining `Vec<T>::from_iter` cost is the per-row rollback mark,
not symbol-key storage. `QwpWsTableBuffer::rollback_mark()` cloned a rollback
mark for every column at every `table()` call, even though almost every row
commits successfully.

Change tested:

- The hot path now records only the table-level row start state.
- On error, rollback scans the existing columns and removes only cells written
  for the in-progress row.
- Symbol cells record whether they created a new local dictionary entry, so
  rollback can remove that entry without keeping a per-row dictionary snapshot.
- Added a regression test that rolls back a newly interned symbol and verifies
  it does not appear in the encoded symbol dictionary.

Measurements:

| Workload | Before total ms | Before build ms | After total ms | After build ms |
| --- | ---: | ---: | ---: | ---: |
| base | 614 | 524 | 465 | 370 |
| symbol | 922 | 807 | 744 | 636 |
| full | 1525 | 1346 | 1246 | 1075 |

Clean perf-recorded full runs after lazy rollback:

- best observed: total `1246 ms`, build `1075 ms`, flush `128 ms`, close `41 ms`
- profiled run: total `1292 ms`, build `1119 ms`, flush `131 ms`, close `40 ms`

Profile shift:

- `Vec<T>::from_iter` no longer appears above `0.5%`.
- Top remaining profile rows are `write_frame_to_buf`, QWP/WS column append
  methods, and benchmark value-generation helpers.

Verdict: keep. This is the largest win in the series and removes work that was
only needed on rare rollback paths. The full public Rust benchmark is now faster
than the earlier same-shape Java full benchmark (`1246-1292 ms` vs `1460 ms`),
with row-build also faster (`1075-1119 ms` vs `1199 ms`).

### 8-Byte WebSocket Masking

Hypothesis: `write_frame_to_buf` is the top clean-profile symbol after lazy
rollback, so replacing the scalar byte mask loop with an unaligned 8-byte XOR
loop might reduce flush time.

Change tested:

- Copied the payload as before, then applied the four-byte WebSocket mask eight
  bytes at a time with unaligned `u64` loads/stores.

Measurements:

| Workload | Before total ms | Before build ms | Before flush ms | After total ms | After build ms | After flush ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| full | 1246-1292 | 1075-1119 | 128-131 | 1407-1416 | 1238-1241 | 128-131 |

Verdict: rejected and reverted. It did not reduce flush time and made the full
benchmark slower, likely through worse code layout or optimization side effects.

### Tiny Local Symbol Linear Scan

Hypothesis: `QwpWsLocalSymbolLookup::get` remains visible in the clean profile,
and the benchmark's per-frame local symbol dictionaries are tiny. A linear scan
for dictionaries up to 16 entries might beat hashing for repeated symbols.

Change tested:

- For local symbol dictionaries with at most 16 entries, scan the dictionary
  arena and compare bytes directly before falling back to the hash lookup.

Measurements:

| Workload | Before total ms | Before build ms | After total ms | After build ms |
| --- | ---: | ---: | ---: | ---: |
| full | 1254 | 1081 | 1342 | 1165 |

Verdict: rejected and reverted. The extra branch/scan shape is slower in the
full public workload. This matches the earlier pre-lazy-rollback result where a
small linear symbol scan did not hold up for the full benchmark.

### Final Hot QWP/WS Method Inlining

Hypothesis: after lazy rollback removed the large per-row snapshot cost, the
remaining symbol-only producer cost was mostly small QWP/WS forwarding methods
that LLVM still did not consistently inline through the public `Buffer` path.

Change tested:

- Marked the hot QWP/WS methods `#[inline(always)]`: row start, scalar column
  append, symbol append, timestamp append, row commit, and the internal
  append/resolve helpers.
- Did not change storage layout, validation rules, or sender/buffer ownership.

Measurements with the explicit-flush `batch_size=999` control shape:

| Workload | Rows | Before total ms | Before build ms | After total ms | After build ms | After flush ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| base | 20M | not rerun immediately before | not rerun immediately before | 391 | 299 | 49 |
| symbol | 20M | 750-751 | 644-645 | 598-650 | 493-545 | 62-63 |
| full | 20M | 1239 | 1066 | 982 | 811 | 129 |
| symbol | 500M | 17334 | 16119 | 13640 | 12450 | 1126 |

Verdict: keep. This is still a normal optimizer hint on tiny hot methods, not a
benchmark-only shortcut. It also fixes the last measured long-run symbol gap:
the 500M symbol run now reaches `36.7M rows/sec`, ahead of the comparable Java
direct run at `33.1M rows/sec`.

## Current Java/Rust Comparison

Java source facts from
`java-questdb-client/core/src/test/java/io/questdb/client/test/cutlass/qwp/client/QwpWebSocketBatchThroughputBenchmark.java`:

- The benchmark uses the public Java `Sender` API and an in-process WebSocket
  ACK server.
- It times `appendBatch(...)` separately from `sender.flush()`.
- The symbol workload is the same shape as the Rust public benchmark:
  `table("trades")`, `symbol("sym", SYMBOLS[rowIndex & 7])`,
  `longColumn("qty", seq)`, `at(seq, NANOS)`.

Java source facts from
`java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/QwpWebSocketSender.java`:

- `flush()` delegates to `flushAndGetSequence()`.
- `flushAndGetSequence()` calls `flushPendingRows()`, seals the active buffer,
  and appends the sealed buffer into the cursor engine.
- It does not wait for server ACKs in the flush path; ACKs are handled by the
  cursor WebSocket I/O loop and close-time drain waits separately.
- When the Java sender hits the SF memory cap, backpressure wait can be charged
  to row-build time because `sendRow()` may call `flushPendingRows()` through
  auto-flush.

Rust source facts from `questdb-rs/src/tests/qwp_ws.rs` and
`questdb-rs/src/ingress/sender/qwp_ws.rs`:

- The Rust benchmark also uses public `Sender`, public `Buffer`, and an
  in-process loopback WebSocket ACK server.
- `Sender::flush(&mut buffer)` calls the QWP/WS encoder and publishes into the
  local replay queue; the background runner advances WebSocket I/O.
- Therefore the old explanation "Rust waits for ACK after every batch while
  Java does not" is wrong for the current code.

Current 20M symbol measurements:

| Client | Total ms | Build ms | Flush ms | Close ms |
| --- | ---: | ---: | ---: | ---: |
| Java, Maven exec | 678 | 633 | 1 | 42 |
| Java, direct `java` | 768 | 631 | 1 | 134 |
| Rust | 747 | 643 | 61 | 42 |

Important correction: the Java `batch_size=1000` bucket split is distorted by
the Java WebSocket default `auto_flush_rows=1000`. With a 1000-row benchmark
batch, the real publication happens inside the timed `appendBatch(...)` loop on
the final `.at(...)`, and the following timed `sender.flush()` is usually empty.
The total still matters, but the `flush_ms=1` bucket is not comparable to Rust's
explicit `sender.flush(&mut buffer)` bucket.

The control experiment is `batch_size=999`, which prevents the Java default
auto-flush threshold from firing inside `appendBatch(...)`:

| Workload | Client | Total ms | Build ms | Flush ms | Close ms |
| --- | --- | ---: | ---: | ---: | ---: |
| symbol | Java | 727-734 | 549-554 | 134-135 | 41-42 |
| symbol | Rust | 598-650 | 493-545 | 62-63 | 40-41 |
| full | Java | 1668 | 748 | 644 | 273 |
| full | Rust | 982 | 811 | 129 | 41 |

Interpretation: Java's near-zero flush bucket at batch size 1000 is mostly an
auto-flush artifact. On an explicit-flush shape, Java spends visible time in
`flush()`, and Rust's flush bucket is faster. In the current working tree, Rust
is faster overall for the measured symbol-only and full public Sender workloads.
The Java full run also logged SF memory-cap backpressure, which explains the
large close bucket and reinforces that bucket-level comparisons are
workload-sensitive.

Current long symbol measurements:

| Client | Rows | Total ms | Build ms | Flush ms | Close ms | Rows/sec |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Java, JFR direct | 500M | 15090 | 15017 | 11 | 42 | 33.1M |
| Rust, before final hot inlining | 500M | 17334 | 16119 | 1152 | 42 | 28.8M |
| Rust, after final hot inlining | 500M | 13640 | 12450 | 1126 | 41 | 36.7M |
| Rust, after final hot inlining | 200M | 5479 | 4973 | 455 | 41 | 36.5M |

Java JFR evidence for the 500M symbol run:

- Duration: `15.2s`, CPU samples: `1504`.
- Threads: `main` `1192` samples (`79.3%`),
  `WebSocket-Client-*` test-server ACK thread `307` samples (`20.4%`),
  Java sender `qdb-cursor-ws-io` `3` samples (`0.2%`).
- Top Java self-time: benchmark `appendBatch` `53.0%`, test-server
  `AckEveryFrameHandler.onBinaryMessage` `18.7%`, `QwpWebSocketSender.sendRow`
  `9.6%`, `StringLatin1.hashCode` `6.2%`,
  `QwpWebSocketSender.checkConnectionError` `5.1%`.

Rust perf evidence for the 200M symbol run:

- Top self-time rows include `QwpWsColumnarBuffer::symbol` `8.98%`,
  `column_i64` `7.50%`, `write_frame_to_buf` `7.36%`,
  `append_designated_ts` `7.06%`, `append_symbol` `6.89%`, `table` `6.73%`,
  `QwpWsLocalSymbolLookup::get` `5.68%`, test-server `read_frame` `4.29%`,
  and `encode_ws_replay_message` `3.31%`.

Interpretation:

1. Rust build time is now faster than the measured Java direct run on the
   longer symbol run.
2. Java's near-zero flush bucket at `batch_size=1000` is not evidence that Java
   publication is free; it is primarily a bucket-placement artifact caused by
   default auto-flush firing inside row build.
3. Java's JFR says its sender I/O thread is not doing large CPU work in this
   benchmark. Most CPU is still in the benchmark producer thread and the
   in-process test server.
4. The Rust flush bucket mostly represents local QWP/WS encode/publication work.
   It is not an ACK wait, and it is not enough to explain a separate lock/off-CPU
   problem without more evidence.
5. The measured public Sender gap is closed in the current working tree. Further
   performance work should start from a fresh profile and a specific workload,
   not from the old Java/Rust headline.

## Current Validation Checkpoint

Current working state keeps:

- QWP/WS symbol fast hasher.
- Stored lowercase ASCII column names.
- Packed short column-name compare for the cursor fast path.
- Packed short current-table-name compare.
- QWP/WS row-builder inlining.
- Public `Buffer` wrapper inlining for hot row-building calls.
- Arena-backed local symbol lookup.
- Lazy current-row rollback.
- Final hot QWP/WS method inlining.

Compatibility note: the existing-name skip-validation fast path requires row and
column name inputs to expose their raw string bytes before validation. The
public `Buffer` name methods now require `AsRef<str>` in addition to
`TryInto<TableName>` / `TryInto<ColumnName>`. This does not affect normal
`&str`, `String`, `TableName`, or `ColumnName` use, but it is a public generic
bound change for custom name wrapper types.

Current working state rejected and reverted:

- exact-name branch before case-insensitive compare;
- buffer-persistent local symbol dictionary;
- buffer-persistent symbol lookup cache.

Validation commands passed after the retained changes:

```bash
cargo fmt --manifest-path questdb-rs/Cargo.toml --check
cargo test --manifest-path questdb-rs/Cargo.toml --lib
cargo test --manifest-path questdb-rs/Cargo.toml --features sync-sender-qwp-ws qwp_ws --lib
cargo clippy --manifest-path questdb-rs/Cargo.toml --features sync-sender-qwp-ws --lib --tests -- -D warnings
git diff --check
```

Final benchmark commands passed after the retained changes:

```bash
QWP_WS_PUBLIC_BENCH_ROWS=20000000 QWP_WS_PUBLIC_BENCH_BATCH_SIZE=999 QWP_WS_PUBLIC_BENCH_IN_FLIGHT=128 QWP_WS_PUBLIC_BENCH_WORKLOAD=base cargo test --release --manifest-path questdb-rs/Cargo.toml --features sync-sender-qwp-ws qwp_ws_public_sender_batch_throughput_benchmark --lib -- --ignored --nocapture --test-threads=1
QWP_WS_PUBLIC_BENCH_ROWS=20000000 QWP_WS_PUBLIC_BENCH_BATCH_SIZE=999 QWP_WS_PUBLIC_BENCH_IN_FLIGHT=128 QWP_WS_PUBLIC_BENCH_WORKLOAD=symbol cargo test --release --manifest-path questdb-rs/Cargo.toml --features sync-sender-qwp-ws qwp_ws_public_sender_batch_throughput_benchmark --lib -- --ignored --nocapture --test-threads=1
QWP_WS_PUBLIC_BENCH_ROWS=20000000 QWP_WS_PUBLIC_BENCH_BATCH_SIZE=999 QWP_WS_PUBLIC_BENCH_IN_FLIGHT=128 QWP_WS_PUBLIC_BENCH_WORKLOAD=full cargo test --release --manifest-path questdb-rs/Cargo.toml --features sync-sender-qwp-ws qwp_ws_public_sender_batch_throughput_benchmark --lib -- --ignored --nocapture --test-threads=1
QWP_WS_PUBLIC_BENCH_ROWS=500000000 QWP_WS_PUBLIC_BENCH_BATCH_SIZE=999 QWP_WS_PUBLIC_BENCH_IN_FLIGHT=128 QWP_WS_PUBLIC_BENCH_WORKLOAD=symbol cargo test --release --manifest-path questdb-rs/Cargo.toml --features sync-sender-qwp-ws qwp_ws_public_sender_batch_throughput_benchmark --lib -- --ignored --nocapture --test-threads=1
```

Latest current-tree validation:

```bash
cargo fmt --manifest-path questdb-rs/Cargo.toml --check
cargo test --manifest-path questdb-rs/Cargo.toml --features sync-sender-qwp-ws qwp_ws --lib
cargo clippy --manifest-path questdb-rs/Cargo.toml --features sync-sender-qwp-ws --lib --tests -- -D warnings
git diff --check
```
