# Pool commit batching

**Decision:** batch ready network writes by default and provide an opt-in,
automatic commit window for QWP/WebSocket ingestion through `QuestDb`.
Reuse `wait` and `flush_and_wait` for explicit completion. Keep the current
SF format and one successful SF publication per flush.

This document describes the implementation, its compatibility constraints,
and the performance evidence used to choose it. The fixed-schema
record-first experiment is evidence for a separate format design (§7.3);
it is not part of the library implementation.

## 1. Problem and scope

A Stream consumer often borrows a sender, flushes one message and returns
it. Repeating this pattern used to require one socket write and one server
commit per small QWP frame. Batching already-published frames across leases
on the same pool slot shares these costs without changing the caller.

```text
application flush → SF publication → background transport → server
                       original       bounded writes and     commit at
                       QWP frames     commit windows         window end
```

A successful flush means the client owns replayable data in SF. Disk SF
supports process-restart replay; power-loss durability depends on
`sf_durability`. Memory SF does not survive process death. Unflushed Buffer
rows remain the application's responsibility. Returning a lease is not an
implicit flush.

Network batching applies to the background QWP transport, including the
standalone sender. Commit windows apply only to pooled SF ingestion.
Direct, non-SF column transactions and manual recovery drainers retain
their existing send behavior. Rust, C and C++ share the implementation.

## 2. Decisions and reasons

| Decision | Reason |
|---|---|
| Batch complete ready WebSocket messages into writes of up to 64 KiB | Independent experiments show fewer writes help; no extra waiting timer is needed |
| Allow automatic commit windows across leases on one slot | Commit batching adds benefit beyond network batching and supports unchanged callers |
| Leave commit windows off unless configured | Delayed server visibility is a behavior change; throughput results do not establish a suitable default latency |
| Use the existing `commit_interval_ms` and optional `commit_rows` settings | One time setting is enough to opt in; a row limit remains useful for high-rate workloads without adding another alias |
| Reuse `wait` / `*_and_wait` | These already express “finish my published work now and wait for its ACK”; another `commit()` would duplicate the operation |
| Modify defer flags only in the wire copy | Restart can replay the original SF frames without reconstructing a lost commit window |
| Keep one SF record and one wire sequence per frame | Preserves recovery format, dictionary handling, rejection attribution and cumulative ACK mapping |
| Retain measured, general hot-path improvements | Reduces per-call overhead without changing acceptance, durability or wire format |
| Exclude the fixed-schema record-first prototype | It needs a general format, compatibility policy and complete ACK/rejection mapping before it can ship |

This is automatic mode. The server may commit earlier windows before an
explicit wait. There is no manual mode that prevents commits until a caller
command, and a window is not a transaction across tables or pool slots.

## 3. Configuration and API

| Pool key | Default | Meaning |
|---|---|---|
| `commit_interval_ms` | unset | Positive milliseconds from the first staged frame until the window is eligible to close |
| `commit_rows` | unset | Positive row threshold that also closes a window; alone selects a 100 ms interval |

For example, `ws::addr=localhost:9000;commit_interval_ms=10;` enables
automatic windows without requiring a row-count choice. A high-rate caller
can additionally use `commit_rows=1000`. Neither key changes foreground
Buffer flushing. Omit both to keep the existing per-frame commit boundaries.
Standalone senders reject these pool-only keys. The pool removes them before
passing the remaining, correctly escaped configuration to ingress and egress.

An interval is a staging policy, not an end-to-end deadline. It starts when
the I/O thread collects the first frame. Scheduling, backlog, network transfer,
server processing and WAL apply add time. Byte and row limits can close a
window earlier.

| Operation | Guarantee with automatic batching |
|---|---|
| `flush_buffer`, `flush_chunk`, `flush_arrow_batch_*`, keep/get-FSN variants | Successful publication to SF, as before |
| `wait(level, timeout)` | Request closure through this lease's pending publication boundary, then wait for the chosen ACK |
| Rust `flush_buffer_and_wait` / C++ `flush_and_wait` / C `qwp_sender_flush_buffer_and_wait` | Publish the Buffer, request closure, then wait |
| Return/drop a lease | Neither publish unflushed rows nor close the background window |
| Close with a drain budget | Request closure through published data, bounded by the existing close timeout |

Use the **publishing lease before returning it**. A fresh empty lease's wait
is a no-op for earlier borrowers; it is not a pool-wide drain. Earlier frames
on the same slot may be covered by the cumulative ACK, but different slots
are independent. OK ACK is not SQL visibility. Durable ACK still requires
`request_durable_ack=on` and a supporting server. Wait retains its existing
no-progress timeout; timeout does not withdraw accepted data.

For example, after A+B commit automatically and C enters the next window,
`wait` on C's publishing lease closes that tail and confirms progress. It
does not undo the earlier commit or turn A+B+C into one transaction.

### Relationship to auto-flush

Foreground batching accumulates application rows **before** SF acceptance.
It can reduce encoding calls, SF records and QWP frames. Network and commit
batching share work **after** SF acceptance and retain every publication.
This client currently accepts only `auto_flush=off`; the other `auto_flush*`
settings remain rejected. No foreground auto-flush parameters are added or
repurposed by this change.

## 4. Transport implementation

### Network batching

Each background drive step reads a bounded burst of ready SF frames. The
transport masks each as its own complete WebSocket message, then writes
whole messages together in chunks of at most 64 KiB. A larger individual
message is written whole. Once the ready queue is empty or the burst reaches
its budget, the thread checks the window, polls responses and performs SF
maintenance.

With commit windows disabled, the burst is written immediately; no timer
waits for additional data. The first message still waits for assembly of the
bounded burst, so this does not claim zero latency impact under every load.
No columns are decoded or re-encoded. FSNs, wire sequences and cumulative
ACK mapping remain one-to-one for data frames.

### Commit windows

The transport retains a bounded window of masked messages. Appending a new
frame adds `FLAG_DEFER_COMMIT` to the preceding frame's **wire copy**. The
newest frame keeps its original flags. Closing the window writes its complete
messages; an ordinary final frame commits the pending server rows.

An existing deferred tail is never converted to a committing frame. The
memory-mode split path may already store deferred frames; its final split
frame is still required to finish that group. Disk SF continues to store
ordinary, replayable frame flags.

A window closes when:

1. The first staged frame's interval expires.
2. The configured row threshold is reached.
3. The next message would exceed the staging byte cap.
4. A wait's pending publication boundary has been collected.
5. Close requests draining through the final publication.

The byte cap is the minimum of `max_buf_size`, the advertised server batch
cap and the SF segment payload capacity. Whole messages are never split by
this layer; a whole message larger than the staging target is sent alone.
Existing per-frame limits and rejection handling still apply. Network chunks
and commit windows are separate limits. Storage is
reused, with additional per-message metadata proportional to the bounded
window.

Row thresholds read only the dictionary-length fields and row count of a
single-table delta frame. Other layouts close conservatively rather than
walking column data or treating one frame as one row. Deadline checks run
on idle drive steps too, so a short tail needs no later flush.

### Wait, close and recovery

A wait atomically publishes the highest requested FSN boundary before ACK
polling. The I/O thread closes once that boundary is included. Once sent
with a committing tail, the request does not force later windows to close.
Reconnect clears staged copies and the satisfied-boundary state, then replays
from the ACK watermark in FSN order. Original SF bytes remain authoritative.

| Event | Required behavior |
|---|---|
| Partial/failed socket write | Retain SF data; discard staging on reconnect and replay unacked frames |
| Retriable rejection or disconnect | Existing policy reconnects; the whole uncommitted suffix can replay |
| Terminal rejection | Existing terminal handling applies; no new skip-and-continue policy |
| Disk restart | Replay original flags, including when commit windows are disabled after restart |
| Server commits early at its uncommitted-row limit | Existing cumulative/deferred ACK handling remains valid |
| Close with zero/expired drain budget | Stop within the existing policy; disk data remains available for recovery |

An ambiguous disconnect after a server commit can cause replay. Delivery
remains at least once, not exactly once. SF data is retired only by the
existing requested ACK policy, never by staging or a successful write alone.

## 5. General hot-path changes

These optimizations apply to ordinary QWP buffers and pooled SF senders:

- An atomic empty-error hint avoids the publication-store mutex when both
  diagnostic cursors are drained. New errors publish the hint; nonempty and
  poisoned stores keep the locked path.
- An active-segment append performs the existing validation, CRC, copy and
  publication before creating a timeout deadline. Rotation and backpressure
  retain the slow path and its deadline; durability checks are unchanged.
- Fixed-size SF pools omit idle timestamps because they cannot reap below
  their fixed warm floor. Growable pools and direct senders retain reaping.
- Cleared single-table Buffers reuse their validated table name while
  resetting row state. Changed names still take the normal validation path.
- A one-symbol dictionary uses a direct comparison and creates its hash index
  only on the second distinct symbol. Dictionary IDs, collision handling,
  rollback, clone and clear behavior are preserved.

Bulk-discarding lease diagnostics and changing CRC calculation were also
measured. Their timing differences were inconsistent or regressed other
paths, so neither experiment is retained. No durability barrier was relaxed.

## 6. Validation

The regression suite covers network message preservation, row and byte caps,
idle expiry, stored defer flags, one-shot wait boundaries, partial writes
and reconnect reset. Pool tests cover windows spanning leases, explicit
short-tail closure, idle/close progress, disconnect/rejection replay, and
disk restart with original flags. Memory and disk tests also wait for a
cumulative durable ACK through an entire window.

Configuration tests cover defaults, invalid/overflowing values, rows-only
fallback, escaped values and standalone rejection. Buffer tests cover name
validation after clear and singleton-symbol promotion, rollback and clone.
Existing backpressure, lease-boundary, dictionary recovery and reaping tests
remain applicable. C++17/C++20 tests exercise configuration and wait through
the C ABI. No exported function or ABI layout changes.

Final validation results and the real-server restart check are recorded in
§7.4. Power-loss, WAN/TLS performance and low-rate p99 latency are not claimed
by the local throughput measurements.

## 7. Performance evidence

Measurements were taken on the same arm64 Mac as the existing
`127.0.0.1:9000` server, with proxies bypassed. Unless stated otherwise, each
case has five shuffled repetitions, 1M timed rows after 10k warmup, one pool
slot, 1,000 symbols, and SYMBOL/LONG/DOUBLE/TIMESTAMP_NS columns in a WAL table.
The final OK ACK on the last publishing lease is inside timing; SQL checks
are outside it. Disk SF uses 4 MiB segments and OS page cache durability,
not fsync per row. Client CPU includes background threads, not server CPU.

[Curated evidence](net_bench/pool_batching_evidence.json) retains measurements,
source/binary hashes, server build responses and validation summaries.
Raw logs, sample dumps, temporary SF directories and benchmark tables are
cleanup artifacts. Results from different campaigns must not be combined
into precise speedup claims.

### 7.1 Why both kinds of batching

The original controlled experiment held staging constant at up to 1,000
frames, with a 10 ms tail timer, and changed network/commit toggles separately:

| Controlled arm | Memory SF median ms | Disk SF median ms |
|---|---:|---:|
| Neither toggle | 3,316.392 | 4,116.508 |
| Network only | 1,945.023 | 2,702.791 |
| Commit only | 2,851.847 | 3,748.510 |
| Both | 1,203.572 | 1,833.082 |

Network batching saved 41.4% / 34.3%; commit batching alone saved
14.0% / 8.9%. Adding commits to network batching saved another 38.1% / 32.2%.
Every memory run still sent 1,010,000 frames including warmup. Network
batching reduced application writes to 2,020; commit batching reduced WAL
commits to 1,010. Writes are not TCP packet or syscall counts.

This experiment retained per-frame receive polling. The final implementation
also amortizes background-loop work across bounded bursts, so these numbers
isolate the toggles rather than describe the final implementation.

### 7.2 Compatible frame-path measurements

An earlier implementation campaign, before the hot-path follow-up, measured:

| Path | Memory SF median ms (range) | Disk SF median ms (range) |
|---|---:|---:|
| Network only | 1,685.253 (1,599–1,742) | 2,506.304 (2,411–2,991) |
| Network + commit window | 470.088 (452–513) | 1,229.961 (1,172–1,276) |
| Pool, explicit 1,000-row flush | 64.950 (63–95) | 326.759 (299–842) |
| Standalone, explicit 1,000-row flush | 62.791 (55–81) | 293.382 (275–302) |

The network/window rows are paired; the standalone references came from a
separate campaign. A separate paired default comparison found network
batching reduced one-row elapsed time by 46.5% / 44.3% versus the original
send loop. Explicit 1,000-row flushes showed no reliable large gain from
network batching alone. The final source is remeasured in §7.4.

### 7.3 Record-first exploration: a separate format decision

The experiment published an owned compact record for each one-row flush,
then assembled up to 1,000 records into one QWP frame in the background.
It retained real SF append, CRC, rotation, backpressure and per-row borrowing.
Memory runs had 1,010,000 SF publications but only 1,010 physical frames.

Its record supported only `sym/qty/px/designated-ns`. It was not compatible
with Java replay and did not generalize durable ACK or rejection ranges.
The prototype and experimental environment switches are removed from the
library; its results must not be reported as the compatible path's speed.

After the first four hot-path changes, fixed-pool memory improved from
318.575 to 163.699 ms in a paired campaign. The subsequent singleton-symbol
experiment remeasured both controls:

| Prototype/control path | Before median ms (range) | After median ms (range) |
|---|---:|---:|
| Fixed memory pool, one-row flush | 163.343 (146–194) | 152.524 (143–187) |
| Held memory lease, one-row flush | 123.924 (122–139) | 113.880 (111–130) |
| Growable memory pool, one-row flush | 198.282 (170–218) | 192.759 (167–207) |
| Disk pool, one-row flush | 744.108 (660–746) | 672.417 (634–715) |
| Standalone, explicit 1,000-row flush, memory | 56.520 (56–62) | 54.148 (54–66) |
| Standalone, explicit 1,000-row flush, disk | 247.084 (244–287) | 247.977 (244–256) |

The final small change saved 6.6% elapsed / 5.1% client CPU in fixed memory
and 9.6% / 5.5% on disk, with overlapping elapsed ranges. Even this restricted
prototype remained **2.82× / 2.71×** slower than its fresh standalone controls.
It recovered 10,003 records after SIGKILL with all-column SQL verification;
that checks process restart, not power loss.

Fresh main-thread wall-stack samples after optimization attributed 32.4%
to borrowing, 29.2% to flush, 18.0% to recognizable Buffer filling and 5.6%
to return; 14.7% was other/unwound work. Nested samples included lease
rebasing (15.3%) and SF append (12.0%). These overlapping stack observations
are not isolated CPU costs or promised speedups. The held-lease comparison
also changes scheduling, so it is not a per-borrow microbenchmark.

A future general record-first design needs owned schema/type/symbol data,
versioned replay compatibility, publication-range ACK/rejection semantics,
splitting, durable ACK and restart coverage. The evidence supports exploring
that direction; silently changing the SF format is not justified here.

### 7.4 Final compatible implementation

The final release binary was measured in five shuffled rounds per mode,
with `commit_rows=1000;commit_interval_ms=10` for window cases. The ordinary
library build contains no experimental environment switches. All 50 trials
verified every column per symbol and WAL progress; their unique tables and
SF directories were removed.

| Final path | Memory SF median ms (range) | Disk SF median ms (range) |
|---|---:|---:|
| Network only, one-row flush | 1,958.935 (1,942–1,995) | 2,592.371 (2,494–2,766) |
| **Network + commit, one-row flush** | **519.421 (514–596)** | **1,143.334 (1,017–1,277)** |
| Pool, explicit 1,000-row flush, network only | 63.310 (62–66) | 270.809 (251–338) |
| Pool, explicit 1,000-row flush, network + commit | 62.665 (62–76) | 267.968 (238–331) |
| Standalone, explicit 1,000-row flush | 54.979 (53–59) | 263.341 (248–318) |

In these paired runs, adding the commit window saves **73.5% memory /
55.9% disk elapsed time**, and **23.4% / 59.3% client CPU**, relative to
network batching alone. Including warmup, one-row paths still publish and
send 1,010,000 frames; WAL commits fall from 1,010,000 to 1,010 in memory and
1,014–1,017 on disk.

**One-row streaming has not reached standalone explicit-batch performance:**
it takes about **9.45× / 4.34×** as long in this compatible implementation.
Explicit 1,000-row pool flushes are close to the standalone reference,
particularly on disk; the memory pool's existing 10 ms wait polling matters
at this scale. These are workload-specific observations, not equivalence
claims. The 152.524 ms prototype result in §7.3 uses a different SF payload
and is not the result of this implementation.

The memory window path's median publication phase is 171.621 ms; median
end-to-ACK time is 519.421 ms. Foreground/background work overlaps, so these
figures do not isolate server or transport cost, but the remaining tail is
consistent with continuing to process one million individual frames. A
record-first format would address that work and requires the separate design
listed in §7.3.

Validation on the final source: **2,264 Rust tests passed, 24 ignored**;
core and FFI Clippy checks passed with warnings denied; C++17/C++20
column-sender suites and format checks passed. A separate process published
10,003 rows into disk SF while offline, was killed with SIGKILL, and recovered
all rows after restart against the existing server. All 1,000 symbol groups
matched every column; WAL reached 11 committed transactions. This replay
still used individual QWP frames, not the record-first prototype.

The measured binary SHA-256 is
`00b5e61476d8db1bcadfb1f4b371625369be25c94c43053668f9ccdb91385567`;
source hashes and validation details are under `final_implementation` in the
[evidence file](net_bench/pool_batching_evidence.json).

## 8. Reproduction and ownership

```sh
cargo build --manifest-path questdb-rs/Cargo.toml --release --locked \
  --example qwp_pool_bench --no-default-features \
  --features sync-sender-qwp-ws,ring-crypto,tls-webpki-certs
python3 doc/net_bench/run_pool_baseline.py \
  --binary questdb-rs/target/release/examples/qwp_pool_bench \
  --output /tmp/pool-memory-results --sf-mode memory
python3 doc/net_bench/run_pool_baseline.py \
  --binary questdb-rs/target/release/examples/qwp_pool_bench \
  --output /tmp/pool-disk-results --sf-mode disk
python3 doc/net_bench/run_pool_recovery.py \
  --binary questdb-rs/target/release/examples/qwp_pool_bench \
  --output /tmp/pool-recovery-results
```

Use fresh output paths. The runners create unique tables, validate all
columns per symbol and WAL progress, then remove their tables and temporary
SF directories. They leave the existing server and its configuration running.
The restart probe kills only its own offline publisher process.

Implementation ownership: `qwp_ws_batch.rs` owns wire staging and limits;
`qwp_ws_driver.rs` owns transport writes/reconnect reset; `qwp_ws.rs` owns
bounded background progress and wait/close requests. `db/conf.rs` parses
pool policy, and `column_sender/sender.rs` requests closure before waiting.
