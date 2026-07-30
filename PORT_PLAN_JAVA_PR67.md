# Porting java-questdb-client PR #67 to c-questdb-client

Working notes + plan. Single PR, delivered as a sequence of milestones.
Implementing agents deliver each milestone as uncommitted working-tree
changes — **never run `git commit`/`git push`**; the user reviews and
commits each milestone manually. Milestone 1 is implemented and committed
(`41124441`).

## Context

Java PR: https://github.com/questdb/java-questdb-client/pull/67
(`fix(qwp): keep SF slot locked until manager worker quiesces`, merged as
`5bbdfb86`, ~7.5k inserted lines of main code across 47 files).

Root cause fixed in Java: `SegmentManager.deregister(ring)` removed a ring
from the live registry, but an I/O/manager worker could already hold a
snapshot of the entry and be inside `serviceRing()`. Close then unmapped the
ring/watermark, unlinked segment files, and released the slot flock while
that in-flight pass was still running. A replacement engine could acquire
the same slot directory and race the stale worker → slot corruption, data
loss after restart, mmap/SIGBUS failures.

The Java PR bundles, on top of the core race fix:

1. worker-quiescence barrier (atomic registered/in-service claim, bounded
   quiescence wait, exactly-once CAS terminal cleanup, cleanup handoff to
   worker exit on timed-out close);
2. confirmed slot release (`SlotLock.release()` reports success; slot
   returns to pool capacity only after confirmed unlock; retired-slot
   retention + shared flock-release retry driver with backoff);
3. crash-safe close-time segment cleanup (persist final acked FSN through
   the still-mapped watermark → enumerate fully → delete acked segments in
   generation order, stop on first failure → remove watermark last) plus a
   new `SfManifest` (two fixed-size CRC32C-protected records at offsets 0
   and 4096, alternating on update, survives a single sector tear);
4. `sf_durability=periodic` + `sf_sync_interval_millis` (default 5000 ms):
   background msync checkpointing of published segment data, fd barriers,
   rotation gated on predecessor-segment durability — bounded-loss
   protection against host power loss;
5. bounded transport shutdown: socket/WS layers expose traffic shutdown
   separately from final close, so close can break a worker blocked in
   native send/recv, join it, then close resources;
6. serialized `QuestDB.close()` (second closer blocks until teardown done);
7. `ObjList.remove(from, to)` stale-tail fix; recovery segment sort
   hardened to introsort (O(N log N) on adversarial orders);
8. attachment guards + test-only lifecycle observability hooks.

## Rust-side findings (as of branch `jh_thread_handoff_fix`, post-#171)

The Rust client has a full Java-format-compatible SFA subsystem (~8.3k
lines), all under `questdb-rs/src/ingress/sender/`, feature-gated on
`_sender-qwp-ws`:

| File | Role |
|---|---|
| `qwp_ws_sfa_segment.rs` | `.sfa` disk codec, `SF01` magic, mmap via `memmap2` |
| `qwp_ws_sfa_queue.rs` | `SfaFrameQueue`, rotation, recovery, `.ack-watermark` (`AKW1`) side file |
| `qwp_ws_sfa_slot.rs` | `<sf_dir>/<sender_id>/.lock` flock (Unix `flock` / Windows `LockFileEx`), `Drop`-released |
| `qwp_ws_sfa_symbol_dict.rs` | `.symbol-dict` append-only, CRC32C per entry, write-ahead ordered, **not** fsynced |
| `qwp_ws_orphan.rs` | orphan-slot scan/adoption, `OrphanDrainerPool` worker threads |
| `qwp_ws.rs` | `SyncQwpWsRunner` — exactly one background I/O thread per SFA sender |
| `qwp_ws_driver.rs` | `PublicationLifecycle{Open,Closing,Terminal}` CAS close FSM, `BlockingQwpWsTransport` |

Pool (`questdb-rs/src/db.rs`): one reaper thread; borrow/return under a
single mutex with RAII rollback guards; `SenderSlotRelease` notifies parked
borrowers immediately after a closing sender finishes; batched close drain
under one shared `close_flush_timeout` deadline. Already at/near parity
with the Java PR's pool-recovery goals after #171.

Threading/shutdown facts that matter here:

- `SyncQwpWsRunner` is stopped cooperatively (`stop: AtomicBool` polled
  between `drive_step`s) and joined **unbounded** in `Drop`
  (`qwp_ws.rs:1626-1633`). Ingress never calls `TcpStream::shutdown()` and
  never sends an outbound WS Close; a thread blocked in native read/write
  is released only by `set_read_timeout`/`set_write_timeout`.
- `OrphanDrainerPool::close_with_timeouts` (`qwp_ws_orphan.rs:213-224`)
  waits ~2500 ms + 500 ms grace, then **detaches** straggler threads
  (`threads.clear()`).
- Egress reader path is single-threaded, no background threads; egress
  transport already uses `Shutdown::Both`
  (`questdb-rs/src/egress/ws/client.rs:101-106`).
- `sf_durability` parses `memory|flush|append` but anything ≠ `memory` is
  hard-rejected at open (`ingress.rs:3170-3175`, `qwp_ws.rs:1636-1641`).
  There is **no fsync/msync anywhere** in the SF write path.

## Gap analysis

### Gap 1 — orphan-drainer thread detach (severity corrected)

*(Corrected while designing milestone 2 — the original claim of a
file-corruption race was wrong: the detached thread retains the slot
flock, so adopters get `SlotInUse` and never race its file operations.)*
The real defects: after `close_with_timeouts` returns, the detached
thread keeps doing network I/O and file trims the owner can't observe or
stop; the slot stays unavailable for an unbounded time (a restarted pool
in the same process cannot reuse it); and process exit kills the thread
mid-drain, turning a "graceful" close into a crash-shaped stop. See the
milestone 2 design section for the verified details.

### Gap 2 — unbounded close, no transport shutdown on ingress

The per-sender runner join is unbounded and there is no way to break a
thread blocked in native send/recv. Today this trades the Java corruption
bug for a potential close-time hang (bounded in practice only by socket
timeouts). Porting the Java "traffic shutdown ≠ final close" contract
(`TcpStream::shutdown` + TLS `close_notify` handling) makes runner joins
boundable and is also the correct fix for Gap 1 (drainer threads become
promptly stoppable instead of detached).

### Gap 3 — close-time cleanup ordering + no manifest

Rust has the `.ack-watermark` side file but no `SfManifest` boundary
record, and the close-time segment deletion ordering (persist watermark
first, enumerate fully before deleting, generation order, stop on first
failure, watermark removed last) has not been verified/ported. Without it,
a crash or unlink failure mid-close can make recovery replay acked data or
trip over torn state.

### Gap 4 — no durability mode beyond `memory` (feature, not fix)

`sf_durability=periodic` + `sf_sync_interval_millis` from the Java PR is a
new feature for the Rust client: msync cadence in the runner loop, checked
mmap + fd barriers, rotation gated on predecessor durability, failed
checkpoint surfaced to the producer and retried ≤1 s. Spans all four
layers (questdb-rs → questdb-rs-ffi → include/ C & C++ headers → cpp_test)
plus README. Largest single chunk of work.

## Not ported (already covered by Rust's design)

- **Worker-quiescence CAS machinery** — one runner thread per sender,
  owned and joined; no shared manager/registry to race (modulo Gaps 1–2).
- **Serialized `QuestDB.close()`** — `close(self)` consumes by move;
  concurrent double-close is unrepresentable in safe Rust. FFI latch
  already guards in-flight-call-vs-free (documented non-idempotent).
- **Confirmed flock release + retry driver + retired slots** — flock
  releases on fd close via `Drop`; the Java failure mode (JNI unlock
  reporting) doesn't map. Pool already notifies waiters on slot release.
- **`ObjList.remove` fix** — std `Vec`; N/A.
- **Introsort for recovery sort** — std `sort_unstable` (pdqsort) is
  already O(N log N) on adversarial input.
- **Native C changes** — libc/std/memmap2 cover flock, shutdown, msync;
  no `core/src/main/c` analogue needed.

## Rules for the implementing agent (QuestDB style)

Binding for every milestone in this PR. When a rule conflicts with
something in this plan, the rule wins; note the departure in this file.

0. **Never commit.** Deliver each milestone as uncommitted working-tree
   changes and stop; no `git commit`, `git push`, branching, or staging.
   The user reviews and commits every milestone themselves.

1. **Simple, direct code.** Plain functions and `match` over indirection.
   Write the obvious implementation first; only deviate when a measurement
   or a named invariant demands it. If a reviewer needs the plan document
   to understand a function, rewrite the function.
2. **No artificial abstraction.** No trait with a single production
   implementation (a test double is not a second implementation — use the
   existing test-transport seams). No generic parameter without a second
   concrete type in the same milestone. No wrapper type unless it enforces an
   invariant that would otherwise live in comments (`TrafficGate`'s sticky
   shutdown qualifies; a `ShutdownStrategy` would not). No speculative
   extensibility, config knobs, or "for later" hooks.
3. **Performance-conscious, hot path sacred.** The per-frame send/receive
   path gets zero new allocations, locks, atomics, branches, or syscalls.
   Cold paths (connect, reconnect, close, recovery) may take a mutex.
   Reuse scratch buffers as the existing code does (`send_buf` pattern);
   never allocate per frame or per checkpoint. State the hot/cold
   classification of every new code path in the milestone's completion
   report, and how it was verified (test, bench, or reasoning).
4. **Match the surrounding idiom.** Error handling via `crate::Result` +
   `error::fmt!`; comment density and doc-comment style of the module
   being edited; comments state constraints and invariants, not narration.
5. **Bounded everything.** No unbounded waits, queues, or thread counts;
   every new blocking wait has a deadline and a documented fallback,
   every timeout constant a rationale (prefer Java's constants for parity).
6. **Deterministic tests.** Synchronize with channels/latches, never bare
   sleeps; timing assertions must pass on a loaded CI machine (assert
   "well under the old worst case", not tight bounds).

## Proposed single PR, milestone sequence

1. **milestone 1 — ingress transport shutdown contract.** Add traffic
   shutdown (`TcpStream::shutdown(Both)` + TLS teardown) reachable from
   another thread; runner close becomes shutdown → bounded join → final
   close. Mirrors Java's Socket/WS shutdown split. Tests: blocked-send
   close, connect-phase close (Java analogues:
   `CursorWebSocketSendLoopBlockedSendCloseTest`, `...ConnectPhaseCloseTest`).
2. **milestone 2 — orphan-drainer quiescence.** Replace detach-on-timeout in
   `OrphanDrainerPool` with shutdown-driven bounded stop; if a thread still
   won't die, retire the slot (keep flock held, don't allow adoption)
   instead of detaching over live files. Tests: wedged-drainer slot
   retention, no adoption of a slot with a live stale thread.
3. **milestone 3 — crash-safe close cleanup + `SfManifest`.** Port the
   ordered close path and the dual-slot CRC manifest record; recovery skips
   acked residue after unlink failure/crash. Tests: unlink-failure
   stop-on-first, torn-enumeration, watermark-preserved recovery,
   manifest monotonic clamp (Java analogues: `CursorSendEngineCloseUnlink*`,
   `SfManifestClampTest`, `SegmentManagerCrashConsistencyTest`).
4. **milestone 4 — `sf_durability=periodic` + `sf_sync_interval_millis`.**
   Runner-loop msync cadence, rotation gating, checkpoint-failure
   surfacing/retry; config plumbing conf.rs → FFI → `client.h`/`.hpp`;
   cpp_test coverage; README. Validation identical to Java: positive,
   ≤ `i64::MAX / 1_000_000`, requires `periodic`, WS transport only.
5. **milestone 5 — docs + parity notes.** README durability contract, remove
   this plan file or fold into docs.

Ordering rationale: 1 unblocks 2 (bounded stop needs interruptible I/O);
3 and 4 both touch segment/queue close paths, land 3 first so 4's sync
checkpoints build on the safe cleanup ordering.

## Milestone 1 design — ingress traffic-shutdown contract

### Verified current behavior (no assumptions)

Where the per-sender I/O thread (`SyncQwpWsRunner`, one per SFA sender) can
be when close is requested, from reading `qwp_ws.rs`/`qwp_ws_driver.rs`:

| State | Bounded today by | Worst close latency |
| --- | --- | --- |
| blocking `write` in `send_frame`/keepalive (`qwp_ws_driver.rs:3213,3195`) | `SO_SNDTIMEO` = `request_timeout` (WS default **30 s**, `conf.rs:336`) | 30 s |
| reads | already nonblocking — `read_nonblocking_once` returns `WouldBlock` → `Idle` (`qwp_ws.rs:1919`) | ~0 |
| connect attempt (initial or reconnect) | runner connects are `Foreground`: configured `connect_timeout`, otherwise the OS dial timeout; TLS handshake 5 s; auth `auth_timeout` | OS dial timeout when unset, then 5–15 s |
| reconnect backoff sleep | stop-checked every 50 ms (`sleep_before_runner_reconnect`, `qwp_ws.rs:1616`) | 50 ms |
| DNS (`getaddrinfo`) | nothing | unbounded (same residual as Java) |
| idle | 50 µs park | ~0 |

So the pre-Milestone-1 `Drop` (stop flag + **unbounded join**) cannot
corrupt anything — the `SlotLock` lives inside the `Arc<Mutex<store>>`
whose last reference drops only after the thread exits, so the flock is
provably released *after* worker quiescence already. The problem is purely
latency: a pool close can stall up to `request_timeout` per blocked writer.
SIGPIPE on shutdown-during-write is already handled (`NoSigpipeTcp`:
`MSG_NOSIGNAL` on Linux, `SO_NOSIGPIPE` inherited by `try_clone` fds on
BSD/macOS, N/A Windows).

Java's contract (from `CursorWebSocketSendLoop.close()`,
`PlainSocket.closeTraffic`): stop flag → `closeTraffic()` =
`shutdown(fd, SHUT_RDWR)` bypassing TLS, `ENOTCONN` = success → cancel an
in-flight connect that was *registered before it blocked* → **bounded**
latch await → on timeout, loud-fail and delegate all cleanup to the worker
exit path (never free memory under a live worker).

### Design: `TrafficGate`

New small type in `qwp_ws.rs` (milestone 2 reuses it for orphan drainers):

```rust
struct TrafficGate {
    inner: Mutex<GateInner>,   // { current: Option<TcpStream>, shut: bool }
}
```

- `register(sock: &TcpStream)`: `try_clone()` the socket (dup'd fd; on
  Unix `shutdown` on the dup affects the shared socket, and holding the
  dup avoids any raw-fd-reuse hazard) and store it. If `shut` is already
  set (sticky), immediately shutdown the new socket instead — this closes
  the race "closer shuts old socket while runner installs a fresh one".
- `clear()`: drop the clone (also frees the dup'd fd of a dead peer).
- `shutdown()`: set `shut = true`, then `TcpStream::shutdown(Both)` on the
  stored clone; treat `NotConnected` as success (Java parity).

Wiring (all cold paths):
- `Arc<TrafficGate>` owned by `SyncQwpWsRunner`; threaded into
  `QwpWsPendingConnect` and `BlockingQwpWsTransport`.
- Registration happens at **TCP-establish**, before TLS handshake/auth
  (inside `connect_qwp_ws_endpoint_round` → `connect_qwp_ws_tcp` path, new
  `Option<&TrafficGate>` parameter; manual, direct-pooled, and Milestone 1
  orphan-drainer callers pass `None`)
  — matches Java, whose fd is reachable mid-handshake, and makes the
  5 s + auth_timeout handshake window interruptible too.
- `BlockingQwpWsTransport::reconnect` clears the gate on entry and the
  connect path re-registers the new socket.

### Close sequence (replaces `Drop for SyncQwpWsRunner` body)

1. `stop.store(true)` (unchanged).
2. `gate.shutdown()` — any blocked write/handshake returns an error within
   milliseconds; `drive_step` sees `stop` and exits.
3. Bounded wait by polling `JoinHandle::is_finished()` every 1 ms, with the
   Java-matching 30 s backstop. The pre-registration TCP-connect syscall and
   DNS are the residual paths the gate cannot interrupt.
4. Finished → `join()` (instant). Timeout → log loudly and
   **detach** the `JoinHandle` — safe here, unlike the orphan pool: the
   thread's own `Arc` keeps the store *and the `SlotLock`* alive, so the
   slot stays locked until the wedged thread actually dies. This is Java's
   "cleanup transfers to worker exit" and "slot remains unavailable rather
   than handed over," obtained for free from `Arc` refcounts instead of
   Java's exactly-once CAS machinery.

Graceful drain (`begin_close` → `drain_to_deadline`) is untouched and runs
*before* `Drop`, so acks still drain over live traffic; the gate fires only
after the drain budget is spent.

### Performance constraints (why this shape)

- **Hot path untouched**: no new atomics, locks, or branches in
  `send_frame`/read/`drive_step`. The gate is touched only at
  connect, reconnect, and close. The existing single `stop` load per
  `drive_step` iteration remains the only steady-state overhead.
- **No socket-mode changes**: keeps blocking writes (one syscall per WS
  frame, no epoll/poll registration, no extra copies); rejected the
  alternative of switching the socket nonblocking + poll loop, which
  would add a syscall and wake-up machinery to every frame.
- **No mutex around I/O**: the gate mutex is never held during send/recv,
  only during register/clear/shutdown.
- Cost: one dup'd fd plus one `Arc<Mutex<...>>` gate per background sender;
  there is no exit latch.

### Files touched

- `questdb-rs/src/ingress/sender/qwp_ws.rs` — `TrafficGate`, bounded runner
  `Drop`, gate threading through `QwpWsPendingConnect::connect_with_retry` and
  the connect fns (~250 lines).
- `questdb-rs/src/ingress/sender/qwp_ws_driver.rs` — gate field +
  `reconnect()` clear/register (~30 lines).
- `questdb-rs/src/ingress.rs` and
  `questdb-rs/src/ingress/sender/qwp_ws_orphan.rs` — explicit `None` at the
  shared connect API's pooled/manual-orphan callers; those paths do not own the
  Milestone 1 runner gate.
- `questdb-rs/src/tests/qwp_ws.rs` — real socket regressions.
- No FFI/header/C changes: behavior-only; `sf_*`/close ABI unchanged.

### Tests (mirroring Java's)

Using the existing QWP socket-test helpers:

1. blocked-send close: server accepts, never reads; fill the socket buffer
   until the runner blocks in `write`; drop sender; assert close returns
   well under `request_timeout` (Java: `...BlockedSendCloseTest`).
2. connect-phase close: accepted sockets stalled in the WebSocket upgrade and
   TLS handshake; close during async initial connect and assert prompt return
   (Java: `...ConnectPhaseCloseTest`).
3. sticky-gate race: shutdown the gate, then register a fresh socket;
   assert the new socket is shut immediately.
4. reconnect variant of (1): replace the connection, block the replay write,
   then prove close interrupts the replacement socket rather than a stale fd.
5. detach fallback: test-transport that ignores shutdown; assert Drop
   returns after the backstop and the slot flock stays held until thread exit.

### Milestone 1 implementation notes and deliberate departures

- The production shutdown backstop is **30 seconds**, matching Java's
  `DEFAULT_CLOSE_SHUTDOWN_AWAIT_MILLIS`, rather than the plan's approximate
  20-second budget.
- There is no exit `Condvar`. `Drop` polls `JoinHandle::is_finished()` every
  1 ms, only during shutdown, then joins an already-finished thread. This avoids
  an extra `Arc`/mutex/condvar and an exit-path notification while preserving
  the bounded wait. The timeout branch drops the handle (detach) and logs an
  error; the worker's `Arc` still owns the publication store and slot lock.
- `TrafficGate::register()` returns a small RAII registration guard. Failed
  TLS/HTTP upgrades clear the duplicated socket automatically, and
  `BlockingQwpWsTransport::drop()` clears a successful registration when a
  worker exits terminally before its owner is dropped. This prevents the
  cancellation fd from extending a dead connection's lifetime.
- After the current connect attempt returns, the endpoint-round loop checks the
  sticky shutdown state and exits immediately. A close-triggered error therefore
  does not narrate a connection failure or start dialing the remaining endpoints.
- Corrected the connection-boundary description: runner initial/reconnect
  connects use `QwpWsConnectKind::Foreground`, so the default
  `connect_timeout=None` remains the OS dial timeout. Only orphan drainers get
  the 15-second fallback. Rust cannot register the `TcpStream` until
  `TcpStream::connect[_timeout]` returns, so that pre-registration syscall (and
  DNS) remains interruptible only by its own timeout; the 30-second detach
  backstop bounds the owner's wait without releasing the slot.
- The connect-phase tests use deterministic accepted sockets stalled in the
  WebSocket upgrade and TLS handshake instead of a network-dependent blackhole.
  The TLS regression exercises the raw-socket shutdown while rustls is blocked;
  duplicating the large blocked-send test under TLS would test the same gate
  with substantially more fixture code and memory.
- No new frame-path branch, lock, allocation, or syscall was added. The gate is
  touched only at TCP establishment, reconnect, transport drop, and runner
  drop. Cost remains one duplicated fd, one `Arc`, and one cold-path mutex per
  live background sender.

## Milestone 2 design — orphan-drainer quiescence

### Verified current behavior (corrects Gap 1's severity)

From reading `qwp_ws_orphan.rs` in full:

- Each pool worker thread (`OrphanDrainerPool::start`, `:197`) loops
  `pop_pending_orphan` → `drain_orphan_to_completion`, which opens the slot
  via `SfaSlotQueue::open_replay_only_existing` — **the queue owns the
  `SlotLock`, and the queue lives on the worker's stack**. A detached
  thread therefore retains the flock until it actually exits; any adopter
  meanwhile gets `SlotInUse` → `OrphanOpenOutcome::Locked` → skipped
  (`:421`). The `.failed`/`.last_error` sentinel writes are already
  stop-guarded (`mark_orphan_failed_unless_stopped`, `:731`).
- **Gap 1 is therefore not a file-corruption race** (my earlier claim was
  too strong — the flock closes that). The real defects of
  detach-on-timeout (`close_with_timeouts`, `:213`): (a) `close()` returns
  while the thread still does network I/O and file trims the owner can no
  longer observe or stop; (b) the slot stays `SlotInUse` for an unbounded
  time after close — a restarted pool in the same process can't adopt or
  reuse it; (c) process exit kills the thread mid-drain/mid-unlink,
  downgrading a "graceful" close to a crash (recovery must cope — milestone 3
  hardens that).
- Why threads outlive the 2.5 s + 0.5 s close budget today: the drainer's
  `BlockingQwpWsTransport::connect` (`:448`, gate = `None` since milestone 1)
  is `BackgroundDrainer`-kind — bounded but ~15 s TCP + 5 s TLS + auth;
  and a mid-drain blocked `write` rides `request_timeout` (30 s). Backoff
  sleeps already poll `stop` every 50 ms (`sleep_before_orphan_reconnect`).
- `ManualOrphanDrainers` runs on the caller thread — no threads, nothing
  to interrupt; out of scope.

### Design: wire milestone 1's `TrafficGate` into the pool

No new abstraction. One `Arc<TrafficGate>` **per worker thread** (a worker
drains slots sequentially, so one gate per thread suffices; the gate
already handles register→clear→re-register across a thread's successive
connections and reconnects, and transport `Drop` clears it between slots).

- `OrphanDrainerPool.threads` becomes
  `Vec<(thread::JoinHandle<()>, Arc<TrafficGate>)>`.
- `drain_orphan_to_completion` and `OrphanDrainer::open_with_stop` gain a
  `&Arc<TrafficGate>` parameter, passed as `Some(gate)` at the
  `BlockingQwpWsTransport::connect` call (`:457`, replacing `None`).
  Manual drainers keep `None`.
- `close_with_timeouts` sequence becomes:
  1. join finished; graceful wait (`ORPHAN_POOL_GRACEFUL_DRAIN`, 2.5 s,
     unchanged) — live drains may still finish cleanly;
  2. `stop.store(true)` — **before** the gates, mirroring milestone 1, so a
     woken thread exits instead of reconnecting;
  3. `gate.shutdown()` on every remaining thread's gate — blocked
     connect/handshake/send returns in milliseconds; the sticky flag makes
     any *next* connect (thread moving to its next queued slot) fail
     immediately, so a closing pool never starts dialing new slots;
  4. bounded grace wait (keep 500 ms), then detach any survivor exactly as
     today — same log, same safety (flock retained by the thread).
- Detach becomes the rare path: reachable only while a thread is inside
  queue open/recovery (segment CRC scans have no stop checks — noted
  below), not during any network wait.

### Performance

All cold path: gates are touched at connect, between-slot transition, and
close. The drain loop (`close_drain_ready_step` stepping) is unchanged —
zero new atomics, locks, or branches per frame. Cost: one `Arc` + mutex +
(while connected) one dup'd fd per worker thread; workers default to
`max_background_drainers` (small).

### Residuals (documented, not fixed here)

- Segment recovery inside `SfaSlotQueue::open_replay_only_existing` has no
  `stop` polling; a huge/slow slot can still push a thread into the detach
  path. If milestone 3's cleanup work touches the recovery scan anyway, add a
  cheap per-segment `stop` check there; otherwise leave it.
- DNS (`getaddrinfo`) remains uninterruptible — same residual as milestone 1.

### Tests (in-module, following the existing `close_with_timeouts` test
pattern at `:888`/`:914`)

1. blocked-connect close: stalled-accept server; pool close joins the
   worker within the budget (no detach) — asserts the gate reaches the
   connect path.
2. blocked-send close: slot with a queued frame, server peeks then stalls
   with a tiny receive buffer; close interrupts the drain write and joins.
3. sticky no-new-dials: two pending slots, first drain blocked; close;
   assert the server sees no second connection attempt.
4. detach still safe: wedge a thread past the grace budget (reuse the
   existing detach test's approach); assert bounded close, `SlotInUse`
   while detached, slot adoptable after the thread exits — the milestone 1
   slot-retention assertions, applied to the pool.

### Milestone 2 implementation notes (reviewed 2026-07-30)

Implemented as designed, no departures: per-worker gates in
`OrphanDrainerPool.threads: Vec<(JoinHandle, Arc<TrafficGate>)>`, stop set
before gates shut, detach path retained with an error log.
`TrafficGate::shutdown` widened to `pub(super)` for the sibling orphan
module. All new code paths are cold (connect, close); the drain loop is
unchanged. Four regressions as planned: stalled-connect close (worker
joins, slot immediately reusable), blocked-send close (< 5 s vs the 30 s
write timeout, unacked frame retained), sticky no-next-dial (second slot
never dialed, both slots keep their `.sfa` files), and wedged-worker
detach (slot `SlotInUse` until the thread exits, adoptable after).
Reviewer verification: 7 targeted tests + full suite (1570 passed) green,
`cargo fmt --check` clean, plain clippy clean.

## Milestone 3 design — crash-safe cleanup, `sf-manifest.bin`, watermark upgrade

The meat of the port. Grounded in two full deep-reads: the Rust close/trim/
recovery paths (`qwp_ws_sfa_queue.rs`/`_segment.rs`/`_slot.rs`) and the
Java post-#67 contract (`SfManifest`, `AckWatermark`, `CursorSendEngine`
close, `SegmentRing.recover`). Line refs below are to those files.

### 3.0 Why this is bigger than "port a manifest" — verified findings

**Rust today:**

- Close never persists the watermark; it just drops the handle
  (`SfaFrameQueue::close`, queue.rs:588-592). Cleanup deletes `*.sfa` in
  **raw readdir order**, continues past unlink failures (diagnostic only),
  and removes `.ack-watermark` only if every unlink succeeded
  (`record_all_sfa_cleanup`, :1949-1986). An undrained close touches no
  files; a *second* close never cleans up (one-shot `closed` flag, :982).
- `.ack-watermark` is the **legacy 16-byte format**: magic `AKW1`,
  reserved, i64 FSN — **no CRC, no shadow record** (:52-54, :1673-1684).
  A torn 8-byte value rewrite is undetectable, and a plausible-but-high
  FSN both skips unacked frames and lets trim delete their segments —
  **the only silent-data-loss path in the Rust design** (everything else
  fails toward duplicates). Java #67 replaced this exact format.
- Recovery (`recover_segments`, :1715-1816) sorts by header `base_seq`
  and **hard-fails the whole slot on any chain gap** (:1785) — no
  truncate-to-prefix, no residue skip. A torn tail on a *sealed* segment
  becomes a gap and bricks the slot.
- **Zero fsync/msync anywhere** in the SFA write, trim, or close paths
  (verified by sweep). All ordering guarantees are page-cache-only; the
  crash model is process crash, not power loss.
- Segment header scan **rejects non-zero flags** (segment.rs scan).

**Java post-#67:**

- Adds `sf-manifest.bin` (durable chain-boundary record, fsync'd per
  update) *and* upgrades `.ack-watermark` to the same dual-slot CRC
  geometry. Segments written under a manifest get
  `MANIFEST_REQUIRED_FLAG = 1` stamped at **header byte 5** (fail-closed
  backstop if the manifest disappears).
- **Cross-client hazard, live today:** a Java-post-#67 slot has flagged
  segments; Rust's scan rejects non-zero flags → skips every flagged
  segment as a diagnostic → recovery sees an empty/partial slot → the
  backlog is silently not replayed (or partially replayed against a fresh
  FSN space). Conversely a Rust slot adopted by Java gets migrated
  (manifest created, flags stamped) and is thereafter **unreadable by
  Rust**. Milestone 3 closes both directions.

### 3.1 Scope decision

Port the **full Java contract, byte-compatible**, in one milestone (the
pieces are not separable: writing flags/manifest without the recovery
rewrite would brick Rust's own restarts). Four internally ordered parts,
each leaving the suite green: (A) dual-slot record primitive + manifest +
watermark upgrade, (B) recovery rewrite + legacy migration, (C) write-path
barriers, (D) close-time ordered cleanup + error taxonomy.

### 3.2 On-disk formats (byte-exact, all little-endian)

Shared dual-slot geometry (one Rust helper serves both files — this is a
real invariant, not an abstraction: identical layout, CRC rule, slot
parity, and selection):

- File size 8192 = two 4096-byte slots; a 64-byte record at each slot
  start; bytes 64..4095 of a slot are never rewritten after creation.
- Record: `magic i32 @0`, `version i32 @4 = 1`, `generation i64 @8`,
  payload, `crc32c i32 @60` — standard Castagnoli over bytes `[0,60)`
  (init 0xFFFFFFFF, reflected, final xor; Rust: the same CRC the frame
  codec already uses), CRC stored **last** on write.
- Writer targets slot `(new_generation & 1) * 4096`. `create()` writes
  generation 1 → **offset 4096; slot 0 stays zero** (byte-parity trap).
- Reader validates both records (short read, magic, version, CRC,
  `generation <= 0`, payload-specific checks) and selects the greatest
  valid generation; tie → slot 1. One valid record is enough; both
  invalid → treat file as absent after quarantining
  (`rename → .corrupt`, else remove, else error).

`sf-manifest.bin` (magic `0x314d4653` 'SFM1'): payload `head_base i64
@16`, `active_base i64 @24` — **segment base sequences, not FSNs**.
Invariant `0 <= head_base <= active_base` (reject on read and write).
`update()` semantics (pin with a clamp test, Java
`SfManifestClampTest`): clamp each field independently against the
committed in-memory value (suppressed on the generation-0 first write,
which overwrites the `-1` sentinels); validate after clamping; **no-op
short-circuit** when the clamped pair is unchanged (no write, no
generation bump — observable in slot parity, must match); else pwrite 64
bytes → `fsync` → only then advance in-memory state (failed update leaves
state so retry reuses the same generation). Wrong-sized file → quarantine,
treat as absent (proves a pre-first-record creation crash).

`.ack-watermark` (magic `0x31574B41` 'AKW1' — same magic as legacy):
payload `fsn i64 @16`, valid `fsn >= -1`. On open, **any wrong-sized file
— including Rust's own legacy 16-byte format — is reset** (Java behavior;
trusting a legacy CRC-less FSN would preserve the torn-write ambiguity;
cost is duplicate replay once after upgrade, the safe direction). Note the
legacy Rust decoder rejects the new format (version byte lands in its
must-be-zero reserved field) and Java resets the 16-byte file: neither
direction ever *misreads* a value — the formats are mutually invalid,
which is what makes the upgrade safe to ship.

Mechanism departure from Java (format-compatible, deliberately different
I/O): Java mmaps the watermark and does mapping-stores + `msync`+`fsync`
in `sync()`. Rust keeps its existing **pwrite** approach (its documented
anti-SIGBUS stance, queue.rs:1555-1559) with `sync_data()` where Java
calls `sync()`. Same bytes, same barriers, no new mmap.

Segment header: accept and stamp flag bit `0x1` (`MANIFEST_REQUIRED`) at
byte 5; continue rejecting all other flag bits. Stamping = set byte +
header-page flush + file fsync (Java `markManifestRequired`/`syncHeader`),
done when a legacy slot is migrated and on new-segment creation once a
manifest exists.

### 3.3 Write-path barriers (part C) — where durability enters steady state

| Event | New behavior | Cadence / cost |
| --- | --- | --- |
| Segment rotation | `manifest.update(head_base, new_active_base)` **before any queue mutation**; the promoted spare's rebased header is flushed *before* the manifest names it. Update failure ⇒ rotation never happened. | once per segment fill: 1 pwrite + 1 fsync |
| Trim (acked segment) | Before the unlink: persist watermark, `sync_data` it (**covering barrier** — the acks that justify the trim must be durable before the file vanishes), then `manifest.update(successor_base, active_base)` (fsync), then unlink. | once per trimmed segment: ≤2 fsync |
| Fresh slot open | `SfManifest::create` (exclusive create, allocate 8192, write gen 1, fsync file, fsync dir; rollback removes on failure) | once per slot |

Nothing changes per frame. The runner's hot send/receive path is
untouched; all fsyncs ride the existing storage-maintenance /rotation
steps (already cold). This ordering is what makes recovery's residue-skip
sound: **manifest head is durably ahead of every unlink**, so a file
below `head_base` is *proven* acked residue.

Trim-ordering fix required in Rust: today trim pops the segment from the
in-memory queue **before** the I/O (queue.rs:1292 vs :222) and refunds the
byte budget even if the unlink fails. Keep the pop-before-IO shape (the
queue lock must not span I/O) but the covering barrier and manifest update
must complete **before** `pop_front`, and an unlink failure must leave the
manifest consistent (it already names the successor as head — the leftover
file is below head ⇒ skipped residue; acceptable, matches Java).

### 3.4 Close-time cleanup (part D) — exact order, replacing today's sweep

Fully-drained close (pinned barrier sequence, from Java
`CursorSendEngineCrashConsistencyTest`):

1. persist final acked FSN through the still-open watermark → `sync_data`
   → **fsync the slot dir**; on failure: retain everything (segments,
   watermark, manifest, flock) and surface the error — never publish a
   slot whose durable watermark is stale;
2. tear down mappings/handles;
3. **enumerate `*.sfa` to completion before any unlink**; a partial
   listing (readdir error mid-scan) ⇒ delete nothing;
4. sort by cleanup rank: `sf-initial.sfa` → MIN, `sf-<16hex>.sfa` → its
   generation, else MAX; ties by name;
5. reopen the manifest, `update(active_base, active_base)` (collapse —
   declares everything below active acked) **before the first unlink**;
   failure ⇒ delete nothing;
6. unlink ascending, **stop on the first failure** (ascending order means
   the surviving suffix always contains the active segment — recovery
   then finds `head == active` present and residue below it, instead of
   "missing active" refusal);
7. all gone → **fsync dir** → remove `.ack-watermark` (only now: until
   the dirent removals are durable, stable storage may still hold acked
   segments the watermark must vouch for) → remove `sf-manifest.bin`
   **last** (failure non-fatal: manifest+zero-segments is the recognized
   drain window);
8. release the flock (unchanged milestone 1/2 territory).

Undrained close: sync live data is milestone 4; here it retains all files
(current behavior, now with the manifest also retained). Also fix the
`fully_drained` read outside the state lock (:979 vs :980).

### 3.5 Recovery decision tree (part B) — replaces the flat gap-check

Order: enumerate fully (readdir error ⇒ fail, do not skip) → scan every
candidate (I/O error ⇒ fail the open, corruption ⇒ collect for deferred
quarantine) → open manifest → branch:

- **No manifest** + any segment flagged ⇒ **hard fail** (fail-closed
  backstop). No manifest + unflagged segments ⇒ **legacy migration**:
  validate contiguity (today's rule), durably zero sealed torn tails
  (silently — legacy predates the contract), create the manifest from the
  recovered chain, stamp flags on every member. This is the path every
  existing Rust slot takes exactly once.
- **Manifest present**: skip segments wholly below `head_base` (acked
  residue — later removed as extras); segment *straddling* `head_base` ⇒
  fail; segment beyond `active_base` ⇒ fail; then contiguity + "first
  chain member's base == head_base" + "active found at active_base", with
  the Java-matched acceptances for the empty/drain windows (collapsed
  boundaries + no files ⇒ EMPTY with a warning; each lenient acceptance
  guarded on "no corrupt candidate of unknown identity exists").
- **Sealed torn tails under a manifest**: durably zero them, then fail
  once with a distinct error (`SanitizedResidue`); an immediate reopen
  succeeds. Active-tail torn bytes: durably zero unconditionally (policy:
  replay cannot cross the tear; preserving bytes risks resurrecting a
  stale CRC-valid frame at a recycled FSN).
- **Watermark reconciliation** (unchanged shape, new format): seed =
  `max(watermark_fsn, lowest_surviving_base − 1)`, unless that exceeds
  `published_fsn` — then the watermark is corrupt, use the segment floor.
  Missing/unopenable watermark on a recovered disk slot ⇒ hard fail
  (Java `SfOperationalException`) — do not silently accept full replay
  when the file *should* exist.

### 3.6 Failure-mode inventory (why each ordering is what it is)

- Crash between manifest-head fsync and trim unlink ⇒ stale file below
  head ⇒ skipped residue, cleaned later. (Reverse order would make
  recovery demand a file the trim deleted ⇒ permanent "missing head".)
- Crash between unlink and dir fsync ⇒ file can *reappear* after power
  loss ⇒ same skipped-residue case. Covered only because the manifest
  advance was fsynced first.
- Trim without the watermark covering barrier would let recovery skip
  frames whose acks were never durable ⇒ real loss; hence sync-before-
  unlink.
- Close crash after step 1 ⇒ full chain + durable final watermark ⇒
  replay nothing, cleanup retries next open. Crash mid-step-6 ⇒ residue
  is an ascending-suffix containing the active ⇒ recovers as fully-acked,
  cleanup retries. Unlink *failure* (no crash) ⇒ same state, close
  reports partial, watermark+manifest retained.
- Torn manifest update ⇒ sibling record intact by construction (single-
  slot writes); both-torn ⇒ only possible from a creation crash ⇒ safe to
  treat as absent (backstopped by segment flags).
- Torn watermark update ⇒ sibling record; both torn ⇒ INVALID ⇒ segment
  floor ⇒ duplicates, never loss. This closes today's Rust silent-loss
  hole.
- ENOSPC at manifest create ⇒ rollback (close fd, remove file); slot
  opens fail loudly rather than run manifest-less.

### 3.7 Rust mapping

- New file `qwp_ws_sfa_manifest.rs`: the dual-slot record helper +
  `SfManifest` + the upgraded watermark record codec (~450 lines incl.
  docs). `SfaAckWatermark` in queue.rs rewrites onto it (pwrite
  mechanism kept).
- `qwp_ws_sfa_segment.rs`: flag-bit acceptance in the scan, stamp +
  header-flush helper, torn-tail durable zeroing (`flush_range` +
  `sync_data`) (~80 lines).
- `qwp_ws_sfa_queue.rs`: recovery rewrite, trim/rotation barriers, close
  rewrite, error variants (`SanitizedResidue`, distinct
  recovery-terminal vs operational) (~large; the dominant chunk).
- `qwp_ws_orphan.rs`: catch-order parity — `SanitizedResidue` ⇒ retry
  once, then `.failed`; recovery-terminal ⇒ `.failed`; operational ⇒
  retry (matches Java `BackgroundDrainer:592-621`) (~30 lines).
- No FFI/header changes (no new config; behavior + on-disk only).
- Java-golden fixtures: extend `tests/qwp_ws_java_golden.rs` with
  byte-exact manifest/watermark fixtures (created-by-Java hexdumps) so
  compatibility is pinned, not assumed.

### 3.8 Hot/cold classification

Hot (per-frame publish/ack): **unchanged, zero additions**. Warm
(per-segment rotation/trim): +1–2 fsync + 64-byte pwrite — bounded by
segment size, the same cost Java accepted; worst case with tiny test
segments is fsync-per-segment-fill, production segments are MBs. Cold
(open/close/recovery): new ordered barriers as specified.

### 3.9 Tests

Port the Java pinned suite: clamp mutant-killer, slot-parity/generation
byte tests, both-torn/one-torn/wrong-size manifest matrix, close barrier
**sequence** test (needs a `#[cfg(test)]` barrier-event recorder — the
demand-driven hook case), partial-enumeration ⇒ no deletion,
stop-on-first-failure (readonly-dir / open-handle tricks as today),
residue-skip after simulated crash windows (kill between staged steps by
driving the queue directly), legacy-Rust-slot migration (open a
pre-milestone-3 fixture slot; assert manifest created, flags stamped,
16-byte watermark reset, backlog replayed), Java-golden byte fixtures
both directions, boundary matrix for recovery (missing head / beyond
active / straddle / drain-window / corrupt-candidate-blocks-lenient-
acceptance), watermark reconciliation matrix (behind/ahead/torn/both-torn
/ above-published), orphan retry-once on `SanitizedResidue`.

### 3.10 Implementation notes (completed 2026-07-30)

Implemented as uncommitted working-tree changes. The new
`qwp_ws_sfa_manifest.rs` owns the shared Java-compatible 8192-byte
dual-slot codec, `SfManifest`, and upgraded `SfaAckWatermark`. Segment
headers now accept/stamp `MANIFEST_REQUIRED`; fresh creation uses Java's
durable order (unflagged segment + directory sync → manifest → flag), and
legacy slots migrate in place. Java-generated manifest/watermark records
are pinned byte-for-byte in `qwp_ws_java_golden.rs` in both directions.

Recovery now follows the manifest boundary decision tree, including
fail-closed missing manifests/watermarks, monotonic watermark
reconciliation, acked-residue cleanup, durable sealed-tail sanitation with
one-shot `SanitizedResidue`, unconditional active-tail sanitation, and
orphan retry-once classification. Rotation and trim enforce the header /
watermark / directory / manifest barriers before queue mutation. Fully
drained close persists the final watermark, releases every segment owner,
fully enumerates and sorts before unlink, collapses the manifest, stops on
the first unlink failure, and removes the watermark before the manifest;
undrained close retains the slot.

The per-frame append/send path is unchanged. One narrow ACK-path addition
does an atomic published-boundary comparison and branch (no allocation,
lock, or syscall) so the final ACK releases the send cursor's mmap owner
*before* publishing completion to a concurrent close thread. This is the
required correctness exception to §3.8's literal "zero additions" claim;
the ordering is pinned by `hot_final_ack_releases_the_sfa_cursor`. All new
filesystem work remains per-segment or open/close/recovery work.

Validation on the final tree:

- `cargo check --no-default-features --features
  sync-sender-qwp-ws,tls-webpki-certs,ring-crypto` — green.
- `cargo test --features sync-sender-qwp-ws` — 1593 unit tests passed,
  21 ignored; all integration targets green (78 + 2 + 4 + 5 + 5 tests);
  doctests green (48 passed, 3 ignored, plus 3 compile-fail tests).
- `cargo clippy --features sync-sender-qwp-ws --all-targets --
  -D warnings` and `cargo fmt --all -- --check` — green.

### Milestone 3 implementation notes (added by reviewer, 2026-07-30)

Implementation verified byte-compatible and barrier-correct (full-context
adversarial review; CRCs of the golden fixtures independently recomputed).
Four deliberate departures the implementing agent left unrecorded:

1. **Watermark-ahead is repaired in place**: when the recovered FSN
   exceeds `published_fsn`, Java only rejects it in memory; Rust also
   writes the segment-floor FSN back (generation-bumped, CRC-valid).
   Same seed either way; self-healing on disk.
2. **Trim barrier cadence**: 4 barriers per trimmed segment (watermark
   `sync_data` + slot-dir fsync + manifest `sync_all` pre-pop, dir fsync
   post-unlink) vs the design's "≤2" and Java's once-per-≤64-segment
   quantum. Per-segment cold path; the post-unlink dir fsync is a safety
   improvement over Java. Revisit only if trim throughput ever measures
   as a bottleneck.
3. **Fresh-slot creation order** is Rust-specific: durable watermark →
   durable unflagged segment → manifest → flag stamp (Java: manifest
   before segments). Crash-safe at every prefix, pinned by
   `fresh_creation_crash_windows_recover_before_and_after_manifest_publication`.
4. **Synchronous ack path propagates watermark write errors** (manual
   senders surface ENOSPC on ack); the runner's cold-effect path keeps
   degrade-don't-fail. The old disable-after-first-failure latch is gone
   — a persistently failing disk costs one failed pwrite per ack batch.

Hot-path note: per-frame publish/send unchanged; the ack-processing path
gained one `Acquire` load feeding the Windows active-segment-unlink fix.
Reviewer validation: 1593 tests passed (23 new), fmt clean, plain clippy
clean; barrier-sequence, byte-golden (both directions), crash-window,
boundary-matrix, migration, and orphan retry-once tests all present.

## Milestone 4 design — `sf_durability=periodic` + `sf_sync_interval_millis`

Grounded in a deep-read of Java's periodic-sync machinery
(`SegmentManager.servicePeriodicSync`, `MmapSegment.syncPublished`,
`SegmentRing` rotation gate + durability latch, `Sender` validation) and a
map of this repo's config plumbing. Good news first: **all `sf_*` keys are
config-string-only and the C/C++ layer needs zero new code** — the FFI
builds senders from conf strings; headers are hand-maintained prose.

### 4.1 What Java does (the contract to match)

- **Checkpoint pass** (per ring, on the manager worker): collect
  non-durable sealed segments from a saved frontier, then the active —
  for each: skip if `published <= durable_cursor`; mlock the dirty delta
  (fsyncgate guard); `msync(0..published)`; `fsync(fd)`; advance
  `durable_cursor`. On failure: re-dirty the delta pages (one byte per
  page) before munlock, abort the rest of the pass. Zero allocation per
  tick (reused scratch list).
- **Scheduling**: per-ring deadline in nanos; first pass immediate
  (durable baseline); cadence re-armed from *pass completion*; failed
  pass retries at `min(interval, 1 s)` (bare literal in Java);
  edge-triggered error log; a `sync_requested` flag (set by the rotation
  gate) overrides the deadline.
- **Rotation gate**: when the active segment fills and its data is not
  yet durable, rotation is refused with the ordinary
  no-spare backpressure sentinel, `sync_requested` is set, the manager is
  woken. The producer just sees normal backpressure until the checkpoint
  covers the predecessor. Pinned by a mutant-killer test (this gate once
  shipped neutralized with a green suite).
- **Durability latch**: a failed checkpoint latches the error; **every
  append and flush/await fails with the same latched instance** (checked
  first, before an FSN is reserved) until a fully successful pass clears
  it — sound only because failed pages were re-dirtied.
- **Recovery/close**: nothing on disk records a failed checkpoint;
  instead every reopened disk segment counts as non-durable from the
  header, and opening a recovered slot with periodic on runs a
  synchronous full-ring sync (throws if the disk is bad). An undrained
  close in periodic mode syncs all live segments before teardown, and
  retains the slot on failure. Periodic also fsyncs `sf_dir`'s parent at
  build time and the slot dir's parent at lock time.
- **Validation**: `sf_sync_interval_millis` range `1..=i64::MAX/1_000_000`
  ("sf_sync_interval_millis is out of range: <v>", thrown eagerly in the
  setter — so `periodic` + `0` reports out-of-range, not
  requires-periodic); key requires `sf_durability=periodic`; periodic
  requires `sf_dir`; WS transport only; default **5000 ms applied only in
  periodic mode**. `flush`/`append` rejection message becomes "... (use
  sf_durability=memory or periodic)".
- **Explicitly NOT in the checkpoint**: watermark, manifest, directories,
  hot spare — each has its own barrier path (Rust already has these from
  milestone 3). `request_durable_ack` is fully orthogonal (server-side
  durability; README says use both for end-to-end).

### 4.2 Rust mapping

**Config** (`ingress.rs` + `conf.rs`): add `Periodic` to `SfDurability` +
parser (allowed-values list gains `periodic`); new key parsed as i64 with
the Java range/messages via a private setter (copy the
`durable_ack_keepalive_interval_millis` pattern); build-time cross-checks
(requires-periodic, periodic-requires-sf_dir, WS-only via the existing
idiom); default applied only in periodic; update both rejection guards
(`ingress.rs:3171`, `qwp_ws.rs:1776`) to the new message and flip
`ingress/tests.rs:579-588`; add the key to the reader-side accepted list
(`egress/config.rs:560-566`) and the rustdoc key list (`ingress.rs:994`).
The pool conf walker passes `sf_*` through already.

**Scheduling**: Rust has no shared manager — the per-sender runner is the
worker, which simplifies everything to one ring. Copy the keepalive
due-check pattern (`last_*: Option<Instant>` + interval compare); state
lives beside the queue: `next_sync: Instant`, `sync_requested: AtomicBool`.
No wakeup plumbing needed — the runner polls at 50 µs idle, so a
gate-requested sync starts within ~50 µs.

**Checkpoint**: a new `SfaStorageStep::SyncPublished(Vec<Arc<SfaSharedSegment>>)`
riding the existing take/perform/finish split — collect under the lock
(frontier index + active, reused scratch), msync/fsync **off-lock**,
finish under the lock (clear latch on full success, re-arm deadline,
clear `sync_requested` if the active is durable). Per-segment
`durable_cursor: AtomicU64` on `SfaSharedSegment`. Needs one new segment
helper: `sync_published_range` (mapping `flush_range(0..published)` +
`file.sync_data()`), following the existing `sync_header` shape.

**Rotation gate**: in the producer-side rotate path — one `Acquire` load
comparing the active's `durable_cursor` to `published_offset`; not durable
⇒ set `sync_requested`, return the existing backpressure error. The
producer's normal backpressure wait (append deadline) does the rest.

**Latch**: `durability_failed: AtomicBool` + the error stored under the
state lock. Append checks the flag first (one `Acquire` load, never set
outside periodic mode); flush/await surfaces the stored error repeatably
until a healed pass clears it.

**Recovery/close hooks**: queue open with periodic + recovered segments ⇒
synchronous sync-all-live before returning (fail the open on bad disk);
undrained close in periodic ⇒ sync live segments before teardown, retain
slot on failure (the spot milestone 3's close design reserved); parent-dir
fsyncs at build/lock time; verify the hot-spare install already does
header-sync + dir-fsync from milestone 3 and add the dir fsync if missing.

### 4.3 Departures from Java (deliberate, record any others)

1. **mlock/re-dirty**: port the re-dirty-on-failure (portable, it's what
   makes latch-clearing sound). Port `mlock`/`munlock` on Unix via libc;
   **skip the page pin on Windows** (Java treats mlock refusal as a
   soft-degrade with one warning anyway — we take that path always on
   Windows). Revisit if a Windows power-loss torture test ever exists.
2. Java's global `shortestSyncIntervalNanos` park budget doesn't map —
   one ring per runner; the 50 µs idle poll already outpaces it.
3. The 1 s retry cap becomes a named constant.

### 4.4 Hot/cold classification

Per-frame append: **+1 `Acquire` load** (latch flag) — same cost Java
accepted (volatile read). Rotate path (per segment fill): +1 atomic
compare. Checkpoint: default every 5 s — msync+fsync of only the
never-yet-durable prefix per live segment, off-lock on the runner thread.
Send/receive paths: untouched.

### 4.5 Files touched

`conf.rs`, `ingress.rs` (config+validation), `qwp_ws_sfa_queue.rs`
(checkpoint step, gate, latch, open/close hooks — dominant chunk),
`qwp_ws_sfa_segment.rs` (`sync_published_range`, `durable_cursor` move if
needed), `qwp_ws.rs` (runner due-check hop), `egress/config.rs` (accepted
key), README + `doc/CONSIDERATIONS.md` + rustdoc (mirror Java's "target,
not a guarantee" wording), `cpp_test/test_column_sender.cpp`
(validation-only conf-string tests through the C boundary — no new infra).
No FFI code, no header code.

### 4.6 Tests (porting Java's pinned suite)

- Rotation-gate mutant-killer with Java's three kill points: gated append
  returns backpressure *while a spare is installed*; the requested sync
  runs on the next pass before the deadline; the retried append rotates.
- Sync-pass stops at first failure, healed retry covers all segments
  (barrier-count assertions via the milestone 3 test recorder seam,
  extended with failure injection).
- Transient failure: latch set ⇒ appends/flush fail with the same error
  instance repeatedly ⇒ success clears ⇒ appends resume. Failed append
  must not advance published FSN.
- Re-dirty before unlatch (model fsyncgate: consumed-error retry must not
  vacuously succeed).
- Config matrix: default 5000 only in periodic; out-of-range (0, max+1);
  requires-periodic; periodic-requires-sf_dir; TCP/HTTP rejection;
  error-message ordering (`periodic` + `0` ⇒ out-of-range).
- Recovered-slot baseline sync (including MEMORY→PERIODIC upgrade of an
  existing slot); undrained close syncs the active, failure retains slot.
- cpp_test: bad interval and requires-periodic surface as ConfigError
  through the C API.

### 4.7 Implementation record — 2026-07-30

Milestone 4 is implemented as an uncommitted working-tree change. The
configuration surface matches Java (`periodic`, the 5000 ms effective
default, eager signed-range validation and ordering, WS/sf-dir cross-checks);
the checkpoint rides the existing take/perform/finish storage split with a
reused segment scratch vector; rotation requests an immediate checkpoint and
returns ordinary backpressure; and the durability latch is checked before an
FSN is reserved. Recovery, orphan adoption and undrained close all carry the
periodic interval and establish the required covering syncs. C and C++ use the
configuration-string path unchanged — no FFI or header code was added.

Blocker-focused review added two race/scheduler guards beyond the initial
mapping:

1. A pending rotation request may override the normal cadence, but not the
   `min(interval, 1 s)` delay after a failed checkpoint. The deterministic
   failure test now proves there is no immediate retry spin.
2. An off-lock checkpoint batch is marked in flight. Background close waits
   for its segment owners to return before tearing down mappings, unlinking
   files or releasing the slot lock.

Recorded implementation departures:

1. The next deadline is represented as `last_sync_completed + delay` during
   comparison rather than storing an absolute future `Instant`. This accepts
   Java's maximum valid interval without risking `Instant` overflow while
   retaining completion-relative scheduling.
2. Parent-directory barriers use the existing `sync_directory` abstraction:
   real directory fsync on Unix and the existing no-op on Windows, where this
   codebase has no portable directory-handle sync. Windows still gets
   `FlushViewOfFile` through memmap plus `FlushFileBuffers` through
   `File::sync_data`; Unix additionally uses best-effort mlock/munlock.

Validation on Linux:

- `cargo fmt --all -- --check`
- `cargo clippy --features sync-sender-qwp-ws --all-targets -- -D warnings`
- production feature-only `cargo check` for
  `sync-sender-qwp-ws,tls-webpki-certs,ring-crypto`
- focused SFA suite: 141 passed, 6 ignored
- full Rust suite: 1600 unit tests passed (21 ignored), all integration suites
  passed, 48 doctests passed (3 ignored), and 3 compile-fail doctests passed
- C++17 and C++20 `test_column_sender`: 23 cases / 82 assertions passed in
  each build, including the new raw-C ConfigError test
- `git diff --check`

### Milestone 4 implementation notes (added by reviewer, 2026-07-30)

Verified faithful to the design and Java contract by adversarial
full-context review. Departures and additions the implementing agent left
unrecorded:

1. **Weaker flock retention than Java after a failed periodic close**:
   `SfaSlotQueue::close` keeps the lock on error, but `Drop` retries once
   and then releases the flock regardless. Java's retry driver holds the
   slot until process exit. Mitigations: the caller saw the close error,
   and a periodic adopter re-runs the baseline sync at open. Residual
   exposure: host power loss between drop-release and re-adoption.
2. **Rotation-requested syncs respect the 1 s failure retry delay**
   (Java re-runs them immediately even against a failing device). Rust
   bounds it deliberately to avoid busy-looping a broken disk; pinned by
   a test.
3. Undrained periodic close syncs inline under the engine state lock
   (terminal path; Java does the same).
4. Beyond-design additions (both correct): `close_drain` waits for an
   in-flight checkpoint batch before tearing down mappings, and terminal
   vs durability errors are distinguished so a latched failure cannot
   wedge close.
5. Test seam: `fail_sync_after_for_test` thread-local countdown (the
   demand-driven `#[cfg(test)]` injection for barrier-failure tests).
   Windows: mlock skipped as designed; redirty stride hardcoded 4 KiB.

Hot path verified: append +1 `Acquire` load, rotate +1 atomic compare,
send/receive untouched. Reviewer validation: 1600 tests passed (+7), fmt
clean, plain clippy clean. cpp_test not built (multi-minute build); its
two new cases use only existing, verified C symbols.

## Decisions (formerly open questions — all resolved)

- ~~Keep Java's key names verbatim?~~ **Decided: yes.** `sf_durability=periodic`
  + `sf_sync_interval_millis`, copied verbatim for cross-client config
  parity. Note: legacy ILP duration keys (`retry_timeout`,
  `auto_flush_interval`, …) are suffix-free with implied millis, but the
  SF key family already uses `_millis` in both Java and Rust
  (`sf_append_deadline_millis`), so verbatim is also internally consistent.
- ~~Should `flush`/`append` stay rejected?~~ **Decided: match Java.**
  Java itself rejects them (`Sender.java:4107`: "not yet supported (use
  sf_durability=memory or periodic)"). Implement `memory|periodic` only;
  keep `flush`/`append` parsed-but-rejected and align our error message
  with Java's wording.
- ~~Windows flush semantics~~ **Verified (memmap2 0.9.11).** `flush()` on
  Windows = `FlushViewOfFile` + `FlushFileBuffers` (full barrier); on
  Unix = `msync(MS_SYNC)` (data pages only). Steady-state checkpoints can
  use `flush()`; segment creation/rotation additionally needs
  `File::sync_all()` + parent-dir fsync on Unix for size/dirent metadata
  (mirrors Java's hot-spare header + parent-directory sync).
- ~~TLS: `close_notify` or hard shutdown?~~ **Decided: hard shutdown,
  matching Java.** Java's `closeTraffic()` bypasses the SSLEngine and
  calls `shutdown(fd, SHUT_RDWR)` on the raw fd (`PlainSocket.closeTraffic`
  → native `Net.shutdown`; `JavaTlsClientSocket` just delegates — a
  concurrent TLS send may still own the engine/buffers). Rust: call
  `TcpStream::shutdown(Both)` on the underlying socket without touching
  rustls; TLS state is freed in final close after the runner joins. Java
  treats `ENOTCONN` as success — mirror that.
- ~~Test-only lifecycle hooks?~~ **Decided: demand-driven.** Start from
  existing fault-injection seams; add a `#[cfg(test)]`-gated hook only
  when a specific Java race test cannot be reproduced without a pause
  point. Expected landing spots: runner close path (`qwp_ws.rs`) and
  `OrphanDrainerPool` shutdown — the paths milestones 1–2 change.
