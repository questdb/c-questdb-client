# QWP/WebSocket Orphan Draining TODO

Status: follow-up after segment-backed durable Store-and-Forward storage.

This document tracks the Java-parity work needed to implement
`drain_orphans=on` in the Rust QWP/WebSocket sender. It is intentionally
separate from `QWP_WEBSOCKET_DURABLE_SF_STORAGE.md`: orphan draining depends on
segment-backed SFA recovery, slot locking, ACK watermarks, reconnect handling,
and cleanup semantics being correct first.

## Current Rust State

Rust does not drain orphan slots today.

- `questdb-rs/src/ingress.rs` accepts `drain_orphans=off` and
  `drain_orphans=false`.
- `drain_orphans=on` and `drain_orphans=true` are rejected with an unsupported
  QWP/WebSocket message.
- `max_background_drainers` is parsed and validated as `>= 0`, but has no
  runtime effect while orphan draining is disabled.
- TCP/UDP configurations still reject both keys as QWP/WebSocket-only.

Keep that behavior until this TODO is implemented. Do not silently accept
`drain_orphans=on` before real orphan adoption exists.

## Java Reference

The reference behavior is in the Java client under:

- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/Sender.java`
  - builder defaults: `drainOrphans=false`,
    `maxBackgroundDrainers=DEFAULT_MAX_BACKGROUND_DRAINERS`;
  - config parsing: `drain_orphans`, `max_background_drainers`;
  - connect path: after the foreground sender has acquired its own slot lock,
    scan sibling slots and start drainers when `drainOrphans && sfDir != null`.
- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/OrphanScanner.java`
  - scans child directories of `sf_dir`;
  - excludes the foreground `sender_id`;
  - treats a slot as a candidate when it contains at least one `.sfa` file and
    no `.failed` sentinel;
  - missing or unenumerable `sf_dir` returns no candidates, with a warning on
    enumeration failure.
- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/QwpWebSocketSender.java`
  - `startOrphanDrainers(...)` creates a bounded drainer pool when the orphan
    list is non-empty and `max_background_drainers > 0`;
  - each candidate slot gets a `BackgroundDrainer`.
- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/BackgroundDrainer.java`
  - one drainer per orphan slot;
  - acquires the slot lock through `CursorSendEngine`;
  - skips locked slots without marking them failed;
  - opens a fresh WebSocket connection, separate from the foreground sender;
  - drains until the recovered `ackedFsn` reaches the startup snapshot of
    `publishedFsn`;
  - writes `.failed` on terminal setup, connect, reconnect, recovery, or wire
    failure.
- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/BackgroundDrainerPool.java`
  - bounded pool, one pool per foreground sender;
  - concurrent execution capped by `max_background_drainers`;
  - excess candidates queue inside the pool;
  - close requests active drainers to stop and waits briefly.

## Target Rust Semantics

Implement Java-like semantics unless an item below explicitly says otherwise.

- `drain_orphans=on` is only meaningful when `sf_dir` is configured. Java
  accepts the setting without `sf_dir`, but the startup path has no sibling
  slots to scan and launches no drainers.
- The foreground sender never adopts its own slot.
- Candidate orphan slot:
  - child directory under `sf_dir`;
  - child name is not the foreground `sender_id`;
  - contains at least one `.sfa` file;
  - does not contain `.failed`.
- Scanner does not decide ownership. It only finds candidates. Lock acquisition
  in the drainer decides whether this process can own the slot.
- If another process or drainer holds the orphan slot lock, skip the slot
  without creating `.failed`.
- Each drainer uses a separate WebSocket connection and its own QWP/WebSocket
  receive/send loop. Do not multiplex orphan traffic over the foreground
  sender connection.
- Drainers are read-only with respect to the orphan slot's durable data: they
  recover existing `.sfa` files and replay unacked frames, but never append new
  application frames.
- The target is the recovered `published_fsn` snapshot captured at drainer
  startup. A drainer succeeds when recovered `acked_fsn >= target_fsn`.
- On terminal setup, recovery, initial connect, reconnect-budget, auth, or wire
  failure, write a `.failed` sentinel in the orphan slot before exiting.
- `.failed` is an operator-visible stop sign. Future scans skip the slot until
  an operator removes the sentinel.
- `max_background_drainers=0` disables launching drainers even when
  `drain_orphans=on`, matching Java's `startOrphanDrainers(...)` early return.
- Closing the foreground sender must close the drainer pool and request active
  drainers to stop. Stopping due to foreground close should release locks and
  must not write `.failed` by itself.

## Design Constraints

- Keep publication fast. Foreground publication must not scan sibling slots or
  perform orphan cleanup.
- Start orphan scanning only after the foreground sender has acquired its own
  slot lock. This preserves the Java ordering and avoids adopting this sender's
  slot during startup.
- In automated Rust mode, orphan drainers may run on background threads because
  the feature is explicitly background adoption of another sender's slot.
- In manual mode, do not introduce hidden maintenance from publication. If
  Rust supports orphan draining in manual mode, the application-owned pump must
  drive it explicitly and the one-pump-owner rule still applies.
- Do not share mutable queue state between the foreground SFA queue and orphan
  drainers. Treat each orphan slot as a separate recovered queue.
- Reuse the foreground reconnect classification and terminal-failure policy
  where possible, but keep foreground and orphan errors distinguishable.
- `.failed` creation is best-effort. Failure to write the sentinel should be
  diagnostic, not a reason to corrupt or delete the orphan data.
- Windows support is not optional long-term. The first implementation may follow
  the current Unix-only slot-locking support, but orphan draining must not bake
  in assumptions that make Windows adoption harder later. Keep slot locking,
  directory scanning, sentinel creation, and mapped-file handling behind narrow
  helpers that can grow Windows implementations.

## Implementation Checklist

1. Add runtime QWP/WebSocket config fields for:
   - `drain_orphans: bool`;
   - `max_background_drainers: usize`.
2. Preserve current validation:
   - reject these keys for non-QWP/WebSocket protocols;
   - reject negative `max_background_drainers`;
   - keep `drain_orphans=on` unsupported until the full runtime path exists.
3. Add an orphan scanner:
   - scan `sf_dir` children once;
   - skip missing `sf_dir`;
   - log or otherwise surface enumeration failures;
   - exclude current `sender_id`;
   - require at least one `.sfa`;
   - skip `.failed`.
4. Add `.failed` sentinel helpers:
   - constant name `.failed`;
   - idempotent marker creation with short human-readable reason;
   - scanner exclusion test.
5. Add a read-only orphan recovery/drain engine:
   - acquire the orphan slot lock;
   - distinguish "already locked" from terminal recovery failures;
   - recover published and acknowledged FSN;
   - expose a segment cursor over unacked frames;
   - forbid appending.
6. Add the drainer loop:
   - establish a separate WebSocket connection;
   - send orphan frames from the recovered cursor;
   - receive durable ACKs through the same QWP/WebSocket pump used by the
     foreground sender;
   - stop when `acked_fsn >= target_fsn`;
   - map terminal failures to `.failed`.
7. Add a bounded drainer pool:
   - cap concurrent drainers by `max_background_drainers`;
   - queue excess candidates behind the concurrency cap;
   - close by requesting active drainers to stop and waiting for lock release.
8. Hook startup:
   - after foreground slot lock acquisition and successful connection;
   - scan once;
   - launch drainers if `drain_orphans=on`, `sf_dir` is set, candidates exist,
     and `max_background_drainers > 0`.
9. Hook shutdown:
   - foreground sender close closes the drainer pool;
   - stopped drainers release locks;
   - stopped-by-owner-close is not a failed orphan.
10. Add diagnostics:
   - number of candidates found;
   - slots skipped because locked;
   - successful drain with target and acknowledged FSN;
   - `.failed` reason;
   - pool close timeout, if any.

## Required Tests

- Config:
  - `drain_orphans=off/false` still accepted;
  - `drain_orphans=on/true` accepted only after runtime implementation lands;
  - invalid boolean values rejected;
  - non-QWP/WebSocket protocols reject both keys;
  - `max_background_drainers=-1` rejected;
  - `max_background_drainers=0` disables drainer launch.
- Scanner:
  - missing `sf_dir` returns no candidates;
  - own `sender_id` excluded;
  - child without `.sfa` excluded;
  - child with `.sfa` included;
  - child with `.failed` excluded;
  - `.failed` marker is idempotent.
- Locking:
  - locked orphan slot skipped without `.failed`;
  - unlocked orphan slot acquired and released;
  - foreground slot is never adopted.
- Drain success:
  - recovered orphan frames replayed over a separate connection;
  - durable ACKs advance `acked_fsn`;
  - success when `acked_fsn >= target_fsn`;
  - drained files are cleaned up according to the normal close-drain cleanup
    rules.
- Failure:
  - recovery failure writes `.failed`;
  - initial connect failure writes `.failed`;
  - terminal reconnect/auth/wire failure writes `.failed`;
  - foreground close stops active drainers without writing `.failed`.
- Pool:
  - concurrency capped by `max_background_drainers`;
  - excess slots are not run concurrently above the cap;
  - closing the pool races safely with in-flight submission.
- Integration:
  - create data with one `sender_id`, open another with `drain_orphans=on`,
    and verify orphan data is delivered;
  - `.failed` orphan remains untouched until the sentinel is removed.

## Non-Goals For The First Storage Slice

- Do not implement orphan draining before segment-backed SFA storage and ACK
  recovery are correct.
- Do not add best-effort foreground fallback draining from publication.
- Do not silently delete orphan directories that do not match the candidate
  rules.
- Do not retry `.failed` slots automatically.
- Do not share the foreground WebSocket connection with drainers.
- Do not treat the current Unix-only slot-locking limitation as the final
  platform story. Windows support is deferred, not rejected.
- Do not make the first Rust implementation more aggressive than Java. If Rust
  intentionally diverges, document the difference in the parity gaps doc before
  enabling the feature.
