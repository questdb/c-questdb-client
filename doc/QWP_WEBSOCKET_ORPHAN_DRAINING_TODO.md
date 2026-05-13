# QWP/WebSocket Orphan Draining Notes

Status: first Rust runtime slice implemented. Source rechecked against the Java
client and `docs/qwp/sf-client.md` on 2026-05-13. Keep this file as the handoff
for remaining orphan-draining follow-ups and Java-parity caveats.

This document tracks `drain_orphans=on` in the Rust QWP/WebSocket sender. It is
separate from `QWP_WEBSOCKET_DURABLE_SF_STORAGE.md` because orphan draining
depends on segment-backed SFA recovery, slot locking, ACK watermarks, reconnect
handling, and cleanup semantics.

## Current Rust State

Implemented:

- `questdb-rs/src/ingress.rs` accepts `drain_orphans=off/false/on/true`.
- `max_background_drainers` is parsed, rejects negative values, and `0`
  disables drainer launch.
- TCP/UDP configurations reject both keys as QWP/WebSocket-only.
- `questdb-rs/src/ingress/sender/qwp_ws_orphan.rs` scans sibling slot
  directories, skips the foreground `sender_id`, skips `.failed`, and requires
  at least one `.sfa` file.
- Orphan drainers acquire the orphan slot lock through the SFA slot layer. A
  locked slot is skipped without `.failed`.
- Replay-only SFA open recovers existing segments but creates no initial
  segment, no hot spare, and no producer.
- Recovery/setup/connect/wire failures write a best-effort `.failed` sentinel.
- Already-drained orphan slots close without networking.
- Background mode starts a bounded drainer pool after the foreground sender has
  opened successfully.
- Background close waits briefly for drainers to finish naturally, requests stop,
  waits a short stop grace, and then detaches any remaining worker threads so
  foreground close stays bounded.
- Manual mode exposes orphan progress through the same application-owned
  `drive_once()` pump. Publication does not secretly run orphan maintenance.

Still incomplete or intentionally different:

- There is no Java-style operator logging, drainer counter API, or
  `BackgroundDrainerListener` equivalent yet. `.failed` is currently the only
  durable operator-visible artifact.
- Rust orphan replay currently trims on ordinary OK even when the WebSocket
  connection requested durable ACK. Java and `sf-client.md` require
  durable-ACK-driven trim when `request_durable_ack=on`; this is a parity gap.
- Background worker shutdown is bounded and best-effort. Rust waits briefly,
  requests stop, waits a short stop grace, and then detaches remaining workers.
- Rust has manual orphan driving; Java only has automatic background drainers.
- Windows slot locking is still unsupported because the shared SFA slot lock is
  Unix-only today.

## Java Reference

Reference behavior lives in the Java client under:

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
  - each candidate slot gets a `BackgroundDrainer`;
  - drainers reuse `buildAndConnect()`, so the WebSocket upgrade uses the
    foreground durable-ACK request flag.
- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/BackgroundDrainer.java`
  - one drainer per orphan slot;
  - acquires the slot lock through `CursorSendEngine`;
  - skips locked slots without marking them failed;
  - opens a fresh WebSocket connection, separate from the foreground sender;
  - drains until the recovered `ackedFsn` reaches the startup snapshot of
    `publishedFsn`;
  - retries initial connect briefly on whole-cluster durable-ACK unavailability
    and writes `.failed` only after the durable-ACK mismatch budget is exhausted;
  - writes `.failed` on terminal setup, connect, reconnect, recovery, or wire
    failure.
- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/CursorWebSocketSendLoop.java`
  - the constructor used by `BackgroundDrainer` receives the foreground
    `requestDurableAck` flag;
  - orphan trim is OK-driven only when durable ACK was not requested;
  - when durable ACK was requested, OK frames are queued and trim advances only
    from `STATUS_DURABLE_ACK`, matching `sf-client.md`.
- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/BackgroundDrainerPool.java`
  - bounded pool, one pool per foreground sender;
  - concurrent execution capped by `max_background_drainers`;
  - excess candidates queue inside the pool;
  - close first waits briefly for natural drain completion, then requests active
    drainers to stop and waits a short stop grace;
  - exposes active, succeeded, and failed drainer counters;
  - supports a pool-level `BackgroundDrainerListener` for per-drainer
    observation.

## Rust Semantics

- `drain_orphans=on` is only meaningful when `sf_dir` is configured. Without
  `sf_dir`, there are no sibling slots to scan and no drainers launch.
- The foreground sender never adopts its own slot.
- Candidate orphan slot:
  - child directory under `sf_dir`;
  - child name is not the foreground `sender_id`;
  - contains at least one `.sfa` file;
  - does not contain `.failed`.
- Scanner does not decide ownership. Lock acquisition in the drainer decides
  whether this process can own the slot.
- If another process or drainer holds the orphan slot lock, skip the slot
  without creating `.failed`.
- Each drainer uses a separate WebSocket connection and its own QWP/WebSocket
  receive/send loop. It does not multiplex orphan traffic over the foreground
  sender connection.
- Drainers are read-only with respect to the orphan slot's durable data: they
  recover existing `.sfa` files and replay unacked frames, but never append new
  application frames or create storage.
- The target is the recovered `published_fsn` snapshot captured at drainer
  startup. A drainer succeeds when recovered `acked_fsn >= target_fsn`.
- Current Rust orphan replay uses ordinary OK-driven trim even when the
  connection setup uses the foreground durable-ACK upgrade opt-in. This is not
  Java/spec parity: with `request_durable_ack=on`, orphan trim must be driven by
  `STATUS_DURABLE_ACK`, and OK frames must not advance the trim watermark.
- On terminal setup, recovery, initial connect, reconnect-budget, auth, or wire
  failure, write a `.failed` sentinel in the orphan slot before exiting.
- `.failed` is an operator-visible stop sign. Future scans skip the slot until
  an operator removes the sentinel.
- `max_background_drainers=0` disables launching drainers even when
  `drain_orphans=on`.
- Closing the foreground sender requests active background drainers to stop.
  Close first gives them a bounded natural-drain window, then a bounded stop
  window. Stopping due to foreground close should release locks and must not
  write `.failed` by itself.

## Design Constraints

- Keep publication fast. Foreground publication must not scan sibling slots or
  perform orphan cleanup.
- Start orphan scanning only after the foreground sender has acquired its own
  slot lock. This preserves Java ordering and avoids adopting this sender's
  slot during startup.
- In automated Rust mode, orphan drainers may run on background threads because
  the feature is explicitly background adoption of another sender's slot.
- In manual mode, orphan draining is driven only by the application-owned
  `drive_once()` path. There is no hidden maintenance from publication.
- Do not share mutable queue state between the foreground SFA queue and orphan
  drainers. Treat each orphan slot as a separate recovered queue.
- Reuse the foreground reconnect classification and terminal-failure policy
  where possible, but keep foreground and orphan errors distinguishable.
- `.failed` creation is best-effort. Failure to write the sentinel should be
  diagnostic, not a reason to corrupt or delete the orphan data.
- Windows support is not optional long-term. Keep slot locking, directory
  scanning, sentinel creation, and mapped-file handling behind helpers that can
  grow Windows implementations.

## Remaining Work

1. Fix durable-ACK parity for orphan drainers:
   - when `request_durable_ack=on`, trim orphan slots only on
     `STATUS_DURABLE_ACK`;
   - preserve OK-driven trim when durable ACK is off;
   - handle durable-ACK-unavailable initial connect/reconnect in a way that
     matches the Java/spec failure policy;
   - add integration coverage that proves OK alone does not delete orphan data
     in durable-ACK mode.
2. Add Java-style observability:
   - candidates found;
   - slots skipped because locked;
   - successful drain with target and acknowledged FSN;
   - `.failed` reason;
   - background close stop/timeout behavior;
   - active, succeeded, and failed background-drainer counters;
   - listener or callback surface for durable-ACK mismatch and terminal drainer
     outcomes.
3. Add background-mode integration coverage that proves a recovered orphan slot
   drains to cleanup over a separate WebSocket connection, not only that a
   background drainer can replay the payload before foreground close.
4. Add explicit background-pool tests for concurrency capping.
5. Implement Windows slot locking in the shared SFA slot layer.

## Required Tests

Covered by the first runtime slice:

- Config:
  - `drain_orphans=off/false/on/true` accepted for QWP/WebSocket;
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
  - `.failed` marker is written with a reason.
- Locking and replay-only open:
  - locked orphan slot skipped without `.failed`;
  - replay-only open does not create a missing slot;
  - replay-only empty slot creates no segments or producer;
  - skipped/corrupt segments are not treated as drained.
- Manual orphan driving:
  - already-drained slot is consumed without network;
  - locked slot is skipped without `.failed`;
  - recovery failure writes `.failed` without deleting the bad `.sfa`;
  - recovered orphan frames replay over a separate connection;
  - ordinary OK advances the orphan to completion and removes drained `.sfa`
    files.

Still needed:

- Background-mode recovered orphan frames replayed to completion and cleaned up
  over a separate connection.
- Durable-ACK opt-in interaction covered by an integration test, including the
  negative case that OK frames alone do not trim in durable-ACK mode.
- Initial connect failure writes `.failed`.
- Terminal reconnect/auth/wire failure writes `.failed`.
- Foreground close stops active drainers without writing `.failed` in the
  durable-ACK/reconnect cases, beyond the existing stalled-background close
  coverage.
- Background concurrency capped by `max_background_drainers`.
- Java-style drainer counters/listener behavior.
- `.failed` orphan remains untouched until the sentinel is removed.

## Non-Goals

- Do not add best-effort foreground fallback draining from publication.
- Do not silently delete orphan directories that do not match the candidate
  rules.
- Do not retry `.failed` slots automatically.
- Do not share the foreground WebSocket connection with drainers.
- Do not treat the current Unix-only slot-locking limitation as the final
  platform story. Windows support is deferred, not rejected.
