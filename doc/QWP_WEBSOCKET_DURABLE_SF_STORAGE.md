# QWP/WebSocket durable Store-and-Forward storage design

Date: 2026-05-06 (updated 2026-05-07)

Status: design handover. The bulk of the design is implemented on this branch:
mmap-backed SFA segments via `memmap2`, fast `crc32c`, segment-backed queue
state with `allocated_segment_bytes` and a `hot_spare`, an `SfaSendCursor` send
path, `StorageSpareNotReady`/`StorageSegmentCapFull` backpressure, and parsed
`sf_append_deadline_millis`. The document is kept as a target/spec reference
and as a checklist for what still needs verification or tightening (close-drain
parity, orphan draining, fsync modes, Windows). Re-check every source reference
before implementing on another branch; both the Rust and Java clients are
moving.

## Purpose

Close the durable Store-and-Forward storage gap without conflating three
separate concepts:

- **disk-backed S&F**: frames are written to `.sfa` files and can be replayed
  after process restart;
- **durable ACK**: server OKs do not complete local storage until WAL durability
  watermarks cover them;
- **fsync durability modes**: `sf_durability=flush` and `sf_durability=append`
  explicitly flush client-side segment bytes to stable storage.

Rust now has disk-backed `.sfa` recovery, durable ACK completion, and a
segment-backed queue: the active/sealed/hot-spare segments are owned through
mmap-backed handles, `sf_max_total_bytes` accounts for allocated segment bytes,
and replay walks segment storage with `SfaSendCursor` rather than retaining
heap payload copies.

The remaining work tracked here is around the edges of that model: close-drain
parity with Java, orphan draining, fsync durability modes, and Windows slot
locking. `sf_durability=flush` and `sf_durability=append` remain rejected until
those modes are explicitly designed.

## Current Rust State

Configuration:

- `questdb-rs/src/ingress/conf.rs:129-143` defines `SfDurability::{Memory,
  Flush, Append}`.
- `questdb-rs/src/ingress/conf.rs:203-208` defaults `sf_dir` to unset and
  `sf_durability` to `memory`.
- `questdb-rs/src/ingress/conf.rs:215-225` picks a different default
  `sf_max_total_bytes` depending on whether `sf_dir` is set.
- `questdb-rs/src/ingress.rs:2029-2042` parses `memory`, `flush`, and
  `append`.
- `questdb-rs/src/ingress.rs:2060-2066` rejects non-`memory` durability.
- `questdb-rs/src/ingress/sender/qwp_ws.rs:807-812` also rejects non-`memory`
  before opening the queue.

Queue selection:

- `questdb-rs/src/ingress/sender/qwp_ws.rs:800-803` has memory and
  Store-and-Forward queue variants.
- `questdb-rs/src/ingress/sender/qwp_ws.rs:819-836` opens `SfaSlotQueue` when
  `sf_dir` is configured.
- `questdb-rs/src/ingress/sender/qwp_ws.rs:815-827` passes
  `sf_max_total_bytes` as `max_bytes`.
- `questdb-rs/src/ingress/sender/qwp_ws.rs:856-861` derives `max_frames` from
  ceiling division of `sf_max_total_bytes / sf_max_bytes`, then raises it to at
  least `max_in_flight`.

Slot and file behavior:

- `questdb-rs/src/ingress/sender/qwp_ws_sfa_slot.rs` creates
  `<sf_dir>/<sender_id>`, takes the slot lock, and opens `SfaFrameQueue`. Slot
  locking uses Unix `flock`; non-Unix still returns unsupported.
- `questdb-rs/src/ingress/sender/qwp_ws_sfa_segment.rs` sizes a fresh segment
  with `set_len()`, writes the Java-compatible header, and then appends frames
  through the mmap mapping (CRC last, append offset published last).
- `questdb-rs/src/ingress/sender/qwp_ws_codec.rs` prepares a WebSocket frame
  in a `Vec<u8>` and masks byte by byte; that is a known later-performance
  follow-up, not part of the storage slice.

Implemented since the original handover (verify before relying on exact line
numbers):

- `questdb-rs/src/ingress/sender/qwp_ws_sfa_segment.rs` appends through a
  `memmap2::MmapMut` mapping; CRC-last publish semantics are unchanged.
- Production CRC32C uses the `crc32c` crate over borrowed mapped slices; the
  bit-at-a-time loop only survives as a tiny test oracle if at all.
- `questdb-rs/src/ingress/sender/qwp_ws_sfa_queue.rs` owns
  `active`/`sealed_segments`/`hot_spare` segment handles plus
  `allocated_segment_bytes`. `sf_max_total_bytes` is the allocated-segment
  cap; recovered bytes seed the accounting.
- Send/replay walks segment bytes with `SfaSendCursor`; no `Arc<[u8]>` payload
  retention or per-frame Rust descriptor table on the production path.
- Hot-spare provisioning, promotion on rotation, and one-segment-per-call trim
  are folded into the driver's `drive_once()` pump. `try_publish()` does not
  provision storage.
- Append-path backpressure is exposed as `StorageSpareNotReady` and
  `StorageSegmentCapFull`. The runner waits up to `sf_append_deadline_millis`
  before reporting an actionable timeout.

Remaining gaps tracked by this document:

- Close-drain parity with Java's default `close_flush_timeout_millis` is still
  out of scope for this slice.
- Orphan draining has a first runtime slice; remaining diagnostics, integration
  tests, shutdown semantics, and Windows support are tracked in
  `doc/QWP_WEBSOCKET_ORPHAN_DRAINING_TODO.md`.
- `sf_durability=flush`/`append` stay rejected; see Slice 9.
- Windows slot locking is still unsupported; the queue/driver APIs avoid Unix
  assumptions so it can be added without a redesign.
- Trim and close cleanup diagnostics (Slice 7) should be re-audited end to end
  for parity with Java's logging/skip behavior.

## Java Reference

Durability modes:

- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/Sender.java:552-570`
  documents `SfDurability`.
- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/Sender.java:1068-1072`
  rejects non-`memory` today.
- `/home/jara/devel/oss/questdb-arrays/docs/qwp/sf-client.md:897-901`
  says `flush` and `append` are deferred.

Segment-backed storage:

- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/MmapSegment.java:118-147`
  creates a fixed-size segment and writes its header through the mapping.
- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/MmapSegment.java:195-258`
  opens an existing segment, validates it, scans frames, and positions cursors.
- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/MmapSegment.java:355-391`
  appends without syscall or allocation on the hot path and publishes the cursor
  last.
- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/CursorWebSocketSendLoop.java:974-992`
  sends directly from the segment mapping.
- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/CursorWebSocketSendLoop.java:890-910`
  positions the send cursor by finding the segment for a target FSN and scanning
  frame headers within that segment.
- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/SegmentRing.java:489-520`
  lets the I/O loop advance between sealed segments without building a per-frame
  index.

CRC32C:

- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/std/Crc32c.java:27-33`
  documents the implementation as software/native slice-by-8.
- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/std/Crc32c.java:66`
  exposes the native `update(seed, addr, len)` entry point used for mapped or
  direct-memory ranges.

WebSocket send/masking:

- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/http/client/WebSocketClient.java:365-372`
  copies the selected payload range into the native WebSocket send buffer.
- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/websocket/WebSocketFrameWriter.java:75-105`
  applies the client mask with 8-byte and 4-byte chunks, then tail bytes.
- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/http/client/WebSocketSendBuffer.java:153-170`
  writes frame metadata and masks the payload in the send buffer.

Capacity and rotation:

- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/SegmentManager.java:100-114`
  defines `maxTotalBytes` as allocated segment bytes: active, sealed, hot
  spare, and recovered/orphan-adopted files.
- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/SegmentManager.java:180-189`
  seeds that accounting from recovered ring state.
- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/SegmentManager.java:286-296`
  refuses to provision another full segment when it would exceed the cap.
- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/SegmentRing.java:327-387`
  rotates to a hot spare when active fills and publishes `publishedFsn` last.
- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/SegmentRing.java:586-597`
  reports total owned segment bytes.

Backpressure:

- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/CursorSendEngine.java:288-316`
  waits up to `sf_append_deadline_millis` when append hits segment
  backpressure.
- `/home/jara/devel/oss/questdb-arrays/docs/qwp/sf-client.md:747-755`
  specifies that full storage waits for ACK-driven trim until the append
  deadline expires.

Recovery and close:

- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/SegmentRing.java:210-222`
  skips bad `.sfa` side files with a warning.
- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/SegmentRing.java:241-269`
  sorts valid segments, validates contiguous FSNs, and makes the newest segment
  active.
- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/SegmentManager.java:370-381`
  logs trim/unlink failures and continues.
- `/home/jara/devel/oss/questdb-arrays/docs/qwp/sf-client.md:765-782`
  defines Java close-drain behavior and the default close timeout.

## Target Shape

### Target contract

When `sf_dir` is set and `sf_durability=memory`:

- a submit is locally published only after its QWP payload is committed to an
  `.sfa` segment;
- append and replay use mmap-backed segment storage, not `seek`/`write_all`
  as the steady-state storage primitive;
- SFA send/replay walks segment bytes with a cursor, not a per-frame Rust
  descriptor table;
- CRC32C is computed with a performance-oriented implementation, not the
  bit-at-a-time reference loop;
- unresolved frames survive process restart if the OS has retained the file
  contents;
- replay reads from segment storage, not from a retained heap copy of every
  queued payload;
- replay/send does not add a file-backed scratch path that reads each payload
  into an owned `Vec<u8>`;
- `sf_max_total_bytes` means allocated segment bytes;
- recovered segment bytes count against the cap;
- if recovered bytes are already at or above the cap, startup still succeeds,
  but no new segment can be allocated until ACK-driven trim frees space;
- completing durable ACK progress trims fully completed sealed segments;
- unexpected unlink/trim failures are observable but should not convert an
  already-acked segment cleanup problem into delivery failure;
- `sf_durability=flush` and `sf_durability=append` remain rejected.

### Preferred Rust simplification

Do not port Java's background `SegmentManager` first. This does not mean the
default sender has no background activity: automated mode still uses the
existing client-owned runner thread. The simplification is that storage
maintenance is folded into the runner's single progress pump instead of being
owned by a separate segment-manager thread.

Do keep the important Java idea: rotation should usually promote an already
prepared hot spare rather than create a segment on the append that filled the
active segment.

Use a queue-local hot spare:

1. `SfaFrameQueue` owns `active`, `sealed_segments`, `hot_spare`, and
   `allocated_segment_bytes`.
2. Opening a queue creates or recovers the active segment and, if the cap allows
   it, prepares one hot spare.
3. Appending first tries the active segment.
4. If active is full and a hot spare exists, promote it immediately, move the
   old active to sealed, rebase/write the spare's real `base_seq`, and append.
5. After promotion, mark that another spare is needed.
6. If active is full and no spare exists, report backpressure. Do not create a
   segment on the append path.

Do not store one Rust descriptor per unresolved SFA frame. The SFA queue state
is segment state; the send state is a cursor over segment bytes. That matches
Java's cursor shape and avoids O(number of unresolved frames) memory when a
sender queues many tiny frames.

Hot-spare file lifecycle should match Java:

- spares are ordinary `.sfa` files named `sf-<generation:016x>.sfa`;
- spares must not use `sf-initial.sfa`;
- a spare's header `base_seq` is provisional while the spare is empty;
- a spare counts in `allocated_segment_bytes` while the process owns it;
- promotion rewrites the spare header with the real `base_seq` before the first
  append;
- recovery treats frame-count-zero files as abandoned spares: clean empty files
  are removed, and empty torn files are quarantined as `.corrupt`;
- recovery treats non-empty valid files as recovered segments;
- recovery still skips bad side files and still fails on a real gap in the
  surviving valid non-empty FSN chain;
- new spare generation must skip past every existing `sf-<generation>.sfa`
  name before creating a file, so a fresh spare never truncates recovered state.

This avoids the worst tail-latency cliff of pure synchronous rotation while
staying simpler than Java's global/background `SegmentManager`. It also keeps
concurrency control simple: all segment provisioning happens in one progress
place, not opportunistically from producer append.

There should not be a public or driver-visible `queue.maintain_storage()`
lifecycle entry point. Storage maintenance is a private phase of the driver's
single progress pump. Keep the current semantic `DriveOutcome` style
(`Sent`, `Acked`, `Rejected`, `Reconnected`, `Progress`, `Idle`, `Terminal`);
do not add a separate `Backpressured` drive outcome. Storage backpressure is a
publication/queue result, not a progress-pump result.

```rust
fn drive_once(&mut self) -> Result<DriveOutcome, DriverError>;
```

`drive_once()` should do available transport work and bounded physical storage
maintenance in a fixed order:

1. send at most one outbound frame;
2. consume ready receive frames until idle and apply OK/durable ACK progress;
3. trim completed sealed segments;
4. ensure or replenish the queue-local hot spare when needed and under cap;
5. if no send, receive, trim, or spare-provisioning progress happened, send a
   durable-ACK keepalive if due;
6. return whether it made progress, is idle, or became terminal.

The storage-maintenance bound is part of the contract. One `drive_once()` call
may perform at most one heavy physical storage operation:

- provision one missing hot spare; or
- close/unmap/unlink one trim-eligible sealed segment.

It must not create multiple spares or physically trim an unbounded number of
segments in one call. This bound applies to physical storage work, not to the
ready-receive drain: `drive_once()` may still consume ready receive frames until
the transport reports idle and apply all ACK state changes discovered that way.
Physical cleanup is paced across repeated progress calls. If storage
maintenance did work, return progress so automated and manual callers continue
driving until idle.

This is a deliberate Java deviation. Java's `SegmentManager` can drain and
physically trim every currently eligible sealed segment in one service pass
because that work runs on the segment-manager thread, not on the WebSocket I/O
thread. In this Rust design, physical storage maintenance runs on the same
runner that sends frames, receives ACKs, reconnects, and sends durable-ACK
keepalives. Bounding physical trim to one segment per `drive_once()` prevents a
large ACK from turning into an unbounded I/O-thread cleanup stall. The cost is
that Rust may free segment-cap headroom over multiple progress turns after a
large ACK. That is accepted until profiling proves a separate storage worker is
needed.

Default automated mode starts a runner thread that owns this pump. When
`drive_once()` reports progress, the runner should immediately call it again;
when it reports idle, the runner can park briefly or wait for external work.
This is the Java-like default: users do not have to call a storage maintenance
API, and the runner keeps spares warm as part of normal send/receive progress.

Manual mode is explicitly selected by users who do not want the client-owned
runner thread. It uses the same pump, but the user owns scheduling and
serialization. There may still be an application-owned progress thread calling
`drive_once()`, but there must be only one pump owner at a time. Safe Rust's
`&mut Sender` API enforces this shape for Rust callers; FFI/C++ users must get
the same rule from the public thread-safety contract and their own locking. If
`drive_once()` reports progress, the pump owner is expected to call it again
until it reports idle. If the application does not drive progress often enough,
publication may return backpressure until the next progress call provisions the
spare or trims acknowledged storage.

Keep `try_publish()` for now, but treat it as an internal append primitive, not
as the lifecycle boundary. The primitive append path must not perform storage
maintenance. It may only append to active storage, promote an already-prepared
hot spare, or report backpressure. This preserves the hot-path invariant and
avoids introducing a second segment-provisioning path with different locking
and error handling.

Higher-level APIs with an explicit blocking or waiting contract differ by mode:

- In automated mode, publication backpressure waits for the runner to make
  progress or until `sf_append_deadline_millis` expires. The publishing thread
  must not call `drive_once()` because the runner owns the transport and pump.
- In manual mode, the caller that currently has exclusive ownership of the
  manual sender/pump may loop around `try_publish()` and `drive_once()` until it
  publishes, hits a terminal error, or expires `sf_append_deadline_millis`. This
  includes explicit wait/flush/close paths and application-owned progress
  threads, but not concurrently.

That is intentionally different from secretly doing maintenance inside
`try_publish()`: the primitive append path must not hide progress work.

### Pre-implementation decisions

Dependency policy:

- Add `memmap2 = "0.9"` for mapped segment IO. Wrap unsafe map creation inside
  the SFA segment module; higher layers should only see safe segment handles and
  bounded payload views.
- Add `crc32c = "0.6"` for CRC-32C/Castagnoli. Use its append/chaining API for
  `[payload_len_le][payload]` without copying mapped bytes into a temporary
  buffer.
- Do not use `crc32fast`: it implements IEEE CRC32, not CRC32C/Castagnoli.
- These are ordinary Cargo dependencies. No extra system tooling should be
  required, but the first build may need Cargo to fetch the new crates.

Platform scope:

- The first implementation may keep the current effective SFA platform support:
  Unix works through the existing slot lock, and non-Unix remains cleanly
  unsupported until slot locking is implemented there.
- Do not bake Unix assumptions into queue or driver APIs. Keep slot locking,
  directory operations, mmap creation, and file cleanup behind narrow helpers so
  Windows support can be added later without redesigning the queue.
- `memmap2` is chosen partly because it has a cross-platform API; the remaining
  Windows blocker is the sender's slot/file lifecycle, not the concept of mapped
  segment storage.

Diagnostic surface:

- For this storage slice, cleanup/recovery diagnostics are internal and
  test-visible, not a new public API.
- Add a small SFA diagnostic event path for cases that stop being delivery
  errors, such as unlink failure after successful close/unmap or skipped bad
  side files.
- Tests must assert those diagnostics. Production logging or callbacks can be a
  later API decision; do not silently drop cleanup failures in the
  implementation just because Rust has no logging surface here today.

Append-deadline contract:

- Represent storage append pressure internally as:
  - `SpareNotReady`: active is full, cap allows another segment, but the pump
    has not provisioned a spare yet;
  - `SegmentCapFull`: active is full and allocated segment bytes are at or above
    the cap.
- On deadline expiry, report an actionable storage error, not
  payload-too-large.
- `SpareNotReady` timeout text should point at progress scheduling: in automated
  mode the runner is expected to make progress; in manual mode the application
  must call `drive_once()` until idle.
- `SegmentCapFull` timeout text should point at ACK/trim/cap state: storage is
  full until ACK progress allows trim, or the user increases
  `sf_max_total_bytes`.

Implementation granularity:

- Do not land this as one broad rewrite. Each slice should compile and keep the
  existing focused QWP/WebSocket SFA tests green.
- Start with the metadata-scan refactor. It is the smallest slice that can prove
  recovery no longer needs owned payload vectors or a production per-frame
  descriptor table.
- Add mmap and fast CRC only after that metadata shape is in place.

## Required Implementation Slices

### Slice 1: Make SFA segment metadata and cursors first-class

Add enough segment metadata to avoid treating queued payload bytes, or queued
frame descriptors, as the durable queue state.

Suggested internal shape:

```rust
struct SfaSegmentHandle {
    path: PathBuf,
    base_seq: u64,
    frame_count: u64,
    size_bytes: u64,
    published_offset: u64,
    // file handle + mmap owner
}

struct SfaFrameQueue {
    active: Arc<SfaSegmentHandle>,
    sealed_segments: VecDeque<Arc<SfaSegmentHandle>>,
    hot_spare: Option<Arc<SfaSegmentHandle>>,
    allocated_segment_bytes: u64,
    published_fsn: Option<u64>,
    completed_fsn: Option<u64>,
}

struct SfaSendCursor {
    segment: Arc<SfaSegmentHandle>,
    offset: u64, // frame header offset inside `segment`
    fsn: u64,
}
```

The frame queue should keep segment ownership and ACK watermarks, not
`Arc<[u8]>` payloads and not one `SfaQueuedFrame` per unresolved frame. Recovery
should populate active/sealed segments with base sequence, frame count, published
offset, torn-tail information, and allocated byte accounting. It should not
retain `Vec<u8>` for every payload and should not build a full frame-offset
table for production.

`scan_segment_bytes()` currently returns owned `Vec<u8>` payloads. Split the
scanner into:

- a metadata scan for production recovery: base sequence, frame count, append
  offset, torn-tail information;
- a payload-copying scan for tests and Java fixture assertions.

Keep the CRC-last recovery semantics unchanged.

### Slice 2: Make SFA segment IO mmap-backed

Replace the current `seek`/`write_all` segment implementation with a mapped
segment object. This is required for Java-like performance; a file-write segment
plus better accounting would still leave Rust with a syscall-heavy append path.
Use `memmap2`; do not hand-roll platform mmap wrappers in this slice.

The mapped segment should own:

- the file handle;
- the mapping;
- the immutable segment capacity;
- the published append offset;
- enough metadata to validate that payload slices never read past published
  bytes.

Append writes payload length, payload bytes, and CRC through the mapping, then
publishes the new append offset last. Recovery scans the mapping and returns
segment metadata. Replay obtains payload slices from the same mapping by walking
the `SfaSendCursor`.

Do not add a per-send file-read fallback for durable SFA payloads. That would
create a separate hot path with different lifetime, error, and performance
behavior from the Java cursor engine.

### Slice 3: Replace the CRC32C reference loop

Use a fast CRC32C implementation for SFA append and recovery. The production
API should operate on borrowed byte slices so it can run directly over mapped
segment bytes:

- the 4-byte payload-length field in the mapping;
- the payload slice in the mapping.

It must not require copying mapped frame bytes into owned temporary buffers. Use
the `crc32c` crate. Do not use `crc32fast`; that crate is fast, but it computes
IEEE CRC32 rather than CRC32C/Castagnoli.

The current bit-at-a-time loop can remain only as a tiny test oracle if useful.
It must not be the production implementation once SFA storage is made
Java-like. Keep known-vector and Java fixture tests around the final API so the
implementation choice is replaceable.

### Slice 4: Make SFA outbound send cursor-backed

Current sending path:

- `PublicationLog::pending_payload_for_fsn()` returns `PendingPayload`.
- `SendCursor::next_outbound_frame()` wraps it into `OutboundFrame`.
- `OutboundFrame::with_view()` lends `&[u8]` to `transport.send_frame()`.

Do not implement SFA by making `pending_payload_for_fsn(fsn)` do random access
into segment storage. That API shape forces either a per-frame descriptor table
or repeated scans. SFA send is sequential; expose that honestly.

Move next-frame selection to the queue enum or another non-generic dispatch
point that can use different internal models:

- volatile queues may keep the existing FSN lookup/ring behavior;
- SFA queues use `SfaSendCursor`.

The SFA cursor send operation:

1. If no SFA send cursor exists, find the segment containing
   `oldest_unresolved_fsn`.
2. Scan within that segment once to position `offset` at the target FSN.
3. Read payload length from `[crc][payload_len][payload]` at `offset`.
4. Check `frame_end <= segment.published_offset`.
5. Lend the mapped payload slice to the synchronous transport send.
6. On send success, advance `offset` and `fsn`.
7. When a sealed segment is exhausted, move to the next sealed segment or active
   segment.
8. When the active segment has no more published bytes, report no outbound
   frame.

This follows Java's segment-cursor send model but uses Rust ownership to encode
the lifetime rule Java enforces by discipline. The SFA cursor must own an `Arc`
segment/map handle while lending a payload slice. Trim may remove a segment from
queue ownership once all frames in it are resolved, but it must not invalidate
any currently borrowed send view; the cursor-held `Arc` keeps the mapping alive
until `send_frame()` returns.

The store mutex boundary is part of this contract. The runner selects the next
outbound frame while holding the publication-store lock, then drops that lock
before calling `send_frame()`. Therefore an SFA `OutboundFrame` must not borrow
from the queue or from the mutex guard. It must own a mapped-segment handle plus
offset and length, and `OutboundFrame::with_view()` should create the borrowed
payload slice only inside the synchronous transport call. This lets queue trim
remove the segment from queue ownership while the outbound frame keeps the map
alive until the send returns.

The current transport contract already expects synchronous writes: the borrowed
payload slice is valid only for the `send_frame()` call. A future async
transport must not retain `&[u8]` after `send_frame()` returns. It must either
copy into owned output storage or hold its own `Arc` mapped payload view.

Do not keep the current `Arc<[u8]>` copy for SFA as the permanent design; that
keeps `sf_max_total_bytes` from being a real disk-storage cap.

Do not replace `Arc<[u8]>` with one SFA descriptor per unresolved frame. That
would remove payload memory but preserve the wrong O(number of unresolved
frames) asymptotic for send/replay metadata. If reconnect positioning scans ever
show up in profiles, add sparse per-segment checkpoints later, not a full offset
entry for every frame.

Do not add a file-backed scratch variant as part of this design. It would close
memory-at-rest semantics but would still add a file read and payload copy on
replay/send, which is specifically not the Java-like storage model.

### Slice 5: Change `sf_max_total_bytes` accounting

Replace disk SFA payload-byte capacity with allocated-segment capacity:

- maintain `allocated_segment_bytes`;
- seed it from recovered active + sealed segments plus any hot spare created at
  open time;
- add one segment size when a hot spare is provisioned;
- subtract a sealed segment's size after trim removes it from queue ownership
  and closes/unmaps it; unlink failure records a diagnostic but does not keep
  the bytes logically allocated;
- if close/unmap fails and the implementation cannot prove the process no
  longer owns the mapping or file handle, keep the bytes accounted and record a
  diagnostic;
- do not derive a user-visible frame cap from `sf_max_total_bytes`.

Keep an internal sanity bound if needed to protect Rust memory for transport
bookkeeping, such as bounded in-flight state, but do not expose it as
Java-compatible `sf_max_total_bytes`.

Recovery rule:

- Fresh/opening capacity must allow at least one segment. If no valid recovered
  segment exists and configured `sf_max_total_bytes < sf_max_bytes`, fail
  configuration/open with an actionable error.
- If recovered allocated bytes exceed configured `sf_max_total_bytes`, startup
  should still succeed. That mirrors Java manager registration, where recovered
  state can start at or above the cap and future spare provisioning is blocked
  until trim.
- If any single segment is malformed or the recovered FSN chain has a real gap,
  use the existing recovery rules: bad side files can be skipped, but a gap in
  the surviving valid chain remains fatal.

### Slice 6: Add storage backpressure and append deadline

Introduce specific queue backpressure reasons. Do not report these as
payload-too-large:

- `SpareNotReady`: active is full, no hot spare is installed, and progress must
  run to provision one.
- `SegmentCapFull`: active is full, no hot spare is installed, and the
  allocated segment cap prevents provisioning another one until trim.

Queue behavior:

- `try_publish()` appends if active has room.
- If active is full, it promotes `hot_spare` when present.
- If no spare is present, it returns backpressure. Segment provisioning belongs
  to `drive_once()`, not the append path.
- If allocated segment bytes are under the cap, that backpressure reason is
  `SpareNotReady`.
- If allocated segment bytes are at or above the cap, that backpressure reason
  is `SegmentCapFull`.

Driver behavior:

- In automated mode, storage backpressure waits on runner progress. The runner
  can send frames, receive OKs, receive durable ACKs, trim storage, and replenish
  the hot spare. The publishing thread retries append after notification or a
  short wait.
- In manual mode, storage backpressure is resolved by whichever caller currently
  owns the manual pump. If that caller invokes `drive_once()` and it reports
  progress, it may keep driving it; if it reports idle, retry publication or
  park. Do not allow concurrent `drive_once()` callers.
- Stop when the append deadline expires and return an actionable error.

Configuration:

- `sf_append_deadline_millis` is parsed as a duration and stored on
  `QwpWsConfig` independently of `request_timeout`. Default is 30000 ms,
  matching the Java/spec default. The driver applies this deadline when
  publication hits `StorageSpareNotReady` or `StorageSegmentCapFull`.

### Slice 7: Align trim and close cleanup behavior

Trim:

- Java logs and continues when a fully ACKed segment cannot be unlinked.
- Rust currently propagates unexpected unlink errors from
  `trim_acked_sealed_segments()`.
- For parity, change unlink cleanup to record/log diagnostics and continue.
  This prevents a post-delivery cleanup failure from becoming a delivery
  failure and prevents already-trimmed bytes from keeping the logical segment
  cap full forever.
- Close/unmap failure is different from unlink failure: if the implementation
  cannot prove the mapping and file handle are no longer owned, keep the bytes
  in `allocated_segment_bytes` and expose a diagnostic.

Close:

- Keep Rust's current explicit close-drain model for this storage slice.
- Do not make Java's default `close_flush_timeout_millis=5000` behavior part of
  this implementation; that is a separate public API/FFI decision.
- This remains a deliberate Java deviation until ordinary Rust sender close
  honors `close_flush_timeout_millis`. Java drains on close by default; this
  storage slice only preserves the existing explicit `close_drain()` path and
  the best-effort cleanup rules that follow from it.
- Clean fully drained close should remove all owned `.sfa` files best-effort,
  including clean active and hot-spare files.
- Timeout or non-drained close should release the slot lock and leave
  unresolved `.sfa` files for recovery.
- Cleanup unlink failures after successful close/unmap are diagnostics, not
  delivery failures.

### Slice 8: Orphan lifecycle follow-up

The first runtime slice for `drain_orphans=on` exists now. Remaining follow-up
work lives in `doc/QWP_WEBSOCKET_ORPHAN_DRAINING_TODO.md`: Java-style
diagnostics, real replay integration tests, background pool close behavior, and
Windows slot locking.

### Slice 9: Consider fsync modes last

Only after segment-backed storage and segment-cap accounting are correct:

- `memory`: no explicit sync, current Java behavior;
- `flush`: sync dirty segment bytes at user flush and implicit close flush;
- `append`: sync after each frame append;
- for true OS-crash durability, also sync the parent directory after segment
  create/unlink, otherwise the file namespace itself may not be durable.

This goes beyond current Java behavior because Java still rejects non-`memory`.
Do not enable these modes as a parity slice unless the Java client enables them
too or the Rust client intentionally chooses to lead.

## Correctness Invariants

- A receipt is returned only after the frame is committed in the segment.
- CRC is written last for each frame.
- Send/replay must never read bytes past a segment's published append offset.
- Any borrowed send slice from a mapped segment must be backed by an owning
  segment/map handle that remains live until the synchronous send call returns.
- Recovery must never silently bridge a real FSN gap between valid segments.
- A fully ACKed sealed segment may be trimmed; an active segment is kept even
  if all frames inside it are ACKed.
- Reconnect maps wire sequence zero to the oldest unresolved FSN.
- Durable ACK mode completes local storage only when durable watermarks cover
  pending OKs.
- Slot lock lifetime covers the open queue and is released on close/drop.
- `sf_durability=flush` and `append` must fail loudly until implemented.

## Tests To Add

Storage source:

- SFA append writes through a mapped segment object, not `seek` plus
  `write_all`.
- Submit many small frames with `sf_dir` and a large segment cap; assert process
  memory is not represented by queued payload-byte accounting or one production
  metadata object per frame.
- Reopen a queue with many frames and assert recovery does not retain payload
  `Vec<u8>` per frame or build a full frame-offset table in production data
  structures.
- Send/replay reads the correct payload from the segment cursor after recovery,
  including cursor positioning to a non-zero oldest unresolved FSN.
- The SFA cursor lends a mapped-segment view; tests should fail if it regresses
  to an owned `Arc<[u8]>`, owned `Vec<u8>`, full per-frame descriptor table, or
  per-send file read.
- The cursor-held segment handle keeps its mapping alive while `send_frame()`
  borrows from it, even if the segment has been removed from queue ownership.
- Transports must not retain the borrowed payload slice after `send_frame()`
  returns.

CRC:

- Known CRC32C vectors still pass through the production implementation.
- Java-written `.sfa` fixtures still verify with Rust's production CRC32C.
- Production CRC32C runs over borrowed mapped slices and does not copy payload
  bytes into an owned temporary buffer.
- The bit-at-a-time reference loop, if kept, is test-only and not used by SFA
  append or recovery.

Capacity:

- `sf_max_total_bytes = 2 * sf_max_bytes` allows active + one sealed segment.
- Fresh open with no valid recovered segment fails when configured
  `sf_max_total_bytes < sf_max_bytes`.
- A prepared hot spare counts against `sf_max_total_bytes`.
- Unpromoted clean hot-spare files are removed on recovery and recreated by the
  progress pump when capacity allows.
- Rotation with a prepared hot spare does not create a segment on the append
  path.
- Rotation without a prepared hot spare returns backpressure even when the cap
  would allow another segment.
- In manual mode, calling `drive_once()` provisions the missing spare when the
  cap allows it; retrying publication after that can rotate.
- Rotation beyond the segment cap returns storage backpressure rather than
  payload-too-large.
- Tests distinguish spare-not-ready backpressure from segment-cap-full
  backpressure.
- Recovered allocated segment bytes at the cap still allow startup.
- Recovered allocated segment bytes above the cap still allow startup but block
  new segment allocation until trim.
- Tiny-frame workloads are not capped by the current derived frame count based
  on segment count and `max_in_flight`.

Trim:

- Durable ACK completion trims fully ACKed sealed segments.
- Active segment remains on disk after all frames inside it are ACKed.
- A single `drive_once()` physically trims at most one sealed segment even if
  several sealed segments became ACKed.
- Unlink failure on a trimmable sealed segment is logged/diagnosed and does not
  fail delivery.
- Unlink failure after successful close/unmap does not keep the segment counted
  against `sf_max_total_bytes`.
- Close/unmap failure keeps the segment counted unless the implementation can
  prove ownership was released.

Backpressure:

- Append blocked by segment cap makes progress when receive drains ACKs.
- Append deadline expires with an actionable error when no trim is possible.
- Durable ACK mode does not trim on ordinary OK before durable watermarks cover
  the batch.
- Durable ACK keepalive is not sent from a `drive_once()` call that already
  sent a frame, received a response/control frame, trimmed a segment, or
  provisioned a spare.
- `drive_once()` replenishes a missing hot spare when capacity allows it.
- A single `drive_once()` provisions at most one hot spare.
- `try_publish()` never replenishes a hot spare; tests should fail if append
  path provisioning reappears.
- Blocking/waiting loops do not call a separate storage-maintenance API.

Recovery:

- Empty clean segments are removed.
- Empty torn segments are quarantined.
- Empty clean hot spares use the same removal rule as Java.
- Empty torn hot spares use the same `.corrupt` quarantine rule as Java.
- Spare generation skips past every existing generated `sf-*.sfa` name.
- Bad side files are skipped.
- Bad middle files that create an FSN gap remain fatal.
- Non-empty torn tails recover valid prefix and expose diagnostics.

Parity:

- Java-written `.sfa` fixtures still recover in Rust.
- Rust-written `.sfa` fixtures still recover in Java.
- Segment-cap behavior is covered by tests named around Java's
  `maxTotalBytes` contract.

## Milestones

Group implementation by invariant, not by source file.

### Milestone 0: Baseline harness

Lock down current behavior before structural changes.

Done when:

- Java/Rust `.sfa` fixture tests still pass.
- Current recovery edge cases are covered.
- SFA diagnostics needed by this work are test-visible.
- No queue model change has landed yet.

### Milestone 1: Metadata scan split

Introduce metadata recovery without forcing the queue model to change in the
same slice.

Done when:

- Segment scan returns metadata: base FSN, frame count, published offset, and
  torn-tail state.
- Payload-copying scan remains available for tests, fixture assertions, and the
  temporary payload-backed queue.
- Production code paths that only need segment metadata no longer have to scan
  payloads.
- Removing production recovery payload copies is deferred to the segment-backed
  queue and cursor-backed send milestones.

### Milestone 2: Mmap segment plus fast CRC

Replace the physical storage primitive.

Done when:

- SFA append writes through `memmap2`.
- CRC uses `crc32c`.
- CRC-last append semantics stay unchanged.
- Recovery scans mapped bytes.
- Send cursor rewrite is not required yet.

### Milestone 3: Segment-backed queue state

Make capacity and ownership Java-like.

Done when:

- Queue owns `active`, `sealed_segments`, `hot_spare`, and
  `allocated_segment_bytes`.
- `sf_max_total_bytes` means allocated segment bytes.
- Hot-spare lifecycle works.
- Recovery seeds segment accounting correctly.
- Production state has no per-frame descriptor table.

### Milestone 4: Cursor-backed send/replay

Remove retained SFA payload copies from the send path.

Done when:

- SFA send walks mapped segment bytes with `SfaSendCursor`.
- `Arc<[u8]>` payload retention is gone for SFA.
- Reconnect positions the cursor from the oldest unresolved FSN.
- Mapping lifetime is protected while `send_frame()` borrows the payload slice.

This is the milestone where the main storage gap actually closes.

### Milestone 5: Progress pump and backpressure

Integrate storage maintenance into `drive_once()`.

Done when:

- `drive_once()` trims at most one sealed segment or provisions at most one
  spare.
- `try_publish()` never provisions storage.
- `SpareNotReady` and `SegmentCapFull` are distinct.
- `sf_append_deadline_millis` works with actionable timeout errors.
- Manual mode behavior is explicit and tested.

### Milestone 6: Cleanup and close parity

Make post-ACK cleanup match the intended contract.

Done when:

- ACKed sealed segment unlink failure is diagnostic, not delivery failure.
- Clean explicit close-drain removes owned `.sfa` files best-effort.
- Non-drained close leaves recoverable files.
- Ordinary Java close-timeout parity remains explicitly deferred.

### Milestone 7: Parity and performance signoff

Prove the new model is what we think it is.

Done when:

- Java-written files recover in Rust.
- Rust-written files recover in Java.
- Tiny-frame backlog does not scale memory with unresolved frame count.
- Segment-cap behavior matches Java's allocated-byte model.
- A focused benchmark shows SFA storage is no longer dominated by heap payload
  retention or per-send file reads.

Deferred after these milestones:

- `sf_durability=flush/append`;
- Windows slot locking;
- Java close-timeout public behavior;
- WebSocket masking optimization.

## Suggested Order

1. Refactor scan output to return segment metadata without payload copies or
   per-frame production descriptors.
2. Replace SFA segment IO with a mapped segment object.
3. Replace production CRC32C with a fast implementation.
4. Change SFA queue state from payload-backed frames to segment ownership and
   ACK watermarks.
5. Replace SFA random FSN payload lookup with a segment send cursor.
6. Add queue-local hot spare state and promotion.
7. Change `sf_max_total_bytes` to allocated segment accounting.
8. Fold trim and hot-spare replenishment into the single driver `drive_once()`
   pump.
9. Add storage-backpressure errors and append-deadline retry in the driver.
10. Align trim cleanup behavior with Java logging/diagnostics.
11. Update `doc/QWP_WEBSOCKET_SPEC_COMPLIANCE_GAPS.md` by removing the completed
   storage-capacity item and narrowing any remaining close/orphan/fsync items.
12. Only later implement fsync durability modes.

## Later Performance Work

The WebSocket send path remains a separate performance gap. Current Rust frame
writing copies payload bytes into a `Vec<u8>` and masks byte by byte, while the
Java client copies into a native send buffer and masks with word-sized chunks.
That does not block segment-backed durable storage parity because RFC 6455
client masking requires a writable outgoing frame buffer anyway, but it should
be tracked as the next likely hot-path optimization after SFA storage stops
retaining and rereading payloads.

The storage slice is complete when SFA queued payloads are represented by mapped
segments plus a send cursor, and replay/send no longer retains or reloads
payloads from heap buffers. That is not the same as end-to-end WebSocket
send-path parity with Java. Before claiming send-path parity, add a focused
benchmark for WebSocket frame writing and masking that covers both large frames
and many small frames, and isolates masking/framing cost from network I/O and
server ACK timing.

## Non-goals For The First Implementation

- Do not implement Java's global/background `SegmentManager`.
- Do not expose a low-level storage-maintenance entry point to higher layers.
- Do not add synchronous segment-provisioning fallback to `try_publish()`.
- Do not hide progress pumping inside the primitive append path.
- Do not add a durable SFA file-backed scratch/replay path.
- Do not enable `sf_durability=flush` or `append`.
- Do not solve Windows slot locking.
- Do not make Java close timeout parity part of the storage-accounting patch.
- Do not change WebSocket wire response parsing.
- Do not optimize WebSocket masking in the same patch unless profiling shows it
  is necessary to validate the storage change.

## Implementation Risks

- A capacity-only patch that leaves `Arc<[u8]>` payload retention in SFA would
  be misleading. It would make the config name Java-like while preserving a
  memory-backed backlog.
- A descriptor-table patch that leaves one Rust metadata object per unresolved
  SFA frame would still be the wrong shape for many tiny frames. The durable
  queue is the segment list; the send path is a cursor over segment bytes.
- A file-backed scratch/replay path would be a false simplification: it avoids
  retained payload memory but keeps per-send file IO and payload copies, so it
  is outside this design.
- Mmap support adds unsafe lifetime and platform work. The segment must not be
  unmapped while an outbound frame view is live, and recovery must never expose
  slices past the published append offset.
- A slow CRC32C implementation can dominate append/recovery once segment IO is
  mmap-backed. Do not keep the bit-at-a-time loop on the production path, and
  do not introduce a CRC API that requires copying mapped payload bytes.
- If manual mode does not call `drive_once()` often enough, publication can
  report backpressure even when the byte cap would allow another segment. That
  is intentional: manual mode means the user owns progress scheduling.
- Splitting storage maintenance into a separate public method would be a footgun:
  manual-mode callers could forget to run it. Keep maintenance as an internal
  phase of `drive_once()`.
- Logging is currently not part of the Rust client surface in this area. If
  cleanup failures become diagnostics instead of errors, add an observable test
  hook or event path so failures are not silently swallowed.
- The current WebSocket frame writer may become the next bottleneck after SFA
  storage is fixed. Treat that as a tracked follow-up, not as a reason to keep
  SFA replay heap-backed.
- Parent-directory sync is required for true namespace durability, but it is
  irrelevant until `flush` or `append` durability modes are actually enabled.
