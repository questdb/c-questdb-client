# QWP/WebSocket spec compliance gaps

Date: 2026-05-06

Status: open-gap handoff. Completed implementation notes have been removed
unless they still explain an unresolved spec/reference decision.

This document records gaps found while comparing the Rust QWP/WebSocket
Store-and-Forward implementation against the current QWP spec documents in:

```text
/home/jara/devel/oss/questdb-arrays/docs/qwp
```

and the current Java reference client in:

```text
/home/jara/devel/oss/questdb-arrays/java-questdb-client
```

Use this as implementation-agent context. Re-check the cited files before
coding because both the spec and the Java client are actively moving.

## Source Documents

Primary spec documents read during the audit:

- `/home/jara/devel/oss/questdb-arrays/docs/qwp/README.md`
- `/home/jara/devel/oss/questdb-arrays/docs/qwp/sf-client.md`
- `/home/jara/devel/oss/questdb-arrays/docs/qwp/wire-ingress.md`
- `/home/jara/devel/oss/questdb-arrays/docs/qwp/wire-udp.md`
- `/home/jara/devel/oss/questdb-arrays/docs/qwp/wire-egress.md`
- `/home/jara/devel/oss/questdb-arrays/docs/qwp/design/egress-phase2-backlog.md`

Primary Rust files inspected:

- `questdb-rs/src/ingress.rs`
- `questdb-rs/src/ingress/conf.rs`
- `questdb-rs/src/ingress/sender/qwp_ws.rs`
- `questdb-rs/src/ingress/sender/qwp_ws_codec.rs`
- `questdb-rs/src/ingress/sender/qwp_ws_driver.rs`
- `questdb-rs/src/ingress/sender/qwp_ws_publisher.rs`
- `questdb-rs/src/ingress/sender/qwp_ws_queue.rs`
- `questdb-rs/src/ingress/sender/qwp_ws_sfa_queue.rs`
- `questdb-rs/src/ingress/sender/qwp_ws_sfa_segment.rs`
- `questdb-rs/src/ingress/sender/qwp_ws_sfa_slot.rs`
- `questdb-rs/src/ingress/buffer/qwp.rs`

Primary Java reference files inspected:

- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/Sender.java`
- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/SenderProgressHandler.java`
- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/http/client/WebSocketClient.java`
- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/http/client/WebSocketFrameHandler.java`
- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/QwpWebSocketSender.java`
- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/WebSocketResponse.java`
- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/BackgroundDrainer.java`
- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/CursorSendEngine.java`
- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/CursorWebSocketSendLoop.java`
- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/MmapSegment.java`
- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/OrphanScanner.java`
- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/SegmentManager.java`

## Summary

The current Rust implementation is a coherent partial QWP/WebSocket
Store-and-Forward implementation. It is not yet a full implementation of the
new SF client spec.

The largest remaining areas are:

- strict unknown-key handling,
- Java/spec close, retry, and orphan-drainer semantics,
- remaining Java wire-sequence tolerance around ACK-before-send and
  NACK/reject high-sequence clamping,
- Java public API/config surface parity, including deprecated auth aliases,
  WebSocket auto-flush settings, builder methods, and callback-style progress
  handlers,
- several SFA disk-format/recovery details where the spec and Java reference
  need to be reconciled before Rust should change behavior,
- durable-mode OK coalescing/cumulation contract validation against the live
  server if the protocol ever permits skipped per-message OK table entries.

## Confirmed Rust Gaps

### 1. Durable OK coalescing remains a protocol assumption

Rust state:

- Rust assumes durable-mode OK frames are emitted per sent message, with table
  entries for that message. If the server can coalesce/cumulate durable-mode
  OKs without emitting the skipped OK table entries, the tracker needs an
  explicit protocol decision because it cannot safely infer missing per-batch
  table watermarks.

Java reference:

- `CursorWebSocketSendLoop.java` has `durableAckMode`,
  `durableTableWatermarks`, `pendingDurable`, and durable trim counters.
- `SenderProgressHandler.java:33-45` documents the user-visible progress
  watermark: `ackedFsn` is the highest FSN now durable on the server side. In
  durable ACK mode this is the durable-ack-driven watermark, not the ordinary
  OK watermark.

### 2. Error response parsing is stricter than Java's live receive path

Spec requirement:

- `sf-client.md:641-649` says error `msgLen` is `uint16 LE (<= 1024)`.

Rust state:

- `msgLen > 1024` is rejected before UTF-8 conversion.
- Error frames must end exactly at `11 + msgLen`; trailing bytes are rejected.

Java reference:

- The Rust behavior is spec-strict, but Java's live Store-and-Forward receive
  path is more permissive today. `CursorWebSocketSendLoop.java:1086` calls
  `WebSocketResponse.readFrom(...)` directly, and
  `WebSocketResponse.java:286-300` accepts error frames when the received
  length is at least `offset + msgLen`; it does not enforce the 1024-byte cap,
  exact end-of-frame, or UTF-8 validity on this path.
- Treat this as a Java/spec reconciliation item before relaxing Rust. The Rust
  parser should not loosen without an explicit cross-client decision because
  the current Rust behavior matches the documented wire contract.

### 3. Unknown-key behavior diverges from the spec

Spec requirements:

- `sf-client.md:107` says WebSocket transport options use `ws::` / `wss::`.
- `wire-ingress.md:815` gives a durable ACK example using `ws::`.
- `sf-client.md:179-181` says the parser must reject unknown keys.

Rust state:

- `questdb-rs/src/ingress.rs:361-363` accepts `qwpws` / `qwpwss` and the
  spec aliases `ws` / `wss`.
- `questdb-rs/src/ingress.rs:724-728` intentionally ignores unknown keys.

Java reference:

- `Sender.java` uses WebSocket protocol strings compatible with `ws::`.
- `Sender.java:2747-2751` still ignores unknown keys unless malformed.

Open decision:

- Because Java still ignores unknown keys, strict unknown-key rejection is a
  cross-client behavior change. It should probably be changed in Java and Rust
  together, or the spec should document a transition rule.

### 4. Several normative config keys and Java API surfaces are rejected, inert, or config-only

Spec references:

- `sf-client.md:115-122` lists SF disk options, including
  `sf_append_deadline_millis`, `drain_orphans`, and
  `max_background_drainers`.
- `sf-client.md:131-135` lists reconnect and close keys, including
  `initial_connect_retry` and `close_flush_timeout_millis`.
- `sf-client.md:141-148` lists durable ACK and error inbox keys.
- `sf-client.md:174-175` lists `in_flight_window` and
  `max_schemas_per_connection`.

Rust state:

- `questdb-rs/src/ingress.rs:515-517` recognizes `username`, `password`, and
  token keys. Deprecated Java aliases `user` and `pass` are not recognized and
  therefore fall through to the unknown-key ignore path at
  `questdb-rs/src/ingress.rs:724-728`.
- `questdb-rs/src/ingress.rs:182-200` rejects `auto_flush_rows` and
  `auto_flush_bytes`; `auto_flush_interval` is not recognized and falls
  through to the unknown-key ignore path.
- `sf_append_deadline_millis` is parsed and stored for QWP/WebSocket append
  backpressure; the background runner uses it separately from
  `request_timeout`.
- `questdb-rs/src/ingress.rs:564` routes
  `close_flush_timeout_millis` to an explicit rejection.
- `questdb-rs/src/ingress.rs:568-571` rejects
  `max_schemas_per_connection`.
- `questdb-rs/src/ingress.rs:577-579` parses `drain_orphans` and
  `max_background_drainers`, but enabled orphan draining is unsupported.
- `questdb-rs/src/ingress.rs:581-584` rejects `error_inbox_capacity`.
- `questdb-rs/src/ingress.rs:1948-1963` rejects
  `initial_connect_retry=async`.
- `questdb-rs/src/ingress.rs:505-508` splits `addr` once on `:`, so it does
  not store comma-separated multi-host addresses.
- Store-and-Forward builder setters such as `sf_dir`, `sender_id`,
  `sf_max_bytes`, `sf_max_total_bytes`, `sf_durability`, and durable ACK opt-in
  are currently config-string-only implementation details rather than public
  Rust builder methods.
- Durable completion observation is pull/wait based:
  `Sender::acked_fsn()` and `Sender::await_acked_fsn(...)`. There is no
  Java-style callback registration surface.

Java reference:

- `Sender.java:2445-2465` parses deprecated `user` / `pass` aliases and
  `Sender.java:2764-2768` applies them to HTTP/WebSocket auth.
- `Sender.java:619-621` defines WebSocket-specific auto-flush defaults and
  `Sender.java:2536-2581` parses `auto_flush_rows`,
  `auto_flush_interval`, and `auto_flush_bytes`.
- `Sender.java:1767` exposes `requestDurableAck(boolean)`.
- `SenderProgressHandler.java:27-38` defines callback-style ACK progress
  observation.
- `Sender.java:1841`, `Sender.java:1940`, `Sender.java:2074`, and
  `Sender.java:2103` expose builder methods for Store-and-Forward directory,
  close timeout, append deadline, and orphan draining.
- `Sender.java:2663-2668` parses `close_flush_timeout_millis`.
- `Sender.java:2688-2701` accepts `initial_connect_retry=async`.
- `Sender.java:2703-2708` parses `sf_append_deadline_millis`.
- `Sender.java:2709-2719` parses `drain_orphans`.
- `Sender.java:2721-2726` parses `max_background_drainers`.
- `Sender.java:2727-2732` parses `error_inbox_capacity`.

Implementation direction:

- Split this into compatibility slices. Do not implement all keys by merely
  accepting them; behavior-bearing keys should stay rejected until the behavior
  exists.
- For `initial_connect_retry=async`, implement the Java startup state model or
  keep the current explicit rejection.
- For `close_flush_timeout_millis`, implement Java close semantics before
  accepting the key.
- For `error_inbox_capacity`, decide whether Rust should expose Java-style
  callback dispatch or preserve poll-based Rust ergonomics with a compatible
  capacity knob.
- Decide whether Rust should support the deprecated `user` / `pass` aliases as
  compatibility aliases. Because unknown keys are ignored, the current behavior
  is a silent authentication misconfiguration rather than a loud parser error.
- Auto-flush parity is larger than accepting the keys: Java WebSocket has
  rows/bytes/interval defaults, while Rust currently requires explicit user
  flush. Keep these rejected or ignored only if that remains the intended Rust
  API contract.

### 5. Default close semantics are not Java/spec compatible

Spec requirements:

- `sf-client.md:767-784` defines `close()` behavior:
  default drain up to 5 seconds, `0` or `-1` skips pre-drain `checkError()`,
  and close rethrows terminal errors unless opted out.

Rust state:

- `questdb-rs/src/ingress.rs:1268-1279` rejects
  `close_flush_timeout_millis`.
- `questdb-rs/src/ingress/sender.rs:666-673` exposes explicit
  `Sender::close_drain()`.
- `questdb-rs/src/ingress/sender/qwp_ws.rs:335-369` implements runner
  close-drain logic, but timeout is returned as an error.
- `questdb-rs/src/ingress/sender/qwp_ws.rs:791-797` runner `Drop` only stops
  and joins the runner thread.
- `questdb-rs/src/ingress/sender/qwp_ws.rs:1973-1995` uses a fixed
  close-drain timeout where close-drain is explicitly called.

Java reference:

- `QwpWebSocketSender.java:745-799` implements public `close()` by flushing
  pending rows, surfacing unsurfaced terminal errors, and draining up to the
  configured timeout.
- `QwpWebSocketSender.java:1930-1962` defines the bounded close-drain loop and
  timeout error text.

Implementation direction:

- Decide whether Rust `Drop` should remain non-blocking and only explicit
  `close_drain()` follows Java, or whether public `Sender::close()` should be
  added/wired as the Java-compatible close.
- If accepting `close_flush_timeout_millis`, the behavior should match Java:
  configurable timeout, skip modes, cleanup error preservation, and terminal
  error rethrow behavior.

### 6. ACK-before-send and NACK clamping differ from Java

Spec requirement:

- `sf-client.md:472-474` says ordinary OK trim computes
  `fsnAtZero + min(sequence, nextWireSeq - 1)` to defend against a buggy or
  malicious server reporting a future wire sequence.

Rust state:

- Error/NACK responses remain strict protocol errors when they name a future
  sequence.
- ACK before a send path has established `fsn_at_zero` / `last_sent_wire_seq`
  still reports `ProtocolAckWithoutConnection`.

Java reference:

- `CursorWebSocketSendLoop.java:1091-1121` clamps OK responses with
  `Math.min(wireSeq, highestSent)` and ignores an OK frame when
  `highestSent < 0`.
- `CursorWebSocketSendLoop.java:1150-1161` applies the same high-sequence
  clamp to NACK/server-rejection responses.

Implementation direction:

- Implement the remaining Java tolerance in one sequence-mapping slice:
  ignore ACK-before-send, clamp future NACK/reject to highest sent, and keep
  monotonic completion so no unsent frame can be marked resolved.
- This is a Java parity target even though the spec text explicitly calls out
  only ordinary OK.

### 7. Reconnect timing, idle receive, and ACK-timeout behavior are incomplete

Spec requirements:

- `sf-client.md:584` says send/recv failure, server close, and ACK timeout
  enter reconnect.
- `sf-client.md:592-595` says actual reconnect sleep is jittered in
  `[backoff, 2 * backoff)`.

Rust state:

- `questdb-rs/src/ingress/sender/qwp_ws_driver.rs` and
  `questdb-rs/src/ingress/sender/qwp_ws.rs` use deterministic backoff.
- The current driver polls readable bytes and progress but does not maintain a
  sent-time ACK deadline that triggers reconnect.
- `questdb-rs/src/ingress/sender/qwp_ws_driver.rs:1615-1617` returns
  `TransportPoll::Idle` without reading the socket when no wire sequences are
  pending and durable ACK mode is off. This can defer server PING/PONG/CLOSE or
  stray response handling until another send happens.
- `questdb-rs/src/ingress/sender/qwp_ws_driver.rs:751-754` treats generic
  WebSocket protocol violations as terminal protocol errors.
- `questdb-rs/src/ingress/sender/qwp_ws_driver.rs:1654-1659` treats completed
  non-binary QWP responses as protocol violations.

Java reference:

- `CursorWebSocketSendLoop.java` has the current reference reconnect loop.
  Verify current jitter behavior before copying the spec literally; the Java
  grep during this audit showed deterministic `Math.min(... * 2, max)` growth,
  so the spec and Java may not yet agree.
- `CursorWebSocketSendLoop.java:1010-1019` drains
  `client.tryReceiveFrame(...)` until idle whenever the loop polls receives.
- `WebSocketClient.java:915-924` sends a close frame on WebSocket parser
  errors and throws; `CursorWebSocketSendLoop.java:1016-1018` routes that
  through `fail(...)`, which can enter reconnect handling when the reconnect
  factory exists.
- `WebSocketClient.java:972-978` dispatches text frames to the handler, and
  `WebSocketFrameHandler.java:90-92` ignores text frames by default.

Implementation direction:

- Treat ACK-timeout reconnect as a real runtime behavior gap.
- Decide whether idle non-durable receive pumping should follow Java exactly.
  It is behavior-visible for server CLOSE/PING/PONG and malformed stray frames
  received after the last pending ACK.
- Decide whether Rust's stricter terminal classification for malformed
  WebSocket frames and non-binary QWP responses is a deliberate safety policy
  or should follow Java's reconnect/ignore behavior.
- Treat jitter as a spec/reference reconciliation item unless Java has already
  changed.

### 8. Orphan adoption and `.failed` are missing

Spec requirements:

- `sf-client.md:121-122` defines `drain_orphans` and
  `max_background_drainers`.
- `sf-client.md:220-228` defines `.failed`.
- `sf-client.md:804-831` defines orphan adoption and background drainer
  behavior.

Rust state:

- `questdb-rs/src/ingress.rs:1295-1316` accepts `drain_orphans=off/false` and
  rejects `on/true`.
- `questdb-rs/src/ingress.rs:1331-1345` parses
  `max_background_drainers` but it is inert without drainers.
- No Rust orphan scanner, background drainer, or `.failed` sentinel path was
  found in the inspected source.

Implementation direction:

- Keep `drain_orphans=on` rejected until the scanner/drainer lifecycle exists.
- Implement `.failed` before enabling background drainers; otherwise failed
  orphan attempts will be retried blindly.

### 9. Error inbox and default error-handler behavior differ

Spec requirements:

- `sf-client.md:700-709` requires a bounded error inbox, a dispatcher, and
  drop-oldest overflow behavior.
- `sf-client.md:891-893` says the default error handler logs; silence is
  forbidden.

Rust state:

- `questdb-rs/src/ingress/sender/qwp_ws_ownership.rs:40-43` documents
  poll-based error observation.
- `questdb-rs/src/ingress/sender.rs:592-608` exposes `poll_qwp_ws_error()`.
- `questdb-rs/src/ingress/sender.rs:628-641` exposes dropped-error counts.
- `questdb-rs/src/ingress/sender/qwp_ws_driver.rs:60` uses a default capacity
  of 1024, not the spec's 256 default.
- `questdb-rs/src/ingress.rs:581-584` rejects `error_inbox_capacity`.

Implementation direction:

- Decide whether Rust should implement Java-style callback dispatch or keep a
  Rust-native polling API.
- Even if Rust keeps polling, `error_inbox_capacity` should not be silently
  ignored. Either implement it or keep explicit rejection.
- Add actual logging for the default path if the spec remains strict about
  non-silence.

### 10. Slot locking is Unix-only

Spec requirements:

- `sf-client.md:202-205` says POSIX clients use `flock`/`fcntl` and Windows
  clients use `LockFileEx`.
- `sf-client.md:844-848` lists slot locking as a mandatory cross-client
  invariant.

Rust state:

- `questdb-rs/src/ingress/sender/qwp_ws_sfa_slot.rs:169-185` implements Unix
  `flock`.
- `questdb-rs/src/ingress/sender/qwp_ws_sfa_slot.rs:188-192` returns
  `SlotLockUnsupported` on non-Unix.
- `.lock.pid` writing is best-effort in Rust; if the spec requires a hard
  diagnostic write on every successful acquisition, that is another small gap.

Implementation direction:

- Either implement Windows `LockFileEx` or document SF disk mode as unsupported
  on Windows and ensure the builder fails clearly.

### 11. SFA header validation is stricter than Java

Spec requirement:

- `sf-client.md:260-264` says header `flags` and `reserved` must be 0.

Rust state:

- `questdb-rs/src/ingress/sender/qwp_ws_sfa_segment.rs:294-302` writes those
  fields as 0.
- Segment scan now rejects non-zero `flags` and non-zero `reserved` fields
  before accepting the segment header. Under the current recovery policy these
  are treated like other segment scan failures: a bad side file can be skipped,
  while a required segment that creates an FSN gap still fails recovery.

Java reference divergence:

- `MmapSegment.java:226-246` validates magic, version, and non-negative
  `baseSeq`, but currently does not reject non-zero `flags` or `reserved`.
- This makes Rust stricter than Java for malformed segment headers. Treat it
  as intentional spec hardening unless Java decides to preserve non-zero
  header extensions.

### 12. Fresh SFA filename conflicts with the current spec

Spec requirement:

- `sf-client.md:230-240` defines new segment files as
  `sf-<gen:016x>.sfa` and says `sf-initial.sfa` is a legacy name accepted by
  recovery and skipped during max-generation computation.
- `sf-client.md:842` lists `sf-<gen:016x>.sfa` as a mandatory cross-client
  filename pattern.

Rust state:

- `questdb-rs/src/ingress/sender/qwp_ws_sfa_segment.rs:41` defines
  `INITIAL_SEGMENT_FILE_NAME = "sf-initial.sfa"`.
- `questdb-rs/src/ingress/sender/qwp_ws_sfa_queue.rs:141-149` creates a fresh
  queue with `sf-initial.sfa`.
- `questdb-rs/src/ingress/sender/qwp_ws_sfa_segment.rs:552-563` has a test
  that locks in the initial filename.

Java reference:

- `CursorSendEngine.java:196-197` also creates a fresh disk slot as
  `sf-initial.sfa`.
- `SegmentManager.java:208-238` treats `sf-initial.sfa` as legacy/non-hex for
  max-generation scanning.

Open decision:

- This is a spec/reference mismatch, not a Rust-only bug.
- If the spec is authoritative, change Java and Rust together.
- If Java remains authoritative for now, update the spec wording to say fresh
  initial active segments may still be `sf-initial.sfa`.

### 13. Recovery behavior for corrupt or empty side files needs a spec decision

Spec text:

- `sf-client.md:340-359` describes validating `*.sfa`, sorting recovered
  segments, and failing on gaps.
- `sf-client.md:251-253` allows zero or more frames in a segment and says the
  tail is zero-filled until written.
- `sf-client.md:349-350` says recovery sets frame count and cursors from the
  scan.

Rust state:

- `questdb-rs/src/ingress/sender/qwp_ws_sfa_queue.rs:577-585` records a
  `SkippedSegment` diagnostic and continues when `scan_file()` fails.
- `questdb-rs/src/ingress/sender/qwp_ws_sfa_queue.rs:587-597` removes clean
  empty segments and quarantines empty torn segments.
- `questdb-rs/src/ingress/sender/qwp_ws_sfa_queue.rs:687-701` still fails
  recovered-FSN gaps after sorting the remaining valid segments.

Java reference:

- `SegmentRingTest.java` includes a "stray .sfa with no proper header must be
  ignored" case, so at least some bad side-file skipping is Java behavior.

Open decision:

- The spec should distinguish "bad side file outside the recovered FSN chain"
  from "bad segment that creates a recovered-FSN gap".
- Rust's current behavior is intentionally Java-like for bad side files, but
  it is not a literal reading of "validate each `*.sfa`" if that phrase means
  every bad file is fatal.
- Empty segment base-sequence preservation should also be clarified. Current
  Rust can discard an empty segment and create a new baseSeq 0 segment if no
  non-empty files remain.

### 14. Torn-tail diagnostics are not operator-visible

Spec requirement:

- `sf-client.md:351-353` says non-empty torn tails should produce a warning.

Rust state:

- `questdb-rs/src/ingress/sender/qwp_ws_sfa_queue.rs:600-608` records
  structured diagnostics for non-empty torn tails.
- There is no current Rust logging facade in this path, so the diagnostic is
  not obviously operator-visible unless callers inspect recovery diagnostics.

Implementation direction:

- Earlier we chose to ignore logging for now. If spec compliance is required,
  add a logging facade or expose recovery diagnostics through a public surface
  that operators can observe.

## Spec Or Reference Issues

### `sf-initial.sfa` is a spec/reference mismatch

See gap 12. Current Java and Rust both create `sf-initial.sfa` for a fresh
slot, while the spec says it is legacy recovery input. Resolve this before
changing Rust alone.

### Unknown-key rejection conflicts with Java

See gap 3. The current spec says unknown keys must be rejected, but current
Java still ignores unknown keys unless malformed. If strict rejection is the
new contract, Java and Rust should be changed together.

## Suggested Fix Order

1. Finish Java sequence tolerance:
   ignore ACK-before-send and clamp future NACK/reject to highest sent.
2. Resolve spec/reference mismatches that should not be Rust-only changes:
   `sf-initial.sfa`, unknown-key policy, and Rust-stricter SFA header
   extension handling if Java intends to accept non-zero fields.
3. Validate the durable OK emission/coalescing contract against the live
   durable-ACK server.
5. Implement Java-compatible close semantics and then accept
   `close_flush_timeout_millis`.
6. Implement ACK-timeout reconnect, and decide idle receive/protocol-violation
   classification parity with Java.
7. Decide Rust API shape for Java-facing config/API gaps:
   deprecated `user` / `pass` aliases, WebSocket auto-flush, progress/error
   callback parity versus polling, and then support `error_inbox_capacity` if
   applicable.
8. Add orphan scanner/drainers and `.failed`, then enable `drain_orphans=on`.
9. Address lower-level SFA disk details:
   filename decision, empty-segment behavior, and operator-visible recovery
   diagnostics.
10. Decide Windows SF support:
   implement `LockFileEx` or document/fail disk SF mode clearly on Windows.

Each fix should start with a failing regression or golden fixture. For any
behavior where Java and the spec conflict, update the spec or Java first rather
than making Rust the only divergent client.
