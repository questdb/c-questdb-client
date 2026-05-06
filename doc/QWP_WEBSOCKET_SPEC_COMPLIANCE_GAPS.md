# QWP/WebSocket spec compliance gaps

Date: 2026-05-05

Status: audit handoff, updated after the parser-completeness, internal
durable-ACK-tracker, and public durable-ACK enablement slices. Response parser
completeness, durable ACK upgrade echo validation, durable OK tracking, durable
ACK trimming, and durable keepalive PINGs are implemented in the current
working tree.

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
- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/CursorSendEngine.java`
- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/CursorWebSocketSendLoop.java`
- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/MmapSegment.java`
- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/SegmentManager.java`

## Summary

The current Rust implementation is a coherent partial QWP/WebSocket
Store-and-Forward implementation. It is not yet a full implementation of the
new SF client spec.

The largest remaining areas are:

- strict unknown-key handling,
- Java/spec close, retry, and orphan-drainer semantics,
- several SFA disk-format/recovery details where the spec and Java reference
  need to be reconciled before Rust should change behavior,
- durable-mode OK coalescing/cumulation contract validation against the live
  server if the protocol ever permits skipped per-message OK table entries.

Several core pieces already look aligned: single-producer queue ownership,
FSN/wire-sequence mapping, strict in-order replay, self-sufficient replay
encoding, non-durable status policy mapping, terminal WebSocket close-code
routing, CRC-last SFA append order, and recovery gap checks.

## Confirmed Rust Gaps

### 1. Public durable ACK mode is implemented; durable OK coalescing remains a protocol assumption

Spec requirements:

- `sf-client.md:141` says `request_durable_ack` opts in to durable ACK and
  OK frames no longer advance the trim watermark.
- `sf-client.md:432-441` requires the client to validate
  `X-QWP-Durable-Ack: enabled` in the 101 response and fail loudly if absent.
- `sf-client.md:483-488` says durable mode trims only from
  `STATUS_DURABLE_ACK`.
- `sf-client.md:499-527` defines durable ACK table-watermark payloads and the
  drain loop.
- `wire-ingress.md:787-798` repeats the same handshake and trim rule.

Rust state:

- `request_durable_ack=on` is accepted from the connect string.
- `durable_ack_keepalive_interval_millis` is stored; `<= 0` disables the idle
  durable-ACK PING.
- The upgrade request sends `X-QWP-Request-Durable-Ack: true` when requested.
- The upgrade response must include `X-QWP-Durable-Ack: enabled`; Rust fails
  the connection instead of silently downgrading.
- OK and durable ACK table-watermark payloads are parsed.
- Durable OK releases the send window without completing the publication log.
- Durable ACK watermarks drain consecutive covered OKs.
- The background/manual ready loop sends a WebSocket PING while durable
  confirmations are pending and the keepalive interval has elapsed.
- Empty OKs wait behind earlier non-empty OKs, stale durable watermarks do not
  move backwards, durable drop-and-continue rejections enqueue ordered empty
  placeholders, and reconnect clears pending durable state for replay.
- The non-durable path still trims on ordinary OK.

Remaining protocol assumption:

- Rust assumes durable-mode OK frames are emitted per sent message, with table
  entries for that message. If the server can coalesce/cumulate durable-mode
  OKs without emitting the skipped OK table entries, the tracker needs an
  explicit protocol decision because it cannot safely infer missing per-batch
  table watermarks.

Java reference:

- `CursorWebSocketSendLoop.java` has `durableAckMode`,
  `durableTableWatermarks`, `pendingDurable`, and durable trim counters.
- `Sender.java:1758` documents durable ACK opt-in.
- `Sender.java:2614-2625` parses `request_durable_ack=on|off` from the
  connect string.
- `Sender.java:2669-2675` parses
  `durable_ack_keepalive_interval_millis`.
- `SenderProgressHandler.java:33-45` documents the user-visible progress
  watermark: `ackedFsn` is the highest FSN now durable on the server side. In
  durable ACK mode this is the durable-ack-driven watermark, not the ordinary
  OK watermark.

User exposure:

- Durable ACK is exposed as an opt-in connection mode, not as a raw
  per-`STATUS_DURABLE_ACK` callback API.
- Users enable it with `request_durable_ack=on` in the connect string or
  `requestDurableAck(true)` on the Java builder.
- Users can tune idle durable-ACK flushing with
  `durable_ack_keepalive_interval_millis` or
  `durableAckKeepaliveIntervalMillis(...)`.
- If the server does not confirm support with `X-QWP-Durable-Ack: enabled`,
  the connect attempt must fail loudly. The client must not silently downgrade
  to ordinary OK trimming.
- Applications observe durable completion through the existing progress/ack
  watermark (`onAcked(ackedFsn)` in Java). In durable ACK mode that watermark
  advances only after durable ACK coverage, so user code does not need a
  separate durable-ack event stream.
- Rust exposes durable ACK publicly through the connect string:
  `request_durable_ack=on|off` and
  `durable_ack_keepalive_interval_millis=<millis>`.

### 2. OK response parsing was incomplete (addressed)

Spec requirements:

- `wire-ingress.md:692-704` says OK response is `11+` bytes:
  status, sequence, tableCount, and repeated table entries.
- `sf-client.md:454-466` gives the same layout.

Previous Rust state:

- Before the parser-completeness slice, the Rust parser accepted any OK frame
  with only status plus 8-byte sequence.
- It returned only `sequence`, dropping `tableCount` and table `seqTxn`
  watermarks.

Previous impact:

- Truncated OK frames are accepted.
- Durable ACK mode could not be implemented correctly because the OK-side
  per-table `seqTxn` data was missing.

Current working-tree state:

- OK parsing can expose parsed table entries through a callback.
- OK requires status, sequence, and table count.
- Table entry lengths and UTF-8 table names are validated.
- The non-durable driver path validates table-entry bytes without allocating
  table-name strings.
- The durable decode path retains parsed table watermarks for the internal
  durable ACK tracker, and public durable ACK mode uses those watermarks for
  durable trimming.

### 3. Error response message length was not capped at 1024 (addressed)

Spec requirement:

- `sf-client.md:641-649` says error `msgLen` is `uint16 LE (<= 1024)`.

Previous Rust state:

- Before the error-frame slice, the Rust parser accepted any `u16` message
  length that fit in the received frame and was UTF-8.

Current working-tree state:

- `msgLen > 1024` is rejected before UTF-8 conversion.
- Error frames must end exactly at `11 + msgLen`; trailing bytes are rejected.
- Focused parser tests cover 1024 bytes, 1025 bytes, and trailing bytes.

### 4. Unknown-key behavior diverges from the spec

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

### 5. Several normative config keys are rejected or inert

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

- `questdb-rs/src/ingress.rs:548` routes
  `sf_append_deadline_millis` to an explicit rejection.
- `questdb-rs/src/ingress.rs:564` routes
  `close_flush_timeout_millis` to an explicit rejection.
- `questdb-rs/src/ingress.rs:568-571` rejects
  `max_schemas_per_connection`.
- `durable_ack_keepalive_interval_millis` is implemented for public durable
  ACK mode; `<= 0` disables the idle PING.
- `questdb-rs/src/ingress.rs:577-579` parses `drain_orphans` and
  `max_background_drainers`, but enabled orphan draining is unsupported.
- `questdb-rs/src/ingress.rs:581-584` rejects `error_inbox_capacity`.
- `questdb-rs/src/ingress.rs:1948-1963` rejects
  `initial_connect_retry=async`.
- `questdb-rs/src/ingress.rs:505-508` splits `addr` once on `:`, so it does
  not store comma-separated multi-host addresses.

Java reference:

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

### 6. Default close semantics are not Java/spec compatible

Spec requirements:

- `sf-client.md:767-784` defines `close()` behavior:
  default drain up to 5 seconds, `0` or `-1` skips pre-drain `checkError()`,
  and close rethrows terminal errors unless opted out.

Rust state:

- `questdb-rs/src/ingress.rs:1255-1268` rejects
  `close_flush_timeout_millis`.
- `questdb-rs/src/ingress/sender.rs:662-669` exposes explicit
  `Sender::close_drain()`.
- `questdb-rs/src/ingress/sender/qwp_ws.rs:335-369` implements runner
  close-drain logic, but timeout is returned as an error.
- `questdb-rs/src/ingress/sender/qwp_ws.rs:709-715` runner `Drop` only stops
  and joins the runner thread.
- `questdb-rs/src/ingress/sender/qwp_ws.rs:1527-1548` uses a fixed close-drain
  timeout where close-drain is explicitly called.

Implementation direction:

- Decide whether Rust `Drop` should remain non-blocking and only explicit
  `close_drain()` follows Java, or whether public `Sender::close()` should be
  added/wired as the Java-compatible close.
- If accepting `close_flush_timeout_millis`, the behavior should match Java:
  configurable timeout, skip modes, cleanup error preservation, and terminal
  error rethrow behavior.

### 7. Overlarge ordinary OK sequences are clamped

Spec requirement:

- `sf-client.md:472-474` says ordinary OK trim computes
  `fsnAtZero + min(sequence, nextWireSeq - 1)` to defend against a buggy or
  malicious server reporting a future wire sequence.

Rust state:

- Ordinary OK responses clamp a response sequence greater than the highest sent
  sequence to the highest sent sequence before completing frames.
- Error/NACK responses remain strict protocol errors when they name a future
  sequence.

Java reference:

- `CursorWebSocketSendLoop.java` clamps with `Math.min(wireSeq, highestSent)`.

Remaining check:

- Re-check error/NACK statuses separately. The spec explicitly calls out OK;
  Java may clamp server errors too.

### 8. Reconnect timing and ACK-timeout behavior are incomplete

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

Java reference:

- `CursorWebSocketSendLoop.java` has the current reference reconnect loop.
  Verify current jitter behavior before copying the spec literally; the Java
  grep during this audit showed deterministic `Math.min(... * 2, max)` growth,
  so the spec and Java may not yet agree.

Implementation direction:

- Treat ACK-timeout reconnect as a real runtime behavior gap.
- Treat jitter as a spec/reference reconciliation item unless Java has already
  changed.

### 9. Durable ACK keepalive PING is implemented

Spec requirements:

- `sf-client.md:540-557` requires client WebSocket PING while durable
  confirmations are pending and the keepalive interval is positive.

Reference clarification:

- `wire-ingress.md` now matches `sf-client.md` and says opted-in clients
  should send WebSocket PINGs while durable confirmations are pending and
  there is no organic outbound traffic.
- Vlad Ilyushchenko clarified on 2026-05-05 that this behavior is
  intentional: without client PING, the server may not emit durable ACKs
  unless organic traffic arrives.

Rust state:

- `questdb-rs/src/ingress/sender/qwp_ws.rs:1211` replies to incoming PING with
  PONG.
- Rust sends empty outbound WebSocket PINGs while durable confirmations are
  pending and the configured interval has elapsed since the last durable-ACK
  keepalive PING.
- The public in-process WebSocket test covers: `request_durable_ack=on`,
  required upgrade echo, durable OK pending state, outbound PING, server PONG,
  delayed durable ACK completion, and `acked_fsn` advancement.

Java reference:

- `CursorWebSocketSendLoop.java:938-941` calls
  `sendDurableAckKeepaliveIfDue()` when durable mode is enabled, pending
  durable entries exist, and the interval elapsed.
- `CursorWebSocketSendLoop.java:1027-1033` documents why Java sends PINGs.

Remaining check:

- Validate against the live server once a durable-ACK-capable server is
  available in CI/manual probes.

### 10. Orphan adoption and `.failed` are missing

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

### 11. Error inbox and default error-handler behavior differ

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

### 12. Slot locking is Unix-only

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

### 13. SFA header reserved fields are validated

Spec requirement:

- `sf-client.md:260-264` says header `flags` and `reserved` must be 0.

Rust state:

- `questdb-rs/src/ingress/sender/qwp_ws_sfa_segment.rs:294-302` writes those
  fields as 0.
- Segment scan now rejects non-zero `flags` and non-zero `reserved` fields
  before accepting the segment header. Under the current recovery policy these
  are treated like other segment scan failures: a bad side file can be skipped,
  while a required segment that creates an FSN gap still fails recovery.

### 14. Fresh SFA filename conflicts with the current spec

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

### 15. Recovery behavior for corrupt or empty side files needs a spec decision

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

### 16. Torn-tail diagnostics are not operator-visible

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

See gap 14. Current Java and Rust both create `sf-initial.sfa` for a fresh
slot, while the spec says it is legacy recovery input. Resolve this before
changing Rust alone.

### Durable ACK keepalive text has been reconciled in `wire-ingress.md`

See gap 9. `sf-client.md`, `wire-ingress.md`, and current Java now agree that
durable ACK clients should send WebSocket PINGs while durable confirmations
are pending and no organic outbound traffic is available.

### Unknown-key rejection conflicts with Java

See gap 4. The current spec says unknown keys must be rejected, but current
Java still ignores unknown keys unless malformed. If strict rejection is the
new contract, Java and Rust should be changed together.

## Areas That Look Aligned

These areas were checked during the audit and should not be reopened without
new evidence:

- SPSC queue ownership and termination safety are coherent for the current
  single-sender API.
- FSN/wire sequence mapping and strict in-order send match the SF model.
- Replay frames are self-sufficient: Rust replay encoding emits dense symbol
  dictionaries from id 0 and full schema.
- Non-durable status-to-policy mapping matches the spec categories.
- Terminal WebSocket close-code routing matches the spec terminal-code set.
- OK, durable ACK, and error response payload parsing now validates required
  fixed fields, table-entry structure, bounded error messages, and trailing
  bytes.
- SFA append order is length, payload, CRC last, then queue publication.
- Torn-tail detection logic and recovered-segment sort/gap checks are aligned
  with the intended recovery model.

## Suggested Fix Order

1. Resolve spec/reference mismatches first:
   `sf-initial.sfa`, unknown-key policy.
2. Validate the durable OK emission/coalescing contract against the live
   durable-ACK server.
3. Implement Java-compatible close semantics and then accept
   `close_flush_timeout_millis`.
4. Implement ACK-timeout reconnect.
5. Decide Rust API shape for error dispatch/inbox and then support
   `error_inbox_capacity`.
6. Add orphan scanner/drainers and `.failed`, then enable `drain_orphans=on`.
7. Address lower-level SFA disk details:
   filename decision, empty-segment behavior, and operator-visible recovery
   diagnostics.
8. Decide Windows SF support:
   implement `LockFileEx` or document/fail disk SF mode clearly on Windows.

Each fix should start with a failing regression or golden fixture. For any
behavior where Java and the spec conflict, update the spec or Java first rather
than making Rust the only divergent client.
