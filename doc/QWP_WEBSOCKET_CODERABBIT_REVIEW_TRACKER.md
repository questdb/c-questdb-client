# QWP/WebSocket CodeRabbit review tracker

Collected: 2026-05-11 from PR #141.

Source: CodeRabbit review body plus 17 unresolved inline review threads on
`ia_qwp_ws`.

Status legend:

- `[ ]` open
- `[x]` resolved in code/docs and verified
- `[-]` skipped, stale, or intentionally not applicable

Keep items open until the current tree has been checked. Several items mention
the same root problem, especially portable Java reference paths; those may be
closed together by one consistent documentation cleanup.

## Actionable Inline Threads

### CR-01 - QWP/UDP C example targets may miss `examples/concat.c`

- Status: [ ]
- Priority: P1, CodeRabbit major
- Source: `CMakeLists.txt:135-140`, thread `PRRT_kwDOG7eCc86BCQDS`
- Action: Verify whether `line_sender_c_example_qwpudp` and
  `line_sender_c_example_qwpudp_batch` use helper symbols from
  `examples/concat.c`. If so, add that source to both `compile_example` calls.
- Acceptance: C examples link when examples are enabled.

### CR-02 - Refresh architecture doc for unified SFA and pump flow

- Status: [ ]
- Priority: P2, CodeRabbit minor
- Source: `doc/QWP_WEBSOCKET_ARCHITECTURE.md:24-30`, also `119-137` and
  `168-180`, thread `PRRT_kwDOG7eCc86BCQDZ`
- Action: Remove stale references to `VolatileFrameQueue`,
  `LockFreeVolatileFrameQueue`, and the old `read_message_with_close` shape.
  Document memory mode through `SfaSlotQueue::open_memory(...)` and describe
  receive progress as the `WsFrameReader` plus `TransportPoll` pump.
- Acceptance: The architecture doc maps current responsibilities to
  `QwpWsPublicationStore`, `QwpWsSendCore`, `SfaFrameQueue` or `SfaSlotQueue`,
  and the pump-based reader/transport.

### CR-03 - Add language tags to architecture doc fences

- Status: [ ]
- Priority: P2, CodeRabbit minor
- Source: `doc/QWP_WEBSOCKET_ARCHITECTURE.md:42-85`, also `109-115`,
  `191-207`, `259-285`, and `322-332`, thread
  `PRRT_kwDOG7eCc86BCQDh`
- Action: Add `text`, `rust`, or another appropriate language hint to fenced
  code blocks in the architecture doc.
- Acceptance: Markdownlint MD040 no longer reports these fences.

### CR-04 - Replace absolute Java paths in columnar buffer design doc

- Status: [ ]
- Priority: P2, CodeRabbit minor
- Source: `doc/QWP_WEBSOCKET_COLUMNAR_BUFFER_DESIGN.md:75-77`, thread
  `PRRT_kwDOG7eCc86BCQDl`
- Action: Replace `/home/jara/.../java-questdb-client/...` references with a
  portable convention such as `${JAVA_CLIENT_DIR}/...`, repo-relative paths, or
  GitHub permalinks.
- Acceptance: The document no longer depends on a local workstation path, and
  the chosen convention is consistent with the other QWP/WebSocket docs.

### CR-05 - Replace absolute Java paths in durable SFA storage doc

- Status: [ ]
- Priority: P2, CodeRabbit minor
- Source: `doc/QWP_WEBSOCKET_DURABLE_SF_STORAGE.md:115-190`, thread
  `PRRT_kwDOG7eCc86BCQDo`
- Action: Convert local Java client references for `Sender.java`,
  `MmapSegment.java`, `CursorWebSocketSendLoop.java`, `SegmentRing.java`,
  `Crc32c.java`, `WebSocketClient.java`, `WebSocketFrameWriter.java`,
  `WebSocketSendBuffer.java`, `SegmentManager.java`, `CursorSendEngine.java`,
  and `sf-client.md` to portable references.
- Acceptance: Every source reference in the range is usable by contributors
  outside this machine.

### CR-06 - Replace absolute path in final FFI API doc

- Status: [ ]
- Priority: P2, CodeRabbit minor
- Source: `doc/QWP_WEBSOCKET_FINAL_FFI_API.md:12`, thread
  `PRRT_kwDOG7eCc86BCQDy`
- Action: Replace the local `java-questdb-client` checkout path with the same
  placeholder or relative-reference convention used elsewhere.
- Acceptance: No absolute local path remains in the file.

### CR-07 - Replace absolute paths in handover doc and document setup roots

- Status: [ ]
- Priority: P2, CodeRabbit minor
- Source: `doc/QWP_WEBSOCKET_HANDOVER.md:70-81`, also around `12` and `397`,
  thread `PRRT_kwDOG7eCc86BCQD2`
- Action: Replace local absolute paths with documented placeholders such as
  `${JAVA_CLIENT_ROOT}` and add a short setup section that explains the expected
  roots.
- Acceptance: All Java/client/spec references in the handover doc are portable.

### CR-08 - Escape raw pipes inside Java parity tracker table cells

- Status: [ ]
- Priority: P2, CodeRabbit minor
- Source: `doc/QWP_WEBSOCKET_JAVA_PARITY_FOLLOWUP_PLAN.md:566-571`, thread
  `PRRT_kwDOG7eCc86BCQD-`
- Action: Escape raw pipe characters inside inline-code table cells, including
  `drain_orphans=off|false` and `request_durable_ack=off|on`.
- Acceptance: The affected table rows keep the expected column count in
  Markdown renderers and markdownlint no longer reports MD056 for those rows.

### CR-09 - Update pipelined FFI doc to post-unification storage model

- Status: [ ]
- Priority: P2, CodeRabbit minor
- Source: `doc/QWP_WEBSOCKET_PIPELINED_FFI.md:80-93`, also `435-438`,
  `599-609`, `699-701`, and `1389-1395`, thread
  `PRRT_kwDOG7eCc86BCQEE`
- Action: Remove distinct volatile-queue wording. State that memory mode uses
  `SfaSlotQueue::open_memory(...)`, public sync senders publish through the
  unified SFA pipeline, and `sf_dir` controls in-memory versus on-disk slot
  backing.
- Acceptance: FFI storage and durability wording matches the unified SFA
  implementation and no longer promises a separate volatile queue.

### CR-10 - Clarify `R4` status in self-review TODOs

- Status: [ ]
- Priority: P2, CodeRabbit minor
- Source: `doc/QWP_WEBSOCKET_SELF_REVIEW_TODOS.md:42`, also `157-162`, thread
  `PRRT_kwDOG7eCc86BCQEJ`
- Action: Resolve the contradiction between `R4` being marked `done` and the
  slice notes describing remaining architectural debt. Either mark `R4` partial
  or move remaining debt into a separate TODO.
- Acceptance: The tracker row and notes give the same status story.

### CR-11 - Replace absolute paths in spec compliance gaps doc

- Status: [ ]
- Priority: P2, CodeRabbit minor
- Source: `doc/QWP_WEBSOCKET_SPEC_COMPLIANCE_GAPS.md:15-22`, thread
  `PRRT_kwDOG7eCc86BCQEM`
- Action: Replace local paths for `docs/qwp` and `java-questdb-client` with
  portable placeholders or repo-relative references.
- Acceptance: The document declares the placeholder convention and contains no
  `/home/jara/...` source roots.

### CR-12 - Clarify `peek()` semantics for QWP/UDP versus QWP/WebSocket

- Status: [ ]
- Priority: P2, CodeRabbit minor
- Source: `include/questdb/ingress/line_sender.h:521-528`, thread
  `PRRT_kwDOG7eCc86BCQET`
- Action: Scope the existing datagram wording to QWP/UDP or explicitly document
  both QWP/UDP and QWP/WebSocket behavior for buffers produced by
  `line_sender_buffer_new_for_sender()`.
- Acceptance: C callers can tell what `peek()` returns for `qwpudp`, `qwpws`,
  and `qwpwss` buffers.

### CR-13 - Use actual `qwpws_progress` config key in C docs

- Status: [ ]
- Priority: P2, CodeRabbit minor
- Source: `include/questdb/ingress/line_sender.h:1391-1394`, thread
  `PRRT_kwDOG7eCc86BCQEY`
- Action: Replace `qwp_ws_progress=manual` with `qwpws_progress=manual` near
  `line_sender_opts_qwpws_progress(...)` and in nearby examples.
- Acceptance: Header comments use the parser's real key name.

### CR-14 - Document ownership of `line_sender_qwpws_poll_error` output

- Status: [ ]
- Priority: P2, CodeRabbit minor
- Source: `include/questdb/ingress/line_sender.h:1433-1441`, thread
  `PRRT_kwDOG7eCc86BCQEc`
- Action: State that a returned non-null `*error_out` is owned by the caller and
  must be released with `line_sender_qwpws_error_free()`. Also state that no
  diagnostic sets `*error_out` to null and needs no free.
- Acceptance: Ownership is explicit in the C API docblock.

### CR-15 - Specify the timeout used by `line_sender_qwpws_close_drain`

- Status: [ ]
- Priority: P2, CodeRabbit minor
- Source: `include/questdb/ingress/line_sender.h:1480-1488`, thread
  `PRRT_kwDOG7eCc86BCQEf`
- Action: Name the actual configured timeout that bounds `close_drain`, explain
  timeout error reporting through `err_out`, and document how callers adjust
  that budget.
- Acceptance: Shutdown latency semantics are discoverable from the header.

### CR-16 - Guard null `buffer` in bookmark FFI entrypoints

- Status: [ ]
- Priority: P1, CodeRabbit major
- Source: `questdb-rs-ffi/src/lib.rs:921-970`, thread
  `PRRT_kwDOG7eCc86BCQEi`
- Action: Add null checks to `line_sender_buffer_bookmark`,
  `line_sender_buffer_rewind_to_bookmark`, and
  `line_sender_buffer_clear_bookmark`. Return `InvalidApiCall` for the boolean
  APIs and no-op for clear.
- Acceptance: Null C buffer pointers do not cause UB in these new entrypoints.

### CR-17 - Reject `protocol_version` for QWP/WebSocket

- Status: [ ]
- Priority: P1, CodeRabbit major
- Source: `questdb-rs/src/ingress.rs:940-955`, thread
  `PRRT_kwDOG7eCc86BCQEn`
- Action: Extend the `protocol_version` setter to reject `qwpws` and `qwpwss`,
  guarded by the QWP/WebSocket feature.
- Acceptance: Programmatic builders and config parsing reject unsupported
  protocol-version settings for all QWP transports.

## Nitpick Items

### CR-N01 - Style nits in self-review TODOs

- Status: [ ]
- Priority: P3, CodeRabbit nitpick
- Source: `doc/QWP_WEBSOCKET_SELF_REVIEW_TODOS.md:51`, also `91` and `197`
- Action: Strengthen "should be first", hyphenate "high-sequence responses",
  and add an explicit subject to the best-effort Drop sentence.
- Acceptance: Text is clearer without changing tracker meaning.

### CR-N02 - Parameterize golden payload regeneration paths

- Status: [ ]
- Priority: P3, CodeRabbit nitpick
- Source: `doc/QWP_WEBSOCKET_JAVA_RUST_GOLDEN_PAYLOADS.md:39`, also `57-68`
- Action: Replace local absolute paths with variables such as
  `JAVA_CLIENT_DIR`, `C_CLIENT_DIR`, and `QWP_OUT_DIR`.
- Acceptance: Regeneration commands are portable and do not expose local paths.

### CR-N03 - Replace absolute Java paths in columnar review findings

- Status: [ ]
- Priority: P3, CodeRabbit nitpick
- Source: `doc/QWP_WEBSOCKET_COLUMNAR_BUFFER_REVIEW_FINDINGS.md:23-25`
- Action: Replace three local Java file paths with package-qualified names,
  repo-relative paths, or the shared Java-client placeholder convention.
- Acceptance: The document contains no workstation-local Java source paths.

### CR-N04 - Replace absolute Java paths in orphan draining TODO

- Status: [ ]
- Priority: P3, CodeRabbit nitpick
- Source: `doc/QWP_WEBSOCKET_ORPHAN_DRAINING_TODO.md:47-83`
- Action: Replace local Java references for `Sender`, `OrphanScanner`,
  `QwpWebSocketSender`, `BackgroundDrainer`, `CursorWebSocketSendLoop`, and
  `BackgroundDrainerPool` with portable references.
- Acceptance: The document states a Java reference root and all source paths are
  relative to it.

### CR-N05 - Replace local Java paths in ready/receive design note

- Status: [ ]
- Priority: P3, CodeRabbit nitpick
- Source: `doc/QWP_WEBSOCKET_JAVA_LIKE_READY_RECEIVE.md:15-29`
- Action: Use repo-relative Java source references and explicit symbols, and
  add a pinned commit or branch note.
- Acceptance: Readers can locate the referenced Java implementation without the
  author's workstation path.

### CR-N06 - Replace local paths in Java parity follow-up plan

- Status: [ ]
- Priority: P3, CodeRabbit nitpick
- Source: `doc/QWP_WEBSOCKET_JAVA_PARITY_FOLLOWUP_PLAN.md:19-21`, also
  `107-114`
- Action: Replace hardcoded local repository paths with portable placeholders
  and explain what each placeholder means.
- Acceptance: The handoff plan is reusable on another checkout layout.
