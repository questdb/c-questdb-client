# QWP/WebSocket Notification-Only Error Delivery

Status: design

This document captures the planned simplification of QWP/WebSocket structured
error delivery. It supersedes the pollable-diagnostic parts of
`QWP_WEBSOCKET_ERROR_HANDLING.md`, `QWP_WEBSOCKET_FINAL_FFI_API.md`, and
`QWP_WEBSOCKET_ARCHITECTURE.md` until those documents are cleaned up.

## Goal

Simplify QWP/WebSocket error delivery and bring the Rust/C/C++/Python shape
closer to the Java client.

The current Rust implementation exposes two public diagnostic consumption paths:

- a callback path through `qwp_ws_error_handler`;
- a pull path through `poll_qwp_ws_error` / `line_sender_qwpws_poll_error`.

Supporting both paths forces the driver to keep independent poll and notification
cursors over the same diagnostic stream. That is extra code and extra public API
for a QWP feature that has not been released as a stable compatibility surface.

The target is a Java-like public model:

- callbacks notify users about non-terminal and terminal server diagnostics;
- terminal errors are attached to later public `Sender` failures;
- dropped-notification accounting remains available;
- there is no public "poll next diagnostic" queue.

## References

Java reference:

- [SenderErrorHandler.java](../../questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/SenderErrorHandler.java)
- [QwpWebSocketSender.java](../../questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/QwpWebSocketSender.java)
- [CursorWebSocketSendLoop.java](../../questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/CursorWebSocketSendLoop.java)

Current Rust/C/C++/Python surfaces to change or preserve:

- [Rust Sender](../questdb-rs/src/ingress/sender.rs)
- [Rust QWP driver](../questdb-rs/src/ingress/sender/qwp_ws_driver.rs)
- [C FFI implementation](../questdb-rs-ffi/src/lib.rs)
- [C header](../include/questdb/ingress/line_sender.h)
- [C++ wrapper](../include/questdb/ingress/line_sender.hpp)
- [Python Cython sender](../../py-questdb-client/src/questdb/ingress.pyx)
- [Python FFI declarations](../../py-questdb-client/src/questdb/line_sender.pxd)

## Decision

Remove the public pollable diagnostic API:

- remove Rust `Sender::poll_qwp_ws_error`;
- remove C `line_sender_qwpws_poll_error`;
- remove the C owned `line_sender_qwpws_error` object API if it is only used for
  polling;
- remove C++ `line_sender::poll_qwp_ws_error`;
- remove Python `Sender.poll_qwp_ws_error`;
- remove tests and docs that advertise post-hoc diagnostic polling.

Keep the notification and terminal-error APIs:

- keep Rust `SenderBuilder::qwp_ws_error_handler`;
- keep C `line_sender_opts_qwpws_error_handler`;
- keep C++ `opts::qwp_ws_error_handler`;
- keep Python `qwp_ws_error_handler`;
- keep terminal diagnostic lookup through public errors, such as
  `line_sender_error_qwpws_get_view`, C++ exception diagnostic access, and
  Python `IngressError.qwp_ws_error`;
- keep `qwp_ws_errors_dropped`, but define it as dropped callback-notification
  count, not as a unified poll-plus-callback log drop count.

Do not add compatibility shims for the removed poll API unless a later decision
explicitly treats QWP/WebSocket as a released stable ABI. The simplification goal
is to remove the second public consumption model, not to hide it behind another
wrapper.

## Public Contract

### DROP and Continue

For a server rejection whose policy is DROP:

- the affected frame is completed according to the QWP protocol;
- the sender continues accepting later frames;
- the structured diagnostic is delivered through the configured error handler;
- no later `poll_qwp_ws_error` equivalent exists.

Users who need non-terminal diagnostics must install a handler before sending.
The default handler must remain loud enough that diagnostics are not silently
lost when the user does not configure a custom handler.

### HALT and Terminal Failures

For a HALT rejection or terminal protocol failure:

- terminal state is recorded before user notification;
- the configured handler receives the structured diagnostic;
- later public sender calls fail and carry the terminal structured diagnostic;
- non-consuming terminal lookup may remain internal if the FFI layer needs it to
  attach diagnostics to returned errors.

The terminal diagnostic path must not depend on the removed polling API.

### Dropped Notifications

Notification delivery may remain bounded. When the callback-notification queue
overflows, `qwp_ws_errors_dropped` reports dropped notifications.

This should match Java's `getDroppedErrorNotifications()` conceptually. It is
not a count of entries lost from a shared poll-and-notification diagnostic log.

## Internal Model

Use one internal notification stream, not two public consumer cursors.

`QwpWsPublicationStore` may own:

- terminal sender-error payloads;
- bounded pending notification records;
- dropped-notification counters;
- rejected-frame history needed to materialize terminal errors.

It should not own a public poll cursor. It should not retain entries solely so a
polling API can consume them after callback delivery.

`Sender` remains responsible for invoking user callbacks. Store, core, runner,
manual driver, and progress-thread code must not call user callbacks directly.
This preserves the current Rust/Python lifetime and reentrancy boundary and
avoids copying Java's callback dispatcher thread into Rust.

The implementation can keep a small queue or ring for pending callback
notifications. It should not keep the current independent `poll_next_seq` and
`notification_next_seq` shape once public polling is gone.

## Delivery Points

After polling is removed, callback delivery must not depend only on `flush` and
`close_drain`.

Every public API that can drive or observe QWP/WebSocket progress should drain
pending notifications at a predictable point before returning, including:

- publish/flush APIs;
- manual `drive_once`;
- `await_acked_fsn`;
- status reads that report published, completed, or ACKed progress;
- `close_drain` and close/error paths.

This requirement matters because users can rely on progress APIs instead of
`flush` after the frame has been published. Without the poll API, the callback is
the only non-terminal diagnostic delivery surface.

Callback invocation must remain non-reentrant with respect to the same sender:
document that handlers must not call back into that sender, and avoid holding
store/core locks while invoking user code.

## Python Client

The Python source is already shaped for callback delivery:

- it exposes `qwp_ws_error_handler`;
- it converts C diagnostic views into `QwpWsError`;
- its Cython trampoline enters with the GIL and invokes the Python handler;
- `IngressError.qwp_ws_error` carries terminal diagnostics.

Python should remove `Sender.poll_qwp_ws_error` and all related `.pyi`, `.pyx`,
and `.pxd` declarations that only support owned poll results.

Keep:

- `QwpWsError` and related enums;
- `qwp_ws_error_handler`;
- default logging handler;
- terminal `IngressError.qwp_ws_error`;
- `qwp_ws_errors_dropped`, if the C/Rust layer keeps dropped-notification
  telemetry.

The vendored `c-questdb-client` copy under `py-questdb-client` must be updated in
the same implementation work. The Python source may already declare callback
symbols, but the vendored C/Rust snapshot must actually provide them.

## Tests

Prefer behavior tests over internal cursor-shape tests.

Keep or add tests that prove:

- callback delivery receives DROP diagnostics and progress continues;
- callback delivery receives HALT diagnostics and later calls fail with the same
  structured terminal diagnostic;
- manual and background progress modes expose the same user-visible behavior;
- terminal `line_sender_error` / C++ exception / Python `IngressError` carries a
  structured diagnostic without using polling;
- dropped-notification count increases when the notification queue overflows;
- Python callback delivery works through the real FFI callback path.

Delete or rewrite tests that exist only to prove:

- `poll_qwp_ws_error` consumes independently from callbacks;
- a poll cursor and a notification cursor retain separate positions;
- old poll API docs/examples remain valid.

Do not replace poll tests with fake registration-only callback tests. A useful
callback test must create a real QWP/WebSocket diagnostic and observe the handler
receiving it.

## Implementation Outline

1. Update design/API docs to make notification-only delivery the QWP target.
2. Remove Rust public `Sender::poll_qwp_ws_error` and internal callers that exist
   only to service public polling.
3. Simplify `SenderErrorLog` or its replacement to one notification consumer and
   one dropped-notification counter.
4. Ensure all progress-driving and progress-observing public APIs drain
   notifications without holding store/core locks while invoking user code.
5. Remove C `line_sender_qwpws_poll_error` and the owned poll-result API.
6. Remove C++ and Python poll wrappers and examples.
7. Update C/C++/Python documentation to describe callbacks, terminal diagnostics,
   and dropped notifications.
8. Update system and unit tests to assert behavior through callbacks and terminal
   errors.
9. Update the vendored `c-questdb-client` snapshot in the Python repository.

## Non-Goals

- Do not add a Java-style asynchronous callback dispatcher thread to Rust.
- Do not change manual mode to start a background thread.
- Do not introduce a generic diagnostic/event framework.
- Do not preserve the removed poll API through compatibility shims unless QWP
  API stability is explicitly reprioritized.
- Do not fold this into the lock-free hot-path work unless a change naturally
  overlaps. Error notification delivery is cold/API-facing behavior.

## Risks

- This is a source and ABI break for QWP C/C++/Python users. It is acceptable
  only while QWP/WebSocket remains unreleased as a stable API.
- Callback delivery becomes the only non-terminal diagnostic surface. Missing a
  drain point would make diagnostics appear lost.
- Python must keep callback object lifetime and GIL handling correct.
- Dropped-count semantics change from "unified diagnostic log drops" to
  "callback-notification drops"; docs and tests must say that explicitly.
