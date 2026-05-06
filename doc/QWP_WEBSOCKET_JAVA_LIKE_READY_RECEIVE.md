# QWP/WebSocket Java-aligned pump receive design

Date: 2026-05-06

Status: implemented in the current working tree for the durable ACK keepalive
follow-up. Re-check the referenced source files before carrying this design to
another branch; both Rust and Java are moving.

## Context

The Rust public durable ACK slice added idle WebSocket PINGs while durable ACKs
are pending. That exposed a receive-loop mismatch with the Java reference
client.

Java uses a non-blocking frame pump:

- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/CursorWebSocketSendLoop.java`
  - `run()` calls `tryReceiveAcks()`.
  - `tryReceiveAcks()` loops while `client.tryReceiveFrame(responseHandler)`
    returns `true`.
  - The loop sends a durable-ACK keepalive PING only when no send or receive
    work happened.
- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/http/client/WebSocketClient.java`
  - `tryReceiveFrame(...)` first parses already-buffered bytes, then performs at
    most one non-blocking `recv`, then parses once more.
  - `tryParseFrame(...)` consumes exactly one complete WebSocket frame and
    returns `PARSE_OK` for control frames as well as data frames.
  - `PING` sends a `PONG`; `PONG` calls the handler and returns as completed
    work. It does not keep reading until a later binary frame arrives.

Java's generic `WebSocketClient` also has a blocking
`receiveFrame(handler, timeout)` helper. That is not the Store-and-Forward
sender reference. The SF sender loop uses `tryReceiveFrame(...)` only; blocking
frame receive is used by other Java QWP/WebSocket clients such as query/egress.

The implemented Rust ready path now follows the same pump shape:

- `questdb-rs/src/ingress/sender/qwp_ws_driver.rs`
  - `BlockingQwpWsTransport::try_poll_response()` calls the transport-owned
    `WsFrameReader` and maps a consumed control frame or non-final fragment to
    `TransportPoll::Progress`.
- `questdb-rs/src/ingress/sender/qwp_ws.rs`
  - `WsFrameReader::try_read_one()` parses at most one complete frame per pump
    call, replies to `PING` with `PONG`, reports `PING`/`PONG` as progress, and
    preserves any buffered following frame for the next pump call.

Therefore a readable `PONG` is one unit of progress: Rust consumes it and
returns to the outer loop immediately instead of blocking for a later binary
durable ACK.

## Goal

Make Rust's established-WebSocket progress loop Java-like:

- parse and handle at most one complete WebSocket frame per low-level
  `try_poll_response()` call,
- drain ready receive frames in the driver loop until the transport reports
  idle, just like Java loops on `tryReceiveFrame(...)`,
- never block waiting for a data frame after consuming a control frame,
- preserve already-read bytes so `PONG + durable ACK` in one TCP/TLS read is
  consumed by consecutive pump calls without needing a fresh socket-readability
  signal,
- report control-frame handling as progress, not idle,
- use the same non-blocking pump primitive for background progress, manual
  progress, and `await_acked_fsn()`.

## Non-goals

- Do not rewrite QWP response parsing.
- Do not change durable ACK tracking semantics.
- Do not change publication-store locking or queue ownership.
- Do not introduce a callback API for durable ACKs; durable ACK remains exposed
  through the existing acked-FSN progress surface.
- Do not remove blocking I/O from connection setup, HTTP upgrade, or ordinary
  socket writes. This note only removes blocking ACK receive from the
  established WebSocket progress loop.

## Proposed API shape

Replace the transport receive API with a three-way pump result:

```rust
enum TransportPoll {
    Response(TransportResponse),
    Progress,
    Idle,
}
```

`Progress` means a WebSocket frame was consumed or answered, but no QWP
application response is ready yet. Examples:

- server `PONG` in response to our keepalive PING,
- server `PING` answered with a client `PONG`,
- non-final data fragment appended to an in-progress message.

`ManualDriverTransport` should expose:

```rust
fn try_poll_response(&mut self) -> Result<TransportPoll, TransportFailure>;
```

There should be no established-WebSocket `poll_response()` that blocks waiting
for a QWP response. Test transports should model the same pump contract by
returning `Response`, `Progress`, or `Idle`.

Driver mapping:

- `TransportPoll::Response(response)` -> existing `finish_response(...)`.
- `TransportPoll::Progress` -> a new driver/runner progress outcome.
- `TransportPoll::Idle` -> maybe send durable-ACK keepalive if due.

This mirrors Java's `didWork` flag: a consumed control frame is work and should
prevent the loop from parking or sending another keepalive in the same turn.

`QwpWsPublicationDriver::drive_once()` should always be pump based:

1. send at most one queued frame,
2. drain currently ready receive frames by calling `try_poll_response()` until
   it returns `Idle`,
3. if no send or receive work happened and durable ACK is pending, maybe send
   the durable keepalive PING,
4. return whether the call performed useful work.

This mirrors Java's split: `trySendOne()` is bounded to one outbound frame for
fairness, while `tryReceiveAcks()` drains all immediately available inbound
frames before the loop parks.

Background runner parity detail: Java does not set `didWork = true` after
sending the durable keepalive PING; it still parks briefly after prodding the
server. Rust should use the same meaning for background and manual progress:
keepalive-only turns do not count as progress. They should map to the
sleep/park outcome in the background runner and `Ok(false)` from public manual
`drive_once()`.

`Sender::await_acked_fsn(...)` should keep its current shape: check the acked
watermark, call `drive_once()` in manual mode, then sleep or return on deadline.
That mirrors Java's `awaitAckedFsn(...)`, which waits by checking the cursor
watermark and parking briefly rather than by doing a blocking receive on the
caller thread.

## WebSocket reader

Add a stateful WebSocket frame reader owned by `BlockingQwpWsTransport`.
The reader owns both raw input and the assembled message buffer:

```rust
struct WsFrameReader {
    input: Vec<u8>,
    read_pos: usize,
    fragment_opcode: Option<u8>,
    message: Vec<u8>,
}

enum WsFrameRead {
    Message { opcode: u8 },
    Progress,
    Idle,
}
```

`BlockingQwpWsTransport` should not keep a second assembled-message `recv`
buffer. On `WsFrameRead::Message`, the transport should borrow the completed
message slice from the reader, decode the QWP response, and then let the reader
clear/reuse that message buffer before the next data message. This keeps raw
framing state and assembled-message ownership in one place.

### Pump mode

`try_read_one(...)` should be the only established-WebSocket receive primitive:

1. Try to parse one complete frame from already-buffered input.
2. If incomplete, perform at most one non-blocking read into the input buffer.
3. Try to parse one complete frame again.
4. Return `Idle` if no full frame is available.
5. Return `Progress` after handling one control frame or one non-final
   fragment.
6. Return `Message` only when a full text/binary message is assembled.

It must not loop after `Progress`. If the input buffer contains `PONG` followed
by `STATUS_DURABLE_ACK`, the first call returns `Progress`; the next call sees
the already-buffered durable ACK and returns `Message`.

The low-level reader is intentionally one-frame-at-a-time. The higher-level
driver performs Java's `while (tryReceiveFrame(...))` behavior by calling the
reader repeatedly until it returns `Idle`.

After each consumed frame, advance `read_pos` and compact or reset the raw input
buffer using a fixed rule. Recommended rule:

- if `read_pos == input.len()`, clear the input buffer and reset `read_pos` to
  zero;
- otherwise compact when `read_pos >= 4096 && read_pos * 2 >= input.len()`.

This is the Rust equivalent of Java's `recvReadPos += consumed` followed by
`compactRecvBuffer()`. The exact threshold can change if profiling says so, but
the implementation must have a deterministic compaction rule and regression
coverage so sustained small frames do not grow the raw input buffer without
bound.

## Frame semantics

The parser should preserve the existing Rust WebSocket rules:

- server frames must not be masked,
- client `PONG` replies must be masked,
- control frames must be final and at most 125 bytes,
- oversized frames are protocol violations,
- close frames surface through the existing close-code classification,
- data continuations must follow a non-final data frame,
- a new data frame during an unfinished fragmented message is a protocol
  violation.

Frame outcomes:

| Frame | Ready outcome | Notes |
| --- | --- | --- |
| `PING` | `Progress` | Read payload, send masked `PONG`, return immediately. |
| `PONG` | `Progress` | Read payload and return immediately. |
| `CLOSE` | error | Preserve terminal close-code mapping. |
| final `BINARY`/`TEXT` | `Message` | Parse as a QWP response in transport code. |
| non-final `BINARY`/`TEXT` | `Progress` | Start fragmented message. |
| non-final `CONTINUATION` | `Progress` | Append fragment. |
| final `CONTINUATION` | `Message` | Finish fragmented message. |

Java invokes callbacks for all of these frames. Rust does not need to introduce
callbacks; `TransportPoll::Progress` is the callback-free equivalent for
control/fragment progress, while `TransportPoll::Response` is the equivalent of
Java's `onBinaryMessage(...)` path.

## Plain TCP and TLS reads

The current `can_read_without_blocking() -> poll_response()` shortcut is not
strong enough. Readability of the underlying socket means "some bytes exist",
not "a whole WebSocket data message is ready".

The ready reader should instead perform an actual non-blocking read attempt.
For the current synchronous transport, prefer a scoped nonblocking-read guard
over permanently switching the socket to nonblocking mode. A fully nonblocking
transport would also need `WouldBlock` handling for writes and is a broader
refactor.

- temporarily put the underlying `TcpStream` into non-blocking mode,
- call `Read::read` on the active `WsStream`,
- treat `WouldBlock` as "no more bytes available now",
- restore blocking mode before returning.

The temporary mode switch must be implemented with an RAII/drop guard, not a
trailing `set_nonblocking(false)` call. The guard should restore blocking mode
on early `?` returns and during unwinding.

For plain TCP, `Read::read` returning `Ok(0)` means EOF/peer disconnect and must
surface as a disconnect. Idle is represented by `WouldBlock`, not `Ok(0)`.

For TLS, the read must go through `rustls::StreamOwned` so decrypted bytes and
rustls' internal plaintext buffer are respected. A non-blocking underlying
socket should cause rustls to return `WouldBlock` when it needs more network
bytes. Partial TLS-record progress is safe: rustls retains its internal
incomplete-record state and resumes on the next read. The reader must also parse
any already-buffered plaintext before trying the socket.

Implementation detail: keep the helper on `WsStream`, for example:

```rust
impl WsStream {
    fn read_nonblocking_once(&mut self, out: &mut [u8]) -> std::io::Result<usize>;
}
```

The helper should restore blocking mode even on error.

## QWP response parsing boundary

Keep QWP response parsing in `BlockingQwpWsTransport`, not inside the WebSocket
reader.

The WebSocket reader should only return a completed message opcode and payload
bytes. Transport code should then preserve the existing policy:

- binary response required for QWP status frames,
- OK/NACK/error/durable-ACK decoding through `qwp_ws_codec.rs`,
- ACK wire-sequence mapping through `pending_wire_sequences`,
- durable ACK table-watermark handling through the publication store/core.

This keeps WebSocket framing independent from QWP semantics, matching the
existing layering.

## Durable keepalive details

The Java keepalive PING is empty:

- `WebSocketClient.sendPing(...)` calls `WebSocketSendBuffer.writePingFrame()`.
- `writePingFrame()` delegates to `writePingFrame(0, 0)`.

The earlier Rust durable keepalive implementation sent `b"da"`. The payload is
legal, but the Java-like implementation sends an empty payload.

Implementation note: the current Rust change sends an empty keepalive PING. The
visible wire-shape change is recorded in
`doc/QWP_WEBSOCKET_SPEC_COMPLIANCE_GAPS.md`; this repo does not currently have
a dedicated project changelog.

Throttle policy can remain Rust-specific, but the closest Java match is:

- Java throttles against the last keepalive PING timestamp.
- Java resets that timestamp on reconnect so the new connection can prod
  immediately.
- Java sends the keepalive only after a loop turn with no send and no receive
  work.

Rust currently throttles against last outbound activity, including ordinary
binary sends. That is defensible because ordinary binary traffic already prods
the server's receive path, but it is not Java parity. The Java-aligned target is
to track `last_durable_keepalive_ping` separately from data sends.

## Tests

Add focused tests before or with the implementation:

1. Ready read consumes a server `PONG` and returns progress without blocking for
   a following binary frame.
2. Ready read handles `PONG + durable ACK` buffered together: first poll returns
   progress, second poll returns the durable ACK response without requiring a
   fresh socket-readability signal.
3. Driver/background pump drains `PONG + durable ACK` in one progress turn by
   repeatedly calling the one-frame reader until idle.
4. Ready read handles server `PING` by writing a masked `PONG` and returning
   progress.
5. Background durable ACK path: mock server replies to the keepalive PING with
   `PONG`, delays durable ACK, and the runner does not stall until
   `request_timeout`.
6. Keepalive PING writer emits an empty masked client PING if switching to Java
   payload parity.
7. Keepalive-only background turn parks or yields instead of spinning
   immediately, matching Java's `didWork` handling.

Regression test 2 is important because it catches a common incorrect fix: stop
after control frames but discard or hide bytes that arrived in the same network
read.

## Migration plan

1. Add `WsFrameReader` with byte-slice parsing and tests using in-memory frame
   buffers.
2. Add `TransportPoll` and map test transports through it.
3. Route `BlockingQwpWsTransport::try_poll_response()` through pump-mode
   `WsFrameReader`, while leaving the old blocking path in place until the new
   path compiles and focused tests pass.
4. Make the driver drain ready receive frames until `Idle` after at most one
   outbound data send.
5. Make background progress, manual `drive_once()`, and manual
   `await_acked_fsn()` all use the same pump primitive.
6. Align durable keepalive with Java where practical: empty PING payload,
   last-keepalive timestamp, reset on reconnect, and no background spin after a
   keepalive-only turn.
7. Add durable keepalive PONG-delay regression coverage.
8. Delete the established-WebSocket blocking `poll_response()` path from the
   driver and transport traits once the pump path is the only live caller.
9. Run the focused QWP/WebSocket tests, clippy, fmt check, and `git diff
   --check`.

## Implementation checklist

Use this section as the concrete Rust edit map. Names are from the current
`ia_qwp_ws` branch and may need a quick re-check before editing.

### Driver and transport API

- In `questdb-rs/src/ingress/sender/qwp_ws_driver.rs`, add:

  ```rust
  enum TransportPoll {
      Response(TransportResponse),
      Progress,
      Idle,
  }
  ```

- Change `ManualDriverTransport::try_poll_response(...)` to return
  `Result<TransportPoll, TransportFailure>`.
- Remove `ManualDriverTransport::poll_response(...)` from the established
  WebSocket progress path.
- Remove or stop using `QwpWsSendCore::poll_response(...)`.
- Remove or stop using `QwpWsPublicationDriver::drive_receive_once(...)` as a
  blocking ACK receive step.
- Rework `QwpWsPublicationDriver::drive_once(...)` so it:
  - sends at most one outbound frame,
  - drains ready inbound frames through `try_poll_response()` until `Idle`,
  - sends durable keepalive only when the turn was otherwise idle and durable
    ACK is pending,
  - returns progress if it sent data or consumed/handled any inbound frame;
    keepalive-only turns should return no-progress to match Java's `didWork`
    semantics.
- Rework `QwpWsPublicationDriver::drive_ready_once(...)` to use the same pump
  path or delete the separate ready/blocking distinction if all callers can use
  `drive_once()`.

### Runner mapping

- In `questdb-rs/src/ingress/sender/qwp_ws.rs`, update
  `SyncQwpWsRunner::finish_receive(...)` to handle `TransportPoll`.
- Suggested mapping:
  - `Response(response)` -> existing `finish_response(...)`; notify
    backpressure; map the returned `DriveOutcome` as today.
  - `Progress` -> `RunnerStep::Continue`.
  - `Idle` -> evaluate durable keepalive.
- For Java parity, a background keepalive-only turn should not tight-spin. It
  should send the PING and then return `RunnerStep::Idle`, the existing
  sleep/park outcome.
- Manual `drive_once()` should use the same progress meaning as the background
  runner: keepalive-only turns return no-progress.
- Do not hold the publication-store mutex while draining network frames. The
  runner should call `try_poll_response()` without the store lock and lock only
  around `finish_response(...)` for each decoded response, preserving the
  current lock-hold shape.

### WebSocket parser state

- In `BlockingQwpWsTransport`, add a dedicated `WsFrameReader` equivalent to
  Java's `recvBuf`, `recvPos`, and `recvReadPos`.
- Required state:
  - raw input bytes,
  - consumed/raw-read offset,
  - current fragmented-message opcode,
  - assembled message payload buffer.
- `WsFrameReader` owns the assembled message buffer. The transport should not
  keep a second `recv` buffer for completed WebSocket messages.
- Raw buffered bytes must survive across calls. This is required for
  `PONG + STATUS_DURABLE_ACK` delivered by one socket/TLS read.
- Clear the assembled message payload only when starting a new data message,
  not when a control frame is consumed.
- After a frame is consumed, advance the read offset and compact/reset the raw
  input buffer using the fixed compaction rule above. Do not drop unconsumed
  trailing bytes.

### Partial frame behavior

The one-frame reader must distinguish incomplete data from protocol errors:

- incomplete 2-byte header after one nonblocking read -> `Idle`;
- incomplete extended length -> `Idle`;
- incomplete control or data payload -> `Idle`;
- incomplete fragmented message after a non-final frame was consumed ->
  `Progress` for the consumed frame, then later `Idle` until more bytes arrive;
- masked server frame -> protocol violation;
- fragmented control frame -> protocol violation;
- control payload larger than 125 bytes -> protocol violation;
- continuation without a prior non-final data frame -> protocol violation;
- new data frame while a fragmented message is open -> protocol violation.

`Idle` must mean "no complete frame is available now", not "connection closed".
For Rust `Read` on a TCP stream, `Ok(0)` means EOF/peer disconnect; only
`WouldBlock` maps to idle.

### Close and error mapping

Preserve the current mapping in `BlockingQwpWsTransport::poll_response(...)`
when converting WebSocket reader errors:

- close frame with terminal close code -> `TransportFailure::ProtocolViolation`
  with the close code and reason,
- close frame with reconnect-eligible close code ->
  `TransportFailure::Disconnect(close.into_error())`,
- WebSocket protocol violation -> `TransportFailure::ProtocolViolation`,
- socket/read/write errors -> `TransportFailure::Disconnect` unless the
  existing code classifies the error as terminal.

QWP response decoding should remain outside the WebSocket reader:

- non-binary completed messages are protocol violations,
- durable mode uses `decode_durable_transport_response(...)`,
- non-durable mode uses `decode_transport_response(...)`,
- ACK/DurableOk/Reject responses still call `complete_pending_through(...)`.

### Nonblocking read helper

- Replace `can_read_without_blocking() -> poll_response()` with a real
  nonblocking read attempt.
- Add a helper on `WsStream`, for example
  `read_nonblocking_once(&mut self, out: &mut [u8])`.
- The helper must:
  - temporarily set the underlying `TcpStream` nonblocking,
  - call `Read::read` on the active `WsStream` so TLS plaintext buffering is
    respected,
  - restore blocking mode with a drop guard before returning, including on
    error and unwind,
  - map `WouldBlock` to "no bytes available now".
- Parse already-buffered raw input before attempting any socket read.
- Do not permanently switch the existing sync transport to nonblocking unless
  the implementation also broadens the slice to handle `WouldBlock` correctly
  on writes.

### Keepalive parity

- Change durable keepalive PING payload from `b"da"` to empty.
- Track the throttle as last durable keepalive PING timestamp, not last
  outbound data activity, unless a deliberate Rust-specific decision is made.
- Reset the keepalive timestamp on reconnect so a new connection can prod the
  server immediately.
- Only consider sending the keepalive after the pump turn had no send and no
  receive work.

### Public behavior note

Manual `Sender::drive_once()` may consume more inbound work than before because
the Java-aligned loop drains ready frames until idle after at most one outbound
send. This is intentional. It still satisfies the public contract that
`drive_once()` returns immediately and reports whether progress was available.
Durable keepalive-only turns are not reported as progress.

## Validation commands

Run at least:

```sh
cargo test --manifest-path questdb-rs/Cargo.toml qwp_ws --lib
cargo test --manifest-path questdb-rs/Cargo.toml qwp_ws_driver --lib
cargo clippy --manifest-path questdb-rs/Cargo.toml --lib --tests -- -D warnings
cargo fmt --manifest-path questdb-rs/Cargo.toml --check
git diff --check
```

If tests are renamed or split while implementing, keep equivalent focused
coverage for:

- WebSocket frame parser/control-frame tests,
- durable ACK public-path tests,
- manual driver tests,
- reconnect/close-code error mapping tests,
- raw input compaction/growth tests.

When shipping the empty keepalive PING change, mention it in the changelog or
release notes because it is visible to server-side frame logging or filters.

## Rejected alternatives

### Keep `can_read_without_blocking()` and stop after control frames

This fixes only the obvious `PONG` loop. It does not solve partial headers,
partial payloads, or `PONG + ACK` buffered in one read. It also leaves two
separate frame-reading models in the code.

### Add a socket read timeout around `try_poll_response()`

This bounds the stall but does not make the ready path non-blocking. It would
still delay progress and would not match Java's pump.

### Keep a separate blocking ACK receive path

This is unnecessary for Java parity and weakens the public manual-progress
contract. Java's sender loop uses `tryReceiveFrame(...)`, and user-facing waits
observe the acked watermark with short parks. Rust can use the same shape: one
non-blocking pump primitive for established WebSocket progress, with deadlines
handled by the caller loop.

### Parse QWP responses directly from the socket-ready path

That would mix WebSocket framing, QWP response parsing, and durable ACK state in
one place. The current architecture deliberately keeps frame transport separate
from QWP response semantics; this design preserves that split.
