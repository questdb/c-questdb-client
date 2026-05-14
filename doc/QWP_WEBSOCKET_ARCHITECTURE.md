# QWP/WebSocket Sender — High-Level Architecture

This document describes the architecture of the synchronous QWP/WebSocket
sender in `questdb-rs` (`feature = "sync-sender-qwp-ws"`). It covers the
layered module structure, key concepts (FSN vs wire sequence, publication
store, manual vs background progress), the threading model, the lifecycle of
one batch, error/reconnect handling, and the expected interaction between
user code and the sender.

The on-the-wire protocol itself (HTTP/1.1 upgrade, version negotiation,
response formats, status bytes) is specified by `QWP_SPECIFICATION` and is
not re-described here.

---

## 1. Where it lives

All code is under `questdb-rs/src/ingress/sender/`:

| File | Role |
| --- | --- |
| `qwp_ws.rs` | Public glue: `SyncQwpWsHandlerState` / `ManualQwpWsHandlerState`, `SyncQwpWsRunner` (background thread), queue selection (`open_configured_qwp_ws_queue`), connection setup, WebSocket I/O helpers (`write_binary_frame`, `read_message_with_close`, `WsFrameReader`, `perform_upgrade`). |
| `qwp_ws_publisher.rs` | Payload-aware shell: `QwpWsPublicationDriver` + `QwpWsReplayEncoder`. Turns a `QwpWsColumnarBuffer` into a self-sufficient replay payload and submits it. |
| `qwp_ws_driver.rs` | Replay-payload-opaque core: `QwpWsPublicationStore`, `QwpWsSendCore`, `SendCursor`, `ReconnectPolicy`, the `PublicationLog` and `ManualDriverTransport` traits, `BlockingQwpWsTransport`, `FakeOrderedServer` (test). Also QWP response/error categorization. |
| `qwp_ws_queue.rs` | Shared payload-layer types only: `QwpReceipt`, `QwpReceiptStatus`, `SentFrame`, `OutboundFrame`/`OutboundFrameView`, `QueueError`. No queue implementation lives here. |
| `qwp_ws_codec.rs` | Pure-bytes WebSocket framing + HTTP/1.1 upgrade builders (`build_upgrade_request`, `validate_upgrade_response`) + QWP pipelined-response decoder. No I/O. |
| `qwp_ws_ownership.rs` | Public types: `QwpWsProgress`, `QwpWsSenderError`, `QwpWsErrorHandler`, `QwpWsErrorCategory`, `QwpWsErrorPolicy`. |
| `qwp_ws_sfa_segment.rs` | Java `.sfa` segment file format: 24-byte segment header, 8-byte frame header, CRC32C, torn-tail recovery, `memmap2`-backed mappings. |
| `qwp_ws_sfa_queue.rs` | `SfaFrameQueue` adapts a directory or anonymous-mapped segment ring to `PublicationLog`. Owns `SfaEngine` (segments + watermarks), `SfaProducer` (single-writer handle), and the `.ack-watermark` sidecar for recovery. |
| `qwp_ws_sfa_slot.rs` | `SfaSlotQueue` wraps `SfaFrameQueue` with a per-sender directory `<sf_dir>/<sender_id>/` and a `.lock`/`.lock.pid` file. Memory-only mode opens without a lock. This is the only `PublicationLog` impl actually instantiated by the production sender. |
| `qwp_ws_orphan.rs` | `OrphanDrainerPool` / `ManualOrphanDrainers` for replaying sibling sender-id slots left behind by crashed senders. |

Public configuration lives in `ingress/conf.rs`: `QwpWsConfig`, `SfDurability`
(`Memory`; `Flush` and `Append` are parsed but currently rejected),
`QwpWsInitialConnectMode` (`Off | Sync | Async`, default `Off`).

---

## 2. Layered architecture

Everything below `QwpWsPublicationDriver` treats published replay payload bytes
as **opaque**: the store, queue, and send cursor shuttle bytes identified only
by frame sequence number (FSN). The lower driver/transport still parse
QWP/WebSocket response and control frames so they can apply ACKs, rejections,
durable-ACK coverage, and reconnect policy.

```
┌──────────────────────────────────────────────────────────────────┐
│ Sender (ingress/sender.rs) — protocol dispatch                   │
└──────────────────────────────────────────────────────────────────┘
                            │ flush() / flush_and_get_fsn()
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│ SyncQwpWsHandlerState  /  ManualQwpWsHandlerState  (qwp_ws.rs)   │
│   • encoder (background) OR publisher (manual)                   │
│   • SyncQwpWsRunner (background)                                 │
│   • optional OrphanDrainerPool / ManualOrphanDrainers            │
└──────────────────────────────────────────────────────────────────┘
                            │ replay payload bytes
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│ QwpWsPublicationDriver + QwpWsReplayEncoder (qwp_ws_publisher.rs)│
│   • encodes QwpWsColumnarBuffer → self-sufficient replay message │
│   • last layer that knows outbound QWP batch semantics           │
└──────────────────────────────────────────────────────────────────┘
                            │ submit(&[u8]) → QwpReceipt { fsn }
                            ▼
┌──────────────────────────┬───────────────────────────────────────┐
│ QwpWsPublicationStore<Q> │  QwpWsSendCore<T>   (qwp_ws_driver.rs)│
│   queue + lifecycle +    │    transport +                        │
│   events + errors +      │    SendCursor (FSN ↔ wire_seq) +      │
│   optional durable-ACK   │    ReconnectPolicy                    │
└────────────┬─────────────┴─────────────┬─────────────────────────┘
             │ PublicationLog            │ ManualDriverTransport
             ▼                           ▼
┌──────────────────────────────┐  ┌──────────────────────────────┐
│ SfaSlotQueue                 │  │ BlockingQwpWsTransport (real)│
│   wraps SfaFrameQueue + lock │  │ FakeOrderedServer (test)     │
│   ├─ SfaEngine (segments,    │  │                              │
│   │   published/completed    │  │                              │
│   │   atomic watermarks)     │  │                              │
│   ├─ SfaProducer (SPSC handle│  │                              │
│   │   into segments)         │  │                              │
│   └─ .ack-watermark sidecar  │  │                              │
└──────────────────────────────┘  └────────────┬─────────────────┘
                                                │
                                                ▼
                                  ┌──────────────────────────────┐
                                  │ qwp_ws_codec.rs (pure bytes):│
                                  │   SHA-1, HTTP/1.1 upgrade    │
                                  │   builder/validator,         │
                                  │   WS frame header + masking, │
                                  │   QWP pipelined-response     │
                                  │   decoder                    │
                                  └──────────────────────────────┘
```

The same `QwpWsSendCore<T>` is used by both the background runner and the
manual driver: the only difference is who calls `drive_step` / `drive_once`.

---

## 3. Key concepts

### 3.1 Frame Sequence Number (FSN)

The sender's durable identifier for a published batch. Assigned monotonically
by `SfaEngine` at submit time, returned via `QwpReceipt { fsn }`, and exposed
to users through `Sender::published_fsn()`, `Sender::acked_fsn()`, and
`Sender::await_acked_fsn(fsn, timeout)`. FSN is stable across reconnects and
across process restarts when an SFA slot directory is reused.

### 3.2 Wire sequence (`wire_seq`)

Per-connection sequence number used in the QWP pipelined wire protocol. Reset
to 0 after every reconnect. The driver maintains the FSN ↔ `wire_seq` mapping
in `SendCursor` (`qwp_ws_driver.rs`):

```rust
pub(crate) struct SendCursor {
    max_in_flight: usize,
    fsn_at_zero: Option<u64>,
    next_fsn: Option<u64>,
    next_wire_seq: u64,
    last_sent_wire_seq: Option<u64>,
    in_flight: VecDeque<SentFrame>,
}
```

On reconnect the driver replays from the oldest unresolved FSN as
`wire_seq=0`:

```rust
fn restart<Q: PublicationLog>(&mut self, log: &Q) {
    self.in_flight.clear();
    self.fsn_at_zero    = log.oldest_unresolved_fsn();
    self.next_fsn       = self.fsn_at_zero;
    self.next_wire_seq  = 0;
    self.last_sent_wire_seq = None;
}
```

### 3.3 PublicationLog (queue trait)

A queue of pending payload bytes with FSN bookkeeping and storage-maintenance
hooks. Two implementations exist:

- **`SfaFrameQueue`** — Java-`.sfa`-compatible segment-based queue
  (`qwp_ws_sfa_queue.rs`). Backing storage is a ring of mapped segments
  (`memmap2::MmapMut`): either real files in a slot directory or anonymous
  mappings for in-memory mode. Frames are appended length-prefixed with a
  CRC32C-checked commit marker; recovery scans the tail and discards torn
  appends. Watermarks (`published_upper`, `completed_upper`) live on
  `SfaEngine` as `AtomicU64`. A single-writer `SfaProducer` handle is taken
  once at startup and given to the producer side; everything else (sending,
  ACK accounting, recovery) happens under the publication mutex.

- **`SfaSlotQueue`** — wraps `SfaFrameQueue` with a per-sender directory
  `<sf_dir>/<sender_id>/` and a `.lock`/`.lock.pid` advisory lock
  (`flock` on Unix, `LockFileEx` on Windows). `SfaSlotQueue::open_memory(...)`
  opens the same underlying `SfaFrameQueue` against anonymous segment
  mappings (no slot directory, no lock). The production sender always uses
  `SfaSlotQueue` — the disk-vs-memory distinction is internal.

The production-side selector is the free function `open_configured_qwp_ws_queue`
in `qwp_ws.rs`. It currently rejects `sf_durability != memory` with a
`ConfigError`. When `sf_dir` is set it calls `SfaSlotQueue::open(...)`;
otherwise it calls `SfaSlotQueue::open_memory(...)`. The per-segment size is
`sf_max_bytes`; total bytes are bounded by `sf_max_total_bytes`; in-flight
frames are bounded by `max_in_flight`.

### 3.4 PublicationStore

`QwpWsPublicationStore<Q>` (in `qwp_ws_driver.rs`) owns:

- the queue `Q` (default `SfaFrameQueue`; the production sender uses
  `SfaSlotQueue`);
- `PublicationLifecycle` — `Open → Closing → Terminal`, `AtomicU8` with
  AcqRel transitions; `is_terminal()` is a load-Acquire;
- `terminal_error: Option<Error>` and `terminal_sender_error: Option<QwpWsSenderError>`
  (latched once set);
- `last_server_error: Option<QwpServerError>` (most recent raw server error);
- `rejected_frames: VecDeque<QwpRejectedFrame>` (bounded side-table of
  per-frame rejection details);
- a bounded `DriverEventRing` of internal events: `Published`, `Sent`,
  `CompletedThrough`, `Rejected`, `Reconnected`, `Progress`, `Terminal`;
- two bounded `SenderErrorRing`s — one drained by `poll_qwp_ws_error()`,
  one consumed internally by the optional error-handler callback — each with
  a dropped-counter for overflow accounting;
- an optional `DurableAckTracker` when `request_durable_ack=on`.

The store mutex is the main synchronization point between the user thread and
the runner thread for publication state: completion watermarks, lifecycle
checks, queued events, and sender-error rings. Producers take an `SfaProducer`
handle once at startup (`store.take_producer()`) and submit through it without
holding the publication mutex; transport, cursor, reconnect, backpressure, and
thread-stop state are synchronized separately by the runner.

### 3.5 SendCursor

Connection-local pipelining state: which FSN to send next, the next
`wire_seq` to issue, and the in-flight window. Bounded by `max_in_flight`.
Lives in `QwpWsSendCore`, not in the publication store, so blocking I/O
never holds the publication mutex.

### 3.6 Replay encoder

`QwpWsReplayEncoder` (in `qwp_ws_publisher.rs`) owns reusable scratch (a
`QwpWsEncodeScratch` and a `SymbolGlobalDict`) so steady-state encoding of a
`QwpWsColumnarBuffer` into a replay-shaped payload is allocation-free. It is
the last layer that knows outbound QWP batch semantics; below it, the stored
replay payload is opaque bytes, while the driver/transport still parse QWP
response frames.

`encode_with_max_size(buffer, max_buf_size)` enforces `max_buf_size`
**after** encoding (rolling the global symbol-dict back on overflow). It
cannot be enforced pre-encoding because the connection-global symbol-dict
prefix can grow between calls.

### 3.7 Transport

`ManualDriverTransport` is a small trait — `send_frame(view)`,
`try_poll_response`, `send_durable_ack_keepalive_if_due`,
`restart_connection(reason)`. Two implementations:

- **`BlockingQwpWsTransport`** — owns a `WsStream` (plain `TcpStream` or
  `rustls::StreamOwned`); reads and writes share the same socket. It also
  owns the multi-endpoint list, `QwpWsHostHealthTracker`, the parsed
  `QwpWsConfig`, the auth header, the negotiated QWP version, the inbound
  `WsFrameReader`, and a `pending_wire_sequences: VecDeque<u64>` tracking
  unresolved outbound frames. HTTP/1.1 upgrade is hand-rolled in
  `qwp_ws.rs::perform_upgrade` using the pure-bytes builder/validator from
  `qwp_ws_codec.rs`. Outbound frames are masked binary WS frames (random
  per-frame mask from `rand`). Inbound uses `read_message_with_close` /
  `WsFrameReader::try_read_one` which handle continuations, ping/pong inline,
  close codes with reason text, and enforce `MAX_INBOUND_FRAME_BYTES`
  (256 MiB).
- **`FakeOrderedServer`** — in-process `#[cfg(test)]` double that implements
  the same trait surface.

There is no async runtime and no external WebSocket crate.

---

## 4. Threading model

### 4.1 Background mode (`QwpWsProgress::Background`, default)

```
        user thread                       runner thread (one OS thread)
        ───────────                       ──────────────
flush*()                                  while !stop:
  encoder.encode(buffer)                    core.drive_step:
  runner.publish_replay_payload ──────►       lock store
    producer.try_submit          (SPSC)       next_outbound_frame
       OR fallback                            unlock store
       store.try_submit (under mutex)         transport.send_frame  ── I/O
    park on BackpressureNotifier if full      lock store
                                              record_sent_frame
                                              unlock store
                                              transport.try_poll_response ─ I/O
                                              lock store
                                              apply_response
                                              notify backpressure
                                              unlock store
```

Key rules:

- **Producer never holds the publication mutex during I/O.** The runner
  releases the mutex around every transport call.
- **Producer side owns the `SfaProducer`** (taken once via
  `store.take_producer()` at startup); the runner is the unique consumer/
  completer. Submission is SPSC against the SFA segment ring.
- **Transport, send cursor, and reconnect state live on the runner.** They
  are never visible to user threads.
- **Backpressure** is `BackpressureNotifier { Mutex<()>, Condvar, AtomicU64 generation }`
  in `qwp_ws.rs`. The runner bumps `generation` after every ACK / reject /
  terminal transition / storage maintenance step; producers park via
  `wait_for_change(generation, deadline)`. When the deadline expires, submit
  returns `DriverError::SubmitTimedOut { backpressure: Option<QueueError> }`,
  which `Sender::flush*` translates to a user-facing error.

`SyncQwpWsRunner` joins its background thread on `Drop`
(`qwp_ws.rs:1115`).

### 4.2 Manual mode (`QwpWsProgress::Manual`)

No background thread is spawned. The user calls `Sender::drive_once`,
`Sender::await_acked_fsn`, `Sender::flush*`, or `Sender::close_drain` to
advance the same `QwpWsSendCore` loop synchronously.
`submit_with_drive_deadline` interleaves submit attempts with `drive_once`
calls so a backpressured queue can drain without blocking indefinitely.

One `drive_once` call performs, in order:

1. send at most one queued frame;
2. drain all ready response frames from the transport (acks, durable acks,
   rejects), applying their effects on local store state;
3. perform at most one bounded storage-maintenance step (provision a missing
   hot spare or trim one fully-acked sealed segment);
4. send a durable-ACK keepalive PING only if nothing above produced progress
   and one is due.

Use cases for manual mode: embedding the sender in an existing event loop,
or running deterministic tests without a thread.

### 4.3 Memory ordering

Key atomics:

- `SfaEngine::published_upper`, `SfaEngine::completed_upper` — `AtomicU64`
  high watermarks (`qwp_ws_sfa_queue.rs`). The producer/runner publish via
  release stores; readers (e.g. `published_fsn`, `acked_fsn`) load with
  acquire ordering.
- `PublicationLifecycle` — `AtomicU8` shared via `Arc`, AcqRel transitions
  (`begin_close`, `terminalize`); `is_terminal()` is load-Acquire.
- `BackpressureNotifier::generation` — `AtomicU64`, paired with `Mutex<()>`
  and `Condvar` so a producer can sample the generation, recheck after the
  lock is held, and park atomically.

---

## 5. Lifecycle of one batch

```
Sender::flush(buffer)
  │
  ├─ flush_qwp_ws (qwp_ws.rs)
  │
  ├─ encoder.encode_with_max_size(buffer, max_buf_size)
  │     → &[u8] replay payload
  │
  ├─ runner.publish_replay_payload(payload)
  │     producer.try_submit(payload)
  │       on success: returns QwpReceipt { fsn }
  │       on backpressure: park on BackpressureNotifier, retry until deadline
  │     fallback path: store.try_submit (under mutex) when no producer
  │
  └─ runner thread drives in the background:
        drive_step:
          ├─ store.next_outbound_frame(&mut send_cursor)
          │     → Option<OutboundFrame> (borrowed payload via SfaMappedPayload)
          ├─ transport.send_frame(OutboundFrameView)
          │     → Result<TransportSendResult, TransportFailure>
          │     on success: store.record_sent_frame(&mut send_cursor,
          │                   SentFrame { fsn, wire_seq, payload_len })
          │
          ├─ transport.try_poll_response → TransportPoll
          │     Response(TransportResponse::Ack { wire_seq })
          │     Response(TransportResponse::DurableOk { wire_seq, table_seq_txns })
          │     Response(TransportResponse::DurableAck { table_seq_txns })
          │     Response(TransportResponse::Reject { wire_seq, error })
          │     Progress / Idle
          │
          ├─ store.apply_response
          │     Ack          → complete_through(fsn); bump completed_upper
          │     DurableOk    → release send-window pressure; enqueue frame
          │                     in DurableAckTracker if durable ACK is enabled
          │     DurableAck   → update durable watermarks; complete ready
          │                     tracked frames and bump completed_upper
          │     Reject + DropAndContinue → record reject, complete_through(fsn)
          │     Reject + Halt           → latch terminal_sender_error,
          │                                terminalize lifecycle
          │
          └─ notify BackpressureNotifier (producers / close_drain wake)
```

`Sender::close_drain` flips lifecycle to `Closing` (rejecting new submits),
waits up to `close_flush_timeout_millis` for `completed_fsn >=
published_fsn`, then calls `queue.close()` if all published frames resolved.
It does not itself join the background runner; the runner thread is joined
when `SyncQwpWsRunner` is dropped. The background runner exits when it observes
`PublicationState::Terminal` or its stop flag.

In durable-ACK mode (`request_durable_ack=on`), ordinary OK frames only
release send-window pressure; `acked_fsn()` and `await_acked_fsn` only
advance after `STATUS_DURABLE_ACK` coverage.

---

## 6. Errors and reconnect

### 6.1 Server error categorization

`server_error_category` / `server_error_policy` in `qwp_ws_driver.rs` map a
QWP status byte to:

| Status byte | Category | Policy |
| --- | --- | --- |
| `WS_STATUS_SCHEMA_MISMATCH` (0x03) | `SchemaMismatch` | `DropAndContinue` |
| `WS_STATUS_WRITE_ERROR` (0x09)    | `WriteError`    | `DropAndContinue` |
| `WS_STATUS_PARSE_ERROR` (0x05)    | `ParseError`    | `Halt` |
| `WS_STATUS_INTERNAL_ERROR` (0x06) | `InternalError` | `Halt` |
| `WS_STATUS_SECURITY_ERROR` (0x08) | `SecurityError` | `Halt` |
| other / WS protocol violation     | `Unknown` / `ProtocolViolation` | `Halt` |

`DropAndContinue` rejects the affected FSN, advances the cursor, and
continues. `Halt` latches `terminal_sender_error` on the store and stops the
runner; the sender must be closed and rebuilt.

WebSocket `Close` frames map to:

- `is_terminal_ws_close_code(code) == true` → `TransportFailure::ProtocolViolation`
  → store records a synthesized `QwpWsSenderError { category: ProtocolViolation,
  applied_policy: Halt, status: None, message: "...", ... }`.
- non-terminal close → `TransportFailure::Disconnect` → reconnect.

### 6.2 Reconnect

`reconnect_transport_with_policy` in `QwpWsSendCore` is the single entry
point. Bounded by `ReconnectPolicy { max_duration, initial_backoff,
max_backoff }`:

```
deadline = now + max_duration
backoff  = initial_backoff
loop:
    if attempts > 0: sleep(equal_jitter(backoff))   // role-reject uses initial_backoff
    transport.restart_connection(reason)
        Ok       → cursor.restart(log); resume sending
        Terminal → mark store terminal
        Other    → backoff = min(backoff*2, max_backoff); continue
    if deadline expired or stop signaled → break with retry-budget-exhausted error
```

`BlockingQwpWsTransport` carries the multi-endpoint list and a
`QwpWsHostHealthTracker` so reconnect walks endpoints in a round-robin
fashion, preferring healthy ones. After a successful reconnect, the
unresolved FSN window is replayed from `wire_seq=0`; the QWP server is
expected to dedupe by FSN.

`initial_connect_retry` is `QwpWsInitialConnectMode` (`Off | Sync | Async`,
default `Off`). `Async` lets the runner start before the first connection
succeeds; `Sync` retries inline; `Off` fails fast on the first attempt.

### 6.3 Error visibility

Users observe errors through:

- `Sender::flush*` — synchronous return paths surface immediate errors.
- `Sender::poll_qwp_ws_error()` — drains one structured `QwpWsSenderError`
  per call from the bounded sender-error ring. Remains usable after the
  sender has halted.
- `Sender::qwp_ws_errors_dropped()` — overflow counter for the ring.
- `Sender::qwp_ws_terminal_error()` (doc-hidden) — non-consuming view of the
  latched terminal `QwpWsSenderError`.
- Optional handler callback installed via `SenderBuilder::qwp_ws_error_handler`
  — invoked synchronously from producer-thread API calls. Default handler
  logs at WARN for `DropAndContinue` and ERROR for `Halt` via the `log`
  crate, target `questdb::ingress`. See `doc/QWP_WEBSOCKET_ERROR_HANDLING.md`
  for the full callback contract.

---

## 7. Expected interactions (user perspective)

### 7.1 Background mode (default)

```rust
let mut sender = Sender::from_conf("qwpws::addr=localhost:9000;sender_id=mysender;")?;
let mut buf = sender.new_buffer();
buf.table("temps")?.column_f64("v", 1.5)?.at(ts)?;

// flush_and_get_fsn clears the buffer; flush_and_keep_and_get_fsn does not.
let fsn = sender.flush_and_get_fsn(&mut buf)?;     // Result<Option<u64>>
if let Some(fsn) = fsn {
    sender.await_acked_fsn(fsn, Duration::from_secs(5))?;
}
if let Some(err) = sender.poll_qwp_ws_error()? {
    // structured server-side error for an earlier batch
}
```

What the user can rely on:

- `flush*` returns once the payload is **locally accepted** (queued and
  receipted). It does *not* mean the server has ACKed.
- `published_fsn()` advances at submit; `acked_fsn()` advances at server ACK
  (or at durable-ACK coverage in `request_durable_ack=on` mode).
- The runner thread continues advancing I/O between user calls.
- `Sender::close_drain` waits for outstanding frames up to the configured
  timeout and closes the queue when drained; sender drop joins the background
  runner.

### 7.2 Manual mode

```rust
let mut sender = Sender::from_conf(
    "qwpws::addr=localhost:9000;qwp_ws_progress=manual;"
)?;
loop {
    let fsn = sender.flush_and_keep_and_get_fsn(&buf)?;
    while sender.drive_once()? { /* keep going until idle */ }
    if let Some(fsn) = fsn
        && sender.acked_fsn()?.is_some_and(|acked| acked >= fsn)
    {
        break;
    }
}
```

Use this when integrating with an existing event loop, or in tests where you
need step-by-step determinism. `await_acked_fsn` will also drive progress
while waiting in manual mode.

### 7.3 What the user must not do

- Mix ILP and QWP buffers — every QWP path checks the buffer kind and
  rejects the wrong one.
- Request transactional flushes on QWP — explicitly rejected.
- Hold a `&mut Sender` across long-lived async work; QWP flush is
  synchronous by design.

---

## 8. Testing strategy

The split between outbound-payload-aware (`qwp_ws_publisher.rs`) and
replay-payload-opaque (`qwp_ws_driver.rs`) layers lets each layer be tested in
isolation:

- `FakeOrderedServer` (`qwp_ws_driver.rs`, `#[cfg(test)]`) tests the
  driver/cursor/queue interaction without any WebSocket I/O.
- `qwp_ws_codec.rs` is pure bytes and is unit-tested against RFC 6455
  examples and QWP fixtures.
- `qwp_ws_sfa_segment.rs` ships with Java-generated `.sfa.hex` fixtures
  under `src/tests/interop/qwp-ws-sfa/` for cross-language byte-level
  validation.
- `src/tests/qwp_ws_*.rs` contain end-to-end probes (publication,
  protocol, replay, Java golden payloads) that exercise the full stack;
  many are gated `#[ignore]` and run against a local QuestDB server.

---

## 9. Notable design choices

- **Replay-payload opacity below the publisher.** The store, queue, and send
  cursor never parse published replay payloads. The driver/transport still
  parse QWP/WebSocket response frames, which lets the same driver back the real
  WebSocket transport and the test double while keeping stored payload bytes
  reusable in isolation.
- **Single segment-based queue with two backings.** Memory-only and disk
  modes share the same Java-`.sfa` storage layout via `SfaFrameQueue` /
  `SfaEngine`. There is no separate volatile queue.
- **Production-side SPSC.** A single `SfaProducer` handle is taken at
  startup; the runner is the unique consumer. Steady state is
  allocation-free thanks to the segment ring and the reusable encoder
  scratch.
- **Strict mutex discipline.** The runner releases the publication mutex
  around every transport call; user threads never touch transport state.
- **FSN as the durable identifier.** Wire sequences are connection-local;
  reconnect replays from the oldest unresolved FSN as `wire_seq=0`, so the
  server side handles dedupe. The `.ack-watermark` sidecar makes the
  cumulative completion watermark durable across process restarts.
- **Bounded everything.** Frames, segments, in-flight window, events, and
  sender-error rings are all bounded with explicit overflow accounting.
- **Java parity is a design goal.** Sender lifecycle, SFA file format,
  error categorization, default behaviors, and the durable-ACK protocol
  mirror the Java client where possible. Known gaps and intentional
  deferrals are tracked in `doc/QWP_WEBSOCKET_OPEN_ISSUES.md`.
