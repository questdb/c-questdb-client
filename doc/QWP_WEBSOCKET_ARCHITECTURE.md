# QWP/WebSocket Sender — High-Level Architecture

This document describes the architecture of the synchronous QWP/WebSocket
sender in `questdb-rs` (`feature = "sync-sender-qwp-ws"`). It covers the layered
module structure, the key concepts (FSN vs wire sequence, publication store,
manual vs background progress), the threading model, the lifecycle of a single
batch, error/reconnect handling, and the expected interaction between user code
and the sender.

The on-the-wire protocol itself (HTTP/1.1 upgrade, version negotiation, response
formats, status bytes) is specified by `QWP_SPECIFICATION` §2/§3/§13 and is not
re-described here.

---

## 1. Where it lives

All code is under `questdb-rs/src/ingress/sender/`:

| File | Role |
| --- | --- |
| `qwp_ws.rs` | Public glue: handler state, background runner, connection setup, queue selection, public flush/drive entry points, WebSocket frame I/O. |
| `qwp_ws_publisher.rs` | Payload-aware shell: `QwpWsPublicationDriver` + `QwpWsReplayEncoder`. Turns a `QwpBuffer` into a self-sufficient replay payload and submits it. |
| `qwp_ws_driver.rs` | Payload-opaque core: `QwpWsPublicationStore` (queue + lifecycle + events), `QwpWsSendCore` (transport + cursor + reconnect), `BlockingQwpWsTransport`, `SendCursor`, `PublicationLog` and `ManualDriverTransport` traits, `FakeOrderedServer` test double. |
| `qwp_ws_queue.rs` | Two queue implementations: `VolatileFrameQueue` (mutex-guarded) and `LockFreeVolatileFrameQueue` (SPSC, lock-free, used by the production sender). |
| `qwp_ws_codec.rs` | Pure-bytes WebSocket framing + HTTP/1.1 upgrade + QWP response decoding. No I/O. |
| `qwp_ws_ownership.rs` | Public types: `QwpWsProgress`, `QwpWsSenderError`, `QwpWsErrorCategory`, `QwpWsErrorPolicy`. |
| `qwp_ws_sfa_segment.rs` | Java `.sfa` on-disk format: 24-byte segment header, 8-byte frame header, CRC32C. Torn-tail recovery. |
| `qwp_ws_sfa_queue.rs` | `SfaFrameQueue`: adapts segment files to `PublicationLog`. Persists replay payloads only. |
| `qwp_ws_sfa_slot.rs` | Per-sender directory wrapper: `<sf_dir>/<sender_id>/{.lock,.lock.pid,sf-*.sfa}`, lockfile-based multi-process safety. |

Public configuration knobs live in `ingress/conf.rs` as `QwpWsConfig` /
`SfDurability`.

---

## 2. Layered architecture

Everything below `QwpWsPublicationDriver` is **payload-opaque**: it shuttles
bytes identified only by frame sequence number (FSN) and never parses QWP.

```
┌──────────────────────────────────────────────────────────────────┐
│ Sender (ingress/sender.rs) — ILP-or-QWP dispatch                 │
└──────────────────────────────────────────────────────────────────┘
                            │ flush(buffer)
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│ SyncQwpWsHandlerState  /  ManualQwpWsHandlerState  (qwp_ws.rs)   │
│   • encoder (payload-aware)                                      │
│   • runner (background) OR publisher (manual)                    │
└──────────────────────────────────────────────────────────────────┘
                            │ replay payload bytes
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│ QwpWsPublicationDriver + QwpWsReplayEncoder (qwp_ws_publisher.rs)│
│   • encodes QwpBuffer → self-sufficient QWP replay message       │
│   • last layer that knows about QWP semantics                    │
└──────────────────────────────────────────────────────────────────┘
                            │ submit(&[u8]) → QwpReceipt {fsn}
                            ▼
┌──────────────────────────┬───────────────────────────────────────┐
│ QwpWsPublicationStore<Q> │  QwpWsSendCore<T>   (qwp_ws_driver.rs)│
│   queue + lifecycle +    │    transport +                        │
│   events + errors        │    SendCursor (FSN ↔ wire_seq) +      │
│                          │    ReconnectPolicy                    │
└────────────┬─────────────┴─────────────┬─────────────────────────┘
             │ PublicationLog            │ ManualDriverTransport
             ▼                           ▼
┌──────────────────────────────┐  ┌──────────────────────────────┐
│ VolatileFrameQueue           │  │ BlockingQwpWsTransport (real)│
│ LockFreeVolatilePublication- │  │ FakeOrderedServer (test)     │
│   Log (SPSC, lock-free)      │  │                              │
│ SfaSlotQueue (disk, gated)   │  │                              │
└──────────────────────────────┘  └────────────┬─────────────────┘
                                                │
                                                ▼
                                  ┌──────────────────────────────┐
                                  │ qwp_ws_codec.rs (pure bytes):│
                                  │   SHA-1, HTTP/1.1 upgrade,   │
                                  │   WS frame header + masking, │
                                  │   QWP pipelined-response     │
                                  │   decoder                    │
                                  └──────────────────────────────┘
```

The same `QwpWsSendCore<T>` is used by both the background runner and the
manual driver: the only difference is who calls `drive_step`.

---

## 3. Key concepts

### 3.1 Frame Sequence Number (FSN)

The sender's durable identifier for a published batch. Assigned monotonically by
the queue at submit time, returned via `QwpReceipt { fsn }`, and exposed to
users through `published_fsn()`, `acked_fsn()`, and `await_acked_fsn()`. FSN is
stable across reconnects.

### 3.2 Wire sequence (`wire_seq`)

Per-connection sequence number used in the QWP pipelined wire protocol. Reset
to 0 after every reconnect. The driver maintains the FSN ↔ `wire_seq` mapping
in `SendCursor` (`fsn_at_zero`, `next_wire_seq`, `last_sent_wire_seq`,
`in_flight: VecDeque<SentFrame>`).

On reconnect the driver replays from the oldest unresolved FSN as `wire_seq=0`:
```
SendCursor::restart(log):
    in_flight.clear();
    fsn_at_zero = log.oldest_unresolved_fsn();
    next_fsn    = fsn_at_zero;
    next_wire_seq = 0;
```

### 3.3 PublicationLog (queue trait)

A bounded ring of pending payload bytes plus FSN bookkeeping. Implementations:

- **`LockFreeVolatileFrameQueue`** — production memory queue. SPSC over a
  byte ring (`LockFreeByteRing<UnsafeCell<u8>>`) and a slot table. The producer
  thread reserves bytes, copies in payload, then publishes the slot via a
  release-store of `state = LOCK_FREE_SLOT_PUBLISHED`. The runner thread reads
  through `PendingPayload::LockFreeQueue { offset, len }` — a borrow into the
  ring, so steady-state I/O does no copies off the queue.
- **`VolatileFrameQueue`** — simpler `Vec<FrameSlot>` ring with `Arc<[u8]>`
  payloads. Used by the manual driver tests and as a fallback.
- **`SfaSlotQueue`** — Java-`.sfa`-compatible disk persistence. Wired
  end-to-end but currently gated: `ConfiguredQwpWsQueue::open` rejects
  `sf_durability != memory` with a `ConfigError` ("not yet supported, deferred
  follow-up").

`ConfiguredQwpWsQueue` (in `qwp_ws.rs`) is the production selector and its slot
count is computed from `sf_max_total_bytes / sf_max_bytes`, floored by
`max_in_flight`.

### 3.4 PublicationStore

`QwpWsPublicationStore<Q>` (in `qwp_ws_driver.rs`) owns:

- the queue `Q`,
- a `PublicationLifecycle` state machine — `Open → Closing → Terminal`, atomic
  via `AtomicU8`, cloned cheaply into producer and runner,
- `terminal_error: Option<Error>` and `terminal_sender_error: Option<QwpWsSenderError>` (latched once set),
- a bounded `DriverEventRing` of internal events (`Published`, `Sent`,
  `CompletedThrough`, `Rejected`, `Reconnected`, `Terminal`),
- a bounded `SenderErrorRing` of structured server errors with overflow
  counter (`sender_errors_dropped_total`).

The store is the only synchronization point between the user thread and the
runner thread for non-payload state.

### 3.5 SendCursor

Connection-local pipelining state: which FSN to send next, the next `wire_seq`
to issue, and the in-flight window. Bounded by `max_in_flight`. Lives in
`QwpWsSendCore`, not in the publication store, so blocking I/O never holds the
publication mutex.

### 3.6 Replay encoder

`QwpWsReplayEncoder` (in `qwp_ws_publisher.rs`) owns reusable scratch (a
`QwpWsEncodeScratch` and a `SymbolGlobalDict`) so steady-state encoding of a
`QwpBuffer` into a replay-shaped payload is allocation-free. It is the last
layer that knows about QWP semantics; everything below it is opaque bytes.

### 3.7 Transport

`ManualDriverTransport` is a small trait — `send_frame(view)`,
`poll_response`/`try_poll_response`, `restart_connection(reason)`. Two
implementations:

- **`BlockingQwpWsTransport`** — owns a `WsStream` (plain `TcpStream` or
  `rustls::StreamOwned`); reads and writes share the same socket. HTTP/1.1
  upgrade is hand-rolled in `qwp_ws_codec.rs::perform_upgrade`. Outbound frames
  are masked binary WS frames (random per-frame mask from `rand`). Inbound uses
  `read_message_with_close` which handles continuations, ping/pong inline,
  close codes with reason text, and enforces `MAX_INBOUND_FRAME_BYTES` (256 MiB).
- **`FakeOrderedServer`** — in-process test double that implements the same
  trait surface.

There is no async runtime and no external WebSocket crate.

---

## 4. Threading model

### 4.1 Background mode (`QwpWsProgress::Background`, default)

```
        user thread                          runner thread (one OS thread)
        ───────────                          ──────────────
flush()                                      while !stop:
  encoder.encode(buffer)                       lock store
  producer.try_submit(&payload) ──────►        next_outbound_frame
       (lock-free SPSC; or                     unlock store
        store.try_submit if no producer)       transport.send_frame  ── I/O
                                               lock store
                                               finish_send_result
                                               unlock store
                                               try_poll_response     ── I/O
                                               lock store
                                               finish_response
                                               notify_all backpressure
                                               unlock store
```

Key rules:

- **Producer never holds the publication mutex during I/O.** The runner
  releases the mutex around every transport call.
- **Runner never publishes.** The producer side owns the lock-free producer
  handle (taken once via `take_lock_free_producer` at startup); the runner is
  the unique consumer/completer.
- **Transport, send cursor, and reconnect state live on the runner.** They
  are never visible to user threads.
- **Backpressure** is a `(Mutex<()>, Condvar, AtomicU64 generation)` triple in
  `BackpressureNotifier`. The runner bumps `generation` after every ACK,
  Reject, or terminal transition; producers park via
  `wait_for_change(generation, deadline)`. When the deadline expires, submit
  returns `DriverError::SubmitTimedOut`.

`SyncQwpWsRunner` joins the background thread on `Drop`, so shutdown order is
controlled (see `Drop for SyncQwpWsRunner` in `qwp_ws.rs:709`).

### 4.2 Manual mode (`QwpWsProgress::Manual`)

No thread is spawned. The user calls `Sender::drive_once` /
`Sender::await_acked_fsn` / `flush` to advance the same `QwpWsSendCore` loop
synchronously. `submit_with_drive_limit` interleaves submit attempts with
`drive_once` calls so a backpressured queue can drain without blocking
indefinitely.

Use cases for manual mode: embedding the sender in an existing event loop, or
running deterministic tests without a thread.

### 4.3 Memory ordering

Key atomics:

- `LockFreeFrameSlot::state` — release on publish, acquire on read; covers
  the slot's `fsn`, `offset`, `len` and the byte range in the ring.
- `LockFreeVolatileFrameQueueInner::published_upper`, `completed_upper` — high
  watermarks for cheap progress queries.
- `PublicationLifecycle` — `AtomicU8`, AcqRel transitions; `is_terminal()` is
  a load-Acquire.
- `BackpressureNotifier::generation` — `AtomicU64`, paired with a `Condvar`.

The SPSC safety statement is documented at `qwp_ws_queue.rs:325–329`: only the
producer thread writes slots, only the runner reads them, and the byte range
backing a published slot is not freed or reused until the runner advances
`completed_upper` past it.

---

## 5. Lifecycle of one batch

```
flush_qwp_ws(state, &QwpBuffer)
  │
  ├─ encoder.encode(buffer)          → &[u8] replay payload
  │
  ├─ runner.publish_replay_payload   → QwpReceipt { fsn }
  │     producer.try_submit / store.try_submit
  │     (parks on backpressure if queue is full)
  │
  └─ runner: drive_step (background OR caller-driven)
        ├─ next_outbound_frame   (SendCursor → OutboundFrameView, no copy)
        ├─ transport.send_frame  (binary WS frame, masked)
        │     SentFrame { fsn, wire_seq, payload_len }
        │
        ├─ try_poll_response
        │     OK { sequence }            → TransportResponse::Ack { wire_seq }
        │     DurableAck                 → ignored at this layer
        │     Error { sequence, status } → TransportResponse::Reject
        │
        ├─ apply_response
        │     Ack    → queue.complete_through(fsn) ; bump completed_upper
        │     Reject → policy = error category-derived
        │              Halt           → store.mark_terminal, latch sender_error
        │              DropAndContinue → queue.reject_fsn(fsn), push to ring
        │
        └─ notify_all backpressure   (producers and close-drain wake up)
```

`close_drain` flips lifecycle to `Closing`, waits until
`all_published_receipts_resolved()` (i.e. `completed_fsn >= published_fsn`),
then calls `queue.close()`. Background runner exits when it observes
`PublicationState::Terminal` or `stop`.

---

## 6. Errors and reconnect

### 6.1 Categorization

`server_error_category` / `server_error_policy` in `qwp_ws_driver.rs` map a
QWP status byte to:

| Category | Policy |
| --- | --- |
| `SchemaMismatch`, `ParseError`, `WriteError` | `DropAndContinue` |
| `InternalError`, `SecurityError`, `ProtocolViolation`, `Unknown` | `Halt` |

`DropAndContinue` rejects the affected FSN, advances the cursor, and continues.
`Halt` latches `terminal_sender_error` on the store and stops the runner; the
sender must be closed and rebuilt.

WebSocket `Close` frames map to:

- `is_terminal_ws_close_code(code)` → `TransportFailure::ProtocolViolation` →
  store records a synthesized `QwpWsSenderError { category: ProtocolViolation,
  applied_policy: Halt, status: None, message: "ws-close[code]: reason", ... }`.
- non-terminal close → `TransportFailure::Disconnect` → reconnect.

### 6.2 Reconnect

`reconnect_transport_with_policy` in `QwpWsSendCore` is the single entry point.
Bounded by `ReconnectPolicy { max_duration, initial_backoff, max_backoff }`:

```
deadline = now + max_duration
backoff  = initial_backoff
loop:
    if attempts > 0: sleep(min(backoff, deadline - now))
    transport.restart_connection(reason)
        Ok       → Reconnected { reason }; cursor.restart(log)
        Terminal → mark store terminal
        Other    → backoff = min(backoff*2, max_backoff); continue
    if deadline expired or stop signaled → break
```

After a successful reconnect, the unresolved FSN window is replayed from
`wire_seq=0`. The QWP server is expected to dedupe by FSN.

`initial_connect_retry` (default `false`, matching Java) controls whether the
*first* connection attempt also uses this policy or fails fast.

### 6.3 Error visibility

Users observe errors through:

- `Sender::check_qwp_ws_error` — surfaces a latched terminal error.
- `Sender::poll_sender_error` — drains the bounded `SenderErrorRing` with one
  structured `QwpWsSenderError` per call.
- `Sender::terminal_sender_error` — clone of the latched terminal error.
- `Sender::sender_errors_dropped_total` — overflow counter for the ring.

Flush calls themselves return `Result`, so the immediate error is reported
inline; the polling APIs are for asynchronous server-side errors that arrive
between flushes.

---

## 7. Expected interactions (user perspective)

### 7.1 Background mode (default)

```rust
let mut sender = Sender::from_conf("qwpws::addr=...;sender_id=mysender;")?;
let mut buf = sender.new_buffer();
buf.table("temps")?.column_f64("v", 1.5)?.at(ts)?;

let fsn = sender.flush_and_keep(&mut buf)?;     // returns Some(fsn)
sender.await_acked_fsn(fsn, deadline)?;         // blocks until ACKed
if let Some(err) = sender.poll_sender_error()? {
    // structured server-side error for an earlier batch
}
```

What the user can rely on:

- `flush*` returns once the payload is **locally accepted** (queued and
  receipted). It does *not* mean the server has ACKed.
- `published_fsn()` advances at submit; `acked_fsn()` advances at server ACK.
- The runner thread continues advancing I/O between user calls.
- `Sender::close` (or drop) joins the runner; outstanding frames are best-effort.

### 7.2 Manual mode

```rust
let mut sender = Sender::from_conf("qwpws::addr=...;progress=manual;")?;
loop {
    let fsn = sender.flush_and_keep(&mut buf)?;
    while !sender.drive_once()? { /* nothing more to do this tick */ }
    if sender.acked_fsn() >= Some(fsn) { break; }
}
```

Use this when integrating with an existing event loop, or in tests where you
need step-by-step determinism.

### 7.3 What the user must not do

- Mix ILP and QWP buffers — every QWP path checks the buffer kind and rejects
  the wrong one.
- Request transactional flushes on QWP — explicitly rejected.
- Hold a `&mut Sender` across long-lived async work; QWP flush is synchronous
  by design.

---

## 8. Testing strategy

The split between payload-aware (`qwp_ws_publisher.rs`) and payload-opaque
(`qwp_ws_driver.rs`) lets each layer be tested in isolation:

- `FakeOrderedServer` tests the driver/cursor/queue interaction without any
  WebSocket I/O.
- `qwp_ws_codec.rs` is pure bytes and is unit-tested against RFC 6455
  examples and QWP fixtures.
- `qwp_ws_sfa_segment.rs` ships with Java-generated `.sfa` fixtures
  (`src/tests/interop/qwp-ws-sfa/`) and a paired ignored test that runs against
  the Java implementation for cross-language validation.
- `src/tests/qwp_ws_*.rs` contain end-to-end probes (publication, protocol,
  replay, Java golden) that exercise the full stack.

---

## 9. Notable design choices

- **Payload opacity below the publisher.** The driver, store, queue, and
  transport never parse QWP. This keeps the SFA codec usable in isolation and
  lets the same driver back the real WebSocket transport and the test double.
- **Strict SPSC publication path.** The user thread never touches transport
  state; the runner never holds the publication mutex during I/O. Steady state
  is allocation-free thanks to the lock-free byte ring and the reusable
  encoder scratch.
- **FSN as the durable identifier.** Wire sequences are connection-local;
  reconnect replays from the oldest unresolved FSN as `wire_seq=0`, so the
  server side handles dedupe.
- **Bounded everything.** Frames, bytes, in-flight, events, sender-errors are
  all bounded with explicit overflow accounting (`*_dropped_total`).
- **Java parity is a design goal.** Sender lifecycle, SFA file format, error
  categorization, and default behaviors mirror the Java client where possible.
