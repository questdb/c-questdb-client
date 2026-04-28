# QWP/WebSocket pipelined Store-and-Forward handover

Date: 2026-04-28

Status: working design discussion for Rust client plus C/C++/Python FFI.
No production implementation has started from this design yet.

## Read first

- `doc/QWP_WEBSOCKET_PIPELINED_FFI.md` — main proposal.
- `doc/QWP_WEBSOCKET_VALIDATION_PLAN.md` — validation ladder and stop
  conditions.
- Java reference:
  `/home/jara/devel/oss/questdb-arrays/java-questdb-client/design/qwp-cursor-durability.md`
- Java implementation reference:
  `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/QwpWebSocketSender.java`
  and
  `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/CursorWebSocketSendLoop.java`

## Current design direction

Build a new Rust QWP/WebSocket pipelined Store-and-Forward core rather than
wrapping the current Tokio-based sender.

The core should be:

- Rust-first but FFI-friendly.
- `Sender` / `Buffer` separated, matching existing Rust/C/C++ client shape.
- Threadless by default. No silent background thread in the low-level API.
- Integratable with Tokio or a background thread through explicit adapters.
- Allocation-free on the steady-state hot path after warm-up and sizing, not
  necessarily allocation-free during setup or first use.
- Explicit about local publication, server ACK, timeout, poison, and close
  outcomes.

The core contract should be stable across Rust, C, C++, and Python. Adapters may
change ergonomics, but not delivery semantics.

## Settled decisions

### Progress ownership

A sender core has exactly one progress owner.

Avoid runtime mode flags such as "runner active". Prefer ownership conversion:

```rust
let sender = QwpWsSender::open(opts)?;
let threaded = QwpWsThreadedSender::start(sender)?;

let sender = QwpWsSender::open(opts)?;
let async_sender = QwpWsAsyncSender::from_sender(sender)?;
```

The original `QwpWsSender` is moved into the adapter and cannot also call
`drive_once()`.

For C FFI, model this as consuming ownership:

```c
line_sender_qwpws_threaded_start(&sender, &threaded, &err);
/* sender is NULL on success */
```

### Local acceptance vs server delivery

The Java client's `flush()` returns after publishing into its local engine, not
after server ACK.

For Rust, this distinction must be impossible to miss. Current working
preference:

```rust
let receipt = sender.submit(&mut buffer)?;
let outcome = sender.wait(receipt, timeout)?;
```

`submit()` means local queue/SF acceptance. `wait()` means server delivery
observation for a receipt.

Whether to expose `flush()` as compatibility sugar is still an API-sketch
question. If it exists, it must document whether it means local acceptance or
server ACK.

### Delivery contract

Store-and-Forward is at-least-once.

Replay after uncertain delivery can produce duplicate frames. This is acceptable
because QuestDB can deduplicate by `messageSequence`; current ILP retry behavior
is already in the same at-least-once family.

The Rust design should still document that deduplication is a server-side
mechanism, not a client-side exactly-once guarantee.

### Server ordering and ACKs

Server processing is assumed strictly in order.

The server may coalesce ACKs by sending the highest successful sequence. The
client can treat ACK `N` as cumulative ACK for all unresolved frames up to `N`.

This is important enough to validate early against a real QuestDB server.

### V1 replay encoding

Use the Java-way first: dense self-sufficient replay frames.

Every frame stored by the new pipelined sender must be valid as the first QWP
data frame on a fresh WebSocket connection.

For v1:

```text
confirmedMaxId = -1
useSchemaRef = false
```

If a frame references symbol id `N`, the frame carries the dense
connection-global dictionary prefix from id `0` through `N`.

This is intentionally not the final scalability target. It is correctness-first
to get end-to-end replay working. It limits scalability for long-running
high-cardinality symbol workloads because one frame using an old high-numbered
symbol id repeats every lower dictionary entry.

Future optimizations can add sparse referenced-entry dictionaries, state-only
QWP messages, and durable state checkpoints. Do not make v1 depend on those.

### WebSocket masking boundary

Store unmasked QWP payload bytes in volatile/SF queues.

WebSocket headers, mask keys, and masked payload bytes are transport artifacts.
They are generated fresh for every client-to-server send or replay and must not
be part of durable frame identity, segment CRC, receipt state, or replay
comparison.

Replaying the same FSN can use a different WebSocket mask key. That is correct
as long as the server observes the same unmasked QWP payload.

Server-to-client frames are expected to be unmasked. A masked server response is
a WebSocket protocol error, not a QWP delivery outcome.

### Real-server probes

Mocks are necessary but insufficient.

Use this split:

```text
Mocks validate client design.
Real-server probes validate protocol truth.
Full integration validates the product.
```

Real-server probes should happen early, especially for:

- self-sufficient replay frame acceptance,
- cumulative ACK/order/close behavior,
- server error taxonomy.

## Open questions

1. Primary Rust verb:
   `submit()` is semantically precise. `flush()` is familiar. The API sketch
   should decide whether `flush()` exists and, if so, whether it is only an alias
   for local acceptance.

2. Receipt-returning convenience:
   Decide whether the common call always returns a receipt, or whether there are
   separate methods such as `submit()` and `submit_with_receipt()`.

3. Blocking defaults:
   Local queue full can block while the manual sender drives progress. Defaults
   need explicit timeout behavior so the API does not hang forever by accident.

4. Error policy:
   Java treats non-success server ACK as terminal. Rust design should still aim
   to avoid infinite replay and silent data loss. Frame-level quarantine is the
   likely Rust target, but final Rust/FFI enums should wait until real-server
   error probes confirm what the server actually reports.

5. C ABI result shape:
   Do not collapse events, receipt status, wait outcome, and close outcome into
   one enum. C needs distinct status/outcome structs so timeout, pending,
   drained, poisoned, and API failure are observable without abusing `err_out`.

6. Durability boundary:
   A receipt must not be returned until the frame satisfies the selected queue
   mode. `volatile`, `page_cache`, `flush`, and `append` need exact publication
   boundaries before implementation.

## Recommended next step

Start with Step 1 from the validation plan: API sketch first.

Create:

```text
doc/QWP_WEBSOCKET_API_SKETCH.md
```

Write concrete end-user examples for:

- Rust manual/synchronous sender
- Rust threaded adapter
- Rust Tokio adapter
- C ABI
- C++ RAII wrapper
- Python blocking wrapper
- Python asyncio wrapper, if planned

The API sketch should answer:

- Is the primary verb `submit()` or `flush()`?
- Does the default call return after local acceptance only?
- Which call returns a receipt?
- Which operations block, poll, or drive progress?
- How do timeouts surface?
- How does adapter ownership conversion look?
- Can C express all non-error states without losing information?

End the sketch with the required reflections:

```text
Local reflection
- Does this API feel simpler than the current Sender + Buffer shape?
- What looks awkward in the examples?

Global reflection
- Does this preserve Buffer/Sender segregation, explicit progress ownership,
  runtime-neutral FFI, and observable delivery?
- Should the design proceed to a type-only progress ownership prototype?
```

Do not implement transport before this sketch feels right.

## Suggested validation sequence after the API sketch

1. Type-only progress ownership prototype.
2. Java-style dense self-sufficient replay encoder spike.
3. Real-server replay probe for a later frame sent alone on a fresh connection.
4. Volatile bounded queue plus receipts with fake cumulative ACKs.
5. Manual synchronous driver with fake server.
6. Real-server ACK/order/close probe.
7. Minimal Store-and-Forward disk queue.
8. Fake-server error policy validation.
9. Real-server error taxonomy probe.
10. FFI shape pass.
11. Full real WebSocket integration.

Stop and redesign if any real-server probe invalidates a core assumption.

## Things to avoid

- Do not let the low-level API silently start a thread.
- Do not expose Tokio concepts through C.
- Do not make `flush()` sometimes drive, sometimes passively wait, and sometimes
  fail because a runner owns progress.
- Do not store WebSocket framing or masked payload bytes in the durable queue.
- Do not freeze C enums before real-server error behavior is known.
- Do not optimize away dense replay before v1 end-to-end correctness is proven.
- Do not treat Java's current tests as real-server semantic proof; the Java
  notes say its `TestWebSocketServer` sees opaque bytes and does not parse QWP
  semantics.
