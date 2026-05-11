# QWP/WebSocket error handling — findings and recommendations

## Summary

The Rust QWP/WS sender can silently lose server-side error notifications.
For categories that the protocol classifies as `DropAndContinue` (schema
mismatch, write error) the affected batch is dropped, `flush()` returns
`Ok(())`, and the only way the user learns about it is by calling
`Sender::poll_qwp_ws_error()`. Nothing in the API forces or hints at
polling; no log line is emitted; no default handler runs. A user who
follows the obvious `flush()` pattern will lose data and not know.

The Java client (`/home/jara/devel/oss/questdb-arrays/java-questdb-client`)
solves an adjacent but broader problem with an async dispatcher thread
that fans an entire **observability event stream** out to a
`SenderErrorHandler`: schema rejections, write rejections, reconnect
attempts, transient auth failures during failover, disconnects,
backpressure warnings, terminal halts. Most of those entries are
informational — operational signal that the client is surviving normal
events like primary-replica failover, rolling upgrades, box resize,
DNS failover. Only the halt case is genuinely "your sender is dead."

This doc proposes adopting Java's *properties* — no silent loss, full
observability, callback ergonomics — without paying for Java's dispatcher
thread:

1. **Two channels.** Control flow (`flush()`'s `Result`), and events
   (a user-installed callback invoked **on the producer thread inside
   `flush()`** — never on a background dispatcher).
2. **`flush()` fails only when the sender can't usefully continue.**
   Halt rejections and local transport failures. Operational events and
   data rejections fire the callback but never cause a flush to fail.
3. **Default callback logs at the language's standard log target.**
   Silence is not the default; users who do nothing still see events in
   their app logs.
4. **`poll_event()` stays as an optional pull alternative** for users
   who prefer pull over push.

Firing the callback on the producer thread dodges every cross-thread
hazard that made an async dispatcher complex: no `PyGILState_Ensure`,
no `catch_unwind` across thread boundaries, no fork/finalization
guards, no `void* user_data` lifetime puzzles beyond the sender's own
lifetime. The callback's only constraint is "don't call sender methods
from inside it" — a one-line documented invariant.

## Current Rust behavior

### Error classification

`questdb-rs/src/ingress/sender/qwp_ws_ownership.rs:46-96` defines:

- `QwpWsSenderError` (struct, line 46) — carries category, applied
  policy, optional status byte, optional message, optional message
  sequence, and inclusive `from_fsn..=to_fsn` span.
- `QwpWsErrorCategory` (enum, line 69): `SchemaMismatch` (0x03),
  `ParseError` (0x05), `InternalError` (0x06), `SecurityError` (0x08),
  `WriteError` (0x09), `ProtocolViolation`, `Unknown`.
- `QwpWsErrorPolicy` (enum, line 91): `DropAndContinue` for 0x03 and
  0x09; `Halt` for everything else.

### Current user-facing API

| API | Defined at | Behavior |
|---|---|---|
| `Sender::flush(&mut Buffer) -> Result<()>` | `sender.rs:494` | `Ok(())` once the frame is locally queued. Returns `Err(SocketError(...))` only for transport failure or if the sender is already terminal. |
| `Sender::poll_qwp_ws_error() -> Result<Option<QwpWsSenderError>>` | `sender.rs:600` | Dequeues one error from the `SenderErrorRing` (`qwp_ws_driver.rs:2368`). |
| `Sender::qwp_ws_terminal_error() -> Result<Option<QwpWsSenderError>>` | `sender.rs:618` | Idempotent view of the halt error if terminal. |
| `Sender::qwp_ws_errors_dropped() -> Result<u64>` | `sender.rs:632` | Count of errors lost to ring overflow. |

The ring's capacity is `DEFAULT_EVENT_CAPACITY = 1024`
(`qwp_ws_driver.rs:65`), shared with the driver's event ring.

### What happens on schema mismatch when the user does nothing

1. I/O thread classifies status 0x03 as `DropAndContinue`.
2. The affected batch is dropped from the SF replay queue.
3. The error is pushed into the bounded ring buffer.
4. **Nothing else.** A grep across `questdb-rs/src/ingress/sender/`
   confirms zero `log::`/`tracing::`/`warn!`/`error!`/`eprintln!` calls —
   no default sink.
5. `flush()` returns `Ok(())`. Subsequent `flush()` calls keep returning
   `Ok(())`.
6. If the user never polls, errors sit until the ring fills, then later
   errors are dropped (counted in `qwp_ws_errors_dropped()` — also never
   surfaced anywhere).

The most natural user code silently loses data:

```rust
loop {
    buffer.table("x")?.column_i64("v", 1)?.at_now()?;
    sender.flush(&mut buffer)?;  // Ok(()) — but rows may be silently dropped
}
```

## Java comparison

Reference: `/home/jara/devel/oss/questdb-arrays/java-questdb-client`.

### The Java callback is an event stream, not an error channel

`SenderErrorHandler` receives:

- Operational signal: reconnect started/succeeded/abandoned, transient
  auth failure during WS upgrade after failover, disconnect, backpressure
  warning.
- Data-rejection signal: drop-and-continue batches (schema mismatch,
  write error).
- Terminal signal: halt.

Most traffic on the channel is informational. The client is engineered
to survive primary-replica failover, rolling upgrades, occasional
downtime, and DNS failover; the operational signal is what tells ops
that those survivable events happened. Forcing this stream through
`flush()`'s `Err` would turn every customer's ingest pipeline into a
flake during normal operations.

### Delivery shape

| Aspect | Java | Rust today |
|---|---|---|
| Halt | Callback fires AND next API call throws `LineSenderServerException` | Next `flush()` returns `Err(SocketError("…terminal"))` |
| Drop (schema/write rejection) | **Push** via `SenderErrorHandler` callback on dispatcher thread | **Pull only** via `poll_qwp_ws_error()` |
| Reconnect / transient auth / disconnect / backpressure | Push via same callback | No notification at all |
| Default when user installs nothing | `DefaultSenderErrorHandler` logs via SLF4J — WARN for drop, ERROR for halt, INFO for operational | Nothing |
| Backpressure on the queue | 256-cap inbox (`SenderErrorDispatcher.DEFAULT_CAPACITY`); overflow counted in `getDroppedErrorNotifications()` | 1024-cap ring (`DEFAULT_EVENT_CAPACITY`); overflow counted in `qwp_ws_errors_dropped()` |
| Visible to a do-nothing user | Yes (log line per event) | No |

### The loud-by-default invariant in Java

`SenderErrorDispatcher`
(`core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/SenderErrorDispatcher.java`)
requires a non-null handler and falls back to
`DefaultSenderErrorHandler.INSTANCE` when none is supplied. The default
(`.../DefaultSenderErrorHandler.java:43-72`) emits a structured SLF4J
line per event. The comment is explicit:

> Logs every server rejection so silence is never the default —
> connect-string-only users still see errors in their logs.

## Why a producer-thread callback, not Java's dispatcher

A faithful port of Java's *delivery model* would add:

- A dispatcher thread in `questdb-rs` — **on top of** the per-sender
  background runner that QWP/WS already spawns for I/O in default
  mode. Two threads per sender for what most users will treat as a
  logging channel.
- For users who deliberately chose manual-progress mode (no background
  I/O thread), a dispatcher would silently re-introduce the background
  thread they opted out of.
- `PyGILState_Ensure` / `PyGILState_Release` around every Python
  invocation, with `catch_unwind` to suppress panics across the C ABI.
- Finalization guards (`Py_IsFinalizing`), module-unload survival, PEP
  703 (free-threaded Python 3.13+) considerations.
- A handler-outlives-dispatcher lifetime contract requiring careful
  join semantics on sender close.
- A second bounded queue (dispatcher inbox) on top of the ring already
  in the driver, with its own overflow counter.
- Subtle ordering hazards between `poll_event()` and the dispatcher
  draining concurrently; lifetime hazards on mid-callback close;
  panic-across-thread-boundary semantics per language.

All of that exists in Java because the dispatcher fires on a thread
that isn't the producer's, and because Java's threading economics make
it cheap. Move delivery to the producer thread and the entire pile
evaporates: the producer thread is already alive, the GIL is already
held, the user's callback is just another function call.

The callback retains Java's ergonomic property (register once, get
events automatically; no polling loop required) while sharing the
producer-thread lifecycle with the rest of the user's code. The only
substantive concession is latency: an event observed by the I/O
thread between `flush(N)` and `flush(N+1)` is reported to the user at
the start of `flush(N+1)`. Java's dispatcher fires it sooner; for
typical flush cadences (milliseconds) the difference is operationally
invisible. The stated goal of this design is **no silent loss +
callback ergonomics**, not sub-flush latency for observability events.

## Recommendation: producer-thread callback + control-flow split

### Mental model

| Channel | Purpose | Mechanism | Failure mode if user does nothing |
|---|---|---|---|
| **Control flow** | "Can I keep using this sender?" | `flush()` `Result` | Halt errors and local failures propagate up the call stack |
| **Events** | "What did the sender do in the background?" | User callback invoked on producer thread inside `flush()` and `close()` | Default callback logs to the language's standard log target |

`poll_event()` exists as a secondary pull API for users who prefer
not to install a callback. The default callback and the pull API
share the same underlying event ring; events are delivered to
whichever is being consumed.

The first channel preserves the existing `flush()` semantics for halt
and transport failures. The second channel restores Java's
loud-by-default property and matches its ergonomic shape (register a
handler, get events automatically) without inheriting its dispatcher
thread.

### Event taxonomy

```rust
pub struct QwpWsEvent {
    pub severity: Severity,
    pub kind: QwpWsEventKind,
    pub timestamp: SystemTime,
}

pub enum Severity { Info, Warn, Error }

pub enum QwpWsEventKind {
    // -- Operational (Info / Warn) — sender keeps going --
    ReconnectStarted    { reason: ReconnectReason, attempt: u32 },
    ReconnectSucceeded  { attempt: u32, elapsed_ms: u64 },
    ReconnectGivingUp   { attempt: u32, last_error: String },
    TransientAuthFailed { detail: String },
    Disconnected        { reason: String },
    BackpressureWarn    { sfa_bytes: u64, cap: u64 },

    // -- Data rejection (Warn) — server dropped a batch; sender keeps going --
    BatchRejected(QwpWsSenderError),

    // -- Terminal (Error) — sender is dead; also surfaces via flush().Err --
    Halted(QwpWsSenderError),
}
```

`QwpWsSenderError` keeps its existing shape (category, policy, FSN
span, message, status byte). It's the payload for the two event kinds
that carry server diagnostics.

### Channel 1 — control flow (`flush()`)

`flush()` returns `Err` for, and *only* for:

- Local encode failure, transport timeout, terminal-sender check,
  backpressure timeout (today's existing reasons).
- **Halt** — when the sender transitions to terminal because the server
  returned a halt-policy status. Carries the structured rejection via
  `Error::qwp_ws_rejection()` so callers identify the offending FSN
  and category without polling.

`flush()` returns `Ok(())` through everything else: reconnect events,
transient auth, disconnects, drop-and-continue rejections, backpressure
warnings.

Net: **`flush()` fails only when the sender can't usefully continue.**
Async rejections do not turn `flush(N+5)` into a failure because of a
rejection on frame N+1 — that mismatch was the central reason the
"fold all errors into `flush()`" sketch was wrong.

### Channel 2 — events (producer-thread callback)

A user-installed callback fires once per queued event at three drain
points:

1. At the start of every `flush()` call, after pre-checks pass and
   before the publish phase. The callback runs synchronously on the
   producer thread; the publish phase does not start until the
   callback returns from all queued events.
2. At the start of every `poll_event()` call (drain-one-and-return for
   pull-style consumers).
3. During `close()`, draining any remaining queued events before the
   sender's I/O resources are released.

Severity is carried on the event; the callback decides what to do with
it. The default callback logs:

| Event kind | Severity | Default log level |
|---|---|---|
| `ReconnectStarted`, `ReconnectSucceeded`, `Disconnected` | Info | `info!` / `logger.info` |
| `ReconnectGivingUp`, `TransientAuthFailed`, `BackpressureWarn`, `BatchRejected` | Warn | `warn!` / `logger.warning` |
| `Halted` | Error | `error!` / `logger.error` |

Per-layer default destination (used by the default callback only;
user-installed callbacks do whatever they like):

| Layer | Default destination |
|---|---|
| Rust | `log` crate, target `"questdb::ingress"`. Users wire `env_logger`/`tracing-subscriber` per their app. |
| C FFI | `stderr`, one-line structured format. |
| C++ | inherits C — stderr by default. |
| Python | `logging.getLogger("questdb.ingress")`. Users configure via standard `logging.basicConfig` / `dictConfig`. |

#### Reentrancy and exception contract

- The callback **must not** call any method on the sender it was
  registered with (including `flush`, `poll_event`, `close`). Doing so
  is documented UB; in practice it produces a borrow-checker panic in
  Rust, recursive locking elsewhere, and is not worth defending
  against.
- A panic / exception from the callback propagates up through
  `flush()` / `close()` like any other user-code exception during
  those calls. Rust: panic unwinds the caller's stack. Python: the
  exception leaves `flush()` raised. C: the callback signature is
  declared `noexcept` in C++; C users with non-trivial cleanup should
  not throw across the FFI boundary.
- The callback is invoked with `&QwpWsEvent` — borrows the event for
  the duration of the call. User code that needs to retain the event
  must clone fields (string copies, etc.).

#### Pull alternative

`Sender::poll_event() -> Result<Option<QwpWsEvent>>` returns the next
queued event without invoking the callback. Users who prefer pull
either skip registering a callback (the default callback is then a
no-op or absent) or register one that defers to their own queue. Pull
and push are not mutually exclusive — they drain the same ring.

`Sender::events_dropped() -> Result<u64>` reports ring overflow.

### Async semantics — fully embraced

Events describe what already happened. They are not tied to the
current `flush()`:

- A `BatchRejected` event for frame 87 is observed by the I/O thread
  asynchronously and queued. The callback fires for it at the start of
  the next `flush()` (say, the one publishing frame 101). The event
  carries `from_fsn=87..=to_fsn=87`; the caller correlates by FSN, not
  by call site.
- Reconnect events fire on the I/O thread between flushes and queue
  the same way; the callback gets them on the next flush.
- The only event that is *also* synchronous with `flush()`'s return
  value is `Halted`: the callback fires AND `flush()` returns
  `Err(crate::Error)` with halt payload, because the sender is dead
  and the user's control flow must learn about it.

## Per-layer implementation

### Rust core (`questdb-rs`)

1. **New types** in `ingress/sender/qwp_ws_ownership.rs`: `QwpWsEvent`,
   `QwpWsEventKind`, `Severity`. Keep `QwpWsSenderError` unchanged.
2. **Callback signature**:

   ```rust
   pub type QwpWsEventHandler = Arc<dyn Fn(&QwpWsEvent) + Send + Sync>;

   impl SenderBuilder {
       pub fn qwp_ws_event_handler<F>(self, handler: F) -> Self
       where F: Fn(&QwpWsEvent) + Send + Sync + 'static;
   }
   ```

   `Arc` rather than `Box` so the sender can hand the handler to
   internal components without exclusive ownership. `Send + Sync`
   because the same handler value may be invoked from `flush()`
   (producer thread) and from `close()` (potentially a different
   thread, e.g. `Drop`).
3. **Driver emission**: at every existing rejection / reconnect /
   disconnect / backpressure site in `qwp_ws_driver.rs` and
   `qwp_ws.rs`, construct a `QwpWsEvent` and push to the existing
   ring (broadened to `SenderEventRing`). The I/O thread does **not**
   invoke the callback directly — it only enqueues.
4. **Drain points** invoke the handler synchronously, in order:
   - At the start of `flush()` after pre-checks
     (`sender.rs:248-252`).
   - At the start of `poll_event()`.
   - During `close()` / `Drop`.
   Each drain pops events from the ring and invokes the handler with
   `&QwpWsEvent`.
5. **Default handler**: if none is installed via the builder, a
   built-in handler emits `log::info!`/`warn!`/`error!` at target
   `"questdb::ingress"` with a `Display`-formatted summary.
6. **`Error::qwp_ws_rejection()`** accessor — populated only for
   `flush()` `Err` values from halt transitions:

   ```rust
   pub struct Error {
       code: ErrorCode,
       msg: String,
       rejection: Option<Box<QwpWsSenderError>>,  // halt only
   }
   impl Error {
       pub fn qwp_ws_rejection(&self) -> Option<&QwpWsSenderError> { ... }
   }
   ```

   The pre-publish check (`qwp_ws_check_error_*` at `qwp_ws.rs:841`)
   attaches the halt payload from `qwp_ws_terminal_error()`. Drop
   rejections never reach `crate::Error`.
7. **`ErrorCode::ServerRejection`** new variant. Requires
   `#[non_exhaustive]` on the enum if not already.
8. **API surface**:
   - `SenderBuilder::qwp_ws_event_handler(F)` — install callback.
   - `Sender::poll_event() -> Result<Option<QwpWsEvent>>` — pull
     alternative; also drains-and-invokes the handler for any other
     queued events first.
   - `Sender::events_dropped() -> Result<u64>` — overflow counter.
   - `Sender::qwp_ws_terminal_error()` stays — post-close inspection.
   - Old `poll_qwp_ws_error()` / `qwp_ws_errors_dropped()` kept as
     `#[deprecated]` aliases for one release.

The "fast path atomic" from earlier sketches is not needed: drain at
`flush()` is a `Vec::is_empty`-cheap check against the ring's head.

### C FFI (`questdb-rs-ffi`)

1. **Event view struct** `line_sender_event_view` — POD with severity,
   kind discriminant, FSN span, optional message pointer + length. No
   opaque heap type needed; the view is constructed on the stack by
   the trampoline and passed by const-pointer to the callback. It is
   valid only for the duration of the callback call; consumers that
   need to retain it must copy fields out.
2. **Callback ABI**:

   ```c
   typedef void (*line_sender_event_cb)(
       void* user_data,
       const line_sender_event_view* event);

   bool line_sender_opts_event_handler(
       line_sender_opts* opts,
       line_sender_event_cb cb,
       void* user_data,
       line_sender_error** err_out);
   ```

   `user_data` lifetime: from `opts_event_handler` until the sender is
   closed (or until the next call replaces the handler). Because the
   callback fires only inside `line_sender_flush` /
   `line_sender_poll_event` / `line_sender_close`, all of which run on
   the user's thread, lifetime is trivially "do not free `user_data`
   while a flush is in progress" — the same contract as for the buffer.
3. **`line_sender_poll_event`** — pull-style API analogous to
   `line_sender_poll_qwp_ws_error`. Returns a heap-allocated
   `line_sender_event*`; caller frees with `line_sender_event_free`.
   Internally also invokes the registered callback for any *other*
   queued events first.
4. **Default callback**: if the user does not install one,
   `line_sender_opts_new` installs an internal callback that writes a
   one-line structured summary to `stderr`. Severity → prefix mapping
   (e.g. `[questdb INFO]`, `[questdb WARN]`, `[questdb ERROR]`). Users
   replace by registering their own callback; passing `NULL` reinstalls
   the default.
5. **`line_sender_error_server_rejection`** new error code +
   `line_sender_error_get_server_rejection_view` accessor for `flush()`
   errors that carry halt payload. The view borrows from the
   `line_sender_error` and is valid until the error is freed.
   `line_sender_error_get_code(err) == line_sender_error_server_rejection`
   is the canonical check.
6. **`set_err_out_from_error_with_qwpws`**
   (`questdb-rs-ffi/src/lib.rs:513-524`) reads from
   `err.qwp_ws_rejection()` first, falls back to
   `sender.qwp_ws_terminal_error()` if absent — covers halt errors
   surfacing through `flush()`'s `Err`.

#### Reentrancy

The C callback receives an opaque `line_sender*`-less context — by
design, there's no handle to call back into. Users who need
correlation pass their own state via `user_data`. Recursive calls into
the sender from the callback are documented as UB.

### C++ wrapper (`line_sender.hpp` / `line_sender_core.hpp`)

The wrapper throws `line_sender_error` by value (`line_sender_core.hpp:227, 263`).
A subclass would slice. Put the halt payload on the existing exception:

```cpp
class line_sender_error : public std::exception {
public:
    std::optional<qwpws_rejection> server_rejection() const;
};
```

`qwpws_rejection` is a value type holding the category/policy/FSN-span/
message-sequence/message string, copied at construction.

#### Callback API

```cpp
class opts {
public:
    opts& event_handler(std::function<void(const qwpws_event&)> handler);
};
```

Implementation: heap-allocate the `std::function`, pass its pointer as
`user_data` to the C API, register a `noexcept` static trampoline that
casts back and invokes it. The wrapper owns the `std::function`'s
lifetime, freed in the sender's destructor *after* `line_sender_close`
returns (no dispatcher to join — `close()` invokes the handler for any
final queued events synchronously and then returns).

```cpp
auto sender = opts(...)
    .event_handler([](const qwpws_event& e) {
        if (e.kind() == qwpws_event_kind::batch_rejected) {
            // dead-letter logic
        }
    })
    .build();

try {
    sender.flush(buffer);
} catch (const line_sender_error& e) {
    if (auto r = e.server_rejection()) {
        // halt — sender is dead, control flow reacts
    }
}
```

`qwpws_event` is a value type holding severity, kind tag, and a
discriminated union (or `std::variant`) of kind-specific payloads.
Lifetime is the duration of the callback call; user code copies fields
to retain.

#### Pull alternative

```cpp
while (auto event = sender.poll_event()) {
    // event is std::optional<qwpws_event>
}
```

### Python (`py-questdb-client`)

Two constraints on the binding:

1. `c_err_to_py` always constructs `IngressError`
   (`src/questdb/ingress.pyx:251`).
2. `IngressErrorCode.BadDataFrame = invalid_decimal + 1`
   (`src/questdb/ingress.pyx:151`) hard-codes a value adjacent to the C
   enum.

Concrete migration:

- Add `ServerRejection = line_sender_error_server_rejection` to
  `IngressErrorCode` **before** `BadDataFrame`. Update `BadDataFrame`
  to `+2` or, better, rewrite as an explicit integer constant.
- Extend `c_err_to_py` to construct `IngressServerRejectionError`
  (subclass of `IngressError`) when the code is `ServerRejection`,
  populated from `line_sender_error_get_server_rejection_view`:

  ```python
  class IngressServerRejectionError(IngressError):
      category: QwpwsErrorCategory
      policy: QwpwsErrorPolicy
      from_fsn: int
      to_fsn: int
      message_sequence: int | None
      server_message: str | None
  ```

#### Callback API

```python
sender = Sender.from_conf(
    "qwpws::addr=…",
    event_handler=lambda e: log.warning(e) if e.severity >= Severity.WARN else None,
)
```

Cython trampoline:

```cython
cdef void _qwpws_event_trampoline(
        void* user_data,
        const line_sender_event_view* view) noexcept:
    cdef object handler = <object>user_data
    try:
        e = _build_py_event(view)  # copies strings out of view
        handler(e)
    except BaseException:
        # Producer-thread call — exception propagates out of flush().
        # Cython's `noexcept` ensures the C ABI sees a clean return.
        import sys, traceback
        traceback.print_exc(file=sys.stderr)
```

Key simplifications vs. the dispatcher-thread design that earlier
drafts rejected:

- **No `with gil` directive** — `flush()` already holds the GIL on the
  producer thread; the callback runs under it.
- **No `PyGILState_Ensure` / `PyGILState_Release`** — not crossing
  thread boundaries.
- **No `Py_IsFinalizing` guard** — callback fires from user code, never
  during interpreter shutdown.
- **No fork survival** — no background thread to lose across `fork()`.
- **No asyncio bridging in the binding** — users who want async wrap
  `sender.flush()` in `loop.run_in_executor(...)`; the callback fires
  on the executor's thread (still producer-thread for that call), GIL
  acquired by Cython per-call as usual.

The bound callable is stored as an attribute on the `Sender` Cython
class so GC cannot collect it before `close()`. `__dealloc__` releases
the reference after the underlying C sender is freed (which has
already invoked the callback for any final queued events).

#### Default callback

In `Sender.__init__`, if no `event_handler` is supplied, install a
trampoline that calls
`logging.getLogger("questdb.ingress").log(level, ...)` with level
derived from `event.severity`. Users configure routing via
`logging.basicConfig` / `dictConfig` like any other logger.

#### Pull alternative

```python
while (event := sender.poll_event()) is not None:
    ...
```

## Stack at a glance

| Layer | Control flow | Callback registration | Default callback | Pull alternative |
|---|---|---|---|---|
| Rust | `flush()` `Err` carries halt via `qwp_ws_rejection()` | `SenderBuilder::qwp_ws_event_handler(F)` | `log` crate at `"questdb::ingress"` | `Sender::poll_event()` |
| C | `line_sender_flush` populates `line_sender_error*` with halt payload | `line_sender_opts_event_handler(cb, user_data)` | stderr (one-line format) | `line_sender_poll_event` |
| C++ | `flush()` throws `line_sender_error`; halt via `e.server_rejection()` | `opts.event_handler(std::function<...>)` | inherits C stderr | `sender.poll_event()` |
| Python | `flush()` raises `IngressServerRejectionError` for halt | `Sender(event_handler=callable)` | `logging.getLogger("questdb.ingress")` | `sender.poll_event()` |

## Migration

- `Sender::poll_qwp_ws_error()` → `Sender::poll_event()`. The old name
  is kept as a `#[deprecated]` alias for one release; return type
  widens from `Option<QwpWsSenderError>` to `Option<QwpWsEvent>`. Old
  callers update by switching on `event.kind`.
- `Sender::qwp_ws_errors_dropped()` → `Sender::events_dropped()`. Same
  semantics, broader scope.
- `Sender::qwp_ws_terminal_error()` stays as-is.
- `crate::Error` gains a private `Option<Box<QwpWsSenderError>>` field
  — no source-level break for public constructors/accessors.
- `ErrorCode` gains `ServerRejection`. Breaking for exhaustive matches
  unless `#[non_exhaustive]` is applied.
- `flush()`'s signature is unchanged; only the `Err` content for halt
  events broadens.
- Python `IngressErrorCode.BadDataFrame` shifts integer value.
  Document in the binding's changelog.

## Test surface

For each layer, cover:

1. Schema mismatch (`DropAndContinue`) → `flush()` returns `Ok(())`;
   custom callback fires once for the `BatchRejected` event during the
   next `flush()`; FSN is correct.
2. Multiple `DropAndContinue` events between flushes → callback fires
   in FSN order at the start of the next `flush()`, all before publish
   begins.
3. Halt → callback fires for the `Halted` event; same `flush()` call
   returns `Err` with halt payload; subsequent `flush()` calls return
   the same terminal error (callback does not re-fire).
4. Each of the seven `QwpWsErrorCategory` variants round-trips its
   payload through all four layers.
5. Reconnect cycle (forced disconnect → reconnect succeeds):
   `flush()` returns `Ok(())` throughout; `ReconnectStarted`,
   `Disconnected`, `ReconnectSucceeded` events fire on the callback in
   order at the boundary of the flushes during which they were
   observed.
6. Transient auth failure during reconnect: `TransientAuthFailed`
   event; sender keeps trying; eventual `ReconnectSucceeded`; `flush()`
   never returns `Err`.
7. Default callback output: Rust via `log` capture, Python via
   `caplog`, C via stderr redirection. Per-severity levels match the
   table above.
8. `events_dropped()` increments when the ring overflows.
9. Callback panic / exception propagates out of the call that triggered
   it (`flush()` returns `Err` carrying the panic message in Rust;
   Python raises through `flush()`; C++ propagates through the throw).
10. Reentrancy: calling `sender.flush()` from within the callback
    yields a documented error (Rust: borrow-checker panic; FFI: detect
    and return a specific error code rather than UB if cheap, else
    document).
11. `close()` drains pending events through the callback before
    releasing I/O resources.
12. Existing `poll_qwp_ws_error()` deprecated alias returns events of
    kind `BatchRejected` / `Halted` only.

## Non-goals

- Changing the wire protocol or reconnect behavior.
- Dispatcher-thread / background-thread delivery in v1. The whole
  point of the on-flush callback is to avoid adding a second
  per-sender thread to a sender that already has one in default mode
  (and explicitly avoid threads for users in manual-progress mode).
  See *Future work* below for the opt-in path.
- Sub-flush latency in v1. Events fire at flush boundaries; users who
  need sooner delivery flush more often, or opt into the future
  dispatcher mode.
- First-class asyncio integration. Users wrap `flush()` (or
  `poll_event()`) in `loop.run_in_executor`; the callback fires
  synchronously inside that executor call.
- Per-event-type counters / metrics export. Build on top of the
  callback.
- Identical-shape parity with Java's `SenderErrorHandler`. We match
  Java's *properties* (loud-by-default, callback ergonomics, halt as
  control flow) without copying its thread model.

## Future work — opt-in dispatcher mode

If real customers ask for sub-flush latency on observability events
(e.g. ops dashboards that watch reconnect storms in real time), add
an explicit per-sender mode:

```rust
let sender = SenderBuilder::new(...)
    .qwp_ws_event_delivery(EventDelivery::Dispatcher)  // default: ProducerThread
    .qwp_ws_event_handler(handler)
    .build();
```

Properties to inherit from Java's design if this lands:

- One dispatcher thread per sender, lazy-started on first event.
- Non-blocking enqueue from the I/O thread (the ring already provides
  this).
- Bounded inbox with drop counter (same `events_dropped()` accessor).
- Caught handler exceptions; the dispatcher logs and continues.
- Bounded drain on `close()` so shutdown doesn't hang on a slow
  handler.

Bindings:

- **Rust / C / C++**: callback fires on the dispatcher thread.
- **Python**: not supported. Python senders always use
  `EventDelivery::ProducerThread`. Attempting to construct a Python
  sender with `Dispatcher` is a config error.

Decision points to revisit at that time: ordering between
`poll_event()` and dispatcher draining concurrently; whether the
dispatcher invokes the handler for events that arrived after `close()`
began; whether to share the dispatcher across senders. Defer these
until a real use case scopes them.

## Open questions

1. **`#[non_exhaustive]` on `ErrorCode` and `QwpWsEventKind`.**
   Both should be non-exhaustive so adding event kinds or error codes
   isn't a breaking change. Verify on `ErrorCode`; apply to new types
   from the start.
2. **Default-callback format.** One-line structured (`category=…
   policy=… fsn=[X,Y] msg=…`) is the obvious choice — easy to grep,
   easy to parse with `logfmt`-style tools. Confirm before locking in.
3. **Backpressure interaction.** `flush()` can return `Err(SocketError)`
   for SF queue full. If the sender is also about to halt on the next
   server ack, which wins? Recommend halt takes precedence; specify in
   tests.
4. **Callback under `Drop`.** Sender dropped without explicit `close()`
   — should the callback fire for pending events from the `Drop`
   impl? Trade-off: convenient for users, but `Drop` can run on
   unexpected threads and the callback may not be safe to invoke there
   (e.g. a callback that touches thread-local state). Recommend: yes,
   but document that `Drop`-time invocation may happen on any thread,
   and recommend explicit `close()` for predictable behavior.
5. **Handler swap mid-life.** Java allows runtime handler replacement
   via the dispatcher's `volatile` field. We could expose
   `Sender::set_event_handler(Option<F>)` for the same. Useful for
   tests / reconfiguration; adds a `Mutex<Option<...>>` to the handler
   slot. Recommend: defer until a real use case appears.
6. **Reconnect-event granularity.** Java emits one event per attempt;
   our driver does too internally. Recommend per-attempt at Info
   severity, matching Java; bulk filtering is downstream.
7. **`noexcept` vs. propagating callback exceptions.** Rust panics
   unwind out of `flush()` naturally. C++ has `noexcept` on the C
   trampoline; user `std::function`s that throw will `std::terminate`
   the process. Python raises through `flush()`. C: callbacks must
   not unwind, period. Document each layer's contract explicitly.
