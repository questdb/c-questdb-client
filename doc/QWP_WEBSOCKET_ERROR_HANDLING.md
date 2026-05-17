# QWP/WebSocket Error Handling

## Status

Implemented scope:

- QWP/WebSocket server-side batch rejections are no longer silent by default.
- Drop-and-continue rejections are delivered to a callback and remain available
  through the existing pull API.
- Halt rejections are delivered to the callback and also surface as terminal
  control-flow errors with the same structured rejection payload.
- Rust, C, C++, and the Python WIP binding expose the rejection callback.

Not implemented:

- A broad `QwpWsEvent` taxonomy for reconnects, disconnects, transient auth, or
  backpressure.
- Public `poll_event()` / `events_dropped()` aliases.
- A Java-style dispatcher thread.

Those items were in an earlier draft of this document, but tracing the Java
client showed that the callback contract to mirror is narrower:
`SenderErrorHandler.onError(SenderError)` receives server-side batch
rejections. Operational reconnect state is not part of that public callback
contract. Keeping the Rust/C/C++/Python implementation to `QwpWsSenderError`
avoids introducing a new event abstraction that is not needed for the current
contract.

## Java Contract

Reference tree:

`/home/jara/devel/oss/questdb-arrays/java-questdb-client`

Relevant Java files:

- `core/src/main/java/io/questdb/client/SenderError.java`
- `core/src/main/java/io/questdb/client/SenderErrorHandler.java`
- `core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/DefaultSenderErrorHandler.java`

The Java callback shape is:

```java
public interface SenderErrorHandler {
    void onError(@NotNull SenderError error);
}
```

`SenderError` is an immutable description of an asynchronously observed
server-side rejection. It carries:

- rejection category;
- applied policy (`DROP_AND_CONTINUE` or `HALT`);
- optional server status byte;
- optional message sequence;
- rejected FSN span;
- optional server message;
- optional table name;
- detection timestamp.

The default Java handler logs every rejection. `DROP_AND_CONTINUE` is WARN,
`HALT` is ERROR. Handler exceptions are caught and logged by the dispatcher.

## Implemented Model

The implementation has two channels:

| Channel | Purpose | Behavior |
|---|---|---|
| Control flow | Tell the producer when the sender is terminal. | Halt-policy server rejections and protocol violations return `ServerRejection` errors with a structured `QwpWsSenderError` payload. |
| Notification | Tell the user about rejected batches even when the sender continues. | A producer-thread callback receives `QwpWsSenderError` values. The existing `poll_qwp_ws_error()` pull API remains independent. |

There is intentionally no dispatcher thread. Delivery happens from existing
producer-thread API calls, primarily `flush()` and `close_drain()`. This keeps
manual-progress senders thread-free and avoids cross-thread callback lifetime
and Python GIL concerns.

## Rust API

Implemented in:

- `questdb-rs/src/error.rs`
- `questdb-rs/src/ingress.rs`
- `questdb-rs/src/ingress/sender.rs`
- `questdb-rs/src/ingress/sender/qwp_ws_driver.rs`
- `questdb-rs/src/ingress/sender/qwp_ws_ownership.rs`

Public additions:

```rust
impl SenderBuilder {
    pub fn qwp_ws_error_handler<F>(self, handler: F) -> Result<Self>
    where
        F: Fn(&QwpWsSenderError) + Send + Sync + 'static;
}

impl Error {
    pub fn qwp_ws_rejection(&self) -> Option<&QwpWsSenderError>;
}

pub enum ErrorCode {
    ServerRejection,
    // ...
}
```

Default behavior:

- `SenderBuilder` installs a default `QwpWsErrorHandler`.
- Default Rust delivery logs through the `log` crate with target
  `questdb::ingress`.
- Halt-policy rejections log at ERROR.
- Drop-and-continue rejections log at WARN.

Delivery details:

- The driver pushes each server rejection into two rings:
  one for `poll_qwp_ws_error()` and one for callback notifications.
- Callback delivery never consumes the pull diagnostic.
- `flush()` drains notifications after the terminal pre-check passes and before
  publishing the next frame.
- If the terminal pre-check fails, `flush()` first drains the queued terminal
  notification and then returns the terminal error.
- `close_drain()` drains remaining notifications after the close-drain attempt.

## C API

Implemented in:

- `questdb-rs-ffi/src/lib.rs`
- `include/questdb/ingress/line_sender.h`

Public additions:

```c
typedef void (*line_sender_qwpws_error_cb)(
    void* user_data,
    const line_sender_qwpws_error_view* event);

bool line_sender_opts_qwpws_error_handler(
    line_sender_opts* opts,
    line_sender_qwpws_error_cb cb,
    void* user_data,
    line_sender_error** err_out);
```

`line_sender_error_server_rejection` identifies terminal QWP/WebSocket
server rejections and protocol violations. The existing
`line_sender_error_qwpws_get_view()` accessor exposes the structured payload
attached to those errors.

Default behavior:

- C opts constructors install a default callback.
- The default C callback writes one structured line to stderr.
- Passing `NULL` as the callback restores the default.

The callback receives a stack view valid only for the callback call. Consumers
must copy fields they need to retain.

## C++ API

Implemented in:

- `include/questdb/ingress/line_sender_core.hpp`
- `include/questdb/ingress/line_sender.hpp`

Public additions:

```cpp
opts& qwp_ws_error_handler(
    std::function<void(const qwp_ws_error&)> handler);
```

The wrapper stores the `std::function` with the options and sender so the C
callback `user_data` remains valid for the sender lifetime.

Terminal errors keep using the existing `line_sender_error` exception type.
The existing `qwp_ws_error()` payload on that exception carries the structured
server rejection.

## Python WIP API

Implemented in:

- `/home/jara/devel/oss/py-questdb-client/src/questdb/line_sender.pxd`
- `/home/jara/devel/oss/py-questdb-client/src/questdb/ingress.pyx`
- `/home/jara/devel/oss/py-questdb-client/src/questdb/ingress.pyi`

Public additions:

```python
sender = Sender.from_conf(
    "qwpws::addr=localhost:9000;",
    qwp_ws_error_handler=lambda error: ...
)
```

The callback receives a `QwpWsError`.

Additional error surface:

```python
class IngressServerRejectionError(IngressError):
    ...

IngressErrorCode.ServerRejection
```

`IngressServerRejectionError.qwp_ws_error` carries the structured halt payload.

Default behavior:

- QWP/WebSocket Python senders install a default handler when no explicit
  `qwp_ws_error_handler` is supplied.
- The default handler logs through `logging.getLogger("questdb.ingress")`.
- Halt-policy rejections log at ERROR.
- Drop-and-continue rejections log at WARNING.

The Python binding releases the GIL around sender calls, so the Cython
trampoline reacquires it with `with gil`. Handler exceptions are caught and
logged on `questdb.ingress`, matching the Java handler-exception behavior.

## Verification

Rust behavior:

```text
cargo test --manifest-path questdb-rs/Cargo.toml \
  --features sync-sender-qwp-ws,tls-webpki-certs,ring-crypto \
  qwp_ws --lib

239 passed; 20 ignored
```

Coverage from the Rust tests:

- halt rejection returns `ErrorCode::ServerRejection`;
- halt rejection carries `Error::qwp_ws_rejection()`;
- callback receives the halt rejection;
- schema mismatch remains drop-and-continue;
- callback receives the drop-and-continue rejection;
- `poll_qwp_ws_error()` still sees the same rejection after callback delivery;
- notification delivery does not consume the pull diagnostic.

FFI behavior:

```text
cargo test --manifest-path questdb-rs-ffi/Cargo.toml qwpws

6 passed
```

Coverage from the FFI tests:

- QWP/WebSocket terminal diagnostic remains visible after polling;
- C callback receives the same terminal diagnostic;
- terminal `line_sender_error` exposes the QWP/WebSocket diagnostic view;
- plain errors do not expose a QWP/WebSocket diagnostic view;
- non-WebSocket senders reject QWP/WebSocket extension calls.

C++ wrapper:

```text
cmake --build build_CXX20 --target test_line_sender
build_CXX20/test_line_sender

78 passed; 1724 assertions
```

Python WIP binding:

```text
PYTHONPATH=/tmp/codex-py-qdb-deps \
TEST_QUESTDB_PATCH_PATH=1 \
python3 test/test.py -v TestQwpWebSocketApi

12 passed
```

Coverage from the Python tests:

- `IngressServerRejectionError` is an `IngressError`;
- `IngressErrorCode.ServerRejection` exists;
- `qwp_ws_error_handler` can be registered on QWP/WebSocket senders;
- `qwp_ws_error_handler` is rejected on non-WebSocket senders.

The Python extension was also compiled against the updated C headers and Rust
FFI library via:

```text
PYTHONPATH=/tmp/codex-py-qdb-deps python3 setup.py build_ext --inplace
```

The only compiler warning observed there was the pre-existing Python 3.14
`PyWeakref_GetObject` deprecation warning.

## Deferred Scope

The following earlier draft items remain intentionally deferred:

- a public `QwpWsEvent` abstraction;
- reconnect, disconnect, auth, and backpressure notifications;
- `poll_event()` and `events_dropped()` aliases;
- runtime handler replacement on an already-built sender;
- opt-in dispatcher-thread delivery.

These can be added later if a user-visible need appears, but they are not
required to match the current Java callback contract for server-side batch
rejections.
