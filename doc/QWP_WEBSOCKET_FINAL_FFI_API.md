# QWP/WebSocket Final FFI, C++, And Python API Shape

This document defines the intended final C ABI plus the C++, Python, and other
language wrapper shape for QWP/WebSocket ingestion. It supersedes the older
shape-only `line_sender_qwpws*` prototype as a product API direction.

## Source Of Truth

The behavioral parity target is the Java client in:

```text
/home/jara/devel/oss/questdb-arrays/java-questdb-client
```

Use the Java source, not only design notes, when checking semantics. The
important Java shape is:

- one ordinary `Sender` surface for users,
- a cursor/send-engine split internally,
- `flush()` publishes into the local engine and returns before ACK,
- a background WebSocket loop owns transport progress by default,
- server errors are observable as structured sender errors,
- close/drain errors are observable on explicit close paths.

Rust intentionally follows that product shape with one exception: Rust, C, C++,
Python, and other FFI consumers must allow users to avoid a client-owned
background thread.

## Motivation

C, C++, and Python users split into two common groups.

The first group wants the convenience Java/Rust experience: create a sender,
append rows, call `flush()`, and let the client run the WebSocket send/ACK/replay
loop in the background.

The second group wants fine-grained control. This is common in C/C++ because
callers may already own an event loop, have strict thread-ownership rules, run
inside embedded systems, integrate with custom schedulers, or simply do not want
a library to start a background thread. It also matters to Python users embedding
QuestDB ingestion in existing schedulers, notebooks, services, or test harnesses
where background thread ownership and shutdown need to be explicit. These users
still want the same delivery semantics, Store-and-Forward behavior, server
diagnostics, and replay policy as the convenience path. They should not have to
use a separate sender type with a different contract.

The final FFI therefore mirrors Rust:

- one sender handle,
- background progress by default,
- manual progress as a configuration mode on the same handle,
- QWP/WebSocket-specific helper functions for the low-level state that only
  matters to users who opt into pipelined/manual control.

## Retired Prototype Surface

The separate shape-only `line_sender_qwpws*` prototype surface has been removed
from the public C header. The final API uses the existing `line_sender` handle
with QWP/WebSocket-specific helpers and a `qwp_ws_progress` configuration mode.

The removed prototype symbols were:

- `line_sender_qwpws`
- `line_sender_qwpws_receipt`
- `line_sender_qwpws_poll_event`
- `line_sender_qwpws_get_receipt_status`
- `line_sender_qwpws_wait`
- `line_sender_qwpws_threaded_start`
- `line_sender_qwpws_threaded_stop`

Those symbols encoded the old "manual sender plus threaded adapter"
architecture, while Rust has moved to one `Sender` with a progress mode.

## Final C ABI Principles

Use the existing `line_sender*` handle for QWP/WebSocket.

```c
line_sender* sender = line_sender_from_conf(
        line_sender_utf8_assert(strlen(conf), conf),
        &err);
```

The sender protocol decides which protocol-specific extension calls are valid.
Calling a QWP/WebSocket extension on TCP, HTTP, or QWP/UDP returns `false` and
sets `err_out` to `LINE_SENDER_ERROR_INVALID_API_CALL`.

The sender remains single-owner: callers must access a given `line_sender*` from
only one thread at a time, matching the existing C contract.

Do not add a separate public `line_sender_qwpws*` handle. Strong C type
separation would reintroduce the API split that Rust intentionally removed.

## Configuration

Background progress is the default:

```text
qwpws::addr=localhost:9000;
```

Manual progress uses the same sender type:

```text
qwpws::addr=localhost:9000;qwp_ws_progress=manual;
```

The C options API should expose the same setting for users who do not build
from a config string:

```c
typedef enum line_sender_qwpws_progress
{
    LINE_SENDER_QWPWS_PROGRESS_BACKGROUND = 0,
    LINE_SENDER_QWPWS_PROGRESS_MANUAL = 1,
} line_sender_qwpws_progress;

bool line_sender_opts_qwpws_progress(
        line_sender_opts* opts,
        line_sender_qwpws_progress progress,
        line_sender_error** err_out);
```

This follows the existing convention that config keys have corresponding
`line_sender_opts_*` functions where practical.

## Existing Generic Calls

These calls remain the convenience surface:

```c
line_sender_buffer* buffer = line_sender_buffer_new_for_sender(sender);
bool ok = line_sender_flush(sender, buffer, &err);
bool ok = line_sender_flush_and_keep(sender, buffer, &err);
```

For QWP/WebSocket:

- success means the batch was published locally into bounded memory or SFA,
- success does not mean the server has ACKed the batch,
- `line_sender_flush()` clears the buffer only after local publication succeeds,
- later terminal failures surface through subsequent sender calls and can carry
  the structured diagnostic on `line_sender_error*`,
- later server diagnostics are observable through the QWP/WebSocket diagnostic
  polling API below.

This is the C equivalent of Rust `Sender::flush()` and
`Sender::flush_and_keep()`.

## FSN And Watermark Types

Expose optional frame sequence numbers with a small C struct:

```c
typedef struct line_sender_qwpws_fsn
{
    bool has_value;
    uint64_t value;
} line_sender_qwpws_fsn;
```

`has_value == false` is used when no frame exists, such as an empty flush or a
sender that has not published anything yet.

## QWP/WebSocket Publication Helpers

These are QWP/WebSocket-specific variants of flush that return the local frame
sequence number assigned by the sender:

```c
bool line_sender_qwpws_flush_and_get_fsn(
        line_sender* sender,
        line_sender_buffer* buffer,
        line_sender_qwpws_fsn* fsn_out,
        line_sender_error** err_out);

bool line_sender_qwpws_flush_and_keep_and_get_fsn(
        line_sender* sender,
        const line_sender_buffer* buffer,
        line_sender_qwpws_fsn* fsn_out,
        line_sender_error** err_out);
```

These functions are useful for manual-control users who want to wait for a
specific published frame. They should not introduce public receipt handles.

Rules:

- `fsn_out` is required.
- Empty buffers return success with `fsn_out->has_value == false`.
- On failure, the caller buffer is not cleared.
- Transactional flush remains unsupported for QWP/WebSocket.

## Progress And Watermark Helpers

Manual-progress users drive WebSocket work explicitly:

```c
bool line_sender_qwpws_drive_once(
        line_sender* sender,
        bool* progressed_out,
        line_sender_error** err_out);
```

Rules:

- valid only for QWP/WebSocket senders built with `qwp_ws_progress=manual`,
- returns success with `*progressed_out == false` when no immediate progress is
  available,
- does not take a timeout; callers that want parking can sleep or wait in their
  own scheduler,
- returns `InvalidApiCall` for background QWP/WebSocket senders.

Watermark helpers are valid in both background and manual modes:

```c
bool line_sender_qwpws_published_fsn(
        const line_sender* sender,
        line_sender_qwpws_fsn* fsn_out,
        line_sender_error** err_out);

bool line_sender_qwpws_acked_fsn(
        const line_sender* sender,
        line_sender_qwpws_fsn* fsn_out,
        line_sender_error** err_out);

bool line_sender_qwpws_await_acked_fsn(
        line_sender* sender,
        uint64_t fsn,
        uint64_t timeout_millis,
        bool* reached_out,
        line_sender_error** err_out);
```

`await_acked_fsn()` matches Rust:

- in background mode, it waits while the sender-owned runner advances progress,
- in manual mode, it also drives progress while waiting,
- timeout is a normal successful result with `*reached_out == false`,
- terminal sender errors are API failures through `err_out`.

## Structured Error Diagnostics

Do not expose private driver events as the primary user-facing diagnostic path.
Expose the same structured sender error shape as Rust.

```c
typedef enum line_sender_qwpws_error_category
{
    LINE_SENDER_QWPWS_ERROR_SCHEMA_MISMATCH = 0,
    LINE_SENDER_QWPWS_ERROR_PARSE_ERROR = 1,
    LINE_SENDER_QWPWS_ERROR_INTERNAL_ERROR = 2,
    LINE_SENDER_QWPWS_ERROR_SECURITY_ERROR = 3,
    LINE_SENDER_QWPWS_ERROR_WRITE_ERROR = 4,
    LINE_SENDER_QWPWS_ERROR_PROTOCOL_VIOLATION = 5,
    LINE_SENDER_QWPWS_ERROR_UNKNOWN = 6,
} line_sender_qwpws_error_category;

typedef enum line_sender_qwpws_error_policy
{
    LINE_SENDER_QWPWS_ERROR_DROP_AND_CONTINUE = 0,
    LINE_SENDER_QWPWS_ERROR_HALT = 1,
} line_sender_qwpws_error_policy;

typedef struct line_sender_qwpws_error line_sender_qwpws_error;

typedef struct line_sender_qwpws_error_view
{
    line_sender_qwpws_error_category category;
    line_sender_qwpws_error_policy applied_policy;
    bool has_status;
    uint8_t status;
    bool has_message_sequence;
    uint64_t message_sequence;
    uint64_t from_fsn;
    uint64_t to_fsn;
    const char* message;
    size_t message_len;
} line_sender_qwpws_error_view;
```

Polling:

```c
bool line_sender_qwpws_poll_error(
        line_sender* sender,
        line_sender_qwpws_error** error_out,
        line_sender_error** err_out);

line_sender_qwpws_error_view line_sender_qwpws_error_get_view(
        const line_sender_qwpws_error* error);

bool line_sender_error_qwpws_get_view(
        const line_sender_error* error,
        line_sender_qwpws_error_view* view_out);

void line_sender_qwpws_error_free(
        line_sender_qwpws_error* error);

bool line_sender_qwpws_errors_dropped(
        const line_sender* sender,
        uint64_t* dropped_out,
        line_sender_error** err_out);
```

Rules:

- `error_out` is required.
- no diagnostic is success with `*error_out == NULL`,
- a returned diagnostic is owned by the caller and must be freed with
  `line_sender_qwpws_error_free()`,
- the `message` pointer in `line_sender_qwpws_error_view` is valid until the
  diagnostic object is freed,
- QWP server non-OK responses set `has_status == true` and
  `has_message_sequence == true`,
- terminal WebSocket protocol closes set `category ==
  LINE_SENDER_QWPWS_ERROR_PROTOCOL_VIOLATION`, `has_status == false`, and
  `has_message_sequence == false`,
- the function remains usable after terminalization so callers can inspect the
  diagnostic that halted the sender.
- when a HALT diagnostic terminalizes the sender, the next failing sender call
  also returns a `line_sender_error*` whose structured diagnostic can be copied
  with `line_sender_error_qwpws_get_view()`. The returned view is borrowed from
  the ordinary error object and is valid until `line_sender_error_free()`.

The owned diagnostic object is intentional. A caller-provided message buffer
would be adequate for C, but it is awkward for Cython and other language
bindings because polling consumes the diagnostic. If a short buffer truncated the
message, the full server diagnostic would be unrecoverable. The owned object
matches the existing `line_sender_error*` ownership style and lets C++ and Python
copy a complete message into native string objects.

This replaces the old public `poll_event`, receipt-status, and rejection-detail
API shape for normal users.

## Close Semantics

C/C++ destructors and Python finalizers cannot reliably return errors. Keep void
close/drop best-effort and make delivery-sensitive shutdown explicit.

Final C shape:

```c
bool line_sender_qwpws_close_drain(
        line_sender* sender,
        line_sender_error** err_out);
```

Rules:

- valid for QWP/WebSocket senders in both background and manual modes,
- stops accepting new local publications,
- waits for already published frames to resolve,
- returns `false` and sets `err_out` on timeout or terminal failure,
- uses the same timeout semantics as Rust `Sender::close_drain()`.

Do not expose timeout as a normal outcome. If Rust later accepts
`close_flush_timeout_millis` or adds an explicit timeout parameter, C can add a
matching function. The important semantic rule is that timeout is an observable
failure, not a silent best-effort close.

`line_sender_close(sender)` remains best-effort and non-reporting.

## C Convenience Example

Background mode:

```c
line_sender_error* err = NULL;
line_sender* sender = line_sender_from_conf(
        line_sender_utf8_assert(strlen(conf), conf),
        &err);

line_sender_buffer* buffer = line_sender_buffer_new_for_sender(sender);
/* append rows */

if (!line_sender_flush(sender, buffer, &err)) {
    /* inspect err */
}

line_sender_qwpws_error* qwp_err = NULL;
if (line_sender_qwpws_poll_error(sender, &qwp_err, &err) && qwp_err != NULL) {
    line_sender_qwpws_error_view view =
            line_sender_qwpws_error_get_view(qwp_err);
    /* inspect view.category, view.applied_policy, view.message */
    line_sender_qwpws_error_free(qwp_err);
}

line_sender_close(sender);
```

Manual mode:

```c
const char* conf = "qwpws::addr=localhost:9000;qwp_ws_progress=manual;";
line_sender* sender = line_sender_from_conf(
        line_sender_utf8_assert(strlen(conf), conf),
        &err);

line_sender_qwpws_fsn fsn;
if (line_sender_qwpws_flush_and_get_fsn(sender, buffer, &fsn, &err)
        && fsn.has_value) {
    bool reached = false;
    while (!reached) {
        bool progressed = false;
        line_sender_qwpws_drive_once(sender, &progressed, &err);
        line_sender_qwpws_await_acked_fsn(sender, fsn.value, 10, &reached, &err);
    }
}
```

## Final C++ Wrapper Shape

C++ should also expose one `questdb::ingress::line_sender` class. Do not add a
separate public `qwp_ws_sender` class.

Suggested additions:

```cpp
enum class qwp_ws_progress {
    background,
    manual,
};

enum class qwp_ws_error_category {
    schema_mismatch,
    parse_error,
    internal_error,
    security_error,
    write_error,
    protocol_violation,
    unknown,
};

enum class qwp_ws_error_policy {
    drop_and_continue,
    halt,
};

struct qwp_ws_error {
    qwp_ws_error_category category;
    qwp_ws_error_policy applied_policy;
    std::optional<uint8_t> status;
    std::string message;
    std::optional<uint64_t> message_sequence;
    uint64_t from_fsn;
    uint64_t to_fsn;
};
```

Options:

```cpp
opts& opts::qwp_ws_progress(qwp_ws_progress progress);
```

Sender helpers:

```cpp
std::optional<uint64_t> line_sender::flush_and_get_fsn(line_sender_buffer& buffer);
std::optional<uint64_t> line_sender::flush_and_keep_and_get_fsn(
        const line_sender_buffer& buffer);

std::optional<uint64_t> line_sender::published_fsn() const;
std::optional<uint64_t> line_sender::acked_fsn() const;
bool line_sender::await_acked_fsn(
        uint64_t fsn,
        std::chrono::milliseconds timeout);

bool line_sender::drive_once();

std::optional<qwp_ws_error> line_sender::poll_qwp_ws_error();
uint64_t line_sender::qwp_ws_errors_dropped() const;

void line_sender::close_drain();

const std::optional<qwp_ws_error>& line_sender_error::qwp_ws_diagnostic()
        const noexcept;
```

Rules:

- invalid protocol/mode calls throw `line_sender_error` with
  `line_sender_error_code::invalid_api_call`,
- `drive_once()` throws on background-mode senders,
- `await_acked_fsn()` returns `false` on timeout,
- `close_drain()` throws on timeout or terminal failure,
- terminal QWP/WebSocket failures attach the structured diagnostic to the thrown
  `line_sender_error`,
- `~line_sender()` remains `noexcept` and best-effort.

## C++ Usage Examples

Background mode:

```cpp
auto sender = questdb::ingress::line_sender::from_conf(
    "qwpws::addr=localhost:9000;");
auto buffer = sender.new_buffer();

/* append rows */
sender.flush(buffer);

if (auto err = sender.poll_qwp_ws_error()) {
    /* inspect err->category and err->message */
}
```

Manual mode:

```cpp
auto sender = questdb::ingress::line_sender::from_conf(
    "qwpws::addr=localhost:9000;qwp_ws_progress=manual;");
auto buffer = sender.new_buffer();

/* append rows */
auto fsn = sender.flush_and_get_fsn(buffer);
if (fsn) {
    while (!sender.await_acked_fsn(*fsn, std::chrono::milliseconds{10})) {
        sender.drive_once();
    }
}
```

## Final Python Wrapper Shape

The Python client in:

```text
/home/jara/devel/oss/py-questdb-client
```

should consume this same C ABI through its existing Cython binding layer. It
should not add a separate public `QwpWsSender` class.

Python should expose one `questdb.ingress.Sender` surface:

```python
from questdb.ingress import Protocol, Sender, TimestampNanos

with Sender(Protocol.QwpWs, "localhost", 9000) as sender:
    sender.row(
        "trades",
        columns={"price": 2615.54},
        at=TimestampNanos.now())
    sender.flush()
```

`Sender.flush()` has the same QWP/WebSocket meaning as Rust and C:

- success means local publication into bounded memory or SFA,
- success does not mean the server has ACKed the frame,
- the sender buffer is cleared only after local publication succeeds,
- later terminal failures surface through later sender calls and are available
  as `IngressError.qwp_ws_error`,
- later server diagnostics are available through `poll_qwp_ws_error()`.

Python manual mode should stay on the same `Sender` object:

```python
sender = Sender.from_conf(
    "qwpws::addr=localhost:9000;qwp_ws_progress=manual;")
sender.establish()

fsn = sender.flush_and_get_fsn()
if fsn is not None:
    while not sender.await_acked_fsn(fsn, timeout_millis=10):
        sender.drive_once()

sender.close_drain()
```

Suggested Python additions:

```python
Protocol.QwpWs
Protocol.QwpWss

class QwpWsProgress(Enum):
    Background = ...
    Manual = ...

class QwpWsErrorCategory(Enum): ...
class QwpWsErrorPolicy(Enum): ...

@dataclass(frozen=True)
class QwpWsError:
    category: QwpWsErrorCategory
    applied_policy: QwpWsErrorPolicy
    status: Optional[int]
    message: str
    message_sequence: Optional[int]
    from_fsn: int
    to_fsn: int

Sender.flush_and_get_fsn(...) -> Optional[int]
Sender.flush_and_keep_and_get_fsn(...) -> Optional[int]
Sender.published_fsn() -> Optional[int]
Sender.acked_fsn() -> Optional[int]
Sender.await_acked_fsn(fsn: int, timeout_millis: int) -> bool
Sender.drive_once() -> bool
Sender.poll_qwp_ws_error() -> Optional[QwpWsError]
Sender.qwp_ws_errors_dropped() -> int
Sender.close_drain() -> None

IngressError.qwp_ws_error -> Optional[QwpWsError]
```

Python binding requirements:

- update the vendored `c-questdb-client` submodule before exposing QWP/WebSocket,
- add `qwpws` and `qwpwss` to the Cython `line_sender_protocol` binding,
- add `Protocol.QwpWs` and `Protocol.QwpWss`,
- bind QWP/WebSocket extension functions as methods on `Sender`, not on a
  separate sender class,
- do not silently discard QWP/WebSocket config keys in `Sender.from_conf()`;
  either delegate the full config to C when there are no Python-side overrides or
  reconstruct a synthetic config string that preserves every supported
  QWP/WebSocket key,
- release the GIL around calls that can block on connection, append
  backpressure, ACK waiting, driver progress, or close-drain,
- keep `Sender.close()` and context-manager exit as best-effort local
  flush/close, unless Python intentionally chooses stricter wrapper semantics;
  delivery-sensitive shutdown must be available through explicit
  `Sender.close_drain()`,
- expose complete structured diagnostics. The owned C diagnostic object above
  is required so Cython can copy a full server message without truncation or a
  consume-on-short-buffer failure, and `IngressError.qwp_ws_error` should carry
  the same HALT diagnostic from ordinary sender failures.

The Python implementation should follow the existing QWP/UDP precedent:
`Protocol` enum entry, normal `Sender` construction, `Sender.from_conf()`, normal
`Sender.flush()`, and `Sender.new_buffer()` backed by
`line_sender_buffer_new_for_sender()`.

## API Surface To Avoid

Do not expose these concepts as stable C/C++/Python product APIs unless a future
customer need proves the simpler FSN/watermark/error surface insufficient:

- public receipt handles,
- public receipt-status polling,
- public delivery outcome trees,
- public transport event streams,
- threaded adapter ownership conversion,
- durable ACK/rejection/dead-letter records,
- callbacks invoked from the I/O loop.

These concepts are either internal implementation details or older prototype
machinery. The final product contract should stay small.

## Validation Requirements

Before hardening the C ABI or language wrappers:

1. C `line_sender_from_conf("qwpws::...")` builds the real Rust QWP/WebSocket
   sender, not a placeholder.
2. C `line_sender_flush()` has the same local-publication-before-ACK behavior as
   Rust.
3. C manual mode with `qwp_ws_progress=manual` starts no background thread and
   can publish, drive, and await an ACK.
4. C background mode rejects `line_sender_qwpws_drive_once()` with
   `InvalidApiCall`.
5. C `line_sender_qwpws_poll_error()` observes schema/write drop-and-continue
   errors and terminal parse/protocol-close errors.
6. C diagnostics use an owned object, so language bindings can copy complete
   server messages without truncation.
7. C terminal `line_sender_error*` exposes the same HALT diagnostic without
   consuming the pollable diagnostic.
8. C++ wraps the same C functions without introducing a second sender class.
9. Python wraps the same C functions through the existing `Sender` class without
   introducing a second sender class.
10. Python `Sender.from_conf()` preserves QWP/WebSocket-specific config keys
   instead of forwarding only `addr`.
11. Destructors/void close remain best-effort; explicit `close_drain()` is the
   only close path that reports delivery failure.

The target is semantic parity with Rust and Java where Java semantics make sense
across C/C++, Python, and other FFI ownership boundaries.
