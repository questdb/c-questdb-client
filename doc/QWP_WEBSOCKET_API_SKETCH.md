# QWP/WebSocket pipelined Store-and-Forward API sketch

Date: 2026-04-28

Status: Step 1 sketch for `doc/QWP_WEBSOCKET_VALIDATION_PLAN.md`.
This is not an implementation contract yet. The goal is to write the intended
end-user code before committing to transport, queue, or FFI details.

## Design stance

Use `submit()` as the primary verb.

`submit()` means local publication into the QWP/WebSocket sender core. It
validates and encodes the caller's `Buffer` into sender-owned volatile or
Store-and-Forward storage, then returns a value receipt. It does not wait for
the server to ACK the frame.

`wait(receipt, timeout)` means server delivery observation for a previously
submitted receipt. It may drive progress on the caller's thread for the manual
sender.

The low-level API should not expose `flush()` as the primary verb. Existing
`Sender::flush()` behavior differs by transport and is too overloaded for the
new pipelined contract. If a compatibility wrapper exposes `flush()`, it must
document whether it means local publication only or server delivery.

## Core vocabulary

```rust
pub struct QwpWsSender;
pub struct QwpWsThreadedSender;
pub struct QwpWsTokioSender;
pub struct QwpWsDriver;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct QwpReceipt {
    pub fsn: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QwpOpenMode {
    Connected,
    Lazy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QwpQueueMode {
    Volatile,
    StoreAndForward,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QwpSfDurability {
    PageCache,
    Flush,
    Append,
}

#[derive(Debug)]
pub enum QwpReceiptStatus {
    Published {
        fsn: u64,
    },
    Sent {
        fsn: u64,
        wire_seq: Option<u64>,
    },
    Acked {
        fsn: u64,
    },
    Poisoned {
        fsn: u64,
        status: QwpStatus,
    },
    Terminal {
        fsn: u64,
        error: QwpErrorSummary,
    },
    Invalid {
        fsn: u64,
    },
}

impl QwpReceiptStatus {
    pub fn is_pending(&self) -> bool {
        matches!(self, Self::Published { .. } | Self::Sent { .. })
    }
}

#[derive(Debug)]
pub enum QwpDeliveryOutcome {
    Acked,
    Poisoned {
        fsn: u64,
        status: QwpStatus,
        message_truncated: bool,
        poison_path: Option<std::path::PathBuf>,
    },
    Timeout {
        status: QwpReceiptStatus,
    },
    Terminal {
        error: QwpErrorSummary,
    },
}

#[derive(Debug)]
pub enum QwpDriveOutcome {
    Idle,
    Progress,
    Terminal,
}

#[derive(Debug)]
pub enum QwpCloseOutcome {
    Drained,
    Timeout {
        published_fsn: Option<u64>,
        server_acked_fsn: Option<u64>,
        completed_fsn: Option<u64>,
    },
    Terminal {
        error: QwpErrorSummary,
    },
}

#[derive(Debug)]
pub enum QwpEvent {
    Published { fsn: u64 },
    Sent { fsn: u64, wire_seq: u64 },
    AckedThrough { fsn: u64 },
    DurableAck { details: Option<QwpDurableAckDetails> },
    Retrying { attempt: u32, elapsed: std::time::Duration, error: QwpErrorSummary },
    Reconnected { replay_from_fsn: u64, attempts: u32, elapsed: std::time::Duration },
    Poisoned { fsn: u64, status: QwpStatus, message_truncated: bool },
    Backpressure { duration: std::time::Duration, reason: QwpBackpressureReason },
    Terminal { error: QwpErrorSummary },
}
```

`QwpStatus`, `QwpErrorSummary`, `QwpDurableAckDetails`, and exact poison enum
values are deliberately left provisional until real-server error taxonomy and
durable-ACK probes complete.

`QwpDeliveryOutcome::Poisoned` includes the FSN even though the caller already
has the receipt. That redundancy is intentional for logging and callback
ergonomics. `QwpCloseOutcome` does not have a separate poisoned variant in this
sketch: poison is a receipt completion state. Under `PoisonPolicy::Stop`, the
sender stops sending new frames after already-sent in-flight frames are
resolved; under quarantine policy, poison is reported through receipt state and
events while sending can continue. In both modes, close can only report drained
after all published receipts are resolved as ACKed or poisoned.

`server_acked_fsn` and `completed_fsn` are distinct. After a poison gap,
`completed_fsn` may advance through ACKed later receipts while
`server_acked_fsn` remains before the poisoned FSN.

## Rust manual sender

The manual sender is threadless. It owns the queue, connection state,
in-flight slots, event ring, and scratch buffers. It makes progress only when
the caller invokes `submit()`, `drive_once()`, `wait()`, or `close_drain()`.

```rust
use std::time::Duration;
use questdb::ingress::{
    Buffer, QwpCloseOutcome, QwpDeliveryOutcome, QwpOpenMode, QwpQueueMode,
    QwpWsOptions, QwpWsSender, TimestampNanos,
};

fn manual_submit_and_wait() -> questdb::Result<()> {
    let opts = QwpWsOptions::from_conf(
        "qwpws::addr=localhost:9000;\
         open_mode=connected;\
         queue_mode=sf;\
         sf_dir=/var/lib/my-app/qdb-sf;\
         sender_id=prices;",
    )?;

    let mut sender = QwpWsSender::open(opts)?;
    let mut buffer = sender.new_buffer();

    buffer
        .table("trades")?
        .symbol("sym", "ETH-USD")?
        .column_f64("price", 3421.50)?
        .at(TimestampNanos::new(1_700_000_000_000_000_000))?;

    let receipt = sender.submit(&mut buffer)?;

    assert!(buffer.is_empty());

    match sender.wait(receipt, Duration::from_secs(5))? {
        QwpDeliveryOutcome::Acked => {}
        QwpDeliveryOutcome::Timeout { status } => {
            eprintln!("still waiting for server ACK: {status:?}");
        }
        QwpDeliveryOutcome::Poisoned { fsn, status, .. } => {
            eprintln!("server rejected frame {fsn}: {status:?}");
        }
        QwpDeliveryOutcome::Terminal { error } => {
            eprintln!("sender is terminal: {error:?}");
        }
    }

    match sender.close_drain(Duration::from_secs(5))? {
        QwpCloseOutcome::Drained => {}
        other => eprintln!("not fully drained on close: {other:?}"),
    }

    Ok(())
}
```

If an application wants to keep the buffer intact, it calls
`submit_and_keep()`.

```rust
let receipt = sender.submit_and_keep(&buffer)?;
assert!(!buffer.is_empty());
```

`submit()` may block while waiting for local queue capacity. That blocking is
bounded by the configured local append timeout. A timeout waiting for local
publication is an API error because no receipt exists. A timeout in `wait()` is
a delivery outcome because the receipt remains valid.

Manual progress can also be explicit:

```rust
let receipt = sender.submit(&mut buffer)?;

while sender.receipt_status(receipt).is_pending() {
    sender.drive_once(Duration::from_millis(10))?;
    while let Some(event) = sender.poll_event() {
        println!("qwp event: {event:?}");
    }
}
```

## Rust threaded adapter

Starting the threaded adapter consumes the manual sender. This prevents a
manual driver and a background runner from racing the same core.

```rust
use std::time::Duration;
use questdb::ingress::{QwpDeliveryOutcome, QwpWsSender, QwpWsThreadedSender};

fn threaded_sender() -> questdb::Result<()> {
    let sender = QwpWsSender::open(opts())?;
    let threaded = QwpWsThreadedSender::start(sender)?;

    let mut buffer = threaded.new_buffer();
    buffer.table("metrics")?.symbol("host", "a")?.column_i64("load", 42)?.at_now()?;

    let receipt = threaded.submit(&mut buffer)?;

    match threaded.wait(receipt, Duration::from_secs(5))? {
        QwpDeliveryOutcome::Acked => {}
        other => eprintln!("not acked yet: {other:?}"),
    }

    threaded.close_drain(Duration::from_secs(5))?;
    Ok(())
}
```

The threaded sender is a different type. It may expose synchronized `&self`
methods because the runner owns progress, but v1 should not imply unbounded
multi-producer submission. Assume callers serialize `submit()` unless a
bounded, preallocated multi-producer wrapper is explicitly added. The delivery
semantics remain the same as the manual core.

Stopping a threaded sender does not return the original manual sender. To
resume manual control, close the threaded handle and open or recover a new
manual sender from the same Store-and-Forward slot.

## Rust Tokio adapter

Tokio support is an adapter. The caller decides whether and where to spawn the
driver. Tokio types should not appear in the C ABI.

```rust
use std::time::Duration;
use questdb::ingress::{QwpDeliveryOutcome, QwpWsTokioSender};

async fn tokio_sender() -> questdb::Result<()> {
    let (sender, driver) = QwpWsTokioSender::open(opts()).await?;
    let driver_task = tokio::spawn(async move { driver.run().await });

    let mut buffer = sender.new_buffer();
    buffer.table("events")?.symbol("kind", "click")?.column_i64("user", 7)?.at_now()?;

    let receipt = sender.submit(&mut buffer).await?;

    match sender.wait(receipt, Duration::from_secs(5)).await? {
        QwpDeliveryOutcome::Acked => {}
        QwpDeliveryOutcome::Timeout { .. } => {}
        other => eprintln!("delivery outcome: {other:?}"),
    }

    sender.close_drain(Duration::from_secs(5)).await?;
    driver_task.await??;
    Ok(())
}
```

Async multi-producer convenience may allocate inside the adapter. That does not
change the core requirement: the underlying sender state machine should be able
to run without steady-state hot-path allocation after warm-up and sizing.

## C ABI

The C API should be QWP/WebSocket-specific at first. Do not overload the
existing `line_sender_flush()` before the new delivery semantics are stable.

Opaque handles:

```c
typedef struct line_sender_qwpws_sender line_sender_qwpws_sender;
typedef struct line_sender_qwpws_threaded line_sender_qwpws_threaded;

typedef struct {
    uint64_t fsn;
} line_sender_qwpws_receipt;
```

Submit and wait use distinct result shapes. `err_out` is for API failure only.
Timeout, pending, poisoned, and drained states are normal outcomes.

```c
typedef enum {
    LINE_SENDER_QWPWS_SUBMIT_PUBLISHED = 0,
    LINE_SENDER_QWPWS_SUBMIT_EMPTY = 1
} line_sender_qwpws_submit_status;

typedef struct {
    line_sender_qwpws_submit_status status;
    line_sender_qwpws_receipt receipt;
} line_sender_qwpws_submit_result;

typedef enum {
    LINE_SENDER_QWPWS_WAIT_ACKED = 0,
    LINE_SENDER_QWPWS_WAIT_TIMEOUT = 1,
    LINE_SENDER_QWPWS_WAIT_POISONED = 2,
    LINE_SENDER_QWPWS_WAIT_TERMINAL = 3
} line_sender_qwpws_wait_status;

typedef struct {
    line_sender_qwpws_wait_status status;
    uint64_t fsn;
    int32_t qwp_status;
    bool message_truncated;
} line_sender_qwpws_wait_result;

typedef enum {
    LINE_SENDER_QWPWS_RECEIPT_INVALID = 0,
    LINE_SENDER_QWPWS_RECEIPT_PENDING = 1,
    LINE_SENDER_QWPWS_RECEIPT_ACKED = 2,
    LINE_SENDER_QWPWS_RECEIPT_POISONED = 3,
    LINE_SENDER_QWPWS_RECEIPT_TERMINAL = 4
} line_sender_qwpws_receipt_status_kind;

typedef struct {
    line_sender_qwpws_receipt_status_kind kind;
    uint64_t fsn;
    int32_t qwp_status;
} line_sender_qwpws_receipt_status;

typedef enum {
    LINE_SENDER_QWPWS_EVENT_NONE = 0,
    LINE_SENDER_QWPWS_EVENT_PUBLISHED = 1,
    LINE_SENDER_QWPWS_EVENT_SENT = 2,
    LINE_SENDER_QWPWS_EVENT_ACKED = 3,
    LINE_SENDER_QWPWS_EVENT_DURABLE_ACK = 4,
    LINE_SENDER_QWPWS_EVENT_RETRYING = 5,
    LINE_SENDER_QWPWS_EVENT_RECONNECTED = 6,
    LINE_SENDER_QWPWS_EVENT_POISONED = 7,
    LINE_SENDER_QWPWS_EVENT_BACKPRESSURE = 8,
    LINE_SENDER_QWPWS_EVENT_TERMINAL = 9
} line_sender_qwpws_event_kind;

typedef struct {
    line_sender_qwpws_event_kind kind;
    uint64_t fsn;
    uint64_t wire_sequence;
    int32_t qwp_status;
    bool message_truncated;
} line_sender_qwpws_event;

typedef enum {
    LINE_SENDER_QWPWS_DRIVE_IDLE = 0,
    LINE_SENDER_QWPWS_DRIVE_PROGRESS = 1,
    LINE_SENDER_QWPWS_DRIVE_TERMINAL = 2
} line_sender_qwpws_drive_kind;

typedef struct {
    line_sender_qwpws_drive_kind kind;
} line_sender_qwpws_drive_outcome;

typedef enum {
    LINE_SENDER_QWPWS_CLOSE_DRAINED = 0,
    LINE_SENDER_QWPWS_CLOSE_TIMEOUT = 1,
    LINE_SENDER_QWPWS_CLOSE_TERMINAL = 2
} line_sender_qwpws_close_status;

typedef struct {
    line_sender_qwpws_close_status status;
    bool has_published_fsn;
    uint64_t published_fsn;
    bool has_server_acked_fsn;
    uint64_t server_acked_fsn;
    bool has_completed_fsn;
    uint64_t completed_fsn;
} line_sender_qwpws_close_result;

bool line_sender_qwpws_open(
        const line_sender_qwpws_options *opts,
        line_sender_qwpws_sender **sender_out,
        line_sender_error **err_out);

line_sender_buffer *line_sender_qwpws_new_buffer(
        const line_sender_qwpws_sender *sender,
        line_sender_error **err_out);

bool line_sender_qwpws_submit(
        line_sender_qwpws_sender *sender,
        line_sender_buffer *buffer,
        line_sender_qwpws_submit_result *result_out,
        line_sender_error **err_out);

bool line_sender_qwpws_submit_and_keep(
        line_sender_qwpws_sender *sender,
        const line_sender_buffer *buffer,
        line_sender_qwpws_submit_result *result_out,
        line_sender_error **err_out);

bool line_sender_qwpws_wait(
        line_sender_qwpws_sender *sender,
        line_sender_qwpws_receipt receipt,
        int64_t timeout_micros,
        line_sender_qwpws_wait_result *result_out,
        char *message_buf,
        size_t message_buf_len,
        size_t *message_len_out,
        line_sender_error **err_out);

bool line_sender_qwpws_drive_once(
        line_sender_qwpws_sender *sender,
        int64_t timeout_micros,
        line_sender_qwpws_drive_outcome *outcome_out,
        line_sender_error **err_out);

bool line_sender_qwpws_poll_event(
        line_sender_qwpws_sender *sender,
        line_sender_qwpws_event *event_out,
        char *message_buf,
        size_t message_buf_len,
        size_t *message_len_out,
        line_sender_error **err_out);

bool line_sender_qwpws_receipt_status(
        const line_sender_qwpws_sender *sender,
        line_sender_qwpws_receipt receipt,
        line_sender_qwpws_receipt_status *status_out,
        line_sender_error **err_out);

bool line_sender_qwpws_close_drain(
        line_sender_qwpws_sender *sender,
        int64_t timeout_micros,
        line_sender_qwpws_close_result *result_out,
        line_sender_error **err_out);

void line_sender_qwpws_close_fast(line_sender_qwpws_sender *sender);
void line_sender_qwpws_free(line_sender_qwpws_sender *sender);
```

`line_sender_qwpws_new_buffer()` is the sender-specific constructor. Reusing the
existing `line_sender_buffer_new_qwp()` is also acceptable in examples where the
maximum name length does not depend on sender configuration.

Server messages for poisoned, terminal, or other diagnostic states are copied
into caller-provided storage by `wait()` and `poll_event()`. `message_len_out`,
when non-NULL, receives the full message length before truncation. If
`message_buf` is too small, the returned event or wait result sets
`message_truncated=true`. `message_buf` may be NULL only when
`message_buf_len == 0`.

`drive_once()` is progress-only. It may produce events internally, but
`poll_event()` is the only event consumer.

Threaded adapter ownership conversion consumes the manual handle on success:

```c
bool line_sender_qwpws_threaded_start(
        line_sender_qwpws_sender **sender,
        line_sender_qwpws_threaded **threaded_out,
        line_sender_error **err_out);

void line_sender_qwpws_threaded_stop(
        line_sender_qwpws_threaded *threaded);
```

On success, `*sender` is set to `NULL`. On failure, `*sender` remains unchanged.

Example:

```c
line_sender_qwpws_sender *sender = NULL;
line_sender_error *err = NULL;

if (!line_sender_qwpws_open(&opts, &sender, &err)) {
    handle_error(err);
}

line_sender_buffer *buffer = line_sender_qwpws_new_buffer(sender, &err);
line_sender_buffer_table(buffer, "trades", &err);
line_sender_buffer_symbol(buffer, "sym", "ETH-USD", &err);
line_sender_buffer_column_f64(buffer, "price", 3421.50, &err);
line_sender_buffer_at_now(buffer, &err);

line_sender_qwpws_submit_result submit = {0};
if (!line_sender_qwpws_submit(sender, buffer, &submit, &err)) {
    handle_error(err);
}

line_sender_qwpws_wait_result wait = {0};
char message[1024];
size_t message_len = 0;
if (!line_sender_qwpws_wait(
        sender, submit.receipt, 5 * 1000 * 1000,
        &wait, message, sizeof(message), &message_len, &err)) {
    handle_error(err);
}

if (wait.status == LINE_SENDER_QWPWS_WAIT_TIMEOUT) {
    /* Receipt is still valid. Poll later or close_drain. */
}
```

Convenience rule: `result_out` should be required for `submit()` because the
receipt is the handle to delivery state. If later wrappers need fire-and-forget
publication, add a separate convenience call rather than making receipt
semantics optional in the core ABI.

## C++ RAII wrapper

The C++ wrapper should preserve the same split between local publication and
server delivery.

```cpp
questdb::ingress::qwpws_sender sender =
    questdb::ingress::qwpws_sender::from_conf(
        "qwpws::addr=localhost:9000;queue_mode=sf;sf_dir=/var/lib/app/qdb-sf;");

questdb::ingress::line_sender_buffer buffer =
    questdb::ingress::line_sender_buffer::qwp();

buffer.table("trades")
      .symbol("sym", "ETH-USD")
      .column("price", 3421.50)
      .at_now();

questdb::ingress::qwpws_receipt receipt = sender.submit(buffer);

questdb::ingress::qwpws_delivery_outcome outcome =
    sender.wait(receipt, std::chrono::seconds{5});

if (outcome.is_timeout()) {
    // Normal delivery state, not an exception.
}

sender.close_drain(std::chrono::seconds{5});
```

Exceptions map to API failures. Timeouts, poison, and not-drained close results
are value outcomes.

Threaded ownership is also type-level:

```cpp
auto manual = questdb::ingress::qwpws_sender::from_conf(conf);
auto threaded = questdb::ingress::qwpws_threaded_sender::start(std::move(manual));
```

After `std::move(manual)`, the original object has no usable sender core.

## Python blocking wrapper

Python should expose the receipt split directly. A convenience method can wait
for ACK, but it should not be named as if it only publishes locally.

```python
from datetime import timedelta
from questdb.ingress import QwpWsSender

sender = QwpWsSender.from_conf(
    "qwpws::addr=localhost:9000;queue_mode=sf;sf_dir=/var/lib/app/qdb-sf;"
)

buf = sender.new_buffer()
buf.table("trades").symbol("sym", "ETH-USD").column("price", 3421.50).at_now()

receipt = sender.submit(buf)
outcome = sender.wait(receipt, timeout=timedelta(seconds=5))

if outcome.timeout:
    print("published locally, not ACKed yet")

sender.close_drain(timeout=timedelta(seconds=5))
```

Blocking convenience can be explicit:

```python
receipt, outcome = sender.submit_and_wait(buf, timeout=timedelta(seconds=5))
```

`submit_and_wait()` is wrapper sugar for `submit()` followed by `wait()`. It
still returns the receipt so applications can inspect or log the frame sequence
number when the wait times out. After a timeout, the receipt remains valid for
later `wait()` and `receipt_status()` calls.

## Python asyncio wrapper

The asyncio wrapper is adapter-level. It should not imply that the C ABI
contains futures or event-loop concepts.

```python
from datetime import timedelta
from questdb.ingress.aio import QwpWsSender

async with await QwpWsSender.from_conf(conf) as sender:
    buf = sender.new_buffer()
    buf.table("events").symbol("kind", "click").column("user", 7).at_now()

    receipt = await sender.submit(buf)
    outcome = await sender.wait(receipt, timeout=timedelta(seconds=5))

    if outcome.acked:
        pass
```

If implemented over the C ABI, the asyncio wrapper can use an explicit
background runner or executor internally. That is Python wrapper policy, not a
change to the core delivery contract.

## Answers to Step 1 questions

- Primary verb: `submit()`.
- Default call returns after local acceptance only: yes.
- Receipt-returning call: `submit()` always returns `QwpReceipt` when it
  publishes a non-empty frame. `submit_and_keep()` also returns a receipt.
- Operations that block: `open()` may block according to `open_mode` and
  connection timeouts; `submit()` may block for local queue capacity up to the
  append timeout; `wait()` and `close_drain()` drive progress until their
  timeout; `drive_once()` performs bounded progress once.
- Operations that poll: `receipt_status()` and `poll_event()` are non-blocking.
- Operations that drive progress: manual `drive_once()`, `wait()`,
  `close_drain()`, and possibly `submit()` when waiting for local capacity.
  Threaded and Tokio adapters delegate progress to their explicit driver.
- Timeout surfacing: local publication timeout is an API error because no
  receipt exists; delivery timeout is a `QwpDeliveryOutcome::Timeout`; close
  timeout is a `QwpCloseOutcome::Timeout`.
- Adapter ownership conversion: adapters consume `QwpWsSender`; C models this
  with `line_sender_qwpws_sender **sender` and sets `*sender = NULL` on success.
- C expressiveness: C uses distinct result structs for submit, wait, event, and
  close outcomes. Non-error states do not go through `err_out`.
- Diagnostic message text is carried through caller-provided buffers for event
  polling and wait outcomes, so bounded server messages remain observable
  without allocation on the success path.

## Compatibility notes

Existing `Sender::flush()` should remain unchanged while this API is being
validated. The new QWP/WebSocket pipelined API should start as separate Rust
types and separate C entry points so its receipt and Store-and-Forward
semantics are not diluted by older transport behavior.

Once the new API is validated, compatibility wrappers can be considered:

- `flush_submit()` or `flush_local()` as local-publication sugar.
- `flush_and_wait()` as publish-then-wait sugar.
- Existing `line_sender_flush()` integration only if documentation can explain
  the transport-specific semantics without hiding delivery state.

Do not add a `flush()` alias to the low-level core during the first prototype.

## Local reflection

- Does this API feel simpler than the current Sender + Buffer shape?

  It feels more explicit rather than shorter. The important improvement is that
  caller-visible names now separate local publication from server delivery. The
  extra receipt value is the unavoidable cost of making pipelining observable.

- What looks awkward in the examples?

  C has several result structs and the names are long. That is still preferable
  to collapsing timeout, poison, terminal, pending, and API failure into one
  boolean plus `err_out`. Python and C++ can hide the naming weight without
  losing the semantics.

## Global reflection

- Does this preserve Buffer/Sender segregation, explicit progress ownership,
  runtime-neutral FFI, and observable delivery?

  Yes. `Buffer` remains caller-owned and reusable after successful `submit()`.
  Manual, threaded, and Tokio modes are represented by ownership conversion.
  Tokio is not visible through C. Delivery is observable through receipts,
  status polling, wait outcomes, close outcomes, and events.

- Should the design proceed to a type-only progress ownership prototype?

  Yes, with one constraint: keep the prototype type-only. Do not add transport,
  queue, encoder, or thread implementation before the ownership conversion
  rules compile cleanly in Rust and are expressible in C.
