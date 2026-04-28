# QWP/WebSocket Step 5 volatile queue prototype

Date: 2026-04-28

Status: validation note for Step 5 of
`doc/QWP_WEBSOCKET_VALIDATION_PLAN.md`.

## Prototype scope

Implemented a transport-free volatile queue prototype in:

```text
questdb-rs/src/ingress/sender/qwp_ws_queue.rs
```

The prototype covers:

- value receipts with monotonically increasing FSNs starting at `0`
- receipt status derived from queue state
- bounded in-memory frame slots
- byte-capacity backpressure
- fixed-capacity in-flight ring
- zero-based per-connection wire sequence numbers
- cumulative ACK mapping through `fsn_at_zero + wire_seq`
- reconnect remapping from the oldest unresolved FSN

The prototype intentionally does not cover real WebSocket I/O, disk
Store-and-Forward, FFI, event rings, close semantics, threaded adapters, Tokio,
or poison policy.

Frames are opaque payload bytes in this step. The self-sufficient replay
encoder and Java/Rust payload fixture are validated separately.

## Validation checks

Rust unit tests cover:

- invalid capacity options are rejected
- submit returns value receipts and published status
- empty payload submit is rejected without consuming an FSN
- sending an empty queue returns `NoUnsentFrame`
- failed submit attempts do not consume an FSN
- frame-capacity and byte-capacity backpressure are deterministic
- sending assigns zero-based wire sequences in FSN order
- `max_in_flight` limits sent-but-unresolved frames, not submission
- cumulative ACK completes all covered receipts and frees slots
- later frames do not jump earlier unresolved frames
- ACK beyond the last sent wire sequence is a protocol error
- stale ACKs for already completed receipts are ignored
- ACKs that cover locally published but unsent frames are protocol errors
- reject without a connection and reject beyond the last sent frame are protocol
  errors
- reject of an already completed frame or a locally published but unsent frame is
  a protocol error
- ordered rejection can poison one receipt while ACKing prior frames only
- a poison gap at the first frame prevents `server_acked_fsn` from advancing
- later ACK after ordered rejection completes later receipts without advancing
  `server_acked_fsn` across the poison gap
- receipt status distinguishes future unknown receipts from completed receipts
- reconnect resets wire sequence and replays from the oldest unresolved FSN

Targeted validation command:

```bash
cargo test --manifest-path questdb-rs/Cargo.toml qwp_ws_queue
```

Result: 26 passed.

## Local reflection

- How does this particular step feel?

  The receipt model feels natural when FSNs are plain values and queue state is
  ordered. The internal API is small enough that status polling, send
  backpressure, and cumulative ACKs are understandable without involving real
  transport yet.

- What was simpler or more awkward than expected?

  Cumulative ACK handling was simpler once wire sequence was treated as
  connection-local and mapped through `fsn_at_zero`. The awkward part is that
  `published_fsn`, `server_acked_fsn`, and `completed_fsn` need optional
  sentinels internally; forcing `0` as an empty-state sentinel would blur the
  first real FSN.

- Did the API or implementation shape create accidental complexity?

  Not much, but the queue already shows that submission capacity and
  in-flight capacity are different concepts. Keeping them separate avoids a
  misleading "queue full" result when only send progress is backpressured.

## Global reflection

- How does this fit into the bigger QWP/WebSocket Store-and-Forward design?

  It validates the core Store-and-Forward bookkeeping without durability noise:
  value receipts, bounded local publication, ordered replay, and cumulative
  server ACKs can be modeled with fixed rings.

- Did this step strengthen or weaken the core assumptions?

  It strengthened them. The Java/Rust replay payload work and real-server probe
  validated what bytes can be stored; this step validates how stored frames can
  be tracked and completed.

- Should the next step proceed, or should the design be adjusted first?

  Proceed to Step 6, but keep it fake-server based. The next useful pressure is
  a manual driver loop with `drive_once`, `wait`, response coalescing,
  disconnects, retryable transport failures, and deterministic frame rejection.
