# QWP/WebSocket Step 8 Store-and-Forward queue prototype

Date: 2026-04-28

Status: validation note for Step 8 of
`doc/QWP_WEBSOCKET_VALIDATION_PLAN.md`.

## Prototype scope

Implemented a minimal file-backed SF queue prototype in:

```text
questdb-rs/src/ingress/sender/qwp_ws_sf_queue.rs
```

The prototype is intentionally transport-free. It validates disk recovery under
the same receipt and replay model as the volatile queue, but it does not add
public API, FFI, real WebSocket I/O, segment rotation, compaction, checksums, or
fsync durability modes.

The journal is append-only and length-prefixed. It stores:

- frame publication records: FSN plus self-sufficient QWP payload bytes
- ACK-through completion records
- poison completion records

The journal deliberately does not store connection-local state:

- `Sent` receipt status
- WebSocket wire sequence
- in-flight ring contents
- mask keys or WebSocket frame bytes

After recovery, every unresolved frame is `Published`, replay starts from the
oldest unresolved FSN, and the next wire connection starts at sequence `0`.

Completion is logical in this prototype. ACKed frames are marked by completion
records and omitted from recovered unresolved state. Physical truncation or
segment compaction remains future work.

Coverage is deliberately focused on observable queue and recovery behaviour.
The tests use the real file-backed queue and on-disk journal bytes; they do not
add a fake SF driver or mock transport layer.

## Validation checks

Rust unit tests cover:

- local publication behaviour: invalid capacity rejection, failed submission
  attempts preserving FSN allocation, payload ownership after submit, and frame
  capacity becoming available only after ACK completion
- volatile connection behaviour: `Sent` state and in-flight slots are not
  durable, send backpressure is separate from submit backpressure, and replay
  after restart starts from the oldest unresolved FSN with wire sequence `0`
- delivery semantics: ACK markers survive restart, stale ACKs for already
  completed receipts are idempotent, protocol responses before a connection or
  beyond the sent window are rejected, and stale rejects for completed frames are
  rejected
- poison-gap semantics: first-frame and later-frame poison gaps survive restart,
  later ACKs after poison advance `completed_fsn` without crossing
  `server_acked_fsn` over the poison gap, and completed poison-gap state
  survives a second restart
- journal recovery: incomplete trailing records are ignored as an uncommitted
  tail, incomplete tails are truncated before appending new records, malformed
  headers and record shapes are rejected, completion records cannot reference
  unpublished frames, frame records must remain contiguous and within capacity,
  and duplicate or already-completed poison markers are rejected

Targeted validation commands:

```bash
cargo fmt --check --manifest-path questdb-rs/Cargo.toml
cargo test --manifest-path questdb-rs/Cargo.toml qwp_ws_sf_queue
cargo test --manifest-path questdb-rs/Cargo.toml qwp_ws
cargo +nightly llvm-cov test --manifest-path questdb-rs/Cargo.toml --branch --lib qwp_ws_sf_queue
```

Result:

- SF queue: 24 passed
- widened QWP filter: 87 passed, 2 ignored
- branch coverage for `qwp_ws_sf_queue.rs`: 87.50% branches, 97.09% lines

## Local reflection

- How does this particular step feel?

  The disk layer is small and mechanical when it persists only durable facts:
  local publication and receipt completion. Treating `Sent` as non-durable keeps
  recovery simple and matches the existing reconnect model.

- What was simpler or more awkward than expected?

  Recovery is simpler than expected once unresolved frames are just a replay
  cursor. The awkward part is preserving the poison-gap distinction between
  `completed_fsn` and `server_acked_fsn`; a single durable "acked through"
  counter would lose information after `OK(0), Error(1), OK(2)`.

- Did the API or implementation shape create accidental complexity?

  Not at the public API level. Internally, disk I/O introduces a separate error
  class from queue-capacity and protocol errors, so the eventual public mapping
  should avoid forcing storage failures into delivery outcomes.

## Global reflection

- How does this fit into the bigger QWP/WebSocket Store-and-Forward design?

  It validates the core SF promise: after local publication, process restart
  does not lose unresolved frames, and replay ordering remains the same as the
  volatile queue. The durable identity is the QWP payload plus FSN, not a
  WebSocket frame.

- Did this step strengthen or weaken the core assumptions?

  It strengthened them. Disk durability did not require changing receipt values,
  replay ordering, ACK handling, or poison-gap semantics. The main design
  boundary held: connection state is rebuilt, not recovered.

- Should the next step proceed, or should the design be adjusted first?

  Proceed to Step 9, but the next implementation slice should probably factor a
  small queue trait or driver seam before adding more policy tests. Duplicating
  fake-driver logic for volatile and SF modes is acceptable for this spike, but
  it should not become the production structure.
