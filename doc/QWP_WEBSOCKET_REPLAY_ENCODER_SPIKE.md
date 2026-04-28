# QWP/WebSocket Step 3 self-sufficient frame spike

Date: 2026-04-28

Status: validation note for Step 3 of `doc/QWP_WEBSOCKET_VALIDATION_PLAN.md`.

## Prototype scope

Implemented an encoder-only spike for Java-style self-sufficient
QWP/WebSocket replay payloads.

The spike adds a replay encoder path that:

- stores QWP application payload bytes only,
- keeps WebSocket framing and masking out of the payload identity,
- emits `FLAG_DELTA_SYMBOL_DICT`,
- emits `delta_start = 0`,
- emits the dense global symbol dictionary prefix from id `0` through the
  highest symbol id referenced by the frame,
- emits full schema mode for every table block,
- never emits schema-reference table blocks.

The existing QWP/WebSocket sync and async senders still use the current
connection-delta encoder path. No transport, queue, receipt, disk, or
Store-and-Forward implementation was added in this step.

## Validation checks

- A later replay frame re-emits an already-known symbol instead of using an
  empty delta.
- A replay frame that references global symbol id `2` emits dictionary entries
  `0`, `1`, and `2`.
- Replay encoding always emits full schema mode even when the existing delta
  encoder would emit schema-reference mode.
- A follow-up Java/Rust golden test now compares exact unmasked replay payload
  bytes for the core dense replay case; see
  `doc/QWP_WEBSOCKET_JAVA_RUST_GOLDEN_PAYLOADS.md`.
- Existing QWP/WebSocket tests still pass, including tests that assert the old
  connection-delta encoder emits empty symbol deltas and schema references.

## Local reflection

- How does this particular step feel?

  The encoder change is localized. The existing WebSocket encoder already had a
  clean symbol pre-pass and table writer, so the replay path could reuse most
  row and column payload logic.

- What was simpler or more awkward than expected?

  Preserving ordered global symbols was the main missing piece. The previous
  dictionary only needed `bytes -> id`; replay needs `id -> bytes` as well.

- Did the API or implementation shape create accidental complexity?

  Not much. The largest duplication is between the normal WebSocket encoder and
  replay encoder table loops. That is acceptable for the spike; before
  productionizing, we should consider a small shared helper without hiding the
  important semantic differences.

## Global reflection

- How does this fit into the bigger QWP/WebSocket Store-and-Forward design?

  It validates the core payload shape needed before volatile queues or disk
  Store-and-Forward can safely store caller-independent frames.

- Did this step strengthen or weaken the core assumptions?

  It strengthens the self-sufficient-frame assumption at the byte-shape level.
  It did not initially prove real-server acceptance or Java parity; those
  follow-up gates now have focused notes in
  `doc/QWP_WEBSOCKET_SELF_SUFFICIENT_REPLAY_PROBE.md` and
  `doc/QWP_WEBSOCKET_JAVA_RUST_GOLDEN_PAYLOADS.md`.

- Should the next step proceed, or should the design be adjusted first?

  Proceed to the real-server self-sufficient replay probe before building queue
  mechanics around this assumption.
