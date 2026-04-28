# QWP/WebSocket Step 2 progress ownership prototype

Date: 2026-04-28

Status: validation note for Step 2 of `doc/QWP_WEBSOCKET_VALIDATION_PLAN.md`.

## Prototype scope

Implemented a type-only progress ownership prototype:

- Rust manual core: `QwpWsSender`
- Rust threaded adapter: `QwpWsThreadedSender::start(sender)`
- Rust async adapter placeholder: `QwpWsAsyncSender::from_sender(sender)`
- C handles: `line_sender_qwpws` and `line_sender_qwpws_threaded`
- C ownership conversion: `line_sender_qwpws_threaded_start(&sender, &threaded, &err)`

The prototype intentionally has no transport, queue, encoder, thread, receipt,
or event implementation.

## Validation checks

- Rust adapters consume `QwpWsSender` by value.
- Manual progress placeholder uses `&mut self`.
- Threaded stop does not return a manual sender.
- C `threaded_start` sets `*sender = NULL` on success.
- C `threaded_start` leaves `*sender` unchanged when precondition checks fail.
- C null pointer preconditions are explicit and tested.

## Local reflection

- How does this particular step feel?

  The type split is straightforward. Rust's move semantics make the core rule
  easy to express for manual, threaded, and async ownership.

- What was simpler or more awkward than expected?

  Rust was simpler than C. The C ABI needs an explicit pointer-to-pointer
  ownership handoff plus null checks to express the same rule.

- Did the API or implementation shape create accidental complexity?

  Not yet. The only awkwardness is that real threaded start can fail in future
  implementations. The final implementation must preserve the C contract:
  failed start leaves the manual handle unchanged, successful start consumes it.

## Global reflection

- How does this fit into the bigger QWP/WebSocket Store-and-Forward design?

  It strengthens the "one progress owner" assumption before any queue or
  transport code can accidentally introduce shared mutable progress state.

- Did this step strengthen or weaken the core assumptions?

  It strengthened them. No manual API needs a runtime "runner active" flag in
  this shape.

- Should the next step proceed, or should the design be adjusted first?

  Proceed to the self-sufficient QWP frame spike. Keep that spike encoder-only:
  no volatile queue, disk Store-and-Forward, or real WebSocket transport yet.
