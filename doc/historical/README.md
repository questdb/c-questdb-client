# Historical QWP ingress design records

The documents in this directory describe the unreleased sender architecture
that existed before the unified QWP ingress sender cutover. Names such as
`BorrowedRowSender`, `BorrowedColumnSender`, pooled `row_sender_*` functions,
and `-row-N` / `-col-N` managed slots are historical only; they are not aliases
for, or supported entry points into, the current API.

The current model has one `QuestDb::borrow_sender()` pool and one `-ingest-N`
slot namespace. A borrowed sender accepts row-built `Buffer`, columnar `Chunk`,
and Arrow payloads through the same publication, symbol-dictionary, recovery,
and ACK machinery. See:

- [`QWP_UNIFIED_SENDER_DESIGN.md`](../QWP_UNIFIED_SENDER_DESIGN.md) for the
  implemented architecture and its resolved decisions;
- [`QWP_UNIFIED_SENDER_M0_BASELINE.md`](../QWP_UNIFIED_SENDER_M0_BASELINE.md)
  for the frozen and post-cutover performance evidence;
- [`QWP_SOAK_HARNESS.md`](../QWP_SOAK_HARNESS.md) for current mixed-payload
  recovery and resource-boundedness testing;
- `include/questdb/ingress/column_sender.h` and `.hpp` for the live C and C++
  interfaces.

These records remain checked in only to preserve design and migration history.
They are not normative documentation.
