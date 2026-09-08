# QWP egress and ADBC: what we hit, what we changed, what we still want

Date: 2026-09-08
Repos: `questdb/c-questdb-client` (branch `design/egress-owned-handles`, 19 commits, unpushed),
`adbc-drivers/questdb` (branch `design/v0-rust-driver`, unpushed)

## 1. The problem

`questdb-rs`' QWP egress API is a borrow chain. Each link holds a reference into the one before it:

```rust
pub struct ReaderQuery<'r> { reader: &'r mut Reader, .. }
pub struct Cursor<'r>      { reader: &'r mut Reader, .. }
pub struct BatchView<'c>   { decoded: &'c DecodedBatch, dict: &'c SymbolDict, schema: &'c Schema }
```

That shape is correct. It encodes a real protocol constraint — one in-flight query per connection — and it is pleasant for a scoped caller: `let mut cur = reader.execute(sql)?;` then loop, and the reader is free again.

It is hostile to anyone who needs to **own** a result stream. They must hold the reader and the cursor that borrows it in one value: a self-referential struct, which safe Rust cannot express.

## 2. Why this bites ADBC specifically

Two structural facts, neither negotiable from the driver side:

- **`Statement::execute` must return `Box<dyn RecordBatchReader + Send + 'static>`.** Owned, no lifetime. There is nowhere to put one.
- **`adbc_core::Connection` declares `type StatementType: Statement` with no lifetime parameter.** An associated type cannot borrow from `self`, so a statement cannot hold `&mut Reader` from its connection even in principle.

So the driver has to own both halves, and hand-roll the laundering.

**The existing C ABI is not a shortcut.** `questdb-rs-ffi` had already solved this — with 4 `transmute` call sites laundering 3 handles (`ReaderQuery<'static>`, `Cursor<'static>`, `BatchView<'static>`) in `ManuallyDrop` with hand-maintained drop ordering. But routing a *Rust* ADBC driver through the C ABI would mean Rust → C → Rust, giving up Arrow zero-copy at the boundary, and inheriting C-specific semantics (its Arrow drift contract is deliberately weaker than `RecordBatchReader`'s). So the driver re-derived the trick.

**How hard is it, really?** Two independent competent in-house attempts got it wrong. The ADBC driver's version cost 611 lines, 11 `unsafe` blocks and 5 documented safety invariants, and contained **two separate undefined-behaviour bugs** — neither of which any test could catch:

1. Deriving `&mut Reader` from a `Box<OwnedReader>` and then *moving* the box re-asserts the box's `Unique`/`noalias` guarantee, invalidating the derived reference.
2. After fixing that with raw-pointer ownership, the struct was still a by-value Rust value *containing* a live `&mut Reader`. Passing it by value protects that reference for the whole callee; dropping it inside that call then runs `Box::from_raw` over protected memory. `drop(stream)` and `.map(..).sum()` both trigger it.

Both were found only by building a structural model and running it under Miri with Stacked Borrows *and* Tree Borrows. **A trap that two attempts fell into is a property of the API, not of its callers.** That is the finding this work acts on.

## 3. What we changed

All in `questdb-rs`, purely additive — no existing public item changed shape, mechanically verified (the `reader.rs` public-declaration set is byte-identical to `main`).

| | Before | After |
|---|---|---|
| `Cursor<'r>` | connection borrow + 18 per-query fields | thin forwarder over a lifetime-free `CursorState` |
| Owning handles | none | `OwnedQuery<O>`, `OwnedCursor<O>`, `OwnedArrowReader<O>`, generic over the owner |
| Batch access | `BatchView<'c>`, borrowing reader *and* cursor | accessors on the owning cursor, `&self` only |
| `OwnedReader` | `#[doc(hidden)]`, semver-exempt | public, via `QuestDb::take_reader()` |
| C ABI laundering | 4 `transmute` sites, 3 laundered handles | **0** |

The key move was separating per-query state from the connection: all protocol logic lives in one `CursorState` taking `&mut Reader` as a parameter, so both cursor types share a single implementation. Failover, drift and terminal handling are not duplicated.

**The guarantee is mechanical, not a claim.** `questdb-rs/examples/owned_egress_no_unsafe.rs` consumes the API under `#![forbid(unsafe_code)]` in the four shapes that were UB above — dropped by value, consumed by a by-value adaptor, moved across a thread, boxed as `dyn`. CI already builds it on every PR. If it compiles, the property holds, because the compiler proved it.

**Two things worth recording honestly:**

- **The API as designed was not sufficient.** Migrating the C ABI surfaced five gaps that had to be closed first — most importantly that `OwnedCursor` could not install failover hooks at all, so an owning consumer could not fail over after a batch had been delivered. Also ~25 typed bind forwarders: `bind_uuid` reverses bytes into wire order, so reaching for `Bind::Uuid` directly would have compiled and silently transmitted a swapped UUID.
- **Raw `unsafe` count went up, not down.** In the FFI, `unsafe {` went 124 → 132 — named helpers replacing open-coded raw-pointer sites. The win is the elimination of the *unsound-capable* subset: the lifetime laundering and the self-referential drop ordering. The residual is irreducible `*mut T → &T` at the C boundary.

## 4. The API we want

For ADBC the happy path is now four calls, and all of it exists today:

```rust
let db     = QuestDb::connect(conf)?;                       // ADBC Database
let reader = db.take_reader()?;                             // ADBC Connection
let cursor = reader.query(sql).bind(v).try_execute()?;      // ADBC Statement
let stream: Box<dyn RecordBatchReader + Send> =
    Box::new(cursor.into_arrow_reader()?);                  // Statement::execute
```

That deletes the driver's 611-line module outright. What follows is what a driver
still cannot do, split by whether it is *impossible* or merely awkward.

### Blockers — ADBC features that cannot be implemented at all today

**B1. Query cancellation.** `AdbcStatementCancel` may be called from another thread
*while execution is in progress*. `cancel(&mut self)` needs exclusive access on both
paths, and `into_arrow_reader` consumes the cursor, so once a stream is handed to the
caller there is no handle left to cancel through. Our driver reports `NotImplemented`,
and no driver-side work changes that. **Ask:** `cursor.cancel_handle() -> CancelHandle`,
`Send + Sync`, surviving the wrap, safe to fire concurrently with a read.

**B2. `execute_schema` — the result schema without running the query.**
`RecordBatchReader::schema()` must work before iteration, so `into_arrow_reader` blocks
until the first batch arrives. That makes `execute()` latency data-dependent, and makes
ADBC's schema-only call impossible. **Ask:** deliver the result schema ahead of the
first batch.

**B3. Prepared statements and `get_parameter_schema`.** QWP has no prepare message —
`Reader::prepare` is a client-side builder that encodes a `QUERY_REQUEST`. So
`statement_prepare` has no server-side meaning, and there is no way to ask what types
the parameters are. Both are permanently off in the driver's capability flags.
**Ask:** a protocol-level prepare, or an explicit statement that this is out of scope
so drivers stop treating it as pending.

**B4. Multi-row bind.** ADBC binds a whole `RecordBatch` — N parameter *sets* — and
executes once per set. QWP binds a single set per query. The driver rejects multi-row
batches explicitly rather than silently using row 0, and the validation suite's
`test_parameter_execute` is xfailed as a genuine capability boundary. **Ask:** multiple
bind sets per request, or batched submission.

**B5. Bulk ingest needs a public `OwnedSender`.** The write path has the same ownership
problem the read path just fixed: `OwnedSender` exists but is exported **only** through
`ffi_support`, which is `#[doc(hidden)]` and semver-exempt. `OwnedReader` was promoted
in this branch; `OwnedSender` was not. ADBC's `statement_bulk_ingest` will hit this the
moment we start it. **Ask:** promote `OwnedSender` symmetrically.

### Frictions — implementable, but they cost the driver something

**F1. Rows affected requires draining.** `execute_update` wants a count; today that
means submit, drain every batch, then read `Terminal::ExecDone { rows_affected }` —
decoding batches nobody wants.

**F2. `into_arrow_reader` is a one-way door.** The returned reader exposes only
`schema()`. An `into_cursor()` / `get_ref()` would let a driver reach `terminal()`,
`connection_reusable()` and `into_owner()` after wrapping — all needed for error
reporting and connection reuse.

**F3. `execute()` consumes the owner on failure,** dropping the connection even for an
error that never reached the wire. `try_execute` is the escape, but the fluent default
is the footgun.

**F4. No documented `ErrorCode` → meaning contract.** Drivers map these onto ADBC
statuses and consumers branch on them. We got two wrong on the first pass
(`RoleMismatch` and `ProtocolError` fell into a catch-all despite being connect-time
reachable). A table of which codes are transient, which are caller error and which are
protocol faults would remove the guesswork.

**F5. The concurrency ceiling is low and fails slowly.** Each in-flight, undrained
result stream holds one pooled reader; `query_pool_max` defaults to **4**, and the
fifth stalls for `acquire_timeout_ms` (default **5000 ms**) before erroring. ADBC
consumers routinely hold several result sets open — a notebook with four open queries
is not exotic. The default and the slow failure mode are both worth revisiting.

**F6. Polars has no owning path** — `next_polars`/`iter_polars`/`fetch_all_polars` are
borrowing-only, and the public substitute interns symbols into a process-global rather
than the per-cursor registry. Not needed for ADBC; flagged because it is the one corner
where a consumer would still be pushed back toward a self-referential struct.

## 5. Recommendation

F2, F3 and F4 are small and worth folding in before this lands. B5 is mechanical —
the same promotion `OwnedReader` just had.

B1 is the one that needs a design decision rather than plumbing, and it is worth making
early: it is the difference between an ADBC driver that supports query cancellation and
one that never can. B2 is next, because it decides whether `execute()` can ever be
non-blocking.

B3 and B4 are protocol questions, not API questions. Both are currently recorded in the
driver as permanent limitations; if either is actually on the roadmap, we should say so,
because the capability flags we ship are a public claim about what QuestDB can do.

Everything else in the branch is verified — `questdb-rs` 2111 tests pass, the FFI 120, the C++ suite 106 cases, the C ABI is byte-identical by symbol and signature diff, and the one regression the migration introduced (an Arrow cursor that wedged permanently after schema drift) was caught by a purpose-built baseline-vs-HEAD probe, fixed, and pinned.

Nothing is pushed and no PR exists in either repository.
