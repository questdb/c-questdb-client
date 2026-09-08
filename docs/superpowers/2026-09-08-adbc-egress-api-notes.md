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

That deletes the driver's 611-line module outright. What remains is a ranked list of gaps, from a driver's point of view.

**1. A detachable cancel handle — the one real blocker.**
ADBC's `AdbcStatementCancel` may be called from another thread *while execution is in progress*. Today `cancel(&mut self)` needs exclusive access on both paths, and `into_arrow_reader` consumes the cursor, so once a stream is handed to the caller there is no handle left to cancel through. Our driver reports `NotImplemented` for cancel, and no amount of driver-side work fixes that. The ask: something like `cursor.cancel_handle() -> CancelHandle` that is `Send + Sync`, survives the wrap, and is safe to fire concurrently with a read.

**2. Schema without the first batch.**
`RecordBatchReader::schema()` must work before iteration, so `into_arrow_reader` blocks until the first batch arrives — making `execute()` latency data-dependent. It also means ADBC's `execute_schema` (schema without running the query) cannot be implemented at all. If QWP can deliver the result schema ahead of the first batch, both problems go away.

**3. Rows affected without draining.**
ADBC's `execute_update` wants a row count. Today: submit, drain every batch, then read `Terminal::ExecDone { rows_affected }`. A direct path would be cleaner and avoids decoding batches nobody wants.

**4. Reversibility.** `into_arrow_reader` is a one-way door: the returned reader exposes only `schema()`. An `into_cursor()` / `get_ref()` would let a driver reach `terminal()`, `connection_reusable()` and `into_owner()` after wrapping — all of which ADBC needs for error reporting and connection reuse.

**5. `try_execute` as the default.** `execute()` consumes the owner, so a failed submit drops the connection even for an error that never reached the wire. `try_execute` is the escape, but the fluent default is the footgun.

**6. A documented `ErrorCode` → meaning contract.** The driver maps `questdb::ErrorCode` onto ADBC statuses, and consumers branch on those. We got two wrong on the first pass (`RoleMismatch`, `ProtocolError` fell into a catch-all despite being connect-time reachable). A table saying which codes are transient, which are caller error, and which are protocol faults would remove the guesswork.

**7. Polars has no owning path at all.** `next_polars`/`iter_polars`/`fetch_all_polars` are borrowing-only, and the public substitute interns symbols into a process-global rather than the per-cursor registry. Not needed for ADBC — flagging it because it is the one corner where a consumer would still be pushed back toward a self-referential struct.

## 5. Recommendation

Items 4–6 are small and I would fold them in before this lands. Item 1 is the one that needs a design decision rather than plumbing, and it is worth making early: it is the difference between an ADBC driver that supports query cancellation and one that never can.

Everything else in the branch is verified — `questdb-rs` 2111 tests pass, the FFI 120, the C++ suite 106 cases, the C ABI is byte-identical by symbol and signature diff, and the one regression the migration introduced (an Arrow cursor that wedged permanently after schema drift) was caught by a purpose-built baseline-vs-HEAD probe, fixed, and pinned.

Nothing is pushed and no PR exists in either repository.
