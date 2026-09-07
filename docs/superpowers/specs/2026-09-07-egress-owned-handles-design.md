# Owning handles for the QWP egress API

Date: 2026-09-07
Status: approved, not yet implemented
Target: `questdb/c-questdb-client`, branch off `main` @ `621a6baf`
Branch: `design/egress-owned-handles`

## 1. Goal

**No binding should have to hand-roll `unsafe` to own a QWP result stream.**

That is the whole objective. Everything below is in service of it, and anything
that does not serve it is out of scope.

## 2. The problem, with evidence

`questdb-rs`' egress API is a borrow chain: **Reader → Query → Cursor →
BatchView**, where each link holds a reference into the previous one.

```rust
pub struct ReaderQuery<'r> { reader: &'r mut Reader, .. }
pub struct Cursor<'r>      { reader: &'r mut Reader, .. }
pub struct BatchView<'c>   { decoded: &'c DecodedBatch, dict: &'c SymbolDict, schema: &'c Schema }
```

That shape is correct and ergonomic for a *scoped* caller, and it encodes
something true: QWP egress permits one in-flight query per connection (there is
even a `cursor_active` runtime guard on top of the borrow). The `Reader` is the
connection — it owns the transport, the incrementally-built `SymbolDict`, the
request-id counter and the reusable zstd scratch — and it must outlive any one
query.

The problem is consumers that must **own** a result stream. A C ABI has nowhere
to put a lifetime. ADBC's `Statement::execute` must return
`Box<dyn RecordBatchReader + Send + 'static>`. Such a consumer has to own both
the reader and the cursor borrowing into it — a self-referential struct, which
safe Rust cannot express. So each one re-derives the same lifetime-laundering
trick.

This has now happened twice in-house:

- **`questdb-rs-ffi/src/egress.rs`** launders all three types across **7
  `transmute` sites**: `ReaderQuery<'static>`, `Cursor<'static>` and
  `BatchView<'static>`, held in `ManuallyDrop` with hand-documented drop
  ordering.
- **The ADBC driver** (`adbc-drivers/questdb`) needed a 611-line module with 11
  `unsafe` blocks and 5 documented safety invariants to do the same for two of
  the three types.

The ADBC attempt got it **wrong twice**, and both bugs were undefined behaviour
rather than test failures:

1. Deriving `&mut Reader` from a `Box<OwnedReader>` and then *moving* the box
   re-asserts the box's `Unique`/`noalias` guarantee, popping the derived
   reference off the borrow stack. Every subsequent use of the cursor is a
   use-after-invalidate.
2. After fixing that with raw-pointer ownership, the struct was still a by-value
   Rust value *containing* a live `&mut Reader`. Passing it by value retags that
   nested reference with a protector lasting the whole callee; dropping it
   inside that call then runs `Box::from_raw` over the protected allocation.
   `drop(stream)` and `.map(..).sum()` both trigger it — two of the module's own
   tests were affected.

Both were found only by building a structural model and running it under Miri
with Stacked Borrows *and* Tree Borrows. Neither would have been caught by
`cargo test`, and the shipped shape happened to be in the passing column by
luck rather than design.

The conclusion this spec acts on: **a trap that two competent in-house attempts
fell into is a property of the API, not of its callers.** A third binding — Go
via cgo, .NET — walks into the same one.

## 3. Constraint: purely additive

No existing public item changes shape or signature. `Cursor<'r>`,
`ReaderQuery<'r>` and `BatchView<'c>` keep their exact current public API, so
today's callers compile unchanged. This ships as a minor release.

"Additive" is a constraint on the *public surface*, not a licence to duplicate
protocol logic. Mid-query failover, terminal handling and decode are the
subtlest code in the module; maintaining two copies would be a worse outcome
than the problem being solved. Section 4 is how we get both.

## 4. The seam: separate per-query state from the connection

`Cursor<'r>` currently mixes two unrelated things: a borrow of the connection,
and 18 fields of purely per-query state (of its 21 fields, one is the `reader`
borrow and two are the `'r`-bound failover callbacks discussed below). The
borrow is what makes it unownable; the state is what makes it useful. Split
them.

```rust
/// Per-query state. No lifetimes, no borrow of the connection.
struct CursorState {
    request_id: i64,
    last_batch: Option<DecodedBatch>,
    terminal: Option<Terminal>,
    encoded_request: Bytes,
    failover_budget: FailoverBudget,
    failover_resets: u32,
    decode_failover_rounds: u32,
    stale_plan_retries: u32,
    data_delivered: bool,
    credit_enabled: bool,
    cancelling: bool,
    done: bool,
    terminal_error: Option<Error>,
    // arrow-egress / polars-egress scratch fields, feature-gated as today
}

impl CursorState {
    fn next_batch(
        &mut self,
        reader: &mut Reader,
        on_reset: Option<&mut dyn FnMut(&FailoverResetEvent)>,
        on_progress: Option<&mut dyn FnMut(&FailoverProgressEvent)>,
    ) -> Result<Option<..>>;
    // ... the rest of the protocol logic, all taking `reader: &mut Reader`
}
```

All protocol logic moves onto `CursorState` and takes `&mut Reader` as a
parameter. Both public cursor types become thin forwarders over the **same**
implementation:

```rust
pub struct Cursor<'r>     { reader: &'r mut Reader, state: CursorState, .. }  // API unchanged
pub struct OwnedCursor<O> { reader: O,              state: CursorState, .. }  // new
```

This is a mechanical refactor: the 55 `self.reader` sites in
`questdb-rs/src/egress/reader.rs` become uses of the `reader` parameter.

### Why the split rather than a generic

`CursorImpl<R: BorrowMut<Reader>>` with `pub type Cursor<'r> =
CursorImpl<&'r mut Reader>` would also be additive and also avoid duplication.
The split is preferred because it is the conceptual fix as well as the
mechanical one: it forces "is this state per-connection or per-query?" to be
answered explicitly in the type system, which is exactly what the current
design leaves implicit and what every binding then has to re-derive. It also
keeps generics out of the public signatures and error messages of a type most
users only ever see in one instantiation.

### The one thing the split costs

`on_failover_reset` and `on_failover_progress` are `Option<FailoverResetCallback<'r>>`
— tied to `'r`. They cannot live in a lifetime-free `CursorState`. They stay on
the forwarder types and are passed into `CursorState` methods as
`&mut dyn FnMut`. In the owning types the callbacks take `'static` captures.

## 5. Public API added

```rust
// Promoted out of `ffi_support` (see §7).
pub struct OwnedReader { .. }
impl QuestDb    { pub fn take_reader(&self) -> Result<OwnedReader>; }
impl OwnedReader { pub fn query(self, sql: impl Into<String>) -> PooledQuery; }

pub struct OwnedQuery<O: BorrowMut<Reader>>;
pub struct OwnedCursor<O: BorrowMut<Reader>>;

pub type PooledQuery  = OwnedQuery<OwnedReader>;
pub type PooledCursor = OwnedCursor<OwnedReader>;

impl<O: BorrowMut<Reader>> OwnedQuery<O> {
    pub fn bind(self, value: Bind) -> Self;
    pub fn initial_credit(self, credit: u64) -> Self;
    pub fn reset_symbol_dict(self, reset: bool) -> Self;
    pub fn execute(self) -> Result<OwnedCursor<O>>;
}

impl<O: BorrowMut<Reader>> OwnedCursor<O> {
    /// Advance to the next batch. `Ok(true)` when one is now current and the
    /// `batch_*` accessors below are valid; `Ok(false)` at end of stream.
    pub fn next_batch(&mut self) -> Result<bool>;
    pub fn terminal(&self) -> Option<&Terminal>;
    pub fn request_id(&self) -> i64;
    pub fn connection_reusable(&self) -> bool;
    pub fn into_owner(self) -> O;                            // hand the connection back

    // Batch access without a second handle (§6)
    pub fn batch_row_count(&self) -> usize;
    pub fn batch_column_count(&self) -> usize;
    pub fn batch_column(&self, idx: usize) -> Result<ColumnView<'_>>;
    pub fn batch_schema(&self) -> Option<&Schema>;

    #[cfg(feature = "arrow-egress")]
    pub fn next_arrow_batch(&mut self) -> Result<Option<RecordBatch>>;
    #[cfg(feature = "arrow-egress")]
    pub fn into_arrow_reader(self) -> Result<OwnedArrowReader<O>>;
}

/// `RecordBatchReader + Send + 'static` when `O: Send + 'static`.
#[cfg(feature = "arrow-egress")]
pub struct OwnedArrowReader<O: BorrowMut<Reader>>;
```

Generic over the owner rather than hardcoding `OwnedReader`, so a caller
holding a bare `Reader` with no pool gets the same ergonomics
(`OwnedCursor<Reader>`). The `Pooled*` aliases cover the common case.

`into_arrow_reader` is the single method that deletes the ADBC driver's unsafe
module: `execute()` becomes `Ok(Box::new(cursor.into_arrow_reader()?))`.

## 6. Removing the third handle

`BatchView<'c>` is the awkward link because it borrows from **both** objects at
once — `decoded` from the cursor, but `dict` and `schema` from the *Reader*.
That span is precisely why the C ABI must launder it, and why "add an owning
cursor" alone would not reach the goal.

An owning cursor reaches both, so batch access becomes accessors on the cursor
itself, borrowing only `&self`. The C ABI's batch handle stops being a Rust
reference and becomes a plain "current batch of this cursor" accessor keyed by
the cursor handle it already owns.

`BatchView<'c>` is retained unchanged for the borrowing path. No third owning
type is introduced.

## 7. `OwnedReader` becomes public

`OwnedReader` and `borrow_reader_owned` live in `db::ffi_support`, which is
`#[doc(hidden)]` and documented as semver-exempt: *"it exists so the
`questdb-rs-ffi` C-ABI crate can borrow owned (lifetime-free) pool handles that
C / Python cannot express as Rust lifetimes."*

That description now covers a second consumer, and pinning a shipped driver to
a semver-exempt surface is not a stable arrangement — the ADBC driver currently
carries `questdb-rs = "=7.0.0"` for exactly this reason. Promoting
`OwnedReader` to the public API with a normal stability promise is part of this
change, and `QuestDb::take_reader` is its public entry point.

`ffi_support` itself stays as-is for anything else it exposes.

## 8. Consumer payoff

| Consumer | Today | After |
|---|---|---|
| `questdb-rs-ffi/src/egress.rs` | 7 `transmute`s, 3 laundered types, hand-documented drop ordering | 0 |
| ADBC driver `result_stream.rs` | 611 lines, 11 `unsafe`, 5 invariants, 2 UB bugs found by Miri | deleted |
| Future bindings (Go/cgo, .NET) | inherit the trap | safe by construction |
| Direct Rust users, scoped | `reader.execute(sql)` | unchanged |

## 9. Testing

The goal — "no binding hand-rolls `unsafe`" — is a property to enforce
mechanically, not a test to write once.

1. **A `#![forbid(unsafe_code)]` example crate** consuming the owning API in the
   shapes that broke the ADBC driver: `drop(stream)`, consumed by a by-value
   adaptor (`.map(..).sum()`), moved across a thread, and boxed as
   `Box<dyn RecordBatchReader + Send>`. **If it compiles, the property holds** —
   the compiler is the proof. This is strictly stronger than a Miri model, which
   can only ever show that a particular hand-rolled version was wrong.
2. **Parity tests.** The borrowing and owning paths must produce identical
   results over the existing egress test corpus. This is what protects the
   mechanical refactor of 55 call sites through the failover code, which is the
   main risk in §11.
3. **Pool-return tests.** The owner returns to the pool on drop; `must_close` is
   honoured when the transport tore down; an abandoned mid-stream cursor does
   not recycle a desynced connection. These were the site of real bugs in the
   ADBC driver and belong upstream where the pool lives.
4. **Soak.** Run `doc/QWP_SOAK_HARNESS.md` against both paths before merge,
   since failover behaviour is the part least covered by unit tests.

## 10. Migration for `questdb-rs-ffi`

The C ABI is updated in the same change — it is both the proof the new API is
sufficient and the largest single reduction in `unsafe`. Its public C surface
does not change: `qwp_reader_cursor` keeps its handle semantics, but its
internals become `OwnedCursor<OwnedReader>` with no `transmute`, and the batch
handle becomes an accessor over the cursor rather than a laundered
`BatchView<'static>`.

If the C batch surface cannot be preserved exactly, that is a finding worth
surfacing rather than working around — say so and stop, rather than
reintroducing a laundered handle to keep a signature.

## 11. Risks

- **Threading a `&mut Reader` parameter through 55 sites touches mid-query
  failover**, the subtlest code in the module. Mitigated by §9's parity tests
  and the soak harness. This is the risk that would justify staging the change:
  land the `CursorState` split with `Cursor<'r>` forwarding to it and *no* new
  public API first, prove parity, then add the owning types in a second change.
- **Callback lifetimes** (§4) are the one genuinely awkward part. If passing
  `&mut dyn FnMut` through the state methods proves unworkable for the failover
  paths, the fallback is to keep callbacks entirely on the forwarders and have
  `CursorState` return failover events for the forwarder to dispatch.
- **`cursor_active` still matters.** Ownership does not replace the guard: a
  caller can `into_owner()` and reuse the reader, so the one-query-at-a-time
  invariant still needs enforcing at runtime.
- **`OwnedArrowReader<O>: Send` requires `O: Send`.** `OwnedReader` is `Send`
  today; this must be asserted in the crate so a future change to `DbInner`
  turns into a compile error rather than an unsound `Send` claim downstream.

## 12. Out of scope

Named explicitly because each was considered and rejected for this change:

- Making Arrow the primary egress surface rather than a feature-gated adapter.
- Unifying the pool/reader/cursor model with ADBC's Database/Connection/Statement.
- Any async egress API.
- Re-partitioning `Reader`'s own fields (e.g. whether `query_schema` is really
  per-connection state).

Each may be worth doing; none is required to stop bindings writing `unsafe`.
