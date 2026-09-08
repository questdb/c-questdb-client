# Owning Handles for the QWP Egress API — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let any consumer own a QWP result stream without writing `unsafe`, by separating per-query state from the connection and adding owning handles built on the same implementation.

**Architecture:** Extract the ~18 per-query fields of `Cursor<'r>` into a lifetime-free `CursorState` whose methods take `&mut Reader` as a parameter. The existing `Cursor<'r>` becomes a thin forwarder over it, and a new `OwnedCursor<O: BorrowMut<Reader>>` forwards to the *same* implementation while owning its reader. Batch access moves onto the cursor so no third borrowed handle is needed.

**Tech Stack:** Rust 2024, `questdb-rs` (the QWP client), `questdb-rs-ffi` (its C ABI), `tungstenite` for the in-process mock QWP server used by tests.

**Spec:** `docs/superpowers/specs/2026-09-07-egress-owned-handles-design.md`. Read it before Task 1 — especially §2 (why this exists) and §11 (risks).

## Global Constraints

- **NEVER `git push`.** This work stays local. No PR, no issue, no upstream contact without the repository owner's explicit say-so.
- **Purely additive to the public API.** No existing public item changes shape or signature. `Cursor<'r>`, `ReaderQuery<'r>` and `BatchView<'c>` keep their exact current public API. If you believe a task requires changing one, stop and report — do not change it.
- **No duplicated protocol logic.** Both the borrowing and owning paths must call the same `CursorState` implementation. Two copies of failover/terminal/decode handling is a worse outcome than the problem being solved.
- **Repo lint convention (from `CLAUDE.md`): never pass `-D warnings`.** Run plain `cargo clippy` and read the output. Before every commit, in this order:
  - `cargo fmt --manifest-path questdb-rs/Cargo.toml`
  - `cargo clippy --manifest-path questdb-rs/Cargo.toml --tests`
  and the same pair for `questdb-rs-ffi` when that crate is touched.
- **No new dependencies** in `questdb-rs` or `questdb-rs-ffi`.
- **No behaviour change on the borrowing path.** Tasks 1 and 2 must leave every existing test passing with no change to any test's body or assertions. Task 1 necessarily edits `egress_failover.rs` to remove the harness it extracts, and to add the `mod`/`use` lines — that is expected. What is forbidden is altering what a test asserts. A test whose assertions need editing to pass is a signal you changed behaviour: stop and report it.
- Working directory is the worktree `~/claude/wt/cqc/egress-owned-handles`, branch `design/egress-owned-handles`. Do not touch `/home/nick/repos/c-questdb-client`, which has an unrelated branch checked out.

## A note on how this plan specifies the refactor

Task 2 mechanically rewrites ~31 methods across a 3,685-line file. This plan does **not** reproduce all 31 bodies — that would be thousands of lines nobody reads, and it would go stale the moment the first method differed. Instead Task 2 gives: the exact target shape, a fully worked before/after for two representative methods (one simple, one that touches failover), the mechanical procedure, and the verification that proves the whole set is correct. Where a task introduces genuinely *new* code, the code is given in full.

---

### Task 1: Extract the mock QWP server into a shared test module

The egress tests do not need a live QuestDB: `tests/egress_failover.rs` stands up an in-process QWP server over `tungstenite` and hand-writes frames. That harness is currently private to that one file, so the owning-path tests in later tasks could not reuse it without copying ~700 lines. Extract it first, with zero behaviour change, so every later task has a server to test against.

**Files:**
- Create: `questdb-rs/tests/common/qwp_mock.rs`
- Modify: `questdb-rs/tests/egress_failover.rs` (remove the extracted items, import them instead)

**Interfaces:**
- Consumes: nothing.
- Produces: a test-only module exposing at least `MockServer` (with `addr()`, and its `Drop`), `Script`, `run_script`, `happy_script`, `drop_after_query_script`, `drop_at_connect_script`, `build_addr_list`, `DeadEndpoint`, and the frame builders `framed`, `encode_varint_u64`, `server_info_frame`, `result_end_frame`, `result_batch_frame`, `query_error_frame`, `cache_reset_frame`, plus the `BatchColumn` type they use. Tasks 4, 5 and 6 build their tests on these.

- [ ] **Step 1: Record the baseline**

```bash
cd ~/claude/wt/cqc/egress-owned-handles
cargo test --manifest-path questdb-rs/Cargo.toml --test egress_failover 2>&1 | tail -3
```

Expected: a passing line. **On default features this measured `79 passed` on 2026-09-07** — that is the number to hold constant, not the count of `#[test]` attributes in the file (86), several of which are feature-gated. Record whatever your run reports; it is the acceptance criterion for this task and Task 2.

- [ ] **Step 2: Move the harness into the new module**

Create `questdb-rs/tests/common/qwp_mock.rs` containing everything from `tests/egress_failover.rs` that is server-side plumbing rather than a test: the frame constants (`MAGIC`, `MSG_*`), the frame builders, `BatchColumn`, `MockServer`, `Script`, `run_script`, the script constructors, `DeadEndpoint`, `build_addr_list`, and the helpers `reject_upgrade`, `reject_upgrade_421`, `parse_authorization_header`, `read_until_client_cancel`, `read_until_query_request`.

Make each item `pub` (it is a test-only module; `pub` here means "visible to the test binaries", not part of the crate's API). Keep the code otherwise byte-identical — this step is a move, not a rewrite. Do not "improve" anything you move; a behaviour change hidden inside a move is exactly what Step 4 cannot distinguish from a real regression.

- [ ] **Step 3: Point `egress_failover.rs` at the module**

At the top of `questdb-rs/tests/egress_failover.rs`:

```rust
#[path = "common/qwp_mock.rs"]
mod qwp_mock;

use qwp_mock::*;
```

The `#[path]` form is used because `tests/common/mod.rs` already exists for the live-server harness and declares its own contents; adding `qwp_mock` as a sibling file addressed directly avoids touching that module.

- [ ] **Step 4: Verify zero behaviour change**

```bash
cd ~/claude/wt/cqc/egress-owned-handles
cargo test --manifest-path questdb-rs/Cargo.toml --test egress_failover 2>&1 | tail -3
```

Expected: the same count as Step 1 (79 on default features), with **no test's body or assertions edited**. If a test had to change, you changed behaviour: revert and redo the move faithfully.

- [ ] **Step 5: Confirm the module is genuinely reusable**

Add a second test file `questdb-rs/tests/qwp_mock_smoke.rs`. It is permanent — it is the harness's own regression guard, and the only thing that would catch the shared module silently becoming unusable from outside `egress_failover.rs`:

```rust
#![cfg(feature = "sync-reader-qwp-ws")]

#[path = "common/qwp_mock.rs"]
mod qwp_mock;

use qwp_mock::*;
use questdb::egress::{Reader, ServerRole};

/// Proves the extracted harness is usable from a file other than
/// egress_failover.rs — the whole point of Task 1.
#[test]
fn mock_server_is_reusable_from_another_test_binary() {
    let server = MockServer::start(happy_script(ServerRole::Primary, "n1"));
    let conf = format!("ws::addr={};", server.addr());
    let mut reader = Reader::from_conf(&conf).expect("connect");
    let mut cursor = reader.execute("SELECT 1").expect("execute");
    let mut batches = 0;
    while cursor.next_batch().expect("next_batch").is_some() {
        batches += 1;
    }
    assert!(batches > 0, "the happy script should yield at least one batch");
}
```

Run: `cargo test --manifest-path questdb-rs/Cargo.toml --test qwp_mock_smoke`
Expected: PASS. If `MockServer::start` or `happy_script` has a different signature after your extraction, adjust this test to the real one — but keep the test, it stays as the harness's own regression guard.

- [ ] **Step 6: Lint and commit**

```bash
cd ~/claude/wt/cqc/egress-owned-handles
cargo fmt --manifest-path questdb-rs/Cargo.toml
cargo clippy --manifest-path questdb-rs/Cargo.toml --tests
git add questdb-rs/tests/
git commit -m "test: extract the mock QWP server into a shared module"
```

---

### Task 2: Split `CursorState` out of `Cursor<'r>` — no new public API

The risky task, isolated so it can be proven by parity before anything new is built on it. When this task is done the public API is **byte-identical** to before; only the internals moved.

**Files:**
- Modify: `questdb-rs/src/egress/reader.rs` (3,685 lines; `Cursor<'r>` and its ~31 methods)

**Interfaces:**
- Consumes: nothing.
- Produces: `struct CursorState` (private to the module) carrying the per-query fields, with every protocol method taking `reader: &mut Reader` as its first parameter after `&mut self`. Tasks 4, 5 and 6 build `OwnedCursor` on exactly this type.

- [ ] **Step 1: Record the full baseline**

```bash
cd ~/claude/wt/cqc/egress-owned-handles
cargo test --manifest-path questdb-rs/Cargo.toml 2>&1 | grep -E "^test result" | tee /tmp/egress-baseline.txt
```

Keep `/tmp/egress-baseline.txt`. Every line must be identical at Step 6.

- [ ] **Step 2: Define `CursorState` and re-shape `Cursor<'r>`**

In `questdb-rs/src/egress/reader.rs`:

```rust
/// Per-query state for one in-flight QWP query.
///
/// Deliberately holds no borrow of the `Reader`: every method takes the
/// connection as a parameter. That is what lets the same implementation back
/// both the borrowing `Cursor<'r>` and the owning `OwnedCursor<O>` without
/// duplicating the protocol logic.
///
/// The failover callbacks are NOT here: they are `'r`-bound on the borrowing
/// path, so they stay on the forwarder and are passed in as `&mut dyn FnMut`.
pub(crate) struct CursorState {
    pub(crate) request_id: i64,
    pub(crate) last_batch: Option<DecodedBatch>,
    pub(crate) terminal: Option<Terminal>,
    pub(crate) encoded_request: Bytes,
    pub(crate) failover_budget: FailoverBudget,
    pub(crate) failover_resets: u32,
    pub(crate) decode_failover_rounds: u32,
    pub(crate) stale_plan_retries: u32,
    pub(crate) data_delivered: bool,
    pub(crate) credit_enabled: bool,
    pub(crate) cancelling: bool,
    pub(crate) done: bool,
    pub(crate) terminal_error: Option<Error>,
    #[cfg(feature = "arrow-egress")]
    pub(crate) drifted_batch: Option<DecodedBatch>,
    #[cfg(feature = "arrow-egress")]
    pub(crate) sym_values: crate::egress::arrow::SymbolValuesCache,
    #[cfg(feature = "arrow-egress")]
    pub(crate) sym_scratch: crate::egress::arrow::SymbolBuildScratch,
    #[cfg(feature = "polars-egress")]
    pub(crate) symbol_registry: Option<crate::egress::arrow::polars::SymbolRegistry>,
}

pub struct Cursor<'r> {
    reader: &'r mut Reader,
    state: CursorState,
    on_failover_reset: Option<FailoverResetCallback<'r>>,
    on_failover_progress: Option<FailoverProgressCallback<'r>>,
}
```

Take the exact field list from the current `Cursor<'r>` definition rather than trusting the list above — if the two disagree, the source is right and this plan is stale. Every field except `reader` and the two callbacks moves.

- [ ] **Step 3: Move the method bodies onto `CursorState`, mechanically**

For each of `Cursor`'s ~31 methods, move the body to `impl CursorState` with `reader: &mut Reader` as a parameter, and leave a one-line forwarder behind. Two worked examples — do the rest the same way.

*Simple case.* Before:

```rust
impl<'r> Cursor<'r> {
    pub fn connection_reusable(&self) -> bool {
        self.done && !self.reader.transport_torn_down()
    }
}
```

After:

```rust
impl CursorState {
    pub(crate) fn connection_reusable(&self, reader: &Reader) -> bool {
        self.done && !reader.transport_torn_down()
    }
}

impl<'r> Cursor<'r> {
    pub fn connection_reusable(&self) -> bool {
        self.state.connection_reusable(self.reader)
    }
}
```

*Failover case — the one that needs care,* because it is where the callbacks live. Before:

```rust
impl<'r> Cursor<'r> {
    fn failover_reconnect_and_replay(&mut self, trigger: Error) -> Result<()> {
        // ... uses self.reader, self.failover_budget, and invokes
        // self.on_failover_reset / self.on_failover_progress ...
    }
}
```

After:

```rust
impl CursorState {
    pub(crate) fn failover_reconnect_and_replay(
        &mut self,
        reader: &mut Reader,
        trigger: Error,
        on_reset: Option<&mut dyn FnMut(&FailoverResetEvent)>,
        on_progress: Option<&mut dyn FnMut(&FailoverProgressEvent)>,
    ) -> Result<()> {
        // identical body; `self.reader` -> `reader`,
        // `self.on_failover_reset` -> the `on_reset` parameter
    }
}

impl<'r> Cursor<'r> {
    fn failover_reconnect_and_replay(&mut self, trigger: Error) -> Result<()> {
        // Split the borrows so the callbacks and the state can be passed
        // together: `self.state` and `self.on_*` are disjoint fields.
        let Cursor { reader, state, on_failover_reset, on_failover_progress } = self;
        state.failover_reconnect_and_replay(
            reader,
            trigger,
            on_failover_reset.as_mut().map(|c| c as &mut dyn FnMut(&FailoverResetEvent)),
            on_failover_progress.as_mut().map(|c| c as &mut dyn FnMut(&FailoverProgressEvent)),
        )
    }
}
```

The destructuring in the forwarder is load-bearing: `self.state.f(self.reader, ...)` will not borrow-check when the callee also needs `&mut self.on_*`, because the compiler sees a whole-`self` borrow. Destructuring gives it disjoint fields.

**If the callback threading proves unworkable** for some failover path — the
spec (§11) anticipates this — the sanctioned fallback is to keep the callbacks
entirely on the forwarder and have `CursorState` *return* failover events for
the forwarder to dispatch, rather than invoking them. Take that route and say
so in your report; do not leave a `&mut dyn FnMut` parameter threaded halfway
through, and do not duplicate the failover logic to avoid the problem.

Rules for the whole pass:
- Do not change any body's logic. `self.reader` becomes `reader`; `self.<state field>` becomes `self.<state field>`; `self.on_failover_*` becomes the parameter. Nothing else.
- Methods that only read state and never touch the reader (`request_id`, `failover_resets`, `stale_plan_retries`) do not need a `reader` parameter.
- Keep every public method's signature on `Cursor<'r>` exactly as it is today.
- `next_batch` returns `BatchView<'_>`, which borrows the reader (`dict`, `schema`) *and* the state (`decoded`). Construct it in the **forwarder**, not in `CursorState`, so the lifetimes stay tied to `Cursor` as they are today. `CursorState` should expose `next_batch_inner(&mut self, reader: &mut Reader, ..) -> Result<NextOutcome>` and let the forwarder build the view.

- [ ] **Step 4: Build**

```bash
cd ~/claude/wt/cqc/egress-owned-handles
cargo build --manifest-path questdb-rs/Cargo.toml --features almost-all-features
cargo build --manifest-path questdb-rs/Cargo.toml --features almost-all-features,arrow,polars
```

Expected: both succeed. The second is not optional — `drifted_batch`, `sym_values`, `sym_scratch` and `symbol_registry` are feature-gated, and a split that compiles without `arrow` can easily fail with it.

- [ ] **Step 5: Prove the public API did not move**

```bash
cd ~/claude/wt/cqc/egress-owned-handles
cargo doc --manifest-path questdb-rs/Cargo.toml --no-deps --features arrow 2>&1 | tail -2
git diff --stat questdb-rs/src/egress/mod.rs
```

Expected: docs build, and **`egress/mod.rs` is unchanged** — that file holds the `pub use` list, so an empty diff is direct evidence the exported surface did not change. If it did change, this task exceeded its scope.

- [ ] **Step 6: Prove parity**

```bash
cd ~/claude/wt/cqc/egress-owned-handles
cargo test --manifest-path questdb-rs/Cargo.toml 2>&1 | grep -E "^test result" > /tmp/egress-after.txt
diff /tmp/egress-baseline.txt /tmp/egress-after.txt && echo "PARITY OK"
```

Expected: `PARITY OK`, with **no test file modified** (`git status` should show only `reader.rs`). This is the acceptance criterion for the whole task.

- [ ] **Step 7: Run the arrow and polars suites too**

```bash
cargo test --manifest-path questdb-rs/Cargo.toml --features almost-all-features,arrow,polars 2>&1 | grep -E "^test result|FAILED"
```

Expected: all pass. These exercise the feature-gated state fields the default suite does not.

- [ ] **Step 8: Lint and commit**

```bash
cd ~/claude/wt/cqc/egress-owned-handles
cargo fmt --manifest-path questdb-rs/Cargo.toml
cargo clippy --manifest-path questdb-rs/Cargo.toml --tests
git add questdb-rs/src/egress/reader.rs
git commit -m "refactor(egress): split per-query CursorState out of Cursor"
```

---

### Task 3: Promote `OwnedReader` to the public API

Small and additive. Done before the owning cursor because that cursor's headline instantiation is `OwnedCursor<OwnedReader>`.

**Files:**
- Modify: `questdb-rs/src/lib.rs` (the re-export block, around the `ffi_support` export), `questdb-rs/src/db.rs` (`OwnedReader`'s gating and a public constructor)
- Test: `questdb-rs/src/tests/qwp_sender_pool.rs` (or a new `#[cfg(test)]` module beside the pool tests — follow whatever that file does)

**Interfaces:**
- Consumes: nothing.
- Produces: `pub struct questdb::OwnedReader` with `get(&self) -> &Reader`, `get_mut(&mut self) -> &mut Reader`, `mark_must_close(&mut self)`; and `impl QuestDb { pub fn take_reader(&self) -> Result<OwnedReader> }`. Task 4 takes these by value.

- [ ] **Step 1: Write the failing test**

In the pool test module:

```rust
/// `take_reader` is the public entry point for an owned, pool-backed reader.
/// Dropping it must return the reader to the pool, or a driver that opens and
/// closes connections in a loop would exhaust the pool.
#[test]
fn take_reader_returns_to_the_pool_on_drop() {
    let server = /* mock QWP server, as the surrounding tests construct one */;
    let db = QuestDb::connect(&format!("ws::addr={};query_pool_max=1;", server.addr()))
        .expect("connect");

    {
        let reader = db.take_reader().expect("first checkout");
        assert!(reader.get().server_info().is_some());
    } // dropped here

    // With query_pool_max=1 this only succeeds if the first reader went back.
    let _second = db.take_reader().expect("second checkout after drop");
}
```

- [ ] **Step 2: Run it and watch it fail**

```bash
cargo test --manifest-path questdb-rs/Cargo.toml take_reader_returns_to_the_pool
```

Expected: FAIL — `no method named take_reader`.

- [ ] **Step 3: Promote the type**

In `questdb-rs/src/db.rs`, remove the `#[cfg(all(feature = "_egress", feature = "ffi-support"))]` gating from `OwnedReader` and its inherent impl so it is available whenever `_egress` is on, and add:

```rust
impl QuestDb {
    /// Check out a reader that owns its pool slot.
    ///
    /// Unlike [`QuestDb::borrow_reader`], the returned handle carries no
    /// lifetime, so it can be moved into a struct, returned across an FFI
    /// boundary, or parked in a `Box<dyn ..>`. It returns itself to the pool
    /// when dropped.
    #[cfg(feature = "_egress")]
    pub fn take_reader(&self) -> crate::error::Result<OwnedReader> {
        self.borrow_reader_owned()
    }
}
```

In `questdb-rs/src/lib.rs`, add a public re-export next to the existing `BorrowedReader` one:

```rust
#[cfg(feature = "_egress")]
pub use db::OwnedReader;
```

Leave the `ffi_support` module and its `#[doc(hidden)]` export exactly as they are — `questdb-rs-ffi` still uses other items from it, and removing it is not this task's job.

- [ ] **Step 4: Run the test**

```bash
cargo test --manifest-path questdb-rs/Cargo.toml take_reader_returns_to_the_pool
```

Expected: PASS.

- [ ] **Step 5: Prove `OwnedReader` is `Send`, permanently**

Downstream `RecordBatchReader + Send` claims depend on it, so make a regression a compile error. Add near the type:

```rust
#[cfg(feature = "_egress")]
const _: fn() = || {
    fn assert_send<T: Send>() {}
    assert_send::<OwnedReader>();
};
```

- [ ] **Step 6: Lint and commit**

```bash
cd ~/claude/wt/cqc/egress-owned-handles
cargo fmt --manifest-path questdb-rs/Cargo.toml
cargo clippy --manifest-path questdb-rs/Cargo.toml --tests
git add questdb-rs/src/
git commit -m "feat(egress): make OwnedReader public via QuestDb::take_reader"
```

---

### Task 4: `OwnedQuery<O>` and `OwnedCursor<O>`

**Files:**
- Create: `questdb-rs/src/egress/owned.rs`
- Modify: `questdb-rs/src/egress/mod.rs` (declare the module and re-export the new types)
- Test: `questdb-rs/tests/egress_owned.rs`

**Interfaces:**
- Consumes: `CursorState` (Task 2), `OwnedReader` (Task 3), the mock harness (Task 1).
- Produces:
  - `pub struct OwnedQuery<O: BorrowMut<Reader>>` with `bind(self, Bind) -> Self`, `initial_credit(self, u64) -> Self`, `reset_symbol_dict(self, bool) -> Self`, `execute(self) -> Result<OwnedCursor<O>>`
  - `pub struct OwnedCursor<O: BorrowMut<Reader>>` with `next_batch(&mut self) -> Result<bool>`, `terminal(&self) -> Option<&Terminal>`, `request_id(&self) -> i64`, `connection_reusable(&self) -> bool`, `into_owner(self) -> O`
  - `pub type PooledQuery = OwnedQuery<OwnedReader>`, `pub type PooledCursor = OwnedCursor<OwnedReader>`
  - `impl OwnedReader { pub fn query(self, sql: impl Into<String>) -> PooledQuery }`

  Tasks 5 and 6 extend `OwnedCursor`; Task 8 consumes all of it.

- [ ] **Step 1: Write the failing test**

`questdb-rs/tests/egress_owned.rs`:

```rust
#![cfg(feature = "sync-reader-qwp-ws")]

#[path = "common/qwp_mock.rs"]
mod qwp_mock;

use qwp_mock::*;
use questdb::QuestDb;
use questdb::egress::ServerRole;

/// The shape every owning consumer needs: a cursor with no lifetime, usable
/// after the function that made it has returned.
#[test]
fn an_owned_cursor_outlives_the_scope_that_made_it() {
    let server = MockServer::start(happy_script(ServerRole::Primary, "n1"));
    let conf = format!("ws::addr={};", server.addr());

    fn make_cursor(conf: &str) -> questdb::egress::PooledCursor {
        let db = QuestDb::connect(conf).expect("connect");
        let reader = db.take_reader().expect("take_reader");
        reader.query("SELECT 1").execute().expect("execute")
        // `db` and `reader` both go out of scope here; the cursor owns what it needs
    }

    let mut cursor = make_cursor(&conf);
    let mut batches = 0;
    while cursor.next_batch().expect("next_batch") {
        batches += 1;
    }
    assert!(batches > 0, "expected at least one batch from the happy script");
    assert!(cursor.terminal().is_some(), "stream should have terminated");
}

/// An owned cursor must be movable across threads — a `Box<dyn .. + Send>`
/// consumer will do exactly this.
#[test]
fn an_owned_cursor_can_be_moved_across_threads() {
    let server = MockServer::start(happy_script(ServerRole::Primary, "n1"));
    let conf = format!("ws::addr={};", server.addr());
    let db = QuestDb::connect(&conf).expect("connect");
    let cursor = db.take_reader().expect("take_reader").query("SELECT 1")
        .execute().expect("execute");

    let batches = std::thread::spawn(move || {
        let mut cursor = cursor;
        let mut n = 0;
        while cursor.next_batch().expect("next_batch") { n += 1; }
        n
    })
    .join()
    .expect("thread");

    assert!(batches > 0);
}

/// `into_owner` hands the connection back so the caller can run another query.
#[test]
fn into_owner_returns_a_reusable_reader() {
    let server = MockServer::start(happy_script(ServerRole::Primary, "n1"));
    let conf = format!("ws::addr={};", server.addr());
    let db = QuestDb::connect(&conf).expect("connect");

    let mut cursor = db.take_reader().expect("take_reader").query("SELECT 1")
        .execute().expect("execute");
    while cursor.next_batch().expect("drain") {}
    let reader = cursor.into_owner();

    // The reader is usable again for a second query.
    let mut second = reader.query("SELECT 1").execute().expect("second execute");
    while second.next_batch().expect("drain") {}
    assert!(second.terminal().is_some());
}
```

- [ ] **Step 2: Run and watch it fail**

```bash
cargo test --manifest-path questdb-rs/Cargo.toml --test egress_owned
```

Expected: FAIL — `PooledCursor` / `query` / `take_reader().query` unresolved.

- [ ] **Step 3: Implement `questdb-rs/src/egress/owned.rs`**

```rust
use std::borrow::BorrowMut;

use crate::egress::reader::{CursorState, Reader, Terminal};
use crate::egress::{Bind, QueryRequestBuilder};
use crate::error::Result;
use crate::OwnedReader; // public as of Task 3; NOT via ffi_support

/// A query being built against an owned connection.
///
/// The owning counterpart of [`ReaderQuery`](crate::egress::ReaderQuery).
/// Generic over the owner so a caller with a bare `Reader` and a caller with a
/// pooled `OwnedReader` get the same API.
pub struct OwnedQuery<O: BorrowMut<Reader>> {
    owner: O,
    builder: QueryRequestBuilder,
    reset_symbol_dict: bool,
}

pub type PooledQuery = OwnedQuery<OwnedReader>;
pub type PooledCursor = OwnedCursor<OwnedReader>;

impl<O: BorrowMut<Reader>> OwnedQuery<O> {
    pub(crate) fn new(owner: O, sql: impl Into<String>) -> Self {
        Self {
            owner,
            builder: QueryRequestBuilder::new(sql.into()),
            reset_symbol_dict: false,
        }
    }

    pub fn bind(mut self, value: Bind) -> Self {
        self.builder.push_bind(value);
        self
    }

    pub fn initial_credit(mut self, credit: u64) -> Self {
        self.builder.set_initial_credit(credit);
        self
    }

    pub fn reset_symbol_dict(mut self, reset: bool) -> Self {
        self.reset_symbol_dict = reset;
        self
    }

    /// Submit the query, consuming the builder and moving the connection into
    /// the returned cursor.
    pub fn execute(mut self) -> Result<OwnedCursor<O>> {
        let state = CursorState::submit(
            self.owner.borrow_mut(),
            self.builder,
            self.reset_symbol_dict,
        )?;
        Ok(OwnedCursor { owner: self.owner, state })
    }
}

/// A result stream that owns its connection.
///
/// The owning counterpart of [`Cursor`](crate::egress::Cursor). Because it owns
/// the connection rather than borrowing it, it can be moved into a struct,
/// boxed as a trait object, or returned across an FFI boundary — none of which
/// a lifetime-bound cursor permits.
pub struct OwnedCursor<O: BorrowMut<Reader>> {
    owner: O,
    state: CursorState,
}

impl<O: BorrowMut<Reader>> OwnedCursor<O> {
    /// Advance to the next batch. `Ok(true)` when one is now current and the
    /// `batch_*` accessors are valid; `Ok(false)` at end of stream.
    pub fn next_batch(&mut self) -> Result<bool> {
        self.state.next_batch_owned(self.owner.borrow_mut())
    }

    pub fn terminal(&self) -> Option<&Terminal> {
        self.state.terminal.as_ref()
    }

    pub fn request_id(&self) -> i64 {
        self.state.request_id
    }

    pub fn connection_reusable(&self) -> bool {
        self.state.connection_reusable(self.owner.borrow_mut())
    }

    /// Hand the connection back, discarding any unread remainder of the stream.
    pub fn into_owner(mut self) -> O {
        self.state.finish(self.owner.borrow_mut());
        self.owner
    }
}

impl<O: BorrowMut<Reader>> Drop for OwnedCursor<O> {
    fn drop(&mut self) {
        // Mirrors `Cursor`'s Drop: an abandoned stream must tear the transport
        // down so the connection is not recycled mid-query.
        self.state.finish(self.owner.borrow_mut());
    }
}

impl OwnedReader {
    /// Start a query on this owned connection.
    pub fn query(self, sql: impl Into<String>) -> PooledQuery {
        OwnedQuery::new(self, sql)
    }
}
```

Two things this needs from Task 2's `CursorState`, which you may have to add there as thin wrappers over the logic that already exists in the forwarders:

- `CursorState::submit(reader: &mut Reader, builder: QueryRequestBuilder, reset_symbol_dict: bool) -> Result<CursorState>` — the body of today's `ReaderQuery::execute`, minus the borrow bookkeeping.
- `CursorState::next_batch_owned(&mut self, reader: &mut Reader) -> Result<bool>` — `next_batch_inner` plus "store the decoded batch in `self.last_batch` and report whether one arrived".
- `CursorState::finish(&mut self, reader: &mut Reader)` — today's `Cursor::drop` body.

`BorrowMut<Reader>` must be implemented for `OwnedReader`; add it in `db.rs`:

```rust
impl std::borrow::Borrow<Reader> for OwnedReader {
    fn borrow(&self) -> &Reader { self.get() }
}
impl BorrowMut<Reader> for OwnedReader {
    fn borrow_mut(&mut self) -> &mut Reader { self.get_mut() }
}
```

- [ ] **Step 4: Declare and export the module**

In `questdb-rs/src/egress/mod.rs`:

```rust
#[cfg(feature = "sync-reader-qwp-ws")]
pub mod owned;

#[cfg(feature = "sync-reader-qwp-ws")]
pub use owned::{OwnedCursor, OwnedQuery, PooledCursor, PooledQuery};
```

This is the one edit to `mod.rs` the whole plan makes, and it is purely additive — do not remove or reorder anything already in that file.

- [ ] **Step 5: Run the tests**

```bash
cargo test --manifest-path questdb-rs/Cargo.toml --test egress_owned
```

Expected: 3 passed.

- [ ] **Step 6: Prove the borrowing path is untouched**

```bash
cargo test --manifest-path questdb-rs/Cargo.toml 2>&1 | grep -E "^test result" > /tmp/egress-after-t4.txt
diff /tmp/egress-baseline.txt <(grep -v "egress_owned\|qwp_mock_smoke" /tmp/egress-after-t4.txt) && echo "NO REGRESSION"
```

Expected: the pre-existing suites report exactly what they did at Task 2 Step 1.

- [ ] **Step 7: Lint and commit**

```bash
cd ~/claude/wt/cqc/egress-owned-handles
cargo fmt --manifest-path questdb-rs/Cargo.toml
cargo clippy --manifest-path questdb-rs/Cargo.toml --tests
git add questdb-rs/src questdb-rs/tests/egress_owned.rs
git commit -m "feat(egress): add OwnedQuery and OwnedCursor"
```

---

### Task 5: Batch accessors on `OwnedCursor` — removing the third handle

`BatchView<'c>` borrows from the cursor (`decoded`) *and* the reader (`dict`, `schema`). That span is why the C ABI has to launder it. An owning cursor reaches both, so the same data is reachable through `&self`.

**Files:**
- Modify: `questdb-rs/src/egress/owned.rs`
- Test: `questdb-rs/tests/egress_owned.rs`

**Interfaces:**
- Consumes: `OwnedCursor<O>` (Task 4).
- Produces: `batch_row_count(&self) -> usize`, `batch_column_count(&self) -> usize`, `batch_column(&self, idx: usize) -> Result<ColumnView<'_>>`, `batch_schema(&self) -> Option<&Schema>`, `batch_seq(&self) -> Option<u64>`. Task 8 replaces the C ABI's laundered `BatchView<'static>` with these.

- [ ] **Step 1: Write the failing parity test**

Append to `questdb-rs/tests/egress_owned.rs`:

```rust
use questdb::egress::{ColumnView, Reader};

/// The accessors must return exactly what BatchView returns on the borrowing
/// path — same script, same assertions, two APIs.
#[test]
fn owned_batch_accessors_match_the_borrowing_batchview() {
    let script = happy_script(ServerRole::Primary, "n1");

    // Borrowing path: read the first batch through BatchView.
    let server_a = MockServer::start(script.clone());
    let conf_a = format!("ws::addr={};", server_a.addr());
    let mut reader = Reader::from_conf(&conf_a).expect("connect");
    let mut cursor = reader.execute("SELECT 1").expect("execute");
    let view = cursor.next_batch().expect("next_batch").expect("a batch");
    let expected_rows = view.row_count();
    let expected_cols = view.column_count();
    let expected_first = match view.column(0).expect("column 0") {
        ColumnView::Fixed(c) => format!("{:?}", c.i64_at(0)),
        other => format!("{other:?}"),
    };
    drop(cursor);

    // Owning path: the same, through the accessors.
    let server_b = MockServer::start(script);
    let conf_b = format!("ws::addr={};", server_b.addr());
    let db = QuestDb::connect(&conf_b).expect("connect");
    let mut owned = db.take_reader().expect("take_reader").query("SELECT 1")
        .execute().expect("execute");
    assert!(owned.next_batch().expect("next_batch"), "expected a batch");

    assert_eq!(owned.batch_row_count(), expected_rows, "row count differs");
    assert_eq!(owned.batch_column_count(), expected_cols, "column count differs");
    let actual_first = match owned.batch_column(0).expect("column 0") {
        ColumnView::Fixed(c) => format!("{:?}", c.i64_at(0)),
        other => format!("{other:?}"),
    };
    assert_eq!(actual_first, expected_first, "column 0 differs");
}

/// Accessors before the first `next_batch` must not panic.
#[test]
fn owned_batch_accessors_are_safe_before_the_first_batch() {
    let server = MockServer::start(happy_script(ServerRole::Primary, "n1"));
    let conf = format!("ws::addr={};", server.addr());
    let db = QuestDb::connect(&conf).expect("connect");
    let cursor = db.take_reader().expect("take_reader").query("SELECT 1")
        .execute().expect("execute");

    assert_eq!(cursor.batch_row_count(), 0);
    assert_eq!(cursor.batch_column_count(), 0);
    assert!(cursor.batch_schema().is_none());
    assert!(cursor.batch_column(0).is_err(), "column access must error, not panic");
}
```

If `happy_script` is not `Clone`, derive `Clone` on `Script` in `tests/common/qwp_mock.rs` — the parity test needs two identical servers. Adjust the `ColumnView` match arms to whatever the happy script actually produces; the point is that both paths yield the same value, not which variant it is.

- [ ] **Step 2: Run and watch it fail**

```bash
cargo test --manifest-path questdb-rs/Cargo.toml --test egress_owned owned_batch
```

Expected: FAIL — no method `batch_row_count`.

- [ ] **Step 3: Implement the accessors**

In `questdb-rs/src/egress/owned.rs`:

```rust
impl<O: BorrowMut<Reader>> OwnedCursor<O> {
    /// Rows in the current batch, or 0 before the first `next_batch`.
    pub fn batch_row_count(&self) -> usize {
        self.state.last_batch.as_ref().map_or(0, |b| b.row_count())
    }

    /// Columns in the current batch, or 0 before the first `next_batch`.
    pub fn batch_column_count(&self) -> usize {
        self.state.last_batch.as_ref().map_or(0, |b| b.column_count())
    }

    /// Schema of the current query, or `None` before the first `next_batch`.
    pub fn batch_schema(&self) -> Option<&Schema> {
        self.owner.borrow().query_schema()
    }

    /// Sequence number of the current batch.
    pub fn batch_seq(&self) -> Option<u64> {
        self.state.last_batch.as_ref().map(|b| b.batch_seq())
    }

    /// A view of one column of the current batch.
    ///
    /// This is the owning replacement for going through [`BatchView`]: the
    /// returned view borrows `&self`, so no second handle spanning the cursor
    /// and the reader has to exist.
    pub fn batch_column(&self, idx: usize) -> Result<ColumnView<'_>> {
        let decoded = self.state.last_batch.as_ref().ok_or_else(|| {
            fmt!(InvalidApiCall, "no current batch; call next_batch() first")
        })?;
        let reader = self.owner.borrow();
        decoded.column_view(idx, reader.symbol_dict(), reader.query_schema_or_err()?)
    }
}
```

`Borrow<Reader>` (not just `BorrowMut`) is needed for the `&self` accessors — it was added in Task 4 Step 3. If `DecodedBatch` does not already expose `row_count`/`column_count`/`batch_seq`/`column_view` as used here, add the thin accessors it needs; the data is all present, since `BatchView` reads exactly these fields.

- [ ] **Step 4: Run the tests**

```bash
cargo test --manifest-path questdb-rs/Cargo.toml --test egress_owned
```

Expected: 5 passed.

- [ ] **Step 5: Lint and commit**

```bash
cd ~/claude/wt/cqc/egress-owned-handles
cargo fmt --manifest-path questdb-rs/Cargo.toml
cargo clippy --manifest-path questdb-rs/Cargo.toml --tests
git add questdb-rs/src questdb-rs/tests/egress_owned.rs
git commit -m "feat(egress): batch accessors on OwnedCursor"
```

---

### Task 6: `OwnedArrowReader` — the method that deletes the ADBC driver's unsafe

**Files:**
- Modify: `questdb-rs/src/egress/owned.rs`, `questdb-rs/src/egress/arrow/mod.rs` (export)
- Test: `questdb-rs/tests/egress_owned_arrow.rs`

**Interfaces:**
- Consumes: `OwnedCursor<O>` (Task 4).
- Produces: `OwnedCursor::into_arrow_reader(self) -> Result<OwnedArrowReader<O>>` and `pub struct OwnedArrowReader<O: BorrowMut<Reader>>` implementing `Iterator<Item = Result<RecordBatch, ArrowError>>` and `arrow::array::RecordBatchReader`, and `Send` when `O: Send`.

- [ ] **Step 1: Write the failing test**

`questdb-rs/tests/egress_owned_arrow.rs`:

```rust
#![cfg(all(feature = "sync-reader-qwp-ws", feature = "arrow-egress"))]

#[path = "common/qwp_mock.rs"]
mod qwp_mock;

use qwp_mock::*;
use questdb::QuestDb;
use questdb::egress::ServerRole;
use arrow::array::RecordBatchReader;

/// The exact shape ADBC needs: an owned `Box<dyn RecordBatchReader + Send>`,
/// with a valid schema before iteration, consumed by value.
#[test]
fn boxed_dyn_record_batch_reader_streams_to_completion() {
    let server = MockServer::start(happy_script(ServerRole::Primary, "n1"));
    let conf = format!("ws::addr={};", server.addr());
    let db = QuestDb::connect(&conf).expect("connect");

    let reader: Box<dyn RecordBatchReader + Send> = Box::new(
        db.take_reader().expect("take_reader")
            .query("SELECT 1")
            .execute().expect("execute")
            .into_arrow_reader().expect("into_arrow_reader"),
    );

    // Schema must be available before any iteration.
    assert!(reader.schema().fields().len() > 0, "schema must be known up front");

    let rows: usize = reader.map(|b| b.expect("batch").num_rows()).sum();
    assert!(rows > 0, "expected rows from the happy script");
}

/// Abandoning the stream part-way is what a LIMIT or an error does. It must not
/// panic, and must release the reader back to the pool.
#[test]
fn abandoning_the_stream_releases_the_pooled_reader() {
    let server = MockServer::start(happy_script(ServerRole::Primary, "n1"));
    let conf = format!("ws::addr={};query_pool_max=1;", server.addr());
    let db = QuestDb::connect(&conf).expect("connect");

    {
        let mut reader = db.take_reader().expect("take_reader")
            .query("SELECT 1").execute().expect("execute")
            .into_arrow_reader().expect("into_arrow_reader");
        let _first = reader.next();
        // dropped mid-stream
    }

    // Only succeeds if the abandoned reader was released.
    let _again = db.take_reader().expect("reader must be available again");
}
```

- [ ] **Step 2: Run and watch it fail**

```bash
cargo test --manifest-path questdb-rs/Cargo.toml --features arrow --test egress_owned_arrow
```

Expected: FAIL — no method `into_arrow_reader`.

- [ ] **Step 3: Implement it**

In `questdb-rs/src/egress/owned.rs`:

```rust
#[cfg(feature = "arrow-egress")]
pub struct OwnedArrowReader<O: BorrowMut<Reader>> {
    cursor: OwnedCursor<O>,
    schema: arrow::datatypes::SchemaRef,
    pending: Option<arrow::array::RecordBatch>,
    finished: bool,
}

#[cfg(feature = "arrow-egress")]
impl<O: BorrowMut<Reader>> OwnedCursor<O> {
    /// Consume this cursor as an Arrow [`RecordBatchReader`].
    ///
    /// Blocks until the first batch arrives, because `RecordBatchReader`
    /// requires a schema before iteration; the result's latency is therefore
    /// data-dependent. A statement that yields no batch at all (DDL) gives an
    /// empty schema and an immediately-exhausted stream.
    pub fn into_arrow_reader(mut self) -> Result<OwnedArrowReader<O>> {
        let first = self.next_arrow_batch()?;
        let schema = match &first {
            Some(b) => b.schema(),
            None => std::sync::Arc::new(arrow::datatypes::Schema::empty()),
        };
        let finished = first.is_none();
        Ok(OwnedArrowReader { cursor: self, schema, pending: first, finished })
    }

    /// Next batch as an Arrow `RecordBatch`, or `None` at end of stream.
    pub fn next_arrow_batch(&mut self) -> Result<Option<arrow::array::RecordBatch>> {
        self.state.next_arrow_batch_owned(self.owner.borrow_mut())
    }
}

#[cfg(feature = "arrow-egress")]
impl<O: BorrowMut<Reader>> Iterator for OwnedArrowReader<O> {
    type Item = std::result::Result<arrow::array::RecordBatch, arrow::error::ArrowError>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(b) = self.pending.take() {
            return Some(Ok(b));
        }
        if self.finished {
            return None;
        }
        match self.cursor.next_arrow_batch() {
            Ok(Some(b)) => Some(Ok(b)),
            Ok(None) => { self.finished = true; None }
            Err(e) => {
                self.finished = true;
                Some(Err(arrow::error::ArrowError::ExternalError(Box::new(e))))
            }
        }
    }
}

#[cfg(feature = "arrow-egress")]
impl<O: BorrowMut<Reader>> arrow::array::RecordBatchReader for OwnedArrowReader<O> {
    fn schema(&self) -> arrow::datatypes::SchemaRef {
        self.schema.clone()
    }
}
```

`CursorState::next_arrow_batch_owned(&mut self, reader: &mut Reader)` is the existing `next_arrow_batch_inner` logic with the reader passed in; add it in `reader.rs` beside the other `CursorState` methods.

Note what is *absent*: no `unsafe`, no `ManuallyDrop`, no `transmute`. `OwnedArrowReader` owns `OwnedCursor` which owns the reader, so the ordinary drop glue does the teardown in the right order. That is the entire point of the change.

- [ ] **Step 4: Run the tests**

```bash
cargo test --manifest-path questdb-rs/Cargo.toml --features arrow --test egress_owned_arrow
```

Expected: 2 passed.

- [ ] **Step 5: Assert `Send` at compile time**

Add to `owned.rs`:

```rust
#[cfg(feature = "arrow-egress")]
const _: fn() = || {
    fn assert_send<T: Send>() {}
    assert_send::<OwnedCursor<crate::OwnedReader>>();
    assert_send::<OwnedArrowReader<crate::OwnedReader>>();
};
```

- [ ] **Step 6: Lint and commit**

```bash
cd ~/claude/wt/cqc/egress-owned-handles
cargo fmt --manifest-path questdb-rs/Cargo.toml
cargo clippy --manifest-path questdb-rs/Cargo.toml --tests
git add questdb-rs/src questdb-rs/tests/egress_owned_arrow.rs
git commit -m "feat(egress): OwnedArrowReader, an owned RecordBatchReader"
```

---

### Task 7: The `forbid(unsafe_code)` proof

The goal of this whole change is "no binding hand-rolls `unsafe`". That is a property to enforce mechanically, not a claim to make in a README. This task makes the compiler the proof.

**Files:**
- Create: `questdb-rs/examples/owned_egress_no_unsafe.rs`
- Modify: `questdb-rs/Cargo.toml` (register the example)

**Interfaces:**
- Consumes: everything from Tasks 3-6.
- Produces: a compile-time guarantee. No runtime interface.

- [ ] **Step 1: Write the example**

`questdb-rs/examples/owned_egress_no_unsafe.rs`:

```rust
//! Proof that an owning consumer needs no `unsafe`.
//!
//! This exercises the four shapes that made a hand-rolled self-referential
//! stream undefined behaviour in the ADBC driver before this API existed:
//! dropping by value, consuming by a by-value adaptor, moving across a thread,
//! and boxing as a trait object. `forbid(unsafe_code)` is the assertion — if
//! this file compiles, the property holds, because the compiler proved it.

#![forbid(unsafe_code)]

use arrow::array::RecordBatchReader;
use questdb::QuestDb;

fn main() -> questdb::Result<()> {
    let conf = std::env::args().nth(1).unwrap_or_else(|| "ws::addr=localhost:9000;".to_string());
    let db = QuestDb::connect(&conf)?;

    // 1. Dropped by value inside a call.
    let cursor = db.take_reader()?.query("SELECT 1").execute()?;
    drop(cursor);

    // 2. Consumed by a by-value iterator adaptor.
    let rows: usize = db
        .take_reader()?
        .query("SELECT 1")
        .execute()?
        .into_arrow_reader()?
        .map(|b| b.map(|b| b.num_rows()).unwrap_or(0))
        .sum();
    println!("rows: {rows}");

    // 3. Moved across a thread and consumed there.
    let reader = db.take_reader()?.query("SELECT 1").execute()?.into_arrow_reader()?;
    let n = std::thread::spawn(move || reader.count()).join().unwrap();
    println!("batches: {n}");

    // 4. Boxed as a trait object — the ADBC shape.
    let boxed: Box<dyn RecordBatchReader + Send> =
        Box::new(db.take_reader()?.query("SELECT 1").execute()?.into_arrow_reader()?);
    println!("schema: {}", boxed.schema());

    Ok(())
}
```

- [ ] **Step 2: Register it**

In `questdb-rs/Cargo.toml`, beside the other `[[example]]` entries:

```toml
[[example]]
name = "owned_egress_no_unsafe"
required-features = ["sync-reader-qwp-ws", "arrow-egress"]
```

- [ ] **Step 3: Compile it — this is the test**

```bash
cargo build --manifest-path questdb-rs/Cargo.toml --features arrow --example owned_egress_no_unsafe
```

Expected: compiles. It does not need to be *run* — compilation under `forbid(unsafe_code)` is the whole assertion. If it fails to compile because some shape needs `unsafe`, that is the API still being inadequate, and it is a finding to report rather than to work around by relaxing the lint.

- [ ] **Step 4: Prove the guard is real**

Temporarily add `let _ = unsafe { std::mem::zeroed::<u8>() };` to `main`, rebuild, and confirm the build **fails** with `usage of an `unsafe` block`. Remove it and rebuild clean. A `forbid` that would not have fired proves nothing; report both outcomes.

- [ ] **Step 5: Commit**

```bash
cd ~/claude/wt/cqc/egress-owned-handles
cargo fmt --manifest-path questdb-rs/Cargo.toml
git add questdb-rs/examples questdb-rs/Cargo.toml
git commit -m "test: prove the owning egress API needs no unsafe"
```

---

### Task 8: Migrate `questdb-rs-ffi` off the laundered handles

The C ABI is both the proof the new API is sufficient and the place where the *unsound-capable* subset of `unsafe` is eliminated: 7 lifetime launders, 3 self-referential `ManuallyDrop` slots, and an aliasing invariant maintained by a comment.

It is **not** a reduction in the volume of `unsafe`, and the task must not be judged on one. Measured on `questdb-rs-ffi/src/egress.rs`: `transmute` 7 → 0 and `ManuallyDrop` 14 → 0, while `unsafe {` blocks went 124 → **132** and `unsafe fn` 13 → **20**. The increase is benign — named helpers (`cursor_mut_or_err`, `defer_query_err`, ...) replacing open-coded raw-pointer sites, each small and locally checkable. What remains is irreducible `*mut T → &T` work at the C boundary, which no owning type can remove: a C ABI has raw pointers in its signatures by definition.

**Files:**
- Modify: `questdb-rs-ffi/src/egress.rs` (4,206 lines; 7 `transmute` sites)

**Interfaces:**
- Consumes: everything from Tasks 3-6.
- Produces: an FFI layer with zero lifetime laundering in the egress path. The **public C surface must not change** — `cbindgen` output is a contract with the C, C++, Python and .NET bindings.

- [ ] **Step 1: Record the baseline**

```bash
cd ~/claude/wt/cqc/egress-owned-handles
grep -c transmute questdb-rs-ffi/src/egress.rs
cargo test --manifest-path questdb-rs-ffi/Cargo.toml 2>&1 | grep -E "^test result"
```

Expected: `7`, and a passing test line. Both are acceptance criteria.

- [ ] **Step 2: Replace the query handle**

`qwp_reader_query` currently holds `ManuallyDrop<ReaderQuery<'static>>`. Replace its inner with `OwnedQuery<OwnedReader>`, obtained from `OwnedReader::query(sql)`. The builder methods (`bind`, `initial_credit`, `reset_symbol_dict`) are consuming-and-returning on both types, so the existing `with_query`-style helper that maps `ReaderQuery<'static> -> ReaderQuery<'static>` becomes the same shape over `OwnedQuery`, with no `transmute` and no `ManuallyDrop`.

- [ ] **Step 3: Replace the cursor handle**

`qwp_reader_cursor` currently holds `ManuallyDrop<Cursor<'static>>` plus `current_batch: Option<BatchView<'static>>`. Replace both with a single `OwnedCursor<OwnedReader>`:

- `next_batch` becomes `cursor.next_batch()? -> bool`, storing nothing.
- Every accessor that read through `current_batch` now reads through the cursor: `row_count` → `cursor.batch_row_count()`, `column_count` → `cursor.batch_column_count()`, `column(i)` → `cursor.batch_column(i)`, `schema` → `cursor.batch_schema()`, `batch_seq` → `cursor.batch_seq()`.
- The `cursor_for_mut` / `cursor_for_aux` chokepoints that existed to keep the laundered `BatchView` valid against a re-borrow of the `Cursor` are no longer needed — the borrow they were protecting against does not exist once the batch is reached through `&self`.
- `_free` drops the `OwnedCursor` normally; the explicit view→cursor→box teardown ordering goes away because ordinary drop glue now does it.

- [ ] **Step 4: Verify the C surface did not move**

```bash
cd ~/claude/wt/cqc/egress-owned-handles
git stash && cbindgen --config cbindgen.toml --crate questdb-rs-ffi --output /tmp/questdb_before.h 2>/dev/null
git stash pop && cbindgen --config cbindgen.toml --crate questdb-rs-ffi --output /tmp/questdb_after.h 2>/dev/null
diff /tmp/questdb_before.h /tmp/questdb_after.h && echo "C ABI UNCHANGED"
```

Expected: `C ABI UNCHANGED`. If `cbindgen` is not installed, do not install it — instead diff `include/questdb/ingress/line_sender.h` (or whichever header this repo commits) against `git show HEAD:` of the same path, and say in your report which method you used.

**If the C batch surface genuinely cannot be preserved, stop and report it.** Do not reintroduce a laundered handle to keep a signature — that would defeat the entire change.

- [ ] **Step 5: Verify the laundering is gone**

```bash
grep -c transmute questdb-rs-ffi/src/egress.rs
grep -c "ManuallyDrop" questdb-rs-ffi/src/egress.rs
```

Expected: `0` transmutes in the egress path. Any remaining `ManuallyDrop` must be justified in your report — some may be unrelated to the borrow chain.

- [ ] **Step 6: Run the FFI and system tests**

```bash
cargo test --manifest-path questdb-rs-ffi/Cargo.toml 2>&1 | grep -E "^test result|FAILED"
cargo test --manifest-path questdb-rs/Cargo.toml 2>&1 | grep -E "^test result|FAILED"
```

Expected: all pass, matching the Step 1 baseline.

- [ ] **Step 7: Lint and commit**

```bash
cd ~/claude/wt/cqc/egress-owned-handles
cargo fmt --manifest-path questdb-rs-ffi/Cargo.toml
cargo clippy --manifest-path questdb-rs-ffi/Cargo.toml --tests
git add questdb-rs-ffi/src/egress.rs
git commit -m "refactor(ffi): drop lifetime laundering, use the owning egress API"
```

---

## Completion

The change is done when, from the worktree root:

```bash
cargo test --manifest-path questdb-rs/Cargo.toml
cargo test --manifest-path questdb-rs/Cargo.toml --features almost-all-features,arrow,polars
cargo test --manifest-path questdb-rs-ffi/Cargo.toml
cargo build --manifest-path questdb-rs/Cargo.toml --features arrow --example owned_egress_no_unsafe
grep -c transmute questdb-rs-ffi/src/egress.rs   # expect 0
git diff --stat origin/main -- questdb-rs/src/egress/mod.rs   # expect additions only
```

all succeed, and no pre-existing test file was modified to make them pass.

Then, per spec §9.4, run the soak harness described in `doc/QWP_SOAK_HARNESS.md`
against both the borrowing and the owning paths. Failover is the part of this
change least covered by unit tests, and the soak harness is the only thing that
exercises it under sustained load. Report the result; if the harness cannot be
run in this environment, say so explicitly rather than silently skipping it —
an unrun soak is a known gap, not a pass.

**Do not push.** Report the state and stop.

## Follow-on, explicitly not in this plan

Once this lands, the ADBC driver in `adbc-drivers/questdb` can delete
`rust/src/result_stream.rs` (611 lines, 11 `unsafe` blocks) and implement
`Statement::execute` as `Ok(Box::new(cursor.into_arrow_reader()?))`. That is a
change to a different repository and gets its own plan.
