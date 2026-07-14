# Unified QWP Ingress Sender Design

**Status:** proposal

**Audience:** Rust core, C FFI, C++ wrapper, Python wrapper, and client API
reviewers

**Scope:** the pooled QWP/WebSocket ingestion API rooted at `QuestDb`

**Supersedes:** the decisions in
`historical/COLUMN_SENDER_PLAN.md` that made replacing
the row sender and sharing its publisher explicit non-goals. The performance
requirements and the separate row and bulk-column encoders remain valid.

---

## 1. Summary

`QuestDb` should expose one borrowed store-and-forward ingestion sender, not a
row sender and a column sender.

The unified sender accepts several payload representations:

- `Buffer`: owned data assembled incrementally through the row API;
- `Chunk<'a>`: borrowed typed column slices;
- Arrow `RecordBatch`: a complete columnar batch;
- higher-level dataframe adapters built on the Arrow or chunk paths.

The payload representations remain separate because they have different
ownership and validation contracts. They share one connection, one
store-and-forward publisher, one symbol dictionary, one frame-sequence stream,
and one ACK lifecycle.

The public distinction becomes:

- **store-and-forward sender:** accepts buffers, chunks, and Arrow batches;
- **direct dataframe path:** retains the caller's complete source and owns
  checkpointing and replay;
- **reader:** executes queries and streams results.

Row-major versus column-major is an input and encoder concern. It is not a
sender or pool concern.

## 2. Current state

`QuestDb` currently maintains four independent resource pools when all features
are enabled:

| Pool | Public entry point | Input | Delivery mode |
|---|---|---|---|
| Store-and-forward column sender | `borrow_column_sender()` | `Chunk`, Arrow | Store-and-forward |
| Row sender | `borrow_row_sender()` | `Buffer` | Store-and-forward |
| Direct column sender | Hidden; used by `flush_arrow_batch()` and `flush_polars_dataframe()` | Arrow/dataframe | Direct with caller-owned replay |
| Reader | `borrow_reader()` | Query | Streaming egress |

The two public ingestion senders expose nearly identical lifecycle operations:

- publish and clear the input;
- publish and return an FSN;
- publish and wait for an ACK level;
- inspect published and acknowledged watermarks;
- wait for a watermark;
- force retirement rather than recycling on return;
- return a healthy handle to its pool on `Drop`.

Their intended semantic difference is the accepted payload type. They also
differ today in construction and edge behavior: the row pool rebuilds a
standalone `Sender`, the column SFA pool can lend a local producer before an
endpoint is available, and Chunk/Arrow inputs can split oversized batches
while Buffer cannot. Those contracts must be reconciled explicitly, but they
do not require separate sender identities. Separate connection pools, slot
namespaces, recovery paths, reaper bookkeeping, and FFI handles are
implementation consequences rather than QWP wire requirements.

The QWP/WebSocket `Buffer` already demonstrates that API orientation and wire
orientation need not match: callers populate it row by row, while
`QwpWsColumnarBuffer` stores and encodes the result in the column-major QWP wire
format.

## 3. Problem

The current API turns an implementation history into a user-facing concept:

```text
borrow_row_sender()       -> Buffer
borrow_column_sender()    -> Chunk / Arrow
```

That split creates several problems:

1. Users must choose a sender based on the shape of data already in memory,
   even though both senders publish to the same QWP endpoint with the same
   store-and-forward and ACK model.
2. `pool_max` is enforced independently, so configuring one logical database
   client can produce separate row and column connection populations.
3. Disk-backed store-and-forward requires separate `-row-N` and `-col-N` slot
   namespaces and separate recovery bookkeeping.
4. Symbol dictionary, persistence, rollback, frame publication, wait, and error
   behavior are implemented twice.
5. Every binding must expose two borrow types and duplicate the same progress
   surface.
6. Higher-level clients inherit a misleading row-sender versus column-sender
   mental model even when they never manipulate a sender directly.

The wire does not require this split. Both encoders produce QWP/WebSocket
ingress payloads and both store-and-forward paths ultimately append those
payloads to the same queue/driver design.

## 4. Goals

- Expose one pooled store-and-forward sender for all QWP ingress payloads.
- Preserve the zero-copy `Chunk<'a>` and Arrow fast paths.
- Preserve the incremental row-building `Buffer` API.
- Preserve existing Buffer clear/keep, error, and retry contracts.
- Use one connection-scoped symbol-ID namespace across all payload shapes.
- Use one store-and-forward queue, FSN stream, ACK stream, error state, and
  pooled slot per borrowed sender.
- Enforce one `pool_max` cap for store-and-forward ingestion regardless of
  input shape.
- Remove the pooled row-sender implementation and its Rust, FFI, and C++
  public surfaces.
- Keep direct dataframe ingestion separate where the caller retains the source
  and owns checkpoint/replay policy.
- Make the common high-level path `QuestDb`/`Client` operations rather than
  exposing transport-oriented handles unnecessarily.
- Move pooled row-building ingestion onto the QWP path; preserving the Buffer
  API does not imply preserving ILP as its transport.

## 5. Non-goals

- Do not convert a `Buffer` into a `Chunk` before publication.
- Do not copy borrowed dataframe columns into an owned `Buffer`.
- Do not merge readers into the ingestion sender.
- Do not remove the standalone, multi-transport `ingress::Sender` in this
  change. Deprecating its ILP modes and removing their compatibility surface is
  a separate product decision; the unified pooled API is QWP-only and must not
  add new dependencies on ILP.
- Do not make the public store-and-forward sender implement direct dataframe
  retry policy.
- Do not introduce a new QWP wire message or server capability.
- Do not promise transactional multi-table ingestion beyond the existing
  QWP/WebSocket frame semantics.
- Do not preserve names or compatibility aliases for an unreleased pooled API
  merely to mirror the old split.

## 6. Design decisions

### 6.1 One public pooled ingestion lease

Replace:

```rust
QuestDb::borrow_row_sender() -> BorrowedRowSender<'_>
QuestDb::borrow_column_sender() -> BorrowedColumnSender<'_>
```

with:

```rust
QuestDb::borrow_sender() -> BorrowedSender<'_>
```

`BorrowedSender` is lifetime-bound to `QuestDb`, is neither `Send` nor `Sync`,
and returns a healthy sender to the ingestion pool on `Drop`.

The internal type should no longer be called `ColumnSender` once it accepts
both buffers and columnar batches. Suggested internal names are
`PooledSenderCore`, `QwpIngressSender`, or `SenderCore`. The public name should
describe its role, not its original encoder.

### 6.2 Keep payload representations specialized

`Buffer` and `Chunk<'a>` should not be merged.

`Buffer`:

- owns appended values;
- is assembled one cell and one row at a time;
- can contain multiple tables;
- can hold an incomplete row;
- supports bookmark, rewind, clear, clone, and keep-after-flush behavior;
- can outlive the sender from which it was created.

`Chunk<'a>`:

- borrows caller-owned typed column arrays;
- locks its row count from the first column or timestamp source;
- targets one table;
- requires equal logical lengths;
- is valid only while every borrowed array remains alive;
- can split into zero-copy row ranges when a frame exceeds the negotiated cap.

These are valid reasons for two batch types and two encoders. They are not
reasons for two sender leases or two store-and-forward pools.

### 6.3 Explicit shape-specific methods

Rust cannot overload methods by argument type. The unified API should use
explicit names rather than a public generic ingestion trait in the first
version:

```rust
impl BorrowedSender<'_> {
    pub fn flush_buffer(&mut self, buffer: &mut Buffer) -> Result<()>;
    pub fn flush_buffer_and_keep(&mut self, buffer: &Buffer) -> Result<()>;
    pub fn flush_buffer_and_get_fsn(
        &mut self,
        buffer: &mut Buffer,
    ) -> Result<Option<u64>>;
    pub fn flush_buffer_and_keep_and_get_fsn(
        &mut self,
        buffer: &Buffer,
    ) -> Result<Option<u64>>;
    pub fn flush_buffer_and_wait(
        &mut self,
        buffer: &mut Buffer,
        ack_level: AckLevel,
    ) -> Result<()>;

    pub fn flush_chunk(&mut self, chunk: &mut Chunk<'_>) -> Result<()>;
    pub fn flush_chunk_and_get_fsn(
        &mut self,
        chunk: &mut Chunk<'_>,
    ) -> Result<Option<u64>>;
    pub fn flush_chunk_and_wait(
        &mut self,
        chunk: &mut Chunk<'_>,
        ack_level: AckLevel,
    ) -> Result<()>;

    #[cfg(feature = "arrow-ingress")]
    pub fn flush_arrow_batch_at_now(/* existing arguments */) -> Result<()>;

    #[cfg(feature = "arrow-ingress")]
    pub fn flush_arrow_batch_at_column(/* existing arguments */) -> Result<()>;

    pub fn published_fsn(&self) -> Result<Option<u64>>;
    pub fn acked_fsn(&self) -> Result<Option<u64>>;
    pub fn wait(&mut self, ack_level: AckLevel, timeout: Duration) -> Result<()>;
    pub fn drop_on_return(&mut self);
}
```

Shape-specific names keep differences such as `flush_buffer_and_keep` and
chunk splitting visible. A sealed internal trait may remove implementation
duplication later without becoming part of the public contract.

### 6.4 Buffer creation belongs to `QuestDb`

Creating a QWP/WebSocket buffer does not require a live connection or an
exclusive sender lease. Add:

```rust
impl QuestDb {
    pub fn new_buffer(&self) -> Buffer;
}
```

It constructs a QWP/WebSocket buffer with the pool's configured name limit.
`BorrowedSender::new_buffer()` may remain as a convenience delegating to the
pool, but the ownership documentation must state that the returned buffer is
caller-owned and is not tied to that borrowed sender.

Store the small Buffer-factory configuration (at minimum `max_name_len`) on
`DbInner`; do not retain `SenderBuilder` merely to manufacture buffers after
the row pool is removed.

The unified sender accepts only the QWP/WebSocket `Buffer` variant. Passing an
ILP or QWP/UDP buffer returns `InvalidApiCall` without modifying it.

### 6.5 One connection-scoped symbol namespace

This is the central correctness requirement.

The current SFA connector creates a row replay encoder with a
`SymbolGlobalDict`. The store-and-forward column backend transfers the
persisted symbol state, seeds its own dictionary, then clears the dormant row
dictionary. That hand-off is safe only because the resulting physical sender
never alternates row and column encoders.

The unified sender must own exactly one symbol state above every encoder:

```rust
struct SymbolPublishState {
    global: SymbolGlobalDict,
    persisted: Option<PersistedSymbolDict>,
    delta_enabled: bool,
}
```

Every Buffer, Chunk, and Arrow frame on a sender uses this state. Alternating
payload shapes must produce one monotonically growing symbol-ID namespace, and
the background catch-up mirror must observe the same deltas.

### 6.6 One transactional publish primitive

Extract the common store-and-forward foreground publication transaction:

1. Check the sender's terminal/error state.
2. Mark the in-memory symbol dictionary.
3. Mark the persisted symbol side-file, when enabled.
4. Ask the selected encoder to write one QWP payload while mutating the shared
   symbol dictionary.
5. Check the encoded size against the effective server/client limit.
6. Persist newly introduced symbols before publishing the frame.
7. Append the payload to the store-and-forward queue and obtain its FSN.
8. On encode, size, persistence, or publication failure, roll the in-memory
   dictionary and side-file back to their marks.
9. On success, commit the payload-specific mutation: clear the mutable input
   when required and optionally wait for the requested ACK level.

Conceptually:

```rust
fn encode_persist_publish(
    &mut self,
    encode: impl FnOnce(
        &mut Vec<u8>,
        &mut SymbolGlobalDict,
        bool, // delta dictionary mode
    ) -> Result<()>,
) -> Result<u64>;
```

The actual implementation may split borrows into smaller structs to satisfy
Rust's aliasing rules. The invariant matters more than the exact closure shape:
dictionary mutation, persistence, payload append, and rollback form one
transaction for every encoder.

**Decision: the unified core bypasses `QwpWsReplayEncoder`.** That encoder
remains untouched as the transaction engine for the standalone
`ingress::Sender` QWP paths (`flush_qwp_ws` and manual driving) and as the
synchronous validator of the recovered symbol dictionary during async connect;
the pooled core releases its dormant dictionary at construction, exactly as
today, and never touches it afterwards. The pooled core instead calls
`encode_ws_replay_message_with_defer()` directly against its own shared symbol
state and a retained `QwpWsEncodeScratch`. So the rollback/write-ahead
transaction exists exactly twice, with unambiguous owners: the unified pooled
core and the standalone encoder — the latter keeps its existing regression
tests.

To keep every encoder writing into the shared retained payload without a copy,
`encode_ws_replay_message_with_defer()` changes signature to take its output
vector as a separate `&mut Vec<u8>` parameter instead of writing into
`QwpWsEncodeScratch`'s internal message buffer. The pooled path always uses
async connect, so buffer encoding uses the same fixed QWP version the dormant
encoder is constructed with today.

### 6.7 Keep encoder-specific scratch storage

The unified sender can retain both scratch allocations:

```rust
struct EncoderScratch {
    buffer: QwpWsEncodeScratch,
    chunk: column_sender::encoder::EncodeScratch,
    payload: Vec<u8>,
}
```

`Buffer` publication calls
`QwpWsColumnarBuffer::encode_ws_replay_message_with_defer()`.

`Chunk` publication calls `encode_chunk_into()` or
`encode_chunk_replay_into()`.

Arrow publication continues through its metadata-aware classifier and encoder.

No input is normalized through another public input type. This preserves the
columnar performance path and the row API's multi-table and sparse-row behavior.

### 6.8 Delivery mode, not input orientation, defines pool separation

Keep two internal ingestion pool kinds:

1. **Store-and-forward ingestion pool**
   - returned by `QuestDb::borrow_sender()`;
   - accepts Buffer, Chunk, and Arrow payloads;
   - publishes each accepted frame into the local queue;
   - exposes FSN and ACK watermarks;
   - uses in-memory storage without `sf_dir` and disk-backed storage with it.

2. **Direct ingestion pool**
   - hidden from the normal public API;
   - used by `QuestDb::flush_arrow_batch()` and
     `QuestDb::flush_polars_dataframe()`;
   - pipelines deferred frames and explicit commit boundaries;
   - relies on the caller-owned complete source for checkpoint/re-drive logic;
   - remains independent of `sf_dir`.

Readers retain their independent pool. With the row pool removed, a fully
featured `QuestDb` has at most three independently capped resource kinds:
store-and-forward ingestion, direct ingestion, and readers.

### 6.9 One store-and-forward slot namespace

Replace separate managed directories:

```text
<sender-id>-row-N
<sender-id>-col-N
```

with:

```text
<sender-id>-ingest-N
```

The unified recovery scanner, managed-slot exclusions, reaper, and close path
operate on that one namespace.

**Decision:** the pooled API and its managed slot names are unreleased — they
exist only on the development branch and are absent from the last released
tag — so `-ingest-N` is adopted with no compatibility or adoption path for old
`-row-N`/`-col-N` slots. A stale development slot is ignored by the new
scanner and can be wiped manually.

### 6.10 Background progress remains the pooled contract

The unified store-and-forward pool uses the background QWP runner. A pooled
sender must be borrowable while its endpoint is unavailable so callers can
append to the local queue.

`QuestDb::connect()` already rejects `qwp_ws_progress=manual`. Preserve that
contract for the unified sender. Manual driving remains available through the
standalone QWP `ingress::Sender` until a separate design supplies a pool-safe
scheduler. Removing the separately constructed row sender also removes another
place where pooled behavior could drift from the common background-progress
contract.

## 7. Target architecture

```text
                         QuestDb
                            |
             +--------------+---------------+
             |                              |
     borrow_sender()                whole-source operations
             |                              |
      BorrowedSender                 hidden direct sender
             |                              |
   +---------+----------+             +-----+------+
   |         |          |             |            |
 Buffer    Chunk      Arrow       RecordBatch   DataFrame
 encoder   encoder    encoder        encoder       adapter
   |         |          |             |            |
   +---------+----------+             +-----+------+
             |                              |
     shared SFA publisher             direct publisher
             |                              |
       local replay queue               QWP/WebSocket
             |
       QWP/WebSocket
```

The store-and-forward sender owns one stream of connection-scoped state:

```text
symbol IDs + persisted symbol side-file + FSNs + ACK watermarks + errors
```

That state is never duplicated per payload orientation.

## 8. Behavioral contract

### 8.1 Common publication semantics

For every accepted payload shape:

- `flush_*` returns after local store-and-forward acceptance, not server ACK;
- `flush_*_and_get_fsn` returns the final FSN covering that logical payload;
- `flush_*_and_wait` publishes and then waits for the requested ACK level;
- `wait` is a barrier for everything previously published on that borrowed
  sender;
- FSNs are stream-local watermarks and are meaningful only on the sender stream
  that produced them;
- terminal state or `drop_on_return()` prevents recycling;
- a healthy sender is returned to the pool on `Drop` while its background
  runner continues delivering queued frames.

### 8.2 Buffer-specific behavior

- Reject an incomplete row before encoding.
- Treat an empty Buffer as no new publication.
- Preserve multi-table frames.
- `flush_buffer` clears only after local publication succeeds.
- `flush_buffer_and_keep` never clears the caller's Buffer.
- `flush_buffer_and_wait` clears after local publication succeeds even if the
  subsequent wait fails, matching the existing publish-then-wait contract.
- Preserve bookmark/rewind state according to existing Buffer rules.
- Preserve the existing too-large behavior until Buffer range splitting is
  designed separately; do not silently change a single Buffer publication into
  partially accepted frames.

### 8.3 Chunk-specific behavior

- Preserve one-table and equal-row-count validation.
- Preserve zero-copy row slicing when a frame exceeds the negotiated cap.
- Clear the Chunk after the complete logical chunk has been locally accepted.
- If a split prefix has been accepted and a later split fails, surface the
  existing partial-publication/delivery-unknown classification. Never report
  the original Chunk as safe for a blind retry.

### 8.4 Arrow-specific behavior

- Preserve type-width inference, schema metadata overrides, validity handling,
  and timestamp-source selection.
- Preserve Arrow C Data Interface ownership and retry-restoration contracts.
- Keep one-call Arrow/DataFrame operations on the direct path unless the caller
  explicitly borrows the store-and-forward sender.

### 8.5 Mixed-shape behavior

The following sequence is supported on one borrowed sender:

```text
Buffer -> Chunk -> Arrow -> Buffer -> wait
```

Its FSNs are monotonically increasing, `wait` covers the whole sequence, and a
symbol first introduced by any input shape has the same ID when referenced by
all later shapes. Reconnect and process-restart recovery preserve that property.

## 9. Rust API migration

### Remove

- `QuestDb::borrow_row_sender()`
- `BorrowedRowSender`
- `OwnedRowSender`
- `PooledRowSender`
- row-pool return/reborrow helpers
- row-pool debug counts

### Rename or internalize

- `QuestDb::borrow_column_sender()` -> `QuestDb::borrow_sender()`
- `BorrowedColumnSender` -> `BorrowedSender`
- internal `ColumnSender` -> a generic QWP ingestion sender core
- `ColumnSenderHandle` -> `SenderHandle`

Because this is an unreleased API, perform direct removals/renames rather than
keeping aliases that perpetuate the old model.

### Retain

- `Chunk`, `Validity`, `ArrowColumnOverride`, and column encoder modules;
- `Buffer` and its row-building API;
- `QuestDb::flush_arrow_batch()` and `flush_polars_dataframe()`;
- the standalone `ingress::Sender` outside the pooled QWP API.

## 10. Pool and recovery migration

Delete from `DbInner`:

- `row_sender_builder` once connector construction no longer depends on it;
- `row_sender_state`;
- `row_cv`;
- row slot reservations and row-specific close guards.

Fold into the unified ingestion pool:

- Buffer publication;
- mixed Buffer/Chunk/Arrow symbol state;
- recovery of all store-and-forward ingress frames;
- one set of free, in-use, closing, and reserved slot counters;
- one reaper and close-drain path;
- one `pool_max` cap.

The hidden direct pool remains separate because its commit and replay ownership
are materially different. The reader pool remains separate so query load cannot
starve ingestion.

## 11. C FFI design

The C ABI should expose one pooled QWP sender handle. Suggested naming:

```c
typedef struct qwp_sender qwp_sender;

qwp_sender *questdb_db_borrow_sender(
        questdb_db *db,
        line_sender_error **err_out);

line_sender_buffer *questdb_db_new_buffer(
        const questdb_db *db,
        line_sender_error **err_out);

bool qwp_sender_flush_buffer(
        qwp_sender *sender,
        line_sender_buffer *buffer,
        line_sender_error **err_out);

bool qwp_sender_flush_chunk(
        qwp_sender *sender,
        column_sender_chunk *chunk,
        line_sender_error **err_out);
```

The exact prefix may change during API review, but it must not call the unified
handle `row_sender` or `column_sender`.

Remove the pooled `row_sender_*` functions and the owned Rust row-sender escape
hatch. Keep `column_sender_chunk_*` names because those functions manipulate a
column-shaped payload, not a sender identity.

FFI-owned handles continue to carry `Arc<DbInner>` so they can be released
safely after the public `questdb_db*` is closed. The normal Rust handle remains
lifetime-bound and cannot outlive `QuestDb`.

## 12. C++ design

Expose one RAII lease:

```cpp
auto sender = pool.borrow_sender();
sender.flush(buffer);
sender.flush(chunk);
sender.wait(qwpws_ack_level::ok, timeout);
```

C++ overloads can use the same `flush` name because the payload types differ.
The wrapper must not expose a raw pointer/reference that can escape the lease.
Moved-from and returned leases remain invalid and safe to destroy.

Remove `borrowed_row_sender`, `borrow_row_sender()`, and their retry variants.
Rename the existing borrowed column wrapper to the generic borrowed sender.

## 13. Python implications

The target Python model has one connection-owning root:

- `Client.query()` queries;
- `Client.dataframe()` ingests a complete dataframe through the hidden direct
  path;
- `Client.sender()` (final name subject to Python API review) returns a
  row-building lease backed by the unified store-and-forward sender.

For example:

```python
with Client.from_conf("ws::addr=localhost:9000;") as client:
    with client.sender() as sender:
        sender.row("weather", columns={"temperature": 21.5}, at=ServerTimestamp)

    client.dataframe(frame, table_name="weather", at="ts")
    result = client.query("select * from weather")
```

The Python client does not expose Buffer-versus-Chunk sender types. Migrate
row-building ingestion from the standalone ILP path to `Client.sender()`, which
borrows the unified FFI sender and flushes QWP/WebSocket buffers through it.
This retains the familiar row-building API while changing transport,
connection ownership, and publication machinery. The standalone
multi-transport `Sender` remains a compatibility surface in this proposal, but
new examples and recommendations use the QWP `Client` root.

The `Client.sender()` lease participates in the Client's active-use count for
its full context-manager lifetime. `Client.close()` therefore waits for an
orderly return, while the FFI handle's `Arc<DbInner>` remains the final
use-after-free guard. The leased row builder does not expose a dataframe
method.

`Sender.dataframe()` and `Buffer.dataframe()` should not be implemented by
feeding a dataframe through the row Buffer. Their separate deprecation and
removal plan points dataframe users to `Client.dataframe()` and prevents the
slow dataframe-to-rows-to-columnar round trip from returning.

The Python repository already has a deprecation pattern: emit
`DeprecationWarning` with `stacklevel=2`, test the warning, mark the API as
deprecated in its docstring, and list the replacement in the changelog. Follow
that pattern for at least one published release before removal unless these
APIs are confirmed unreleased. The warning text must name `Client.dataframe()`
as the replacement and state the planned removal release once chosen.

## 14. Milestones

Each milestone must leave the repository buildable and testable. Do not remove
the old row pool until Buffer publication through the unified sender has full
contract and recovery coverage.

### Milestone 0: Freeze contracts and baselines

**Work**

- Confirm that the pooled row/column API and managed slot names are unreleased.
- Update `historical/COLUMN_SENDER_SFA_ROW_TEST_INVENTORY.md` into a
  cross-shape migration
  inventory covering Rust, C, C++, Python, tests, examples, and docs that
  mention `BorrowedRowSender`, `BorrowedColumnSender`, or pooled
  `row_sender_*` APIs.
- Include the soak infrastructure in that inventory: `soak.py`'s
  `row_sender` pool-counter keys, the Rust workload legs, and the CI soak
  pipeline. Row-pool tests and the row workload leg are retargeted, not
  deleted: the leg becomes a buffer-flush leg on the unified sender (feeding
  Milestone 6's mixed-shape soak), and the row-pool contract tests migrate to
  buffer-through-unified-sender equivalents that become Milestone 2's exit
  proof.
- Record the current Buffer, Chunk, and Arrow publication/error matrices.
- Record row and column store-and-forward throughput, allocation, and queue
  latency baselines.
- Decide the final public Rust and C names.

**Exit criteria**

- A checked-in inventory identifies every public and test-only surface to
  migrate.
- Golden wire payloads exist for equivalent Buffer and Chunk data.
- Baseline mixed-symbol fixtures and performance numbers are reproducible.
- Any compatibility requirement for existing disk slots is explicitly decided
  (resolved in Section 6.9: none).

### Milestone 1: Extract shared symbol/publication state

**Work**

- Move `SymbolGlobalDict`, persisted side-file ownership, delta-mode state,
  mark/persist/rollback, and payload publication into a shared SFA foreground
  component.
- Adapt the current column Chunk and Arrow paths to use it without changing
  their public API. The Arrow SFA path currently inlines its own copy of the
  transaction rather than sharing the chunk primitive; folding it in is
  explicitly in scope.
- Do not adapt the row replay encoder: the pooled row path dies in
  Milestone 4, and the standalone `ingress::Sender` deliberately keeps
  `QwpWsReplayEncoder` as its own transaction owner (Section 6.6).
- Remove duplicated dictionary write-ahead and rollback implementations within
  the pooled path (Buffer, Chunk, Arrow share one primitive).

**Exit criteria**

- Existing row and column tests pass unchanged.
- Injected failures at encode, size check, side-file append, and queue append
  roll back both in-memory and persisted symbol state.
- Column throughput shows no material regression against Milestone 0.
- Recovery and catch-up tests prove that the driver's symbol mirror stays in
  lockstep.

### Milestone 2: Publish Buffer through the column sender core

**Work**

- Add Buffer encoding to the current column sender backend using
  `encode_ws_replay_message_with_defer()`.
- Add Buffer flush, keep, FSN, and wait variants.
- Add `QuestDb::new_buffer()` and make configured name limits available without
  borrowing a sender.
- Store the Buffer-factory settings directly on `DbInner` so this path does not
  depend on the legacy `SenderBuilder`.
- Reject non-QWP/WebSocket Buffer variants before modifying them.

**Exit criteria**

- Buffer behavior matches the old `BorrowedRowSender` for empty, incomplete,
  single-table, multi-table, keep, clear, too-large, and failure cases.
- FSN and ACK semantics match the existing row pool.
- Buffer publication inherits the column SFA pool's offline-first borrow: an
  unavailable endpoint does not prevent local acceptance while queue capacity
  remains.
- A Buffer can be created, filled, moved between threads where its own type
  permits, and flushed by a different borrowed sender without origin coupling.
- No Buffer-to-Chunk conversion or per-cell replay is introduced.

### Milestone 3: Prove mixed-input correctness

**Work**

- Exercise Buffer, Chunk, and Arrow frames alternately on one sender.
- Cover symbols introduced and reused across every orientation.
- Cover reconnect, failover, disk recovery, orphan draining, queue pressure,
  ACK timeouts, and terminal server errors.
- Cover mixed payloads around pool return and reborrow.

**Exit criteria**

- Symbol IDs remain consistent across mixed input shapes before and after
  reconnect/restart.
- FSNs remain monotonic and one `wait` covers the mixed sequence.
- No later borrower inherits uncommitted direct frames or terminal state.
- Disk-backed recovery replays mixed frames without torn-dictionary errors.

### Milestone 4: Cross-surface cutover (Rust API + C FFI + C++)

This milestone is atomic across Rust, C FFI, and C++ because
`questdb-rs-ffi` builds directly against the renamed Rust symbols. A Rust-only
rename would therefore make the FFI crate—and consequently the C and C++
build—unbuildable. Introducing `borrow_sender()` alongside a still-living row
pool would also create an intermediate three-ingestion-pool state with no user.
The unified Rust API, FFI ABI, C++ wrapper, and row-pool removal therefore land
together, with direct renames and removals rather than aliases or compatibility
wrappers.

**Work**

- Add `BorrowedSender` and `QuestDb::borrow_sender()` with the shape-specific
  methods described in Section 6.3.
- Remove `BorrowedRowSender`, `OwnedRowSender`, and `PooledRowSender`.
- Remove `row_sender_state`, `row_cv`, row reaper/recovery branches, and
  row-specific pool counters.
- Consolidate managed SFA slots under `-ingest-N`.
- Update pool close, reap, debug-count, and exhaustion messages.
- Move public documentation and examples to the unified model.
- Keep the existing `QuestDb::connect()` rejection of manual QWP/WebSocket
  progress covered by a contract test.
- Introduce the unified opaque FFI handle and Buffer/Chunk flush functions.
- Remove pooled `row_sender_*` FFI functions and old owned row handles.
- Rename the C++ lease and pool borrow methods.
- Update ABI declarations, generated headers if any, examples, and tests.

**Exit criteria**

- Every pooled ingestion example uses `borrow_sender()`.
- Rustdoc no longer teaches row and column sender selection.
- `rg` finds no pooled row-sender types or row/column managed-slot split outside
  historical documents.
- `pool_max` caps all public SFA ingestion regardless of payload shape.
- Close/reap tests cover idle, borrowed, delivering, terminal, and disk-locked
  unified senders.
- With readers enabled, documented maximum connection counts match the three
  remaining independently capped pool kinds.
- Feature combinations without Arrow or Polars still build the Buffer/Chunk
  core appropriately.
- Compile-fail tests pin lifetime and `!Send`/`!Sync` behavior.
- C and C++ smoke tests send both a Buffer and a Chunk through one borrowed
  sender.
- Compile-fail probes prevent handles or raw references from escaping their
  lease wrappers.
- Exported symbol inspection shows no unintended old pooled row symbols.
- Closing the pool before releasing an FFI-owned sender remains safe and
  deterministic.

### Milestone 5: Adopt in Python and remove slow dataframe routing

**Work**

- Bind the unified pooled sender and expose it through `Client.sender()` (or
  the final reviewed name) for QWP row-building use.
- Move recommended Python row ingestion from the standalone ILP route to
  QWP/WebSocket buffers without changing its row-at-a-time user model.
- Keep `Client.dataframe()` on the direct whole-source path.
- Deprecate `Sender.dataframe()` and `Buffer.dataframe()` with migration
  guidance to `Client.dataframe()`.
- Do not expose Chunk or sender-orientation choices in the Python user model.

**Exit criteria**

- Python row ingestion and dataframe ingestion both use their intended QWP
  paths with no dataframe-to-row-to-column conversion.
- One `Client` configuration can query, ingest a dataframe, and lend a
  row-building sender without exposing row-versus-column connection choices.
- Deprecation tests assert `DeprecationWarning`, `stacklevel=2`, and replacement
  text; the changelog, README, and migration guide identify the replacement
  and removal release.
- Python integration tests cover query plus row ingestion plus dataframe
  ingestion through one `Client` configuration.

### Milestone 6: Performance, soak, and documentation closure

The implementation owner explicitly relaxed the full-duration soak gate on
2026-07-14. Milestone closure uses the completed 33-minute-40-second mixed
observation plus a complete short-run oracle pass, and must identify the late
fault episodes that the shortened observation did not reach. This changes only
the soak duration; the performance, correctness, bounded-state, language
surface, and documentation criteria below still apply.

**Work**

- Re-run the Milestone 0 performance suite.
- Run long-lived mixed Buffer/Chunk/Arrow store-and-forward soak tests.
- Move `COLUMN_SENDER_PLAN.md`, `COLUMN_SENDER_STORE_AND_FORWARD.md`, the FFI
  design records, and the frozen migration inventory under `doc/historical/`;
  update live source documentation and examples that described separate
  sender pools.
- Document only payload orientation and delivery mode, not row/column sender
  identities.

**Exit criteria**

- Columnar throughput has no material regression from the pre-unification
  baseline.
- Row-buffer throughput is no worse than the existing pooled row path.
- No unbounded pool, queue, dictionary, or scratch-buffer growth appears in
  soak testing.
- All supported language surfaces present one coherent sender model.

## 15. Validation matrix

At minimum, the final change must cover:

| Area | Required cases |
|---|---|
| Buffer validation | empty, incomplete row, duplicate column, multiple tables, all scalar types, null/omitted values |
| Buffer ownership | clear, keep, clone, bookmark/rewind, create without borrow, flush from another borrow |
| Chunk validation | empty, mismatched lengths, timestamp sources, nullable columns, oversize splitting |
| Arrow | supported types, metadata overrides, import ownership, retry restoration, oversize splitting |
| Mixed symbols | Buffer-to-Chunk, Chunk-to-Buffer, Arrow-to-both, reconnect, process restart |
| Publication | queue full, max-size rejection, side-file failure, publish failure, partial split acceptance |
| ACKs | OK, durable opt-in, timeout with progress, timeout without progress, terminal rejection |
| Pool | exhaustion, return, forced drop, reaper, close drain, close with outstanding FFI handle |
| Recovery | memory SFA reconnect, disk SFA restart, orphan adoption, torn symbol side-file |
| Feature gates | core QWP, Arrow ingress, Polars ingress, egress enabled/disabled, FFI support |
| Bindings | Rust, C, C++, Python smoke and error contracts |
| Performance | row Buffer, Chunk, Arrow, dataframe end-to-end, mixed-shape soak |

## 16. Risks and mitigations

### Symbol dictionary divergence

**Risk:** Buffer and Chunk encoders allocate IDs from separate dictionaries on
one connection, causing symbol aliasing or torn-dictionary recovery.

**Mitigation:** one dictionary/persistence owner above every encoder; mandatory
mixed-shape reconnect and restart tests before removing the row pool.

### Performance regression from abstraction

**Risk:** a generic publisher adds indirection, extra copies, or repeated
allocation to the column fast path.

**Mitigation:** encoder closures write directly into retained payload storage;
keep encoder-specific scratch; benchmark each milestone against the frozen
baseline.

### Partial-publication contract drift

**Risk:** a generic flush API hides that Chunk/Arrow inputs can be split while a
Buffer currently cannot, producing incorrect retry advice.

**Mitigation:** explicit shape-specific methods and error tests; keep partial
publication classification in the payload adapter.

### Pool semantics change

**Risk:** removing the row pool changes capacity, initial-connect behavior,
manual progress, and disk slot naming.

**Mitigation:** declare the unified background-SFA contract, use one ingestion
cap, reject unsupported manual mode, and adopt `-ingest-N` with no old-slot
compatibility (decided in Section 6.9).

### Cross-language ABI churn

**Risk:** removing row-sender handles touches Rust, C, C++, and Python at
different times and leaves an inconsistent intermediate tree.

**Mitigation:** land the Rust API, C FFI, and C++ direct renames and removals in
the single atomic Milestone 4 cross-surface cutover; do not create aliases or a
partially renamed intermediate tree.

### Direct versus SFA confusion remains

**Risk:** users interpret the hidden direct pool and public SFA pool as another
row/column split.

**Mitigation:** document the distinction entirely in terms of source ownership
and delivery semantics. Whole-source `QuestDb` methods hide the direct sender;
only explicit borrowed senders expose SFA progress.

## 17. Rejected alternatives

### Convert Buffer to Chunk

Rejected because Buffer can contain sparse rows and multiple tables and owns
its values, while Chunk borrows equal-length columns for one table. Conversion
would add copies or complex temporary views and would erase Buffer-specific
retry and keep semantics.

### Copy Chunk into Buffer

Rejected because it restores the per-cell name lookup and validation cost that
the column fast path was created to eliminate.

### Keep both senders but hide one in language bindings

Rejected because Rust, FFI, recovery, pool capacity, and store-and-forward
state would remain duplicated. It fixes only documentation, not the
architecture.

### Generic public `flush<T: IngressBatch>` in the first version

Rejected initially because Buffer and Chunk have different keep, split, clear,
empty, and retry contracts. Explicit methods make those differences reviewable.
A sealed internal trait or closure-based encoder abstraction is still useful.

### Merge direct and store-and-forward pools

Rejected because they have genuinely different ownership and replay models.
The SFA path persists encoded frames and exposes FSNs; the direct dataframe
path retains the complete source, pipelines commits, and re-drives from
checkpoints.

## 18. Completion criteria

The design is complete when:

1. `QuestDb` exposes one public borrowed ingestion sender.
2. That sender accepts Buffer, Chunk, and Arrow inputs without conversion
   between their public representations.
3. Mixed payloads share one connection-scoped symbol dictionary and one
   publication/ACK stream across reconnect and disk recovery.
4. The separate pooled row sender and its pool, slots, FFI, and C++ wrappers are
   gone.
5. Direct whole-dataframe ingestion remains hidden behind `QuestDb`/`Client`
   operations.
6. Documentation teaches payload shape and delivery mode rather than two sender
   identities.
7. Correctness, ABI, performance, and soak gates in the milestones pass.
