# QWP DataFrame Benchmark Plan — pandas (Python) & Polars (Rust), ingress + egress

**Status:** draft, pending approval
**Scope:** benchmark suite for the QWP/WebSocket DataFrame paths — pandas in
`py-questdb-client`, Polars in `c-questdb-client/questdb-rs`. Both directions:
**ingress** (DataFrame → wire) and **egress** (query result → DataFrame).
**Supersedes:** the missing `plan-pandas-columnar-performance.md` (referenced 4×
in the now-deleted `plan-egress-to-pandas.md` / `plan-conn-pool-and-writers.md`).
**Relationship:** this is the concrete realisation of `c-questdb-client`'s
`doc/COLUMN_SENDER_PLAN.md` **WS-6** (Rust benches) and **WS-7** (Python
end-to-end throughput, the `pandas_to_questdb_throughput` deliverable). Methodology
is inherited from `doc/COLUMN_SENDER_PERF.md`.

**This doc lives in `c-questdb-client/doc/`.** Path conventions: Rust paths are
relative to `c-questdb-client/questdb-rs/` (e.g. `benches/decoder.rs`,
`src/ingress/column_sender/encoder.rs`); Python paths are relative to the
`py-questdb-client/` repo (e.g. `test/benchmark_pandas_columnar.py`).

---

## 1. Goal & priorities

Build the smallest benchmark suite that delivers, in priority order:

1. **DataFrame path characterisation** — where does time go in pandas/Polars
   encode (ingress) and decode (egress), per column type; verify the zero-copy
   claims. This is the biggest gap today: **there is no egress benchmark in
   either client**, despite egress→DataFrame being the marquee QWP feature.
2. **Cross-client parity table** — one comparable `rows/s` + `GiB/s` per client
   (pandas, Polars, and the Java/Go anchors) on a single shared schema.

Non-goals for v1: QWP-vs-ILP/PGWire/CSV protocol shootout (Java `StacBenchmarkClient`
and Go `bench/qwp-egress-read` already own that); a precomputed combinatorial
sweep matrix (see §2).

---

## 2. Guiding principles (narrow-v1 discipline)

Inherited from `COLUMN_SENDER_PLAN.md` ("that is the *whole* goal; anything else
is out of scope") and from the Go finding that a full `max_batch_rows`/`credit`/
`bufpool` sweep was wasted because "the path is pipeline-coupling-bound, **not
param-bound**." We do not front-load breadth.

- **Exhaustive only where it's cheap.** Per-type coverage lives in the
  no-network micro/floor tier (Rust Criterion; Python `columnar-populate` /
  decode-from-bytes). The expensive real-server tier stays **narrow**.
- **One schema (S1) for the expensive paths.** Vary with **knobs, not a matrix**.
- **Defer every secondary axis until a number implicates it** (compression, TLS,
  ack-level, pooled-vs-per-call, concurrency, output-backend matrix, chunk layout).
- **Report the honest sum, not the near-free part.** After borrow-not-copy a
  `column_i64` append is ~57 ns (descriptor only — it doesn't move data); the
  honest ingress metric is `populate_plus_encode`. Symmetrically on egress the
  honest metric is `decode_plus_assemble`, not the near-free zero-copy column view.
- **Report baseline-relative.** Each type as a ratio to its raw floor
  (`extend_from_slice`/memcpy on ingress; `np.frombuffer(...).copy()` / `Bytes`
  slice on egress).

This discipline *serves* both priorities: the parity table wants one comparable
number per client (not a matrix to align), and characterisation's per-type breadth
is cheap (no server), so narrowing the expensive tier costs nothing there.

---

## 3. Shared infrastructure ("the spine")

Steps 1 and 2 build this once; every later step plugs into it.

### 3.1 Canonical scenario set

**S1 — `narrow` (headline, all expensive paths).** 5 columns, matches Go/Rust
`qwp-egress-read` and (loosely) Java STAC so numbers line up cross-client:

| Column | QWP type | pandas dtype | Polars/Arrow |
|---|---|---|---|
| `ts`    | TIMESTAMP (designated) | `datetime64[ns]` | `Datetime(ns)` |
| `id`    | LONG    | `int64`     | `Int64` |
| `price` | DOUBLE  | `float64`   | `Float64` |
| `sym`   | SYMBOL  | `Categorical` (card 8) | `Categorical` |
| `note`  | VARCHAR | `string` (Arrow), len ~16 | `Utf8` |

Defaults: `rows=10_000_000` (headline), `rows=100_000` (CI), no-null.

**Cheap tier — per-type (broaden here, no server).** Split by direction because
column **ingress** is v1-scoped while **egress** decodes everything:

- *Ingress S4* (v1 types only, per `COLUMN_SENDER_PLAN.md` §6): bool, i8, i16,
  i32, i64, f32, f64, varchar, symbol, timestamp, date, uuid, ipv4, long256.
  **Excluded** (not implemented for column ingress): decimal, long/double array,
  geohash, char, binary.
- *Egress S4* (full decode set — maps to `egress.pxi` chunk functions):
  - fast / zero-copy (`_numpy_fixed_chunk`): bool, byte, short, int, long, float,
    double, char, ipv4, timestamp, date;
  - slow / per-row Python loop (prime targets): varchar+binary
    (`_numpy_varlen_chunk`), uuid (`_numpy_uuid_chunk`), long256
    (`_numpy_long256_chunk`), decimal (`_numpy_decimal_chunk`), long/double array
    (`_numpy_array_chunk`); symbol → `pd.Categorical.from_codes`.

Use `COLUMN_SENDER_PLAN.md` §6 as the authority for which dtype to construct per
type and which are "no native" (uuid→bytes, ipv4→uint32, long256→bytes).

**Deferred until a number says it matters:** S2 wide; output-backend matrix
(numpy / pyarrow / numpy_nullable / `__arrow_c_stream__`); chunk layout
(rechunked vs multi-chunk); no-null-vs-nullable per type; Categorical
"100k categories, few referenced"; zstd; TLS (`wss`); ack-level
(`Ok` vs `Durable`); pooled-vs-per-call; concurrency (N pooled senders).

### 3.2 Metric / JSON contract (one schema, both languages → one aggregator)

Formalise the existing `benchmark_pandas_columnar.py` report. Rust examples emit
the **same** JSON so a single aggregator builds the parity table.

```jsonc
{
  "schema": "s1-narrow", "rows": 10000000, "columns": 5,
  "direction": "ingress",            // or "egress"
  "client": "py-pandas",             // py-pandas | py-polars | rust-polars | java | go
  "warmups": 3,
  "machine": { "platform": "...", "cpu": "...", "python|rustc": "...",
               "pandas": "...", "pyarrow": "...", "polars": "..." },
  "commits": { "py_questdb_client": "...", "c_questdb_client": "..." },
  "run_mode": "quick|full",
  "paths": {
    "<name>": {
      "median_s": 0.0, "p50_s": 0.0, "p90_s": 0.0, "p99_s": 0.0,
      "rows_per_s_median": 0, "cells_per_s_median": 0,
      "wire_bytes": 0, "mib_per_s": 0.0,
      "process_cpu": { "user_s": 0.0, "sys_s": 0.0 },
      "cov": 0.0, "copies": 0, "zero_copy": true,
      "phase": "floor|e2e", "warm": true
    }
  }
}
```

### 3.3 Knobs (parity names with the Rust suite)

Mirror `COLUMN_SENDER_PERF.md`: `--rows` (`QUESTDB_COLUMN_BENCH_ROWS`, default
100k), `--sym-card` (`QUESTDB_COLUMN_BENCH_SYM_CARD`, default 8 for S1),
`--varchar-len` (`QUESTDB_COLUMN_BENCH_VARCHAR_LEN`, default 16). CI runs use
`--quick` (Rust: `cargo bench -- --quick --noplot`).

### 3.4 Correctness — DEDUP (mandatory for real-server throughput)

QWP/WS is **at-least-once on reconnect**; replayed frames inflate row counts
5–16 % (c-questdb-client PR #143). Every real-server path must pre-create the
table and use monotonic-unique timestamps:

```sql
CREATE TABLE bench_s1 (...) TIMESTAMP(ts) PARTITION BY HOUR WAL DEDUP UPSERT KEYS(ts);
```

`run_pandas_columnar_layer3.py` currently lets ingestion auto-create the table
(no DEDUP keys) and only `SELECT count()` to verify — Step 1 must add the explicit
`CREATE TABLE … DEDUP` and unique-ts generation.

### 3.5 Cold vs warm (verified against code, not the stale doc)

`COLUMN_SENDER_PERF.md:53` claims a "REFERENCE mode" schema-signature cache. That
is **stale**: the encoder rebuilds and writes the schema signature inline on every
frame (`column_sender/encoder.rs:153-224`); `COLUMN_SENDER_PLAN.md:83` ("no schema
cache") is correct. So there is **no schema FULL/REFERENCE axis**.

The real cold/warm axis is the **symbol delta-dict + commit mode**
(`column_sender/sender.rs:90-96,144-145`): the first frame on a fresh connection
sends the full symbol dict from id 0 with an immediate commit (warms the server's
`ClientSymbolCache`); later frames send `FLAG_DELTA_SYMBOL_DICT` deltas with
`FLAG_DEFER_COMMIT`. `first_frame_sent` travels with the pool slot, so a
warm-recycled connection skips the cold cost. Benchmarks must report **first-flush
(cold)** separately from **warm steady-state**, and note warm-from-pool.

### 3.6 Honest-sum & baseline-relative (see §2)

Ingress: report `populate` / `encode` / `populate_plus_encode` and headline the
**sum**. Egress: report `decode` / `assemble` / `decode_plus_assemble` and
headline the sum. Always alongside the raw floor.

### 3.7 Environment recording

Record machine, CPU, library versions, both repo commits, and run-mode in every
JSON (already present in the Python harness; add to Rust). Parity table runs must
be single-box, single-stream (prior numbers are Apple-Silicon loopback).

---

## 4. Step 1 — Python pandas **ingress** e2e (`pandas_to_questdb_throughput`)  *[DETAILED]*

The WS-7 deliverable, scoped to current branch state and narrow-v1.

### 4.1 Current branch state (`jh_experiment_new_ilp`)

Already exists — Step 1 is **alignment + hardening, not greenfield**:

- `Client.dataframe()` columnar fast path → Rust `column_sender_flush_arrow_batch`
  FFI (the WS-7 "build a wrapper" TODO is already done).
- `test/benchmark_pandas_columnar.py` (963 lines): paths `columnar-populate`
  (no-network floor), `client-ack` / `client-ack-reuse` (mock-server e2e via
  `qwp_ws_ack_server.py`, with `ack_delay_s` injection), `real-client` /
  `real-row` (real server), `arrow-materialize`. Emits the JSON report
  (machine, commits, percentiles, CPU, `columnar_io_stats`); has a perf
  assertion (`--ack-reuse-min-calls` default 100 within `--ack-reuse-max-seconds`
  default 10). Schemas: `numeric-core`, `numeric-wide`, `categorical-symbols`,
  `arrow-strings`, `arrow-large-strings`, `mixed-physical`, `nullable-extension`.
- `test/run_pandas_columnar_layer3.py`: installs/builds a real QuestDB
  (`system_test.py`), runs `real-*` paths, verifies via `SELECT count()`.

### 4.2 Work items

1. **Add the `s1-narrow` schema** (§3.1) to `SCHEMAS` in
   `benchmark_pandas_columnar.py` (+ its `CREATE TABLE` template with
   `DEDUP UPSERT KEYS(ts)`), with `--sym-card`/`--varchar-len` knobs feeding its
   generator. This becomes the single headline schema; keep the existing schemas
   available for the cheap tier.
2. **Lock the JSON metric contract v1** (§3.2): add `direction`, `client`,
   `wire_bytes`, `mib_per_s`, `phase` (`floor`/`e2e`), `warm`, `run_mode`. Keep
   the existing fields.
3. **Wire DEDUP + unique-ts** into `run_pandas_columnar_layer3.py` and the
   `real-*` setup (§3.4): explicit `CREATE TABLE … DEDUP`, monotonic-unique `ts`,
   and assert `count() == rows` (no inflation).
4. **Pair floor + e2e in one run**: the headline invocation runs
   `columnar-populate` (floor) **and** `real-client` (e2e) on S1 and reports both
   + the `populate_plus_encode`-style sum (§3.6).
5. **Cold/warm split** (§3.5): report the first `real-client` flush separately
   from warm steady-state (the `client-ack-reuse` machinery already exercises
   warm reuse — extend its reporting rather than add a path).
6. **Name the entrypoint** `pandas_to_questdb_throughput` (a thin documented
   wrapper / make-target that runs items 4–5 on S1). `ack_level=Ok`; note
   `Durable` is Enterprise + deferred (§13).
7. **CI**: local-run-first via `run_pandas_columnar_layer3.py` (unblocked today);
   wire a real server into CI as a fast-follow (the WS-7 "done when" gate).

### 4.3 Deliverables

- `s1-narrow` schema + DEDUP table template.
- JSON contract v1 emitted by the harness.
- `pandas_to_questdb_throughput` headline run (floor + e2e + cold/warm) on S1.
- DEDUP-correct real-server fixture.

### 4.4 Done when

- One command yields S1 `rows/s` + `MiB/s` for **e2e (`real-client`)** alongside
  the **`columnar-populate` floor**, on 10M rows, with `count() == rows`.
- Cold first-flush vs warm steady-state both reported.
- JSON conforms to the contract; machine + both commits recorded.
- Runs locally via `run_pandas_columnar_layer3.py`; CI wiring tracked.

### 4.5 Run

```sh
python test/run_pandas_columnar_layer3.py --questdb-repo ../../questdb \
  --schema s1-narrow --rows 10000000 --iterations 5 \
  --path columnar-populate --path real-client --pretty
```

---

## 5. Step 2 — Python pandas **egress** e2e (symmetry)  *[DETAILED]*

The mirror of Step 1, closing the #1 gap. New harness, **same spine**.

### 5.1 Current branch state

No egress benchmark exists. `src/questdb/egress.pxi` exposes the API to bench:
`Client.query(...)` → `to_pandas()` (numpy default), `to_pandas(dtype_backend=
"pyarrow"|"numpy_nullable")`, `to_polars()`, `__arrow_c_stream__` (pyarrow-free),
`iter_pandas()` / `iter_arrow()` (lazy per-batch). Fast `_numpy_fixed_chunk`
(zero-copy `np.frombuffer`) vs slow per-row loops (§3.1).

### 5.2 Fixture decision (narrow-v1)

**Read back the S1 table that Step 1 ingested** on the real server (natural
symmetry: write in Step 1, read in Step 2; reuses the Step 1 spine, DEDUP-correct).
A server-free **RESULT_BATCH replay server** (extend `qwp_ws_ack_server.py` to
stream captured/synthesised batches) is **deferred to Step 5** — it's only needed
for CI-isolated decode micro and the cheap-tier egress per-type set.

### 5.3 Paths (symmetry to ingress)

- `decode-only` — iterate the cursor's Arrow batches without building a DataFrame
  (the egress floor; analog of `columnar-populate`).
- `to-pandas` — default numpy materialise (the headline).
- `to-polars` — Polars output (shares the Arrow path; cheap to add).
- `arrow-c-stream` — `__arrow_c_stream__` → `polars.from_arrow` (pyarrow-free).
- `iter-pandas` — lazy per-batch vs `to-pandas` full materialise.
- `real-egress` — end-to-end against the real server (reads the S1 table).

Headline run pairs `decode-only` (floor) + `to-pandas` (e2e) and reports the
`decode_plus_assemble` sum (§3.6).

### 5.4 Work items

1. New `test/benchmark_pandas_egress.py` mirroring the ingress harness structure
   and **emitting the identical JSON contract** (`direction="egress"`).
2. Extend `run_pandas_columnar_layer3.py` to ingest S1 then query it back (or a
   sibling `run_pandas_egress_layer3.py`), reusing the DEDUP fixture.
3. Implement the §5.3 paths on **S1 only**, 10M rows, no-null.
4. Verify zero-copy on the fixed-width fast path (assert `_numpy_fixed_chunk`
   taken; buffer-shares-memory check) — characterisation deliverable.

### 5.5 Deliverables

- `benchmark_pandas_egress.py` (S1, paths in §5.3, contract-conformant JSON).
- Real-server read-back fixture.
- First egress `rows/s` + `MiB/s` numbers for `to_pandas` / `to_polars` /
  `arrow_c_stream`, with the decode/assemble split.

### 5.6 Done when

- One command yields S1 egress `rows/s` + `MiB/s` for `to_pandas` (+ `to_polars`,
  `arrow_c_stream`) alongside the `decode-only` floor, reading back the DEDUP'd
  S1 table, 10M rows.
- Zero-copy verified on the fast path.
- JSON conforms; comparable in shape to Step 1 and to the Go anchor
  (40.7M rows/s narrow).

### 5.7 Run

```sh
python test/run_pandas_egress_layer3.py --questdb-repo ../../questdb \
  --schema s1-narrow --rows 10000000 --iterations 5 \
  --path decode-only --path to-pandas --path to-polars --pretty
```

---

## 6. Step 3 — Rust **Polars** parity, ingress + egress  *[summary]*

Bring the Rust side onto the same S1 + JSON contract → 4 comparable headline
numbers (pandas/Polars × ingress/egress).

- **Ingress:** `examples/qwp_ingress_polars.rs` measuring `flush_polars_dataframe()`
  on S1; report e2e + the `column_sender.rs` encode floor (already exists) so the
  DataFrame→batches overhead is isolated.
- **Egress:** `examples/qwp_egress_polars.rs` (`fetch_all_polars` / `iter_polars` /
  `next_polars`) on S1, plus a `→ polars` arm in `benches/decoder.rs` (Criterion
  synthesises batches in-process → server-free decode→DataFrame micro). Report
  `decode` (the existing 13.3M rows/s floor) vs `assemble` vs the sum.
- Emit the §3.2 JSON from both examples.

## 7. Step 4 — Parity table  *[IMPLEMENTED]*

Aggregator script consumes all §3.2 JSON (pandas, Polars, + Go/Java anchors run
on the same box) → one S1 `rows/s` + `GiB/s` table per direction. Single-box,
single-stream; environment block enforced.

**Implemented:** `doc/bench_parity_aggregate.py` (stdlib-only). Consumes the
contract JSON from both clients, normalizes per-client path names → canonical
roles (`ROLE_OF_PATH`), and renders a `rows/s` + `GiB/s` table per direction
(md/text). GiB/s is derived from `rows/s × canonical on-wire bytes/row`
(`--ingress-bpr`/`--egress-bpr`, defaults 45.0 / 37.1284) because the per-file
`wire_bytes` basis differs across clients on egress (py = decoded-Arrow nbytes
~480 MB, rust = on-wire ~371 MB) — so native `mib_per_s` is not cross-client
comparable, but `rows/s` is. Enforces single-box via a coarse `(os, arch)` match
(✅/⚠️) and warns on duplicate `(client, direction)` inputs. Run:
`python doc/bench_parity_aggregate.py <contract>.json ... [--glob 'dir/*.json']`.
Go/Java anchors emit their own formats (not the §3.2 contract) → deferred; add a
per-client normalizer when those JSONs exist.

## 8. Step 5 — First deepening: S2 wide + DataFrame characterisation  *[summary]*

Only after the 4 headline numbers exist.

- **S2 — `wide` (15 col)** *[IMPLEMENTED, both clients]*: S1-narrow + 5 DOUBLE
  (`d1..d5`) + 5 high-cardinality SYMBOL (`s1..s5`, default card 100k — the Go
  `qwp-egress-read-wide` anchor, so the wide number lines up; pass a 10k–100k
  spread for dict-scale characterisation). The "QWP wins on wide rows" claim +
  symbol-dict stress. **Python:** `make_s2_wide` / `--schema s2-wide` in
  `benchmark_pandas_columnar.py` + the egress harness. **Rust:** `SCHEMA=s2-wide`
  in `examples/qwp_{ingress,egress}_polars.rs`, sharing one parity contract
  (column layout, DDL, value generators) via `examples/bench_schema/mod.rs` so
  both clients put byte-identical column data on the wire. The high-card delta-dict
  overflows the 1m default — run the server with `http.receive.buffer.size=16M`.
  Headline 10M parity numbers feed the existing §7 aggregator (`schema` field
  already carried per-path).
- **DataFrame-specific knobs (cheap):** output-backend matrix (numpy / pyarrow /
  numpy_nullable / `__arrow_c_stream__`); chunk layout (rechunked vs multi-chunk);
  no-null vs nullable per type (memcpy vs invert+gather — expect the ~57 ns→289 ns
  ratio from `COLUMN_SENDER_PERF.md`); Categorical "100k categories, few
  referenced" (tests the scan-only-referenced path, `encoder.rs:1110,1128`).
- **RESULT_BATCH replay server** (extend `qwp_ws_ack_server.py`) for CI-stable
  egress decode micro + the cheap-tier egress per-type set.

## 9. Step 6 — Secondary axes  *[summary]*

Each gated on a prior number implicating it: zstd (raw vs `sync-reader-zstd`);
TLS (`wss`); ack-level (`Ok` vs `Durable`, Enterprise); pooled-vs-per-call;
**concurrency** — N pooled senders / one frame in flight each
(`COLUMN_SENDER_PLAN.md` parallelism model; the Go "single-stream is
pipeline-coupling-bound" missing axis).

## 10. Step 7 — Soak  *[summary]*

Nightly CI, 1-hour run, random chunks: assert no leaks, no reconnects, latched-error
handling (`COLUMN_SENDER_PLAN.md` WS-6).

---

## 11. Baselines & targets

| Path | Known number (Apple-Silicon, loopback) | Source |
|---|---|---|
| Egress decode, 15-col | Rust 13.3M rows/s ~1.0 GiB/s (≈7 % off Java 1.3 GiB/s); Go 40.7M rows/s @ 1003 MiB/s narrow | c #140, go #62 |
| Ingress encode floor | no-null f64/i64 ≈ memcpy ~54 GiB/s; symbol intern 16×; varchar within ~5 % memcpy | `COLUMN_SENDER_PERF.md` |
| Ingress pipelined e2e | Rust 350 MB/s; per-chunk p50 0.72 ms | c #140 |
| Ingress latency | Java ~38 µs p50 SF `flush()` | `QwpIngressLatencyBenchmark` |
| 5-col 100k chunk | populate ~76 µs, encode ~500 µs, **e2e ~575 µs**; i64 no-null ~57 ns vs nullable ~289 ns | `COLUMN_SENDER_PERF.md` |

**Pass/fail targets:** VARCHAR within ~2× of f64; SYMBOL within 2× of f64 at
10M × 1000-card (`COLUMN_SENDER_PLAN.md` WS-3/WS-4). DataFrame-assembly overhead
is reported as a **% on top of these floors** per type.

---

## 12. Gotchas

- **DEDUP** `UPSERT KEYS(ts)` + monotonic-unique `ts` on every real-server run
  (at-least-once inflates 5–16 %).
- **Cold/warm = symbol-dict delta + commit mode**, not schema (verified
  `sender.rs:90-96`, `encoder.rs:153-224`); `PERF.md`'s REFERENCE-mode note is
  stale.
- **Buffer pre-size** (`estimate_frame_size`): payloads > 64 KiB regress without
  one-shot sizing (~880 µs vs ~575 µs); ensure benches pre-size; one scenario
  should deliberately exceed 64 KiB.
- **Honest sum** (`populate_plus_encode` / `decode_plus_assemble`), never the
  near-free zero-copy view.
- **No cell-by-cell row-vs-column microbench** — ruled out as apples/oranges
  (`PERF.md:95`); row-vs-column is a DataFrame-level comparison (`real-row` vs
  `real-client`).

---

## 13. Open decisions

1. **Doc home** — resolved: lives in `c-questdb-client/doc/` alongside
   `COLUMN_SENDER_PLAN.md` / `COLUMN_SENDER_PERF.md` (single source of truth).
   Add a one-line pointer from `py-questdb-client` when Step 1 lands.
2. **Step 1 CI** — local-run-first (default, unblocked now) vs real-server-in-CI
   inside Step 1 (matches WS-7 "done when").
3. **Durable ack-level** — defer (Enterprise, `request_durable_ack=on`) vs
   in-scope for Step 6.
4. **Egress fixture** — read-back real server for v1 (default) vs build the
   RESULT_BATCH replay server earlier than Step 5.

---

## Appendix — existing assets inventory

**Python (`py-questdb-client`):** `test/benchmark_pandas_columnar.py`,
`test/run_pandas_columnar_layer3.py`, `test/qwp_ws_ack_server.py`,
`test/benchmark.py` (10M row-path + GIL-release scaling), `perf/README.md`,
`src/questdb/egress.pxi`, `src/questdb/dataframe.pxi`.

**Rust (`c-questdb-client/questdb-rs`):** `benches/decoder.rs`,
`benches/column_sender.rs`; examples `qwp_egress_read.rs`,
`qwp_egress_read_wide.rs`, `qwp_egress_latency.rs`, `qwp_egress_hits.rs`,
`qwp_ws_l1_quotes.rs`, `qwp_ws_unified_sfa_bench.rs`, `polars.rs`;
`src/ingress/polars.rs`, `src/egress/arrow/polars.rs`;
`doc/COLUMN_SENDER_PLAN.md`, `doc/COLUMN_SENDER_PERF.md`.

**Anchors:** Java `StacBenchmarkClient.java`, `QwpIngressLatencyBenchmark.java`;
Go `bench/qwp-egress-read[-wide]/main.go`.
