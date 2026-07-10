# Long-Running Soak & Stress Harness — Design

**Status:** draft (2026-07-10)
**Owner:** TBD
**Audience:** engineers working on the Rust core (`questdb-rs`), the C FFI
(`questdb-rs-ffi`), the C/C++ surface, the Python wrapper
(`py-questdb-client`), and CI.
**Context:** release-readiness thread ("no long running tests" blocker). This
doc turns that item into a concrete, repeatable, CI-run harness with explicit
pass/fail criteria.

---

## 1. Goal

Answer, with evidence produced automatically on every PR run:

1. **No slow leaks.** Memory (RSS), file descriptors, pool slots, and SF disk
   usage stay **bounded** under hours-equivalent sustained load, including
   across hundreds of reconnect/failover/restart cycles.
2. **No data loss, bounded duplication.** Every acked row is readable back;
   duplication stays within the at-least-once replay window; a
   `DEDUP UPSERT KEYS` table shows exact counts.
3. **Correct values for every datatype.** All QWP wire types round-trip with
   exact values through every ingest route (row API, column sender,
   DataFrame) and back out through egress.
4. **Recovery liveness.** After every induced fault (server kill, client kill,
   connection reset, stall, disk-full), the client resumes making progress
   within a deadline — no stuck replay, no deadlock, no orphaned state.

The harness exercises: **Direct and Store-and-Forward backends** (SF both
disk-based and in-memory), **all four pools** (row sender, column SF, column
direct, reader) with **multiple concurrent connections**, **ingress and egress
workloads running in parallel** against the same server, with **server and
client restarts** injected throughout.

### Duration philosophy: oracle over wall-clock

A raw "run for an hour and see if it crashes" has a near-useless oracle
("didn't crash = pass"). This design substitutes **high throughput ×
instrumentation × assertions** for raw duration:

- a 60–90 min per-PR run at sustained throughput with 10–15 fault episodes
  covers more reconnect/replay/recovery cycles than a quiet multi-hour run;
- leak detection comes from **sampled resource curves with slope assertions**
  plus a **sanitizer profile** (ASan/LSan), not from waiting for RSS to get
  visibly huge;
- the run is **seeded and reproducible**: one `--seed` reproduces the same
  episode schedule and the same generated data.

A longer run is a queue-time parameter (`SOAK_DURATION_MIN`), not a different
harness.

---

## 2. Scope & non-goals

**In scope (v1):**

- QWP/WS protocol paths: row sender, column sender (direct + SF backends),
  DataFrame entries (`flush_polars_dataframe` / Arrow batch), egress reader
  (materialise-whole and streaming).
- Rust and C workload processes (C also serves the sanitizer job). Python
  (`py-questdb-client`) workload is a follow-up leg (S6).
- Single-endpoint server restart/reconnect (`reconnect_*` enables reconnect on
  a single endpoint, per `COLUMN_SENDER_SF_FAILOVER_DESIGN.md` §F2), plus
  client kill/restart with SF-disk recovery.
- Linux CI (Hetzner incus pool, same as `TestVsQuestDBMaster`).

**Non-goals (v1):**

- **ILP/TCP + ILP/HTTP legacy paths.** The generated-code risk is in the QWP
  stack; legacy paths keep their existing tests. Extension point, not v1.
- **Multi-endpoint primary failover soak.** Needs a primary/replica topology
  (role-reject rotation), i.e. Enterprise. The harness keeps an endpoint-list
  knob so the same legs can run in `system_test/enterprise_e2e` /
  `TriggerEnterpriseCClientE2E` later; v1 asserts single-endpoint
  reconnect only.
- **macOS / Windows soak.** Sampler uses `/proc`; per-PR native tests keep
  covering those platforms functionally.
- **Server-side leak gating.** Server RSS is sampled for triage but never
  gates — a server leak must not fail the client pipeline.
- **Performance regression gating.** Throughput is recorded, not asserted
  (that's `COLUMN_SENDER_PERF.md`'s job).

---

## 3. What exists today (reuse map)

| Capability | Existing asset | Reuse |
|---|---|---|
| QuestDB lifecycle (download/build, start, `/ping` wait, SIGTERM→SIGKILL, log capture) | `system_test/fixture.py` (`QuestDbFixture`) | orchestrator uses it as-is; add a `kill9()` helper |
| Two-instance + mid-stream kill pattern | `system_test/test_egress_failover.py` | episode + reconciliation patterns |
| Loop-style long tests | `system_test/_fuzz_loop.py`, `_arrow_sfa_fuzz_loop.py` | episode-loop skeleton |
| Compiled-client sidecar pattern | `system_test/c_sidecars/`, `system_test/failover_clients/` | C workload leg |
| TCP-in-the-middle fixture pattern | `system_test/tls_proxy/` | model for the fault proxy |
| Scheduled pipeline + Slack `#builds` alert | `ci/run_fuzz_pipeline.yaml` (`NotifyOnFailure`) | clone for the soak pipeline |
| Server-from-master in CI | `ci/templates/clone_questdb.yaml`, `TestVsQuestDBMaster` job | same provisioning |
| ASan/UBSan build | `SanitizeCppTests` (`-DQUESTDB_SANITIZE=ON`, CMakeLists.txt) | sanitize profile links the C leg against this build |
| Egress failover event surface | `ReaderQuery::on_failover_reset` + `FailoverResetEvent` (attempts, elapsed, trigger); FFI `reader_query_on_failover_reset` | egress legs count/verify failovers |
| Egress stats | `ReaderStats` (`bytes_received`, …) + FFI getters; `questdb_db_dbg_reader_free_count` / `_in_use_count` | sampled directly; **naming precedent for S0** |

**The gap** (why S0 exists): the sender side exposes almost nothing.
`QwpWsCounters` (`qwp_ws_driver.rs`: `total_frames_sent`, `total_acks`,
`total_reconnect_attempts`, `total_reconnects_succeeded`,
`total_server_errors`) is `pub(crate)`; SF's `allocated_segment_bytes()` /
`sealed_segment_count()` are `#[cfg(test)]`; the sender pools (`PoolState
{ free, in_use, closing }` in `db.rs`) have no count accessors (only the
reader pool does). Without S0 the oracle cannot assert "pool returned to
baseline" or "SF disk reclaimed".

---

## 4. Architecture

```
                    ┌────────────────────────────────────────────┐
                    │ orchestrator  system_test/soak/soak.py     │
                    │  • episode scheduler (seeded)              │
                    │  • sampler: RSS/FD per pid (psutil, 5 s)   │
                    │  • reconciliation queries (PG/HTTP)        │
                    │  • verdicts → summary.json                 │
                    └───┬──────────────┬──────────────┬──────────┘
                        │ spawn/kill   │ spawn/kill   │ start/stop/kill9
              ┌─────────▼───┐   ┌──────▼──────┐   ┌───▼─────────────┐
              │ workload    │   │ fault proxy │   │ QuestDbFixture  │
              │ processes   │──▶│ (TCP MITM:  │──▶│ (faulted)       │
              │ rust / C /  │   │ reset,stall,│   └─────────────────┘
              │ (py later)  │   │ throttle)   │   ┌─────────────────┐
              │ + journal   │   └─────────────┘   │ QuestDbFixture  │
              │ + stats.jsonl                     │ (control, never │
              └───────────────────────direct─────▶│  faulted)       │
                                                  └─────────────────┘
```

- **Workloads are separate OS processes**, not threads of the orchestrator —
  so the orchestrator can `SIGKILL` and restart them (client-restart
  coverage), and so the sanitizer profile gets clean per-process LSan reports
  at exit.
- **Fault proxy** (`system_test/soak/fault_proxy.py`, following the
  `tls_proxy` fixture pattern): a TCP forwarder the orchestrator commands to
  reset connections (optionally after N forwarded bytes — mid-flush reset),
  stall (stop forwarding for T seconds → ack starvation, in-flight cap,
  timeout paths), or throttle (bytes/sec → sustained backpressure). Faulted
  legs connect through it; control legs connect direct to the control server.
- **Control legs**: one ingress + one egress leg run against the
  never-faulted control instance for the whole run. They must show **zero**
  duplicates, zero gaps, and their resource curves are the cleanest leak
  signal (no failover noise).
- **Client journal**: each ingress workload appends `acked <seq>` (fsync'd)
  to a per-worker journal file after every successful `sync`/ack watermark
  advance. On restart it resumes at `watermark + 1`. This makes every leg
  **gap-free by construction** regardless of backend, and gives the oracle
  the authoritative lower bound of what must be readable.
- **Stats side-channel**: each workload emits one JSON line per 5 s to
  `--stats-file`: internal counters only (rows sent/acked, fsn watermarks,
  pool counts, SF backlog bytes, `QwpWsCounters` snapshot, errors by code).
  The orchestrator samples RSS/FD externally per pid and merges both into
  `stats.jsonl`. Optionally (`--stats-questdb`) samples are also ingested
  into a table on the control instance for interactive triage (dogfooding);
  the JSONL artifact is authoritative.

---

## 5. Coverage matrix

Workload legs (each an independent process with its own worker-id range,
journal, and — for SF disk — its own `sf_dir` + `sender_id`, sidestepping the
v1 single-slot constraint of the column-SF pool by scaling across processes):

| Leg | Route | Backend / pool | Concurrency | Faulted |
|---|---|---|---|---|
| `rust-row-direct` | row API `Sender` | direct | pool, N threads | ✔ |
| `rust-row-saf-disk` | row API | SAF disk (`sf_dir`) | 1/process × M processes | ✔ |
| `rust-row-saf-mem` | row API | SAF in-memory (`max_bytes`) | 1/process × M processes | ✔ |
| `rust-col-direct` | column sender chunks | direct pool (`direct_state`) | pool_max > 1, N threads borrow/return | ✔ |
| `rust-col-sf` | column sender chunks | SF pool (`state`) | 1/process × M processes | ✔ |
| `rust-col-df` | `flush_polars_dataframe` | direct pool | N threads | ✔ |
| `rust-egress-whole` | `fetch_all_polars` (reset callback wired) | reader pool | N concurrent queries | ✔ |
| `rust-egress-stream` | incremental batches (expects `FailoverWouldDuplicate`, re-issues) | reader pool | N concurrent | ✔ |
| `c-row`, `c-col` | C API via sidecar | direct + SF | small N | ✔ (and the sanitize job) |
| `control-ingress`, `control-egress` | row + column + reader | direct | small N | ✘ never |
| `py-df` (S6) | `client.dataframe` + egress | direct pool | small N | ✔ |

**Datatype coverage** — every ingress leg writes one column per QWP wire type
its route supports, generated deterministically from `(seed, worker_id, seq)`
(shared generator spec so Rust/C/Python produce identical values):

`BOOLEAN, BYTE, SHORT, INT, LONG, FLOAT, DOUBLE, SYMBOL, TIMESTAMP, DATE,
UUID, LONG256, GEOHASH, VARCHAR, TIMESTAMP_NANOS, DOUBLE_ARRAY, DECIMAL64,
DECIMAL128, DECIMAL256, CHAR, BINARY, IPV4`
(source of truth: `questdb-rs/src/ingress/column_sender/wire.rs`).

Generators must hit edge values on a fixed cadence: NULLs per nullable type,
NaN/±Inf, min/max integers, empty/oversized varchar & binary, zero-length and
max-dim arrays, all decimal scales, non-ASCII symbols (exercises the Unicode
case-folding path). The expected-value model encodes **server-side
canonicalisation** — the oracle compares against what QuestDB defines as the
read-back value, not what was sent (e.g. a double `NaN` reads back as `NULL`;
geohash truncates to the declared column precision).

Every table: `worker_id` + `seq LONG` + the type columns + designated
timestamp **derived from `seq`** (monotonic per worker; no wall-clock in
data). Each ingress leg splits its workers across two table flavours: plain
WAL, and `DEDUP UPSERT KEYS(ts, worker_id)` for the exactness assertion
(split — not doubled — write volume).

**Egress verification.** Egress legs query **sealed ranges**: snapshot a
worker's journal watermark `W`, then `SELECT … WHERE worker_id = w AND
seq <= W ORDER BY ts` against the **dedup flavour** — sealed + deduped means
the expected result is exactly regenerable from the seed even while ingest
continues. `rust-egress-whole` wires `on_failover_reset` and must return the
complete, in-order result across failovers; `rust-egress-stream` treats
`FailoverWouldDuplicate` as expected only inside episode windows, re-issues,
and reports both counts plus `FailoverResetEvent` fields (attempts, elapsed) into
its stats stream. Plain-flavour reads are dup-tolerant (distinct-seq checks
only).

**Rate control.** Every ingress leg runs a token-bucket
`target_rows_per_sec` knob — the point is sustained pressure and cycle
counts, not outrunning the server (a saturated server measures the server,
not the client). Defaults are sized so a 60-min `full` run keeps total
server-side data under ~20 GB on the runner volume.

---

## 6. Fault-injection episodes

Episodes fire on a seeded randomized schedule (uniform 3–7 min apart,
~10–15 per hour-run). One episode at a time; each is followed by a
**drain-and-verify checkpoint** before the next may fire.

| Episode | Action | Primarily validates |
|---|---|---|
| `server_graceful` | fixture SIGTERM → wait down → restart → `/ping` | reconnect, SF replay after clean restart |
| `server_kill9` | SIGKILL the server | reconnect + replay of unacked tail; server-side WAL recovery interplay |
| `client_kill9` | SIGKILL one workload, restart with same journal/`sf_dir` | **SF-disk crash recovery** (orphan scan, segment replay); journal resume for direct/SF-mem |
| `client_graceful` | SIGTERM (workload flushes, syncs, exits 0), restart | clean shutdown path releases slots/FDs; **LSan report in sanitize profile** |
| `conn_reset` | proxy resets all (or one) connections, optionally after N bytes | mid-flush failure, `line_sender_error_failover_retry` path, pool drop+borrow |
| `stall` | proxy stops forwarding 10–60 s | ack starvation, `MAX_IN_FLIGHT` backpressure, sync timeout, health marking |
| `throttle` | proxy caps bytes/sec for 1–3 min | sustained backpressure; SF backlog growth then drain |
| `sf_disk_full` | `sf_dir` on a small loopback fs; fill → clear | disk-full surfaces a clean documented error (no corruption); recovery after space freed |

Client-restart semantics the oracle must encode (not treat as bugs):

- **SF-disk + `client_kill9`**: everything the store accepted must survive —
  recovery replays segments; journal resume re-sends anything unacked.
  Duplicates possible, loss not.
- **SF-mem + `client_kill9`**: queued-but-unsent data **dies with the process
  by design**. The journal watermark is the only guarantee; the oracle asserts
  completeness up to the watermark only.
- **Direct + `client_kill9`**: same watermark rule.

`stall` against an SF-mem leg with a small `max_bytes` additionally asserts
the documented backpressure error surfaces (bounded memory, no OOM, no
silent drop).

---

## 7. Oracle — pass/fail invariants

Violation of any invariant fails the run. All thresholds are harness config
with the defaults below; the first calibration week runs I4 in **advisory
mode** (reported, not gating — see §10). Oracle independence: I1/I2
aggregates run over an **independent query path** (HTTP `/exec`), never
through the client under test; I3 deliberately reads through the egress
client, so value verification doubles as egress coverage.

**I1 — Completeness (no loss).** Per worker:
`count_distinct(seq) == max(seq)+1` over `[0, journal_watermark]`, i.e. every
seq up to the fsync'd ack watermark is present, no gaps anywhere.

**I2 — Bounded duplication.** `count(*) - count_distinct(seq)` per leg must
be ≤ the leg's replay-window budget:
`episodes_hitting_leg × replay_window_rows` (column sender:
`64 × max_rows_per_batch`; row API: max unacked in-flight window). Control
legs: **exactly 0**. Dedup-table flavour, **per worker**:
`count(*) == count_distinct(seq)` exactly.

**I3 — Value correctness (all datatypes).** For K (default 1000) seeded-random
`seq` values per leg: read the full row back via the egress reader and compare
every column against the regenerated expected value — exact for integral
types/decimals/UUID/binary/symbol, bit-exact for float/double (same generator
both sides), NULL-pattern match. Plus cheap whole-leg aggregates
(`sum(long_col)`, `count(bool_col)` where true, …) against closed-form
expected values.

**I4 — Resource boundedness.** From `stats.jsonl`, discard warmup (first
10 min), then:
- **RSS slope** per workload process over the steady state (least-squares) ≤
  100 KiB/min, and total steady-state growth ≤ 10%. Backstop: RSS never
  exceeds 4× warmup peak.
- **FD count** returns to the pre-episode baseline (±4) within 60 s after
  every episode's drain; steady-state slope ≈ 0.
- **Pools**: `in_use` returns to steady baseline after each episode and is 0
  at final quiesce; `free ≤ pool_max`; `closing` drains to 0.
- **SF disk**: `du(sf_dir)` and `allocated_segment_bytes` return to ~baseline
  after each drain (segments reclaimed — catches "files never deleted");
  SF-mem backlog ≤ configured `max_bytes` at all times.

**I5 — Sanitizer-clean.** The sanitize profile exits with no ASan errors and
no LSan leak reports from any workload process (processes exit cleanly at
episode boundaries precisely so LSan can report).

**I6 — Recovery liveness.** After every episode, each affected leg's acked
watermark advances again within 60 s of the fault clearing. At final
quiesce, `published_fsn == completed_fsn` (SF fully drained) within a 60 s
deadline — catches stuck replay, which "didn't crash" would miss.

**I7 — Error hygiene.** Every error a workload observes is in the expected
set for the active episode window (`failover_retry`, `FailoverWouldDuplicate`,
reader reconnect/timeout codes during `stall`, documented
backpressure/disk-full codes). Any unexpected code, any error
outside an episode window, or any workload abort ⇒ fail. `QwpWsCounters`
sanity: `total_reconnects_succeeded` ≥ number of connection-severing episodes.

Final reconciliation (I1–I3) runs in a **quiet period**: last episode →
3 min quiesce → SF drain deadline (I6) → queries. Mid-run reconciliation
passes are logged for triage but only the final one gates.

---

## 8. S0 — observability prerequisites (library changes)

Small, `dbg_`-prefixed (matching the existing
`questdb_db_dbg_reader_free_count` precedent), explicitly **unstable /
diagnostics-only** surface. Without these, I4/I6 cannot be asserted.

| Where | Addition |
|---|---|
| `questdb-rs/src/db.rs` | `QuestDb::dbg_pool_counts() -> DbgPoolCounts` — `{free, in_use, closing}` for each of the four pools (`row_sender_state`, `state` (col SF), `direct_state`, `reader_state`) |
| `qwp_ws_sfa_queue.rs` | de-`#[cfg(test)]` `allocated_segment_bytes()` and `sealed_segment_count()`; add `backlog_frames()` (published − completed) and `backlog_bytes()` (mem variant: queued bytes vs `max_bytes`) |
| `qwp_ws_driver.rs` | `QwpWsCounters` snapshot accessor on the sender handles (`dbg_counters()`), covering frames sent/acked, reconnect attempts/successes, server errors |
| `questdb-rs-ffi` + `include/questdb/…` | C getters mirroring all of the above (`questdb_db_dbg_*`, `line_sender_dbg_*`), so the C leg and sanitize job sample the same counters |

Acceptance: each accessor unit-tested; zero cost when unread (plain reads of
existing state/atomics; no new locks on hot paths — pool counts read under
the existing pool mutex, same as `reap_idle`).

---

## 9. CI integration

New pipeline `ci/run_soak_pipeline.yaml` (Azure DevOps, cloned from
`run_fuzz_pipeline.yaml`):

- **Trigger:** every PR to `main` runs the full ~1h soak (no schedule). A
  fast `SoakSelftest` pre-gate fails a broken harness in minutes before the
  hour is spent; `SoakFull` runs after it passes.
- **Manual dispatch** with queue-time parameters: `SOAK_DURATION_MIN`
  (default 60), `SOAK_SEED` (default `$(Build.BuildId)`), `SOAK_PROFILE`
  (`full` | `sanitize` | `quick`).
- **Job 1 `SoakFull`** (Hetzner incus, Linux): build QuestDB master (existing
  templates), build workloads (release), run
  `python3 system_test/soak/soak.py run --repo ./questdb --profile full
  --duration $(SOAK_DURATION_MIN) --seed $(SOAK_SEED)`. Timeout duration
  + 30 min.
- **Job 2 `SoakSanitize`**: C legs linked against the existing
  `-DQUESTDB_SANITIZE=ON` build (LSan sees Rust-core heap too — the Rust
  static lib uses the system allocator, so its allocations are
  malloc-backed; verify this assumption in the S5 spike). Reduced duration
  (20 min), reduced throughput, `client_graceful` episodes emphasized so
  LSan reports fire at process exits. A nightly-Rust
  `-Zsanitizer=address` build of the Rust workload is a stretch goal, not a
  gate.
- **`NotifyOnFailure`** → Slack `#builds`, same as the fuzz pipeline.
- **Artifacts (always):** `stats.jsonl`, `summary.json` (per-invariant
  verdicts + violating windows), client journals, episode log with the seed.
  **On failure additionally:** server logs (existing archive step), `ls -lR`
  of every `sf_dir`, last N MB of workload stderr. `summary.json` prints the
  one-line repro: `soak.py run --seed <seed> --duration <n> --profile <p>`.
- **`SoakSelftest`** (the PR pre-gate, ~minutes): the harness component
  selftests + workload-crate build + Rust/Python golden-vector parity diff.
  Fail-fast so a broken harness never burns the full hour.

---

## 10. Workstreams

| # | Deliverable | Done when | Depends on |
|---|---|---|---|
| **S0** | `dbg_` observability surface (§8) in `questdb-rs` + FFI | accessors unit-tested; C getters callable; no hot-path cost | — |
| **S1** | Workload processes: Rust binary (`system_test/soak/workload_rs/`, standalone crate, path-dep on `questdb-rs`, **not** in the published workspace) implementing every Rust leg in §5 (legs selected by flag); C sidecar (`c_sidecars` pattern) for `c-row`/`c-col`; shared deterministic generator spec (all 22 types + edge cadence); journal + stats emission | each leg runs standalone against a local server; identical values regenerable from seed; journal resume verified by a unit-style kill test | S0 |
| **S2** | Orchestrator `system_test/soak/soak.py`: fixture reuse (+`kill9()`), process supervision, sampler (psutil RSS/FD), stats merge, episode scheduler (seeded) | `--profile quick` end-to-end run green locally; every §6 episode implemented behind one interface | S1 (interface only; can start in parallel) |
| **S3** | Fault proxy (`fault_proxy.py`): reset / reset-after-N-bytes / stall / throttle; `sf_disk_full` loopback-fs rig | proxy unit tests; each episode demonstrably triggers its target client path (observed via S0 counters) | — |
| **S4** | Oracle: reconciliation queries (I1–I3), boundedness evaluation (I4), liveness (I6), error-hygiene ledger (I7), `summary.json` | seeded fault run passes; seeded run with a planted bug (workload `--plant=<fault>` debug flags, e.g. leak a conn on the error path) **fails** with the right invariant — the oracle is itself tested both ways | S1, S2, S3 |
| **S5** | CI: `run_soak_pipeline.yaml` (nightly + manual params), sanitize job (incl. the LSan-sees-Rust-heap spike), artifacts, Slack, PR `selftest` step | nightly green twice consecutively; artifacts inspectable; selftest in PR pipeline | S4 |
| **S6** | Python leg (`py-df`): workload module here, driving the `py-questdb-client` wheel; tracemalloc snapshot deltas in its stats | Python ingest+egress leg passes I1–I4 under faults | S4; wheel availability |

Calibration: S5's first week runs I4 in advisory mode; thresholds are then
frozen from observed clean-run envelopes and I4 starts gating.

---

## 11. Risks & open questions

1. **I4 threshold flakiness.** Allocator behaviour (arena growth, glibc trim)
   can mimic slow leaks. Mitigations: warmup discard, slope-not-absolute
   gating, control legs as reference curves, advisory week, and the
   sanitize profile as the ground-truth leak detector.
2. **Duplicate attribution is coarse.** I2 bounds duplicates per leg for the
   whole run rather than per episode window. Acceptable for v1 (control legs
   pin the zero case; budgets are formula-derived, not vibes).
3. **LSan coverage of the Rust core via the C link** rests on the
   default-system-allocator assumption. Spike first in S5; fallback is the
   nightly-Rust ASan build of the Rust workload.
4. **Server bugs failing the client pipeline.** A master-built server can
   itself leak/regress. Triage aid: server RSS + logs are archived; I-failures
   whose evidence points server-side get routed to the server repo, and the
   harness can pin a released server (`fixture.install_questdb`) to bisect.
5. **Hetzner pool contention** with the hourly fuzz pipeline. Nightly
   off-peak slot; soak job declares a lower pool priority if supported.
6. **Column-SF v1 single-slot pool** limits in-process SF concurrency;
   covered by scaling across processes (distinct `sender_id`/`sf_dir`). When
   multi-slot lands, raise the in-process concurrency knob — matrix, not
   design, changes.
7. **`sf_disk_full` on loopback fs needs root/loop devices** on the runner.
   Fallback: a tiny `max_bytes`-quota mode or a `fallocate`-filled directory
   quota; decide during S3.
8. **Egress consistency reads after failover** (`target=any` vs `primary`)
   can read stale data on Enterprise topologies; v1 single-endpoint avoids
   this, but reconciliation queries should set `target=primary` now so the
   Enterprise variant inherits correctness.

---

## 12. Decisions log

- **Every PR runs the full 1h soak + manual dispatch, not a one-off manual
  run.** A manual hour decays the day it's run; gating each PR on the hour
  makes the harness a hard regression net. A fast `SoakSelftest` pre-gate
  fails a broken harness in minutes so the hour is only spent on real runs.
  **Settled.**
- **Oracle over duration.** 60–90 min at high throughput with sampled
  resource curves, sanitizers, and reconciliation beats an unstrumented
  multi-hour run; duration stays a knob. **Settled.**
- **Workloads are killable OS processes with fsync'd ack journals.**
  Enables client-restart coverage, per-process LSan, and a construction-level
  no-gap guarantee (resume from watermark). **Settled.**
- **At-least-once encoded in the oracle.** No-loss is absolute (I1);
  duplication is budgeted by the replay-window formula (I2); exactness is
  asserted on the `DEDUP UPSERT KEYS` flavour; control legs must be
  dup-free. **Settled.**
- **SF-mem + client kill loses unacked data by design** — the oracle asserts
  up to the journal watermark only; never reported as a bug. **Settled.**
- **S0 `dbg_` surface is a prerequisite** and is explicitly unstable
  diagnostics API, following the `questdb_db_dbg_reader_*` precedent.
  **Settled.**
- **QWP/WS scope only in v1**; ILP legacy paths and multi-endpoint
  (Enterprise) failover are extension points (`enterprise_e2e` hook kept).
  **Settled.**
- **Linux-first** (sampler + runners); functional cross-platform coverage
  stays in the per-PR pipeline. **Settled.**
- **Seeded determinism throughout** (episode schedule, data generation,
  sampling of I3 rows); no wall-clock-derived data. One seed = one repro.
  **Settled.**
- **Fault proxy over `tc netem`** for portability/no-root; netem stays an
  optional Linux extra. **Settled.**
- **PR gate is the full 1h soak**, fronted by the fast `SoakSelftest`
  pre-gate (harness selftests + workload build + generator parity) so a
  broken harness fails in minutes, not after the hour. **Settled.**
