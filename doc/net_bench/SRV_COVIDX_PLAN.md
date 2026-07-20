# Server covering-index ingest campaign (`srv-covidx`)

Design spec, 2026-07-20. Companion to `QWP_NETWORK_BENCH_PLAN.md`, but the
target flips: previous campaigns measured **clients** against a fixed server;
this one measures the **server's WAL-apply path** under a fixed, calibrated
client load. Motivated by a field-reported backfill workload: a narrow
3-column telemetry table with a POSTING covering index, ingested at
~2.2M rows/s with default client batching (~1k rows per transaction,
i.e. ~2.2k txns/s), ~2k unique symbols with a heavily skewed (zipfian)
distribution.

## Goals

1. **Covering-index ingest cost (A/B).** Same load, two tables — POSTING
   covering index vs no index. Price the index on the apply path: sustained
   rows/s, apply lag, CPU, write amplification, memory.
2. **Server ceiling under the reference regime.** Drive the covering-index
   table past 2.2M rows/s (1k rows/txn) and find where the server plateaus
   and what saturates first (apply workers, index generations, seal job,
   disk).

Non-goals: query-side benefit of INCLUDE, bitmap-index comparison, client
performance (clients are calibrated instruments here, not subjects).
Stability defects found along the way are by-catch, filed separately.

## Server under test

OSS build at the campaign pin `5b2efe5e` (same lineage as prior campaigns;
contains the full posting-index implementation including the recent
skewed-symbol seal/OOM and O3-commit fixes). Default server configuration
except `http.recv.buffer.size=16m` (rig default from prior campaigns);
every non-default key is recorded in the run sidecar.

Key mechanism being priced (from `PostingIndexWriter`): *each commit appends
one generation covering all keys* to the index, and INCLUDE additionally
copies the covered columns into sidecar files per commit. At 1k rows/txn the
commit rate — not just the row rate — multiplies index write cost; a
background seal job (`PostingSealPurgeJob`) compacts generations behind the
writer. This is why the reference regime's small transactions matter and why
our previous 10k-row batches would understate the cost ~10x.

## Tables

Two variants, identical except for the index clause. No DEDUP, no explicit
SYMBOL CAPACITY (reference DDL has neither):

```sql
CREATE TABLE bench_s3_cov (
    timestamp TIMESTAMP_NS,
    symbol SYMBOL INDEX TYPE POSTING INCLUDE (value, timestamp),
    value FLOAT
) timestamp(timestamp) PARTITION BY HOUR;

CREATE TABLE bench_s3_plain (
    timestamp TIMESTAMP_NS,
    symbol SYMBOL,
    value FLOAT
) timestamp(timestamp) PARTITION BY HOUR;
```

(The reference DDL also carries per-column `PARQUET(...)` encoding hints;
they are inert on the native-format ingest path and are dropped here.)

## Load generator

New rust example `qwp_ingress_srvidx.rs` (questdb-rs, alongside
`qwp_ingress_row.rs`, reusing its harness conventions: env-var parameters,
JSON result output, per-pass process-CPU accounting). Row path only —
`flush_and_get_fsn` per batch, so **1 flush = 1 frame = 1 WAL txn** exactly.

- **Batch:** `MAX_BATCH_ROWS=1000` (1 txn per 1k rows).
- **Symbols:** 2,000 values `sym0000`..`sym1999`; zipfian rank-frequency,
  exponent `s = 1.0` (over 2k ranks this yields a ~2000:1 hottest:coldest
  ratio, matching the reported ~1–1500 Hz per-symbol spread). Sampler:
  precomputed cumulative zipf table + binary search on a seeded PRNG.
- **Timestamps:** strictly ascending at reference data density,
  **+5405 ns per row** (~185k rows per data-second, derived from ~2B rows
  per few-hour backfill unit) → ~660M rows per hourly partition. Fixed
  start epoch `2026-01-01T00:00:00Z`. At 2.2M rows/s ingest this advances
  data-time ~12x faster than wall time (partition roll every ~5 wall-min
  at scale; local 100M-row passes stay inside one partition).
- **Value:** seeded random `f32` via `column_f32` (QWP transport supports
  FLOAT natively).
- **Determinism:** seed = 42 + pass index; identical row stream across
  variants and boxes.
- **Multi-sender:** total rows split round-robin (sender k takes rows
  `i mod N == k`), each sender's stream stays ascending; the merged apply
  stream is near-ordered. The 1-sender cell is the pure in-order reference.

## Cells and pass structure (steady state)

Matrix: `{cov, plain} x {1, 2, 4, 8 senders}`, per box.

Per pass: `DROP TABLE IF EXISTS` + `CREATE`, then WARMUPS=2 + ITERATIONS=5
measured passes (prior-campaign convention). Rows per pass: **100M on the
local M4**, **500M on the Ryzen 9950X3D**. Ceiling = the sender count where
sustained applied rows/s plateaus on `cov`; compared against the same
plateau on `plain` and against the 2.2M rows/s reference line. Client CPU
per pass is recorded as always — with the known client-side floor it proves
the server, not the generator, is the limiter.

## Growth run (one)

Covering variant only, Ryzen box, sender count = smallest that saturates
(from the steady-state sweep). Continuous backfill of **~2B rows** (≥3
hourly partitions, multiple partition rolls), no table recreation. Sampled
every ~5s: applied rows/s, WAL apply lag, server RSS, `du` of table dir
split into column files vs index vs covered sidecar, seal-job activity from
server logs. Answers whether index cost degrades as generations and
partitions accumulate — invisible to fresh-table passes.

## Metrics (per pass unless noted)

- **Applied rate** (headline): rows / wall time until WAL fully drained
  (`wal_tables()`: writerTxn == sequencerTxn). Also reported: flush-ack
  rate (rows / time to last ack) and **drain time** after last flush.
- **Apply lag over time:** writerTxn vs sequencerTxn sampled ~1s.
- **Server CPU:** process total everywhere; per-thread breakdown
  (writer / apply / seal) on Linux via `/proc/<pid>/task` sampling.
- **Write amplification:** OS-level bytes written to the DB root during the
  pass vs raw ingested bytes; end-of-pass `du` split (columns / index /
  sidecar).
- **Server RSS**, and seal/purge log lines count.
- Client-side: process CPU per pass (existing harness output).

## Boxes and phases

1. **P1 — local M4:** build the generator, validate DDL + f32 + ns path
   end-to-end, smoke the metrics harness, first 100M-row A/B.
2. **P2 — Ryzen 9950X3D (Linux):** full matrix, ceiling sweep vs the 2.2M
   line, per-thread CPU attribution, growth run.
3. **P3 — AWS rig (optional):** only if Graviton-comparable numbers are
   needed against prior campaigns; same layout as before (client box →
   server box).

## Results

`doc/net_bench/results/srv-covidx-<date>/` in the usual campaign format
(per-cell JSON + sidecars + findings notes). Workload described generically
in all committed artifacts.

## Harness usage

Generator: `questdb-rs/examples/qwp_ingress_srvidx.rs` (module
`bench_srvidx` holds the data contract). Build:

    cargo build --release --example qwp_ingress_srvidx \
        --features sync-sender-qwp-ws,sync-sender-http

Generator invariants (no server needed): `RUN_MODE=selftest cargo run
--example qwp_ingress_srvidx --features
sync-sender-qwp-ws,sync-sender-http`.

One local cell (server already running):

    doc/net_bench/srvidx_local.sh <cov|plain> <senders> <rows> <outdir> [tag]

Env: `QDB_HOST/QDB_PORT` (default 127.0.0.1:9000), `QDB_ROOT` (enables
table-dir du sampling + Linux write-amplification meta), `MAX_BATCH_ROWS`
(default 1000 = rows per WAL txn), `ITERATIONS`/`WARMUPS` (defaults 5/2),
`DRAIN_DEADLINE_S` (default 900; raise for growth runs — a degraded apply
path can legitimately need longer terminal drains).

Outputs per cell: `<cell>.json` (bench_json contract; headline =
`applied_rows_per_s`, gates = `row_count_check` + `txn_check`),
`<cell>.sampler.csv` (1 Hz: writerTxn, sequencerTxn, server RSS KB,
table-dir KB), `<cell>.meta`.

Per-pass semantics: fresh table (`DROP`+`CREATE`), timed flush across N
round-robin senders (each 1k-row flush = exactly one WAL txn), then a
`wal_tables()` drain poll — `srvidx-applied` is flush+drain wall, the
campaign headline; `srvidx-drain`'s rate is the server's backlog-apply
throughput. Seed = 42 + pass index, so every box/variant/sender-count
ingests the identical dataset.

The growth run is the same tool with `ITERATIONS=1 WARMUPS=0
ROWS=<billions>`: one fresh table, one continuous backfill, the 1 Hz
sampler CSV carries the whole trajectory (lag, RSS, table size over time).

Server process-CPU sampling (and the per-thread/du-class/seal-log metrics)
is deferred to the P2 Linux harness.
