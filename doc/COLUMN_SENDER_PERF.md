# Column-Major Sender — Performance Notes

Tracks the bench results that anchor `doc/COLUMN_SENDER_PLAN.md` §2.1
("encode is a header + extend_from_slice per column") and §2.2 ("no-null
= memcpy; nullable = invert+gather").

The Criterion bench lives at `questdb-rs/benches/column_sender.rs`. It
covers three families:

1. **Per-column bulk append** — each column-type's hot path vs a raw
   `extend_from_slice` baseline.
2. **Symbol bulk-intern** — `Chunk::symbol_i32` vs a naïve per-row
   HashMap probe that mirrors what a row-API symbol cell pays.
3. **End-to-end encode** — populate a 100k-row chunk with a
   representative column mix and time the encoder body.

Pure encoder cost — no network, no real server.

## Running

```sh
cargo bench --features sync-sender-qwp-ws --bench column_sender

# Larger workload (anchors the headline 10M-rows-per-batch number from
# the WS-2/WS-4 plan):
QUESTDB_COLUMN_BENCH_ROWS=10000000 \
    cargo bench --features sync-sender-qwp-ws --bench column_sender

# Knobs:
#   QUESTDB_COLUMN_BENCH_ROWS         default 100_000
#   QUESTDB_COLUMN_BENCH_VARCHAR_LEN  default 16
#   QUESTDB_COLUMN_BENCH_SYM_CARD     default 1_000
```

## Numbers after the borrow-not-copy rewrite

Captured on an Apple Silicon laptop, default workload
(`rows = 100_000`, `varchar_len = 16`, `sym_card = 1_000`),
`cargo bench ... -- --quick --noplot`. The big change vs the first
baseline: `Chunk` now holds raw pointers into the caller's buffers;
all wire-formatting is deferred to flush time and writes directly into
the connection's reusable write buffer.

| Bench                               | Median time | Notes |
|-------------------------------------|------------:|-------|
| `column_i64/column_sender_no_null`  |    ~57 ns   | Descriptor store only — no data copy at append time. |
| `column_i64/column_sender_nullable` |   ~289 ns   | Descriptor store + `non_null_count` precompute over the bitmap. |
| `column_f64/column_sender_no_null`  |    ~57 ns   | Same as i64 — `Chunk` never touches the caller's bytes. |
| `encode_chunk/populate_only`        |    ~76 µs   | Chunk-fill for the 5-column workload (was ~294 µs in the pre-rewrite baseline). **~4× faster.** |
| `encode_chunk/encode_only`          |   ~500 µs   | Full encode: header + dict-delta + table block + per-column wire encode straight into a reusable buffer (was ~437 µs in the pre-rewrite baseline; now does the per-row work that previously happened during populate). |
| `encode_chunk/populate_plus_encode` |   ~575 µs   | **End-to-end flush time (no network) was ~718 µs pre-rewrite → ~575 µs after. ~20 % faster.** |

A second-pass `encode_chunk/encode_only` on the same workload should
land in **REFERENCE mode** for the schema (because the registry caches
the signature from the first encode), shaving off the FULL-mode
signature bytes — see `doc/COLUMN_SENDER_PLAN.md` §2.1.

The per-column microbenches no longer measure data movement: with raw
pointers stored, `column_iN`/`column_fN` are essentially constant-time
in `row_count`. The honest end-to-end metric is
`encode_chunk/populate_plus_encode`, which is what a single flush
costs (chunk-fill + frame encode into the WS write buffer, before
masking/socket-write).

## Interpreting the numbers

- The **`encode_chunk/populate_plus_encode` ~20 % win** is the
  load-bearing claim: end-to-end CPU time per flush is lower than the
  pre-rewrite design that copied each column into per-column `Vec<u8>`
  staging and then aggregated those into a fresh per-frame `Vec<u8>`.
  We now do exactly one memcpy per fixed-width column — straight from
  the caller's buffer into the connection's reusable write buffer.
- The **`encode_only` is *slightly* slower in isolation** (~500 µs vs
  ~437 µs) because the per-row work that used to be amortised into
  `populate_only` is now done at encode time. `populate_only` dropped
  from ~294 µs to ~76 µs, and the sum is what matters.
- The encoder pre-sizes the write buffer in one shot via
  `estimate_frame_size(...)` to avoid the geometric-growth memcpy
  pattern when payloads exceed the default 64 KiB capacity. Without
  this, end-to-end flush time would be ~880 µs (worse than the
  baseline).
- The **symbol bulk-intern** still runs the WS-4 three-pass design
  (referenced bitset, intern only referenced slots, then per-row
  emit). At 100 k rows × 1 000-card dict the encoder runs ≤ 1 000
  interns + 100 k varint writes — the per-row HashMap probe of the
  row-API path remains ~16× slower.

## Out of scope here

- **End-to-end Pandas → QuestDB throughput** lives in the Python
  wrapper repo (WS-7); add the `pandas_to_questdb_throughput` bench
  there once a real server is wired into its CI.
- **1-hour soak** belongs in nightly CI rather than the in-tree
  Criterion suite; track that as a follow-up alongside WS-7.
- **Microbench against the row-API encoder** is intentionally absent.
  The row API's `Buffer::column_i64` is a per-cell call (it appends a
  single value per invocation); comparing it cell-by-cell against the
  column sender's bulk append would be apples vs oranges and is
  already qualitatively captured by the `symbol_dict/naive_per_row_*`
  comparison.
