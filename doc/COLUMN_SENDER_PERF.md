# Column-Major Sender — Performance Notes

Tracks the bench results that anchor `doc/COLUMN_SENDER_PLAN.md` §2.1
("encode is a header + extend_from_slice per column") and §2.2 ("no-null
= memcpy; nullable = invert+gather").

The Criterion bench lives at `questdb-rs/benches/column_sender.rs`. It
covers three families:

1. **Per-column bulk append** — each column-type's hot path vs a raw
   `extend_from_slice` baseline.
2. **Symbol bulk-intern** — `Chunk::symbol_dict_i32` vs a naïve per-row
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

## First-baseline numbers

Captured on an Apple Silicon laptop, default workload
(`rows = 100_000`, `varchar_len = 16`, `sym_card = 1_000`),
`cargo bench ... -- --quick --noplot`. Replace with refreshed numbers as
the encoder evolves.

| Bench                               | Median time | Median throughput   | Notes |
|-------------------------------------|------------:|--------------------:|-------|
| `column_i64/memcpy_baseline`        |     ~143 µs |     ~5.2 GiB/s      | High variance — bare `Vec` alloc + push + extend on a 800 KB allocation dominates. |
| `column_i64/column_sender_no_null`  |    ~13.7 µs |     ~54 GiB/s       | Memcpy-bound; matches the plan's "no-null = `extend_from_slice`" goal. |
| `column_i64/column_sender_nullable` |    ~79.1 µs |     ~9.4 GiB/s      | Sentinel-encode per row (`i64::MIN` for nulls). |
| `column_f64/memcpy_baseline`        |    ~13.6 µs |     ~54.7 GiB/s     | |
| `column_f64/column_sender_no_null`  |    ~13.5 µs |     ~55 GiB/s       | Indistinguishable from memcpy. |
| `column_varchar/memcpy_baseline`    |    ~63.6 µs |     ~29.3 GiB/s     | Offset table + bytes copy. |
| `column_varchar/column_sender_no_null` | ~67.0 µs |     ~27.8 GiB/s     | Within ~5 % of memcpy; rebase-to-zero path is the same as memcpy when `offsets[0] == 0`. |
| `symbol_dict/column_sender`         |     ~135 µs |  ~740 M rows/s      | 100k rows × 1 000-card dict; three-pass bulk-intern. |
| `symbol_dict/naive_per_row_hashmap` |    ~2.16 ms |   ~46 M rows/s      | Per-row HashMap probe; mirrors what the row API pays. **~16× slower than the column path** — confirms the WS-4 plan claim (drops 100k probes to 1 000 interns). |
| `encode_chunk/populate_only`        |     ~294 µs |  ~341 M rows/s      | 5 columns (i64, f64, varchar, symbol, designated_ts); all bulk-append calls. |
| `encode_chunk/encode_only`          |     ~437 µs |  ~229 M rows/s      | Header + dict-delta + table block + per-column splices. |
| `encode_chunk/populate_plus_encode` |     ~718 µs |  ~139 M rows/s      | End-to-end, no network. |

A second-pass `encode_chunk/encode_only` on the same workload should
land in **REFERENCE mode** for the schema (because the registry caches
the signature from the first encode), shaving off the FULL-mode
signature bytes — see `doc/COLUMN_SENDER_PLAN.md` §2.1.

## Interpreting the baseline

- The **`column_f64/column_sender_no_null` ≈ memcpy** result is the
  load-bearing perf claim of the column sender: a contiguous typed
  buffer pays the cost of a `memcpy` and nothing more. The chunk's
  per-column `Vec<u8>` storage absorbs the null-flag byte + payload in
  one extend; encode time then turns each column into a single
  `extend_from_slice`.
- The **`column_i64/memcpy_baseline` variance** is bench noise from the
  large per-iteration allocation in the baseline (a fresh
  ~800 KB `Vec` per sample). The column-sender path reuses its
  `Vec::with_capacity(16)` seed and grows in place, which the
  allocator handles more uniformly. Both medians are well above
  network bandwidth, so this is not the bottleneck.
- The **nullable I64 path** at ~9.4 GiB/s is the sentinel-encode loop
  (`if v.is_valid(i) { value } else { I64_NULL }`), bounded by branch
  prediction. It still moves the same 800 KB; a SIMD lowering would
  close the gap with the no-null path but isn't necessary to hit the
  "memcpy-bound when the user has no nulls" bar.
- The **symbol bulk-intern speedup (~16×)** comes from the WS-4
  three-pass design — referenced bitset, compact dict copy, code
  translation. At 100k rows × 1 000-card dict the column path runs
  1 000 interns plus 100 000 `Vec<u32>` writes; the naïve path runs
  100 000 HashMap probes.

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
