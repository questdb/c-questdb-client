# Unified QWP ingress Milestone 0 baseline

This file freezes the correctness and performance baseline required by
`QWP_UNIFIED_SENDER_DESIGN.md`. Product code was unchanged when these numbers
were captured.

## Environment

| Item | Value |
|---|---|
| c-questdb-client | `72a6b52fa84fbe702ab2037d7d799569587156a0` |
| QuestDB server | `9.4.4-SNAPSHOT`, commit `0e9453ac5333626ae9d9fa91893ba944f74a7ab5` |
| JDK | 25.0.3 |
| OS | Linux 7.0.0-27-generic x86_64 |
| CPU | AMD Ryzen 9 9950X, 16 cores / 32 threads |
| Rust | rustc 1.95.0, cargo 1.95.0 |

The real-path benchmark used one loopback QuestDB fixture and in-memory SFA:

```text
ws::addr=127.0.0.1:<fixture-port>;
sf_max_bytes=1073741824;
pool_size=1;
pool_max=1;
in_flight_window=128;
```

Each mode published 1,000,000 rows in 1,000-row frames with 1,000 symbols.
Three fresh-process runs used distinct tables. `rows_per_sec` covers input
construction plus synchronous encode/local queue append, but excludes the
final ACK drain. Queue latency covers only the flush call. Allocation counters
are reset after the sender and reusable input storage are constructed, cover
all threads in the benchmark process during publication, and are intended for
same-harness/same-machine comparisons, not as a universal absolute count.

Run one mode with:

```sh
QWP_WS_UNIFIED_SFA_BENCH_CONF='ws::addr=127.0.0.1:9000;sf_max_bytes=1073741824;pool_size=1;pool_max=1;in_flight_window=128;' \
QWP_WS_UNIFIED_SFA_BENCH_MODE=chunk \
QWP_WS_UNIFIED_SFA_BENCH_ROWS=1000000 \
QWP_WS_UNIFIED_SFA_BENCH_BATCH_SIZE=1000 \
cargo run --manifest-path questdb-rs/Cargo.toml --release \
    --features arrow-ingress --example qwp_ws_unified_sfa_bench
```

## SFA publish baseline

Medians of the three runs are the comparison values for M1, M4, and M6.

| Mode | Rows/s | Flush p50 | Flush p95 | Flush p99 | Alloc calls/batch | Alloc bytes/row | Peak live growth |
|---|---:|---:|---:|---:|---:|---:|---:|
| Buffer | 8,000,946 | 18.09 us | 26.37 us | 259.38 us | 1.588 | 0.6199 | 326,394 B |
| Chunk | 10,921,259 | 18.07 us | 31.03 us | 305.21 us | 7.211 | 1.2953 | 251,878 B |
| Arrow | 8,292,196 | 59.52 us | 89.44 us | 93.26 us | 32.640 | 111.9709 | 303,202 B |

Raw runs:

| Mode/run | Rows/s | p50 ns | p95 ns | p99 ns | alloc calls | alloc bytes |
|---|---:|---:|---:|---:|---:|---:|
| Buffer 1 | 5,317,866 | 18,620 | 41,320 | 2,933,705 | 1,318 | 613,382 |
| Buffer 2 | 8,000,946 | 18,090 | 26,371 | 259,381 | 1,588 | 619,862 |
| Buffer 3 | 8,050,007 | 17,930 | 23,750 | 50,740 | 1,654 | 621,446 |
| Chunk 1 | 10,326,596 | 17,990 | 37,850 | 467,532 | 7,211 | 1,295,320 |
| Chunk 2 | 10,921,259 | 18,240 | 31,030 | 305,212 | 7,210 | 1,295,296 |
| Chunk 3 | 11,181,208 | 18,070 | 30,030 | 282,431 | 7,224 | 1,295,641 |
| Arrow 1 | 8,292,196 | 59,411 | 89,440 | 93,261 | 32,628 | 111,970,579 |
| Arrow 2 | 8,427,813 | 59,520 | 78,151 | 89,300 | 32,640 | 111,970,914 |
| Arrow 3 | 8,273,491 | 59,610 | 89,531 | 116,230 | 32,700 | 111,972,362 |

No later milestone may add a payload copy, per-frame retained-payload
allocation, or dynamic dispatch to improve a noisy latency percentile. A
repeatable throughput loss above 5%, any increase in steady allocation counts,
or retained-buffer growth is treated as material and must be investigated.

## Chunk encoder floor

Command:

```sh
QUESTDB_COLUMN_BENCH_ROWS=100000 \
cargo bench --manifest-path questdb-rs/Cargo.toml \
    --features sync-sender-qwp-ws --bench column_sender -- \
    --quick --noplot encode_chunk
```

Criterion point estimates:

| Benchmark | Time | Throughput |
|---|---:|---:|
| `encode_chunk/populate_only` | 95.302 us | 1.0493 Gelem/s |
| `encode_chunk/encode_only` | 380.92 us | 262.52 Melem/s |
| `encode_chunk/populate_plus_encode` | 487.78 us | 205.01 Melem/s |

The M1 comparison uses both the real SFA Chunk row rate/allocation counts and
`populate_plus_encode`. M4 and M6 repeat all three real modes plus this encoder
floor.

## Milestone 1 comparison

M1 was measured with the same benchmark parameters, machine, JDK, and exact
QuestDB server revision recorded above. Chunk and Arrow each used three fresh
processes and distinct tables. The shared foreground transaction added no
payload copy or dynamic dispatch: both encoders write into its retained
`Vec<u8>`, and the queue borrows that allocation.

| Mode | Rows/s | Change | Flush p50 | Alloc calls/batch | Alloc bytes/row | Peak live growth |
|---|---:|---:|---:|---:|---:|---:|
| Chunk | 17,277,226 | +58.2% | 18.00 us | 7.210 | 1.3053 B | 251,906 B |
| Arrow | 16,032,262 | +93.3% | 59.13 us | 32.572 | 111.9657 B | 301,261 B |

Raw M1 runs:

| Mode/run | Rows/s | p50 ns | p95 ns | p99 ns | alloc calls | alloc bytes |
|---|---:|---:|---:|---:|---:|---:|
| Chunk 1 | 7,785,278 | 22,930 | 373,141 | 2,756,432 | 7,208 | 1,305,266 |
| Chunk 2 | 17,277,226 | 18,000 | 218,891 | 860,333 | 7,210 | 1,305,314 |
| Chunk 3 | 23,971,376 | 17,240 | 128,771 | 376,321 | 7,222 | 1,305,602 |
| Arrow 1 | 16,032,262 | 59,461 | 72,411 | 93,461 | 32,495 | 111,967,461 |
| Arrow 2 | 16,263,562 | 59,110 | 76,800 | 86,410 | 32,572 | 111,965,205 |
| Arrow 3 | 15,573,537 | 59,131 | 88,721 | 97,471 | 32,591 | 111,965,661 |

The frozen Chunk allocation-byte delta was traced to the benchmark's table-name
length, not the publisher. A controlled parent-versus-M1 run on one clean server
used equal-length table names: M0/M1 were respectively 7.213/7.209 allocation
calls per batch, 1.2984/1.2983 allocation bytes per row, and both had exactly
251,885 B peak live growth. The equivalent Arrow control also reduced allocation
calls (32.566 to 32.420) and bytes per row (111.9651 to 111.9615); its 120 B
global peak difference is background-thread timing noise, while total allocated
bytes fell by 3,552 B. Full Buffer/Chunk wire goldens remain byte-identical.

The M1 `populate_plus_encode` point estimate was 482.72 us (207.16 Melem/s),
1.0% faster than M0. Criterion reported no statistically significant change.
M1 therefore passes the no-material-regression and no-allocation-growth gates.

## Milestone 4 comparison

M4 used the same machine, JDK, QuestDB commit, connect string, row count,
batch size, and symbol cardinality as M0. The three fresh processes per mode
used distinct equal-length table names. These are the medians:

| Mode | Rows/s | Change from M0 | Flush p50 | Flush p95 | Flush p99 | Alloc calls/batch | Alloc bytes/row | Peak live growth |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Buffer | 15,112,809 | +88.9% | 18.48 us | 28.30 us | 48.77 us | 1.481 | 0.6703 B | 375,708 B |
| Chunk | 24,621,861 | +125.5% | 18.25 us | 111.11 us | 460.25 us | 7.216 | 1.2984 B | 251,885 B |
| Arrow | 14,996,053 | +80.8% | 62.94 us | 90.31 us | 112.20 us | 32.737 | 111.9692 B | 301,247 B |

Raw M4 runs:

| Mode/run | Rows/s | p50 ns | p95 ns | p99 ns | alloc calls | alloc bytes | peak live growth |
|---|---:|---:|---:|---:|---:|---:|---:|
| Buffer 1 | 6,719,661 | 19,130 | 37,840 | 2,098,960 | 1,434 | 670,302 | 375,708 B |
| Buffer 2 | 15,112,809 | 18,480 | 28,300 | 48,771 | 1,582 | 673,854 | 375,708 B |
| Buffer 3 | 17,404,170 | 17,580 | 25,600 | 29,960 | 1,481 | 667,382 | 373,660 B |
| Chunk 1 | 21,443,663 | 23,890 | 167,261 | 460,252 | 7,226 | 1,298,684 | 251,885 B |
| Chunk 2 | 24,621,861 | 18,250 | 99,861 | 510,282 | 7,216 | 1,298,444 | 251,885 B |
| Chunk 3 | 25,972,228 | 17,500 | 111,110 | 384,142 | 7,209 | 1,298,276 | 251,885 B |
| Arrow 1 | 15,005,569 | 63,180 | 83,031 | 116,250 | 32,744 | 111,969,319 | 301,247 B |
| Arrow 2 | 14,996,053 | 62,080 | 90,310 | 112,200 | 32,737 | 111,969,151 | 301,247 B |
| Arrow 3 | 14,520,015 | 62,941 | 91,771 | 97,611 | 32,732 | 111,969,079 | 301,127 B |

The raw Buffer allocation/peak columns include a measurement-boundary change,
not steady publication growth. M0's pooled row borrow completed its initial
network connection before returning; the unified SFA borrow is deliberately
offline-first and returns before that background work. A fixed-size allocation
trace identified three 16 KiB connection-worker allocations that sometimes
landed just after the benchmark reset. With both M0 and M4 given 100 ms for the
same connection to settle before resetting counters, the full-size equal-name
control was:

| Buffer control | Rows/s | Alloc calls/batch | Alloc bytes/row | Peak live growth |
|---|---:|---:|---:|---:|
| M0 | 16,907,452 | 1.505 | 0.6138 B | 324,379 B |
| M4 | 17,650,644 | 1.460 | 0.6165 B | 326,427 B |

The controlled M4 Buffer result is also below the frozen M0 allocation-byte
value (0.6199 B/row), and its 33-byte difference from the frozen 326,394 B peak
is background timing noise. For Arrow, an equal-name same-server M0 control and
M4 run both made exactly 32,732 allocation calls; M4 allocated only 48 more
bytes total and had 120 B less peak growth. Chunk run 3 matches the M1
equal-name control at 7.209 calls/batch, 1.2983 B/row, and 251,885 B peak
growth. There is therefore no steady allocation or retained-buffer increase in
any payload path.

The M4 `populate_plus_encode` point estimate was 481.48 us
(207.69 Melem/s), 1.3% faster than M0. Criterion reported no statistically
significant change. M4 passes the throughput, allocation, retained-buffer, and
no-dynamic-dispatch gates.

## Milestone 6 comparison

M6 repeated the frozen real-path suite against the same QuestDB commit,
machine, connect string, row count, batch size, and symbol cardinality. The
three fresh processes per mode used distinct equal-length table names. Medians
are taken independently for each metric, as at M0:

| Mode | Rows/s | Change from M0 | Flush p50 | Flush p95 | Flush p99 | Alloc calls/batch | Alloc bytes/row | Peak live growth |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Buffer | 15,701,122 | +96.2% | 18.15 us | 26.39 us | 115.53 us | 1.532 | 0.6715 B | 375,708 B |
| Chunk | 26,922,346 | +146.5% | 21.44 us | 108.86 us | 353.86 us | 7.223 | 1.2986 B | 251,885 B |
| Arrow | 15,162,132 | +82.8% | 62.81 us | 86.11 us | 98.14 us | 32.743 | 111.9693 B | 301,247 B |

Raw M6 runs:

| Mode/run | Rows/s | p50 ns | p95 ns | p99 ns | alloc calls | alloc bytes | peak live growth |
|---|---:|---:|---:|---:|---:|---:|---:|
| Buffer 1 | 7,822,043 | 18,700 | 39,370 | 2,148,849 | 1,324 | 667,662 | 375,708 B |
| Buffer 2 | 15,701,122 | 17,830 | 26,390 | 115,531 | 1,532 | 672,654 | 375,708 B |
| Buffer 3 | 17,103,181 | 18,151 | 24,860 | 50,300 | 1,653 | 671,510 | 373,660 B |
| Chunk 1 | 26,968,865 | 17,500 | 115,751 | 374,662 | 7,215 | 1,298,420 | 251,885 B |
| Chunk 2 | 18,511,708 | 21,440 | 108,860 | 353,861 | 7,223 | 1,298,612 | 251,885 B |
| Chunk 3 | 26,922,346 | 23,770 | 61,401 | 287,881 | 7,231 | 1,298,804 | 251,885 B |
| Arrow 1 | 15,162,132 | 62,810 | 86,111 | 98,140 | 32,743 | 111,969,295 | 301,247 B |
| Arrow 2 | 14,940,988 | 62,851 | 91,171 | 94,710 | 32,733 | 111,969,111 | 301,159 B |
| Arrow 3 | 15,266,625 | 62,800 | 80,160 | 100,460 | 32,802 | 111,970,711 | 301,247 B |

As at M4, the raw Buffer allocation boundary includes work from the unified
offline-first connection worker that the old blocking borrow completed before
returning. M6 added the benchmark-only
`QWP_WS_UNIFIED_SFA_BENCH_SETTLE_MILLIS` knob and interleaved the M0 and M6
binaries against the same server with 100 ms settling before counter reset.
The benchmark workload and product paths are unchanged by the knob.

| Controlled comparison | Rows/s | Change | Alloc calls/batch | Alloc bytes/row | Peak live growth |
|---|---:|---:|---:|---:|---:|
| Buffer M0, median of 3 | 16,307,709 | — | 1.723 | 0.6191 B | 324,373 B |
| Buffer M6, median of 3 | 16,984,541 | +4.15% | 1.709 | 0.6184 B | 324,373 B |
| Chunk M0 | 14,144,064 | — | 7.179 | 1.2421 B | 202,598 B |
| Chunk M6 | 23,582,581 | +66.73% | 7.176 | 1.2421 B | 202,598 B |
| Arrow M0 | 15,435,153 | — | 32.797 | 111.9162 B | 251,937 B |
| Arrow M6 | 15,179,011 | -1.66% | 32.747 | 111.9150 B | 251,937 B |

The Buffer controls were three interleaved pairs. Their M0 rows/s values were
15,838,462, 16,760,258, and 16,307,709; M6 values were 16,984,541,
16,928,835, and 17,427,644. The identical peak and lower M6 allocation counts
and bytes show that the unified publication core added neither a steady
allocation nor retained-payload growth. Chunk is likewise byte-for-byte equal
at the measurement boundary, and Arrow's 1.66% row-rate reduction is below the
frozen 5% materiality threshold while its allocation metrics improve.

The M6 encoder-floor point estimates were:

| Benchmark | M6 time | M6 throughput | Change from M0 |
|---|---:|---:|---:|
| `encode_chunk/populate_only` | 93.823 us | 1.0658 Gelem/s | 1.6% faster |
| `encode_chunk/encode_only` | 385.89 us | 259.14 Melem/s | 1.3% slower |
| `encode_chunk/populate_plus_encode` | 481.40 us | 207.73 Melem/s | 1.3% faster |

Criterion reported no performance change for all three comparisons. This
preserves the Chunk/Arrow fast path without a copy, allocation, or dynamic
dispatch regression.

## Python dataframe end-to-end comparison

The Python M5 checkout (`1f5fcbf`) and its pre-unification parent
(`ce4bc84`, with c-questdb-client `72a6b52`) each ran the live-server
`s1-narrow` fixture with 10,000,000 rows, three warmups, and five measured
iterations through the direct whole-source dataframe path. Both used the exact
QuestDB revision from the environment table, required the final DEDUP count to
equal 10,000,000, and were invoked as:

```sh
python3 test/run_pandas_columnar_layer3.py \
  --questdb-repo /path/to/frozen/questdb \
  --schema s1-narrow --rows 10000000 \
  --warmups 3 --iterations 5 --path real-client --pretty
```

| Revision | Median seconds | Rows/s | MiB/s | CoV | Final count |
|---|---:|---:|---:|---:|---:|
| Pre-unification | 0.521084 | 19,190,759 | 823.578 | 0.2270 | 10,000,000 |
| M6 | 0.478546 | 20,896,621 | 896.786 | 0.0387 | 10,000,000 |

M6 is 8.89% faster. The benchmark utility's wire-byte estimator exercises the
now-deprecated `Buffer.dataframe()` helper and therefore emits its expected
deprecation warning; the measured `real-client` path remains
`Client.dataframe()` and does not route the dataframe through rows.

## Correctness fixture

The two checked-in files under
`questdb-rs/src/tests/interop/qwp-unified-ingress/` encode identical logical
Buffer and Chunk data. At M0 the full wire payloads happen to be byte-identical;
the contract is still two specialized encoders writing independently into
their retained output. The golden test fails on any framing, schema, symbol-ID,
column-value, or timestamp drift.

## Milestone 6 soak evidence

The complete one-minute oracle run used the full workload matrix at 1,000 rows
per second per ingest leg:

```sh
python3 system_test/soak/soak.py run \
  --repo /path/to/frozen/questdb \
  --duration 1 --profile quick --rate 1000 \
  --outdir /path/on-a-disk/qwp-unified-m6-quick
```

Its `summary.json` passed all 36 verdicts: I1 completeness, I2 exact DEDUP
replay, I3 value reconciliation across every declared type, I5 complete
Arrow/Buffer/Chunk cycles on both mixed legs, and I7 egress health. All nine
final pool samples had zero in-use and closing handles; both disk SFA slots
drained to 8-byte empty directory entries. As expected for a run shorter than
I4's ten-minute warmup, RSS, FD, and resource slopes were inconclusive.

The long-lived run used the same matrix and rate with the deterministic
60-minute schedule, but the implementation owner explicitly relaxed the
duration gate and stopped it after 33 minutes 40 seconds. The orchestrator's
`finally` drain completed, but interruption preceded final HTTP reconciliation,
so this run is partial evidence and is not reported as a passing 60-minute
`summary.json` run.

At stop, each of the eight ingest legs had sent and journaled 2,020,000
acknowledged rows. Every pooled Buffer, Chunk, and mixed leg reported published
FSN 1009 equal to acknowledged FSN 1009, all ingress/direct/reader pools had
zero in-use and closing handles, and both disk SFA directories had drained to
8 bytes. The egress leg had read 3,288,000 rows. The live portion exercised
three graceful server restarts and three connection resets. It did not reach
the later graceful client restart, client SIGKILL/restart, two additional
server restarts, or throttling episode; those are explicitly outside the
relaxed run's evidence boundary.

Together, the complete short oracle and the shortened long observation cover
mixed-shape correctness, final drain, persisted-slot recovery, pool/FSN
lockstep, and repeated server/reset recovery. They do not constitute a full
60-minute RSS/FD slope or late-episode result.
