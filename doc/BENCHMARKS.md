# QWP benchmarks

## Scope and source layout

The QWP benchmark suite measures in-process encoding/decoding floors and
live-server ingress and egress paths across the supported client shapes. C
benchmarks stay under `examples/`, Criterion benchmarks under
`questdb-rs/benches/`, live Rust programs and their support code under
`questdb-rs/examples/`, and cross-language comparison and network tools under
`tools/qwp_bench/`.

## Deterministic schemas

| Schema | Columns | Defaults |
|---|---|---|
| `s1-narrow` | designated `ts` TIMESTAMP, `id` LONG, `price` DOUBLE, `sym` SYMBOL, `note` VARCHAR | SYMBOL card 8; note length 16 |
| `s2-wide` | S1 plus `d1..d5` DOUBLE and `s1..s5` SYMBOL | each wide SYMBOL card 100,000 |

The generated data is deterministic: `ts = 1704067200000000000 + i*1000` ns
(one microsecond apart), `id=i`, `price=i*0.25`, low-cardinality labels cycle,
note templates cycle through at most 1024 values, `d{k}=i*(0.5+k)`, and wide
symbols use `s{column-1}_{value:06}`. Both live schemas use WAL DEDUP on `ts`.

## Benchmark inventory

- Criterion `decoder` and `column_sender` are in-process CPU/memory floors and
  do not require a server.
- Rust `qwp_ingress_polars`, `qwp_egress_polars`, and `qwp_ingress_row` are
  live-server report emitters, except for the ingress floor-only modes.
- C `qwp_bench_selftest` does not require a server; `qwp_ingress_c` and
  `qwp_egress_c` are live-server report emitters.
- `tools/qwp_bench/aggregate.py` renders comparisons, and
  `tools/qwp_bench/net/README.md` is the AWS runbook.

## Build and run locally

Run the in-process Criterion benchmarks:

```bash
cargo bench --manifest-path questdb-rs/Cargo.toml \
  --features sync-reader-qwp-ws --bench decoder
cargo bench --manifest-path questdb-rs/Cargo.toml \
  --features sync-sender-qwp-ws --bench column_sender
```

Run the live Rust report emitters against a QuestDB server:

```bash
cargo run --release --manifest-path questdb-rs/Cargo.toml \
  --features polars,sync-sender-qwp-ws,sync-sender-http \
  --example qwp_ingress_polars
cargo run --release --manifest-path questdb-rs/Cargo.toml \
  --features polars,sync-reader-qwp-ws,sync-sender-http \
  --example qwp_egress_polars
cargo run --release --manifest-path questdb-rs/Cargo.toml \
  --features sync-sender-qwp-ws,sync-sender-http \
  --example qwp_ingress_row
```

Build the C benchmarks and run the offline self-test:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DQUESTDB_QWP_BENCH=ON
cmake --build build --target qwp_bench_selftest qwp_ingress_c qwp_egress_c
./build/qwp_bench_selftest
```

Render two JSON reports as Markdown:

```bash
python3 tools/qwp_bench/aggregate.py result-a.json result-b.json --format md
```

## Environment variables

| Variable | Default | Applies to / meaning |
|---|---:|---|
| `SCHEMA` | `s1-narrow` | `s1-narrow` or `s2-wide` |
| `ROWS` | `10000000` | positive headline rows |
| `ITERATIONS` | `5` | positive measured passes |
| `WARMUPS` | `2` | zero or more warm-up passes |
| `MAX_BATCH_ROWS` | `10000` | positive ingress batch ceiling |
| `RUN_MODE` | `full` | report/group label; row Rust also gates `full`, `floor`, or `e2e` |
| `SENDERS` | `1` | positive ingress sender/connection count |
| `CHECKPOINT_BATCHES` | `64` | Rust row ack-checkpoint cadence |
| `QUESTDB_COLUMN_BENCH_SYM_CARD` | live emitters: `8`; Criterion column sender: `1000` | positive SYMBOL cardinality |
| `QUESTDB_COLUMN_BENCH_VARCHAR_LEN` | `16` | positive VARCHAR length |
| `HI_SYM_CARD` | `100000` | positive S2 wide SYMBOL cardinality |
| `QDB_HOST` / `QDB_PORT` | `127.0.0.1` / `9000` | QuestDB endpoint |
| `SKIP_E2E` | unset | Polars/C ingress floor-only switch |
| `SKIP_POPULATE` | unset | egress reuse of an existing table |
| `QDB_CONF_EXTRA` | empty | Rust-row connect-string suffix |
| `QUESTDB_BENCH_ROWS` | `100000` | Criterion decoder rows per batch |
| `QUESTDB_COLUMN_BENCH_ROWS` | `100000` | Criterion column-sender rows |

Numeric parsing is not uniformly strict across emitters; callers must supply
the valid ranges above.

## JSON reports and path roles

Top-level report fields are `schema`, `rows`, `columns`, `direction`, `client`,
`run_mode`, `warmups`, `wire_bytes`, ingress `senders`, `machine`, `commits`,
and `paths`. The `headline`, `row_count_check`, `real_conf`, and `http_base`
fields are optional.

Each path summary contains `iterations`, the wall-time summary (`median_s`,
`mean_s`, `min_s`, `max_s`, `p95_s`, `stdev_s`, and `cov`),
`rows_per_s_median`, `cells_per_s_median`, `mib_per_s`, `process_cpu`, `phase`,
`warm`, and `wire_bytes`.

Path names map to comparison roles as follows. This table is the documentation
counterpart of `aggregate.py`'s `ROLE_OF_PATH` mapping.

| Direction | Canonical role | Current/retained path names |
|---|---|---|
| ingress | columnar CPU floor | `columnar-populate`, `encode-floor` |
| ingress | C chunk-build floor | `chunk-build` |
| ingress | row-build floor | `row-build` |
| ingress | columnar e2e | `real-client`, `flush-polars-dataframe`, `flush-chunks` |
| ingress | row e2e | `row-flush` |
| egress | decode floor | `decode-only` |
| egress | materialize | `materialize` |
| egress | -> Arrow | `to-arrow` |
| egress | -> polars | `to-polars`, `fetch-all-polars` |
| egress | -> polars (lazy/iter) | `iter-polars` |
| egress | -> pandas (numpy) | `to-pandas` |
| egress | -> pandas (Arrow) | `to-pandas-arrow` |
| egress | -> pandas (nullable) | `to-pandas-nullable` |
| egress | -> pandas (lazy/iter) | `iter-pandas` |
| egress | Arrow C-stream | `arrow-c-stream` |

## Comparing reports

The comparison identity has exactly five fields: `direction`, `schema`,
`rows`, `senders`, and `run_mode`. A missing ingress `senders` field defaults
to 1; egress always uses 1, regardless of a supplied value. Different valid
keys render as separate tables.

The aggregator rejects unknown path names, path names belonging to the other
direction, and duplicate cells for the same canonical role and client within
one comparison group. An ingress report with an e2e role requires
`row_count_check`: `expected` must equal `rows`, `actual` must equal `expected`,
`ok` must be true, and `inflated` must be false. An ingress floor-only report
may omit the check; if it includes one, it must meet the same requirements.
Egress reports do not require a row-count check.

The canonical on-wire byte estimates are:

| Schema at 10,000,000 rows | Ingress B/row | Egress B/row |
|---|---:|---:|
| `s1-narrow` | 45.0 | 37.1283602 |
| `s2-wide` | 100.335059 | 92.4641382 |

Other schemas or row counts require `--ingress-bpr` or `--egress-bpr` as
appropriate. Native egress `mib_per_s` values are not cross-client comparable;
use the normalized comparison output instead.

## Known limitations

- Warm/cold is a label rather than a separately retained first-flush sample.
- `RUN_MODE` behavior differs: Rust row gates passes, while Polars/C mostly
  report the label and use `SKIP_*`.
- C and row ingress report unknown/zero wire bytes, so rows/s is the primary
  metric.
- Provenance fields may be null or unknown.
- Numeric parsing is not uniformly strict.
- The scripts do not automatically verify deployed SHAs, roll back partial
  provisioning, or make teardown exit status a complete resource audit.

## Network and soak testing

Use [the network runbook](../tools/qwp_bench/net/README.md) for the existing AWS
P0-P5 campaign method and operator checks. [The QWP soak
harness](QWP_SOAK_HARNESS.md) is a separate stress/soak facility rather than a
parity benchmark.
