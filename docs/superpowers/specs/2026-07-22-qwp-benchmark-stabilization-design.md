# QWP benchmark stabilization design

2026-07-22. Approved scope: document the benchmark suite as it exists today,
move operational tooling out of `doc/`, and make only the smallest changes
needed to prevent invalid benchmark results from looking successful. This is
one follow-up PR on `sm_qwp_bench_followup`, based on `origin/main` after the
merge of PR #153.

## Problem

The merged QWP benchmark suite is useful but difficult to discover and easy to
misuse. Its live contract is spread across Rust and C source comments, Cargo
metadata, one Python aggregator, and an AWS runbook. Several of those comments
still point at historical plans removed by `ce82e88d`.

The implementation also has three narrow data-integrity gaps:

1. `qwp_ingress_polars` records a failed DEDUP row-count check but exits zero.
2. `run_cell.sh` can return the status of its final `tail` command instead of
   the benchmark, and it does not reject missing or malformed result JSON.
3. `bench_parity_aggregate.py` predates the C and row emitters, ignores
   comparison dimensions such as schema and sender count, and applies S1 byte
   assumptions to S2 reports.

The goal is stabilization, not a new benchmark framework. Current timing
regions, report fields, workload generation, AWS topology, and measurement
methodology remain intact.

## Goals

- Provide one maintained guide for the existing local and network benchmarks.
- Replace active references to deleted plans with the live guide or direct
  explanations.
- Give benchmark tooling a coherent home under `tools/qwp_bench/`.
- Make the existing row-count, process-status, JSON, path-role, and comparison
  checks fail clearly when their current contract is violated.
- Exercise the existing C benchmark self-test and the Python/shell harness
  checks in ordinary local and CI unit-test entry points.
- Keep the implementation reviewable as one PR with no paid AWS validation.

## Non-goals

- No new JSON version, generic schema-validation framework, or compatibility
  layer for historical result formats.
- No new metrics, benchmark paths, AWS cells, or performance claims.
- No redesign of cold/warm measurement, `RUN_MODE`, timing regions, wire-byte
  accounting, sar analysis, result format, or artifact retention. The local
  generated-results path follows the moved network tool.
- No automatic deployed-SHA verification, provisioning rollback, or teardown
  correctness changes. Those remain documented operator responsibilities.
- No restoration of historical plans, frozen baselines, campaign notes, or
  their migration-specific regression thresholds.
- No mandatory process for future performance-related PRs.
- No live QuestDB or AWS campaign as an acceptance gate for this PR.

## Repository layout

The maintained documentation stays in the repository's tracked `doc/` tree.
Executable and operational benchmark tooling moves to `tools/qwp_bench/`:

```text
doc/
├── README.md
└── BENCHMARKS.md

tools/
└── qwp_bench/
    ├── aggregate.py
    ├── test_aggregate.py
    └── net/
        ├── README.md
        ├── env.sh
        ├── provision.sh
        ├── teardown.sh
        ├── run_cell.sh
        ├── ssmx.sh
        ├── box_channel.sh
        ├── box_bootstrap_client.sh
        ├── box_bootstrap_server.sh
        └── test_run_cell.sh
```

`doc/bench_parity_aggregate.py` becomes `tools/qwp_bench/aggregate.py`.
The tracked contents of `doc/net_bench/` move together to
`tools/qwp_bench/net/`, preserving their relative sourcing and calls. Local,
untracked `doc/net_bench/results/`, `box-prof.sh`, `.DS_Store` files, and
pre-existing `docs/superpowers/` material are not moved or added by the
implementation PR.

Both the legacy local results path and the new generated results path are
ignored so existing campaign artifacts remain private and do not pollute Git
status:

```text
/doc/net_bench/results/
/tools/qwp_bench/net/results/
```

The C sources remain in `examples/`. Rust Criterion benchmarks remain in
`questdb-rs/benches/`, while live-server benchmark executables and their
support modules remain in `questdb-rs/examples/`. Moving those sources would
add churn without improving this stabilization PR.

## Maintained benchmark guide

`doc/BENCHMARKS.md` is descriptive, not a new versioned specification. It
documents the behavior implemented by the final merged tree:

- the S1 narrow and S2 wide schemas and deterministic data intent;
- Criterion `decoder` and `column_sender` benches;
- Rust `qwp_ingress_polars`, `qwp_egress_polars`, and `qwp_ingress_row` runs;
- C `qwp_bench_selftest`, `qwp_ingress_c`, and `qwp_egress_c` targets;
- current environment knobs and valid values;
- report fields and the path-role table for every current emitter;
- which dimensions must match before two results are compared;
- current bytes-per-row bases and when an explicit override is required;
- local build/run/aggregation commands;
- current limitations: cold/warm labeling, `RUN_MODE` differences, unknown C
  and row wire throughput, positive numeric knob requirements, and optional
  provenance fields;
- a link to the network runbook and to `QWP_SOAK_HARNESS.md` as a separate
  stress/soak facility.

`doc/README.md` links `BENCHMARKS.md` from maintainer documentation. The root
README already links the documentation index, so it gains no additional
benchmark-specific entry.

The moved network README remains an operational runbook. It records the
existing P0-P5 campaign methodology and result-validity rules, but does not
claim to enforce requirements the scripts do not enforce. In particular, it
states that operators must:

- use exact client SHAs and bootstrap again before a publishable campaign;
- run teardown after any provisioning failure;
- inspect the final tag audit rather than relying solely on teardown's exit
  status;
- validate the raw channel before interpreting benchmark numbers;
- keep generated result artifacts outside version control.

## Minimal behavior changes

### Rust row-count failure

`qwp_ingress_polars` keeps its existing table creation, WAL polling, and JSON
`row_count_check`. If the final count differs from `ROWS`, it prints the report
for diagnostics and then exits nonzero. Successful and floor-only runs retain
their current output shape. No timing region changes.

### Network runner failure propagation

The moved `run_cell.sh` captures the benchmark process status before printing
the log tail. It validates the expected result file with `jq -e` and fails if
the file is missing, empty, malformed, or not a JSON object. Log and sar cleanup
still run so a failed cell remains diagnosable. The original benchmark status
takes precedence; otherwise JSON-validation failure is returned.

No other AWS behavior changes. In particular, the runner does not compare the
installed repositories with configured SHAs, and provision/teardown retain
their current behavior.

### Aggregator compatibility checks

The moved aggregator keeps its command-line interface and Markdown/text
rendering. It adds canonical roles for all current paths, including C
`chunk-build`, `flush-chunks`, and `materialize`, Rust row `row-build` and
`row-flush`, and current Rust egress materialization/Arrow paths. Row and
columnar paths remain distinct roles when their timed work is not comparable.

Aggregation no longer merges incompatible inputs. Valid reports are partitioned
into separate comparison tables using this group identity:

```text
direction, schema, rows, senders, run_mode
```

`senders` defaults to `1` for reports that legitimately predate or omit the
ingress-only field. Egress always has one effective sender. Duplicate
client/role data within one full group is an error instead of last-wins.
Unknown paths and failed ingress `row_count_check` values are errors rather
than silent omissions. An ingress report containing an e2e path must contain
`row_count_check.ok=true`; a floor-only report may omit the check.

GiB/s continues to be derived from rows/s and a canonical on-wire bytes-per-row
basis because native egress `mib_per_s` fields use different byte bases across
clients. Defaults apply only to the canonical 10,000,000-row workloads:

| schema | ingress B/row | egress B/row |
|---|---:|---:|
| `s1-narrow` | 45.0 | 37.1283602 |
| `s2-wide` | 100.335059 | 92.4641382 |

Another schema or row count requires an explicit CLI override; the tool does
not silently reuse S1 or 10M-row values.

## Tests and CI

### Aggregator unit tests

`tools/qwp_bench/test_aggregate.py` uses only Python's standard `unittest`
library and synthetic reports. It covers current path mapping, comparison-group
partitioning, duplicate rejection, failed row-count rejection,
S1/S2 byte-basis selection, unknown path handling, rendering, glob input, and
CLI errors.

### Network runner test

`tools/qwp_bench/net/test_run_cell.sh` is a local Bash regression test. It uses
a temporary directory and stub `env.sh`, `ssmx.sh`, `aws`, and `jq` commands;
it never contacts AWS. It proves that a nonzero benchmark status survives log
collection, malformed/missing JSON fails, valid JSON succeeds, and the current
client dispatch/environment arguments remain unchanged.

### C benchmark self-test

`qwp_bench_selftest` is registered through the existing CMake `compile_test`
path when `QUESTDB_TESTS_AND_EXAMPLES=ON`, so standard CI and sanitizer CTest
runs execute it. When tests are disabled, the existing
`QUESTDB_QWP_BENCH=ON --target qwp_bench_selftest` build remains available via
an example-target fallback. The optional benchmark setting continues to build
the live C ingress and egress executables without globally enabling those
CURL-dependent targets in every CI job.

### Existing CI entry points

`ci/run_all_tests.py unit` runs the aggregator test on all platforms and the
Bash runner test on non-Windows platforms. Its native test list includes
`qwp_bench_selftest`. `ci/check_docs.py` treats `doc/BENCHMARKS.md` and the
moved network README as active documentation. Existing pipeline jobs already
invoke these entry points, so no new CI framework or paid environment is
introduced.

## Error handling and result ownership

The PR distinguishes invalid measurements from documented limitations:

- A failed benchmark process, malformed result JSON, failed row-count gate,
  unknown aggregator path, or duplicate comparison cell is a hard failure.
- Valid inputs with different comparison dimensions render as separate tables
  and are never merged into one cell.
- Missing enforced deployed-SHA checks, automatic rollback, trustworthy
  teardown status, separate cold/warm paths, and measured C/row wire bytes are
  documented limitations, not silently presented as implemented guarantees.

Generated benchmark results remain local artifacts owned by the operator.
Neither historical results nor new fixtures copied from local campaigns are
committed; tests construct small synthetic reports instead.

## Acceptance criteria

- The repository contains one indexed live benchmark guide and no active
  benchmark comment points to a removed plan or nonexistent runbook.
- Benchmark tooling is discoverable under `tools/qwp_bench/`; the old tracked
  `doc/net_bench/` and `doc/bench_parity_aggregate.py` locations are gone.
- Current benchmark JSON from Rust Polars, Rust row, and C maps without silent
  path omission. Different workloads render separately, while invalid inputs
  fail clearly.
- A failed Polars count check and a failed remote benchmark both produce
  nonzero status.
- The C self-test, Python aggregator tests, Bash runner tests, documentation
  checks, relevant Rust compilation, CMake build, and shell syntax checks pass
  locally.
- No AWS resources or live QuestDB server are required for verification.
