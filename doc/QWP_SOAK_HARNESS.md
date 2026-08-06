# QWP ingress and egress soak harness

The soak harness exercises connection-pool lifecycle, store-and-forward
recovery, QWP ingress, and QWP egress against real QuestDB processes. Its
unified-ingress leg is load-bearing: one borrowed sender cycles through Arrow,
row-built `Buffer`, and columnar `Chunk` batches while sharing one FSN stream,
symbol dictionary, retained payload allocation, and managed `-ingest-N` slot.

The orchestrator, independent oracle, fault proxy, and Rust workloads live in
`system_test/soak/`.

## Build and self-test

Build the workload with dataframe support so every default leg is available:

```sh
cargo build --release \
  --manifest-path system_test/soak/workload_rs/Cargo.toml \
  --features dataframe
```

The pure unit tests do not need a server:

```sh
cargo test --manifest-path system_test/soak/workload_rs/Cargo.toml
cargo test --manifest-path system_test/soak/workload_rs/Cargo.toml \
  --features dataframe
python3 system_test/soak/gen.py selftest
python3 system_test/soak/fault_proxy.py selftest
python3 system_test/soak/oracle.py selftest
python3 system_test/soak/soak.py selftest
```

## Run

Point `--repo` at a QuestDB checkout containing a built server jar. The
recommended full-duration run is 60 minutes:

```sh
python3 system_test/soak/soak.py run \
  --repo /path/to/questdb \
  --duration 60 \
  --profile full \
  --rate 20000 \
  --outdir /path/on-a-disk/qwp-soak
```

`--rate` is the target rows per second for each ingest leg; zero means
unlimited. It controls load, not coverage. The mixed leg always uses 2,000-row
batches and derives its payload shape from the durable batch index. Put
`--outdir` on a disk with ample space: the two QuestDB roots, WALs, journals,
store-and-forward slots, logs, and samples are intentionally retained for
diagnosis.

For a short wiring check, use `--duration 1 --profile quick`. Resource trend
checks are expected to be inconclusive in a one-minute run because I4 excludes
the first ten minutes as warmup; a quick pass is not a substitute for the
full-duration resource-trend run. The unified-sender implementation accepted a
shorter long-lived observation by explicit owner decision.

`--server HOST:PORT` targets an existing server instead of provisioning two
processes. In that mode server-restart episodes are no-ops and the control and
faulted legs share the server, so it is useful for diagnosis but not equivalent
to the full gate. `--no-proxy` similarly disables connection-reset, stall, and
throttle injection.

The schedule is deterministic for a seed. Inspect it without running servers:

```sh
python3 system_test/soak/soak.py schedule --seed 1 --duration 60
```

## Workload matrix

The default run starts these independently journaled paths:

| Leg | Payload and delivery mode |
|---|---|
| `rust-mixed-saf-disk` | One borrowed sender, Arrow → Buffer → Chunk, disk store-and-forward |
| `rust-mixed-saf-mem` | One borrowed sender, Arrow → Buffer → Chunk, memory store-and-forward |
| `rust-buffer-saf-default` | Row-built Buffer, default memory store-and-forward |
| `rust-buffer-saf-disk` | Row-built Buffer, disk store-and-forward |
| `rust-buffer-saf-mem` | Row-built Buffer, explicitly bounded memory store-and-forward |
| `rust-chunk-saf-default` | Chunk, default memory store-and-forward |
| `rust-dataframe-direct` | DataFrame through Arrow, direct delivery |
| `control-buffer-saf-default` | Never-faulted Buffer control, default memory store-and-forward |
| `rust-egress-whole` | Whole-result reader through the fault proxy |

Buffer, Chunk, and Arrow name payload orientation only. The three SFA variants
all borrow the same sender type and use the same `-ingest-N` slot namespace;
only the configured delivery storage differs. The DataFrame helper retains its
separate direct whole-source delivery mode and owns commit/replay internally.

Fault episodes cover connection reset, stalled and throttled traffic, client
kill/restart, and graceful server restart. A quiet tail lets queues drain
before final reconciliation. Disk-full injection is not advertised by this
harness: it requires an externally provisioned quota or loopback filesystem,
and the harness never treats a skipped no-op as a fault episode.

## Oracle

Every successful ingest batch is followed by an ACK and then an fsync of its
last sequence number to that leg's journal. The journal is therefore an
independent lower bound on what must be queryable after recovery. Final checks
use QuestDB's HTTP `/exec` endpoint, not the client path under test:

- **I1 completeness:** every journaled sequence exists without gaps.
- **I2 duplication:** replay stays within budget; the default DEDUP tables and
  control leg must be exact.
- **I3 value correctness:** a deterministic sample is regenerated from the
  seed and compared across every datatype written by that leg.
- **I4 resource boundedness:** steady-state RSS, file descriptors, pool use,
  FSN backlog, and store-and-forward disk/memory state stay bounded.
- **I5 mixed-shape coverage:** the mixed leg's fsync'd watermark proves at
  least one complete Arrow, Buffer, Chunk cycle reached ACK. Because shape is
  `batch_index % 3` and the journal advances only after a whole batch ACK, the
  proof remains valid across process restart.
- **I7 workload health:** the egress leg exits successfully after its own
  contiguity checks.

The run passes only when `summary.json` has `"passed": true` and zero failed
verdicts. Review individual I4 details as well as the aggregate: the long gate
must contain enough post-warmup samples to produce actual slopes rather than
`inconclusive` verdicts.

## Artifacts

The output directory contains:

- `summary.json`: aggregate verdicts, per-invariant details, and the exact
  seed/duration/profile/rate reproduction command;
- `episodes.json`: the generated fault schedule;
- `stats.jsonl`: merged process and client watermark samples;
- per-leg `.journal` and `.stats.jsonl` files;
- disk-backed `.sfdir` managed slots;
- `servers/faulted` and `servers/control` QuestDB roots and logs.

Keep a failing output directory intact until the journal, client stats, fault
episode, and server log have been correlated. A test-process exit alone does
not distinguish a client error from a server recovery delay; the retained
evidence does.
