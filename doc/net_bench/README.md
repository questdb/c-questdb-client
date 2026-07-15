# QWP network bench rig

Scripts for [`../QWP_NETWORK_BENCH_PLAN.md`](../QWP_NETWORK_BENCH_PLAN.md) —
reproducing the QWP DataFrame parity benchmarks over a real AWS network
(2 × `c8gn.2xlarge`, cluster placement group, ~$1.08/hr for the pair).

Laptop prerequisites: `aws` CLI v2 + Session Manager plugin, `jq`, a fresh
`aws sso login` with your SSO profile, and a profile for the target account
(scripts default to `dev`; override with `QNB_AWS_PROFILE`).

## Lifecycle

```bash
cd doc/net_bench

./provision.sh                                    # ~3 min; prints instance ids
./ssmx.sh runfile server box_bootstrap_server.sh  # JDK + QuestDB build (~10-15 min)
./ssmx.sh runfile client box_bootstrap_client.sh  # rust/py/java toolchains + repos (~10 min)

# P0 — validate the channel before trusting any bench number
./ssmx.sh runfile client box_channel.sh verify    # gate: >= 9 Gbps single flow

# cells (plan §6), e.g.:
./run_cell.sh --label p1-s1-ingress --schema s1-narrow --direction ingress --rows 10000000
./run_cell.sh --label p1-s1-egress  --schema s1-narrow --direction egress  --rows 10000000 --skip-populate
./run_cell.sh --label p3-s1-ingress-1gbit --schema s1-narrow --direction ingress \
    --rows 30000000 --rate 1gbit --iterations 15
./run_cell.sh --label p4-s1-ingress-rtt20 --schema s1-narrow --direction ingress \
    --rows 10000000 --rtt-ms 20
./run_cell.sh --label p5-s2-ingress-default-buf --schema s2-wide --direction ingress \
    --rows 10000000 --recv-buf 2m       # expected to fail: capture the error UX

# C client cells (same knobs; binaries prebuilt by the bootstrap):
./run_cell.sh --client c --label p1-s1-ingress-c --schema s1-narrow --direction ingress --rows 10000000
./run_cell.sh --client c --label p1-s1-egress-c  --schema s1-narrow --direction egress  --rows 10000000 --skip-populate

# Java client cells (columnar bench jar, prebuilt by the bootstrap via maven):
./run_cell.sh --client java --label p1-s2-egress-java --schema s2-wide --direction egress --rows 10000000

# Rust row-API client cell (row-major counterpart to the default polars-based
# rust client; ingress only):
./run_cell.sh --client rust-row --label p1-s2-ingress-rustrow --schema s2-wide --direction ingress --rows 10000000

# Multi-sender mode: the --senders N flag (default 1) distributes ingress load across N
# parallel e2e senders in parallel threads. Each sender k of N ingests a disjoint range
# [ROWS*k/N, ROWS*(k+1)/N) into the same table over its own connection. Follows the
# server repo's LineTCPSenderMain precedent with one deliberate deviation: the fixed
# ROWS total is split into disjoint contiguous ranges instead of sending a fixed count
# per thread, so the parity aggregates and the count() == ROWS gate stay byte-identical
# for every N. Checkpoint cadence (ack every 64 batches + final ack) applies per sender.
# Connections are created outside the timed region. Reported as a top-level "senders"
# key in the bench JSON and cell sidecar.
./run_cell.sh --label p3-s2-ingress-java-x4 --schema s2-wide --direction ingress --client java --senders 4
./run_cell.sh --label p3-s2-ingress-rustrow-x4 --schema s2-wide --direction ingress --client rust-row --senders 4

# ENT server axis (image ref from internal docs; instance role handles ECR auth;
# built-in admin is enabled — note the harness conf strings need auth support first):
./ssmx.sh run server "qdb-server use-ent <registry>/questdb:<ver>-enterprise"
./ssmx.sh run server "qdb-server use-oss"   # back to the OSS build

# results land in ./results/<label>/ (bench JSON + sar CPU/NIC + cell.json sidecar)

./teardown.sh                                     # terminate + delete + tag audit
```

## Notes

- **SENDERS (default 1)** — parallel e2e senders for ingress benches; sender k of N
  ingests global rows [ROWS*k/N, ROWS*(k+1)/N) over its own connection into the
  same table. Floor paths stay single-threaded. Reported as a top-level
  "senders" key in the bench JSON and in the cell sidecar.
- **Nothing survives teardown** except (optionally) the S3 results bucket —
  sync down what you need first; the final tag audit must print an empty list.
- Access is SSM-only (no SSH keys, no inbound rules). `./ssmx.sh shell <server|client>`
  gives an interactive session.
- `box_channel.sh` shapes only traffic to the peer IP, so the SSM path stays
  usable even at 1 gbit / high RTT.
- Overnight pauses: `aws ec2 stop-instances` on both ids keeps EBS state
  (~$0.01/hr) and drops compute billing; tmpfs (server data) is lost on stop.
  After `start-instances`, re-run `./ssmx.sh runfile server box_bootstrap_server.sh`
  (~1 min: build is skipped, remounts tmpfs, restarts the server + iperf3) and
  re-populate tables. Client box needs nothing. Note: cluster-placement-group
  capacity is not reserved while stopped — if `start-instances` fails, retry.
- Python cells are blocked on W1 (plan §8): the py harness hardcodes
  `127.0.0.1`. Rust cells cover the matrix until that patch lands.
- Java cells run with a fixed `-Xms4g -Xmx4g` heap (no dynamic sizing, so GC
  behavior is comparable across runs); the JSON contract adds a per-path
  `gc_ms_median` field (GC time delta per pass) on top of the shared stats.
  Java ingress now measures a row-build floor too (`RUN_MODE=full|e2e|floor`,
  parity with rust). The floor is asymmetric across languages: java's floor
  runs through a connected `Sender` (inline global-symbol-dict resolution at
  append, a live server required, the table still DROP/CREATEd, and all
  `SENDERS` still connect), while rust's floor is a standalone offline
  `Buffer` with dict interning deferred to flush — floor-vs-floor
  cross-language comparisons need the parity-matrix corrections for this
  asymmetry. The Java client is pinned to our
  `sm_qwp_bench` branch (based on the upstream delta-symbol-dict PR) until
  that PR merges — see `QNB_JAVA_CLIENT_COMMIT` in `env.sh`. java-row's flush
  is a handoff to an async engine (up to a checkpoint window of batches can
  pipeline ahead of the wire), while rust-row's flush writes the socket
  synchronously — each client's idiomatic discipline; expect this to matter
  on shaped/RTT cells. Egress materialize checksums must be compared as
  parsed float64 values, not strings (clients format the number
  differently).
- Row-bench data generation: both row benches (java-row, rust-row) pull
  symbol labels from pools precomputed outside the timed region; the timed
  loop does O(1) lookups and scalar arithmetic only, matching the columnar
  benches' prebuilt-data convention. Row-flush numbers from earlier runs
  (p1-p5 results) include per-row `String.format`/`format!` label cost
  (~45-50% of a pass) and are NOT comparable with numbers produced after
  this change.
