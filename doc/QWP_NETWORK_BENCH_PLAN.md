# QWP Real-Network Benchmark Plan — reproducing the DataFrame parity suite over AWS

**Status:** draft, pending approval. Scripts live in [`doc/net_bench/`](./net_bench/).
**Relationship:** direct continuation of the implemented historical
[`QWP_DATAFRAME_BENCH_PLAN.md`](./historical/QWP_DATAFRAME_BENCH_PLAN.md)
(same S1/S2 schemas, JSON contract, DEDUP fixture, aggregator — "the spine").
That plan deliberately locks parity runs to *single-box, single-stream, loopback*
(§3.7). This plan adds the axis it deferred implicitly: **the network**.
**Trigger (per the spine's own gating rule — "defer every axis until a number
implicates it"):** the standing concern that clients may not sustain even
**1 Gbps** over a real link, which loopback can neither confirm nor refute.

---

## 1. Question under test

Loopback has RTT ≈ 0 and an effectively infinite pipe: it hides every
windowing, ack-gating, and flow-control-credit stall. The Go finding quoted in
the spine ("pipeline-coupling-bound, not param-bound") was also a loopback
finding. The real-network questions, in priority order:

1. **Utilization** — on a verified channel of known capacity, what fraction can
   each client sustain? (`util = wire_bytes × 8 / wall_s / channel_bps`)
2. **RTT sensitivity** — how does utilization degrade as RTT grows from ~0.1 ms
   (same-AZ) to ~20 ms (WAN-ish)? The ingress path acks every 64th batch and on
   the final commit (`drive_from_checkpoint`, `src/ingress/polars.rs`), so this
   directly stresses the pipelining design. `MAX_BATCH_ROWS` is the ready-made
   experiment knob.
3. **Default-config behavior** — the local runs used a non-default server
   receive buffer. What does a customer on stock defaults actually experience?
4. **Cold vs warm over distance** — the cold first-flush (full symbol dict +
   immediate commit + connection setup, spine §3.5) pays RTTs that loopback
   never charged. Report it separately, as the spine already mandates.

### Non-goals (v1)

- Matching loopback absolute numbers. CPU floors *will* drop (8 Graviton vCPUs
  vs 14 Apple cores); the network cells are about utilization, not parity with
  Apple Silicon.
- Protocol shootout (QWP vs ILP/PGWire) — unchanged from the spine.
- Multi-connection concurrency, TLS, zstd, `Durable` acks — deferred (§9),
  each gated on a v1 number implicating it.

---

## 2. Known ceilings the results must be read against

EC2 hard limits (measured facts, not folklore):

| Limit | Value | Consequence |
|---|---|---|
| Single TCP flow, default | **5 Gbps** | S1 ingress e2e (5.3 Gbps loopback) would already be capped |
| Single TCP flow, cluster placement group | **10 Gbps** | The bench uses `pool_size=1` ⇒ this is the absolute per-cell ceiling |
| `c8gn.2xlarge` instance baseline | 25 Gbps sustained | Instance never throttles; only the flow cap binds |
| gp3 EBS default | 125 MB/s | Would poison ingress ⇒ server data dir on **tmpfs** |

Local (loopback) rates mapped onto the wire, from the PR #153 refresh of
2026-07-10 (canonical bytes/row — S1: 45.0 in / 37.13 out; S2: 99.67 / 92.46).
**Caveat:** these were measured against the retired server pin; treat as
directional until the loopback re-run at `5b2efe5e` lands — that re-run is
the **precondition for the P1 parity cells**:

| Path | Loopback | On-wire | vs 10 Gbps flow cap |
|---|---|---|---|
| S1 ingress e2e (rust) | 14.76 M rows/s | ≈ 5.3 Gbps | fits, ~53 % of cap |
| S1 egress decode floor | 66.9 M rows/s | ≈ 19.9 Gbps | **network-bound** (expect ~33 M rows/s ceiling) |
| S2 ingress e2e (rust) | 5.80 M rows/s | ≈ 4.6 Gbps | fits — pipeline-bound, not network-bound |
| S2 egress decode floor | 16.6 M rows/s | ≈ 12.3 Gbps | slightly network-bound |

So: **S1 egress is the channel-saturation probe** (its floor is 2× the cap);
**S2 ingress tests whether RTT degrades an already pipeline-bound path**.

---

## 3. Infrastructure

2 × **`c8gn.2xlarge`** (Graviton4, 8 vCPU, 16 GiB, 25 Gbps baseline,
~$0.54/hr each in `eu-west-1`; pair ≈ **$1.08/hr**), same AZ, **cluster
placement group**, MTU 9001. arm64 keeps SIMD-architecture parity with the
Apple-Silicon loopback runs.

- One box = QuestDB server. Pin: **OSS master `5b2efe5e`** — the core commit
  of the **ENT 3.3.4 release**, so the OSS source build and the ENT docker
  image are the *same lineage* and directly comparable. (The earlier pin,
  `f7af05bc`, was a working-branch build from `sm_dag_startup` — retired as a
  bad reference; local loopback baselines are being re-measured against
  `5b2efe5e`.) Data dir on **tmpfs** (10 GiB cap — sized for table + 1–2
  unpurged WAL iterations; see §5 ROWS ceilings). Archive the first server
  build to the results bucket for reproducibility.
- One box = client (Rust + Python harnesses at the exact PR branch heads:
  c-questdb-client `214830a9ac749800b41501d2722358a634a003ab`,
  py-questdb-client `7334503e84e2d149f9d6550dd023ef484d2edc1e`).
- Access via **SSM only** — no SSH keys, no inbound security-group rules except
  intra-group. Every resource carries `Project=qwp-net-bench`; teardown ends
  with a tag audit that must return empty. Full inventory: 1 security group,
  1 placement group, 1 IAM role+instance profile, 1 S3 results bucket,
  2 instances (root EBS delete-on-termination). Default VPC is reused — zero
  network resources created.
- Why not the internal deployment tooling: it targets managed database
  deployments (no bare client-box concept) and creates VPC/DNS/control-plane
  state — the opposite of a leave-no-trace test rig.

## 4. Channel control — shape a verified fat pipe, never size down

Small instances advertise low rates but those are *burst baselines* enforced by
credit token-buckets: the channel would be time-varying and packet-dropping —
indistinguishable from a client failure. Instead:

1. **Validate** the raw channel first: `ping` RTT, `iperf3` single-flow
   (gate: **≥ 9 Gbps**) and 4-flow, MTU 9001 — no client number means anything
   until iperf3 proves the pipe.
2. **Shape deliberately** with `tc` (htb class filtered to the peer IP, so the
   SSM management path stays unshaped) + `netem` for RTT. Bandwidth is set
   per-side (full-duplex X); delay is half per side (RTT = sum).
3. Record the channel state (`rate`, `rtt`, `tc` output) in the per-cell
   metadata sidecar (§7).

## 5. Run-length & sizing discipline

Sub-second transfers measure TCP slow-start, not utilization. Rules:

- Target **≥ 10 s per timed iteration** where RAM permits; otherwise max
  feasible ROWS and `ITERATIONS ≥ 15` (defensible because the pooled
  connection stays warm across iterations — slow-start and the symbol-dict
  cold path are paid in the 2 warmups).
- RAM ceilings on 16 GiB boxes: client DataFrame ≤ ~6 GB ⇒ **S1 ≤ 60 M rows,
  S2 ≤ 30 M**; server tmpfs ≤ ~8 GB steady (table + WAL headroom).
- Long egress windows use the **streaming paths** (`iter_polars` /
  `iter_pandas`) — RAM O(batch); `fetch_all` cells stay at materialization-safe
  ROWS.
- Keep dedicated **10 M-row parity cells** (5 iters / 2 warmups, recv=16M) —
  directly comparable, cell for cell, against the loopback numbers already in
  the PR #153 thread.
- Wrap every cell with `sar` (CPU + NIC) on **both** boxes so each result
  carries its bottleneck attribution (client CPU vs server CPU vs wire).
- Log warmup wall-times instead of discarding them — that's the cold-path
  (first-flush) measurement over distance, no harness change needed for v1.

## 6. Cell matrix (narrow-v1)

Phases run in order; later phases only where earlier numbers justify.
All cells: Rust first; Python joins once W1 (§8) lands.

| Phase | Cells | Purpose |
|---|---|---|
| **P0 validate** | iperf3 1-flow (≥9 Gbps gate) + 4-flow, ping, MTU | prove the channel |
| **P1 parity** | {S1, S2} × {ingress, egress} @ 10 M rows, native channel, recv=16M | loopback-vs-network delta table |
| **P2 utilization** | S1 ingress 60 M; S1 egress 60 M (`iter`); S2 ingress 30 M | sustained-window utilization |
| **P3 bandwidth sweep** | rates {1, 2.5, 5} Gbps × {S1 ingress, S1 egress-iter, S2 ingress}; ROWS per rate so window ≥ 10 s (1 Gbps → 30 M is ample) | "can we use the channel" at customer-like rates |
| **P4 RTT sweep** | RTT {1, 5, 20} ms @ unshaped rate × {S1 ingress, S1 egress-iter}; then `MAX_BATCH_ROWS` {1k, 10k, 100k} @ 20 ms S1 ingress | ack-gating / pipelining sensitivity |
| **P5 server-config** | recv-buf {**2 MiB default**, 16M} × {S1 ingress, S2 ingress}; on S2×default capture the failure UX (error surfaced, pool/SFA recovery, partial-data state — DEDUP makes retry observable); optional bisect {4M, 8M} | what stock-default customers hit |

Server receive buffer: canonical key **`http.recv.buffer.size`**
(`QDB_HTTP_RECV_BUFFER_SIZE`), default **2 MiB**
(`PropServerConfiguration.java:1375`). The spine's "1m default" via
`http.receive.buffer.size` is stale — that key is deprecated (still honored,
canonical key wins when both set).

## 7. Metric contract extension

The §3.2 JSON contract is unchanged; each cell directory adds a sidecar
`cell.json` written by the runner:

```jsonc
{
  "cell": "p3-s1-ingress-2.5gbit",
  "channel": { "rate_gbps": 2.5, "rtt_ms": 0.12, "shaped": true,
               "placement_group": true, "mtu": 9001,
               "iperf3_gbps_1flow": 9.6 },
  "server": { "instance_type": "c8gn.2xlarge", "az": "eu-west-1a",
              "questdb_commit": "5b2efe5e…", "recv_buffer": "16m",
              "data_dir": "tmpfs" },
  "client_box": { "instance_type": "c8gn.2xlarge" },
  "commits": { "c_questdb_client": "214830a9…", "py_questdb_client": "7334503…" },
  "monitor": ["sar-client.txt", "sar-server.txt"],
  "warmup_wall_s": [0.0, 0.0]
}
```

`rows/s` remains the cross-client unit; add **utilization** (§1) per cell.

## 8. Work items

- **W1 — py remote-server support.** `benchmark_pandas_columnar.py` hardcodes
  `127.0.0.1` (line ~575) and `run_pandas_columnar_layer3.py` builds its own
  local server. Add `QDB_HOST`/`QDB_PORT` env overrides mirroring the Rust
  examples (py-questdb-client branch `jh_experiment_new_ilp`). Until then the
  matrix runs Rust-only.
- **W2 — scripts** (done, `doc/net_bench/`): provision / bootstrap ×2 /
  channel / run_cell / teardown + tag audit.
- **W3 — spine doc fixes** (done in this change): §8 stale default+key;
  network axis pointer in §9.
- **W4 — results home:** aggregate with `bench_parity_aggregate.py` (it
  already warns on mixed `(os, arch)` — network cells are same-arch so it
  holds), post the delta table to PR #153 as the next comment in the series.
- **W5 — C client cells**: `qwp_ingress_c` / `qwp_egress_c` (client `c-columnar`,
  examples/) mirror the Rust cells via `run_cell.sh --client c`. Floor paths
  differ by construction (chunk staging vs encode; decode-only matches);
  `rows_per_s_median` is the cross-client metric (C reports `wire_bytes: 0`).

## 9. Deferred (each gated on a v1 number)

Concurrency (N pooled senders — the only route past the 10 Gbps flow cap),
ack-level `Ok` vs `Durable` (RTT-gated commits; Enterprise), TLS (`wss`),
zstd (trades CPU for wire — interesting exactly at 1–2.5 Gbps), real cross-AZ/
cross-region (netem approximates first), x86 pass (`c6in.2xlarge`), Java/Go
anchors over network.

## 10. Open decisions

1. **Server build source** — build the pin (`5b2efe5e`, OSS master / ENT
   3.3.4 core) from source on the box (~10 min, maven) vs upload a prebuilt
   tarball to the results bucket. Scripts support both (`QDB_TARBALL_S3`
   overrides source build). *AMI survey (2026-07-10): no shortcut exists.
   The official public release
   AMIs (`questdb-9.4.x-al2023-x86_64-ebs` + marketplace copies) do ship the
   QWP server as of 9.4.3, but are x86-only and behind the master pin,
   missing QWP/WS fixes on the measured path (e.g. `e38301f557`, stale FSN
   after empty flush). Wrong for parity; earmarked instead for a deferred
   "released-server over network" cell on the x86 pass, which also matches
   typical customer architecture. If network benching recurs, an internal
   AMI bake of QWP snapshots is the long-term option.*
2. **OSS vs ENT** — resolved by the `5b2efe5e` re-pin: OSS source build and
   ENT 3.3.4 share the same core, so ENT is now a directly-comparable second
   server, not a confounded one. ENT runs on the rig as a **multi-arch
   (amd64 + arm64) container image**, natively on Graviton; the bench
   account can pull the image (ref from internal docs).
   The rig supports it out of the box: `qdb-server use-ent <image-ref>`
   (docker + ECR auth via the instance role, built-in admin enabled). The one
   real ENT prerequisite is **auth**: ENT ships with ACL on — enable the
   built-in admin (`acl.admin.user.enabled` / `acl.admin.user` /
   `acl.admin.password`) and pass credentials in the bench conf strings
   (small harness knob; they currently carry none). ENT unlocks the
   `Durable` ack cell (the most RTT-sensitive path) and matches what
   managed-deployment customers actually run.
3. **Python version on the client box** — the pinned py-client branch declares
   `requires-python >= 3.10`, so 3.9 parity is off the table. Default: 3.10
   (the minimum the branch allows) via `uv`; bump to match whatever the local
   re-runs use.
4. **Placement-group-off cell** — a 5 Gbps-flow-cap "default networking" data
   point; cheap to add (one relaunch) if wanted.
5. **Exact ROWS per P3 rate** — proposed 30 M @ 1–2.5 Gbps, 60 M (S1) @ 5 Gbps;
   confirm against tmpfs headroom on first run.

## 11. Done when

- P0 gate passed and recorded; P1 delta table posted (loopback vs network, per
  cell, same ROWS/iterations).
- P2/P3 utilization table: per client × direction × rate, `rows/s` +
  utilization %, each cell attributed (client-CPU / server-CPU / wire) from sar.
- P4 utilization-vs-RTT curve for S1 ingress + egress; `MAX_BATCH_ROWS`
  sensitivity stated.
- P5: default-config verdict — S1 pass/fail, S2 failure UX documented, minimal
  working buffer known.
- Teardown tag-audit empty; total spend reported.
