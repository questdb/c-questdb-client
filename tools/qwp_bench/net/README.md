# QWP network bench rig

Scripts for benchmarking the QWP clients over a real AWS network instead of
loopback: two `c8gn.2xlarge` boxes in a cluster placement group (~$1.08/hr for
the pair), driven entirely from your laptop over AWS Systems Manager (no SSH
or public inbound access). One box runs QuestDB, the other runs the client
bench; a `tc` channel between them shapes bandwidth and RTT.

For benchmark schemas, report fields, comparison roles, and local commands,
see [the maintained QWP benchmark guide](../../../doc/BENCHMARKS.md).

## Laptop prerequisites

- `aws` CLI v2 and the Session Manager plugin (for `ssmx.sh shell`)
- `jq`
- `git` (for resolving client branch or tag refs)
- a valid SSO session: `aws sso login` with your SSO profile
- a profile for the target account — scripts default to `dev`; override with
  `QNB_AWS_PROFILE`

## Configuration

Shared laptop-side defaults live in [`env.sh`](env.sh) and are overridable
from the environment. Campaign controls are flags to `run_cell.sh`.

| Variable | Default | Purpose |
| --- | --- | --- |
| `QNB_AWS_PROFILE` | `dev` | AWS profile |
| `QNB_AWS_REGION` | `eu-west-1` | region |
| `QNB_INSTANCE_TYPE` | `c8gn.2xlarge` | box type (arm64) |
| `QNB_ROOT_GB` | `48` | instance root volume size in GiB |
| `QNB_QUESTDB_COMMIT` | pinned SHA | server build under test |
| `QNB_C_CLIENT_COMMIT` | `sm_qwp_bench` | c-questdb-client ref (SHA, branch, or tag) |
| `QNB_JAVA_CLIENT_COMMIT` | `sm_qwp_bench` | java client ref |
| `QNB_PY_CLIENT_COMMIT` | pinned SHA | py client ref |

Client refs accept an exact 40-hex SHA or a branch/tag name. Branch names
resolve to the remote tip **at use time** — so re-run the client bootstrap
before a campaign if a branch default may have moved, otherwise the boxes keep
running binaries from the tip seen at their last bootstrap. Export
`QNB_*_COMMIT=<sha>` to pin a campaign.

## Lifecycle

```sh
cd tools/qwp_bench/net

# 1. Provision: SG (intra-group only), placement group, IAM/SSM role,
#    S3 results bucket, 2 tagged instances. Reuses the default VPC.
./provision.sh

# 2. Bootstrap each box (installs toolchains, builds server + clients).
./ssmx.sh runfile server box_bootstrap_server.sh
./ssmx.sh runfile client box_bootstrap_client.sh

# 3. Run a cell: shapes the channel, ensures the server is running at the
#    requested receive buffer (restarting it when required), wraps the bench
#    with sar on both boxes, and syncs results to ./results/<label>/.
./run_cell.sh --label p1-s1-ingress \
    --schema s1-narrow --direction ingress --rows 10000000 \
    --client rust

# 4. Attempt cleanup, then inspect the final tag/IAM audit.
./teardown.sh
```

## The scripts

| Script | Runs on | What it does |
| --- | --- | --- |
| `provision.sh` | laptop | create the rig; aborts if tagged instances already exist |
| `teardown.sh` | laptop | attempt cleanup, then print a final tag/IAM audit |
| `ssmx.sh` | laptop | SSM wrapper: `run` / `runfile` / `pull` / `shell` a box |
| `box_bootstrap_server.sh` | server box | install toolchain, build QuestDB |
| `box_bootstrap_client.sh` | client box | install Rust/Python/JDK, build the clients |
| `run_cell.sh` | laptop | drive one benchmark cell end to end |
| `box_channel.sh` | either box | `tc` bandwidth/RTT shaping to the peer only |
| `env.sh` | laptop | shared config, sourced by the laptop-side scripts |

`box_channel.sh` shapes **only** peer-directed traffic, so the SSM management
path stays unshaped. It is symmetric: run it with the same arguments on both
boxes and pass half the target RTT as `--delay-ms` to each. `run_cell.sh`
applies the channel for you; call it directly only for manual checks
(`box_channel.sh verify` on the client box runs ping + iperf3 to the peer).

See the usage comments at the top of `run_cell.sh`, `ssmx.sh`, and
`box_channel.sh` for their full interfaces.

## Campaign method

The existing benchmark campaign uses these phases:

| Phase | Existing method |
|---|---|
| P0 | Clear shaping, then validate raw ping, iperf3 throughput, and MTU before interpreting benchmark values |
| P1 | S1 and S2 ingress/egress parity at 10M rows, native channel, 16M receive buffer, five iterations and two warmups |
| P2 | Sustained-run utilization with sar attribution on client and server |
| P3 | Bandwidth sensitivity at 1, 2.5, and 5 Gbit/s |
| P4 | RTT sensitivity at 1, 5, and 20 ms, including batch-size sensitivity |
| P5 | Receive-buffer sensitivity at 2 MiB versus 16 MiB |

Target at least 10 seconds per measured iteration. When a row ceiling makes
that impractical, use at least 15 iterations. The scripts expose the knobs but
do not enforce this methodology.

## Result validity and operator responsibilities

- Use exact client SHAs and rerun the relevant bootstrap before a publishable
  campaign; the scripts resolve refs but do not verify installed binaries
  against those SHAs.
- If provisioning fails at any point, invoke `teardown.sh`; provisioning has
  no automatic rollback.
- Inspect teardown's final tag and IAM audit; its exit status alone is not
  proof that every resource was removed.
- Validate the raw P0 channel before interpreting benchmark output.
- Inspect each benchmark JSON against the report contract and its row-count
  requirements; `run_cell.sh` only verifies that the result is a nonempty JSON
  object.
- Use a unique label for each cell, because the local, remote, and S3 result
  directories are not cleared automatically.
- Keep `results/` outside version control; operators own raw artifacts.
