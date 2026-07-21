# QWP network bench rig

Scripts for benchmarking the QWP clients over a real AWS network instead of
loopback: two `c8gn.2xlarge` boxes in a cluster placement group (~$1.08/hr for
the pair), driven entirely from your laptop over AWS Systems Manager (no SSH,
no inbound ports). One box runs QuestDB, the other runs the client bench; a
`tc` channel between them shapes bandwidth and RTT.

## Laptop prerequisites

- `aws` CLI v2 and the Session Manager plugin (for `ssmx.sh shell`)
- `jq`
- a valid SSO session: `aws sso login` with your SSO profile
- a profile for the target account — scripts default to `dev`; override with
  `QNB_AWS_PROFILE`

## Configuration

All knobs live in [`env.sh`](env.sh), overridable from the environment:

| Variable | Default | Purpose |
| --- | --- | --- |
| `QNB_AWS_PROFILE` | `dev` | AWS profile |
| `QNB_AWS_REGION` | `eu-west-1` | region |
| `QNB_INSTANCE_TYPE` | `c8gn.2xlarge` | box type (arm64) |
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
cd doc/net_bench

# 1. Provision: SG (intra-group only), placement group, IAM/SSM role,
#    S3 results bucket, 2 tagged instances. Reuses the default VPC.
./provision.sh

# 2. Bootstrap each box (installs toolchains, builds server + clients).
./ssmx.sh runfile server box_bootstrap_server.sh
./ssmx.sh runfile client box_bootstrap_client.sh

# 3. Run a cell: shapes the channel, (re)starts the server, wraps the bench
#    with sar on both boxes, syncs results to ./results/<label>/.
./run_cell.sh --label p1-s1-ingress \
    --schema s1-narrow --direction ingress --rows 10000000 \
    --rate 2.5gbit --rtt-ms 5 --client rust

# 4. Tear everything down (safe to re-run; audits by tag at the end).
./teardown.sh
```

## The scripts

| Script | Runs on | What it does |
| --- | --- | --- |
| `provision.sh` | laptop | create the rig; aborts if tagged instances already exist |
| `teardown.sh` | laptop | terminate instances and delete every resource, by tag |
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

Run `run_cell.sh` / `ssmx.sh` / `box_channel.sh` with no useful args to see
their full flag lists in the usage headers.
