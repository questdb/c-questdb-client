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
./ssmx.sh runfile client box_bootstrap_client.sh  # rust/py toolchains + repos (~10 min)

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

# ENT server axis (image ref from internal docs; instance role handles ECR auth;
# built-in admin is enabled — note the harness conf strings need auth support first):
./ssmx.sh run server "qdb-server use-ent <registry>/questdb:<ver>-enterprise"
./ssmx.sh run server "qdb-server use-oss"   # back to the OSS build

# results land in ./results/<label>/ (bench JSON + sar CPU/NIC + cell.json sidecar)

./teardown.sh                                     # terminate + delete + tag audit
```

## Notes

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
