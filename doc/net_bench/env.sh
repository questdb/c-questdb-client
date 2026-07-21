#!/usr/bin/env bash
# Shared configuration for the QWP network bench rig (see ./README.md).
# Sourced by the laptop-side scripts. Requires: aws cli v2, jq, and a valid
# SSO session (`aws sso login` with your SSO profile).

export AWS_PROFILE="${QNB_AWS_PROFILE:-dev}"
export AWS_REGION="${QNB_AWS_REGION:-eu-west-1}"
export AWS_DEFAULT_REGION="$AWS_REGION"

QNB_TAG_KEY="Project"
QNB_TAG_VAL="qwp-net-bench"
QNB_PREFIX="qwp-net-bench"
QNB_INSTANCE_TYPE="${QNB_INSTANCE_TYPE:-c8gn.2xlarge}"
QNB_ROOT_GB="${QNB_ROOT_GB:-48}"
# Ubuntu 24.04 LTS arm64, resolved at provision time via the canonical SSM parameter.
QNB_UBUNTU_SSM_PARAM="/aws/service/canonical/ubuntu/server/24.04/stable/current/arm64/hvm/ebs-gp3/ami-id"

# Client repo URLs — shared by run_cell.sh's ref resolution. The box
# bootstrap carries its own copies (env.sh is never shipped to boxes).
QNB_C_CLIENT_REPO="https://github.com/questdb/c-questdb-client.git"
QNB_JAVA_CLIENT_REPO="https://github.com/questdb/java-questdb-client.git"
QNB_PY_CLIENT_REPO="https://github.com/questdb/py-questdb-client.git"

# Commits under test. Server pin = OSS master commit that is the core of the
# ENT 3.3.4 release (so the OSS source build and the ENT docker image are the
# same lineage); local loopback baselines are being re-measured against it.
QNB_QUESTDB_COMMIT="${QNB_QUESTDB_COMMIT:-5b2efe5e58fbb77ef25f87a7aa604365c9c1eb55}"
# Client values accept an exact 40-hex SHA or a branch/tag name. Branch names
# resolve to the remote tip at USE time: boxes resolve at bootstrap, the
# laptop at cell time (qnb_resolve_commit below) — so sidecars and the java
# report always record a concrete SHA. Defaults track our bench branches,
# which kills the pin-bump-commit churn; export QNB_*_COMMIT=<sha> for a
# strictly pinned campaign, and re-run the client bootstrap before a campaign
# whenever a branch default may have moved (otherwise the boxes keep running
# binaries from the tip seen at their last bootstrap).
QNB_C_CLIENT_COMMIT="${QNB_C_CLIENT_COMMIT:-sm_qwp_bench}"
# py pin = exact commit on jh's jh_experiment_new_ilp (not our branch — keep
# exact so upstream movement stays opt-in).
QNB_PY_CLIENT_COMMIT="${QNB_PY_CLIENT_COMMIT:-7334503e84e2d149f9d6550dd023ef484d2edc1e}"
QNB_JAVA_CLIENT_COMMIT="${QNB_JAVA_CLIENT_COMMIT:-sm_qwp_bench}"

# Resolve a client ref that may be a branch/tag name to the SHA at its remote
# tip. Exact 40-hex SHAs pass through untouched (offline). Fails loudly on an
# unknown ref so a typo can't silently bench the wrong tree.
qnb_resolve_commit() { # $1 = repo url, $2 = ref-or-sha
    if printf '%s' "$2" | grep -qE '^[0-9a-f]{40}$'; then
        printf '%s\n' "$2"
        return 0
    fi
    local sha
    sha=$(git ls-remote "$1" "refs/heads/$2" "refs/tags/$2" | head -1 | cut -f1)
    [ -n "$sha" ] || { echo "ERROR: cannot resolve ref '$2' in $1" >&2; return 1; }
    printf '%s\n' "$sha"
}

qnb_account_id() { aws sts get-caller-identity --query Account --output text; }

qnb_bucket() { echo "${QNB_PREFIX}-$(qnb_account_id)"; }

# $1 = role tag value: server | client
qnb_instance_id() {
    aws ec2 describe-instances \
        --filters "Name=tag:${QNB_TAG_KEY},Values=${QNB_TAG_VAL}" \
                  "Name=tag:Role,Values=$1" \
                  "Name=instance-state-name,Values=pending,running,stopping,stopped" \
        --query 'Reservations[].Instances[].InstanceId' --output text
}

qnb_private_ip() {
    aws ec2 describe-instances --instance-ids "$1" \
        --query 'Reservations[0].Instances[0].PrivateIpAddress' --output text
}

qnb_tagspec() { # $1 = resource type
    echo "ResourceType=$1,Tags=[{Key=${QNB_TAG_KEY},Value=${QNB_TAG_VAL}},{Key=Owner,Value=sergey}]"
}
