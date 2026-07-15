#!/usr/bin/env bash
# Shared configuration for the QWP network bench rig (see ../QWP_NETWORK_BENCH_PLAN.md).
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

# Commits under test. Server pin = OSS master commit that is the core of the
# ENT 3.3.4 release (so the OSS source build and the ENT docker image are the
# same lineage); local loopback baselines are being re-measured against it.
QNB_QUESTDB_COMMIT="${QNB_QUESTDB_COMMIT:-5b2efe5e58fbb77ef25f87a7aa604365c9c1eb55}"
# c pin = sm_qwp_bench head with the Rust bench twins' CHECKPOINT_BATCHES
# env knob (row-build floor parity with the java twin); the env.sh bump
# commit itself is laptop-side only.
QNB_C_CLIENT_COMMIT="${QNB_C_CLIENT_COMMIT:-5fdfb02f099e4a1c6bc009cfa4540ab094335e67}"
QNB_PY_CLIENT_COMMIT="${QNB_PY_CLIENT_COMMIT:-7334503e84e2d149f9d6550dd023ef484d2edc1e}"
# Head of our sm_qwp_bench branch of questdb/java-questdb-client (adds the
# qwp-bench module). Pin = pushed head of that branch; bump when it moves.
QNB_JAVA_CLIENT_COMMIT="${QNB_JAVA_CLIENT_COMMIT:-36d1f51a552cbccc81f87b526a387bb838dc550e}"

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
