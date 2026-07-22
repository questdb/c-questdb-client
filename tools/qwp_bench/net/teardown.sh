#!/usr/bin/env bash
# Tear down everything provision.sh created, then audit by tag.
# Safe to re-run; each step tolerates already-deleted resources.
set -uo pipefail
cd "$(dirname "$0")"
. ./env.sh

SG_NAME="${QNB_PREFIX}-sg"
PG_NAME="${QNB_PREFIX}-pg"
ROLE_NAME="${QNB_PREFIX}-ssm"
BUCKET="$(qnb_bucket)"

echo "== terminate instances"
IDS=$(aws ec2 describe-instances \
    --filters "Name=tag:${QNB_TAG_KEY},Values=${QNB_TAG_VAL}" \
              "Name=instance-state-name,Values=pending,running,stopping,stopped" \
    --query 'Reservations[].Instances[].InstanceId' --output text)
if [ -n "$IDS" ]; then
    aws ec2 terminate-instances --instance-ids $IDS >/dev/null
    echo "   waiting for: $IDS"
    aws ec2 wait instance-terminated --instance-ids $IDS
fi

echo "== security group"
SG_ID=$(aws ec2 describe-security-groups \
    --filters "Name=group-name,Values=$SG_NAME" \
    --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null)
if [ -n "$SG_ID" ] && [ "$SG_ID" != "None" ]; then
    for i in $(seq 1 12); do  # ENIs can linger briefly after terminate
        aws ec2 delete-security-group --group-id "$SG_ID" 2>/dev/null && break
        sleep 10
    done
fi

echo "== placement group"
aws ec2 delete-placement-group --group-name "$PG_NAME" 2>/dev/null

echo "== IAM role / instance profile"
aws iam remove-role-from-instance-profile --instance-profile-name "$ROLE_NAME" \
    --role-name "$ROLE_NAME" 2>/dev/null
aws iam delete-instance-profile --instance-profile-name "$ROLE_NAME" 2>/dev/null
aws iam detach-role-policy --role-name "$ROLE_NAME" \
    --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore 2>/dev/null
aws iam delete-role-policy --role-name "$ROLE_NAME" --policy-name bench-bucket 2>/dev/null
aws iam delete-role --role-name "$ROLE_NAME" 2>/dev/null

echo "== S3 bucket (results are deleted with it — sync down anything you need first!)"
read -r -p "Delete s3://$BUCKET and ALL results? (y/n) [n]: " ans
if [[ "${ans:-n}" =~ ^[Yy] ]]; then
    aws s3 rb "s3://$BUCKET" --force 2>/dev/null
else
    echo "   kept s3://$BUCKET (rerun teardown.sh later to remove)"
fi

echo "== tag audit (should list nothing except a kept bucket)"
aws resourcegroupstaggingapi get-resources \
    --tag-filters "Key=${QNB_TAG_KEY},Values=${QNB_TAG_VAL}" \
    --query 'ResourceTagMappingList[].ResourceARN' --output table
# IAM is not covered by the tagging API — check explicitly:
if aws iam get-role --role-name "$ROLE_NAME" >/dev/null 2>&1; then
    echo "WARNING: IAM role $ROLE_NAME still exists" >&2
else
    echo "IAM role: gone"
fi
