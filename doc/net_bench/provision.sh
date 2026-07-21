#!/usr/bin/env bash
# Provision the 2-box QWP network bench rig.
# Creates: security group, cluster placement group, IAM role + instance
# profile (SSM + bucket access), S3 results bucket, 2 tagged instances.
# Reuses the default VPC — no network resources are created.
# Idempotence: aborts if tagged instances already exist.
set -euo pipefail
cd "$(dirname "$0")"
. ./env.sh

SG_NAME="${QNB_PREFIX}-sg"
PG_NAME="${QNB_PREFIX}-pg"
ROLE_NAME="${QNB_PREFIX}-ssm"
BUCKET="$(qnb_bucket)"

if [ -n "$(qnb_instance_id server)$(qnb_instance_id client)" ]; then
    echo "ERROR: tagged instances already exist — run teardown.sh first." >&2
    exit 1
fi

echo "== default VPC"
VPC_ID=$(aws ec2 describe-vpcs --filters Name=isDefault,Values=true \
    --query 'Vpcs[0].VpcId' --output text)
[ "$VPC_ID" != "None" ] || { echo "ERROR: no default VPC in $AWS_REGION" >&2; exit 1; }

echo "== pick AZ offering $QNB_INSTANCE_TYPE"
OFFERED_AZS=$(aws ec2 describe-instance-type-offerings \
    --location-type availability-zone \
    --filters "Name=instance-type,Values=${QNB_INSTANCE_TYPE}" \
    --query 'InstanceTypeOfferings[].Location' --output text)
SUBNET_ID=""; AZ=""
for az in $OFFERED_AZS; do
    sn=$(aws ec2 describe-subnets \
        --filters "Name=vpc-id,Values=$VPC_ID" "Name=availability-zone,Values=$az" \
        --query 'Subnets[0].SubnetId' --output text)
    if [ "$sn" != "None" ]; then SUBNET_ID=$sn; AZ=$az; break; fi
done
[ -n "$SUBNET_ID" ] || { echo "ERROR: no default subnet in an AZ offering ${QNB_INSTANCE_TYPE}" >&2; exit 1; }
echo "   AZ=$AZ subnet=$SUBNET_ID"

echo "== security group (intra-group only, no other inbound)"
SG_ID=$(aws ec2 create-security-group --group-name "$SG_NAME" \
    --description "QWP net bench - intra-group traffic only, access via SSM" \
    --vpc-id "$VPC_ID" \
    --tag-specifications "$(qnb_tagspec security-group)" \
    --query GroupId --output text)
aws ec2 authorize-security-group-ingress --group-id "$SG_ID" \
    --protocol -1 --source-group "$SG_ID" >/dev/null

echo "== cluster placement group"
aws ec2 create-placement-group --group-name "$PG_NAME" --strategy cluster \
    --tag-specifications "$(qnb_tagspec placement-group)"

echo "== S3 results bucket s3://$BUCKET"
aws s3api create-bucket --bucket "$BUCKET" \
    --create-bucket-configuration "LocationConstraint=$AWS_REGION" >/dev/null
aws s3api put-public-access-block --bucket "$BUCKET" \
    --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
aws s3api put-bucket-tagging --bucket "$BUCKET" \
    --tagging "TagSet=[{Key=${QNB_TAG_KEY},Value=${QNB_TAG_VAL}}]"

echo "== IAM role + instance profile (SSM core + bench bucket rw + ECR pull)"
aws iam create-role --role-name "$ROLE_NAME" \
    --tags "Key=${QNB_TAG_KEY},Value=${QNB_TAG_VAL}" \
    --assume-role-policy-document '{
      "Version": "2012-10-17",
      "Statement": [{"Effect": "Allow",
                     "Principal": {"Service": "ec2.amazonaws.com"},
                     "Action": "sts:AssumeRole"}]}' >/dev/null
aws iam attach-role-policy --role-name "$ROLE_NAME" \
    --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
aws iam put-role-policy --role-name "$ROLE_NAME" --policy-name bench-bucket \
    --policy-document "{
      \"Version\": \"2012-10-17\",
      \"Statement\": [
        {\"Effect\": \"Allow\", \"Action\": [\"s3:GetObject\", \"s3:PutObject\", \"s3:ListBucket\"],
         \"Resource\": [\"arn:aws:s3:::${BUCKET}\", \"arn:aws:s3:::${BUCKET}/*\"]},
        {\"Effect\": \"Allow\", \"Action\": [\"ecr:GetAuthorizationToken\", \"ecr:BatchGetImage\",
                                             \"ecr:GetDownloadUrlForLayer\", \"ecr:BatchCheckLayerAvailability\"],
         \"Resource\": \"*\"}]}"
# ECR actions are identity-side only; actual image access is governed by the
# registry's own repository policy (needed for `qdb-server use-ent`).
aws iam create-instance-profile --instance-profile-name "$ROLE_NAME" >/dev/null
aws iam add-role-to-instance-profile --instance-profile-name "$ROLE_NAME" \
    --role-name "$ROLE_NAME"

echo "== AMI"
AMI=$(aws ssm get-parameter --name "$QNB_UBUNTU_SSM_PARAM" \
    --query Parameter.Value --output text)
echo "   $AMI (Ubuntu 24.04 arm64)"

launch() { # $1 = role: server | client
    aws ec2 run-instances \
        --image-id "$AMI" --instance-type "$QNB_INSTANCE_TYPE" \
        --subnet-id "$SUBNET_ID" --security-group-ids "$SG_ID" \
        --associate-public-ip-address \
        --placement "GroupName=$PG_NAME" \
        --iam-instance-profile "Name=$ROLE_NAME" \
        --metadata-options "HttpTokens=required,HttpEndpoint=enabled" \
        --block-device-mappings "DeviceName=/dev/sda1,Ebs={VolumeSize=${QNB_ROOT_GB},VolumeType=gp3,DeleteOnTermination=true}" \
        --tag-specifications \
            "ResourceType=instance,Tags=[{Key=${QNB_TAG_KEY},Value=${QNB_TAG_VAL}},{Key=Owner,Value=sergey},{Key=Role,Value=$1},{Key=Name,Value=${QNB_PREFIX}-$1}]" \
            "ResourceType=volume,Tags=[{Key=${QNB_TAG_KEY},Value=${QNB_TAG_VAL}}]" \
        --query 'Instances[0].InstanceId' --output text
}

echo "== launch instances (instance-profile propagation can need a retry)"
SERVER_ID=""
for i in 1 2 3; do
    if SERVER_ID=$(launch server); then break; fi
    echo "   retry $i ..."; sleep 10
done
[ -n "$SERVER_ID" ] || { echo "ERROR: server launch failed after 3 attempts (capacity for ${QNB_INSTANCE_TYPE} in ${AZ}? try QNB_INSTANCE_TYPE=c7gn.2xlarge)" >&2; exit 1; }
CLIENT_ID=$(launch client)
echo "   server=$SERVER_ID client=$CLIENT_ID"

echo "== wait: running"
aws ec2 wait instance-running --instance-ids "$SERVER_ID" "$CLIENT_ID"

echo "== wait: SSM registration"
for i in $(seq 1 60); do
    n=$(aws ssm describe-instance-information \
        --filters "Key=InstanceIds,Values=$SERVER_ID,$CLIENT_ID" \
        --query 'length(InstanceInformationList)' --output text)
    [ "$n" = "2" ] && break
    sleep 10
done
[ "$n" = "2" ] || { echo "ERROR: instances did not register with SSM" >&2; exit 1; }

echo
echo "== READY =="
echo "server: $SERVER_ID  private_ip=$(qnb_private_ip "$SERVER_ID")"
echo "client: $CLIENT_ID  private_ip=$(qnb_private_ip "$CLIENT_ID")"
echo "bucket: s3://$BUCKET   az: $AZ   pg: $PG_NAME"
echo "Next: ./ssmx.sh runfile server box_bootstrap_server.sh"
echo "      ./ssmx.sh runfile client box_bootstrap_client.sh"
