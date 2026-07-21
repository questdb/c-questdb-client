#!/usr/bin/env bash
# Thin SSM wrapper — run commands/scripts on the bench boxes without SSH.
#
#   ./ssmx.sh run <server|client> "<command>"          run a one-liner, print output
#   ./ssmx.sh runfile <server|client> <script> [args]  ship a local script via S3 and run it
#   ./ssmx.sh pull <server|client> <remote> <local>    fetch a file/dir via the bucket
#   ./ssmx.sh shell <server|client>                    interactive session (needs session-manager-plugin)
#
# Box-side scripts get QNB_BUCKET / QNB_PEER_IP / QNB_* commits exported.
# Note: `run` output is truncated by SSM at 24 KB — long output should go to a
# file and be `pull`ed.
set -euo pipefail
cd "$(dirname "$0")"
. ./env.sh

MODE="${1:?usage: ssmx.sh run|runfile|pull|shell <server|client> ...}"
ROLE="${2:?instance role (server|client) required}"
IID=$(qnb_instance_id "$ROLE")
[ -n "$IID" ] || { echo "ERROR: no running '$ROLE' instance found by tag" >&2; exit 1; }
BUCKET="$(qnb_bucket)"

peer_role() { [ "$ROLE" = "server" ] && echo client || echo server; }

box_env() {
    local peer_id peer_ip
    peer_id=$(qnb_instance_id "$(peer_role)")
    peer_ip=$([ -n "$peer_id" ] && qnb_private_ip "$peer_id" || echo "")
    # SSM runs commands as root with HOME unset — rustup, uv and cargo need it.
    echo "export HOME=/root QNB_BUCKET='$BUCKET' QNB_PEER_IP='$peer_ip'" \
         "QNB_QUESTDB_COMMIT='$QNB_QUESTDB_COMMIT'" \
         "QNB_C_CLIENT_COMMIT='$QNB_C_CLIENT_COMMIT'" \
         "QNB_PY_CLIENT_COMMIT='$QNB_PY_CLIENT_COMMIT'" \
         "QNB_JAVA_CLIENT_COMMIT='$QNB_JAVA_CLIENT_COMMIT'"
}

send_and_wait() { # $1 = command string, $2 = timeout seconds
    local cmd_id status
    cmd_id=$(aws ssm send-command --instance-ids "$IID" \
        --document-name AWS-RunShellScript \
        --parameters "$(jq -n --arg c "$1" --arg t "${2:-3600}" \
            '{commands: [$c], executionTimeout: [$t]}')" \
        --query 'Command.CommandId' --output text)
    while :; do
        status=$(aws ssm get-command-invocation --command-id "$cmd_id" \
            --instance-id "$IID" --query Status --output text 2>/dev/null || echo Pending)
        case "$status" in
            Success|Failed|Cancelled|TimedOut) break ;;
            *) sleep 5 ;;
        esac
    done
    aws ssm get-command-invocation --command-id "$cmd_id" --instance-id "$IID" \
        --query StandardOutputContent --output text
    if [ "$status" != "Success" ]; then
        echo "--- stderr ---" >&2
        aws ssm get-command-invocation --command-id "$cmd_id" --instance-id "$IID" \
            --query StandardErrorContent --output text >&2
        echo "ERROR: command $status on $ROLE ($IID)" >&2
        return 1
    fi
}

# First contact installs the AWS CLI (snap) so boxes can reach the bucket.
BOOTSTRAP_CLI='command -v aws >/dev/null 2>&1 || snap install aws-cli --classic >/dev/null'

case "$MODE" in
    run)
        send_and_wait "$BOOTSTRAP_CLI; $(box_env); ${3:?command required}" "${4:-3600}"
        ;;
    runfile)
        SCRIPT="${3:?local script path required}"; shift 3 || true
        KEY="scripts/$(basename "$SCRIPT")"
        aws s3 cp "$SCRIPT" "s3://$BUCKET/$KEY" >/dev/null
        send_and_wait "$BOOTSTRAP_CLI; $(box_env); \
aws s3 cp 's3://$BUCKET/$KEY' /var/tmp/qnb-script.sh >/dev/null && \
bash /var/tmp/qnb-script.sh $*" 7200
        ;;
    pull)
        REMOTE="${3:?remote path required}"; LOCAL="${4:?local path required}"
        KEY="pull/$(basename "$REMOTE")"
        send_and_wait "$BOOTSTRAP_CLI; if [ -d '$REMOTE' ]; then \
aws s3 cp --recursive '$REMOTE' 's3://$BUCKET/$KEY/'; else \
aws s3 cp '$REMOTE' 's3://$BUCKET/$KEY'; fi" 1800 >/dev/null
        if aws s3 ls "s3://$BUCKET/$KEY/" >/dev/null 2>&1; then
            aws s3 cp --recursive "s3://$BUCKET/$KEY/" "$LOCAL"
        else
            aws s3 cp "s3://$BUCKET/$KEY" "$LOCAL"
        fi
        ;;
    shell)
        aws ssm start-session --target "$IID"
        ;;
    *)
        echo "unknown mode: $MODE" >&2; exit 1 ;;
esac
