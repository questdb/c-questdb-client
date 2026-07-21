#!/usr/bin/env bash
# Laptop-side single-cell runner. Applies the channel, (re)starts the
# server at the requested receive buffer, wraps the bench with sar on both
# boxes, and syncs results + a channel-metadata sidecar to ./results/<label>/.
#
#   ./run_cell.sh --label p1-s1-ingress \
#       --schema s1-narrow --direction ingress --rows 10000000 \
#       [--rate 2.5gbit] [--rtt-ms 5] [--recv-buf 16m] \
#       [--iterations 5] [--warmups 2] [--max-batch-rows 10000] [--senders N] [--skip-populate] \
#       [--client rust|rust-row|c|java] [--conf-extra 'key=value;...']
#
# --conf-extra appends extra conf params to the bench's connect string
# (e.g. 'sf_append_deadline_millis=300000;'). Only the rust-row bench reads
# QDB_CONF_EXTRA today; other clients silently ignore it.
#
# direction: ingress | egress   (egress with --skip-populate reuses the table
# a prior ingress cell filled; without it the egress example populates first).
# rust-row (row-API Rust bench) supports ingress only. Python cells remain
# blocked until W1 (remote-host patch); rust/rust-row/c/java are available.
set -euo pipefail
cd "$(dirname "$0")"
. ./env.sh

LABEL="" SCHEMA="s1-narrow" DIRECTION="ingress" ROWS=10000000
RATE="" RTT_MS="" RECV_BUF="16m" ITERATIONS=5 WARMUPS=2 MAX_BATCH_ROWS=10000
SKIP_POPULATE=0 CLIENT_KIND=rust SENDERS=1 CONF_EXTRA=""
while [ $# -gt 0 ]; do
    case "$1" in
        --label) LABEL="$2"; shift 2 ;;
        --schema) SCHEMA="$2"; shift 2 ;;
        --direction) DIRECTION="$2"; shift 2 ;;
        --rows) ROWS="$2"; shift 2 ;;
        --rate) RATE="$2"; shift 2 ;;
        --rtt-ms) RTT_MS="$2"; shift 2 ;;
        --recv-buf) RECV_BUF="$2"; shift 2 ;;
        --iterations) ITERATIONS="$2"; shift 2 ;;
        --warmups) WARMUPS="$2"; shift 2 ;;
        --max-batch-rows) MAX_BATCH_ROWS="$2"; shift 2 ;;
        --senders) SENDERS="$2"; shift 2 ;;
        --conf-extra) CONF_EXTRA="$2"; shift 2 ;;
        --skip-populate) SKIP_POPULATE=1; shift ;;
        --client) CLIENT_KIND="$2"; shift 2 ;;
        *) echo "unknown arg $1" >&2; exit 1 ;;
    esac
done
case "$CLIENT_KIND" in rust|rust-row|c|java) ;; *) echo "unknown --client '$CLIENT_KIND' (rust|rust-row|c|java)" >&2; exit 1 ;; esac
case "$SENDERS" in ''|0|*[!0-9]*) echo "--senders wants a positive integer" >&2; exit 1 ;; esac
[ -n "$LABEL" ] || { echo "--label required" >&2; exit 1; }

# Branch-name pins resolve to concrete SHAs once per cell so the sidecar and
# the java report record provenance, not a moving ref. NOTE: this resolves the
# tip as of NOW; the boxes run whatever the ref resolved to at their last
# bootstrap — re-run box_bootstrap_client.sh before a campaign if the branch
# may have moved. Exact-SHA pins pass through offline.
QNB_C_CLIENT_COMMIT=$(qnb_resolve_commit "$QNB_C_CLIENT_REPO" "$QNB_C_CLIENT_COMMIT")
QNB_JAVA_CLIENT_COMMIT=$(qnb_resolve_commit "$QNB_JAVA_CLIENT_REPO" "$QNB_JAVA_CLIENT_COMMIT")
QNB_PY_CLIENT_COMMIT=$(qnb_resolve_commit "$QNB_PY_CLIENT_REPO" "$QNB_PY_CLIENT_COMMIT")

SERVER_ID=$(qnb_instance_id server); CLIENT_ID=$(qnb_instance_id client)
SERVER_IP=$(qnb_private_ip "$SERVER_ID")
OUT_LOCAL="results/$LABEL"; OUT_BOX="/var/tmp/qwp-results/$LABEL"
mkdir -p "$OUT_LOCAL"

echo "== channel: rate=${RATE:-unshaped} rtt=${RTT_MS:-native}ms"
HALF_DELAY=""
[ -n "$RTT_MS" ] && HALF_DELAY=$(awk "BEGIN{print $RTT_MS/2}")
CH_ARGS=""
[ -n "$RATE" ] && CH_ARGS="--rate $RATE"
[ -n "$HALF_DELAY" ] && CH_ARGS="$CH_ARGS --delay-ms $HALF_DELAY"
for box in server client; do
    if [ -n "$CH_ARGS" ]; then
        ./ssmx.sh runfile "$box" box_channel.sh set $CH_ARGS
    else
        ./ssmx.sh runfile "$box" box_channel.sh clear
    fi
done

echo "== server: ensure recv buffer $RECV_BUF"
./ssmx.sh run server "qdb-server ensure $RECV_BUF"

echo "== start sar on both boxes"
for box in server client; do
    ./ssmx.sh run "$box" "mkdir -p $OUT_BOX; pkill -f 'sar -o' 2>/dev/null; \
nohup sar -o $OUT_BOX/sar-$box.bin 1 >/dev/null 2>&1 & echo sar started"
done

echo "== bench ($CLIENT_KIND, $DIRECTION, $SCHEMA, ${ROWS} rows, it=$ITERATIONS/wu=$WARMUPS, senders=$SENDERS)"
BENCH_ENV="SCHEMA=$SCHEMA ROWS=$ROWS ITERATIONS=$ITERATIONS WARMUPS=$WARMUPS \
MAX_BATCH_ROWS=$MAX_BATCH_ROWS QDB_HOST=$SERVER_IP QDB_PORT=9000 SENDERS=$SENDERS"
[ "$SKIP_POPULATE" = "1" ] && BENCH_ENV="$BENCH_ENV SKIP_POPULATE=1"
# Single-quote the value: BENCH_ENV lands unquoted in the remote command and
# conf strings end in ';', which the box's shell would treat as a separator.
[ -n "$CONF_EXTRA" ] && BENCH_ENV="$BENCH_ENV QDB_CONF_EXTRA='$CONF_EXTRA'"
JAVA_ENV_EXPORT=""
if [ "$CLIENT_KIND" = "c" ]; then
    BENCH_CMD="/opt/qwp-bench/c-questdb-client/build/qwp_${DIRECTION}_c"
elif [ "$CLIENT_KIND" = "java" ]; then
    BENCH_ENV="$BENCH_ENV JAVA_QUESTDB_CLIENT_COMMIT=$QNB_JAVA_CLIENT_COMMIT"
    JAVA_ENV_EXPORT="export JAVA_HOME=/usr/lib/jvm/java-25-openjdk-arm64; export PATH=\$JAVA_HOME/bin:\$PATH; "
    BENCH_CMD="java -Xms4g -Xmx4g -jar /opt/qwp-bench/java-questdb-client/qwp-bench/target/qwp-bench-java.jar ${DIRECTION}"
elif [ "$CLIENT_KIND" = "rust-row" ]; then
    [ "$DIRECTION" = "ingress" ] || { echo "rust-row supports ingress only" >&2; exit 1; }
    BENCH_CMD="cargo run --release --features sync-sender-qwp-ws,sync-sender-http --example qwp_ingress_row"
else
    EXAMPLE="qwp_ingress_polars"
    [ "$DIRECTION" = "egress" ] && EXAMPLE="qwp_egress_polars"
    BENCH_CMD="cargo run --release \
    --features polars,sync-sender-qwp-ws,sync-sender-http \
    --example $EXAMPLE"
fi
./ssmx.sh run client "${JAVA_ENV_EXPORT}export PATH=/root/.cargo/bin:\$PATH; \
cd /opt/qwp-bench/c-questdb-client/questdb-rs && mkdir -p $OUT_BOX && \
{ time env $BENCH_ENV $BENCH_CMD > $OUT_BOX/$CLIENT_KIND-$DIRECTION.json ; } \
    2> $OUT_BOX/$CLIENT_KIND-$DIRECTION.log; \
tail -5 $OUT_BOX/$CLIENT_KIND-$DIRECTION.log" 14400

echo "== stop sar, render text, collect"
for box in server client; do
    ./ssmx.sh run "$box" "pkill -f 'sar -o' 2>/dev/null; sleep 1; \
sar -f $OUT_BOX/sar-$box.bin -u > $OUT_BOX/sar-$box-cpu.txt 2>/dev/null; \
sar -f $OUT_BOX/sar-$box.bin -n DEV > $OUT_BOX/sar-$box-net.txt 2>/dev/null; \
aws s3 cp --recursive $OUT_BOX s3://$(qnb_bucket)/results/$LABEL/ >/dev/null; echo uploaded"
done
aws s3 cp --recursive "s3://$(qnb_bucket)/results/$LABEL/" "$OUT_LOCAL/" >/dev/null

echo "== channel measurement + sidecar"
IPERF_NOTE="not-measured-this-cell"
jq -n \
    --arg cell "$LABEL" --arg schema "$SCHEMA" --arg direction "$DIRECTION" \
    --arg rate "${RATE:-unshaped}" --arg rtt "${RTT_MS:-native}" \
    --arg recv "$RECV_BUF" --arg rows "$ROWS" \
    --arg itype "$QNB_INSTANCE_TYPE" --arg iperf "$IPERF_NOTE" \
    --arg qdb "$QNB_QUESTDB_COMMIT" --arg cc "$QNB_C_CLIENT_COMMIT" \
    --arg py "$QNB_PY_CLIENT_COMMIT" --arg ck "$CLIENT_KIND" --arg senders "$SENDERS" \
    --arg confx "$CONF_EXTRA" \
    '{cell: $cell, schema: $schema, direction: $direction, rows: ($rows|tonumber),
      client_kind: $ck, senders: ($senders|tonumber), conf_extra: $confx,
      channel: {rate: $rate, rtt_ms: $rtt, placement_group: true, iperf3: $iperf},
      server: {instance_type: $itype, questdb_commit: $qdb,
               recv_buffer: $recv, data_dir: "tmpfs"},
      client_box: {instance_type: $itype},
      commits: {c_questdb_client: $cc, py_questdb_client: $py},
      monitor: ["sar-client-cpu.txt","sar-client-net.txt",
                "sar-server-cpu.txt","sar-server-net.txt"]}' \
    > "$OUT_LOCAL/cell.json"

echo "== done: $OUT_LOCAL"
ls -la "$OUT_LOCAL"
