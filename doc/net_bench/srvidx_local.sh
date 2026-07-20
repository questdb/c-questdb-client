#!/usr/bin/env bash
# One srv-covidx cell against an already-running local server
# (doc/net_bench/SRV_COVIDX_PLAN.md). Samples WAL lag / server RSS /
# table-dir size at 1 Hz while the generator runs.
#
# Usage:
#   srvidx_local.sh <cov|plain> <senders> <rows> <outdir> [tag]
# Env:
#   QDB_HOST=127.0.0.1 QDB_PORT=9000
#   QDB_ROOT=            server db root; enables du sampling + write-amp meta
#   SRV_PID=             server pid; default: pgrep -f io.questdb.ServerMain
#   BIN=                 generator binary; default resolves via repo layout
#   MAX_BATCH_ROWS=1000 ITERATIONS=5 WARMUPS=2   passed through
set -u

VARIANT=${1:?usage: srvidx_local.sh <cov|plain> <senders> <rows> <outdir> [tag]}
SENDERS=${2:?senders}
ROWS=${3:?rows}
OUTDIR=${4:?outdir}
TAG=${5:-local}

QDB_HOST=${QDB_HOST:-127.0.0.1}
QDB_PORT=${QDB_PORT:-9000}
QDB_ROOT=${QDB_ROOT:-}
REPO_DIR=$(cd "$(dirname "$0")/../.." && pwd)
BIN=${BIN:-$REPO_DIR/questdb-rs/target/release/examples/qwp_ingress_srvidx}
TABLE="bench_s3_${VARIANT}"
CELL="srvidx-${VARIANT}-x${SENDERS}-r${ROWS}-${TAG}"

[ -x "$BIN" ] || { echo "ERROR: generator binary not found at $BIN (build it first)" >&2; exit 1; }
mkdir -p "$OUTDIR"

SRV_PID=${SRV_PID:-$(pgrep -f 'io.questdb.ServerMain' | head -1 || true)}

SAMPLE_CSV="$OUTDIR/$CELL.sampler.csv"
echo "epoch_s,writer_txn,seq_txn,rss_kb,du_kb" > "$SAMPLE_CSV"
(
    while :; do
        # Separate -e args: BSD sed's `t` otherwise swallows the rest of the
        # expression as a label name (hard parse error on macOS). The ${wal:-,}
        # default keeps the CSV at 5 columns even when curl emits nothing.
        wal=$(curl -s "http://$QDB_HOST:$QDB_PORT/exec" --get --data-urlencode \
            "query=SELECT writerTxn, sequencerTxn FROM wal_tables() WHERE name = '$TABLE'" \
            | sed -E -e 's/.*"dataset":\[\[(-?[0-9]+),(-?[0-9]+).*/\1,\2/' -e 't' -e 's/.*/,/')
        wal=${wal:-,}
        rss=""
        [ -n "$SRV_PID" ] && rss=$(ps -o rss= -p "$SRV_PID" 2>/dev/null | tr -d ' ')
        du_kb=""
        if [ -n "$QDB_ROOT" ]; then
            # Sum over ALL matching dirs: DROP+CREATE leaves old ~N husks
            # until purge, and picking one can latch an empty husk.
            du_kb=$(find "$QDB_ROOT/db" -maxdepth 1 \( -name "${TABLE}~*" -o -name "$TABLE" \) -print0 2>/dev/null | xargs -0 du -sk 2>/dev/null | awk '{s+=$1} END{print s+0}')
        fi
        echo "$(date +%s),$wal,$rss,$du_kb" >> "$SAMPLE_CSV"
        sleep 1
    done
) &
SAMPLER=$!
trap 'kill "$SAMPLER" 2>/dev/null' EXIT

wb() { # Linux server write_bytes (write-amplification input); empty elsewhere
    [ -n "$SRV_PID" ] && [ -r "/proc/$SRV_PID/io" ] \
        && awk '/^write_bytes/{print $2}' "/proc/$SRV_PID/io" || true
}
WB0=$(wb)

VARIANT=$VARIANT ROWS=$ROWS SENDERS=$SENDERS \
    QDB_HOST=$QDB_HOST QDB_PORT=$QDB_PORT \
    MAX_BATCH_ROWS=${MAX_BATCH_ROWS:-1000} \
    ITERATIONS=${ITERATIONS:-5} WARMUPS=${WARMUPS:-2} \
    "$BIN" > "$OUTDIR/$CELL.json"
RC=$?

WB1=$(wb)
kill "$SAMPLER" 2>/dev/null
{
    echo "cell=$CELL"
    echo "date_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "variant=$VARIANT senders=$SENDERS rows=$ROWS batch=${MAX_BATCH_ROWS:-1000}"
    echo "server_pid=${SRV_PID:-unknown}"
    echo "write_bytes_before=${WB0:-na} write_bytes_after=${WB1:-na}"
    echo "client_commit=$(git -C "$REPO_DIR" rev-parse HEAD 2>/dev/null || echo unknown)"
    echo "rc=$RC"
} > "$OUTDIR/$CELL.meta"

echo "[$CELL] rc=$RC json=$OUTDIR/$CELL.json sampler=$SAMPLE_CSV" >&2
exit "$RC"
