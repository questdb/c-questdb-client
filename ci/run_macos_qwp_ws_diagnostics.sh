#!/usr/bin/env bash

# Reproduce TestQwpWsFuzz.test_add_columns on the hosted macOS arm64 image
# while preserving enough host evidence to distinguish VM pressure from a
# filesystem stall. This is intentionally a diagnostic harness, not a general
# test runner.

set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly ROOT_DIR
readonly DIAG_DIR="${QWP_WS_DIAGNOSTICS_DIR:?QWP_WS_DIAGNOSTICS_DIR is required}"
readonly PRESSURE_MODE="${QWP_WS_MEMORY_PRESSURE:-natural}"
readonly RUN_COUNT="${QWP_WS_DIAGNOSTIC_RUNS:-3}"
readonly FUZZ_SEED="0x268579c36b106b74"
readonly BUILD_MODE_SEED="7856154056746654427"

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "This diagnostic harness must run on macOS." >&2
    exit 2
fi

if [[ "$PRESSURE_MODE" != "natural" && "$PRESSURE_MODE" != "warn" ]]; then
    echo "Unsupported QWP_WS_MEMORY_PRESSURE=$PRESSURE_MODE" >&2
    exit 2
fi

cd "$ROOT_DIR" || exit 2
mkdir -p "$DIAG_DIR"

snapshot_host() {
    local label="$1"
    {
        echo "=== $label $(date -u '+%Y-%m-%dT%H:%M:%SZ') ==="
        sw_vers
        uname -a
        sysctl hw.memsize || true
        sysctl hw.physicalcpu || true
        sysctl hw.logicalcpu || true
        sysctl vm.swapusage || true
        memory_pressure || true
        diskutil info / || true
        df -h /
        ulimit -a
        java -version
        git rev-parse HEAD
        git -C questdb rev-parse HEAD
        find questdb/core/target -maxdepth 1 -type f \
            -name 'questdb*-SNAPSHOT.jar' \
            -exec shasum -a 256 {} \;
    } >>"$DIAG_DIR/manifest.log" 2>&1
}

monitor_pids=()
pressure_pid_file=""
controller_pid=""

# shellcheck disable=SC2329  # Invoked through the EXIT trap below.
stop_monitors() {
    local pid
    if [[ -n "$pressure_pid_file" && -f "$pressure_pid_file" ]]; then
        pid="$(sed -n '1p' "$pressure_pid_file")"
        if [[ -n "$pid" ]]; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    fi
    if [[ -n "$controller_pid" ]]; then
        kill "$controller_pid" 2>/dev/null || true
        wait "$controller_pid" 2>/dev/null || true
    fi
    for pid in "${monitor_pids[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    for pid in "${monitor_pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done
    monitor_pids=()
}

trap stop_monitors EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

snapshot_host before

vm_stat 1 >"$DIAG_DIR/vm-stat.log" 2>&1 &
monitor_pids+=("$!")

iostat -w 1 >"$DIAG_DIR/iostat.log" 2>&1 &
monitor_pids+=("$!")

(
    while true; do
        echo "=== $(date -u '+%Y-%m-%dT%H:%M:%SZ') ==="
        memory_pressure || true
        sysctl vm.swapusage || true
        ps -axo pid,ppid,rss,vsz,%cpu,state,etime,command || true
        sleep 5
    done
) >"$DIAG_DIR/memory-and-processes.log" 2>&1 &
monitor_pids+=("$!")

overall_rc=0
for run_number in $(seq 1 "$RUN_COUNT"); do
    run_dir="$DIAG_DIR/run-$run_number"
    ready_file="$run_dir/server-ready"
    go_file="$run_dir/start-test"
    pressure_pid_file="$run_dir/memory-pressure.pid"
    mkdir -p "$run_dir"

    echo "=== run=$run_number pressure=$PRESSURE_MODE seed=$FUZZ_SEED "\
         "build_mode_seed=$BUILD_MODE_SEED "\
         "started=$(date -u '+%Y-%m-%dT%H:%M:%SZ') ===" \
        | tee -a "$DIAG_DIR/test.log"

    # The test process creates ready_file after QuestDB is accepting requests
    # but before it starts the selected unittest. In the pressure arm, hold it
    # at that barrier until the macOS pressure helper has had five seconds to
    # reach the warning state.
    (
        while [[ ! -f "$ready_file" ]]; do
            sleep 0.1
        done
        if [[ "$PRESSURE_MODE" == "warn" ]]; then
            memory_pressure -l warn -s 300 \
                >"$run_dir/memory-pressure.log" 2>&1 &
            pressure_pid=$!
            echo "$pressure_pid" >"$pressure_pid_file"
            sleep 5
            if ! kill -0 "$pressure_pid" 2>/dev/null; then
                touch "$run_dir/memory-pressure-helper-exited"
            fi
        else
            echo "natural-memory control" >"$run_dir/memory-pressure.log"
        fi
        {
            date -u '+%Y-%m-%dT%H:%M:%SZ'
            memory_pressure || true
            sysctl vm.swapusage || true
            vm_stat || true
        } >"$run_dir/pressure-at-gate.log" 2>&1
        touch "$go_file"
    ) &
    controller_pid=$!

    QWP_WS_FUZZ_SEED="$FUZZ_SEED" \
    QDB_BUILD_MODE_SEED="$BUILD_MODE_SEED" \
    QWP_WS_FUZZ_DIAGNOSTICS=1 \
    QWP_WS_FUZZ_READY_FILE="$ready_file" \
    QWP_WS_FUZZ_GO_FILE="$go_file" \
        python3 system_test/test.py run --repo ./questdb \
            TestQwpWsFuzz.test_add_columns -v \
            2>&1 | tee -a "$DIAG_DIR/test.log"
    test_rc=${PIPESTATUS[0]}
    if [[ "$test_rc" -eq 0 && \
          -f "$run_dir/memory-pressure-helper-exited" ]]; then
        echo "memory_pressure exited before the diagnostic gate" \
            | tee -a "$DIAG_DIR/test.log"
        test_rc=2
    fi

    {
        date -u '+%Y-%m-%dT%H:%M:%SZ'
        memory_pressure || true
        sysctl vm.swapusage || true
        vm_stat || true
    } >"$run_dir/pressure-after-test.log" 2>&1

    if [[ ! -f "$go_file" ]]; then
        kill "$controller_pid" 2>/dev/null || true
    fi
    wait "$controller_pid" 2>/dev/null || true
    controller_pid=""
    if [[ -f "$pressure_pid_file" ]]; then
        pressure_pid="$(sed -n '1p' "$pressure_pid_file")"
        kill "$pressure_pid" 2>/dev/null || true
        wait "$pressure_pid" 2>/dev/null || true
    fi
    pressure_pid_file=""

    server_log="build/questdb/repo/data/log/log.txt"
    if [[ -f "$server_log" ]]; then
        cp "$server_log" "$run_dir/questdb-server.log"
    fi

    echo "=== run=$run_number rc=$test_rc "\
         "finished=$(date -u '+%Y-%m-%dT%H:%M:%SZ') ===" \
        | tee -a "$DIAG_DIR/test.log"

    if [[ "$test_rc" -ne 0 ]]; then
        overall_rc="$test_rc"
        break
    fi
done

snapshot_host after
exit "$overall_rc"
