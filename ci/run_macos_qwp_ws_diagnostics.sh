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
readonly SERVER_REVISION="12a33d651e51e2682e7a448c8db5168fc72dfad3"
readonly FS_TRACE="${QWP_WS_FS_TRACE:-0}"
readonly STOP_ON_CAPTURE="${QWP_WS_STOP_ON_CAPTURE:-1}"
readonly MAX_SECONDS="${QWP_WS_MAX_SECONDS:-1200}"
readonly MIN_FREE_KB="${QWP_WS_MIN_FREE_KB:-2097152}"

if [[ ! "$RUN_COUNT" =~ ^[1-9][0-9]*$ ||
      ! "$MAX_SECONDS" =~ ^[1-9][0-9]*$ ||
      ! "$MIN_FREE_KB" =~ ^[1-9][0-9]*$ ||
      ( "$STOP_ON_CAPTURE" != "0" && "$STOP_ON_CAPTURE" != "1" ) ]]; then
    echo "Invalid repetition, time, disk-space or capture-stop setting" >&2
    exit 2
fi

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "This diagnostic harness must run on macOS." >&2
    exit 2
fi

if [[ "$PRESSURE_MODE" != "natural" && "$PRESSURE_MODE" != "warn" ]]; then
    echo "Unsupported QWP_WS_MEMORY_PRESSURE=$PRESSURE_MODE" >&2
    exit 2
fi

if [[ "$FS_TRACE" != "0" && "$FS_TRACE" != "1" ]]; then
    echo "Unsupported QWP_WS_FS_TRACE=$FS_TRACE" >&2
    exit 2
fi

cd "$ROOT_DIR" || exit 2
mkdir -p "$DIAG_DIR"
if [[ "$(git -C questdb rev-parse HEAD)" != "$SERVER_REVISION" ]]; then
    echo "Diagnostic server revision must be $SERVER_REVISION" >&2
    exit 2
fi
# Keep the original worker sizing and runtime. Do not quietly replay on a
# different hosted-machine shape or a newer JDK after an image update.
if [[ "$(sysctl -n hw.logicalcpu)" != "3" ||
      "$(java -version 2>&1)" != *"25.0.3+9"* ]]; then
    echo "Expected three CPUs and JDK 25.0.3+9; inspect the hosted image" >&2
    sysctl hw.logicalcpu
    java -version
    exit 2
fi

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
        echo "fs_trace=$FS_TRACE server_revision=$SERVER_REVISION"
        echo "runs=$RUN_COUNT max_seconds=$MAX_SECONDS stop_on_capture=$STOP_ON_CAPTURE"
        echo "min_free_kb=$MIN_FREE_KB"
        find questdb/core/target -maxdepth 1 -type f \
            -name 'questdb*-SNAPSHOT.jar' \
            -exec shasum -a 256 {} \;
    } >>"$DIAG_DIR/manifest.log" 2>&1
}

monitor_pids=()
pressure_pid_file=""
trace_pid_file=""
controller_pid=""
watchdog_pid_file=""

stop_watchdog() {
    local pid
    if [[ -n "$watchdog_pid_file" && -f "$watchdog_pid_file" ]]; then
        pid="$(sed -n '1p' "$watchdog_pid_file")"
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
    watchdog_pid_file=""
}

stop_trace() {
    local pid
    if [[ -n "$trace_pid_file" && -f "$trace_pid_file" ]]; then
        pid="$(sed -n '1p' "$trace_pid_file")"
        if [[ -n "$pid" ]]; then
            sudo -n kill "$pid" 2>/dev/null || kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    fi
    trace_pid_file=""
}

# shellcheck disable=SC2329  # Invoked through the EXIT trap below.
stop_monitors() {
    local pid
    stop_watchdog
    stop_trace
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

{
    date -u '+monitor_start=%Y-%m-%dT%H:%M:%SZ interval_seconds=1'
    exec vm_stat 1
} >"$DIAG_DIR/vm-stat.log" 2>&1 &
monitor_pids+=("$!")

{
    date -u '+monitor_start=%Y-%m-%dT%H:%M:%SZ interval_seconds=1'
    exec iostat -w 1
} >"$DIAG_DIR/iostat.log" 2>&1 &
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
soak_started=$SECONDS
stop_reason="run_limit"
for run_number in $(seq 1 "$RUN_COUNT"); do
    # Stay on this hosted VM for the whole loop. JVM/fixture restarts do not
    # allocate a new worker. Let an in-flight test retain its original timeout.
    if (( SECONDS - soak_started >= MAX_SECONDS )); then
        stop_reason="time_budget"
        break
    fi
    for pid in "${monitor_pids[@]}"; do
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "Host monitor exited; refusing an unobserved soak" | tee -a "$DIAG_DIR/test.log"
            overall_rc=2
            stop_reason="host_monitor_failure"
            break
        fi
    done
    [[ "$overall_rc" -eq 0 ]] || break
    free_kb="$(df -Pk "$DIAG_DIR" | awk 'NR == 2 { print $4 }')"
    if [[ ! "$free_kb" =~ ^[0-9]+$ ]] || (( free_kb < MIN_FREE_KB )); then
        echo "Disk-space safety stop: available_kb=$free_kb required_kb=$MIN_FREE_KB" \
            | tee -a "$DIAG_DIR/test.log"
        overall_rc=2
        stop_reason="disk_space_guard"
        break
    fi
    run_started=$SECONDS
    run_epoch="$(date -u '+%s')"
    run_dir="$DIAG_DIR/run-$run_number"
    ready_file="$run_dir/server-ready"
    go_file="$run_dir/start-test"
    server_pid_file="$run_dir/questdb.pid"
    pressure_pid_file="$run_dir/memory-pressure.pid"
    trace_pid_file="$run_dir/fs-usage.pid"
    watchdog_pid_file="$run_dir/watchdog.pid"
    # Keep Python store-and-forward buffers and JVM temporary files on the
    # worker's real filesystem. Never inherit a possibly memory-backed /tmp.
    if [[ -e "$run_dir" ]]; then
        echo "Refusing to reuse existing diagnostic artifacts: $run_dir" >&2
        overall_rc=2
        stop_reason="existing_artifacts"
        break
    fi
    mkdir -p "$run_dir/tmp"

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
        server_pid="$(sed -n '1p' "$server_pid_file")"
        if [[ "$FS_TRACE" == "1" ]]; then
            # Only the tracing replica pays continuous syscall-tracing cost.
            # shellcheck disable=SC2024
            sudo -n fs_usage -w -f filesys "$server_pid" \
                >"$run_dir/fs-usage.log" 2>&1 &
            fs_usage_pid=$!
            echo "$fs_usage_pid" >"$trace_pid_file"
            sleep 1
            if ! sudo -n kill -0 "$fs_usage_pid" 2>/dev/null; then
                touch "$run_dir/fs-usage-helper-exited"
            fi
        fi
        python3 system_test/qwp_ws_watchdog.py --run-dir "$run_dir" \
            >"$run_dir/watchdog-process.log" 2>&1 &
        watchdog_pid=$!
        echo "$watchdog_pid" >"$watchdog_pid_file"
        for _ in $(seq 1 50); do
            [[ -f "$run_dir/watchdog-ready" ]] && break
            kill -0 "$watchdog_pid" 2>/dev/null || break
            sleep 0.1
        done
        if [[ ! -f "$run_dir/watchdog-ready" ]]; then
            touch "$run_dir/watchdog-helper-failed"
        fi
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
    QWP_WS_FUZZ_PID_FILE="$server_pid_file" \
    QWP_WS_FUZZ_WATCHDOG_DIR="$run_dir" \
    TMPDIR="$run_dir/tmp" \
        python3 system_test/test.py run --repo ./questdb \
            TestQwpWsFuzz.test_add_columns -v \
            2>&1 | tee -a "$DIAG_DIR/test.log" "$run_dir/test.log"
    test_status=("${PIPESTATUS[@]}")
    test_rc=${test_status[0]}
    if [[ "${test_status[1]}" -ne 0 && "$test_rc" -eq 0 ]]; then
        test_rc=2
    fi
    if [[ ! -f "$run_dir/workload-finished" ||
          -f "$run_dir/watchdog-helper-failed" ||
          ! -s "$run_dir/heartbeat.jsonl" ||
          ! -s "$run_dir/jvm-pauses.log" ||
          -f "$run_dir/capture-error" ]]; then
        echo "Incomplete onset diagnostics; inspect run=$run_number artifacts" \
            | tee -a "$DIAG_DIR/test.log"
        [[ "$test_rc" -ne 0 ]] || test_rc=2
    fi
    if [[ "$test_rc" -eq 0 && \
          -f "$run_dir/memory-pressure-helper-exited" ]]; then
        echo "memory_pressure exited before the diagnostic gate" \
            | tee -a "$DIAG_DIR/test.log"
        test_rc=2
    fi
    if [[ "$test_rc" -eq 0 && \
          -f "$run_dir/fs-usage-helper-exited" ]]; then
        echo "fs_usage exited before the diagnostic gate" \
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
    # The watchdog normally exits after the workload-finished marker. Allow
    # its in-flight probe to return, then detect an unexpected helper death.
    for _ in $(seq 1 20); do
        [[ -f "$run_dir/watchdog-stopped" ]] && break
        sleep 0.1
    done
    if [[ ! -f "$run_dir/watchdog-stopped" ]] ||
            ! grep -q '"event": "workload_finished"' "$run_dir/watchdog.jsonl"; then
        echo "Watchdog did not observe workload completion" | tee -a "$DIAG_DIR/test.log"
        [[ "$test_rc" -ne 0 ]] || test_rc=2
    fi
    stop_watchdog
    stop_trace
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
    cp build/questdb/repo/data/conf/server.conf "$run_dir/server.conf" || true

    echo "=== run=$run_number rc=$test_rc "\
         "finished=$(date -u '+%Y-%m-%dT%H:%M:%SZ') ===" \
        | tee -a "$DIAG_DIR/test.log"

    python3 ci/summarize_qwp_ws_run.py "$run_dir" \
        --run "$run_number" --started "$run_epoch" \
        --duration "$((SECONDS - run_started))" \
        --soak-elapsed "$((SECONDS - soak_started))" \
        --free-kb "$free_kb" --returncode "$test_rc" \
        | tee -a "$DIAG_DIR/runs.jsonl"
    summary_status=("${PIPESTATUS[@]}")
    if [[ ( "${summary_status[0]}" -ne 0 || "${summary_status[1]}" -ne 0 ) && "$test_rc" -eq 0 ]]; then
        test_rc=2
    fi

    if [[ "$test_rc" -ne 0 ]]; then
        overall_rc="$test_rc"
        stop_reason="test_or_diagnostic_failure"
        break
    fi
    if [[ -f "$run_dir/capture-started" ]]; then
        echo "Onset captured; test passed; stop_on_capture=$STOP_ON_CAPTURE" \
            | tee -a "$DIAG_DIR/test.log"
        if [[ "$STOP_ON_CAPTURE" == "1" ]]; then
            stop_reason="onset_capture"
            break
        fi
    fi
done

echo "=== soak stop=$stop_reason elapsed_seconds=$((SECONDS - soak_started)) rc=$overall_rc ===" \
    | tee -a "$DIAG_DIR/test.log"
snapshot_host after
exit "$overall_rc"
