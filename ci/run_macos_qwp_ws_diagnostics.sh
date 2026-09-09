#!/usr/bin/env bash

# Reproduce TestQwpWsFuzz.test_add_columns on the hosted macOS arm64 image
# while preserving enough host evidence to distinguish VM pressure from a
# filesystem stall. This is intentionally a diagnostic harness, not a general
# test runner.

set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly ROOT_DIR
readonly DIAG_DIR="${QWP_WS_DIAGNOSTICS_DIR:?QWP_WS_DIAGNOSTICS_DIR is required}"
readonly PRESSURE_PLAN="${QWP_WS_MEMORY_PRESSURE:-natural}"
readonly RUN_COUNT="${QWP_WS_DIAGNOSTIC_RUNS:-3}"
readonly FUZZ_SEED="0x268579c36b106b74"
readonly BUILD_MODE_SEED="7856154056746654427"
readonly SERVER_REVISION="12a33d651e51e2682e7a448c8db5168fc72dfad3"
readonly FS_TRACE="${QWP_WS_FS_TRACE:-0}"
readonly STOP_ON_CAPTURE="${QWP_WS_STOP_ON_CAPTURE:-1}"
readonly MAX_SECONDS="${QWP_WS_MAX_SECONDS:-1200}"
readonly MIN_FREE_KB="${QWP_WS_MIN_FREE_KB:-2097152}"
readonly SYSTEM_TRACE="${QWP_WS_SYSTEM_TRACE:-0}"
readonly QUERY_OVERLAY="${QWP_WS_SHOW_COLUMNS_OVERLAY:-}"
readonly DISK_LOAD="${QWP_WS_DISK_LOAD:-0}"
readonly DISK_PATTERN="${QWP_WS_DISK_PATTERN:-pwrite}"
readonly KERNEL_CAPTURE="${QWP_WS_KERNEL_CAPTURE:-off}"
readonly QUERY_READER="${QWP_WS_QUERY_READER:-0}"
readonly DISK_MODE="${QWP_WS_DISK_MODE:-paired}"

if [[ ! "$RUN_COUNT" =~ ^[1-9][0-9]*$ ||
      ! "$MAX_SECONDS" =~ ^[1-9][0-9]*$ ||
      ! "$MIN_FREE_KB" =~ ^[1-9][0-9]*$ ||
      ( "$DISK_LOAD" != "0" && "$DISK_LOAD" != "1" ) ||
      ( "$QUERY_READER" != "0" && "$QUERY_READER" != "1" ) ||
      ( "$DISK_MODE" != "paired" && "$DISK_MODE" != "probe" ) ||
      ( "$SYSTEM_TRACE" != "0" && "$SYSTEM_TRACE" != "1" ) ||
      ( "$STOP_ON_CAPTURE" != "0" && "$STOP_ON_CAPTURE" != "1" ) ]]; then
    echo "Invalid repetition, time, disk-space or capture-stop setting" >&2
    exit 2
fi

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "This diagnostic harness must run on macOS." >&2
    exit 2
fi

if [[ "$PRESSURE_PLAN" != "natural" && "$PRESSURE_PLAN" != "warn" && "$PRESSURE_PLAN" != "paired" ]]; then
    echo "Unsupported QWP_WS_MEMORY_PRESSURE=$PRESSURE_PLAN" >&2
    exit 2
fi

if [[ "$FS_TRACE" != "0" && "$FS_TRACE" != "1" ]]; then
    echo "Unsupported QWP_WS_FS_TRACE=$FS_TRACE" >&2
    exit 2
fi

if [[ "$KERNEL_CAPTURE" != "off" && "$KERNEL_CAPTURE" != "query" && "$KERNEL_CAPTURE" != "ping" ]]; then
    echo "Unsupported QWP_WS_KERNEL_CAPTURE=$KERNEL_CAPTURE" >&2
    exit 2
fi
if [[ "$KERNEL_CAPTURE" != "off" && -z "$QUERY_OVERLAY" ]]; then
    echo "Kernel follow-up requires query-stage telemetry" >&2
    exit 2
fi
if [[ "$DISK_PATTERN" != "pwrite" && "$DISK_PATTERN" != "mapped" ]]; then
    echo "Unsupported QWP_WS_DISK_PATTERN=$DISK_PATTERN" >&2
    exit 2
fi

cd "$ROOT_DIR" || exit 2
if [[ "$QUERY_READER" == "1" && -z "$QUERY_OVERLAY" ]]; then
    echo "Query reader requires query-stage telemetry" >&2
    exit 2
fi
if [[ "$DISK_LOAD" == "1" && ( -z "$QUERY_OVERLAY" || "$PRESSURE_PLAN" != "natural" ) ]]; then
    echo "Disk experiment requires query overlay and natural memory" >&2
    exit 2
fi
if [[ -n "$QUERY_OVERLAY" && ( ! -s "$QUERY_OVERLAY" || "$SYSTEM_TRACE" != "0" ) ]]; then
    echo "SHOW COLUMNS requires a compiled overlay and no System Trace" >&2
    exit 2
fi
mkdir -p "$DIAG_DIR"
if [[ "$SYSTEM_TRACE" == "1" &&
      ( ! -s "$DIAG_DIR/preflight/system-trace-valid.json" ||
        -e "$DIAG_DIR/preflight/system-trace-error.json" ||
        "$FS_TRACE" != "0" || "$PRESSURE_PLAN" != "natural" ) ]]; then
    echo "System Trace requires a successful preflight, no fs_usage and natural memory" >&2
    exit 2
fi
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

if [[ "$KERNEL_CAPTURE" != "off" ]]; then
    # Fetch once before workload/monitor gates, never during onset capture.
    python3 ci/diagnostics/decode_kernel_capture.py \
        "$DIAG_DIR/kernel-symbols" --symbols-only || exit 2
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
        sysctl kern.memorystatus_vm_pressure_level || true
        memory_pressure || true
        diskutil info / || true
        df -h /
        ulimit -a
        java -version
        git rev-parse HEAD
        git -C questdb rev-parse HEAD
        echo "fs_trace=$FS_TRACE server_revision=$SERVER_REVISION"
        echo "runs=$RUN_COUNT max_seconds=$MAX_SECONDS stop_on_capture=$STOP_ON_CAPTURE"
        echo "pressure_plan=$PRESSURE_PLAN"
        echo "startup_missing_lookups=${QWP_WS_STARTUP_LOOKUPS:-0}"
        echo "disk_load=$DISK_LOAD paired_order=probe,load,load,probe max_write_bytes_per_attempt=268435456"
        echo "disk_pattern=$DISK_PATTERN mapped_max_file_bytes=1048576 mapped_load_pacing_seconds=0.01"
        echo "min_free_kb=$MIN_FREE_KB"
        echo "system_trace=$SYSTEM_TRACE trace_capture_limit=2 controls=1,6,11"
        echo "kernel_capture=$KERNEL_CAPTURE ping_trigger_consecutive_failures=2 memory_heartbeat=1"
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
        sysctl kern.memorystatus_vm_pressure_level || true
        ps -axo pid,ppid,rss,vsz,%cpu,state,etime,command || true
        sleep 5
    done
) >"$DIAG_DIR/memory-and-processes.log" 2>&1 &
monitor_pids+=("$!")

overall_rc=0
soak_started=$SECONDS
stop_reason="run_limit"
trace_captures=0
for run_number in $(seq 1 "$RUN_COUNT"); do
    PRESSURE_MODE="$(python3 system_test/qwp_ws_pressure.py mode "$PRESSURE_PLAN" "$run_number")" || exit 2
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
    system_trace_pid_file="$run_dir/system-trace-helper.pid"
    traced=0
    if [[ "$SYSTEM_TRACE" == "1" && "$run_number" != "1" &&
          "$run_number" != "6" && "$run_number" != "11" ]]; then
        traced=1
    fi
    # Keep Python store-and-forward buffers and JVM temporary files on the
    # worker's real filesystem. Never inherit a possibly memory-backed /tmp.
    if [[ -e "$run_dir" ]]; then
        echo "Refusing to reuse existing diagnostic artifacts: $run_dir" >&2
        overall_rc=2
        stop_reason="existing_artifacts"
        break
    fi
    mkdir -p "$run_dir/tmp"
    touch "$run_dir/memory-heartbeat-enabled"
    [[ "$QUERY_READER" != "1" ]] || touch "$run_dir/query-reader-enabled"
    [[ "$traced" == "0" ]] || touch "$run_dir/system-trace-enabled"
    if [[ "$KERNEL_CAPTURE" != "off" ]]; then
        touch "$run_dir/kernel-stacks-enabled"
        [[ "$KERNEL_CAPTURE" != "ping" ]] || touch "$run_dir/kernel-ping-capture-enabled"
    fi

    echo "=== run=$run_number pressure=$PRESSURE_MODE seed=$FUZZ_SEED "\
         "build_mode_seed=$BUILD_MODE_SEED "\
         "system_trace=$traced started=$(date -u '+%Y-%m-%dT%H:%M:%SZ') ===" \
        | tee -a "$DIAG_DIR/test.log"

    # The test process creates ready_file after QuestDB is accepting requests
    # but before it starts the selected unittest. In the pressure arm, hold it
    # at that barrier until the paired arm verifies the actual kernel state.
    (
        system_trace_pid=""
        disk_load_pid=""
        # This shell is the parent of sudo/collector. On setup failure or
        # cancellation, signal that exact child and wait for it to reap xctrace.
        # shellcheck disable=SC2329
        stop_controller_trace() {
            if [[ -n "$disk_load_pid" ]]; then
                kill -TERM "$disk_load_pid" 2>/dev/null || true
                wait "$disk_load_pid" 2>/dev/null || true
            fi
            if [[ -n "$system_trace_pid" ]]; then
                sudo -n kill -TERM "$system_trace_pid" 2>/dev/null || true
                wait "$system_trace_pid" 2>/dev/null || true
            fi
        }
        trap stop_controller_trace EXIT
        trap 'exit 130' INT
        trap 'exit 143' TERM
        while [[ ! -f "$ready_file" ]]; do
            sleep 0.1
        done
        server_pid="$(sed -n '1p' "$server_pid_file")"
        if [[ "$traced" == "1" ]]; then
            # Redirection deliberately belongs to the unprivileged uploader.
            # shellcheck disable=SC2024
            sudo -n env TMPDIR="$run_dir/tmp" "$(command -v python3)" \
                system_test/qwp_ws_system_trace.py collect --run-dir "$run_dir" \
                --pid "$server_pid" >"$run_dir/system-trace-helper.log" 2>&1 &
            system_trace_pid=$!
            echo "$system_trace_pid" >"$system_trace_pid_file"
            # Recorder startup allows 60s; the traced fixture setup gate allows
            # 90s. Leave time for watchdog startup and the host snapshot.
            for _ in $(seq 1 700); do
                [[ -f "$run_dir/system-trace-ready.json" ]] && break
                kill -0 "$system_trace_pid" 2>/dev/null || break
                [[ ! -f "$run_dir/system-trace-error.json" ]] || break
                sleep 0.1
            done
            if [[ ! -f "$run_dir/system-trace-ready.json" ||
                  -f "$run_dir/system-trace-error.json" ]]; then
                touch "$run_dir/watchdog-helper-failed"
                # Never release an unobserved workload; test setup will report
                # its existing gate timeout, and artifacts explain the cause.
                exit 2
            fi
        fi
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
        if [[ "$PRESSURE_PLAN" == "paired" ]]; then
            # The previous allocator has been stopped. Require recovery before
            # creating the next one; memory_pressure exits if already at warn.
            if ! python3 system_test/qwp_ws_pressure.py gate natural \
                    >"$run_dir/pressure-recovery.jsonl" 2>"$run_dir/pressure-recovery-error.log"; then
                touch "$run_dir/pressure-target-not-reached"
                exit 2
            fi
        fi
        if [[ "$PRESSURE_MODE" == "warn" ]]; then
            memory_pressure -l warn -s 1 \
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
        if [[ "$PRESSURE_PLAN" == "paired" ]]; then
            pressure_gate_args=(gate "$PRESSURE_MODE" --timeout 45)
            if [[ "$PRESSURE_MODE" == "warn" ]]; then
                pressure_gate_args+=(--pid "$pressure_pid")
            fi
            if ! python3 system_test/qwp_ws_pressure.py "${pressure_gate_args[@]}" \
                    >"$run_dir/pressure-gate.jsonl" 2>"$run_dir/pressure-gate-error.log"; then
                touch "$run_dir/pressure-target-not-reached"
                # Do not release a workload under a falsely labelled condition.
                # Paired pressure setup has a separate 90-second gate budget.
                exit 2
            fi
        fi
        {
            date -u '+%Y-%m-%dT%H:%M:%SZ'
            memory_pressure || true
            sysctl vm.swapusage || true
            sysctl kern.memorystatus_vm_pressure_level || true
            vm_stat || true
        } >"$run_dir/pressure-at-gate.log" 2>&1
        if [[ "$DISK_LOAD" == "1" ]]; then
            TMPDIR="$run_dir/tmp" python3 system_test/qwp_ws_disk_load.py \
                "$run_dir" --run "$run_number" --pattern "$DISK_PATTERN" --mode "$DISK_MODE" >"$run_dir/disk-load-process.log" 2>&1 &
            disk_load_pid=$!
            for _ in $(seq 1 50); do
                [[ -f "$run_dir/disk-load-ready" ]] && break
                kill -0 "$disk_load_pid" 2>/dev/null || break
                sleep 0.1
            done
            if [[ ! -f "$run_dir/disk-load-ready" || -f "$run_dir/disk-load-error" ]]; then
                exit 2
            fi
        fi
        touch "$go_file"
        if [[ -n "$disk_load_pid" ]]; then
            wait "$disk_load_pid"
            disk_rc=$?
            disk_load_pid=""
            [[ "$disk_rc" -eq 0 ]] || exit "$disk_rc"
        fi
        if [[ "$traced" == "1" ]]; then
            wait "$system_trace_pid"
            trace_rc=$?
            system_trace_pid=""
            exit "$trace_rc"
        fi
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
    if [[ -n "$QUERY_OVERLAY" ]]; then
        if ! python3 ci/diagnostics/show_columns/validate.py "$run_dir"; then
            echo "Invalid SHOW COLUMNS telemetry" | tee -a "$DIAG_DIR/test.log"
            [[ "$test_rc" -ne 0 ]] || test_rc=2
        fi
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
        sysctl kern.memorystatus_vm_pressure_level || true
        vm_stat || true
    } >"$run_dir/pressure-after-test.log" 2>&1

    if [[ ! -f "$go_file" ]]; then
        kill "$controller_pid" 2>/dev/null || true
    fi
    if ! wait "$controller_pid"; then
        echo "Diagnostic controller failed; inspect run=$run_number" | tee -a "$DIAG_DIR/test.log"
        [[ "$test_rc" -ne 0 ]] || test_rc=2
    fi
    controller_pid=""
    if [[ "$DISK_LOAD" == "1" &&
          ( ! -f "$run_dir/disk-load-finished" || -f "$run_dir/disk-load-error" ) ]]; then
        echo "Missing or failed filesystem load telemetry" | tee -a "$DIAG_DIR/test.log"
        [[ "$test_rc" -ne 0 ]] || test_rc=2
    fi
    if [[ "$traced" == "1" &&
          ( ! -s "$run_dir/system-trace-valid.json" ||
            -f "$run_dir/system-trace-error.json" ) ]]; then
        echo "Missing or invalid System Trace; refusing a green result" | tee -a "$DIAG_DIR/test.log"
        [[ "$test_rc" -ne 0 ]] || test_rc=2
    fi
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
    if [[ "$QUERY_READER" == "1" ]] &&
            { ! grep -q '"event": "query_start"' "$run_dir/query-reader.jsonl" ||
              ! grep -q '"event": "stopped"' "$run_dir/query-reader.jsonl"; }; then
        echo "Query reader had no overlap or incomplete telemetry" | tee -a "$DIAG_DIR/test.log"
        [[ "$test_rc" -ne 0 ]] || test_rc=2
    fi
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

    # Decode only after the test and server shutdown. Keep the raw capture
    # even when symbol processing times out; do not rerun the workload for it.
    if [[ -s "$run_dir/kernel-stacks/spindump.raw" ]]; then
        # The watchdog creates this directory as the runner; log ownership
        # deliberately stays with the runner, not the privileged decoder.
        # shellcheck disable=SC2024
        if ! sudo -n env TMPDIR="$run_dir/kernel-stacks/tmp" \
                python3 ci/diagnostics/kernel_wait_preflight.py \
                "$run_dir/kernel-stacks" --decode \
                --symbols "$DIAG_DIR/kernel-symbols/symbols.spindump" \
                >"$run_dir/kernel-stacks/decode.log" 2>&1; then
            echo "Kernel decode failed; raw capture retained" | tee -a "$DIAG_DIR/test.log"
            [[ "$test_rc" -ne 0 ]] || test_rc=2
        fi
    fi

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
        if [[ "$traced" == "1" ]]; then
            trace_captures=$((trace_captures + 1))
            if (( trace_captures >= 2 )); then
                stop_reason="two_system_trace_captures"
                break
            fi
        fi
        echo "Onset captured; test passed; stop_on_capture=$STOP_ON_CAPTURE" \
            | tee -a "$DIAG_DIR/test.log"
        if [[ "$STOP_ON_CAPTURE" == "1" ]]; then
            stop_reason="onset_capture"
            break
        fi
    fi
done

echo "=== soak stop=$stop_reason elapsed_seconds=$((SECONDS - soak_started)) "\
     "system_trace_captures=$trace_captures rc=$overall_rc ===" \
    | tee -a "$DIAG_DIR/test.log"
snapshot_host after
exit "$overall_rc"
