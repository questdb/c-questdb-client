#!/usr/bin/env bash
# Fail before compilation if the hosted Mac cannot export useful System Trace.
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
preflight_dir="${QWP_WS_DIAGNOSTICS_DIR:?QWP_WS_DIAGNOSTICS_DIR is required}/preflight"
if [[ -e "$preflight_dir" ]]; then
    echo "Refusing to reuse preflight artifacts: $preflight_dir" >&2
    exit 2
fi
mkdir -p "$preflight_dir/tmp"
sudo -n env TMPDIR="$preflight_dir/tmp" "$(command -v python3)" \
    "$root_dir/system_test/qwp_ws_system_trace.py" preflight --run-dir "$preflight_dir"
