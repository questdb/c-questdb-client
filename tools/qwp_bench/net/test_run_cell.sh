#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
SUBJECT="$SCRIPT_DIR/run_cell.sh"
TEST_ROOT=$(mktemp -d)
trap 'rm -rf -- "$TEST_ROOT"' EXIT

FAILURES=0
LAST_CASE_DIR=""
LAST_LABEL=""
LAST_RESULT_FILE=""
LAST_STATUS=0

record_failure() {
    echo "FAIL: $*" >&2
    FAILURES=$((FAILURES + 1))
}

make_case() {
    case_name=$1
    LAST_CASE_DIR="$TEST_ROOT/$case_name"
    mkdir -p "$LAST_CASE_DIR/bin"
    cp "$SUBJECT" "$LAST_CASE_DIR/run_cell.sh"

    cat > "$LAST_CASE_DIR/env.sh" <<'EOF'
QNB_AWS_PROFILE=test
QNB_AWS_REGION=eu-west-1
QNB_INSTANCE_TYPE=c8gn.2xlarge
QNB_QUESTDB_COMMIT=1111111111111111111111111111111111111111
QNB_C_CLIENT_REPO=https://example.invalid/c.git
QNB_C_CLIENT_COMMIT=2222222222222222222222222222222222222222
QNB_JAVA_CLIENT_REPO=https://example.invalid/java.git
QNB_JAVA_CLIENT_COMMIT=3333333333333333333333333333333333333333
QNB_PY_CLIENT_REPO=https://example.invalid/py.git
QNB_PY_CLIENT_COMMIT=4444444444444444444444444444444444444444

qnb_resolve_commit() { printf '%s\n' "$2"; }
qnb_instance_id() { printf 'i-%s\n' "$1"; }
qnb_private_ip() { printf '127.0.0.1\n'; }
qnb_bucket() { printf 'test-bucket\n'; }
EOF

    cat > "$LAST_CASE_DIR/ssmx.sh" <<'EOF'
#!/usr/bin/env bash
set -u
printf '%s\n' "$*" >> "$QNB_TEST_TRACE"
if [ "${1:-}" = run ] && [ "${2:-}" = client ]; then
    command_text=${3:-}
    case "$command_text" in
        *"cargo run"*|*"/opt/qwp-bench/c-questdb-client/build/qwp_"*|*"qwp-bench-java.jar"*)
            before_tail=${command_text%%tail -5*}
            case "$before_tail" in
                *'bench_status=$?'*) ;;
                *) echo "bench status is not captured before tail" >&2; exit 90 ;;
            esac
            case "$command_text" in
                *'exit $bench_status'*) ;;
                *) echo "saved bench status is not returned" >&2; exit 91 ;;
            esac
            exit "${MOCK_BENCH_STATUS:-0}"
            ;;
    esac
fi
exit 0
EOF

    cat > "$LAST_CASE_DIR/bin/aws" <<'EOF'
#!/usr/bin/env bash
set -u
if [ "${1:-}" = s3 ] && [ "${2:-}" = cp ] \
        && [ "${3:-}" = --recursive ] \
        && [[ "${4:-}" == s3://* ]] \
        && [[ "${5:-}" != s3://* ]]; then
    destination=$5
    mkdir -p "$destination"
    case "${MOCK_JSON_KIND:-object}" in
        object) printf '{}\n' > "$destination/$MOCK_RESULT_FILE" ;;
        malformed) printf '{' > "$destination/$MOCK_RESULT_FILE" ;;
        empty) : > "$destination/$MOCK_RESULT_FILE" ;;
        array) printf '[]\n' > "$destination/$MOCK_RESULT_FILE" ;;
        missing) ;;
        *) echo "unknown MOCK_JSON_KIND=$MOCK_JSON_KIND" >&2; exit 80 ;;
    esac
fi
exit 0
EOF

    cat > "$LAST_CASE_DIR/bin/jq" <<'EOF'
#!/usr/bin/env bash
set -u
if [ "${1:-}" = "-e" ]; then
    python3 - "$3" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as handle:
    value = json.load(handle)
raise SystemExit(0 if isinstance(value, dict) else 1)
PY
    status=$?
    exit "$status"
fi
if [ "${1:-}" = "-n" ]; then
    printf '{}\n'
    exit 0
fi
exit 2
EOF

    chmod +x "$LAST_CASE_DIR/run_cell.sh" "$LAST_CASE_DIR/ssmx.sh" \
        "$LAST_CASE_DIR/bin/aws" "$LAST_CASE_DIR/bin/jq"
    : > "$LAST_CASE_DIR/trace"
}

run_cell_case() {
    case_name=$1
    bench_status=$2
    json_kind=$3
    client_kind=$4
    direction=$5
    shift 5

    make_case "$case_name"
    LAST_LABEL=$case_name
    LAST_RESULT_FILE="$client_kind-$direction.json"
    MOCK_RESULT_FILE="$LAST_RESULT_FILE" \
    MOCK_BENCH_STATUS=$bench_status \
    MOCK_JSON_KIND=$json_kind \
    QNB_TEST_TRACE="$LAST_CASE_DIR/trace" \
    PATH="$LAST_CASE_DIR/bin:${PATH:-/usr/bin:/bin}" \
        "$LAST_CASE_DIR/run_cell.sh" \
            --label "$LAST_LABEL" \
            --client "$client_kind" \
            --direction "$direction" \
            "$@" > "$LAST_CASE_DIR/output" 2>&1
    LAST_STATUS=$?
}

assert_status() {
    case_name=$1
    expected=$2
    if [ "$LAST_STATUS" -ne "$expected" ]; then
        record_failure "$case_name: expected status $expected, got $LAST_STATUS"
    fi
}

assert_nonzero_status() {
    case_name=$1
    if [ "$LAST_STATUS" -eq 0 ]; then
        record_failure "$case_name: expected nonzero status, got 0"
    fi
}

assert_trace_contains() {
    case_name=$1
    pattern=$2
    if ! grep -F -- "$pattern" "$LAST_CASE_DIR/trace" >/dev/null; then
        record_failure "$case_name: trace does not contain: $pattern"
    fi
}

assert_output_contains() {
    case_name=$1
    pattern=$2
    if ! grep -F -- "$pattern" "$LAST_CASE_DIR/output" >/dev/null; then
        record_failure "$case_name: output does not contain: $pattern"
    fi
}

assert_failed_bench_diagnostics() {
    case_name=$1
    for box in server client; do
        assert_trace_contains "$case_name" \
            "sar -f /var/tmp/qwp-results/$LAST_LABEL/sar-$box.bin -u"
        assert_trace_contains "$case_name" \
            "sar -f /var/tmp/qwp-results/$LAST_LABEL/sar-$box.bin -n DEV"
    done
    assert_trace_contains "$case_name" \
        "aws s3 cp --recursive /var/tmp/qwp-results/$LAST_LABEL s3://test-bucket/results/$LAST_LABEL/"
    if [ ! -f "$LAST_CASE_DIR/results/$LAST_LABEL/$LAST_RESULT_FILE" ]; then
        record_failure "$case_name: collected result $LAST_RESULT_FILE was not created"
    fi
    if [ ! -f "$LAST_CASE_DIR/results/$LAST_LABEL/cell.json" ]; then
        record_failure "$case_name: results/$LAST_LABEL/cell.json was not created"
    fi
    assert_output_contains "$case_name" "== done: results/$LAST_LABEL"
    assert_output_contains "$case_name" "cell.json"
}

run_cell_case valid-rust-ingress 0 object rust ingress
assert_status "valid Rust ingress" 0

run_cell_case failed-rust-ingress 23 object rust ingress
assert_status "failed Rust ingress" 23
assert_failed_bench_diagnostics "failed Rust ingress"

run_cell_case missing-result 0 missing rust ingress
assert_nonzero_status "missing result"

run_cell_case empty-result 0 empty rust ingress
assert_nonzero_status "empty result"

run_cell_case malformed-result 0 malformed rust ingress
assert_nonzero_status "malformed result"

run_cell_case non-object-result 0 array rust ingress
assert_nonzero_status "non-object result"

run_cell_case failed-bench-malformed-json 23 malformed rust ingress
assert_status "bench failure plus malformed JSON" 23
assert_failed_bench_diagnostics "bench failure plus malformed JSON"

run_cell_case dispatch-rust-ingress 0 object rust ingress
assert_status "rust ingress dispatch" 0
assert_trace_contains "rust ingress dispatch" "--example qwp_ingress_polars"

run_cell_case dispatch-rust-egress 0 object rust egress
assert_status "rust egress dispatch" 0
assert_trace_contains "rust egress dispatch" "--example qwp_egress_polars"

run_cell_case dispatch-rust-row-ingress 0 object rust-row ingress
assert_status "rust-row ingress dispatch" 0
assert_trace_contains "rust-row ingress dispatch" "--example qwp_ingress_row"

run_cell_case dispatch-c-ingress 0 object c ingress
assert_status "c ingress dispatch" 0
assert_trace_contains "c ingress dispatch" \
    "/opt/qwp-bench/c-questdb-client/build/qwp_ingress_c"

run_cell_case dispatch-c-egress 0 object c egress
assert_status "c egress dispatch" 0
assert_trace_contains "c egress dispatch" \
    "/opt/qwp-bench/c-questdb-client/build/qwp_egress_c"

run_cell_case dispatch-java-ingress 0 object java ingress
assert_status "java ingress dispatch" 0
assert_trace_contains "java ingress dispatch" "qwp-bench-java.jar ingress"
assert_trace_contains "java ingress dispatch" \
    "JAVA_HOME=/usr/lib/jvm/java-25-openjdk-arm64"

run_cell_case dispatch-java-egress 0 object java egress
assert_status "java egress dispatch" 0
assert_trace_contains "java egress dispatch" "qwp-bench-java.jar egress"
assert_trace_contains "java egress dispatch" \
    "JAVA_HOME=/usr/lib/jvm/java-25-openjdk-arm64"

run_cell_case forwarded-environment 0 object rust ingress \
    --schema s2-wide \
    --rows 123 \
    --iterations 3 \
    --warmups 1 \
    --max-batch-rows 17 \
    --senders 4 \
    --skip-populate \
    --conf-extra 'sf_append_deadline_millis=300000;'
assert_status "forwarded environment" 0
for assignment in \
    SCHEMA=s2-wide \
    ROWS=123 \
    ITERATIONS=3 \
    WARMUPS=1 \
    MAX_BATCH_ROWS=17 \
    QDB_HOST=127.0.0.1 \
    QDB_PORT=9000 \
    SENDERS=4 \
    SKIP_POPULATE=1 \
    "QDB_CONF_EXTRA='sf_append_deadline_millis=300000;'"
do
    assert_trace_contains "forwarded environment" "$assignment"
done

run_cell_case rust-row-egress 0 object rust-row egress
assert_nonzero_status "rust-row egress"
if grep -E 'cargo run|/opt/qwp-bench/c-questdb-client/build/qwp_|qwp-bench-java.jar' \
        "$LAST_CASE_DIR/trace" >/dev/null; then
    record_failure "rust-row egress: benchmark command was invoked"
fi

if [ "$FAILURES" -ne 0 ]; then
    echo "test_run_cell.sh: $FAILURES failure(s)" >&2
    exit 1
fi

echo "test_run_cell.sh: OK"
