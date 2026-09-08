# Focused SHOW COLUMNS stage probe

Purpose: locate loss of progress in the original slow metadata query, not treat
later short ping stalls as a reproduction. No production fix or timeout change.

`prepare.py` reads one source file from server revision
`12a33d651e51e2682e7a448c8db5168fc72dfad3` using git show, checks each replacement
anchor occurs exactly once, and compiles an isolated `--patch-module io.questdb`
JAR against the built server. It preserves source/JAR hashes and patched source
in the output directory. No server checkout files are changed. Compilation uses
the pinned server's JetBrains annotations 17.0.0 dependency from Maven's cache.
The overlay deliberately has no manifest: a generated manifest shadows the
server's build metadata under --patch-module. The smoke test requires the
original version/commit and identical build() results with and without the patch.

Only `QWP_WS_SHOW_COLUMNS_OVERLAY` plus the existing diagnostic fixture gates
activate it. The normal product/test configuration is unchanged. The observer
requires `-Dqwp.show.columns.dir=RUN_DIR`, supplied by the fixture. Overlay output,
runtime temporary files and test data stay on the workspace filesystem.

## Interpretation

TSV fields: wall milliseconds, monotonic nanoseconds, local query ID, Java thread
ID, thread name, table, stage, elapsed nanoseconds since cursor entry. Query IDs
are probe-local, not QueryProgress IDs. Correlate table and wall time with server
logs. Java thread IDs are not native thread IDs; JVM dumps contain both.

`stage` denotes an operation about to run, not its completion. `cursor-ready`
means initialization and resource releases finished. `iteration-breaker` persists
while rows are emitted or response sending is suspended; a long duration there
does not prove the timeout-check method itself blocked. Repeated identical
iteration stages on the same thread are suppressed. `reader-close` also covers
the subsequent metadata-lock release. Exceptions retain their original behavior.

At five seconds active, the observer records a marker once per JVM; the external
watchdog samples native/JVM stacks. Do not interpret post-trigger samples as the
entire preceding interval. Normal queries perform no diagnostic file I/O on the
request worker. There is still allocation/queue overhead; this is not a zero-cost
observer. The queue is bounded to 8192 records and loss is explicitly rejected.

The observer is a JVM daemon and can be paused with the JVM. Its file writes can
also block. Missing telemetry is a diagnostic failure, not a healthy result.
After first observing telemetry, the external watchdog also captures when the
TSV stops advancing for five seconds, even without a Java slow-query marker.
This detects loss of observer progress, not its cause: JVM suspension, observer
scheduling, and blocked diagnostic file output remain distinguishable suspects.
It does not cover a pause before the helper first publishes data, and cannot
capture during a host-wide pause that prevents the watchdog itself from running.
Isolated one-second ping failures still do not trigger this arm.
The harness retains independent Python heartbeat and JVM pause logs. An exe log
without cursor-enter can indicate delay before the probe, or lost/delayed
telemetry; it is not evidence of a metadata lock wait.

## Local validation

No Mac or additional CI worker is needed to validate the probe:

```sh
mkdir -p build-exp/show-columns-test-tmp
TMPDIR="$PWD/build-exp/show-columns-test-tmp" PYTHONDONTWRITEBYTECODE=1 \
  python3 -m unittest discover -s ci/diagnostics/show_columns -p 'test_*.py'
python3 ci/diagnostics/show_columns/prepare.py \
  --repo /path/to/questdb --jar /path/to/questdb/core/target/questdb-10.0.2-SNAPSHOT.jar \
  --output build-exp/query-probe
PYTHONDONTWRITEBYTECODE=1 python3 ci/diagnostics/show_columns/smoke.py \
  --jar /path/to/questdb/core/target/questdb-10.0.2-SNAPSHOT.jar \
  --overlay build-exp/query-probe/show-columns-probe.jar \
  --output build-exp/query-smoke
```

Choose fresh output directories. The smoke launches and stops a baseline and
an overlaid server on loopback, restricts JVM sizing and Linux CPU affinity to
three CPUs, compares SQL results, and requires all normal stages. ProbeTest.java
injects a delay into a standalone helper test; it is never packaged in the
server overlay or used in CI's fuzz workload.

Validated locally: baseline/overlay SQL results identical for repeated SHOW
COLUMNS and after ADD COLUMN; all expected stages recorded; no false slow
trigger. Standalone six-second delay triggers at the expected stage, and fast
completion and exception completion are retained. These validate instrumentation,
not the original macOS failure or performance equivalence.

Build 268391 exposed the generated-manifest problem before any fuzz test ran.
The strengthened smoke reproduces that failure with the old overlay and passes
with the manifest-free overlay. Its result is not a server-stall reproduction.
