# QWP/WebSocket macOS stall investigation

Status: server progress interruption observed; root cause **not established**.
This branch is diagnostic only. Keep sender timeouts and correctness assertions
unchanged. Azure PR 200 allocates only one macOS worker, running only
`TestQwpWsFuzz.test_add_columns` with the focused query-stage probe below.

## Current focus: the original slow SHOW COLUMNS

Build 268363 successfully captured two short ping stalls. All three HTTP workers
spent most of each failed probe in repeated ftruncate calls, predominantly
blocked. Those captures do not establish the original 74.7-second SHOW COLUMNS
delay or the 120-second QWP close-drain failure. HTTP and O3 already use distinct
shared-network/shared-write pools in the failing revision.

The next arm replaces System Trace with an exact-source, diagnostic-only module
overlay for ShowColumnsRecordCursorFactory. Neither the server checkout nor its
JAR is edited. The overlay logs cursor entry, initial circuit-breaker check,
metadata hydration, metadata read-lock wait/acquisition, reader open, symbol
size collection, reader close, cursor-ready, iteration, and completion/error.
Query threads enqueue records in memory; one daemon writes bounded-queue
telemetry and a heartbeat. Dropped/missing telemetry fails the diagnostic arm.

An active cursor reaching five seconds requests the existing native/JVM stack
capture. Ping and heartbeat measurements remain enabled but short anomalies no
longer trigger invasive captures. Workload-error capture remains enabled. Stop
after the first capture/failure, at most 8 repetitions, no new attempt after
600 seconds, one macOS worker. Original test/sender/SQL timeouts are unchanged.

Builds 268394 and 268424 passed 40 natural-memory attempts each, with respectively
504 and 555 completed probe cursors and maxima of 137.21 and 158.25 ms. No
five-second query or observer-loss marker appeared.

Build 268431 passed its natural control, then failed pressure setup before the
second workload started: all sampled kernel pressure levels remained normal
through the 20-second gate. The allocator substantially increased compression,
but that is not a valid warning-pressure test and says nothing about the
original timeout's cause. Pressure is disabled for the next arm.

The original startup prefix is measurably different: 72 failed SHOW COLUMNS
lookups occurred during the 8.948517 seconds before the first QWP handshake.
Across all 80 attempts above, only 1..3 lookups preceded that handshake, after
28..374 ms. All recorded missing-table sequences match the seeded ALTER RNG.
Thus the same seed did not restore the original ALTER RNG position at ingestion.

Build 268433 gated producer connection until the real ALTER thread had
received 72 actual table-not-found errors. Every query, table-choice draw and
normal loop sleep still runs. No RNG is skipped or replaced. The gate has a
30-second bound and rejects unexpected lookup outcomes; it is opt-in via
`QWP_WS_STARTUP_LOOKUPS=72` and requires fuzz diagnostics. It releases producers
after lookup 72; further missing lookups may occur while they connect. Artifacts
must verify the resulting prefix. This restores a recorded scheduling prefix,
not the unknown cause of the original nine-second startup delay or the later
exact interleaving. Sender and SQL deadlines and data assertions are unchanged.
Local Linux calibration passed the full test in 7.787 seconds with three CPUs,
eight producers and the original server revision. All 72 gated table names
matched the original recorded prefix exactly. Its JDK 25.0.4 and Linux filesystem
make this a harness check, not a macOS resource-wait reproduction.

Build 268433 passed all 12 attempts: 165 completed probe cursors, maximum
185.126 ms, zero failed pings and maximum close-drain 5.446 seconds. Every gated
72-name sequence matched the original. Ten runs had exactly 72 missing lookups
before the first handshake; two had 73. No original stall was reproduced.

### Current arm: bounded filesystem work with independent call timing

The failing worker was unusually slow before QuestDB startup. The exact grpc
1.83.0 bottle took 129.437 seconds to pour versus 1.707 on a sibling Mac in the
same build; LLVM 22.1.8 took 63.427 versus 7.854 seconds. Adjacent scheduled
QWP/WS Macs used the same client/server/JVM/macOS image and poured grpc in
2.306/2.231 seconds. These are log intervals, not physical-disk measurements;
they support a pre-existing worker problem, not a particular resource cause.
Original logs: build 266336 task 79 versus 54; neighboring builds 266323 task 57
and 266352 task 62. Different neighboring fuzz seeds prevent same-workload claims.

The next eight attempts use probe/load/load/probe twice. The 72-lookup gate,
query overlay and original deadlines remain fixed; memory pressure is off.
A separate Python process repeatedly truncates its own file to zero, writes
64 KiB of pre-generated random bytes, and calls fsync. Probe arms sleep one
second between cycles; load arms do not. It starts only after SHOW COLUMNS
telemetry exists, so it does not spend its budget on the artificial startup
prefix. Each process records every call's monotonic elapsed and process CPU time.

Each attempt starts at most 4096 cycles (256 MiB written) and stops starting
cycles after 60 seconds or workload completion. Four load arms therefore write
at most 1 GiB combined. The file itself is at most 64 KiB, created exclusively
inside the attempt directory; it is retained as an artifact. No external files,
devices, mounts or quotas are modified. Existing free-space and CI time guards
remain. An in-flight kernel call can exceed the cycle deadline: that delay is
precisely what must be retained, not hidden by a timeout increase.

This is an exploratory filesystem-load perturbation, not an emulation of a
known Azure burst quota. fsync does not establish physical-media latency or
an Apple full-device flush. The control probe also performs I/O, so it is not
an untouched natural control. Compare actual syscall timing and overlap with
the query stages, independent heartbeat, CPU/memory and host I/O before drawing
conclusions. A failed/absent/no-overlap helper invalidates the attempt.

### Optional pressure arm (currently disabled)

`memory_pressure -l warn -s 1` applies real allocation pressure (no `-S`), with
one-second regulation. Before releasing each paired-plan workload, the harness
requires `kern.memorystatus_vm_pressure_level` to reach 1 (natural) or 2 (warn)
within 20 seconds. Unknown/critical levels and an unmet target fail setup; a
five-second sleep alone is not evidence that pressure was reached. Each attempt
first requires recovery to normal, so a helper cannot immediately exit because
the previous attempt left the system at warning pressure. Only this arm's
pre-workload setup gate is extended to 60 seconds; sender and SQL deadlines are
unchanged. Per-run gate samples and five-
second host samples retain the actual levels, compression and swap counters.
The helper is stopped between attempts. Post-pressure natural runs are recovery
controls, not independent cold machines: page-cache/compression carryover is a
known limitation. Stop at the first capture/failure; do not increase workers.

Apple's [memory_pressure manual](https://github.com/apple-oss-distributions/system_cmds/blob/main/memory_pressure/memory_pressure.1)
and implementation distinguish allocation mode from `-S` notification simulation.

The entry marker is inside ShowColumnsRecordCursorFactory.getCursor, after
QueryProgress's exe log: a gap between exe and cursor-enter is itself evidence
outside the instrumented cursor stages. The observer can also be delayed by a
VM/JVM/storage pause; its heartbeat is not independent of the JVM. The existing
external heartbeat and JVM safepoint logs help distinguish those cases.

See [probe implementation and validation](diagnostics/show_columns/README.md).
The recorder configuration described below is historical unless explicitly
selecting the recorder-only preflight parameter.

Local follow-up, 2026-09-08: a controlled O3 close delay demonstrated global
`FdCache` lock propagation into both WAL segment work and the serial network
dispatcher (socket acceptance/closure). Three interleaved inside-lock trials
delayed unrelated-table ACKs by six seconds; three outside-lock controls did
not. This establishes a mechanism, not the original macOS trigger. See the
[experiment, results and rerun instructions](diagnostics/fd_cache_close/README.md).

## Evidence and limits

- Original [build 266336](https://dev.azure.com/questdb/questdb/_build/results?buildId=266336):
  the test begins at 12:17:23 UTC; first reported ALTER timeout at 12:17:38.
  `SHOW COLUMNS FROM 'weather0'` executes from 12:17:51.377661 to
  12:19:06.083621, then reports a server-side timeout after 74,706 ms.
  HTTP, WAL purge and WAL-apply log activity resumes together. A producer's
  close-drain timeout follows at 12:19:44.
- The first JVM dump, headed 12:20:12, is **after failure and during DROP cleanup**:
  three HTTP workers in truncate/msync paths, two WAL-apply workers idle.
  It establishes a late software location, not the original limiting resource.
- Timing audit: QueryProgress duration uses `Os.currentTimeNanos()` backed by
  `clock_gettime(CLOCK_REALTIME)` in the pinned server; the SQL breaker uses
  `System.currentTimeMillis()`. Agreement between reported duration and log
  timestamps is not independent monotonic confirmation. Client close-drain
  deadlines use Rust `Instant`. A wall-clock adjustment alone does not explain
  the client deadline expiring; the original interval lacks paired clocks.
- The two original dump headers are 391 seconds apart, but the persistent
  Reference Handler's monotonic elapsed counters differ by 363.79 seconds.
  HotSpot samples the header before printing thread elapsed counters; stalled
  output can separate them. Do not assign all first-dump frames precisely to
  12:20:12. No original clock-adjustment or dump-output latency record exists.
- First-dump cumulative CPU: all three HTTP threads total 3941.47 ms; GC workers
  total 227.60 ms. These constrain CPU-work explanations, not off-CPU waits or
  time to reach a safepoint. They are not interval-specific measurements.
- WAL commit/ordinary ACK does not normally await O3 application. Both paths
  still share OS resources; schema changes also reconcile and roll WAL files.
  The fuzz case includes type conversions, despite its name.
- [Build 266405](https://dev.azure.com/questdb/questdb/_build/results?buildId=266405)
  passed three natural and three artificial warning-pressure attempts. This
  does **not** rule out memory pressure. Original 3.19 GiB memory accounting
  includes mappings; a recovery sample has physical RSS about 726 MiB. Original
  host pressure during the stall is unknown.
- [Build 268063](https://dev.azure.com/questdb/questdb/_build/results?buildId=268063)
  passed 40 traced attempts on two hosts. Maximum observed filesystem calls
  were below one second; some successful drains took 6–8 seconds. Neither a
  green replay nor a short syscall maximum explains the original failure.
- That replay changed **both server and JVM**: server `00de5bbb`, Temurin
  25.0.4.1, macOS 15.7.9. Original JVM dump records Temurin 25.0.3+9 and startup
  records macOS 15.7.7. The original task log 122 also prints server build hash
  `12a33d651e51e2682e7a448c8db5168fc72dfad3` (line 404, buffered build information).
  This pins the source directly, even though the clone step did not print it.
- Seeds do not pin concurrent scheduling, schema observations, or the exact
  number of conversions. Two hosts do not provide 40 independent host states.
- [Build 268075](https://dev.azure.com/questdb/questdb/_build/results?buildId=268075),
  with the original server/JVM restored, captured a short ping timeout. During
  its one-second probe, selected file calls occupied approximately 943/950/942 ms
  on the three HTTP workers. There were 3,462 selected calls, not one long close.
  Three outlying open/preallocate/truncate calls took 232–251 ms and finished
  within about 51 microseconds of each other. This is elapsed syscall time,
  **not a measurement of physical disk service time**.
- [Build 268312](https://dev.azure.com/questdb/questdb/_build/results?buildId=268312)
  passed 60 attempts on each of two VMs, with 27 onset captures and 29 failed
  one-second pings. A/run-36 naturally captured an O3 worker inside native close
  while holding `FdCache`, with all three HTTP workers waiting for that monitor.
  A/run-24 captured a WAL-apply worker holding it during native open. These first
  dumps came after detection: they establish real cross-pool contention but
  cannot measure its duration during the preceding failed ping.
- That soak did not reproduce the original 120-second close-drain failure.
  Maximum completed drain was 9.795 seconds; no consistent across-host latency
  deterioration or sampled swap activity was observed. Provider burst-credit
  exhaustion and physical-storage saturation remain unproven.
- [Build 268344](https://dev.azure.com/questdb/questdb/_build/results?buildId=268344)
  reached the System Trace preflight on Xcode 16.4. Readiness was absent when
  the collector's 15-second startup budget expired; the recorder log was empty
  and no trace was published. The error combined early exit, cancellation, and
  timeout, and did not record the child PID/exit status. This does not establish
  a permissions failure or lack of System Trace support. Compilation and the
  QuestDB test were skipped; only one macOS job ran.

## Recorder startup validation (completed)

[Build 268361](https://dev.azure.com/questdb/questdb/_build/results?buildId=268361)
passed the preflight-only run. Recorder readiness took 18.712 seconds: the old
15-second allowance would have interrupted this successful start. It exported
1,224 target syscalls with CPU/wait duration fields and 1,084 target thread-state
intervals; the raw trace was retained. Its template uses a five-second rolling
window. This establishes recorder capability on that hosted Mac, not the cause
of the original QuestDB timeout. Kernel wait causes remain to be investigated;
the exported syscall stacks in this smoke recording contain user-space frames.

Pipeline parameter `qwpWsPreflightOnly` now defaults to `false`. Set it to `true`
to repeat just the startup check. In that mode the
expanded job contains checkout, tracing preflight, artifact ownership hand-back,
and publication only. Dependency installs, client/server builds, the fuzz test,
and server-log archival are excluded even if the smoke check succeeds. The job
limit is ten minutes; the preflight step limit is five minutes. Do not turn the
full experiment on without first inspecting the startup artifact.

Both preflight and full-test recorders now receive a 60-second startup budget.
Only traced attempts get a 90-second diagnostic setup gate, before the workload
starts; controls retain their 30-second gate. The shell controller waits up to
70 seconds for recorder readiness. Workload assertions and sender/SQL timeouts
are unchanged.
The smoke process now waits through cold startup and recorder cleanup rather
than expiring at the old 25-second deadline. It exits without replacing the
parent's error if the recorder finishes before releasing the smoke workload.

New startup artifacts in `preflight/`:

- `system-trace-launch.json`: exact recorder command and startup budget.
- `system-trace-recorder.json`: actual recorder PID and attach-target PID.
- `system-trace-startup.jsonl`: elapsed startup/clock readings and exit state
  every five seconds, plus the failure transition.
- `system-trace-ready.json`: startup latency when the notification arrives.
- `system-trace-startup-failure.json`: distinct timeout, spontaneous exit, or
  interruption, with the return code **before cleanup**.
- `system-trace-startup-processes.log`: PID/parent, process group, state, CPU,
  RSS, elapsed time, and command for the collector, recorder, and smoke target.
- `system-trace-startup-sample.txt`: a one-second native sample of a recorder
  still alive after startup failure. It is never taken during successful startup
  or while running the QuestDB test. The process snapshot and sample have
  five-/ten-second command deadlines; command errors/statuses are retained in
  `system-trace-startup-diagnostics.json` and its accompanying command logs.
- `system-trace-cleanup.json` and `system-trace-recorder-exit.json`: state before
  cleanup and the final child return code. Do not mistake a cleanup-induced
  SIGINT/SIGKILL exit for a spontaneous recorder failure.

Startup diagnostic failure cannot suppress recorder cleanup or replace the
original failure reason. Cancellation skips startup sampling. A longer deadline
is an exploratory cold-start allowance, not a claim that slow initialization
caused build 268344. A successful check still requires actual target syscall
and scheduler rows; readiness alone is not sufficient.

## Current experiment: bounded full test

The single worker uses server `12a33d651e51e2682e7a448c8db5168fc72dfad3`, Temurin
25.0.3+9 (official download with pinned SHA-256), fuzz seed
`0x268579c36b106b74`, build-mode seed `7856154056746654427`, three hosted CPUs,
and JVM `ActiveProcessorCount=3`. The managed hosted macOS image is still
moving; record its version, do not call this an exact environment reproduction.

The next measurement is a pre-timeout **System Trace**, not another identical
soak. The question is whether a long native file call is executing on CPU,
blocked in a kernel/filesystem wait, or runnable but not scheduled. Kernel
backtraces and wakeups may identify a wait; an elapsed syscall alone cannot.

Before compiling anything, `prepare_qwp_ws_system_trace.sh` records a five-second
filesystem/sleep smoke workload on the worker. It exports the trace TOC, discovers
syscall and thread-state tables, and requires actual rows associated with the
smoke PID in both. Merely finding Xcode or creating a `.trace` directory is not
success. Unsupported schemas or denied tracing stop the job at this preflight,
which has a five-minute step limit; its logs/artifacts are still published.
No SIP or developer-security settings are changed. The root collector owns and
reaps its recorder child; artifact ownership is returned to the CI uploader.

Run at most 13 attempts on that same VM: attempts **1, 6, 11 are untraced
controls**, the other ten use System Trace. Stop after two event-bearing traced
onset captures, or immediately on a test/diagnostic failure. Refuse to start
another attempt after ten minutes or below 2 GiB free space. The recording itself
has a 30-second hard limit, finalization a 30-second wait, and export/validation
a 60-second budget. Recording expiry before onset/completion is a diagnostic
failure, not evidence of a healthy run. The 30-minute test-step limit remains
the outer bound; the test and sender retain all existing timeouts/assertions.

The recorder starts at the existing server-ready gate and must post its explicit
Darwin readiness notification before the workload is released. Registration's
initial notification state is consumed **before** recorder launch, so it cannot
be mistaken for readiness. Startup is bounded to leave room within the traced
attempt's 90-second diagnostic setup gate.

At the first failed ping, heartbeat gap, or workload-error request, the watchdog
synchronously requests SIGINT of the recorder. The privileged collector polls
that request every 20 ms; the watchdog waits up to three seconds for the
stop-sent acknowledgment before permitting teardown. Normal workload completion
uses the same stop/acknowledgment handshake. Traced attempts do **not** launch
SIGQUIT or native `sample`. Untraced controls retain the previous onset captures.
Any nonzero recorder exit, missing target events, or stop lag over two seconds
fails the diagnostic run. Raw `.trace`, TOC, exported rows, and tool stderr are
kept even when validation fails.

System Trace can use a rolling window; stopping quickly is important, but does
not itself prove that the whole failed probe was retained. Inspect actual event
coverage before interpreting a capture. This policy counts event-bearing onset
captures to bound CI spending, not to declare the investigation solved.

Continuous `fs_usage` is disabled. JVM pause logs, per-second `iostat`/`vm_stat`,
and five-second memory/process snapshots remain enabled. No synthetic memory
pressure or injected delays. Store-and-forward, Java/tool temporary data, and
diagnostics are explicitly directed to the worker filesystem, not `/tmp`.

`runs.jsonl` records attempt index, UTC start, elapsed soak/attempt time, unittest
duration, free space, completed drain maximum, ping errors/maximum, heartbeat
maximum, capture reason, trace/validation flags and exit status. Raw per-attempt `test.log` and server
logs are preserved. Compare successive fixed-seed attempts with the continuous
host measurements; concurrent scheduling and schema interleavings can still vary.
The first disk/VM-stat sample includes statistics since boot, not just this test.

Neither this experiment nor the preceding soak tests a known provider quota. Microsoft's
[hosted-agent documentation](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/hosted?view=azure-devops)
places these macOS machines in GitHub's macOS cloud; an Azure managed-disk burst
credit policy must not be assumed. A worsening latency curve alone would not
prove quota exhaustion, and no degradation would not exclude an unknown quota.

The external Python watchdog probes `/ping` once per second with a one-second
timeout. A separate thread records quarter-second heartbeats in another file.
The first probe failure, heartbeat gap over one second, or transient workload
error requests one bounded capture. In untraced controls, that means three
SIGQUIT requests 500 ms apart and a three-second native `sample` at 10 ms
intervals. The JVM writes GC/safepoint
records to a dedicated rotating log from startup. Capture is allowed to finish
before DROP cleanup, with a 15-second bound; this does not change workload or
sender timeout budgets. Failures occurring during teardown do not trigger onset
capture. Diagnostic helper failures are reported as failures, not green evidence.

`_list_columns()` now lets its existing caller tolerate and report lookup errors;
previously its catch-all hid timeouts from the diagnostic callback.

## Reading the next artifact

Download `qwp-ws-macos-system-trace`. For a preflight-only run, inspect
the startup artifacts above and `system-trace-valid.json`/`system-trace-error.json`.
There should be no `run-*` directories or QuestDB logs. Success establishes
recorder capability only, not a reproduced ping timeout.

When full testing is re-enabled, first check `preflight/`, the final stop
reason in `test.log`, and each run's `system-trace-valid.json` or error marker.
A green job with zero onset captures is a negative replay, not a diagnosis.

For each traced onset:

1. Locate the failed probe's `started_wall_ns` and completion `wall_ns` in
   `watchdog.jsonl`, and the request/stop markers. Their UTC, monotonic, and Mach
   clock readings include a clock-read uncertainty bracket. Use the TOC's run
   start metadata when aligning exported relative timestamps; do not assume the
   ready notification is the recording origin.
2. Open `system.trace` in Instruments and verify the failed interval is covered
   by syscall and scheduler events for the server PID. Check for lost/truncated
   events. Inspect native thread identities/names in that interval, particularly
   `shared-network_*`, `shared-write_*`, and `wal-apply_*`.
3. For long file calls, split elapsed time into running, runnable, and blocked
   intervals using the thread-state timeline. Inspect available kernel stacks
   and wakeups for the blocking dependency. Do not label a generic blocked state
   as disk I/O without supporting stack/event evidence.
4. Correlate with JVM pause logs, heartbeat, and host paging/CPU/I/O observations.
   The nominal one-second host counters can drift; they are not exact per-probe
   service-time measurements. Compare untraced controls for gross observer effects;
   this small interleaved sample cannot quantify tracing overhead precisely.

If syscall/scheduling tables are unavailable, the preflight stops before build.
If events are present but their kernel stacks cannot identify the wait, report
that boundary explicitly; do not spend more identical CI runs assuming the trace
can expose it. Guest traces cannot prove a provider's storage quota or measure
unavailable hypervisor steal time.

| Evidence during the same interval | Interpretation |
|---|---|
| Heartbeat regular; HTTP blocked; repeated native file-operation stacks | Investigate filesystem/page-fault service and worker occupancy. Correlate with syscall durations and host paging. |
| Heartbeat regular; JVM safepoint spans the delay | Investigate the recorded safepoint/GC cause and time to reach it. |
| Heartbeat regular; repeated shared lock or queue waits | Trace the owner and dependency. A waiter is not necessarily the cause. |
| Heartbeat itself has a large gap | Observer scheduling, VM pause, or shared resource delay is possible; not proof of hypervisor descheduling. Check prior log-write duration and host metrics. |
| HTTP stays responsive; sender drain stalls | Investigate connection-specific ACK/commit/replay progress, not a global server freeze. |

Artifact files: `watchdog.jsonl`, `heartbeat.jsonl`, `capture.jsonl`,
`native-sample.txt` (controls), `sample-command.log`, `jvm-pauses.log*`, `questdb-server.log`,
`server.conf`, per-attempt `test.log`, `runs.jsonl`, plus host
manifest/memory/iostat logs. `fs-usage.log` is only present when the optional
continuous tracing setting is explicitly enabled (off in this experiment).
SIGQUIT request time is not dump completion time. JVM dumps use the server log;
native sampling and watchdog output do not depend on that logger. All files
still share storage. `previous_write_ms` exposes one source of observer delay.

Completed filesystem traces cannot reveal every in-flight operation. Sampling
and SIGQUIT perturb scheduling after detection; continuous tracing perturbs the
entire traced arm. Hosted-VM steal time and the original host's pressure timeline
remain unavailable. Do not optimize production code based only on these stacks.

Tool references: Apple's [System Trace walkthrough](https://developer.apple.com/videos/play/wwdc2016/411/)
describes scheduling, syscall, and windowed tracing; the current hosted Xcode is
verified by the smoke test, not assumed to match that older demonstration.
The [notify API documentation](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/notify_register_check.3.html)
documents notification polling. CLI usage is described in the
[xctrace manual](https://keith.github.io/xcode-man-pages/xctrace.1.html).

Local validation uses mocked recorder/notification calls and synthetic exported
XML on Linux; it cannot establish hosted macOS permissions or actual schema
support. Keep all local unit-test temporary files under the repository as well.
