# QWP/WebSocket macOS stall investigation

Status: server progress interruption observed; root cause **not established**.
This branch is diagnostic only. Keep sender timeouts and correctness assertions
unchanged. Azure PR 200 allocates only two macOS workers for
`TestQwpWsFuzz.test_add_columns`.

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
- The first JVM dump, at 12:20:12, is **after failure and during DROP cleanup**:
  three HTTP workers in truncate/msync paths, two WAL-apply workers idle.
  It establishes a late software location, not the original limiting resource.
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

## Current experiment

Both replicas use server `12a33d651e51e2682e7a448c8db5168fc72dfad3`, Temurin
25.0.3+9 (official download with pinned SHA-256), fuzz seed
`0x268579c36b106b74`, build-mode seed `7856154056746654427`, three hosted CPUs,
and JVM `ActiveProcessorCount=3`. The managed hosted macOS image is still
moving; record its version, do not call this an exact environment reproduction.

Replica A has lightweight monitoring; replica B additionally runs continuous
`fs_usage`. Each runs at most 20 attempts and stops at its first capture or test
failure. No synthetic memory pressure. Store-and-forward, Java temporary data,
and diagnostics are explicitly on the worker filesystem, not `/tmp`.

The external Python watchdog probes `/ping` once per second with a one-second
timeout. A separate thread records quarter-second heartbeats in another file.
The first probe failure, heartbeat gap over one second, or transient workload
error requests one bounded capture: three SIGQUIT requests 500 ms apart and
a three-second native `sample` at 10 ms intervals. The JVM writes GC/safepoint
records to a dedicated rotating log from startup. Capture is allowed to finish
before DROP cleanup, with a 15-second bound; this does not change workload or
sender timeout budgets. Failures occurring during teardown do not trigger onset
capture. Diagnostic helper failures are reported as failures, not green evidence.

`_list_columns()` now lets its existing caller tolerate and report lookup errors;
previously its catch-all hid timeouts from the diagnostic callback.

## Reading the next artifact

| Evidence during the same interval | Interpretation |
|---|---|
| Heartbeat regular; HTTP blocked; repeated native file-operation stacks | Investigate filesystem/page-fault service and worker occupancy. Correlate with syscall durations and host paging. |
| Heartbeat regular; JVM safepoint spans the delay | Investigate the recorded safepoint/GC cause and time to reach it. |
| Heartbeat regular; repeated shared lock or queue waits | Trace the owner and dependency. A waiter is not necessarily the cause. |
| Heartbeat itself has a large gap | Observer scheduling, VM pause, or shared resource delay is possible; not proof of hypervisor descheduling. Check prior log-write duration and host metrics. |
| HTTP stays responsive; sender drain stalls | Investigate connection-specific ACK/commit/replay progress, not a global server freeze. |

Artifact files: `watchdog.jsonl`, `heartbeat.jsonl`, `capture.jsonl`,
`native-sample.txt`, `sample-command.log`, `jvm-pauses.log*`, `questdb-server.log`,
`server.conf`, and on B `fs-usage.log`, plus host manifest/memory/iostat logs.
SIGQUIT request time is not dump completion time. JVM dumps use the server log;
native sampling and watchdog output do not depend on that logger. All files
still share storage. `previous_write_ms` exposes one source of observer delay.

Completed filesystem traces cannot reveal every in-flight operation. Sampling
and SIGQUIT perturb scheduling after detection; continuous tracing perturbs the
entire traced arm. Hosted-VM steal time and the original host's pressure timeline
remain unavailable. Do not optimize production code based only on these stacks.
