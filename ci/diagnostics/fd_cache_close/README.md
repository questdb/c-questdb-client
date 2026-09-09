# Controlled O3 close / FdCache experiment

Local-only diagnostic harness. It does not edit QuestDB sources or the server
JAR, change the existing fuzz test, or queue CI. Requires Linux, JDK 25, ASM
9.8, Python with the system-test dependencies, and a built C client library.

## Question and prediction

Can one slow O3 file close stop otherwise unrelated QWP ingestion because
`FdCache.close()` holds a process-wide monitor across native `Files.close0()`?

The same six-second O3 delay should leave unrelated-table ACKs responsive
outside the monitor, but delay ACKs that need the monitor when injected inside.
The thread dump must connect the O3 lock owner to the affected network workers;
elapsed time alone is insufficient evidence.

## Fixed workload and controls

Every trial launches a fresh server, pinned to three CPUs, with three HTTP
workers, three shared-write workers and two WAL-apply workers. Heap is 256 MiB
initial / 1 GiB maximum. All data, temporary files and artifacts are on the
repository's ext4 volume, never `/tmp`.

1. Create a 32-column WAL table `fault_o3`, insert 4,096 ordered rows, and wait
   for application.
2. Warm three separate QWP connections/writers on three unrelated tables.
3. Arm a one-shot fault and insert 256 older rows into `fault_o3`.
4. At an O3 shared-write worker's close of this table's data file, either inject
   no delay (`baseline`), sleep outside `FdCache` (`outside`), or sleep immediately
   before `Files.close0()` while holding `FdCache` (`inside`).
5. Send one row per QWP connection, normally adding a column to force writer
   schema/segment work. Measure publish-to-ACK completion, probe `/ping` on new
   connections, capture a JVM thread dump, and validate all resulting rows.

The reported ACK latency starts before row construction/publication and ends
after `wait()` confirms the frame's ACK. It is not a measurement of just the
socket round trip. Each `/ping` has a 500 ms timeout and a 100 ms inter-probe gap.

The agent checks the actual file path, O3 call stack, shared-write thread name,
and `Thread.holdsLock(Files.fdCache)`. Native calls are preserved. The injected
sleep models time spent holding the monitor; it does **not** simulate an actual
kernel close, slow disk, APFS, or memory pressure. All modes use the same agent.

## Results, 2026-09-08

Server JAR manifest: `12a33d651e51e2682e7a448c8db5168fc72dfad3`.
Runtime: Corretto 25.0.4+7-LTS on Linux x86-64, not the original macOS/Temurin
environment. Exact commands, binary hashes, runtime and CPU affinity are in
each trial's `identity.json`.

Nine primary trials used balanced order:
`baseline, outside, inside, inside, baseline, outside, outside, inside, baseline`.

| Injection | Trials | ACK latency, all three senders | Ping timeouts |
|---|---:|---:|---:|
| None | 3 | 24.5–34.0 ms | 0 |
| Six seconds outside monitor | 3 | 24.2–29.8 ms | 0 |
| Six seconds inside monitor | 3 | 6,012.7–6,034.3 ms | 10 per trial |

All 13 completed trials (nine primary plus four controls below) recovered,
acknowledged every probe frame, and passed row-count/value checks. Three earlier
`smoke-*` setup attempts did not produce results and are not included.

### Two propagation paths, not just exhausted HTTP workers

In `inside-1`, all three HTTP workers were blocked in WAL segment-roll closes,
waiting on the exact `FdCache` monitor held by the sleeping O3 worker.

In `inside-2` and `inside-3`, one HTTP worker was blocked while closing an HTTP
socket in the serial network dispatcher; the other two HTTP workers were idle.
`Net.close()` also goes through `Files.close()` and the same monitor. The serial
dispatcher cannot run on another worker while its current invocation is stuck.

Four further trials used **unchanged-schema**, already-open QWP writers:

- Send immediately: inside-monitor ACKs completed in 1.2–1.6 ms, showing ordinary
  WAL appends do not inherently wait for O3. But subsequent fresh `/ping`
  connections timed out. The dump showed `Net.accept()` blocked while registering
  its socket through `FdCache.createUniqueFdNonCached()`.
- Wait 1.2 seconds after the fault, allowing the ping connection to block the
  dispatcher, then send on the existing QWP connections: all three ACKs waited
  4,793.5–4,793.9 ms, the remaining fault duration. No schema change was needed.
- Corresponding outside-monitor controls acknowledged in 1.7–3.9 ms immediately
  and 0.6–1.6 ms after 1.2 seconds, with no ping timeouts.

The fresh-connection probe is therefore an explicit participant in the second
mechanism, not a passive observer. New SQL/HTTP connections and disconnects can
encounter the same path in real workloads.

Source chain at the pinned server revision:

- `O3CopyJob.copyTail` -> `O3Utils.close` -> `Files.close` -> synchronized
  `FdCache.close` -> native `Files.close0`.
- WAL rolling: `WalWriter.openColumnFiles` -> `MemoryPMARImpl.close` ->
  `Vm.bestEffortClose` -> `Files.close`.
- Socket acceptance: `Net.accept` -> `Files.createUniqueFd` -> synchronized
  `FdCache.createUniqueFdNonCached`.
- `SynchronizedJob.run` holds its serial-job ownership until `runSerially`
  returns. Both Linux and macOS dispatchers use the shared accept path.

### Interpretation and limits

**Established:** a slow O3 close under the global FD monitor can delay unrelated
WAL ingestion directly, or stall the serial dispatcher and thereby existing
network connections. Slowing O3 outside that monitor did not have these effects.

**Not established:** that this caused Azure build 266336's original 74.7-second
interruption or 120-second close-drain failure. Nor does this identify what made
the original native file operations slow. The later CI O3/FdCache dump is from
another test. The macOS short-onset capture showed filesystem operations, not
this induced monitor-wait signature.

The preflight found high host-wide I/O pressure (full PSI avg10 approximately
62–74% during accepted trials), and the repository volume was 98% full, with
about 44 GiB available before the experiment. Those remain systemic caveats,
not evidence that this test saturated disk. Interleaved controls completed
quickly despite that background. The independent observer's maximum gap was
103.1 ms; maximum JVM safepoint across complete runs, including startup, was
67.6 ms. Neither explains the six-second delay.

This is synchronization evidence, not a hardware-bottleneck study or a
production optimization. CPU frequency/thermals, memory bandwidth, controller
queues, device errors and per-process storage latency were not measured.
Host CPU/memory/I/O PSI, memory/VM statistics and disk counters are retained at
100 ms intervals; they cannot attribute host-wide pressure to QuestDB.

## Re-run

From the client repository, set paths to an ASM 9.8 JAR and the pinned QuestDB
JAR. Use a new result directory for each invocation; existing directories are
rejected. Choose three available physical cores for `taskset` on your machine.

```bash
export ASM_JAR=/path/to/asm-9.8.jar
export SERVER_JAR=/path/to/questdb.jar
export TMPDIR="$PWD/build-exp/fd-cache-close/tmp"
mkdir -p "$TMPDIR" build-exp/fd-cache-close/classes
javac -J-Djava.io.tmpdir="$TMPDIR" -cp "$ASM_JAR" \
  -d build-exp/fd-cache-close/classes ci/diagnostics/fd_cache_close/CloseFaultAgent.java
jar -J-Djava.io.tmpdir="$TMPDIR" --create --file build-exp/fd-cache-close/agent.jar \
  --manifest ci/diagnostics/fd_cache_close/MANIFEST.MF \
  -C build-exp/fd-cache-close/classes .
PYTHONDONTWRITEBYTECODE=1 taskset -c 0-2 python3 ci/diagnostics/fd_cache_close/run.py \
  build-exp/fd-cache-close/new-inside inside \
  --server "$SERVER_JAR" --agent build-exp/fd-cache-close/agent.jar --asm "$ASM_JAR"
python3 ci/diagnostics/fd_cache_close/analyze.py build-exp/fd-cache-close
```

Repeat with `baseline` and `outside`, using fresh directory names. For the
dispatcher controls, add `--probe-schema stable`, then also
`--probe-delay-ms 1200`. The default delay is 6,000 ms; the agent rejects delays
above 15 seconds. Do not run this agent against a production instance.

Artifacts are retained under `build-exp/fd-cache-close/`: `analysis.json`, each
trial's `result.json`, `events.json`, `fault-start`, `fault-end`, `server.log`
(including the thread dump), `jvm-pauses.log`, `host.jsonl` and `identity.json`.
No CI changes or production fixes are included.
