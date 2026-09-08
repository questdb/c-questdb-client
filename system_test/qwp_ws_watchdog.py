"""Independent, bounded onset capture for the macOS QWP diagnostic job.

The heartbeat never makes HTTP calls or waits for stack collection. Its gaps
are *observer* delays, not proof of a host pause (including log-write latency
lets us identify one source of observer delay). All artifacts stay in run_dir.
"""

import argparse
from collections import deque
from contextlib import contextmanager
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
import urllib.request

from qwp_ws_system_trace import request_stop


def write_event(stream, event, **fields):
    stream.write(json.dumps(dict(
        event=event, wall_ns=time.time_ns(), monotonic_ns=time.monotonic_ns(),
        **fields)) + '\n')
    stream.flush()


@contextmanager
def event_log(path, buffered=False):
    if not buffered:
        with path.open('w') as stream:
            yield stream
        return
    with io.StringIO() as stream:
        try:
            yield stream
        finally:
            path.write_text(stream.getvalue())


def heartbeat(run_dir, stop, delayed):
    if (run_dir / 'memory-heartbeat-enabled').exists():
        # A filesystem stall must not stall the scheduling observer itself.
        # Keep at most ~34 minutes at 4 Hz; report loss explicitly if exceeded.
        records = deque(maxlen=8192)
        dropped = 0
        previous = time.monotonic()
        while not stop.wait(0.25):
            now = time.monotonic()
            gap_ms = (now - previous) * 1000
            previous = now
            if gap_ms > 1000:
                delayed.set()
            if len(records) == records.maxlen:
                dropped += 1
            records.append(dict(event='heartbeat', wall_ns=time.time_ns(),
                                monotonic_ns=time.monotonic_ns(), gap_ms=gap_ms,
                                previous_write_ms=0, buffered=True))
        with (run_dir / 'heartbeat.jsonl').open('w') as log:
            for record in records:
                log.write(json.dumps(record) + '\n')
        if dropped:
            (run_dir / 'capture-error').write_text(f'memory heartbeat dropped {dropped} events\n')
        return
    with (run_dir / 'heartbeat.jsonl').open('w') as log:
        previous = time.monotonic()
        previous_write_ms = 0.0
        while not stop.wait(0.25):
            now = time.monotonic()
            gap_ms = (now - previous) * 1000
            previous = now
            if gap_ms > 1000:
                delayed.set()
            write_event(log, 'heartbeat', gap_ms=gap_ms,
                        previous_write_ms=previous_write_ms)
            previous_write_ms = (time.monotonic() - now) * 1000


def stop_system_trace(run_dir, reason):
    request_stop(run_dir, reason)
    deadline = time.monotonic() + 3
    while not (run_dir / 'system-trace-stop-sent.json').exists():
        if (run_dir / 'system-trace-error.json').exists() or time.monotonic() > deadline:
            raise RuntimeError('System Trace did not acknowledge onset/completion stop')
        time.sleep(0.02)


class QueryObserverProgress:
    """External fallback: absence of telemetry is not proof of a JVM pause."""

    def __init__(self, run_dir):
        self.path = run_dir / 'show-columns.tsv'
        self.size = None
        self.changed_at = None

    def check(self, now):
        try:
            size = self.path.stat().st_size
        except FileNotFoundError:
            size = 0
        if self.size is None:
            # The helper starts lazily on the first SHOW COLUMNS. Do not
            # diagnose its absence before it has published any telemetry.
            if size > 0:
                self.size, self.changed_at = size, now
            return None
        if size != self.size and size > 0:
            self.size, self.changed_at = size, now
            return None
        elapsed = now - self.changed_at
        if elapsed >= 5:
            return f'Java query observer telemetry stopped advancing for {elapsed:.3f}s; cause unknown'
        return None


def capture_kernel(run_dir, pid, reason):
    """No diagnostic file writes until the recorder has returned its bytes."""
    directory = run_dir / 'kernel-stacks'  # created before watchdog-ready
    controller = Path(__file__).resolve().parents[1] / 'ci/diagnostics/kernel_wait_preflight.py'
    with event_log(run_dir / 'capture.jsonl', buffered=True) as log:
        try:
            write_event(log, 'capture_start', reason=reason, pid=pid)
            write_event(log, 'kernel_sample_start')
            try:
                result = subprocess.run(
                    ['sudo', '-n', 'env', f'TMPDIR={directory / "tmp"}',
                     sys.executable, str(controller), str(directory),
                     '--record-raw', '--limit', '25'],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=35, check=True)
                write_event(log, 'kernel_sample_received', bytes=len(result.stdout))
                if not result.stdout:
                    raise RuntimeError('empty raw kernel capture')
                # Raw bytes are now in this process, outside recorder timeout.
                (directory / 'spindump.raw').write_bytes(result.stdout)
                (run_dir / 'sample-command.log').write_bytes(result.stderr)
                (directory / 'recorder-validation.json').write_text(json.dumps(
                    dict(format='raw', bytes=len(result.stdout), decoded=False)) + '\n')
                write_event(log, 'kernel_sample_complete')
            except Exception as exc:
                write_event(log, 'kernel_sample_error', error=repr(exc))
                partial = getattr(exc, 'stdout', None)
                if partial:
                    (directory / 'spindump.partial.raw').write_bytes(partial)
                stderr = getattr(exc, 'stderr', None)
                if stderr:
                    (run_dir / 'sample-command.log').write_bytes(stderr)
                (run_dir / 'capture-error').write_text(repr(exc) + '\n')
            for index in range(3):
                os.kill(pid, signal.SIGQUIT)
                write_event(log, 'sigquit_requested', index=index)
                time.sleep(0.5)
        finally:
            write_event(log, 'capture_complete')
            (run_dir / 'capture-started').write_text(reason + '\n')
            (run_dir / 'capture-complete').touch()


def capture(run_dir, pid, reason):
    """Stop the active trace, or take native/JVM samples; no HTTP dependency."""
    if sys.platform == 'darwin' and (run_dir / 'kernel-stacks-enabled').exists():
        return capture_kernel(run_dir, pid, reason)
    (run_dir / 'capture-started').write_text(reason + '\n')
    sample = None
    with (run_dir / 'capture.jsonl').open('w') as log, \
            (run_dir / 'sample-command.log').open('w') as sample_log:
        try:
            write_event(log, 'capture_start', reason=reason, pid=pid)
            if (run_dir / 'system-trace-enabled').exists():
                stop_system_trace(run_dir, reason)
                write_event(log, 'system_trace_stop_acknowledged')
                # No additional profilers in this arm. The recorder finalizes
                # independently; the harness validates exported data afterward.
                return
            if sys.platform == 'darwin':
                # Explicit output path: sample otherwise writes into /tmp.
                try:
                    sample = subprocess.Popen(
                        ['/usr/bin/sample', str(pid), '3', '10', '-file',
                         str(run_dir / 'native-sample.txt')],
                        stdout=sample_log, stderr=subprocess.STDOUT)
                except OSError as exc:
                    # A missing/denied native tool must not suppress SIGQUIT.
                    write_event(log, 'native_sample_error', error=repr(exc))
                    (run_dir / 'capture-error').write_text(repr(exc) + '\n')
            else:
                write_event(log, 'native_sample_unavailable', platform=sys.platform)
            if sample is not None:
                try:
                    # SIGQUIT prints at a JVM safepoint. A blocked stdout can
                    # extend that pause, so finish native sampling first;
                    # otherwise we can profile our own dump-induced stall.
                    rc = sample.wait(timeout=10)
                    write_event(log, 'native_sample_exit', returncode=rc)
                    if rc != 0 or not (run_dir / 'native-sample.txt').is_file():
                        raise RuntimeError('native sample failed or produced no output')
                except Exception as exc:
                    write_event(log, 'native_sample_error', error=repr(exc))
                    (run_dir / 'capture-error').write_text(repr(exc) + '\n')
                    if sample.poll() is None:
                        sample.kill()
                        sample.wait()
            for index in range(3):
                os.kill(pid, signal.SIGQUIT)
                write_event(log, 'sigquit_requested', index=index)
                time.sleep(0.5)
        except Exception as exc:
            write_event(log, 'capture_error', error=repr(exc))
            (run_dir / 'capture-error').write_text(repr(exc) + '\n')
        finally:
            if sample is not None and sample.poll() is None:
                sample.kill()
                sample.wait()
            write_event(log, 'capture_complete')
            (run_dir / 'capture-complete').touch()


def watch(run_dir, pid, port, stop):
    buffered = (run_dir / 'memory-heartbeat-enabled').exists()
    kernel = (run_dir / 'kernel-stacks-enabled').exists()
    if kernel:
        (run_dir / 'kernel-stacks/tmp').mkdir(parents=True, exist_ok=True)
    delayed = threading.Event()
    pulse = threading.Thread(target=heartbeat, args=(run_dir, stop, delayed),
                             name='watchdog-heartbeat', daemon=True)
    pulse.start()
    collector = None
    query_observer = QueryObserverProgress(run_dir)
    ping_failures = 0
    # Do not inherit proxy settings for the loopback probe.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with event_log(run_dir / 'watchdog.jsonl', buffered=buffered) as log:
            write_event(log, 'ready', pid=pid, port=port)
            (run_dir / 'watchdog-ready').touch()
            while not (run_dir / 'start-test').exists():
                if stop.wait(0.05):
                    return
            delayed.clear()  # Do not turn a pre-workload gate delay into onset.
            while not stop.is_set():
                if not pulse.is_alive():
                    raise RuntimeError('independent heartbeat stopped')
                if (run_dir / 'workload-finished').exists():
                    # A producer can report a failure immediately before
                    # finishing. Capture that explicit request before acking
                    # teardown, even if the probe loop has not seen it yet.
                    request = run_dir / 'capture-request'
                    if collector is None and request.exists():
                        capture(run_dir, pid, request.read_text())
                    write_event(log, 'workload_finished')
                    break
                reason = None
                started = time.monotonic()
                started_wall_ns = time.time_ns()
                try:
                    with opener.open(f'http://127.0.0.1:{port}/ping', timeout=1) as resp:
                        if resp.status != 204:
                            reason = f'ping HTTP {resp.status}'
                    write_event(log, 'ping', elapsed_ms=(time.monotonic() - started) * 1000,
                                started_wall_ns=started_wall_ns, error=reason)
                except Exception as exc:
                    reason = f'ping: {type(exc).__name__}: {exc}'
                    write_event(log, 'ping', elapsed_ms=(time.monotonic() - started) * 1000,
                                started_wall_ns=started_wall_ns, error=reason)
                request = run_dir / 'capture-request'
                ping_failures = ping_failures + 1 if reason else 0
                if (run_dir / 'show-columns-enabled').exists():
                    # Keep ping/heartbeat telemetry, but reserve invasive capture
                    # for a slow query or an actual workload failure in this arm.
                    ping_reason = reason
                    slow_query = run_dir / 'show-columns-slow'
                    reason = ('slow SHOW COLUMNS: ' + slow_query.read_text()) if slow_query.exists() else None
                    observer_reason = query_observer.check(time.monotonic())
                    if reason is None:
                        reason = observer_reason
                    if reason is None and ping_reason and ping_failures >= 2 and (run_dir / 'kernel-ping-capture-enabled').exists():
                        reason = 'kernel resource follow-up: ' + ping_reason
                if request.exists():
                    reason = request.read_text()
                if delayed.is_set() and reason is None and not (run_dir / 'show-columns-enabled').exists():
                    reason = 'watchdog heartbeat gap exceeded 1 second'
                # Recheck after the probe: never diagnose teardown as onset.
                if reason and collector is None and not (run_dir / 'workload-finished').exists():
                    # Publish synchronously so teardown sees an in-flight
                    # capture even before the collector thread is scheduled.
                    if not kernel:
                        (run_dir / 'capture-started').write_text(reason + '\n')
                    if (run_dir / 'system-trace-enabled').exists():
                        request_stop(run_dir, reason)
                    collector = threading.Thread(
                        target=capture, args=(run_dir, pid, reason),
                        name='watchdog-capture')
                    collector.start()
                stop.wait(max(0, 1 - (time.monotonic() - started)))
    finally:
        if (run_dir / 'system-trace-enabled').exists():
            try:
                stop_system_trace(run_dir, 'workload-finished' if (run_dir / 'workload-finished').exists()
                                  else 'watchdog-stopped')
            except Exception as exc:
                (run_dir / 'capture-error').write_text(repr(exc) + '\n')
        stop.set()
        pulse.join(timeout=2)
        if collector is not None:
            collector.join(timeout=45 if (run_dir / 'kernel-stacks-enabled').exists() else 15)
        (run_dir / 'watchdog-stopped').touch()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-dir', type=Path, required=True)
    args = parser.parse_args()
    run_dir = args.run_dir.resolve()
    endpoint = json.loads((run_dir / 'watchdog-endpoint.json').read_text())
    pid, port = endpoint['pid'], endpoint['port']
    if not isinstance(pid, int) or pid <= 1 or not isinstance(port, int) or not 0 < port < 65536:
        parser.error('invalid managed-server PID or port')
    os.kill(pid, 0)
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    watch(run_dir, pid, port, stop)


if __name__ == '__main__':
    main()
