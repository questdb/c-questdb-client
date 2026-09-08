"""Bounded macOS System Trace collector and cheap pre-build capability check.

Runs as root on the disposable CI worker so the collector owns its xctrace
child and can stop it without a second sudo invocation. Never changes SIP or
developer-security settings. All writable runtime paths are explicit.
"""

import argparse
import ctypes
from functools import lru_cache
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
import uuid

from qwp_ws_trace_export import export_and_validate

# The unchanged fixture gate has a 30-second budget; leave time for watchdog
# startup and the host snapshot after the recorder is ready.
START_TIMEOUT = 15
PREFLIGHT_START_TIMEOUT = 60
FINISH_TIMEOUT = 30
RECORD_SECONDS = 30
MIN_FREE_BYTES = 2 * 1024 ** 3


@lru_cache(maxsize=1)
def mach_clock():
    class Timebase(ctypes.Structure):
        _fields_ = [('numer', ctypes.c_uint32), ('denom', ctypes.c_uint32)]

    lib = ctypes.CDLL('/usr/lib/libSystem.B.dylib')
    lib.mach_absolute_time.restype = ctypes.c_uint64
    lib.mach_absolute_time.argtypes = []
    lib.mach_timebase_info.argtypes = [ctypes.POINTER(Timebase)]
    info = Timebase()
    if lib.mach_timebase_info(ctypes.byref(info)) or not info.denom:
        raise RuntimeError('Cannot read Mach clock timebase')
    return lib.mach_absolute_time, info.numer, info.denom


def clocks():
    before = time.monotonic_ns()
    wall = time.time_ns()
    fields = dict(wall_ns=wall, monotonic_ns=before)
    if sys.platform == 'darwin':
        read, numer, denom = mach_clock()
        fields.update(mach_absolute_ticks=read(), mach_numer=numer, mach_denom=denom)
    fields['clock_read_span_ns'] = time.monotonic_ns() - before
    return fields


def marker(directory, name, **fields):
    # Readers must not see a partially written JSON document.
    path = directory / name
    temporary = path.with_suffix(path.suffix + '.partial')
    temporary.write_text(json.dumps(dict(**clocks(), **fields)) + '\n')
    temporary.replace(path)


def request_stop(directory, reason):
    """Watchdog-owned request. Collector records when it actually sends SIGINT."""
    path = directory / 'system-trace-stop-request.json'
    if not path.exists():
        marker(directory, path.name, reason=reason)


class StartedNotification:
    """Use xctrace's explicit ready notification, not output text or a sleep."""

    def __init__(self):
        self.name = 'io.questdb.ci.system-trace.' + uuid.uuid4().hex
        self.lib = ctypes.CDLL('/usr/lib/system/libsystem_notify.dylib')
        self.lib.notify_register_check.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_int)]
        self.lib.notify_register_check.restype = ctypes.c_uint32
        self.lib.notify_check.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_int)]
        self.lib.notify_check.restype = ctypes.c_uint32
        self.lib.notify_cancel.argtypes = [ctypes.c_int]
        self.lib.notify_cancel.restype = ctypes.c_uint32
        self.token = ctypes.c_int()
        if self.lib.notify_register_check(self.name.encode(), ctypes.byref(self.token)):
            raise RuntimeError('Cannot register xctrace readiness notification')
        # notify_check is initially true even before a post. Clear it BEFORE
        # launching the recorder, then require a subsequent real notification.
        try:
            self.check()
        except Exception:
            self.close()
            raise

    def check(self):
        changed = ctypes.c_int()
        if self.lib.notify_check(self.token, ctypes.byref(changed)):
            raise RuntimeError('Cannot check xctrace readiness notification')
        return bool(changed.value)

    def close(self):
        self.lib.notify_cancel(self.token)


def stop_child(child):
    if child.poll() is None:
        child.send_signal(signal.SIGINT)
        try:
            child.wait(timeout=FINISH_TIMEOUT)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=5)
            raise RuntimeError('xctrace did not finalize after SIGINT')


def capture_startup_state(directory, child, target_pid):
    """Best-effort evidence before stopping a recorder that never became ready."""
    results = []

    def run(name, command, timeout):
        result = dict(command=command)
        try:
            with (directory / name).open('w') as log:
                completed = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                                           timeout=timeout, check=False)
                result['returncode'] = completed.returncode
        except (OSError, subprocess.TimeoutExpired) as exc:
            result['error'] = repr(exc)
        results.append(result)

    run('system-trace-startup-processes.log', [
        '/bin/ps', '-p', f'{child.pid},{target_pid},{os.getpid()}',
        '-o', 'pid,ppid,pgid,state,%cpu,rss,etime,command'], 5)
    # Sample only a still-owned, live recorder, never another process by name.
    # This is after startup failure, not during the test or a successful start.
    sampling_returncode = child.poll()
    if sampling_returncode is None:
        run('system-trace-startup-sample-command.log', [
            '/usr/bin/sample', str(child.pid), '1', '10', '-file',
            str(directory / 'system-trace-startup-sample.txt')], 10)
    marker(directory, 'system-trace-startup-diagnostics.json', commands=results,
           recorder_returncode_at_sampling=sampling_returncode,
           sample_present=(directory / 'system-trace-startup-sample.txt').is_file())


def wait_for_ready(directory, child, target_pid, notification, timeout, interrupted):
    started = time.monotonic()
    next_progress = 0
    with (directory / 'system-trace-startup.jsonl').open('w') as progress:
        while True:
            elapsed = time.monotonic() - started
            returncode = child.poll()
            if interrupted():
                reason = 'interrupted'
            elif returncode is not None:
                reason = 'recorder_exited'
            elif notification.check():
                marker(directory, 'system-trace-ready.json', pid=target_pid,
                       recorder_pid=child.pid, startup_seconds=elapsed)
                return
            elif elapsed >= timeout:
                reason = 'readiness_timeout'
            else:
                reason = None
            if elapsed >= next_progress or reason is not None:
                progress.write(json.dumps(dict(
                    **clocks(), recorder_pid=child.pid, elapsed_seconds=elapsed,
                    returncode=returncode, reason=reason)) + '\n')
                progress.flush()
                next_progress = elapsed + 5
            if reason is not None:
                # Preserve spontaneous exit vs. still running BEFORE our SIGINT.
                marker(directory, 'system-trace-startup-failure.json', reason=reason,
                       recorder_pid=child.pid, target_pid=target_pid,
                       returncode_before_cleanup=returncode, elapsed_seconds=elapsed,
                       timeout_seconds=timeout)
                if reason != 'interrupted':
                    try:
                        capture_startup_state(directory, child, target_pid)
                    except Exception as exc:
                        marker(directory, 'system-trace-startup-diagnostics-error.json',
                               error=repr(exc))
                raise RuntimeError(f'System Trace startup {reason}: recorder PID {child.pid}, '
                                   f'exit={returncode}, elapsed={elapsed:.3f}s, budget={timeout}s; '
                                   'inspect system-trace-startup-* artifacts')
            time.sleep(0.02)


def collect(directory, pid, on_ready=None, start_timeout=START_TIMEOUT):
    child = None
    notification = None
    interrupted = False

    def interrupt(*_):
        nonlocal interrupted
        interrupted = True

    previous = {sig: signal.signal(sig, interrupt) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        if (directory / 'system.trace').exists():
            raise RuntimeError('Refusing to overwrite an existing trace')
        notification = StartedNotification()
        with (directory / 'system-trace-record.log').open('w') as log:
            command = [
                '/usr/bin/xcrun', 'xctrace', 'record', '--template', 'System Trace',
                '--attach', str(pid), '--time-limit', f'{RECORD_SECONDS}s',
                '--no-prompt', '--notify-tracing-started', notification.name,
                '--output', str(directory / 'system.trace')]
            marker(directory, 'system-trace-launch.json', pid=pid, command=command,
                   startup_timeout_seconds=start_timeout)
            child = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
            marker(directory, 'system-trace-recorder.json', pid=child.pid, target_pid=pid)
            wait_for_ready(directory, child, pid, notification, start_timeout, lambda: interrupted)
            if on_ready is not None:
                on_ready()
            deadline = time.monotonic() + RECORD_SECONDS
            next_health_check = 0
            request = directory / 'system-trace-stop-request.json'
            while not request.exists():
                if interrupted:
                    raise RuntimeError('System Trace collector interrupted')
                if child.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError('Recording expired before workload completion/timeout')
                if time.monotonic() >= next_health_check:
                    if shutil.disk_usage(directory).free < MIN_FREE_BYTES:
                        raise RuntimeError('System Trace disk-space safety stop')
                    os.kill(pid, 0)
                    next_health_check = time.monotonic() + 1
                time.sleep(0.02)
            reason = json.loads(request.read_text())
            if child.poll() is not None:
                raise RuntimeError('Recorder exited before stop request')
            child.send_signal(signal.SIGINT)
            marker(directory, 'system-trace-stop-sent.json', reason=reason['reason'],
                   request_wall_ns=reason['wall_ns'])
            # A delayed controller might have lost the failed probe from the
            # template's rolling window. Do not count that as a useful capture.
            stop_lag = time.monotonic_ns() - reason['monotonic_ns']
            child.wait(timeout=FINISH_TIMEOUT)
            marker(directory, 'system-trace-recorded.json', returncode=child.returncode,
                   stop_lag_ms=stop_lag / 1e6)
            if child.returncode != 0:
                raise RuntimeError(f'xctrace exited {child.returncode}')
            if stop_lag > 2_000_000_000:
                raise RuntimeError('Trace stop was over two seconds late; onset may be lost')
        export_and_validate(directory, pid)
    except Exception as exc:
        marker(directory, 'system-trace-error.json', error=repr(exc))
        raise
    finally:
        try:
            if child is not None:
                try:
                    marker(directory, 'system-trace-cleanup.json', recorder_pid=child.pid,
                           returncode_before_cleanup=child.poll())
                finally:
                    # Diagnostic writes must never prevent reaping our child.
                    try:
                        stop_child(child)
                    finally:
                        marker(directory, 'system-trace-recorder-exit.json', recorder_pid=child.pid,
                               returncode=child.poll())
        finally:
            if notification is not None:
                notification.close()
            for sig, handler in previous.items():
                signal.signal(sig, handler)
            marker(directory, 'system-trace-finished.json')


def smoke_target(directory):
    # Exercise real open/truncate/write/close and sleeping thread states on the
    # worker filesystem for five seconds, without compiling or starting Java.
    # Allow the longer cold-start preflight plus failure sampling/finalization.
    # This process must not disappear while the recorder is still attaching.
    deadline = time.monotonic() + PREFLIGHT_START_TIMEOUT + FINISH_TIMEOUT + 30
    while not (directory / 'smoke-go').exists():
        if (directory / 'system-trace-finished.json').exists():
            return  # Parent owns the startup error; do not overwrite it.
        if time.monotonic() >= deadline:
            raise RuntimeError('Smoke workload was never released')
        time.sleep(0.02)
    marker(directory, 'smoke-start.json', pid=os.getpid())
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        with (directory / 'smoke-data').open('wb') as data:
            data.truncate(65536)
            data.write(b'qwp trace capability check\n')
        time.sleep(0.01)
    marker(directory, 'smoke-end.json')
    request_stop(directory, 'preflight-complete')
    # Keep the attach target alive through recording finalization/export.
    deadline = time.monotonic() + 150
    while not (directory / 'system-trace-finished.json').exists():
        if time.monotonic() >= deadline:
            raise RuntimeError('Smoke recorder did not finish')
        time.sleep(0.05)


def preflight(directory):
    with (directory / 'capability.log').open('w') as log:
        for command in (['/usr/bin/xcodebuild', '-version'],
                        ['/usr/bin/xcrun', 'xctrace', 'list', 'templates'],
                        ['/usr/bin/xcrun', 'xctrace', 'help', 'record']):
            subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                           timeout=15, check=True)
    with (directory / 'smoke-target.log').open('w') as log:
        target = subprocess.Popen([sys.executable, __file__, 'smoke-target',
                                   '--run-dir', str(directory)], stdout=log,
                                  stderr=subprocess.STDOUT)
        try:
            collect(directory, target.pid, on_ready=lambda: (directory / 'smoke-go').touch(),
                    start_timeout=PREFLIGHT_START_TIMEOUT)
            target.wait(timeout=5)
            if target.returncode != 0:
                raise RuntimeError('Smoke workload failed')
        finally:
            if target.poll() is None:
                target.terminate()
                target.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['preflight', 'collect', 'smoke-target'])
    parser.add_argument('--run-dir', type=Path, required=True)
    parser.add_argument('--pid', type=int)
    args = parser.parse_args()
    directory = args.run_dir.resolve()
    if sys.platform != 'darwin' or any(
            directory == path or path in directory.parents for path in (Path('/tmp'), Path('/private/tmp'))):
        parser.error('Requires macOS and a worker-filesystem artifact directory, not /tmp')
    os.umask(0o022)  # root-generated artifacts must remain readable by uploader
    directory.mkdir(parents=True, exist_ok=True)
    (directory / 'tmp').mkdir(exist_ok=True)
    os.environ['TMPDIR'] = str(directory / 'tmp')
    try:
        if args.mode == 'smoke-target':
            smoke_target(directory)
        elif args.mode == 'preflight':
            preflight(directory)
        else:
            if args.pid is None or args.pid <= 1:
                parser.error('collect requires a managed target PID > 1')
            collect(directory, args.pid)
    except Exception as exc:
        marker(directory, 'system-trace-error.json', error=repr(exc))
        print(f'System Trace unavailable or incomplete: {exc}', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
