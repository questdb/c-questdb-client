"""Bounded filesystem perturbation with per-call elapsed and process CPU clocks.

Only touches a newly created 64 KiB file in this attempt's artifact directory.
This generates filesystem work; it does not emulate a known hosted-disk quota.
"""
import argparse
import json
import os
from pathlib import Path
import time


def mode_for_run(run):
    if run < 1:
        raise ValueError('run must be positive')
    return 'load' if run % 4 in (2, 3) else 'probe'


def cycle(fd, payload, record, clock=time.monotonic_ns, cpu=time.process_time_ns):
    def measure(stage, action):
        started, cpu_start = clock(), cpu()
        wall_start = time.time_ns()
        result = action()
        finished, cpu_end = clock(), cpu()
        record(dict(event='syscall', stage=stage, start_ns=started,
                    end_ns=finished, elapsed_ns=finished - started,
                    cpu_ns=cpu_end - cpu_start, wall_start_ns=wall_start))
        return result

    measure('truncate', lambda: os.ftruncate(fd, 0))
    written = measure('pwrite', lambda: os.pwrite(fd, payload, 0))
    if written != len(payload):
        raise RuntimeError(f'short diagnostic write: {written}/{len(payload)}')
    measure('fsync', lambda: os.fsync(fd))


def run(directory, mode, max_cycles=4096, max_seconds=60):
    directory = Path(directory)
    if mode not in ('probe', 'load'):
        raise ValueError('unknown disk mode')
    payload = os.urandom(64 * 1024)
    # O_EXCL prevents overwriting any existing artifact or following a symlink.
    fd = os.open(directory / 'disk-load.data', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with (directory / 'disk-load.jsonl').open('x') as output:
            def record(value):
                output.write(json.dumps(value) + '\n')

            record(dict(event='ready', mode=mode, pid=os.getpid(),
                        max_bytes=max_cycles * len(payload), max_seconds=max_seconds))
            output.flush()
            (directory / 'disk-load-ready').touch()
            waiting_since = time.monotonic()
            # Do not spend the load budget on the 72 missing-table prefix.
            while not (directory / 'show-columns.tsv').exists():
                if (directory / 'workload-finished').exists():
                    raise RuntimeError('workload ended before the first SHOW COLUMNS probe')
                if time.monotonic() - waiting_since > 30:
                    raise TimeoutError('no SHOW COLUMNS probe within disk setup deadline')
                time.sleep(.05)
            started = last_flush = time.monotonic()
            count = 0
            while (count < max_cycles and time.monotonic() - started < max_seconds
                   and not (directory / 'workload-finished').exists()):
                cycle(fd, payload, record)
                count += 1
                if time.monotonic() - last_flush >= 1:
                    output.flush()
                    last_flush = time.monotonic()
                if mode == 'probe':
                    time.sleep(1)
            if count == 0:
                raise RuntimeError('disk experiment had no overlap with workload')
            record(dict(event='finished', cycles=count, bytes_written=count * len(payload),
                        elapsed_seconds=time.monotonic() - started,
                        reason='workload_finished' if (directory / 'workload-finished').exists()
                        else 'bounded_budget', wall_ns=time.time_ns()))
        (directory / 'disk-load-finished').touch()
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--run', type=int, required=True)
    args = parser.parse_args()
    try:
        run(args.directory, mode_for_run(args.run))
    except Exception as exc:
        (args.directory / 'disk-load-error').write_text(repr(exc) + '\n')
        raise


if __name__ == '__main__':
    main()
