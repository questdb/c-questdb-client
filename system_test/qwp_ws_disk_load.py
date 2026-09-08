"""Bounded filesystem perturbation with per-call elapsed and process CPU clocks.

Only touches a newly created file in this attempt's artifact directory (1 MiB
maximum with the mapped pattern; 64 KiB with the original pwrite pattern).
This generates filesystem work; it does not emulate a known hosted-disk quota.
"""
import argparse
import ctypes
import functools
import json
import mmap
import os
from pathlib import Path
import time


@functools.cache
def mapping_api():
    # CPython mmap.__new__ issues F_FULLFSYNC on macOS. Raw libc calls are
    # essential here: we are measuring dirty mapping/unmap/shrink ordering,
    # not an implicit full disk flush. Supported diagnostic hosts are LP64.
    library = ctypes.CDLL(None, use_errno=True)
    library.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                            ctypes.c_int, ctypes.c_int, ctypes.c_int64]
    library.mmap.restype = ctypes.c_void_p
    library.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    library.munmap.restype = ctypes.c_int
    return library


def map_shared(fd, size):
    address = mapping_api().mmap(None, size, mmap.PROT_READ | mmap.PROT_WRITE,
                                 mmap.MAP_SHARED, fd, 0)
    if address == ctypes.c_void_p(-1).value:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return address


def unmap(address, size):
    if mapping_api().munmap(address, size) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def mode_for_run(run):
    if run < 1:
        raise ValueError('run must be positive')
    return 'load' if run % 4 in (2, 3) else 'probe'


def cycle(fd, payload, record, clock=time.monotonic_ns, cpu=time.process_time_ns,
          pattern='pwrite'):
    def measure(stage, action):
        started, cpu_start = clock(), cpu()
        wall_start = time.time_ns()
        result = action()
        finished, cpu_end = clock(), cpu()
        record(dict(event='syscall', stage=stage, start_ns=started,
                    end_ns=finished, elapsed_ns=finished - started,
                    cpu_ns=cpu_end - cpu_start, wall_start_ns=wall_start))
        return result

    if pattern == 'mapped':
        # Match the ordering of MemoryCMARWImpl.close: dirty mapped data,
        # unmap, then shrink. No msync/fsync, which would drain the dirty pages
        # before the operation we want to observe. Growth is sparse, not a
        # claim to reproduce QuestDB's physical F_PREALLOCATE behavior.
        measure('grow', lambda: os.ftruncate(fd, 1024 * 1024))
        mapping = measure('mmap', lambda: map_shared(fd, 1024 * 1024))
        try:
            measure('mapped_write', lambda: ctypes.memmove(mapping, payload, len(payload)))
        finally:
            measure('munmap', lambda: unmap(mapping, 1024 * 1024))
        measure('shrink', lambda: os.ftruncate(fd, len(payload)))
        return
    if pattern != 'pwrite':
        raise ValueError('unknown disk pattern')
    measure('truncate', lambda: os.ftruncate(fd, 0))
    written = measure('pwrite', lambda: os.pwrite(fd, payload, 0))
    if written != len(payload):
        raise RuntimeError(f'short diagnostic write: {written}/{len(payload)}')
    measure('fsync', lambda: os.fsync(fd))


def run(directory, mode, max_cycles=4096, max_seconds=60, pattern='pwrite'):
    directory = Path(directory)
    if mode not in ('probe', 'load'):
        raise ValueError('unknown disk mode')
    if pattern not in ('pwrite', 'mapped'):
        raise ValueError('unknown disk pattern')
    if pattern == 'mapped':
        mapping_api()  # Resolve functions before workload timing starts.
    payload = os.urandom(64 * 1024)
    # O_EXCL prevents overwriting any existing artifact or following a symlink.
    fd = os.open(directory / 'disk-load.data', os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with (directory / 'disk-load.jsonl').open('x') as output:
            def record(value):
                output.write(json.dumps(value) + '\n')

            record(dict(event='ready', mode=mode, pattern=pattern, pid=os.getpid(),
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
                cycle(fd, payload, record, pattern=pattern)
                count += 1
                if time.monotonic() - last_flush >= 1:
                    output.flush()
                    last_flush = time.monotonic()
                if mode == 'probe':
                    time.sleep(1)
                elif pattern == 'mapped':
                    # Pace the finite byte budget across the workload, instead
                    # of spending all 4096 cycles in its first few seconds.
                    time.sleep(.01)
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
    parser.add_argument('--pattern', choices=('pwrite', 'mapped'), default='pwrite')
    args = parser.parse_args()
    try:
        run(args.directory, mode_for_run(args.run), pattern=args.pattern)
    except Exception as exc:
        (args.directory / 'disk-load-error').write_text(repr(exc) + '\n')
        raise


if __name__ == '__main__':
    main()
