"""Check hosted-Mac kernel-stack access before paying for another server build."""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import time


def command(directory):
    return ['/usr/sbin/spindump', '-notarget', '3', '20',
            '-file', str(directory / 'spindump.txt'), '-timeline', '-symbolicate']


def inspect_report(report):
    # This is an access check, not proof of a filesystem bottleneck. Keep the
    # actual text so kernel symbols and thread identities can be inspected.
    frames = [line.strip() for line in report.splitlines()
              if re.match(r'^\s*\d+\s+\*', line)]
    named = [line for line in frames if re.match(r'^\d+\s+\*[A-Za-z_]', line)]
    return dict(kernel_frame_lines=len(frames), named_kernel_frame_lines=len(named),
                apfs_present='apfs_transaction_flusher' in report,
                virtio_present='AppleVirtIO' in report,
                kernel_examples=named[:10])


def workload(directory):
    payload = os.urandom(65536)
    fd = os.open(directory / 'smoke.data', os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        (directory / 'workload-ready').touch()
        started = time.monotonic()
        with (directory / 'workload.jsonl').open('x') as log:
            # At most 6.25 MiB application writes, one small file, ten seconds
            # before starting another cycle. No full-disk or pressure stress.
            for cycle in range(100):
                if time.monotonic() - started >= 10:
                    break
                for name, operation in (
                        ('truncate', lambda: os.ftruncate(fd, 0)),
                        ('write', lambda: os.pwrite(fd, payload, 0)),
                        ('fsync', lambda: os.fsync(fd))):
                    begin = time.monotonic_ns()
                    result = operation()
                    if name == 'write' and result != len(payload):
                        raise RuntimeError('short smoke write')
                    log.write(json.dumps(dict(cycle=cycle, stage=name,
                        start_ns=begin, elapsed_ns=time.monotonic_ns()-begin)) + '\n')
                    log.flush()
                time.sleep(0.05)
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--workload', action='store_true')
    parser.add_argument('--record', action='store_true')
    args = parser.parse_args()
    if args.record:
        # This small controller runs as root, so subprocess timeout can kill
        # and reap its actual recorder child, not merely an intervening sudo.
        subprocess.run(command(args.directory), timeout=60, check=True)
        return
    if args.workload:
        workload(args.directory)
        return
    if sys.platform != 'darwin':
        raise RuntimeError('kernel-stack preflight requires macOS')
    directory = args.directory.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    (directory / 'tmp').mkdir()
    environment = dict(os.environ, TMPDIR=str(directory / 'tmp'))
    if shutil.disk_usage(directory).free < 2 * 1024**3:
        raise RuntimeError('less than 2 GiB free for recorder preflight')
    help_result = subprocess.run(['/usr/sbin/spindump', '-h'], stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, text=True, timeout=10,
                                 env=environment)
    (directory / 'spindump-help.txt').write_text(help_result.stdout)
    for option in ('-notarget', '-file', '-timeline', '-symbolicate'):
        if option not in help_result.stdout.lower():
            raise RuntimeError(f'installed recorder does not advertise {option}')
    child = None
    with (directory / 'workload-process.log').open('x') as child_log:
        try:
            child = subprocess.Popen([sys.executable, __file__, str(directory), '--workload'],
                                     stdout=child_log, stderr=subprocess.STDOUT, env=environment)
            deadline = time.monotonic() + 5
            while not (directory / 'workload-ready').exists():
                if child.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError('filesystem smoke helper did not become ready')
                time.sleep(0.05)
            with (directory / 'recorder.log').open('x') as recorder_log:
                subprocess.run(['sudo', '-n', 'env',
                                f'TMPDIR={directory / "tmp"}', sys.executable,
                                str(Path(__file__).resolve()), str(directory), '--record'],
                               stdout=recorder_log,
                               stderr=subprocess.STDOUT, timeout=75, check=True,
                               env=environment)
            child.wait(timeout=15)
            if child.returncode:
                raise RuntimeError(f'smoke helper failed: {child.returncode}')
        finally:
            if child is not None and child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=3)
    report = (directory / 'spindump.txt').read_text(errors='replace')
    result = dict(platform=platform.platform(), command=command(directory),
                  **inspect_report(report))
    (directory / 'validation.json').write_text(json.dumps(result, indent=2) + '\n')
    if not result['named_kernel_frame_lines']:
        raise RuntimeError('no named kernel frames: do not claim kernel-wait access')


if __name__ == '__main__':
    main()
