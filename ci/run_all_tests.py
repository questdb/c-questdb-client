#!/usr/bin/env python3

import sys
sys.dont_write_bytecode = True

import pathlib
import platform
import subprocess
import shlex


def run_cmd(*args, cwd=None):
    args_str =  shlex.join(args)
    sys.stderr.write(f'About to run: {args_str}:\n')
    try:
        subprocess.check_call(args, cwd=cwd)
        sys.stderr.write(f'Success running: {args_str}.\n')
    except subprocess.CalledProcessError as cpe:
        sys.stderr.write(f'Command `{args_str}` failed with return code {cpe.returncode}.\n')
        sys.exit(cpe.returncode)

def find_binary(build_dir, name, exe_suffix):
    return next(iter(build_dir.glob(f'**/{name}{exe_suffix}')))


def main():
    build_dir = pathlib.Path('build')
    build_cxx20_dir = pathlib.Path('build_CXX20')
    exe_suffix = '.exe' if platform.system() == 'Windows' else ''

    # Test binaries to invoke from each build tree. All are
    # broker-independent or skip-on-no-broker, so they are safe to run
    # unconditionally in CI.
    cpp_tests = [
        'test_line_sender',
        'test_line_reader_offline',
        'test_line_reader_mock',
        'line_reader_c_smoke',
        'test_line_reader',  # live-broker; skips per-test when no broker reachable
    ]
    test_paths = [
        (d, find_binary(d, name, exe_suffix))
        for d in (build_dir, build_cxx20_dir)
        for name in cpp_tests
    ]

    system_test_path = pathlib.Path('system_test') / 'test.py'
    qdb_v = '9.2.0'  # The version of QuestDB we'll test against.

    run_cmd('cargo', 'test',
            '--', '--nocapture', cwd='questdb-rs')
    run_cmd('cargo', 'test',
            '--no-default-features',
            '--features=aws-lc-crypto,tls-native-certs,sync-sender',
            '--', '--nocapture', cwd='questdb-rs')
    run_cmd('cargo', 'test', '--no-default-features',
            '--features=ring-crypto,tls-native-certs,sync-sender',
            '--', '--nocapture', cwd='questdb-rs')
    run_cmd('cargo', 'test', '--no-default-features',
            '--features=ring-crypto,tls-webpki-certs,sync-sender-tcp',
            '--', '--nocapture', cwd='questdb-rs')
    run_cmd('cargo', 'test', '--no-default-features',
            '--features=ring-crypto,tls-webpki-certs,sync-sender-http',
            '--', '--nocapture', cwd='questdb-rs')
    run_cmd('cargo', 'test', '--features=almost-all-features',
            '--', '--nocapture', cwd='questdb-rs')
    run_cmd('cargo', 'test', cwd='questdb-rs-ffi')
    for _, path in test_paths:
        run_cmd(str(path))
    run_cmd('python3', str(system_test_path), 'run', '--versions', qdb_v, '-v')
    # run_cmd('python3', str(system_test_path), 'run', '--repo', './questdb', '-v')


if __name__ == '__main__':
    main()
