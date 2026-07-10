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
    return next(iter(build_dir.glob(f'**/{name}{exe_suffix}')), None)


def run_cargo_tests():
    """The questdb-rs / questdb-rs-ffi cargo test matrix. Pure Rust: needs no
    CMake build and no running QuestDB."""
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
    run_cmd('cargo', 'test', '--lib', '--examples', '--no-default-features',
            '--features=ring-crypto,tls-webpki-certs,sync-reader',
            '--', '--nocapture', cwd='questdb-rs')
    run_cmd('cargo', 'test', '--features=almost-all-features',
            '--', '--nocapture', cwd='questdb-rs')
    run_cmd('cargo', 'test',
            '--features=almost-all-features,arrow,polars',
            '--', '--nocapture', cwd='questdb-rs')
    run_cmd('cargo', 'test', '--no-default-features',
            '--features=ring-crypto,tls-webpki-certs,sync-sender-qwp-ws,sync-reader-qwp-ws,arrow',
            '--', '--nocapture', cwd='questdb-rs')
    run_cmd('cargo', 'test', cwd='questdb-rs-ffi')
    run_cmd('cargo', 'test', '--features=arrow', cwd='questdb-rs-ffi')


def run_cpp_tests():
    """The C/C++ test binaries from the CMake `build` tree. All are
    broker-independent or skip-on-no-broker, so no running QuestDB is
    required."""
    build_dir = pathlib.Path('build')
    exe_suffix = '.exe' if platform.system() == 'Windows' else ''
    cpp_tests = [
        'test_line_sender',
        'test_reader_offline',
        'test_reader_mock',
        'reader_c_smoke',
        'test_reader',  # live-broker; skips per-test when no broker reachable
        'test_arrow_c',
        'test_arrow_egress',
        'test_arrow_ingress',
        'test_column_sender',
    ]
    # Each C++ target may also have a `_cxx20` twin (QUESTDB_TEST_CXX20_VARIANTS);
    # run it too when present so the C++20 header paths are exercised.
    for name in cpp_tests:
        base = find_binary(build_dir, name, exe_suffix)
        if base is None:
            sys.stderr.write(f'Missing expected test binary: {name}\n')
            sys.exit(1)
        run_cmd(str(base))
        twin = find_binary(build_dir, f'{name}_cxx20', exe_suffix)
        if twin is not None:
            run_cmd(str(twin))


def run_integration_tests():
    """system_test against a from-source build of QuestDB master (--repo):
    master is ahead of the latest release, so this catches server-side
    regressions before they ship. QWP/Arrow is released as of 9.4.3, so the
    `--versions` alternative below now exercises the same features against a
    fixed release; swap to it to test a release instead of master."""
    system_test_path = pathlib.Path('system_test') / 'test.py'
    run_cmd('python3', str(system_test_path), 'run', '--repo', './questdb', '-v')
    # qdb_v = '9.4.3'  # first release shipping QWP/Arrow; QWP/WS needs >= this
    # run_cmd('python3', str(system_test_path), 'run', '--versions', qdb_v, '-v')


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else 'all'
    if mode not in ('all', 'unit', 'cargo', 'cpp', 'integration'):
        sys.stderr.write(
            f'Unknown mode {mode!r}; expected one of: '
            'cargo, cpp, unit, integration (or no argument for all).\n')
        sys.exit(2)
    if mode in ('all', 'unit', 'cargo'):
        run_cargo_tests()
    if mode in ('all', 'unit', 'cpp'):
        run_cpp_tests()
    if mode in ('all', 'integration'):
        run_integration_tests()


if __name__ == '__main__':
    main()
