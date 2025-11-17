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

def main():
    build_dir = pathlib.Path('build')
    exe_suffix = '.exe' if platform.system() == 'Windows' else ''
    test_line_sender_path = next(iter(
        build_dir.glob(f'**/test_line_sender{exe_suffix}')))
    build_cxx20_dir = pathlib.Path('build_CXX20')
    test_line_sender_path_CXX20 = next(iter(
        build_cxx20_dir.glob(f'**/test_line_sender{exe_suffix}')))

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
    run_cmd(str(test_line_sender_path))
    run_cmd(str(test_line_sender_path_CXX20))
    run_cmd('python3', str(system_test_path), 'run', '--versions', qdb_v, '-v')
    # run_cmd('python3', str(system_test_path), 'run', '--repo', './questdb', '-v')


if __name__ == '__main__':
    main()
