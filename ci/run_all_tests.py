#!/usr/bin/env python3

"""
This script is a hacky workaround the fact that figuring out the right CTest
incantation for a multi-configuration build (i.e. a VS Studio build) is tricky
and calling `cd build; ctest -C Release` was causing a

    1/2 Test #1: test_line_sender .................***Not Run   0.00 sec
        Start 2: system_test

error.

The CI only ever builds one config, so instead it's perfectly fine to just
look for the `test_line_sender` binary and run it.
"""

import sys
sys.dont_write_bytecode = True

import pathlib
import platform
import subprocess


def run_cmd(*args, cwd=None):
    sys.stderr.write(f'About to run: {args!r}:\n')
    try:
        subprocess.check_call(args, cwd=cwd)
        sys.stderr.write(f'Success running: {args!r}.\n')
    except subprocess.CalledProcessError as cpe:
        sys.stderr.write(f'Command {args!r} failed with return code {cpe.returncode}.\n')
        sys.exit(cpe.returncode)


def main():
    build_dir = pathlib.Path('build')
    exe_suffix = '.exe' if platform.system() == 'Windows' else ''
    test_line_sender_path = next(iter(
        build_dir.glob(f'**/test_line_sender{exe_suffix}')))
    system_test_path = pathlib.Path('system_test') / 'test.py'
    qdb_v = '7.3.2'  # The version of QuestDB we'll test against.

    run_cmd('cargo', 'test', '--all-features', '--', '--nocapture', cwd='questdb-rs')
    run_cmd(str(test_line_sender_path))
    run_cmd('python3', str(system_test_path), 'run', '--versions', qdb_v, '-v')


if __name__ == '__main__':
    main()