#!/usr/bin/env python3

"""
Format all the C and C++ code using `clang-format`.
If --check is passed, check for formatting issues instead of modifying files.

CI and local runs must use the same clang-format version (see
`ci/run_tests_pipeline.yaml`): `pipx install clang-format==21.1.8`.
"""

import sys
sys.dont_write_bytecode = True
import subprocess
import glob
import os.path

# Vendored third-party code keeps its upstream formatting.
VENDORED = {'doctest.h'}

FILES = sorted(
    f
    for f in glob.glob('include/questdb/**/*.h', recursive=True)
    + glob.glob('include/questdb/**/*.hpp', recursive=True)
    + glob.glob('cpp_test/*.c')
    + glob.glob('cpp_test/*.cpp')
    + glob.glob('cpp_test/*.h')
    + glob.glob('cpp_test/*.hpp')
    + glob.glob('examples/*.c')
    + glob.glob('examples/*.cpp')
    + glob.glob('examples/*.h')
    + glob.glob('examples/*.hpp')
    if os.path.basename(f) not in VENDORED
)

if __name__ == '__main__':
    check_mode = '--check' in sys.argv
    command = ['clang-format', '--style=file']
    if check_mode:
        command += ['--dry-run', '--Werror']
    else:
        command += ['-i']
    command += FILES
    subprocess.check_call(command)
