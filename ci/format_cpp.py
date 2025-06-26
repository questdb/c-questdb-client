#!/usr/bin/env python3

"""
Format all the C and C++ code using `clang-format`.
If --check is passed, check for formatting issues instead of modifying files.
"""

import sys
sys.dont_write_bytecode = True
import subprocess
import glob

FILES = [
    'include/questdb/ingress/line_sender.h',
    'include/questdb/ingress/line_sender.hpp',
    'cpp_test/build_env.h',
    'cpp_test/mock_server.hpp',
    'cpp_test/mock_server.cpp',
    'cpp_test/test_line_sender.cpp',
]

# Also include all examples.
FILES += glob.glob('examples/*.c')
FILES += glob.glob('examples/*.cpp')
FILES += glob.glob('examples/*.h')
FILES += glob.glob('examples/*.hpp')

if __name__ == '__main__':
    check_mode = '--check' in sys.argv
    command = [
        'clang-format',
        '--style=file',
        '--dry-run' if check_mode else '-i'
        ] + FILES
    subprocess.check_call(command)
