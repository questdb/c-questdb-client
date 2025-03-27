#!/usr/bin/env python3

"""
Format all the and C++ code using `clang-format`.
"""

import sys
sys.dont_write_bytecode = True
import subprocess

FILES = [
    'include/questdb/ingress/line_sender.h',
    'include/questdb/ingress/line_sender.hpp',
    'cpp_test/build_env.h',
    'cpp_test/mock_server.hpp',
    'cpp_test/mock_server.cpp',
    'cpp_test/test_line_sender.cpp',
]

if __name__ == '__main__':
    subprocess.check_call(['clang-format', '-i', '--style=file'] + FILES)
