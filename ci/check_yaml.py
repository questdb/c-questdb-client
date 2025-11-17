#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True
import yaml

paths = [
    'compile.yaml',
    'run_tests_pipeline.yaml'
]


for path in paths:
    sys.stdout.write(f'loading {path}  ')
    with open(path, 'r') as file:
        yaml.load(file, Loader=yaml.SafeLoader)
    sys.stdout.write('  ..ok\n')
