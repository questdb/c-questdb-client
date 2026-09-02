#!/usr/bin/env python3

# Exercises the non-default ends of the arrow (`>=58, <60`) and polars
# (`>=0.52, <0.55`) version ranges, which the main run_all_tests.py leaves
# untested (a clean CI job's default resolve is the newest of each). Only
# `questdb-rs` is built: polars is absent from questdb-rs-ffi, and the FFI's
# version-specific Arrow surface is covered by its locked test builds.
#
# Pins via a Cargo.toml version rewrite + fresh resolve rather than `cargo
# update --precise`: polars and polars-arrow are both direct deps, so a
# targeted --precise pins one and lets the other float, splitting the family
# into two incompatible copies. A full resolve off an exact `=x.y.z` unifies.

import sys
sys.dont_write_bytecode = True

import pathlib
import re
import subprocess

RS = pathlib.Path('questdb-rs')
TOML = RS / 'Cargo.toml'
LOCK = RS / 'Cargo.lock'
FEATURES = '--features=almost-all-features,arrow,polars'


def run(*args):
    sys.stderr.write('+ ' + ' '.join(args) + '\n')
    subprocess.check_call(args, cwd=str(RS))


def pin_dep(text, name, version):
    pat = re.compile(r'(?m)^(' + re.escape(name) + r' = \{ version = )"[^"]*"')
    new, n = pat.subn(r'\1"=' + version + '"', text)
    if n != 1:
        sys.exit(f'expected exactly one `{name}` dependency line, matched {n}')
    return new


def pin_and_test(label, pins):
    original = TOML.read_text()
    text = original
    for name, version in pins:
        text = pin_dep(text, name, version)
    TOML.write_text(text)
    LOCK.unlink(missing_ok=True)
    try:
        sys.stderr.write(f'=== version matrix: {label} ===\n')
        # `--lib --tests` skips examples: they target the newest polars only.
        run('cargo', 'test', '--lib', '--tests', FEATURES, '--', '--nocapture')
    finally:
        TOML.write_text(original)
        LOCK.unlink(missing_ok=True)


def main():
    saved_lock = LOCK.read_bytes() if LOCK.exists() else None
    try:
        pin_and_test('arrow 58.0.0', [('arrow', '58.0.0')])
        pin_and_test(
            'polars 0.52.0',
            [('polars', '0.52.0'), ('polars-arrow', '0.52.0')])
        pin_and_test(
            'polars 0.53.0',
            [('polars', '0.53.0'), ('polars-arrow', '0.53.0')])
    finally:
        if saved_lock is None:
            LOCK.unlink(missing_ok=True)
        else:
            LOCK.write_bytes(saved_lock)


if __name__ == '__main__':
    main()
