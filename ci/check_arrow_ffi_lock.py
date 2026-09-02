#!/usr/bin/env python3
"""Verify the Arrow implementation pinned into questdb-rs-ffi artifacts."""

import collections
import pathlib
import tomllib


EXPECTED_ARROW_VERSION = '59.0.0'
EXPECTED_ARROW_REQUIREMENT = f'={EXPECTED_ARROW_VERSION}'
# Arrow 59.0.0's implementation graph is immutable. List its packages
# explicitly instead of matching every `arrow-*` crate: unrelated packages
# such as `arrow-format` do not share Arrow's release version.
EXPECTED_ARROW_FAMILY = frozenset({
    'arrow',
    'arrow-arith',
    'arrow-array',
    'arrow-buffer',
    'arrow-cast',
    'arrow-data',
    'arrow-ord',
    'arrow-row',
    'arrow-schema',
    'arrow-select',
    'arrow-string',
})
REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
FFI_ROOT = REPO_ROOT / 'questdb-rs-ffi'


def fail(message):
    raise SystemExit(f'Arrow FFI lock guard failed: {message}')


def main():
    with (FFI_ROOT / 'Cargo.toml').open('rb') as manifest_file:
        manifest = tomllib.load(manifest_file)
    arrow_dependency = manifest.get('dependencies', {}).get('arrow')
    if not isinstance(arrow_dependency, dict):
        fail('questdb-rs-ffi must declare arrow as a dependency table')
    requirement = arrow_dependency.get('version')
    if requirement != EXPECTED_ARROW_REQUIREMENT:
        fail(
            'questdb-rs-ffi arrow requirement is '
            f'{requirement!r}, expected {EXPECTED_ARROW_REQUIREMENT!r}')

    with (FFI_ROOT / 'Cargo.lock').open('rb') as lock_file:
        lock = tomllib.load(lock_file)
    packages = lock.get('package', [])
    family = sorted(
        (package.get('name'), package.get('version'))
        for package in packages
        if package.get('name') in EXPECTED_ARROW_FAMILY)
    counts = collections.Counter(name for name, _ in family)
    missing = sorted(EXPECTED_ARROW_FAMILY - counts.keys())
    duplicates = sorted(
        name for name, count in counts.items() if count != 1)
    if missing or duplicates:
        fail(
            'Cargo.lock does not contain exactly one copy of every Arrow 59 '
            f'implementation package: missing={missing!r}, '
            f'duplicates={duplicates!r}')
    mismatches = [(name, version) for name, version in family
                  if version != EXPECTED_ARROW_VERSION]
    if mismatches:
        fail(f'Arrow family versions are not pinned to {EXPECTED_ARROW_VERSION}: '
             f'{mismatches!r}')

    print(
        f'Arrow FFI lock guard passed: {len(family)} packages at '
        f'{EXPECTED_ARROW_VERSION}')


if __name__ == '__main__':
    main()
