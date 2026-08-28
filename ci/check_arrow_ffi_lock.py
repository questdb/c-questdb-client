#!/usr/bin/env python3
"""Verify the Arrow implementation pinned into questdb-rs-ffi artifacts."""

import pathlib
import tomllib


EXPECTED_ARROW_VERSION = '59.0.0'
EXPECTED_ARROW_REQUIREMENT = f'={EXPECTED_ARROW_VERSION}'
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
    arrow_packages = [package for package in packages
                      if package.get('name') == 'arrow']
    if len(arrow_packages) != 1:
        fail(f'Cargo.lock contains {len(arrow_packages)} arrow packages, expected 1')
    if arrow_packages[0].get('version') != EXPECTED_ARROW_VERSION:
        fail(
            f'Cargo.lock resolves arrow {arrow_packages[0].get("version")!r}, '
            f'expected {EXPECTED_ARROW_VERSION!r}')

    family = sorted(
        (package.get('name'), package.get('version'))
        for package in packages
        if package.get('name') == 'arrow'
        or str(package.get('name', '')).startswith('arrow-'))
    mismatches = [(name, version) for name, version in family
                  if version != EXPECTED_ARROW_VERSION]
    if mismatches:
        fail(f'Arrow family versions are not pinned to {EXPECTED_ARROW_VERSION}: '
             f'{mismatches!r}')
    if not family:
        fail('Cargo.lock contains no Arrow family packages')

    print(
        f'Arrow FFI lock guard passed: {len(family)} packages at '
        f'{EXPECTED_ARROW_VERSION}')


if __name__ == '__main__':
    main()
