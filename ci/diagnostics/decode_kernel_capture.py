"""Decode retained kernel samples with retained symbol information. No workload."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

SOURCES = (
    (268494, 'qwp-ws-macos-show-columns/run-3/kernel-stacks/spindump.raw',
     '7afefee742916e36b06f36eafacd2a5e65cce02a1687ee32c01c0bc90e80db14', 'spindump.raw'),
    (268472, 'qwp-ws-macos-show-columns/run-4/kernel-stacks/spindump.txt',
     'f880f248ccd07c49254441eb14d95ead1617077d2f0834e987abf9d0003715ea', 'symbols.spindump'),
)


def extract_member(archive_path, member, expected_hash, destination):
    with zipfile.ZipFile(archive_path) as archive:
        if archive.getinfo(member).file_size > 64 * 1024**2:
            raise RuntimeError('oversized decoder input')
        data = archive.read(member)
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected_hash:
        raise RuntimeError(f'decoder input hash mismatch: {actual}')
    destination.write_bytes(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--symbols-only', action='store_true',
                        help='Fetch the pinned symbol report before a workload; do not decode or sample')
    parser.add_argument('--source-directory', type=Path, default=Path('build-exp/kernel-decode-input'))
    args = parser.parse_args()
    directory = args.directory.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    (directory / 'tmp').mkdir()
    if shutil.disk_usage(directory).free < 2 * 1024**3:
        raise RuntimeError('less than 2 GiB free for decoder inputs')
    source_dir = args.source_directory.resolve()
    source_dir.mkdir(parents=True, exist_ok=False)
    sources = SOURCES[1:] if args.symbols_only else SOURCES
    for build, member, digest, filename in sources:
        archive = source_dir / f'{build}.zip'
        url = (f'https://dev.azure.com/questdb/questdb/_apis/build/builds/{build}/artifacts'
               '?artifactName=qwp-ws-macos-show-columns&api-version=7.1&%24format=zip')
        subprocess.run(['curl', '--fail', '--location', '--silent', '--show-error',
                        '--max-time', '90', url, '--output', str(archive)],
                       timeout=95, check=True)
        extract_member(archive, member, digest, directory / filename)
    (directory / 'inputs.json').write_text(json.dumps(sources, indent=2) + '\n')
    if args.symbols_only:
        return
    controller = Path(__file__).with_name('kernel_wait_preflight.py').resolve()
    with (directory / 'decode.log').open('w') as log:
        subprocess.run(['sudo', '-n', 'env', f'TMPDIR={directory / "tmp"}',
                        sys.executable, str(controller), str(directory), '--decode',
                        '--symbols', str(directory / 'symbols.spindump')],
                       stdout=log, stderr=subprocess.STDOUT, timeout=75, check=True,
                       env=dict(os.environ, TMPDIR=str(directory / 'tmp')))


if __name__ == '__main__':
    main()
