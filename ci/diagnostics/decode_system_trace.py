"""Export unexamined VM/scheduler data from an existing recording, no workload.

The source is pinned to build 268363/run-4's already captured short ping stall.
Its interpretation must not be promoted to the original build 266336's cause.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'system_test'))
from qwp_ws_trace_export import inspect_rows

SOURCE_URL = ('https://dev.azure.com/questdb/questdb/_apis/build/builds/268363/artifacts'
              '?artifactName=qwp-ws-macos-system-trace&api-version=7.1&%24format=zip')
SOURCE_HASH = '374b4d0a7d37d315c4f1c10b6a609ff568b405985ed6398a46af8946dbc6be70'
PREFIX = 'qwp-ws-macos-system-trace/run-4/'


def selections(toc):
    result = []
    for index, table in enumerate(ET.parse(toc).findall('./run/data/table'), 1):
        schema = table.get('schema')
        codes = table.get('codes', '')
        if (schema in ('context-switch', 'virtual-memory', 'system-load')
                or schema == 'kdebug' and ('0x1,0x30' in codes or '0x1,0x40' in codes)):
            result.append((index, dict(table.attrib)))
    if not {'context-switch', 'virtual-memory'} <= {r[1]['schema'] for r in result}:
        raise RuntimeError('recording lacks the required VM/context-switch tables')
    return result


def extract(archive_path, destination):
    with zipfile.ZipFile(archive_path) as archive:
        for item in archive.infolist():
            if not item.filename.startswith(PREFIX):
                continue
            relative = PurePosixPath(item.filename[len(PREFIX):])
            if '..' in relative.parts or relative.is_absolute():
                raise ValueError('unsafe artifact path')
            if relative == PurePosixPath('.'):
                continue
            if relative.parts[0] != 'system.trace' and relative.name not in (
                    'system-trace-toc.xml', 'watchdog.jsonl', 'jvm-pauses.log'):
                continue
            target = destination / relative
            if item.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(item) as src, target.open('xb') as dst:
                    shutil.copyfileobj(src, dst)


def content_hash(archive_path):
    # Azure may regenerate ZIP headers. Pin names and bytes, not packaging.
    digest = hashlib.sha256()
    with zipfile.ZipFile(archive_path) as archive:
        for name in sorted(n for n in archive.namelist()
                           if n.startswith(PREFIX) and not n.endswith('/')):
            with archive.open(name) as stream:
                file_digest = hashlib.sha256()
                for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                    file_digest.update(chunk)
                file_hash = file_digest.digest()
            digest.update(name.encode() + b'\0' + file_hash)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--source-directory', type=Path,
                        default=Path('build-exp/trace-decode-input'))
    args = parser.parse_args()
    directory = args.directory.resolve()
    directory.mkdir(exist_ok=False, parents=True)
    source_directory = args.source_directory.resolve()
    source_directory.mkdir(exist_ok=False, parents=True)
    if shutil.disk_usage(source_directory).free < 2 * 1024**3:
        raise RuntimeError('insufficient space to download and decode the recording')
    source = source_directory / 'source.zip'
    subprocess.run(['curl', '--fail', '--location', '--silent', '--show-error',
                    '--max-time', '90', SOURCE_URL, '--output', str(source)], check=True, timeout=95)
    actual_hash = content_hash(source)
    if actual_hash != SOURCE_HASH:
        raise RuntimeError(f'recording hash differs: {actual_hash}')
    extract(source, source_directory)
    for name in ('system-trace-toc.xml', 'watchdog.jsonl', 'jvm-pauses.log'):
        shutil.copyfile(source_directory / name, directory / name)
    shutil.copyfile(source_directory / 'system.trace/form.template', directory / 'form.template')
    toc = directory / 'decoded-toc.xml'
    deadline = time.monotonic() + 240
    results = []
    with (directory / 'export.log').open('w') as log:
        # Use this xctrace version's actual table ordering, not stale positions
        # from a TOC produced by the original worker's Xcode installation.
        subprocess.run(['/usr/bin/xcrun', 'xctrace', 'export', '--input',
                        str(source_directory / 'system.trace'), '--toc', '--output', str(toc)],
                       stdout=log, stderr=subprocess.STDOUT, timeout=30, check=True)
        target = ET.parse(toc).find('./run/info/target/process')
        pid = int(target.get('pid'))
        if pid != 26020:
            raise RuntimeError(f'unexpected recorded target PID: {pid}')
        for index, attributes in selections(toc):
            if shutil.disk_usage(directory).free < 2 * 1024**3:
                raise RuntimeError('insufficient space for trace export')
            path = directory / f'raw-table-{index}.xml'
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('export-only budget exhausted')
            subprocess.run(['/usr/bin/xcrun', 'xctrace', 'export', '--input',
                            str(source_directory / 'system.trace'), '--xpath',
                            f'/trace-toc/run[1]/data/table[{index}]', '--output', str(path)],
                           stdout=log, stderr=subprocess.STDOUT,
                           timeout=min(45, remaining), check=True)
            results.append(dict(file=path.name, attributes=attributes,
                                **inspect_rows(path, pid, deadline)))
    (directory / 'export-summary.json').write_text(json.dumps(
        dict(source_build=268363, source_attempt=4, source_sha256=actual_hash,
             target_pid=pid, tables=results), indent=2) + '\n')


if __name__ == '__main__':
    main()
