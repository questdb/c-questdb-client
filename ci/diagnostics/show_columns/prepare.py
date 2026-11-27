#!/usr/bin/env python3
"""Build a diagnostic overlay from the exact revision; never edit server checkout."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

REVISION = '12a33d651e51e2682e7a448c8db5168fc72dfad3'
SOURCE = 'core/src/main/java/io/questdb/griffin/engine/table/ShowColumnsRecordCursorFactory.java'


def instrument(source):
    def replace(old, new):
        nonlocal source
        if source.count(old) != 1:
            raise ValueError(f'Expected exactly one source anchor: {old!r}')
        source = source.replace(old, new)

    replace('        executionContext.getCircuitBreaker().statefulThrowExceptionIfTrippedTimeThrottled();\n        return cursor.of(executionContext, tableToken, tokenPosition);',
            '''        cursor.probe = ShowColumnsProbe.begin(tableToken.getTableName());
        try {
            cursor.probe.stage("initial-breaker");
            executionContext.getCircuitBreaker().statefulThrowExceptionIfTrippedTimeThrottled();
            cursor.of(executionContext, tableToken, tokenPosition);
            cursor.probe.stage("cursor-ready");
            return cursor;
        } catch (Throwable error) {
            cursor.probe.finish("open-error:" + error.getClass().getSimpleName());
            throw error;
        }''')
    replace('        private CairoTable cairoTable;', '        private CairoTable cairoTable;\n        private ShowColumnsProbe probe;')
    replace('            cairoTable = null;', '            if (probe != null) probe.finish("cursor-close");\n            cairoTable = null;')
    replace('            circuitBreaker.statefulThrowExceptionIfTripped();', '''            probe.stage("iteration-breaker");
            try {
                circuitBreaker.statefulThrowExceptionIfTripped();
            } catch (Throwable error) {
                probe.finish("iteration-error:" + error.getClass().getSimpleName());
                throw error;
            }''')
    replace('            engine.getMetadataCache().hydrateTableOnDemand(tableToken);', '''            probe.stage("hydrate-enter");
            engine.getMetadataCache().hydrateTableOnDemand(tableToken);
            probe.stage("metadata-read-lock-wait");''')
    replace('                final CairoTable cairoTable = metadataRO.getTable(tableToken);', '''                probe.stage("metadata-read-lock-held");
                final CairoTable cairoTable = metadataRO.getTable(tableToken);''')
    replace('                    try (TableReader tableReader = engine.getReader(tableToken)) {\n                        return of(cairoTable, tableReader);\n                    }', '''                    probe.stage("reader-open");
                    try (TableReader tableReader = engine.getReader(tableToken)) {
                        probe.stage("symbol-sizes");
                        of(cairoTable, tableReader);
                        probe.stage("reader-close");
                        return this;
                    }''')
    return source


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--jar', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--annotations', type=Path, default=Path.home() / '.m2/repository/org/jetbrains/annotations/17.0.0/annotations-17.0.0.jar')
    args = parser.parse_args()
    original = subprocess.check_output(['git', '-C', str(args.repo), 'show', f'{REVISION}:{SOURCE}'], text=True)
    patched = instrument(original)
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / 'tmp').mkdir()
    source_dir = args.output / 'src/io/questdb/griffin/engine/table'
    source_dir.mkdir(parents=True)
    (source_dir / 'ShowColumnsRecordCursorFactory.java').write_text(patched)
    helper = Path(__file__).with_name('ShowColumnsProbe.java').read_text()
    (source_dir / 'ShowColumnsProbe.java').write_text(helper)
    classes = args.output / 'classes'
    subprocess.run(['javac', f'-J-Djava.io.tmpdir={args.output / "tmp"}', '--patch-module', f'io.questdb={args.output / "src"}',
                    '-p', os.pathsep.join(map(str, (args.jar, args.annotations))), '-d', str(classes),
                    *map(str, sorted(source_dir.glob('*.java')))], check=True)
    # A generated manifest shadows the server's /META-INF/MANIFEST.MF under
    # --patch-module and makes BuildInformationHolder return "unknown".
    subprocess.run(['jar', f'-J-Djava.io.tmpdir={args.output / "tmp"}', '--create', '--no-manifest', '--file', str(args.output / 'show-columns-probe.jar'),
                    '-C', str(classes), '.'], check=True)
    (args.output / 'identity.json').write_text(json.dumps(dict(
        server_revision=REVISION,
        server_jar_sha256=hashlib.sha256(args.jar.read_bytes()).hexdigest(),
        original_source_sha256=hashlib.sha256(original.encode()).hexdigest(),
        patched_source_sha256=hashlib.sha256(patched.encode()).hexdigest(),
        helper_sha256=hashlib.sha256(helper.encode()).hexdigest(),
    ), indent=2) + '\n')


if __name__ == '__main__':
    main()
