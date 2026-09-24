"""Local fixed-work baseline/overlay comparison; not a macOS reproduction."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import time
import urllib.parse
import urllib.request

from validate import validate


def run(root, jar, overlay):
    root.mkdir(parents=True, exist_ok=False)
    (root / 'data/conf').mkdir(parents=True)
    (root / 'tmp').mkdir()
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    (root / 'data/conf/server.conf').write_text(
        f'http.bind.to=127.0.0.1:{port}\nhttp.min.enabled=false\npg.enabled=false\n'
        'line.tcp.enabled=false\nline.udp.enabled=false\nqwp.udp.enabled=false\n'
        'telemetry.enabled=false\nshared.network.worker.count=3\nshared.write.worker.count=3\n')
    command = ['java', '-Xms128m', '-Xmx512m', '-XX:ActiveProcessorCount=3', '-ea',
               '-XX:+UnlockExperimentalVMOptions', '--add-exports=java.base/jdk.internal.vm=io.questdb',
               f'-Djava.io.tmpdir={root / "tmp"}']
    if overlay:
        command += ['--patch-module', f'io.questdb={overlay}', f'-Dqwp.show.columns.dir={root}']
    command += ['-p', str(jar), '-m', 'io.questdb/io.questdb.ServerMain', '-d', str(root / 'data')]
    if hasattr(os, 'sched_getaffinity'):
        command = ['taskset', '-c', ','.join(map(str, sorted(os.sched_getaffinity(0))[:3]))] + command
    (root / 'command.json').write_text(json.dumps(command))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def sql(query):
        with opener.open(f'http://127.0.0.1:{port}/exec?' + urllib.parse.urlencode({'query': query}), timeout=10) as response:
            return json.load(response)

    with (root / 'server.log').open('w') as log:
        child = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                 env=dict(os.environ, TMPDIR=str(root / 'tmp')))
        try:
            deadline = time.monotonic() + 30
            while True:
                try:
                    sql('select 1')
                    break
                except Exception:
                    if child.poll() is not None or time.monotonic() > deadline:
                        raise RuntimeError(f'Server failed; inspect {root / "server.log"}')
                    time.sleep(.1)
            sql('create table probe (s symbol, v double, ts timestamp) timestamp(ts) partition by day wal')
            build = sql('select build()')
            assert 'QuestDB 10.0.2-SNAPSHOT' in build['dataset'][0][0], build
            assert '12a33d651e51e2682e7a448c8db5168fc72dfad3' in build['dataset'][0][0], build
            results = [build]
            for _ in range(3):
                results.append(sql('show columns from probe'))
            sql('alter table probe add column extra long')
            results.append(sql('show columns from probe'))
            # Allow asynchronous telemetry to flush before terminating the JVM.
            time.sleep(1.2)
            if overlay:
                validate(root)
                stages = (root / 'show-columns.tsv').read_text()
                for stage in ('initial-breaker', 'hydrate-enter', 'metadata-read-lock-wait',
                              'metadata-read-lock-held', 'reader-open', 'symbol-sizes',
                              'reader-close', 'cursor-ready', 'iteration-breaker', 'cursor-close'):
                    assert '\t' + stage + '\t' in stages, stage
                assert not (root / 'show-columns-slow').exists()
            return results
        finally:
            child.terminate()
            try:
                child.wait(timeout=15)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--jar', type=Path, required=True)
    parser.add_argument('--overlay', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = args.output.resolve()
    baseline = run(root / 'baseline', args.jar.resolve(), None)
    instrumented = run(root / 'instrumented', args.jar.resolve(), args.overlay.resolve())
    assert baseline == instrumented, (baseline, instrumented)
    print('PASS: identical SQL results; all query stages observed; no false slow trigger')
