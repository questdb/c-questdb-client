#!/usr/bin/env python3
"""Fixed-work local fault experiment, not a macOS/disk reproduction."""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / 'system_test'))
import questdb_line_sender as qls


def await_condition(predicate, timeout=30):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            raise TimeoutError('Condition not reached')
        time.sleep(0.02)


def fields(path):
    return dict(line.split('=', 1) for line in path.read_text().splitlines() if '=' in line and not line.startswith('['))


def run(args):
    directory = args.directory.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    (directory / 'tmp').mkdir()
    (directory / 'data/conf').mkdir(parents=True)
    (directory / 'mode').write_text(args.mode)
    (directory / 'delay-ms').write_text(str(args.delay_ms))
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    (directory / 'data/conf/server.conf').write_text(f'''
http.bind.to=127.0.0.1:{port}
http.min.enabled=false
pg.enabled=false
line.tcp.enabled=false
line.udp.enabled=false
qwp.udp.enabled=false
telemetry.enabled=false
shared.network.worker.count=3
shared.write.worker.count=3
wal.apply.worker.count=2
cairo.commit.lag=0
cairo.writer.data.append.page.size=64k
cairo.writer.data.index.value.append.page.size=64k
''')
    command = [args.java, '-Xms256m', '-Xmx1g', '-XX:ActiveProcessorCount=3',
               '-XX:+UnlockExperimentalVMOptions', '-ea',
               f'-Djava.io.tmpdir={directory / "tmp"}',
               '--add-exports=java.base/jdk.internal.vm=io.questdb',
               '-cp', str(args.asm.resolve()),
               '--add-reads=io.questdb=ALL-UNNAMED',
               '--add-opens=io.questdb/io.questdb.std=ALL-UNNAMED',
               f'-javaagent:{args.agent.resolve()}={directory}',
               f'-Xlog:gc*,safepoint=debug:file={directory / "jvm-pauses.log"}:utctime,uptimemillis,level,tags',
               '-p', str(args.server.resolve()), '-m', 'io.questdb/io.questdb.ServerMain',
               '-d', str(directory / 'data')]
    environment = dict(os.environ, TMPDIR=str(directory / 'tmp'))
    identity = dict(command=command, mode=args.mode, delay_ms=args.delay_ms, probe_schema=args.probe_schema,
                    probe_delay_ms=args.probe_delay_ms,
                    affinity=sorted(os.sched_getaffinity(0)), uname=list(os.uname()),
                    server_sha256=hashlib.sha256(args.server.read_bytes()).hexdigest(),
                    agent_sha256=hashlib.sha256(args.agent.read_bytes()).hexdigest(),
                    harness_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    client_sha256=hashlib.sha256((REPO / 'build/libquestdb_client.so').read_bytes()).hexdigest(),
                    java_version=subprocess.check_output([args.java, '-version'], stderr=subprocess.STDOUT, text=True))
    assert len(identity['affinity']) == 3, 'Launch under taskset on exactly three CPUs'
    (directory / 'identity.json').write_text(json.dumps(identity, indent=2))
    events = []
    event_lock = threading.Lock()
    stop = threading.Event()

    def record(kind, **values):
        with event_lock:
            events.append(dict(kind=kind, epoch_ms=time.time_ns() / 1e6, **values))

    def http(path, timeout=20):
        with urllib.request.urlopen(f'http://127.0.0.1:{port}{path}', timeout=timeout) as response:
            return response.read()

    def sql(query):
        return json.loads(http('/exec?' + urllib.parse.urlencode({'query': query})))

    def count(table, expected):
        return sql(f'select count() from {table}')['dataset'][0][0] == expected

    def observer():
        # Host pressure is context, not attribution to this server.
        with (directory / 'host.jsonl').open('w') as output:
            while not stop.wait(0.1):
                sample = dict(epoch_ms=time.time_ns() / 1e6)
                for name in ['pressure/cpu', 'pressure/memory', 'pressure/io', 'meminfo', 'vmstat', 'diskstats']:
                    sample[name] = Path('/proc', name).read_text()
                output.write(json.dumps(sample) + '\n')

    def ping_loop():
        while not stop.is_set():
            start = time.monotonic()
            try:
                http('/ping', timeout=0.5)
                record('ping', duration_ms=(time.monotonic() - start) * 1000, error=None)
            except Exception as error:
                record('ping', duration_ms=(time.monotonic() - start) * 1000, error=str(error))
            stop.wait(0.1)

    def sender(name):
        result = qls.Sender.from_conf(
            f'ws::addr=127.0.0.1:{port};sender_id={name};sf_dir={directory / name};')
        result.__enter__()
        return result

    def send(producer, table, new_column=False, row_id=1):
        start = time.monotonic()
        record('send-start', table=table, new_column=new_column, row_id=row_id)
        producer.table(table).column('id', row_id)
        if new_column:
            producer.column('added', 42)
        producer.at(1704110400000000000 + (1000 if row_id == 2 else 0))
        producer.flush()
        fsn = producer.published_fsn()
        record('published', table=table, fsn=fsn)
        producer.wait(timeout_millis=20000)
        assert producer.acked_fsn() == fsn
        error = producer.poll_qwp_ws_error()
        assert error is None, str(error)
        elapsed = (time.monotonic() - start) * 1000
        record('acked', table=table, fsn=fsn, duration_ms=elapsed, new_column=new_column)
        return elapsed

    senders = []
    threads = []
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=4)
    process = None
    try:
        with (directory / 'server.log').open('w') as output:
            process = subprocess.Popen(command, env=environment, cwd=directory, stdout=output, stderr=subprocess.STDOUT)
            def ready():
                if process.poll() is not None:
                    raise RuntimeError(f'Server exited: {process.returncode}; inspect {directory / "server.log"}')
                try:
                    http('/ping', timeout=0.25)
                    return True
                except OSError:
                    return False
            await_condition(ready)
            record('server-ready', pid=process.pid, version=sql('select build()'))
            columns = ','.join(f'c{i} long' for i in range(32))
            sql(f'create table fault_o3 ({columns}, ts timestamp) timestamp(ts) partition by day wal')
            values = ','.join('x' for _ in range(32))
            sql(f"insert into fault_o3 select {values}, timestamp_sequence('2024-01-01T12:00:00.000Z', 1000L) from long_sequence(4096)")
            await_condition(lambda: count('fault_o3', 4096))
            for i in range(3):
                sql(f'create table probe{i} (id long, ts timestamp) timestamp(ts) partition by day wal')
                senders.append(sender(f'producer{i}'))
                send(senders[-1], f'probe{i}')
                await_condition(lambda i=i: count(f'probe{i}', 1))
            for target in (observer, ping_loop):
                thread = threading.Thread(target=target, daemon=True)
                thread.start()
                threads.append(thread)
            time.sleep(0.5)
            (directory / 'arm').touch()
            trigger = pool.submit(sql, f"insert into fault_o3 select {values}, timestamp_sequence('2024-01-01T00:00:00.000Z', 1000L) from long_sequence(256)")
            await_condition(lambda: (directory / 'fault-start').exists(), timeout=15)
            record('observed-fault-start')
            time.sleep(args.probe_delay_ms / 1000)
            probes = [pool.submit(send, producer, f'probe{i}', args.probe_schema == 'add', 2)
                      for i, producer in enumerate(senders)]
            time.sleep(0.4)
            record('thread-dump-request')
            os.kill(process.pid, signal.SIGQUIT)
            latencies = [probe.result(timeout=25) for probe in probes]
            trigger.result(timeout=25)
            await_condition(lambda: (directory / 'fault-end').exists())
            assert not (directory / 'fault-error').exists()
            assert (directory / 'transform-cache').read_text() == '2'
            assert (directory / 'transform-o3').read_text() == '1'
            start_details = fields(directory / 'fault-start')
            assert start_details['monitorHeld'] == str(args.mode == 'inside').lower()
            await_condition(lambda: count('fault_o3', 4352))
            for i in range(3):
                await_condition(lambda i=i: count(f'probe{i}', 2))
                if args.probe_schema == 'add':
                    assert sql(f'select id, added from probe{i} order by id')['dataset'] == [[1, None], [2, 42]]
                else:
                    assert sql(f'select id from probe{i} order by id')['dataset'] == [[1], [2]]
            time.sleep(0.5)
            stop.set()
            for thread in threads:
                thread.join(timeout=2)
            pings = [event for event in events if event['kind'] == 'ping']
            result = dict(mode=args.mode, probe_schema=args.probe_schema, probe_delay_ms=args.probe_delay_ms,
                          ack_ms=latencies,
                          ping_errors=sum(p['error'] is not None for p in pings),
                          max_ping_ms=max(p['duration_ms'] for p in pings),
                          fault=start_details, fault_end=fields(directory / 'fault-end'), correctness='passed')
            (directory / 'result.json').write_text(json.dumps(result, indent=2))
            print(json.dumps({key: value for key, value in result.items() if key not in ('fault', 'fault_end')}
                             | {'directory': str(directory), 'monitor_held': start_details['monitorHeld']}), flush=True)
    finally:
        stop.set()
        # Shutdown only this harness's child JVM, including on failed setup/fault validation.
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=25)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        pool.shutdown(wait=True, cancel_futures=True)
        for producer in senders:
            producer.close(False)
        for thread in threads:
            thread.join(timeout=2)
        (directory / 'events.json').write_text(json.dumps(events, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('mode', choices=['baseline', 'outside', 'inside'])
    parser.add_argument('--server', type=Path, required=True)
    parser.add_argument('--agent', type=Path, required=True)
    parser.add_argument('--asm', type=Path, required=True)
    parser.add_argument('--java', default='java')
    parser.add_argument('--delay-ms', type=int, default=6000)
    parser.add_argument('--probe-schema', choices=['add', 'stable'], default='add')
    parser.add_argument('--probe-delay-ms', type=int, default=0)
    run(parser.parse_args())
