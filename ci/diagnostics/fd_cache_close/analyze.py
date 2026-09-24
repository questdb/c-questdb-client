#!/usr/bin/env python3
"""Summarize completed trials and independently inspect their thread dumps."""
import argparse
from collections import defaultdict
import json
from pathlib import Path
import re
import statistics


def thread_blocks(log):
    return dict(re.findall(r'^"([^"]+)"([^\n]*\n.*?)(?=\n\n)', log, re.M | re.S))


def analyze(root):
    groups = defaultdict(list)
    trials = []
    for path in sorted(root.glob('*/result.json')):
        result = json.loads(path.read_text())
        directory = path.parent
        blocks = thread_blocks((directory / 'server.log').read_text())
        fault = result['fault']
        owner = blocks.get(fault['thread'], '')
        owner_ids = re.findall(r'- locked <([^>]+)> \(a io.questdb.std.FdCache\)', owner)
        network_waiters = []
        dispatcher_waiters = []
        for name, block in blocks.items():
            if name.startswith('shared-network_') and any(
                    f'- waiting to lock <{monitor}> (a io.questdb.std.FdCache)' in block
                    for monitor in owner_ids):
                network_waiters.append(name)
                if 'io.questdb.network.IODispatcherLinux.runSerially' in block:
                    dispatcher_waiters.append(name)
        pauses = [int(value) / 1e6 for value in re.findall(
            r'Total: (\d+) ns', (directory / 'jvm-pauses.log').read_text())]
        gaps = []
        io_pressure = []
        prior = None
        with (directory / 'host.jsonl').open() as stream:
            for line in stream:
                sample = json.loads(line)
                if prior is not None:
                    gaps.append(sample['epoch_ms'] - prior)
                prior = sample['epoch_ms']
                io_pressure.extend(float(value) for value in re.findall(
                    r'^full avg10=([\d.]+)', sample['pressure/io'], re.M))
        assert result['correctness'] == 'passed'
        assert fault['monitorHeld'] == str(result['mode'] == 'inside').lower()
        assert len(result['ack_ms']) == 3
        card = dict(directory=directory.name, mode=result['mode'],
                    probe_schema=result.get('probe_schema', 'add'),
                    probe_delay_ms=result.get('probe_delay_ms', 0),
                    ack_ms=result['ack_ms'], ping_errors=result['ping_errors'],
                    max_ping_ms=result['max_ping_ms'],
                    delay_observed_ms=float(result['fault_end']['heldMs']),
                    network_fd_waiters=network_waiters, dispatcher_fd_waiters=dispatcher_waiters,
                    max_safepoint_ms=max(pauses, default=0),
                    max_observer_gap_ms=max(gaps, default=0),
                    host_io_full_avg10_range=[min(io_pressure), max(io_pressure)])
        trials.append(card)
        groups[(card['mode'], card['probe_schema'], card['probe_delay_ms'])].append(card)
    summary = []
    for (mode, schema, delay), cards in sorted(groups.items()):
        latencies = [latency for card in cards for latency in card['ack_ms']]
        summary.append(dict(mode=mode, probe_schema=schema, probe_delay_ms=delay, runs=len(cards),
                            ack_ms_range=[min(latencies), max(latencies)],
                            ack_ms_median=statistics.median(latencies),
                            ping_errors=sum(card['ping_errors'] for card in cards),
                            max_ping_ms=max(card['max_ping_ms'] for card in cards)))
    return dict(summary=summary, trials=trials)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    args = parser.parse_args()
    result = analyze(args.root)
    (args.root / 'analysis.json').write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))
