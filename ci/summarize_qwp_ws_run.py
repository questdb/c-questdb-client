"""One row per unchanged fuzz attempt, to expose degradation across a soak."""
import argparse
import json
from pathlib import Path
import re


def summarize(directory):
    # Treat malformed/truncated telemetry as an error rather than a healthy run.
    missing = []

    def read_events(name):
        path = directory / name
        if not path.exists():
            missing.append(name)
            return []
        return [json.loads(line) for line in path.read_text().splitlines()]

    probes = read_events('watchdog.jsonl')
    heartbeats = read_events('heartbeat.jsonl')
    pings = [event for event in probes if event['event'] == 'ping']
    log = (directory / 'test.log').read_text()
    drains = [float(value) for value in re.findall(
        r'event=drain-complete[^\n]*elapsed=([0-9.]+)s', log)]
    unittest_time = re.findall(r'^Ran 1 test in ([0-9.]+)s$', log, re.M)
    return dict(
        directory=directory.name,
        missing_telemetry=missing,
        unittest_seconds=float(unittest_time[-1]) if unittest_time else None,
        ping_count=len(pings),
        ping_errors=sum(event.get('error') is not None for event in pings),
        max_ping_ms=max((event['elapsed_ms'] for event in pings), default=None),
        max_heartbeat_gap_ms=max((event['gap_ms'] for event in heartbeats), default=None),
        max_drain_seconds=max(drains, default=None),
        capture_reason=(directory / 'capture-started').read_text().strip()
        if (directory / 'capture-started').exists() else None,
        system_trace=(directory / 'system-trace-enabled').exists(),
        system_trace_valid=(directory / 'system-trace-valid.json').exists()
        and not (directory / 'system-trace-error.json').exists(),
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    for name in ['run', 'started', 'duration', 'soak-elapsed', 'free-kb', 'returncode']:
        parser.add_argument('--' + name, type=int, required=True)
    args = parser.parse_args()
    row = summarize(args.directory)
    row.update(run=args.run, started_epoch_seconds=args.started,
               attempt_seconds=args.duration, soak_elapsed_seconds=args.soak_elapsed,
               free_kb_before=args.free_kb, returncode=args.returncode)
    print(json.dumps(row))


if __name__ == '__main__':
    main()
