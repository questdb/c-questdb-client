"""Reject missing/dropped query telemetry instead of silently passing the arm."""
from pathlib import Path
import sys


def validate(directory):
    if (directory / 'show-columns-error').exists():
        raise ValueError('Observer failed')
    rows = (directory / 'show-columns.tsv').read_text().splitlines()[1:]
    active = set()
    completed = 0
    heartbeat = False
    for line in rows:
        fields = line.split('\t')
        if len(fields) != 8:
            raise ValueError('Incomplete telemetry row')
        query, stage = fields[2], fields[6]
        if stage.startswith('heartbeat'):
            heartbeat = True
            if stage != 'heartbeat dropped=0':
                raise ValueError(stage)
        if stage == 'cursor-enter':
            active.add(query)
        elif stage == 'cursor-close' or stage.startswith(('open-error:', 'iteration-error:')):
            active.discard(query)
            completed += 1
    if not heartbeat or completed == 0 or active:
        raise ValueError(f'Missing heartbeat/completion: completed={completed}, active={active}')


if __name__ == '__main__':
    validate(Path(sys.argv[1]))
