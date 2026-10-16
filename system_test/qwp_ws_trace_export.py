"""Validate discovered xctrace tables; never mistake a .trace directory for data."""

import json
from pathlib import Path
import re
import subprocess
import time
import xml.etree.ElementTree as ET


def table_kind(schema):
    name = re.sub('[^a-z]', '', schema.lower())
    if 'syscall' in name or 'systemcall' in name:
        return 'syscall'
    if 'threadstate' in name and 'sample' not in name:
        return 'thread-state'
    return None


def discover_tables(toc):
    # Export by position, not a guessed schema name or an interpolated XPath.
    runs = ET.parse(toc).findall('./run')
    if len(runs) != 1:
        raise RuntimeError('Expected exactly one recording run in System Trace')
    tables = runs[0].findall('./data/table')
    return [(i, table.attrib.get('schema', ''), table_kind(table.attrib.get('schema', '')))
            for i, table in enumerate(tables, 1)
            if table_kind(table.attrib.get('schema', ''))]


def inspect_rows(path, target_pid, deadline=None):
    """Resolve xctrace's interned id/ref values, including process inside thread."""
    # Large syscall tables must not become a multi-GB Python tree on a 7-GiB
    # worker. Keep only PID associations for interned values and discard rows.
    refs = {}
    pending = {}
    stack = []
    rows = matching = 0
    for event, node in ET.iterparse(path, events=('start', 'end')):
        if event == 'start':
            stack.append(node)
            continue
        found = set(refs.get(node.attrib.get('ref'), ()))
        if node.tag == 'pid' and (node.text or '').isdigit():
            found.add(int(node.text))
        for child in node:
            found.update(pending.pop(id(child), ()))
        if found and 'id' in node.attrib:
            refs[node.attrib['id']] = found
        pending[id(node)] = found
        if node.tag == 'row':
            rows += 1
            if deadline is not None and rows % 1000 == 0 and time.monotonic() >= deadline:
                raise RuntimeError('System Trace export/validation exceeded its time budget')
            matching += target_pid in found
            pending.pop(id(node))
            if len(stack) > 1:
                stack[-2].remove(node)
            node.clear()
        stack.pop()
    # A sampled thread-state field in a CPU profile is deliberately insufficient:
    # the caller only exports the actual syscall/thread-state tables from TOC.
    return dict(rows=rows, target_rows=matching)


def export_and_validate(directory, target_pid):
    directory = Path(directory)
    trace = directory / 'system.trace'
    toc = directory / 'system-trace-toc.xml'
    deadline = time.monotonic() + 60
    with (directory / 'system-trace-export.log').open('w') as log:
        def export(path, *selection):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError('System Trace export/validation exceeded its time budget')
            subprocess.run(['/usr/bin/xcrun', 'xctrace', 'export', '--input', str(trace),
                            *selection, '--output', str(path)],
                           stdout=log, stderr=subprocess.STDOUT,
                           timeout=min(30, remaining), check=True)

        export(toc, '--toc')
        tables = discover_tables(toc)
        if not {'syscall', 'thread-state'} <= {kind for _, _, kind in tables}:
            raise RuntimeError('System Trace lacks syscall/thread-state tables; inspect TOC')
        results = []
        for index, schema, kind in tables:
            path = directory / f'system-trace-table-{index}.xml'
            export(path, '--xpath', f'/trace-toc/run[1]/data/table[{index}]')
            results.append(dict(schema=schema, kind=kind, file=path.name,
                                **inspect_rows(path, target_pid, deadline)))
        for kind in ('syscall', 'thread-state'):
            if not any(row['kind'] == kind and row['target_rows'] > 0 for row in results):
                raise RuntimeError(f'No {kind} events for target PID {target_pid}')
    result = dict(pid=target_pid, tables=results)
    (directory / 'system-trace-valid.json').write_text(json.dumps(result, indent=2) + '\n')
    return result
