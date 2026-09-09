"""Diagnostic-only replay of the missing-table prefix before ingestion starts.

This restores an ALTER RNG position, not the unknown original startup delay.
The real ALTER loop still executes every query and consumes every RNG draw.
"""
import threading
import time


class StartupGate:
    def __init__(self, missing_lookups, log, timeout=30):
        if not 1 <= missing_lookups <= 200:
            raise ValueError('startup prefix must contain 1..200 lookups')
        self.target = missing_lookups
        self.count = 0
        self.log = log
        self.timeout = timeout
        self.ready = threading.Event()
        self.error = None
        self.started = time.monotonic()

    def wait(self):
        if not self.ready.wait(self.timeout):
            raise TimeoutError('diagnostic startup prefix did not complete')
        if self.error is not None:
            raise RuntimeError(self.error)

    def lookup(self, list_columns, table_name):
        if self.ready.is_set():
            return list_columns(table_name)
        try:
            list_columns(table_name)
        except Exception as exc:
            if 'table does not exist' not in str(exc).lower():
                self.error = f'unexpected startup lookup failure: {exc}'
                self.ready.set()
                raise
            self.count += 1
            self.log(f'diagnostic startup lookup={self.count}/{self.target} '
                     f'table={table_name}')
            if self.count == self.target:
                self.log('diagnostic startup producers released '
                         f'after={self.count} missing lookups '
                         f'elapsed={time.monotonic() - self.started:.6f}s')
                self.ready.set()
            raise
        self.error = 'startup prefix unexpectedly found an existing table'
        self.ready.set()
        raise RuntimeError(self.error)
