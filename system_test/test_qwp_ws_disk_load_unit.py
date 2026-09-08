import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from qwp_ws_disk_load import cycle, mode_for_run, run


class DiskLoadTest(unittest.TestCase):
    def test_balanced_order(self):
        self.assertEqual([mode_for_run(i) for i in range(1, 9)],
                         ['probe', 'load', 'load', 'probe'] * 2)

    def test_real_bounded_work(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'show-columns.tsv').touch()
            run(root, 'load', max_cycles=2)
            rows = [json.loads(s) for s in (root / 'disk-load.jsonl').read_text().splitlines()]
            self.assertEqual(rows[-1]['bytes_written'], 128 * 1024)
            self.assertEqual(rows[-1]['reason'], 'bounded_budget')
            self.assertEqual((root / 'disk-load.data').stat().st_size, 64 * 1024)
            self.assertEqual([r['stage'] for r in rows if r['event'] == 'syscall'],
                             ['truncate', 'pwrite', 'fsync'] * 2)
            self.assertTrue((root / 'disk-load-finished').exists())
            with self.assertRaises(FileExistsError):
                run(root, 'load', max_cycles=2)

    def test_stops_after_workload(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'show-columns.tsv').touch()
            (root / 'workload-finished').touch()
            with self.assertRaisesRegex(RuntimeError, 'no overlap'):
                run(root, 'load')
            self.assertFalse((root / 'disk-load-finished').exists())

    def test_short_write_fails(self):
        with patch('qwp_ws_disk_load.os.ftruncate'), patch('qwp_ws_disk_load.os.pwrite', return_value=1):
            with self.assertRaisesRegex(RuntimeError, 'short diagnostic write'):
                cycle(123, b'abc', lambda _: None)
