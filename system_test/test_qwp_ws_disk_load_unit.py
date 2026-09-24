import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from qwp_ws_disk_load import cycle, map_shared, mode_for_run, run


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

    def test_real_mapped_work_and_pacing(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'show-columns.tsv').touch()
            with patch('qwp_ws_disk_load.time.sleep') as sleep, \
                    patch('qwp_ws_disk_load.os.urandom', return_value=b'z' * 65536), \
                    patch('qwp_ws_disk_load.mmap.mmap', side_effect=AssertionError('implicit F_FULLFSYNC')):
                run(root, 'load', max_cycles=2, pattern='mapped')
            self.assertEqual(sleep.call_count, 2)
            sleep.assert_called_with(.01)
            rows = [json.loads(s) for s in (root / 'disk-load.jsonl').read_text().splitlines()]
            self.assertEqual(rows[0]['pattern'], 'mapped')
            self.assertEqual(rows[-1]['bytes_written'], 128 * 1024)
            self.assertEqual((root / 'disk-load.data').stat().st_size, 64 * 1024)
            self.assertEqual((root / 'disk-load.data').read_bytes(), b'z' * 65536)
            self.assertEqual([r['stage'] for r in rows if r['event'] == 'syscall'],
                             ['grow', 'mmap', 'mapped_write', 'munmap', 'shrink'] * 2)
            self.assertTrue((root / 'disk-load-finished').exists())

    def test_raw_mapping_failure_raises_before_write(self):
        with self.assertRaises(OSError):
            map_shared(-1, 1024 * 1024)

    def test_bad_pattern_creates_no_file(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(ValueError, 'pattern'):
                run(temp, 'load', pattern='invalid')
            self.assertEqual(list(Path(temp).iterdir()), [])

    def test_short_write_fails(self):
        with patch('qwp_ws_disk_load.os.ftruncate'), patch('qwp_ws_disk_load.os.pwrite', return_value=1):
            with self.assertRaisesRegex(RuntimeError, 'short diagnostic write'):
                cycle(123, b'abc', lambda _: None)
