import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import prepare
import validate


class ProbeTest(unittest.TestCase):
    def test_anchor_drift_is_rejected(self):
        with self.assertRaises(ValueError):
            prepare.instrument('unexpected revision')

    def test_observer_captures_slow_stage_and_completed_requests(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = Path(__file__).parent
            subprocess.run(['javac', f'-J-Djava.io.tmpdir={root}', '-d', str(root), str(sources / 'ShowColumnsProbe.java'),
                            str(sources / 'ProbeTest.java')], check=True)
            subprocess.run(['java', '-XX:ActiveProcessorCount=3',
                            f'-Djava.io.tmpdir={root}',
                            f'-Dqwp.show.columns.dir={root}', '-cp', str(root), 'ProbeTest'],
                           check=True, timeout=15)
            validate.validate(root)
            marker = (root / 'show-columns-slow').read_text().split('\t')
            self.assertEqual(marker[6], 'slow:metadata-read-lock-wait')
            self.assertGreaterEqual(int(marker[7]), 5_000_000_000)
            rows = (root / 'show-columns.tsv').read_text()
            self.assertIn('cursor-close', rows)
            self.assertIn('open-error:Injected', rows)
            self.assertNotIn('show-columns-error', os.listdir(root))

    def test_validation_rejects_missing_or_dropped_events(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for body in ('header\n',
                         'header\n0\t0\t0\t0\tobserver\t-\theartbeat dropped=1\t0\n'):
                (root / 'show-columns.tsv').write_text(body)
                with self.assertRaises(ValueError):
                    validate.validate(root)


if __name__ == '__main__':
    unittest.main()
