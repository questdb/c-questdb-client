import unittest
from unittest import mock

from qwp_ws_pressure import mode_for_run, wait_for_level


class PressureTest(unittest.TestCase):
    def test_balanced_plan(self):
        self.assertEqual([mode_for_run('paired', n) for n in range(1, 13)],
                         ['natural', 'warn', 'warn', 'natural'] * 3)
        self.assertEqual(mode_for_run('natural', 2), 'natural')
        self.assertEqual(mode_for_run('warn', 1), 'warn')
        for plan, run in [('bad', 1), ('paired', 0)]:
            with self.assertRaises(ValueError):
                mode_for_run(plan, run)

    def test_gate_requires_actual_target(self):
        read = mock.Mock(side_effect=[1, 1, 2])
        record, sleep = mock.Mock(), mock.Mock()
        wait_for_level('warn', read, record, clock=lambda: 0, sleep=sleep)
        self.assertEqual(record.call_args_list, [mock.call(1), mock.call(1), mock.call(2)])
        self.assertEqual(sleep.call_count, 2)

    def test_natural_waits_for_recovery(self):
        read = mock.Mock(side_effect=[2, 1])
        wait_for_level('natural', read, mock.Mock(), clock=lambda: 0, sleep=mock.Mock())
        self.assertEqual(read.call_count, 2)

    def test_gate_rejects_critical_unknown_and_unreached(self):
        for level in (0, 4):
            with self.assertRaisesRegex(RuntimeError, 'unsafe or unknown'):
                wait_for_level('warn', lambda: level, mock.Mock())
        with self.assertRaisesRegex(RuntimeError, 'not reached'):
            wait_for_level('warn', mock.Mock(), mock.Mock(), clock=mock.Mock(side_effect=[0, 21]))


if __name__ == '__main__':
    unittest.main()
