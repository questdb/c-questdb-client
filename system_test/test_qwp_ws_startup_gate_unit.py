import unittest

from qwp_ws_startup_gate import StartupGate


class StartupGateTest(unittest.TestCase):
    def test_releases_only_after_actual_missing_lookups(self):
        gate = StartupGate(3, lambda _: None)
        calls = []

        def missing(table):
            calls.append(table)
            raise RuntimeError(f'table does not exist [table={table}]')

        for index in range(3):
            with self.assertRaisesRegex(RuntimeError, 'table does not exist'):
                gate.lookup(missing, f'weather{index}')
            self.assertEqual(gate.ready.is_set(), index == 2)
        gate.wait()
        self.assertEqual(calls, ['weather0', 'weather1', 'weather2'])
        self.assertEqual(gate.lookup(lambda _: ['column'], 'weather0'), ['column'])
        self.assertEqual(gate.count, 3)

    def test_unexpected_error_unblocks_producers_with_failure(self):
        gate = StartupGate(72, lambda _: None)

        def timeout(_):
            raise TimeoutError('network timeout')

        with self.assertRaises(TimeoutError):
            gate.lookup(timeout, 'weather0')
        with self.assertRaisesRegex(RuntimeError, 'unexpected startup lookup'):
            gate.wait()
        self.assertEqual(gate.count, 0)

    def test_existing_table_is_not_counted(self):
        gate = StartupGate(72, lambda _: None)
        with self.assertRaisesRegex(RuntimeError, 'existing table'):
            gate.lookup(lambda _: [], 'weather0')
        with self.assertRaisesRegex(RuntimeError, 'existing table'):
            gate.wait()

    def test_wait_is_bounded(self):
        gate = StartupGate(72, lambda _: None, timeout=0)
        with self.assertRaises(TimeoutError):
            gate.wait()

    def test_invalid_target(self):
        for count in (0, -1, 201):
            with self.assertRaises(ValueError):
                StartupGate(count, lambda _: None)
