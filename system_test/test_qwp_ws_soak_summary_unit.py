"""Check repetition telemetry without allocating a CI worker or starting Java."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'ci' / 'summarize_qwp_ws_run.py'
SPEC = importlib.util.spec_from_file_location('qwp_soak_summary', SCRIPT)
SUMMARY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SUMMARY)


class SoakSummaryTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        (self.directory / 'test.log').write_text('Ran 1 test in 8.234s\n\nOK\n')
        self.write_events('watchdog.jsonl', [dict(event='ready'),
                                           dict(event='ping', elapsed_ms=4.5, error=None),
                                           dict(event='workload_finished')])
        self.write_events('heartbeat.jsonl', [dict(event='heartbeat', gap_ms=251.1)])

    def write_events(self, name, events):
        (self.directory / name).write_text(''.join(json.dumps(event) + '\n' for event in events))

    def test_success_without_capture(self):
        result = SUMMARY.summarize(self.directory)
        self.assertEqual(result['unittest_seconds'], 8.234)
        self.assertEqual(result['ping_count'], 1)
        self.assertEqual(result['ping_errors'], 0)
        self.assertEqual(result['max_ping_ms'], 4.5)
        self.assertEqual(result['max_heartbeat_gap_ms'], 251.1)
        self.assertIsNone(result['capture_reason'])
        self.assertEqual(result['missing_telemetry'], [])
        self.assertFalse(result['system_trace'])
        self.assertFalse(result['system_trace_valid'])

    def test_trace_error_overrides_valid_marker(self):
        (self.directory / 'system-trace-enabled').touch()
        (self.directory / 'system-trace-valid.json').write_text('{}')
        self.assertTrue(SUMMARY.summarize(self.directory)['system_trace'])
        self.assertTrue(SUMMARY.summarize(self.directory)['system_trace_valid'])
        (self.directory / 'system-trace-error.json').write_text('{}')
        self.assertFalse(SUMMARY.summarize(self.directory)['system_trace_valid'])

    def test_recovered_ping_stall_is_preserved(self):
        self.write_events('watchdog.jsonl', [dict(event='ping', elapsed_ms=1002, error='timeout'),
                                           dict(event='ping', elapsed_ms=2, error=None)])
        (self.directory / 'capture-started').write_text('ping timeout\n')
        result = SUMMARY.summarize(self.directory)
        self.assertEqual(result['ping_errors'], 1)
        self.assertEqual(result['max_ping_ms'], 1002)
        self.assertEqual(result['capture_reason'], 'ping timeout')

    def test_drain_metrics_match_test_progress_format(self):
        (self.directory / 'test.log').write_text(
            '[qwp_ws_fuzz] diagnostics event=drain-start, sender=t0\n'
            '[qwp_ws_fuzz] diagnostics event=drain-complete, sender=t0, elapsed=3.576s\n'
            '[qwp_ws_fuzz] diagnostics event=drain-complete, sender=t1, elapsed=0.450s\n'
            '[qwp_ws_fuzz] diagnostics event=producer-failed, sender=t2, elapsed=120.001s\n')
        result = SUMMARY.summarize(self.directory)
        self.assertEqual(result['max_drain_seconds'], 3.576)
        self.assertIsNone(result['unittest_seconds'])

    def test_no_probe_is_not_reported_as_zero_latency(self):
        self.write_events('watchdog.jsonl', [dict(event='ready')])
        self.assertIsNone(SUMMARY.summarize(self.directory)['max_ping_ms'])

    def test_missing_file_is_explicit(self):
        (self.directory / 'heartbeat.jsonl').unlink()
        result = SUMMARY.summarize(self.directory)
        self.assertEqual(result['missing_telemetry'], ['heartbeat.jsonl'])
        self.assertIsNone(result['max_heartbeat_gap_ms'])

    def test_truncated_json_is_not_a_healthy_record(self):
        (self.directory / 'watchdog.jsonl').write_text('{"event":')
        with self.assertRaises(json.JSONDecodeError):
            SUMMARY.summarize(self.directory)


if __name__ == '__main__':
    unittest.main()
