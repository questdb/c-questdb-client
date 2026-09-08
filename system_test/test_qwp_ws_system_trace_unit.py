"""Exercise trace validation and collector failure paths without macOS or sudo."""

import json
from pathlib import Path
import signal
import subprocess
import tempfile
import unittest
from unittest import mock

import qwp_ws_system_trace as trace
import qwp_ws_trace_export as export


ROWS = '''<trace-query-result><node>
<row><thread id="t"><process id="p"><pid id="pid">123</pid></process></thread></row>
<row><thread ref="t"/></row>
<row><process ref="p"/></row>
<row><process><pid ref="pid"/></process></row>
<row><process><pid>456</pid></process></row>
</node></trace-query-result>'''


class TraceExportTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def toc(self, schemas=('time-sample', 'syscall', 'thread-state')):
        return '<trace-toc><run><data>' + ''.join(
            f'<table schema="{schema}"/>' for schema in schemas) + '</data></run></trace-toc>'

    def fake_export(self, command, **kwargs):
        self.assertTrue(kwargs['check'])
        self.assertLessEqual(kwargs['timeout'], 30)
        output = Path(command[command.index('--output') + 1])
        output.write_text(self.toc() if '--toc' in command else ROWS)

    def test_discovers_numeric_positions_without_accepting_cpu_samples(self):
        path = self.directory / 'toc.xml'
        path.write_text(self.toc(('time-sample', 'thread-state-sample', 'syscall',
                                  'thread-state')))
        self.assertEqual(export.discover_tables(path), [
            (3, 'syscall', 'syscall'), (4, 'thread-state', 'thread-state')])

    def test_rejects_ambiguous_multiple_recording_runs(self):
        path = self.directory / 'toc.xml'
        path.write_text('<trace-toc><run/><run/></trace-toc>')
        with self.assertRaisesRegex(RuntimeError, 'exactly one'):
            export.discover_tables(path)

    def test_resolves_nested_pid_references_across_discarded_rows(self):
        path = self.directory / 'rows.xml'
        path.write_text(ROWS)
        self.assertEqual(export.inspect_rows(path, 123), dict(rows=5, target_rows=4))
        self.assertEqual(export.inspect_rows(path, 456), dict(rows=5, target_rows=1))
        self.assertEqual(export.inspect_rows(path, 789), dict(rows=5, target_rows=0))

    def test_empty_table_is_not_evidence(self):
        path = self.directory / 'rows.xml'
        path.write_text('<trace-query-result><node/></trace-query-result>')
        self.assertEqual(export.inspect_rows(path, 123), dict(rows=0, target_rows=0))

    def test_validation_deadline_bounds_large_xml(self):
        path = self.directory / 'rows.xml'
        path.write_text('<node>' + '<row><pid>123</pid></row>' * 2000 + '</node>')
        with self.assertRaisesRegex(RuntimeError, 'time budget'):
            export.inspect_rows(path, 123, deadline=0)

    def test_exports_both_event_tables_and_validates_target_not_just_trace_directory(self):
        with mock.patch.object(export.subprocess, 'run', side_effect=self.fake_export) as run:
            result = export.export_and_validate(self.directory, 123)
        self.assertEqual(len(result['tables']), 2)
        self.assertEqual([row['target_rows'] for row in result['tables']], [4, 4])
        self.assertEqual(run.call_args_list[1].args[0][-3],
                         '/trace-toc/run[1]/data/table[2]')
        self.assertEqual(run.call_args_list[2].args[0][-3],
                         '/trace-toc/run[1]/data/table[3]')
        self.assertTrue((self.directory / 'system-trace-valid.json').exists())

    def test_events_for_other_pid_do_not_pass(self):
        with mock.patch.object(export.subprocess, 'run', side_effect=self.fake_export):
            with self.assertRaisesRegex(RuntimeError, 'No syscall events for target PID 789'):
                export.export_and_validate(self.directory, 789)
        self.assertFalse((self.directory / 'system-trace-valid.json').exists())

    def test_missing_scheduler_table_fails_preflight(self):
        def fake(command, **kwargs):
            Path(command[-1]).write_text(self.toc(('syscall', 'time-sample')))

        with mock.patch.object(export.subprocess, 'run', side_effect=fake):
            with self.assertRaisesRegex(RuntimeError, 'lacks syscall/thread-state'):
                export.export_and_validate(self.directory, 123)

    def test_export_tool_error_cannot_produce_valid_marker(self):
        with mock.patch.object(export.subprocess, 'run',
                               side_effect=subprocess.CalledProcessError(1, 'xctrace')):
            with self.assertRaises(subprocess.CalledProcessError):
                export.export_and_validate(self.directory, 123)
        self.assertFalse((self.directory / 'system-trace-valid.json').exists())


class CollectorTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.child = mock.Mock(returncode=None)
        self.child.poll.side_effect = lambda: self.child.returncode

        def finish(**kwargs):
            self.child.returncode = 0
            return 0

        self.child.wait.side_effect = finish
        self.notification = mock.Mock(name='notification')
        self.notification.name = 'test-ready-notification'
        self.notification.check.return_value = True
        self.patch(trace, 'StartedNotification', return_value=self.notification)
        self.launch = self.patch(trace.subprocess, 'Popen', return_value=self.child)
        self.validate = self.patch(trace, 'export_and_validate')
        self.patch(trace.os, 'kill')
        self.disk = self.patch(trace.shutil, 'disk_usage', return_value=mock.Mock(free=10**12))

    def patch(self, target, name, **kwargs):
        patcher = mock.patch.object(target, name, **kwargs)
        result = patcher.start()
        self.addCleanup(patcher.stop)
        return result

    def request(self):
        self.assertTrue((self.directory / 'system-trace-ready.json').exists())
        trace.request_stop(self.directory, 'ping timeout')

    def assert_failed(self):
        self.assertTrue((self.directory / 'system-trace-error.json').exists())
        self.assertTrue((self.directory / 'system-trace-finished.json').exists())
        self.validate.assert_not_called()
        self.notification.close.assert_called_once()

    def test_ready_then_sigint_then_export_and_signal_handlers_restored(self):
        previous = signal.getsignal(signal.SIGTERM)

        def validate(directory, pid):
            self.child.send_signal.assert_called_once_with(signal.SIGINT)
            self.assertEqual(self.child.returncode, 0)
            self.assertTrue((directory / 'system-trace-stop-sent.json').exists())

        self.validate.side_effect = validate
        trace.collect(self.directory, 123, on_ready=self.request)
        self.assertEqual(signal.getsignal(signal.SIGTERM), previous)
        self.assertEqual(self.launch.call_args.args[0], [
            '/usr/bin/xcrun', 'xctrace', 'record', '--template', 'System Trace',
            '--attach', '123', '--time-limit', '30s', '--no-prompt',
            '--notify-tracing-started', 'test-ready-notification',
            '--output', str(self.directory / 'system.trace')])
        self.validate.assert_called_once_with(self.directory, 123)
        self.assertFalse((self.directory / 'system-trace-error.json').exists())

    def test_first_stop_request_preserves_original_clock_and_reason(self):
        trace.request_stop(self.directory, 'ping timeout')
        first = (self.directory / 'system-trace-stop-request.json').read_text()
        trace.request_stop(self.directory, 'workload-finished')
        self.assertEqual((self.directory / 'system-trace-stop-request.json').read_text(), first)
        self.assertGreater(json.loads(first)['monotonic_ns'], 0)

    def test_recorder_exits_without_ready(self):
        self.notification.check.return_value = False
        self.child.returncode = 1
        with self.assertRaisesRegex(RuntimeError, 'did not signal readiness'):
            trace.collect(self.directory, 123)
        self.assertFalse((self.directory / 'system-trace-ready.json').exists())
        self.assert_failed()

    def test_disk_guard_stops_and_reaps_recorder(self):
        self.disk.return_value.free = 0
        with self.assertRaisesRegex(RuntimeError, 'disk-space safety stop'):
            trace.collect(self.directory, 123)
        self.child.send_signal.assert_called_once_with(signal.SIGINT)
        self.child.wait.assert_called_once()
        self.assert_failed()

    def test_recording_expiry_is_not_a_successful_capture(self):
        with mock.patch.object(trace, 'RECORD_SECONDS', 0):
            with self.assertRaisesRegex(RuntimeError, 'Recording expired'):
                trace.collect(self.directory, 123)
        self.assert_failed()

    def test_nonzero_recording_exit_is_a_failure(self):
        def finish(**kwargs):
            self.child.returncode = 2
            return 2

        self.child.wait.side_effect = finish
        with self.assertRaisesRegex(RuntimeError, 'xctrace exited 2'):
            trace.collect(self.directory, 123, on_ready=self.request)
        self.assert_failed()

    def test_delayed_stop_is_rejected(self):
        def request():
            self.request()
            path = self.directory / 'system-trace-stop-request.json'
            contents = json.loads(path.read_text())
            contents['monotonic_ns'] -= 3_000_000_000
            path.write_text(json.dumps(contents))

        with self.assertRaisesRegex(RuntimeError, 'over two seconds late'):
            trace.collect(self.directory, 123, on_ready=request)
        self.assert_failed()

    def test_cancellation_stops_and_reaps_owned_child(self):
        def cancel():
            signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)

        with self.assertRaisesRegex(RuntimeError, 'collector interrupted'):
            trace.collect(self.directory, 123, on_ready=cancel)
        self.child.send_signal.assert_called_once_with(signal.SIGINT)
        self.assert_failed()

    def test_hung_finalization_is_killed_and_marked_failed(self):
        self.child.wait.side_effect = [subprocess.TimeoutExpired('xctrace', 30),
                                       subprocess.TimeoutExpired('xctrace', 30), 0]
        with self.assertRaisesRegex(RuntimeError, 'did not finalize'):
            trace.collect(self.directory, 123, on_ready=self.request)
        self.child.kill.assert_called_once()
        self.assert_failed()


class NotificationTest(unittest.TestCase):
    def test_initial_registration_state_is_consumed_before_real_ready(self):
        library = mock.Mock()
        library.notify_register_check.return_value = 0
        changes = iter([1, 0, 1])

        def check(token, changed):
            changed._obj.value = next(changes)
            return 0

        library.notify_check.side_effect = check
        with mock.patch.object(trace.ctypes, 'CDLL', return_value=library):
            notification = trace.StartedNotification()
            self.assertFalse(notification.check())
            self.assertTrue(notification.check())
            notification.close()
        library.notify_cancel.assert_called_once_with(notification.token)

    def test_notification_failure_is_explicit(self):
        library = mock.Mock()
        library.notify_register_check.return_value = 0
        library.notify_check.return_value = 1
        with mock.patch.object(trace.ctypes, 'CDLL', return_value=library):
            with self.assertRaisesRegex(RuntimeError, 'Cannot check'):
                trace.StartedNotification()
        library.notify_cancel.assert_called_once()


if __name__ == '__main__':
    unittest.main()
