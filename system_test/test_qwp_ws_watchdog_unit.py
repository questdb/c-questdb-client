"""Exercise onset capture without a Mac, JVM, or CI allocation."""

import io
import json
from pathlib import Path
import signal
import tempfile
import threading
import time
import unittest
from unittest import mock

import qwp_ws_watchdog as watchdog


def wait_for(predicate):
    deadline = time.monotonic() + 5
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError('watchdog did not reach expected state')
        time.sleep(0.01)


class WatchdogTest(unittest.TestCase):
    def test_traced_capture_requests_stop_without_dumping_or_sampling(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / 'system-trace-enabled').touch()
            (directory / 'system-trace-stop-sent.json').write_text('{}')
            with mock.patch.object(watchdog.os, 'kill') as send, \
                    mock.patch.object(watchdog.subprocess, 'Popen') as launch:
                watchdog.capture(directory, 123, 'ping timeout')
            send.assert_not_called()
            launch.assert_not_called()
            request = json.loads((directory / 'system-trace-stop-request.json').read_text())
            self.assertEqual(request['reason'], 'ping timeout')
            self.assertTrue((directory / 'capture-complete').exists())
            self.assertFalse((directory / 'capture-error').exists())

    def test_trace_failure_releases_teardown_with_explicit_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / 'system-trace-enabled').touch()
            (directory / 'system-trace-error.json').write_text('{}')
            with mock.patch.object(watchdog.os, 'kill') as send:
                watchdog.capture(directory, 123, 'ping timeout')
            send.assert_not_called()
            self.assertTrue((directory / 'capture-complete').exists())
            self.assertIn('did not acknowledge', (directory / 'capture-error').read_text())

    def test_normal_completion_requests_trace_stop_before_teardown_ack(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for name in ('start-test', 'workload-finished', 'system-trace-enabled'):
                (directory / name).touch()
            (directory / 'system-trace-stop-sent.json').write_text('{}')
            watchdog.watch(directory, 123, 9000, threading.Event())
            request = json.loads((directory / 'system-trace-stop-request.json').read_text())
            self.assertEqual(request['reason'], 'workload-finished')
            self.assertTrue((directory / 'watchdog-stopped').exists())
            self.assertFalse((directory / 'capture-error').exists())

    def test_trace_stop_is_requested_before_capture_thread_starts(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for name in ('start-test', 'system-trace-enabled'):
                (directory / name).touch()
            stop = threading.Event()
            opener = mock.Mock()
            opener.open.side_effect = TimeoutError('injected stall')

            def capture(*_args):
                self.assertTrue((directory / 'system-trace-stop-request.json').exists())
                (directory / 'system-trace-stop-sent.json').write_text('{}')
                stop.set()

            with mock.patch.object(watchdog.urllib.request, 'build_opener', return_value=opener), \
                    mock.patch.object(watchdog, 'capture', side_effect=capture) as collect:
                watchdog.watch(directory, 123, 9000, stop)
            collect.assert_called_once()
            events = [json.loads(line) for line in (directory / 'watchdog.jsonl').read_text().splitlines()]
            ping = next(event for event in events if event['event'] == 'ping')
            self.assertLessEqual(ping['started_wall_ns'], ping['wall_ns'])

    def test_event_has_wall_and_monotonic_clocks(self):
        log = io.StringIO()
        watchdog.write_event(log, 'example', elapsed_ms=7)
        event = json.loads(log.getvalue())
        self.assertEqual(event['event'], 'example')
        self.assertEqual(event['elapsed_ms'], 7)
        self.assertGreater(event['wall_ns'], 0)
        self.assertGreater(event['monotonic_ns'], 0)

    def test_heartbeat_continues_while_http_is_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / 'start-test').touch()
            release = threading.Event()
            stop = threading.Event()
            opener = mock.Mock()

            def blocked_ping(*_args, **_kwargs):
                release.wait(5)
                raise TimeoutError('injected stall')

            opener.open.side_effect = blocked_ping
            with mock.patch.object(watchdog.urllib.request, 'build_opener', return_value=opener), \
                    mock.patch.object(watchdog, 'capture') as capture:
                thread = threading.Thread(target=watchdog.watch,
                                          args=(directory, 123, 9000, stop))
                thread.start()
                try:
                    heartbeat = directory / 'heartbeat.jsonl'
                    wait_for(lambda: heartbeat.exists() and
                             len(heartbeat.read_text().splitlines()) >= 3)
                    capture.assert_not_called()
                    release.set()
                    wait_for(lambda: capture.call_count == 1)
                    self.assertIn('injected stall', capture.call_args.args[2])
                finally:
                    stop.set()
                    release.set()
                    thread.join(5)
                self.assertFalse(thread.is_alive())

    def test_callback_requests_one_capture_even_when_ping_is_healthy(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / 'start-test').touch()
            (directory / 'capture-request').write_text('SHOW COLUMNS timeout')
            stop = threading.Event()
            opener = mock.MagicMock()
            opener.open.return_value.__enter__.return_value.status = 204
            with mock.patch.object(watchdog.urllib.request, 'build_opener', return_value=opener), \
                    mock.patch.object(watchdog, 'capture') as capture:
                thread = threading.Thread(target=watchdog.watch,
                                          args=(directory, 123, 9000, stop))
                thread.start()
                try:
                    wait_for(lambda: opener.open.call_count >= 2)
                finally:
                    stop.set()
                    thread.join(5)
                capture.assert_called_once_with(directory, 123, 'SHOW COLUMNS timeout')

    def test_query_arm_ignores_ping_timeout_then_captures_slow_query(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / 'start-test').touch()
            (directory / 'show-columns-enabled').touch()
            stop = threading.Event()
            opener = mock.Mock()
            calls = []

            def ping(*args, **kwargs):
                calls.append(1)
                if len(calls) == 2:
                    (directory / 'show-columns-slow').write_text('metadata-read-lock-wait')
                raise TimeoutError('ping only')

            opener.open.side_effect = ping
            with mock.patch.object(watchdog.urllib.request, 'build_opener', return_value=opener), \
                    mock.patch.object(watchdog, 'capture', side_effect=lambda *_: stop.set()) as capture:
                watchdog.watch(directory, 123, 9000, stop)
                capture.assert_called_once_with(directory, 123, 'slow SHOW COLUMNS: metadata-read-lock-wait')
                self.assertEqual(len(calls), 2)

    def test_does_not_capture_a_ping_that_finishes_during_teardown(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / 'start-test').touch()
            opener = mock.Mock()

            def teardown_during_ping(*_args, **_kwargs):
                (directory / 'workload-finished').touch()
                raise TimeoutError('cleanup, not onset')

            opener.open.side_effect = teardown_during_ping
            with mock.patch.object(watchdog.urllib.request, 'build_opener', return_value=opener), \
                    mock.patch.object(watchdog, 'capture') as capture:
                watchdog.watch(directory, 123, 9000, threading.Event())
            capture.assert_not_called()

    def test_native_capture_uses_explicit_output_and_three_dump_requests(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / 'native-sample.txt').write_text('sample stacks')
            child = mock.Mock()
            child.wait.return_value = 0
            child.poll.return_value = 0
            with mock.patch.object(watchdog.sys, 'platform', 'darwin'), \
                    mock.patch.object(watchdog.subprocess, 'Popen', return_value=child) as launch, \
                    mock.patch.object(watchdog.os, 'kill') as send, \
                    mock.patch.object(watchdog.time, 'sleep'):
                watchdog.capture(directory, 123, 'timeout')
            self.assertEqual(launch.call_args.args[0], [
                '/usr/bin/sample', '123', '3', '10', '-file',
                str(directory / 'native-sample.txt')])
            self.assertEqual(send.call_args_list, [mock.call(123, signal.SIGQUIT)] * 3)
            self.assertTrue((directory / 'capture-complete').exists())
            self.assertFalse((directory / 'capture-error').exists())

    def test_final_workload_error_is_captured_before_teardown_ack(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for marker in ('start-test', 'workload-finished'):
                (directory / marker).touch()
            (directory / 'capture-request').write_text('producer failed')

            def collect(*_args):
                self.assertFalse((directory / 'watchdog-stopped').exists())

            with mock.patch.object(watchdog, 'capture', side_effect=collect) as capture:
                watchdog.watch(directory, 123, 9000, threading.Event())
            capture.assert_called_once_with(directory, 123, 'producer failed')
            self.assertTrue((directory / 'watchdog-stopped').exists())

    def test_native_capture_failure_is_explicit_and_releases_teardown(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            with mock.patch.object(watchdog.sys, 'platform', 'darwin'), \
                    mock.patch.object(watchdog.subprocess, 'Popen', side_effect=OSError('denied')), \
                    mock.patch.object(watchdog.os, 'kill') as send, \
                    mock.patch.object(watchdog.time, 'sleep'):
                watchdog.capture(directory, 123, 'timeout')
            self.assertEqual(send.call_count, 3)
            self.assertIn('denied', (directory / 'capture-error').read_text())
            self.assertTrue((directory / 'capture-complete').exists())


if __name__ == '__main__':
    unittest.main()
