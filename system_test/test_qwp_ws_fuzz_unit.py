################################################################################
##     ___                  _   ____  ____
##    / _ \ _   _  ___  ___| |_|  _ \| __ )
##   | | | | | | |/ _ \/ __| __| | | |  _ \
##   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
##    \__\_\\__,_|\___||___/\__|____/|____/
##
##  Copyright (c) 2014-2019 Appsicle
##  Copyright (c) 2019-2026 QuestDB
##
##  Licensed under the Apache License, Version 2.0 (the "License");
##  you may not use this file except in compliance with the License.
##  You may obtain a copy of the License at
##
##  http://www.apache.org/licenses/LICENSE-2.0
##
##  Unless required by applicable law or agreed to in writing, software
##  distributed under the License is distributed on an "AS IS" BASIS,
##  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
##  See the License for the specific language governing permissions and
##  limitations under the License.
##
################################################################################

"""Unit-level regression tests for `qwp_ws_fuzz`.

These do not need a QuestDB fixture — they drive the helper module
directly with injected mocks. They pin down transient-network-error
classification and bounce lifecycle ownership: a failed worker exits without
recovering, and the parent joins it before synchronous fixture recovery.

Run with::

    cd system_test && python3 -m unittest test_qwp_ws_fuzz_unit
"""

import sys
sys.dont_write_bytecode = True

import threading
import unittest
import urllib.error

import qwp_ws_fuzz


class TransientNetworkErrorClassificationTest(unittest.TestCase):
    """`is_transient_network_error` should accept the full set of
    exceptions we see when QuestDB is mid-bounce."""

    def test_url_error_is_transient(self):
        # urllib's wrapper for refused / broken connections.
        self.assertTrue(qwp_ws_fuzz.is_transient_network_error(
            urllib.error.URLError('Connection refused')))

    def test_connection_reset_is_transient(self):
        # Linux: Errno 104 when the server process exits mid-RTT.
        self.assertTrue(qwp_ws_fuzz.is_transient_network_error(
            ConnectionResetError(104, 'Connection reset by peer')))

    def test_connection_refused_is_transient(self):
        # Server not yet bound after a restart.
        self.assertTrue(qwp_ws_fuzz.is_transient_network_error(
            ConnectionRefusedError(111, 'Connection refused')))

    def test_connection_aborted_is_transient(self):
        self.assertTrue(qwp_ws_fuzz.is_transient_network_error(
            ConnectionAbortedError(103, 'Software caused connection abort')))

    def test_broken_pipe_is_transient(self):
        self.assertTrue(qwp_ws_fuzz.is_transient_network_error(
            BrokenPipeError(32, 'Broken pipe')))

    def test_timeout_is_transient(self):
        # Windows: socket read timed out while server was coming back up.
        self.assertTrue(qwp_ws_fuzz.is_transient_network_error(
            TimeoutError('timed out')))

    def test_bare_oserror_is_transient(self):
        # Catch-all for socket-layer errors we haven't explicitly
        # enumerated.
        self.assertTrue(qwp_ws_fuzz.is_transient_network_error(
            OSError(54, 'Connection reset by peer')))

    def test_value_error_is_not_transient(self):
        # Logic / programming errors must not be silently swallowed.
        self.assertFalse(qwp_ws_fuzz.is_transient_network_error(
            ValueError('bad column type')))

    def test_assertion_error_is_not_transient(self):
        self.assertFalse(qwp_ws_fuzz.is_transient_network_error(
            AssertionError('mismatch')))

    def test_message_match_is_transient(self):
        # Resilience against wrapping layers that hide the type but
        # keep a recognisable message — Windows urllib has been known
        # to surface raw 'timed out' strings under custom exception
        # classes.
        class CustomError(Exception):
            pass
        self.assertTrue(qwp_ws_fuzz.is_transient_network_error(
            CustomError('Read timed out')))
        self.assertTrue(qwp_ws_fuzz.is_transient_network_error(
            CustomError('Connection reset by peer')))


class AlterThreadTransientErrorTest(unittest.TestCase):
    """`AlterThread._try_one_alter` must treat the full transient set
    as a benign retry. Bug: previously caught only `URLError`, so
    `ConnectionResetError` (Linux mid-bounce) and `TimeoutError`
    (Windows mid-bounce) were classified as fatal alter failures."""

    @staticmethod
    def _make_thread(sql_query_raises):
        """Build an AlterThread without starting it. `sql_query_raises`
        is the exception class to raise on the next SQL call."""
        list_columns_result = [{'name': 'price', 'type': 'DOUBLE'}]

        def list_columns(_table_name):
            return list_columns_result

        def sql_query(_stmt):
            raise sql_query_raises

        failure_counter = [0]
        failures = []

        def record_failure(msg):
            failures.append(msg)
            failure_counter[0] += 1

        thread = qwp_ws_fuzz.AlterThread(
            sql_query=sql_query,
            list_columns=list_columns,
            tables=['weather0'],
            convert_budget=1,
            rnd=qwp_ws_fuzz.Rng(seed=0xdeadbeef),
            producers_done=threading.Event(),
            stop_event=threading.Event(),
            record_failure=record_failure,
            failure_counter=failure_counter,
            log=lambda _msg: None)
        return thread, failure_counter, failures

    def _assert_transient(self, exc):
        """Calling _try_one_alter once with an injected transient
        exception must return False *without* incrementing
        `failure_counter` (so the alter loop keeps trying after the
        server is back up)."""
        thread, counter, failures = self._make_thread(exc)
        result = thread._try_one_alter('weather0')
        self.assertFalse(result)
        self.assertEqual(counter[0], 0,
                         f'transient {type(exc).__name__} bumped failure_counter')
        self.assertEqual(failures, [],
                         f'transient {type(exc).__name__} appended a message')

    def test_connection_reset_is_swallowed(self):
        self._assert_transient(ConnectionResetError(104, 'Connection reset by peer'))

    def test_connection_refused_is_swallowed(self):
        self._assert_transient(ConnectionRefusedError(111, 'Connection refused'))

    def test_broken_pipe_is_swallowed(self):
        self._assert_transient(BrokenPipeError(32, 'Broken pipe'))

    def test_timeout_is_swallowed(self):
        # The exact failure that took Windows CI down:
        #   `fuzz alter: unexpected failure on weather2.location -> VARCHAR: timed out`
        self._assert_transient(TimeoutError('timed out'))

    def test_url_error_is_swallowed(self):
        self._assert_transient(urllib.error.URLError('Connection refused'))

    def test_real_bug_is_still_fatal(self):
        # Sanity: programming errors must still surface so they're
        # not lost in the transient-tolerance bucket.
        thread, counter, failures = self._make_thread(
            ValueError('this would be a real bug'))
        result = thread._try_one_alter('weather0')
        self.assertFalse(result)
        self.assertEqual(counter[0], 1)
        self.assertEqual(len(failures), 1)
        self.assertIn('ValueError', failures[0])


class _ZeroRng:
    """Deterministic BounceThread RNG: fire immediately, then sleep 20ms."""

    @staticmethod
    def next_int(_bound):
        return 0


class _RecordingBounceFixture:
    def __init__(self, fail_first_start=False):
        self.calls = []
        self._fail_first_start = fail_first_start
        self._starts = 0

    def stop(self, wait_timeout_sec):
        self.calls.append(('stop', wait_timeout_sec))

    def start(self, start_timeout_sec, probe_min_http):
        self.calls.append(
            ('start', start_timeout_sec, probe_min_http))
        self._starts += 1
        if self._fail_first_start and self._starts == 1:
            raise TimeoutError('restart timed out')


class BounceThreadLifecycleOwnershipTest(unittest.TestCase):
    """A failed bounce must return fixture ownership to the parent.

    Recovery cannot run in BounceThread: another stop() + start() can outlast
    the parent's normal-cycle join budget and race teardown on the fixture.
    """

    @staticmethod
    def _make_thread(fixture):
        failure_counter = [0]
        failures = []

        def record_failure(msg):
            failures.append(msg)
            failure_counter[0] += 1

        thread = qwp_ws_fuzz.BounceThread(
            fixture=fixture,
            rnd=_ZeroRng(),
            max_bounces=1,
            min_interval_s=0,
            max_interval_s=0,
            stop_timeout_s=120,
            restart_timeout_s=90,
            writers_done=threading.Event(),
            stop_event=threading.Event(),
            record_failure=record_failure,
            failure_counter=failure_counter,
            log=lambda _msg: None)
        return thread, failure_counter, failures

    def test_failed_restart_exits_before_parent_recovers(self):
        fixture = _RecordingBounceFixture(fail_first_start=True)
        thread, failure_counter, failures = self._make_thread(fixture)

        thread.start()
        thread.join(timeout=1)

        self.assertFalse(thread.is_alive())
        self.assertEqual(
            fixture.calls,
            [('stop', 120), ('start', 90, True)],
            'the worker must not perform a second lifecycle cycle')
        self.assertIsInstance(thread.lifecycle_error, TimeoutError)
        self.assertEqual(failure_counter[0], 1)
        self.assertEqual(len(failures), 1)
        self.assertIn('restart timed out', failures[0])

        qwp_ws_fuzz.finish_bounce_thread(
            bounce_thread=thread,
            fixture=fixture,
            wind_down_sec=240,
            stop_timeout_sec=120,
            restart_timeout_sec=90,
            record_failure=lambda msg: self.fail(msg),
            log=lambda msg: self.fail(msg))
        self.assertEqual(
            fixture.calls,
            [('stop', 120), ('start', 90, True),
             ('stop', 120), ('start', 90, True)],
            'the joined parent must perform the recovery cycle')

    def test_successful_bounce_needs_no_parent_recovery(self):
        fixture = _RecordingBounceFixture()
        thread, failure_counter, failures = self._make_thread(fixture)

        thread.start()
        thread.join(timeout=1)
        qwp_ws_fuzz.finish_bounce_thread(
            bounce_thread=thread,
            fixture=fixture,
            wind_down_sec=240,
            stop_timeout_sec=120,
            restart_timeout_sec=90,
            record_failure=lambda msg: self.fail(msg),
            log=lambda msg: self.fail(msg))

        self.assertFalse(thread.is_alive())
        self.assertEqual(
            fixture.calls,
            [('stop', 120), ('start', 90, True)])
        self.assertIsNone(thread.lifecycle_error)
        self.assertEqual(thread.bounces_performed, 1)
        self.assertEqual(failure_counter[0], 0)
        self.assertEqual(failures, [])

    def test_diagnostic_timeout_still_joins_before_recovery(self):
        events = []

        class SlowThread:
            lifecycle_error = TimeoutError('restart timed out')

            def __init__(self):
                self.alive = True

            def join(self, timeout=None):
                events.append(('join', timeout))
                if timeout is None:
                    self.alive = False

            def is_alive(self):
                return self.alive

        thread = SlowThread()

        class Fixture:
            def stop(self, wait_timeout_sec):
                self.assert_thread_joined()
                events.append(('stop', wait_timeout_sec))

            def start(self, start_timeout_sec, probe_min_http):
                self.assert_thread_joined()
                events.append(
                    ('start', start_timeout_sec, probe_min_http))

            @staticmethod
            def assert_thread_joined():
                if thread.is_alive():
                    raise AssertionError('recovery raced the lifecycle thread')

        failures = []
        qwp_ws_fuzz.finish_bounce_thread(
            bounce_thread=thread,
            fixture=Fixture(),
            wind_down_sec=240,
            stop_timeout_sec=120,
            restart_timeout_sec=90,
            record_failure=failures.append,
            log=lambda msg: self.fail(msg))

        self.assertEqual(
            events,
            [('join', 240), ('join', None), ('stop', 120),
             ('start', 90, True)])
        self.assertEqual(len(failures), 1)
        self.assertIn('thread still alive 240s', failures[0])


if __name__ == '__main__':
    unittest.main()
