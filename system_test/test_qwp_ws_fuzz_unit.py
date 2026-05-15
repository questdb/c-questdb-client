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
directly with injected mocks. The point is to pin down the
classification of transient network errors (the bug surfaced by
`test_all_mixed_with_bounce` seed=0xa2127d1c2e42ba0f on Linux CI and
seed=0x8da2facf78940b06 on Windows CI) so the timing race is no
longer the only way to verify the fix.

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


if __name__ == '__main__':
    unittest.main()
