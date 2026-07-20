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

"""Unit-level regression tests for the `fixture` QuestDB lifecycle.

These do not launch QuestDB — they drive `QuestDbFixture` with stand-in
child processes. They pin down how `stop()` reacts when a server refuses
to shut down (originally seen in a qwp_ws_fuzz CI failure on 2026-06-10,
`test_all_mixed_with_bounce` seed=0x8f7a0293542c4692, where the server
hung in graceful shutdown):

* `stop()` escalates SIGTERM -> SIGQUIT (JVM thread dump) -> SIGKILL,
  says so on stderr, and then raises `QuestDbStopTimeout` so a server
  that won't shut down within its timeout fails the test instead of
  being silently absorbed;
* a clean shutdown stays quiet and does not raise;
* `print_log()` reads the log as bytes so a force-kill that truncates
  it mid-character can't crash the dump;
* the readiness probe (`_probe_http` and the main/min HTTP checks that
  `start()` selects between) reports up/down without raising on a
  not-yet-ready server and fails fast once the process has died.

Run with::

    cd system_test && python3 -m unittest test_fixture_unit
"""

import sys
sys.dont_write_bytecode = True

import contextlib
import io
import pathlib
import signal
import subprocess
import tempfile
import time
import unittest
from unittest import mock

import fixture


def _make_fixture(tmp_dir: str) -> fixture.QuestDbFixture:
    root_dir = pathlib.Path(tmp_dir) / 'questdb-1.2.3'
    (root_dir / 'data').mkdir(parents=True)
    return fixture.QuestDbFixture(root_dir)


# A stand-in for a JVM whose graceful shutdown hangs: ignores SIGTERM,
# answers SIGQUIT with a fake thread dump on stdout (which the fixture
# wires to the server log file), and never exits on its own.
_HUNG_JVM_SCRIPT = """
import signal, sys, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
def on_quit(signum, frame):
    sys.stdout.write('FAKE THREAD DUMP')
    sys.stdout.flush()
signal.signal(signal.SIGQUIT, on_quit)
sys.stdout.write('READY')
sys.stdout.flush()
while True:
    time.sleep(1)
"""


class StopEscalationTest(unittest.TestCase):

    @unittest.skipUnless(
        hasattr(signal, 'SIGQUIT'), 'SIGQUIT is POSIX-only')
    def test_hung_shutdown_requests_thread_dump_then_fails(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            qdb = _make_fixture(tmp_dir)
            qdb._log_path.parent.mkdir(parents=True)
            qdb._log = open(qdb._log_path, 'ab')
            qdb._proc = subprocess.Popen(
                [sys.executable, '-u', '-c', _HUNG_JVM_SCRIPT],
                stdout=qdb._log,
                stderr=subprocess.STDOUT)
            proc = qdb._proc
            try:
                # Wait until the child has installed its signal handlers
                # (it prints READY after doing so), else terminate() may
                # land before SIGTERM is ignored and no escalation runs.
                deadline = time.monotonic() + 10
                while b'READY' not in qdb._log_path.read_bytes():
                    if time.monotonic() > deadline:
                        self.fail('stand-in process never became ready')
                    time.sleep(0.02)

                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    # A server that won't shut down within the timeout is
                    # a failure: stop() force-kills it (so nothing leaks)
                    # and then raises so the test fails loudly.
                    with self.assertRaises(fixture.QuestDbStopTimeout):
                        qdb.stop(wait_timeout_sec=1)

                # Cleanup must still have happened before the raise.
                self.assertIsNone(qdb._proc)
                self.assertIsNone(qdb._log)
                self.assertIsNotNone(proc.poll(), 'child must be dead')
                messages = stderr.getvalue()
                self.assertIn('escalating to SIGKILL', messages)
                self.assertIn('thread dump', messages)
                log = qdb._log_path.read_bytes()
                self.assertIn(b'FAKE THREAD DUMP', log,
                              'SIGQUIT must reach the child')
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()

    def test_quick_shutdown_stays_quiet(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            qdb = _make_fixture(tmp_dir)
            qdb._proc = subprocess.Popen(
                [sys.executable, '-c', 'import time; time.sleep(60)'])
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                qdb.stop(wait_timeout_sec=10)  # must not raise
            self.assertIsNone(qdb._proc)
            self.assertEqual('', stderr.getvalue())


class PrintLogTest(unittest.TestCase):

    def test_handles_truncated_utf8_without_crashing(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            qdb = _make_fixture(tmp_dir)
            qdb._log_path.parent.mkdir(parents=True)
            # A lone continuation byte: invalid UTF-8, as produced when a
            # force-kill truncates the log mid-character.
            qdb._log_path.write_bytes(b'GOOD LINE\n\xff\xfe BAD BYTES\n')
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                qdb.print_log()  # must not raise
            dumped = stderr.getvalue()
            self.assertIn('GOOD LINE', dumped)
            self.assertIn('BAD BYTES', dumped)


# Stand-ins for the probe tests: no real JVM or HTTP server is launched.
class _FakeProc:
    """Minimal subprocess stand-in: poll() reports liveness."""

    def __init__(self, alive=True):
        self._alive = alive

    def poll(self):
        # Popen.poll(): None while running, the exit code once dead.
        return None if self._alive else 0


class _FakeResponse:
    """Minimal urlopen() result: the probe only reads .status."""

    def __init__(self, status):
        self.status = status


class ProbeHttpTest(unittest.TestCase):
    """`_probe_http` is the shared readiness primitive: it asserts the
    server is still alive, issues one GET, and maps the outcome to a
    bool — never letting a not-yet-ready server's OSError abort the
    enclosing retry loop."""

    def _probe_fixture(self, tmp_dir, alive=True):
        qdb = _make_fixture(tmp_dir)
        qdb.http_server_port = 9000
        qdb.http_min_port = 9003
        qdb._proc = _FakeProc(alive=alive)
        return qdb

    def test_accepted_status_returns_true(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            qdb = self._probe_fixture(tmp_dir)
            with mock.patch('urllib.request.urlopen',
                            return_value=_FakeResponse(204)):
                self.assertTrue(
                    qdb._probe_http(9000, '/ping', lambda s: s == 204))

    def test_rejected_status_returns_false(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            qdb = self._probe_fixture(tmp_dir)
            with mock.patch('urllib.request.urlopen',
                            return_value=_FakeResponse(503)):
                self.assertFalse(
                    qdb._probe_http(9000, '/ping', lambda s: s == 204))

    def test_connection_error_returns_false(self):
        # A not-yet-ready server refuses the connection; the probe reports
        # not-up rather than letting the OSError propagate and abort retry.
        with tempfile.TemporaryDirectory() as tmp_dir:
            qdb = self._probe_fixture(tmp_dir)
            with mock.patch('urllib.request.urlopen',
                            side_effect=ConnectionRefusedError()):
                self.assertFalse(
                    qdb._probe_http(9000, '/ping', lambda s: s == 204))

    def test_dead_process_fails_fast_without_probing(self):
        # _assert_server_alive runs first: a server that died during
        # startup raises immediately instead of looping until the timeout,
        # and no HTTP request is attempted.
        with tempfile.TemporaryDirectory() as tmp_dir:
            qdb = self._probe_fixture(tmp_dir, alive=False)
            with mock.patch('urllib.request.urlopen') as urlopen:
                with self.assertRaises(RuntimeError):
                    qdb._probe_http(9000, '/ping', lambda s: s == 204)
                urlopen.assert_not_called()


class CheckHttpUpTest(unittest.TestCase):
    """The two readiness checks must target distinct ports and paths and,
    crucially, distinct status predicates: main `/ping` answers 204
    exactly, while the min health endpoint counts any 2xx as healthy."""

    def _capture_probe(self, tmp_dir):
        qdb = _make_fixture(tmp_dir)
        qdb.http_server_port = 9000
        qdb.http_min_port = 9003
        calls = []
        qdb._probe_http = (
            lambda port, path, status_ok:
            calls.append((port, path, status_ok)) or True)
        return qdb, calls

    def test_main_probes_ping_requiring_exactly_204(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            qdb, calls = self._capture_probe(tmp_dir)
            self.assertTrue(qdb._check_main_http_up())
            (port, path, status_ok), = calls
            self.assertEqual(port, 9000)
            self.assertEqual(path, '/ping')
            self.assertTrue(status_ok(204))
            self.assertFalse(status_ok(200))
            self.assertFalse(status_ok(503))

    def test_min_probes_status_accepting_any_2xx(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            qdb, calls = self._capture_probe(tmp_dir)
            self.assertTrue(qdb._check_min_http_up())
            (port, path, status_ok), = calls
            self.assertEqual(port, 9003)
            self.assertEqual(path, '/status')
            self.assertTrue(status_ok(200))
            self.assertTrue(status_ok(204))
            self.assertTrue(status_ok(299))
            self.assertFalse(status_ok(300))
            self.assertFalse(status_ok(404))


class StartProbeSelectionTest(unittest.TestCase):
    """start() picks its readiness check and timeout from its arguments:
    an initial start waits on main `/ping` with the generous default
    timeout, while a bounce restart waits on the min-HTTP health endpoint
    with the tight cap, so a stuck boot fails fast instead of eating into
    the producers' budgets."""

    def _captured_start(self, tmp_dir, **start_kwargs):
        qdb = _make_fixture(tmp_dir)
        # Skip the post-start version query, which would hit real HTTP.
        qdb._version_queried = True
        captured = {}

        def fake_retry(predicate, timeout_sec=None, **_):
            captured['predicate'] = predicate
            captured['timeout_sec'] = timeout_sec
            return True

        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), \
                mock.patch.object(fixture, 'retry', fake_retry), \
                mock.patch.object(fixture, '_find_java', return_value='java'), \
                mock.patch.object(fixture.subprocess, 'Popen',
                                  return_value=_FakeProc(alive=True)), \
                mock.patch.object(fixture.atexit, 'register'):
            qdb.start(**start_kwargs)
        if qdb._log:
            qdb._log.close()
        return captured

    def test_initial_start_gates_on_main_http(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            captured = self._captured_start(tmp_dir)
            self.assertEqual(
                captured['predicate'].__name__, '_check_main_http_up')
            self.assertEqual(captured['timeout_sec'], 300)

    def test_bounce_start_gates_on_min_http_with_tight_cap(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            captured = self._captured_start(
                tmp_dir, start_timeout_sec=90, probe_min_http=True)
            self.assertEqual(
                captured['predicate'].__name__, '_check_min_http_up')
            self.assertEqual(captured['timeout_sec'], 90)


if __name__ == '__main__':
    unittest.main()
