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
* a managed macOS JVM inherits the hard open-file limit without leaving
  the Python test runner's soft limit changed.

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
import types
import unittest
from unittest import mock

import fixture


def _make_fixture(tmp_dir: str) -> fixture.QuestDbFixture:
    root_dir = pathlib.Path(tmp_dir) / 'questdb-1.2.3'
    (root_dir / 'data').mkdir(parents=True)
    return fixture.QuestDbFixture(root_dir)


class MacOsNoFileLimitTest(unittest.TestCase):

    def test_raises_for_child_then_restores_runner_limit(self):
        fake_resource = types.SimpleNamespace(
            RLIMIT_NOFILE=8,
            getrlimit=mock.Mock(return_value=(256, 1_048_576)),
            setrlimit=mock.Mock())

        with mock.patch.object(fixture.sys, 'platform', 'darwin'), \
                mock.patch.dict(sys.modules, {'resource': fake_resource}):
            with fixture._macos_java_nofile_limit() as prepared:
                self.assertTrue(prepared)
                fake_resource.setrlimit.assert_called_once_with(
                    fake_resource.RLIMIT_NOFILE,
                    (1_048_576, 1_048_576))

        self.assertEqual(
            fake_resource.setrlimit.call_args_list,
            [
                mock.call(fake_resource.RLIMIT_NOFILE,
                          (1_048_576, 1_048_576)),
                mock.call(fake_resource.RLIMIT_NOFILE,
                          (256, 1_048_576)),
            ])

    def test_keeps_jvm_default_when_limit_preparation_fails(self):
        fake_resource = types.SimpleNamespace(
            RLIMIT_NOFILE=8,
            getrlimit=mock.Mock(return_value=(256, 1_048_576)),
            setrlimit=mock.Mock(side_effect=ValueError('not permitted')))
        stderr = io.StringIO()

        with mock.patch.object(fixture.sys, 'platform', 'darwin'), \
                mock.patch.dict(sys.modules, {'resource': fake_resource}), \
                contextlib.redirect_stderr(stderr):
            with fixture._macos_java_nofile_limit() as prepared:
                self.assertFalse(prepared)

        self.assertIn('could not prepare', stderr.getvalue())

    def test_managed_macos_jvm_disables_max_fd_limit(self):
        fake_proc = mock.Mock()
        fake_proc.poll.return_value = None
        ping_response = mock.Mock(status=204)

        @contextlib.contextmanager
        def prepared_limit():
            yield True

        with tempfile.TemporaryDirectory() as tmp_dir:
            qdb = _make_fixture(tmp_dir)
            with mock.patch.object(
                    fixture, '_macos_java_nofile_limit', prepared_limit), \
                    mock.patch.object(
                        fixture, 'discover_avail_ports',
                        return_value=[9000, 9009, 8812]), \
                    mock.patch.object(
                        fixture, '_find_java', return_value='/jdk/bin/java'), \
                    mock.patch.object(
                        fixture.subprocess, 'Popen', return_value=fake_proc
                    ) as popen, \
                    mock.patch.object(
                        fixture.urllib.request, 'urlopen',
                        return_value=ping_response), \
                    mock.patch.object(
                        qdb, 'query_version', return_value=(10, 0, 2)), \
                    mock.patch.object(fixture.atexit, 'register'):
                qdb.start()

            try:
                launch_args = popen.call_args.args[0]
                self.assertIn('-XX:-MaxFDLimit', launch_args)
            finally:
                qdb._proc = None
                qdb._log.close()
                qdb._log = None


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


class TimeoutDiagnosticsTest(unittest.TestCase):

    @unittest.skipUnless(
        hasattr(signal, 'SIGQUIT'), 'SIGQUIT is POSIX-only')
    def test_probes_ping_and_requests_thread_dump(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            qdb = _make_fixture(tmp_dir)
            qdb.http_server_port = 9000
            qdb._proc = mock.Mock()
            qdb._proc.poll.return_value = None
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr), \
                    mock.patch.object(
                        fixture.urllib.request,
                        'urlopen',
                        side_effect=TimeoutError('timed out')), \
                    mock.patch.object(fixture.time, 'sleep'):
                qdb.capture_timeout_diagnostics('example.test')

            qdb._proc.send_signal.assert_called_once_with(signal.SIGQUIT)
            messages = stderr.getvalue()
            self.assertIn('/ping after timeout failed', messages)
            self.assertIn('Requested a JVM thread dump', messages)


if __name__ == '__main__':
    unittest.main()
