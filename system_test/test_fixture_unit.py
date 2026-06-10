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
child processes and sockets. They pin down the hardening added after a
qwp_ws_fuzz CI failure (2026-06-10, `test_all_mixed_with_bounce`
seed=0x8f7a0293542c4692) where a hung graceful shutdown cascaded into a
zombie server that the port-based health checks mistook for the
freshly launched instance:

* `stop()` escalates SIGTERM -> SIGQUIT (JVM thread dump) -> SIGKILL
  and says so on stderr;
* `start()` refuses to run while the previous process is still alive;
* `_await_ports_free()` detects a leftover process still serving our
  ports;
* `print_log()` dumps only the current instance's slice of the
  cumulative server log.

Run with::

    cd system_test && python3 -m unittest test_fixture_unit
"""

import sys
sys.dont_write_bytecode = True

import contextlib
import io
import pathlib
import signal
import socket
import subprocess
import tempfile
import time
import unittest
import unittest.mock

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
    def test_hung_shutdown_requests_thread_dump_then_kills(self):
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
                    qdb.stop(wait_timeout_sec=1)

                self.assertIsNone(qdb._proc)
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
                qdb.stop(wait_timeout_sec=10)
            self.assertIsNone(qdb._proc)
            self.assertEqual('', stderr.getvalue())


class DoubleStartGuardTest(unittest.TestCase):

    def test_start_refuses_while_previous_instance_alive(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            qdb = _make_fixture(tmp_dir)
            qdb._proc = subprocess.Popen(
                [sys.executable, '-c', 'import time; time.sleep(60)'])
            try:
                with self.assertRaisesRegex(RuntimeError, 'still running'):
                    qdb.start()
            finally:
                qdb._proc.kill()
                qdb._proc.wait()

    def test_start_allowed_after_previous_instance_died(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            qdb = _make_fixture(tmp_dir)
            qdb._proc = subprocess.Popen([sys.executable, '-c', 'pass'])
            qdb._proc.wait()
            # The guard must not fire for a dead process; the port check
            # is the next thing start() does, so use it as the witness
            # that we got past the guard.
            qdb.http_server_port = 1  # forces the restart branch
            with unittest.mock.patch.object(qdb, '_await_ports_free',
                                            side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt):
                    qdb.start()


class AwaitPortsFreeTest(unittest.TestCase):

    def test_detects_port_still_serving(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            qdb = _make_fixture(tmp_dir)
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0))
                listener.listen(1)
                qdb.http_server_port = listener.getsockname()[1]
                with self.assertRaisesRegex(
                        RuntimeError, 'still serving connections'):
                    qdb._await_ports_free(timeout_sec=0.3)

    def test_returns_once_ports_are_free(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            qdb = _make_fixture(tmp_dir)
            listener = socket.socket()
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)
            qdb.http_server_port = listener.getsockname()[1]
            listener.close()
            qdb._await_ports_free(timeout_sec=1.0)  # must not raise


class PrintLogOffsetTest(unittest.TestCase):

    def test_prints_only_current_instance_slice(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            qdb = _make_fixture(tmp_dir)
            qdb._log_path.parent.mkdir(parents=True)
            old = b'OLD INSTANCE LINE\n'
            new = b'NEW INSTANCE LINE\n'
            qdb._log_path.write_bytes(old + new)
            qdb._log_start_offset = len(old)
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                qdb.print_log()
            dumped = stderr.getvalue()
            self.assertNotIn('OLD INSTANCE LINE', dumped)
            self.assertIn('NEW INSTANCE LINE', dumped)
            self.assertIn(f'byte offset {len(old)}', dumped)

    def test_zero_offset_prints_everything_without_header(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            qdb = _make_fixture(tmp_dir)
            qdb._log_path.parent.mkdir(parents=True)
            qdb._log_path.write_bytes(b'FIRST INSTANCE LINE\n')
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                qdb.print_log()
            dumped = stderr.getvalue()
            self.assertIn('FIRST INSTANCE LINE', dumped)
            self.assertNotIn('byte offset', dumped)


class TryQueryVersionTest(unittest.TestCase):

    def test_transient_network_error_returns_none(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            qdb = _make_fixture(tmp_dir)
            with socket.socket() as probe:
                probe.bind(('127.0.0.1', 0))
                free_port = probe.getsockname()[1]
            # Nothing listens on free_port any more: connection refused.
            qdb.http_server_port = free_port
            self.assertIsNone(qdb._try_query_version())


if __name__ == '__main__':
    unittest.main()
