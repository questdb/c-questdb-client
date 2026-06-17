#!/usr/bin/env python3

################################################################################
##     ___                  _   ____  ____
##    / _ \ _   _  ___  ___| |_|  _ \| __ )
##   | | | | | | |/ _ \/ __| __| | | |  _ \
##   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
##    \__\_\\__,_|\___||___/\__|____/|____/
##
##  Copyright (c) 2014-2019 Appsicle
##  Copyright (c) 2019-2025 QuestDB
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

"""
Mid-query failover system test for the QWP egress reader.

Spins up two standalone QuestDB instances at `build/questdb/server1`
and `build/questdb/server2`, seeds the same table on both, runs a SELECT
against instance #1, kills instance #1 mid-stream, and verifies the
egress reader transparently reconnects to instance #2 and replays the
query.

There is no Python wrapper for the egress reader, so the "client" is the
prebuilt `failover_client` Rust binary under `system_test/failover_clients/`.
The test invokes it as a subprocess and parses its `completed:` summary
line.

Usage:
    # against a locally-built questdb repo:
    python3 system_test/test_egress_failover.py --repo ./questdb -v

    # against a released version:
    python3 system_test/test_egress_failover.py --versions 7.4.0 -v
"""

import sys
sys.dont_write_bytecode = True

import argparse
import json
import os
import pathlib
import shutil
import socket
import subprocess
import textwrap
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request

# Reuse fixture.py's path/port/install helpers but skip QuestDbFixture
# itself — that fixture hard-wires `<root_dir>/data` as the data path, and
# we want explicit `build/questdb/server1` / `server2` directories per
# the test brief.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from fixture import (
    Project,
    discover_avail_ports,
    install_questdb,
    install_questdb_from_repo,
    list_questdb_releases,
    _find_java,
)


PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent

# Row count per server. Large enough that the SELECT-after-failover
# spans many RESULT_BATCH frames (so we're confident the failover replay
# path actually carries data, not just terminals).
ROW_COUNT = 1_000_000

# Hard timeout on each phase: waiting for the BATCH_RECEIVED signal,
# and waiting for the helper to exit after the kill. Loopback on a
# modern machine handles a 1M-row replay in well under this.
HELPER_READY_TIMEOUT_SEC = 60
HELPER_DONE_TIMEOUT_SEC = 180


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _wait_for_ping(host, port, timeout_sec=300.0):
    deadline = time.monotonic() + timeout_sec
    last_err = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(
                    f'http://{host}:{port}/ping', timeout=1) as resp:
                if resp.status == 204:
                    return
        except (urllib.error.URLError, ConnectionError, OSError) as e:
            last_err = e
        time.sleep(0.2)
    raise TimeoutError(
        f'QuestDB at http://{host}:{port}/ping did not respond '
        f'within {timeout_sec}s; last error: {last_err}')


def _http_exec(host, port, sql, timeout_sec=300):
    """Run a single SQL statement via the /exec REST endpoint."""
    url = f'http://{host}:{port}/exec?' + urllib.parse.urlencode({'query': sql})
    req = urllib.request.Request(url, method='GET')
    with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
        body = resp.read()
        if resp.status != 200:
            raise RuntimeError(f'exec({sql!r}) HTTP {resp.status}: {body!r}')
        data = json.loads(body.decode('utf-8'))
        if 'error' in data:
            raise RuntimeError(f'exec({sql!r}) error: {data["error"]}')
        return data


# ---------------------------------------------------------------------------
# Standalone QuestDB instance fixture
# ---------------------------------------------------------------------------


class StandaloneInstance:
    """
    A single QuestDB instance with an explicit data directory.

    Differs from `QuestDbFixture` in three ways:

      - Caller chooses the data directory (`build/questdb/server1`,
        `server2`, ...) rather than `<root_dir>/data`. This matches
        the test brief's wording.
      - The jar lives somewhere else (typically `build/questdb/repo/bin/`
        or `build/questdb/<vers>/bin/`); we don't need a `bin/` sibling
        next to the data dir.
      - `kill()` sends SIGKILL — a graceful `terminate()` would let the
        server send a WS Close to in-flight cursors, which is exactly
        the failure mode we DON'T want to test (failover would not
        engage on a clean disconnect).
    """

    def __init__(self, jar, data_dir, label):
        self.jar = jar
        self.data_dir = pathlib.Path(data_dir)
        self.label = label
        self.host = '127.0.0.1'
        self.http_port = None  # also serves QWP egress on /read/v1
        self.ilp_port = None
        self.pg_port = None
        self._proc = None
        self._log_file = None

    def start(self):
        # Reset the data dir so reruns are deterministic. Leftovers from
        # a previous crashed run (lock files, partial WAL) would either
        # block startup or skew row counts.
        if self.data_dir.exists():
            shutil.rmtree(self.data_dir)
        (self.data_dir / 'conf').mkdir(parents=True)
        (self.data_dir / 'log').mkdir(parents=True)

        self.http_port, self.ilp_port, self.pg_port = discover_avail_ports(3)
        conf = textwrap.dedent(f'''
            http.bind.to=0.0.0.0:{self.http_port}
            line.tcp.net.bind.to=0.0.0.0:{self.ilp_port}
            pg.net.bind.to=0.0.0.0:{self.pg_port}
            http.min.enabled=false
            line.udp.enabled=false
            telemetry.enabled=false
            cairo.commit.lag=100
        ''').lstrip()
        (self.data_dir / 'conf' / 'server.conf').write_text(
            conf, encoding='utf-8')

        java = _find_java()
        log_path = self.data_dir / 'log' / 'log.txt'
        self._log_file = open(log_path, 'ab')
        cmd = [
            str(java),
            f'-DQuestDB-{self.label}',
            '-ea',
            '-Dnoebug',
            '-XX:+UnlockExperimentalVMOptions',
            '-XX:+AlwaysPreTouch',
            # Required so the io.questdb module can reach
            # jdk.internal.vm.ContinuationScope (used by WorkerContinuation);
            # without it every worker thread dies with IllegalAccessError and
            # the server never binds its HTTP port. Mirrors fixture.py.
            '--add-exports=java.base/jdk.internal.vm=io.questdb',
            '-p', str(self.jar),
            '-m', 'io.questdb/io.questdb.ServerMain',
            '-d', str(self.data_dir),
        ]
        sys.stderr.write(
            f'[{self.label}] launching: data={self.data_dir} '
            f'http={self.http_port} ilp={self.ilp_port} pg={self.pg_port}\n')
        self._proc = subprocess.Popen(
            cmd,
            cwd=str(self.data_dir),
            stdout=self._log_file,
            stderr=subprocess.STDOUT,
            close_fds=True)
        try:
            _wait_for_ping(self.host, self.http_port)
        except Exception:
            self.dump_log()
            self.kill()
            raise
        sys.stderr.write(f'[{self.label}] /ping is up.\n')

    def http_exec(self, sql):
        return _http_exec(self.host, self.http_port, sql)

    def is_alive(self):
        return self._proc is not None and self._proc.poll() is None

    def kill(self):
        """SIGKILL — simulates a server crash, no graceful WS Close."""
        if self._proc is not None and self._proc.poll() is None:
            self._proc.kill()
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
        if self._log_file is not None:
            self._log_file.close()
            self._log_file = None
        self._proc = None

    def stop(self):
        """SIGTERM — graceful shutdown. Use kill() to simulate a crash."""
        if self._proc is not None and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait(timeout=5)
        if self._log_file is not None:
            self._log_file.close()
            self._log_file = None
        self._proc = None

    def dump_log(self, tail_lines=100):
        log_path = self.data_dir / 'log' / 'log.txt'
        if not log_path.exists():
            sys.stderr.write(f'[{self.label}] no log at {log_path}\n')
            return
        text = log_path.read_text(encoding='utf-8', errors='replace')
        lines = text.splitlines()
        sys.stderr.write(f'[{self.label}] last {tail_lines} log lines:\n')
        for line in lines[-tail_lines:]:
            sys.stderr.write(f'    {line}\n')


# ---------------------------------------------------------------------------
# Setup helpers
# ---------------------------------------------------------------------------


def _resolve_jar(args):
    """
    Locate (or download) a QuestDB jar. Mirrors test.py's modes.
    """
    if args.repo:
        repo_root = install_questdb_from_repo(pathlib.Path(args.repo))
        return repo_root / 'bin' / 'questdb.jar'
    if args.versions:
        version = args.versions[0]
        url = (
            f'https://github.com/questdb/questdb/releases/download/'
            f'{version}/questdb-{version}-no-jre-bin.tar.gz')
        return install_questdb(version, url) / 'bin' / 'questdb.jar'
    # No mode specified: pick the latest release.
    versions = list(list_questdb_releases(1))
    if not versions:
        raise RuntimeError(
            'Could not list QuestDB releases. Pass --repo or --versions '
            'explicitly.')
    vers, url = versions[0]
    return install_questdb(vers, url) / 'bin' / 'questdb.jar'


def _build_helper_clients():
    """
    Pre-build all helper binaries from `system_test/failover_clients/`
    The Cargo project has no default binary — every binary lives in
    `src/bin/` and is selected by name:

      - `failover_client` — synchronised helper for the mid-query
        test. Prints `BATCH_RECEIVED` after the first batch and blocks
        on stdin so the harness can deterministically kill the
        upstream server before the cursor reads more.
      - `simple_client` — minimal connect-and-drain helper for the
        connect-time endpoint-walk test, which needs no synchronisation.
      - `exhaustion_client` — synchronised helper for the
        failover-exhaustion test. Same BATCH_RECEIVED handshake as
        `failover_client`, but after the green-light it asserts that
        every Reader operation on a post-exhaustion (poisoned) reader
        returns a clean error instead of panicking.

    `cargo build --release` produces all of them in one shot; returns
    `(failover_client_path, simple_client_path, exhaustion_client_path)`.
    """
    project_dir = pathlib.Path(__file__).resolve().parent / 'failover_clients'
    sys.stderr.write(
        'building failover_client + simple_client + exhaustion_client '
        '(release)...\n')
    subprocess.check_call(
        ['cargo', 'build', '--release'],
        cwd=str(project_dir))
    release_dir = project_dir / 'target' / 'release'
    suffix = '.exe' if os.name == 'nt' else ''
    sync_bin = release_dir / f'failover_client{suffix}'
    simple_bin = release_dir / f'simple_client{suffix}'
    exhaustion_bin = release_dir / f'exhaustion_client{suffix}'
    for path in (sync_bin, simple_bin, exhaustion_bin):
        if not path.is_file():
            raise FileNotFoundError(f'helper binary not found at {path}')
    return sync_bin, simple_bin, exhaustion_bin


def _seed_table(server, table, row_count, timeout_sec=60):
    """
    Populate `table` with `row_count` rows.

    Uses CREATE TABLE AS SELECT long_sequence(N) so the seed runs
    server-side rather than crossing the network. The table is created
    `BYPASS WAL` because the default WAL path commits asynchronously in
    multiple transactions for large CTAS — a follow-up `SELECT count(*)`
    can race the WAL apply job and observe partial counts. BYPASS WAL
    keeps the insert synchronous so the count is correct on first read.

    The count is then polled with a timeout in case async background
    work (column index build, etc.) still trails the visible row count.
    """
    server.http_exec(f"DROP TABLE IF EXISTS {table}")
    server.http_exec(
        f"CREATE TABLE {table} AS ("
        f"  SELECT cast(x*1000 AS timestamp) ts, x val "
        f"  FROM long_sequence({row_count})"
        f") TIMESTAMP(ts) PARTITION BY DAY BYPASS WAL")
    deadline = time.monotonic() + timeout_sec
    last_got = None
    while time.monotonic() < deadline:
        resp = server.http_exec(f"SELECT count(*) FROM {table}")
        last_got = resp['dataset'][0][0]
        if last_got == row_count:
            return
        time.sleep(0.2)
    raise RuntimeError(
        f'{server.label}: expected {row_count} rows in {table} within '
        f'{timeout_sec}s, last observed {last_got}')


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------


_ARGS = argparse.Namespace(repo=None, versions=None)


class FailoverTest(unittest.TestCase):
    """
    Mid-query failover end-to-end:

      1. Two standalone QuestDB instances at `build/questdb/server1` and
         `build/questdb/server2` with disjoint ports.
      2. Seed both with the same `failover_test` table.
      3. Spawn the failover_client helper with a multi-addr connect
         string. The cursor opens against instance #1 (rotation walks
         left-to-right) and consumes one batch of the SELECT result.
      4. The helper signals via STDOUT that it has the first batch;
         Python SIGKILLs instance #1 and writes a green-light line on
         the helper's STDIN.
      5. The cursor's next `read_frame()` fails (peer reset); failover
         reconnects to instance #2 and replays QUERY_REQUEST with a
         fresh request_id; streaming resumes from batch_seq=0.
      6. Assert: helper exits 0, reports `failover_resets >= 1`,
         delivers the full ROW_COUNT rows, and the final cursor
         endpoint is instance #2.
    """

    @classmethod
    def setUpClass(cls):
        proj = Project()

        cls.jar = _resolve_jar(_ARGS)

        # The two data dirs the test brief asks for, side by side under
        # the project's build/questdb/.
        data_root = proj.build_dir / 'questdb'
        data_root.mkdir(parents=True, exist_ok=True)
        cls.server1_dir = data_root / 'server1'
        cls.server2_dir = data_root / 'server2'

        (
            cls.client_bin,
            cls.simple_client_bin,
            cls.exhaustion_client_bin,
        ) = _build_helper_clients()

        cls.server1 = StandaloneInstance(cls.jar, cls.server1_dir, 'server1')
        cls.server2 = StandaloneInstance(cls.jar, cls.server2_dir, 'server2')
        cls.server1.start()
        try:
            cls.server2.start()
        except Exception:
            cls.server1.kill()
            raise

        try:
            _seed_table(cls.server1, 'failover_test', ROW_COUNT)
            _seed_table(cls.server2, 'failover_test', ROW_COUNT)
        except Exception:
            cls.server1.dump_log()
            cls.server2.dump_log()
            cls.server1.kill()
            cls.server2.kill()
            raise

    @classmethod
    def tearDownClass(cls):
        # SIGKILL on cleanup — terminate() hangs occasionally if a
        # connection is mid-cancel; the data dirs are wiped on next run.
        if hasattr(cls, 'server1'):
            cls.server1.kill()
        if hasattr(cls, 'server2'):
            cls.server2.kill()

    def setUp(self):
        """
        Per-test: ensure both servers are alive and seeded.

        A previous test in the class may have killed them on purpose
        (`test_mid_query_failover` kills server #1; the exhaustion test
        kills both). Each test starts from a clean slate so we don't
        rely on a particular alphabetical ordering of method names.
        Restart cost is paid only when needed: a healthy `is_alive()`
        is just a `Popen.poll()`, no /ping round-trip.
        """
        respawned = []
        for srv in (self.server1, self.server2):
            if not srv.is_alive():
                sys.stderr.write(f'[{srv.label}] respawning before next test\n')
                srv.start()
                respawned.append(srv)
        for srv in respawned:
            _seed_table(srv, 'failover_test', ROW_COUNT)

    def test_initial_connect_walks_past_unreachable(self):
        """
        Mirrors `initial_connect_walks_all_endpoints` in
        `questdb-rs/tests/egress_failover.rs`:

        The connect string lists an unreachable address first and a
        healthy endpoint second. `Reader::from_conf` MUST silently walk
        past the refused-connect attempt and land on the healthy one,
        then execute a query against it. No mid-query failover happens
        — `failover_resets=0` — only the connect-time endpoint walk.

        Uses `simple_client` (no kill, no synchronisation, no stdin/
        stdout dance) — just connect, run query, drain, print stats.
        Spawned via subprocess.run; the test is just three assertions
        against parsed stderr.

        Test method name sorts before `test_mid_query_failover` so this
        test runs first; that one tears down server #1, but only uses
        server #2 for the post-failover endpoint anyway.
        """
        dead_addr = self._reserve_then_close_addr()
        # Server #1 listed first as the unreachable; server #2 is the
        # healthy fallback. (We don't use server1 at all here — we
        # could, but a closed-port `dead_addr` is closer to what the
        # Rust mock-server test does and simpler to reason about.)
        conf = (
            f'ws::addr={dead_addr},'
            f'127.0.0.1:{self.server2.http_port}')
        sql = 'select 1'

        result = subprocess.run(
            [str(self.simple_client_bin), conf, sql],
            capture_output=True,
            text=True,
            timeout=HELPER_DONE_TIMEOUT_SEC)

        if result.returncode != 0:
            self.server2.dump_log()
            self.fail(
                f'simple_client exited non-zero ({result.returncode}) — '
                f'Reader::from_conf failed to walk past the unreachable '
                f'endpoint.\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}')

        stderr = result.stderr

        # `connected to <host>:<port> (cluster role: ...)` — printed
        # right after Reader::from_conf returns; tells us which
        # endpoint Reader picked.
        connected = next(
            (l for l in stderr.splitlines() if l.startswith('connected to ')),
            None)
        self.assertIsNotNone(
            connected,
            f'no "connected to" line in stderr.\nSTDERR:\n{stderr}')
        self.assertIn(
            f':{self.server2.http_port} ', connected,
            f'cursor did not walk past the unreachable endpoint to '
            f'server #2 (port {self.server2.http_port}). got: {connected!r}')

        # `completed: ... failover_resets=0 final_endpoint=...` — the
        # counter must be 0 because connect-time walk doesn't increment
        # it (only mid-query reconnects do).
        completion = next(
            (l for l in stderr.splitlines() if l.startswith('completed:')),
            None)
        self.assertIsNotNone(
            completion,
            f'no "completed:" line in stderr.\nSTDERR:\n{stderr}')

        def field(name):
            for tok in completion.split():
                if tok.startswith(f'{name}='):
                    return tok.split('=', 1)[1]
            self.fail(f'field {name!r} missing from {completion!r}')

        self.assertEqual(
            int(field('failover_resets')), 0,
            f'connect-time endpoint walk must NOT increment '
            f'failover_resets (that counter is for mid-query '
            f'reconnects only). completion: {completion}')
        self.assertIn(
            str(self.server2.http_port), field('final_endpoint'),
            f'final_endpoint should be server #2. completion: {completion}')

    @staticmethod
    def _reserve_then_close_addr():
        """
        Bind a fresh 127.0.0.1 port and immediately close it. The
        kernel-assigned port is then briefly unbound, so the next
        `connect()` attempt against it returns ConnectRefused — exactly
        the "unreachable endpoint" condition the test needs.

        Mirrors `reserve_then_close_addr()` in egress_failover.rs.
        Race window vs. another process binding the same port is
        non-zero in theory; in test isolation on loopback it is fine.
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(('127.0.0.1', 0))
            host, port = s.getsockname()
        finally:
            s.close()
        return f'{host}:{port}'

    def test_mid_query_failover(self):
        self.assertTrue(self.server1.is_alive())
        self.assertTrue(self.server2.is_alive())

        # Server #1 listed FIRST so the cursor opens against it.
        # `target=primary` accepts STANDALONE per spec §11.8.
        conf = (
            f'ws::addr=127.0.0.1:{self.server1.http_port},'
            f'127.0.0.1:{self.server2.http_port};target=primary')
        sql = 'SELECT * FROM failover_test ORDER BY val'

        sys.stderr.write(
            f'spawning {self.client_bin.name} '
            f'addr=#1({self.server1.http_port}),#2({self.server2.http_port})\n')
        proc = subprocess.Popen(
            [str(self.client_bin), conf, sql],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1)  # line-buffered stdout so we see READY promptly

        try:
            stdout, stderr = self._drive_failover(proc)
        finally:
            # Defensive: never leave a runaway helper.
            if proc.poll() is None:
                proc.kill()
                try:
                    proc.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    pass

        if proc.returncode != 0:
            self.server2.dump_log()
            self.fail(
                f'helper exited non-zero ({proc.returncode}).\n'
                f'STDOUT:\n{stdout}\nSTDERR:\n{stderr}')

        # Helper's final stderr line:
        #   completed: batches=N rows=M failover_resets=K final_endpoint=...
        completion = next(
            (line for line in stderr.splitlines()
             if line.startswith('completed:')),
            None)
        self.assertIsNotNone(
            completion,
            f'no completion line in helper stderr.\nSTDERR:\n{stderr}')

        def field(name):
            for tok in completion.split():
                if tok.startswith(f'{name}='):
                    return tok.split('=', 1)[1]
            self.fail(
                f'field {name!r} missing from completion line: {completion}')

        rows = int(field('rows'))
        resets = int(field('failover_resets'))
        final_endpoint = field('final_endpoint')

        sys.stderr.write(f'helper reported: {completion}\n')

        # The synchronization in the helper guarantees the kill lands
        # mid-stream, so `failover_resets` MUST be at least 1. Anything
        # less means the failover machinery silently no-op'd.
        self.assertGreaterEqual(
            resets, 1,
            f'no failover happened despite mid-stream kill. '
            f'completion: {completion}\nSTDERR:\n{stderr}')

        # After failover the cursor restarts from `batch_seq=0` against
        # server #2, so the final row count must equal ROW_COUNT exactly
        # (not a higher value from double-counting the batches consumed
        # against #1 before the kill — the helper resets its counter in
        # the on_failover_reset callback).
        self.assertEqual(
            rows, ROW_COUNT,
            f'rows after failover != {ROW_COUNT}. '
            f'completion: {completion}')

        # Verify the cursor ended on server #2.
        self.assertIn(
            str(self.server2.http_port), final_endpoint,
            f'expected to land on server #2 (port {self.server2.http_port}); '
            f'got {final_endpoint!r}. completion: {completion}')

    def _drive_failover(self, proc):
        """
        Synchronized failover dance:
          1. Wait for the helper to print BATCH_RECEIVED on stdout
             (cursor has consumed at least one batch from server #1).
          2. SIGKILL server #1.
          3. Send the green-light line to the helper's stdin.
          4. Wait for the helper to exit, returning (stdout, stderr).
        Any phase that times out fails the test.
        """
        # Phase 1: wait for BATCH_RECEIVED. proc.stdout.readline() blocks
        # until a newline arrives or the helper exits.
        deadline = time.monotonic() + HELPER_READY_TIMEOUT_SEC
        ready = False
        stdout_acc = []
        while time.monotonic() < deadline:
            line = proc.stdout.readline()
            if line == '':
                # EOF — helper exited prematurely.
                break
            stdout_acc.append(line)
            if line.strip() == 'BATCH_RECEIVED':
                ready = True
                break
        if not ready:
            proc.kill()
            stdout_rest, stderr = proc.communicate()
            stdout = ''.join(stdout_acc) + stdout_rest
            self.server1.dump_log()
            self.server2.dump_log()
            self.fail(
                f'helper did not print BATCH_RECEIVED within '
                f'{HELPER_READY_TIMEOUT_SEC}s.\n'
                f'STDOUT:\n{stdout}\nSTDERR:\n{stderr}')

        # Phase 2: kill server #1.
        self.assertTrue(
            self.server1.is_alive(),
            'server #1 died before we could kill it (JVM crash?)')
        sys.stderr.write('SIGKILLing server #1 mid-stream...\n')
        self.server1.kill()

        # Phase 3: green-light the helper to drain remaining batches.
        try:
            proc.stdin.write('GO\n')
            proc.stdin.flush()
        except (BrokenPipeError, OSError) as e:
            # Helper died between BATCH_RECEIVED and now (unlikely, but
            # don't mask the real error).
            sys.stderr.write(f'failed to signal helper: {e}\n')

        # Phase 4: wait for completion.
        try:
            stdout_rest, stderr = proc.communicate(
                timeout=HELPER_DONE_TIMEOUT_SEC)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout_rest, stderr = proc.communicate()
            self.server2.dump_log()
            self.fail(
                f'helper did not exit within {HELPER_DONE_TIMEOUT_SEC}s '
                f'after green-light.\n'
                f'STDOUT (so far):\n{"".join(stdout_acc)}{stdout_rest}\n'
                f'STDERR:\n{stderr}')

        return ''.join(stdout_acc) + stdout_rest, stderr

    def test_reader_poisoned_after_failover_exhaustion(self):
        """
        Mirrors `reader_poisoned_after_failover_exhaustion_returns_err_not_panic`
        in `questdb-rs/tests/egress_failover.rs`:

        Connect to both servers with `failover_max_attempts=1` and
        tight backoffs. Read the first batch from server #1, then kill
        BOTH servers. The cursor's next read trips a transport error;
        the failover loop walks to server #2 (also dead) and exhausts
        its budget. `cursor.next_batch()` returns Err — and crucially,
        every subsequent operation on the now-poisoned `Reader`
        (transport=None) MUST surface a clean error rather than panic
        through `Option::expect`.

        Uses the dedicated `exhaustion_client` helper, which checks all
        three contracts in-process and exits non-zero if any one
        panics or returns the wrong code.
        """
        self.assertTrue(self.server1.is_alive())
        self.assertTrue(self.server2.is_alive())

        # Tight backoff so exhaustion is fast even with two retries
        # (initial attempt + max_attempts=1 → 2 total walks).
        conf = (
            f'ws::addr=127.0.0.1:{self.server1.http_port},'
            f'127.0.0.1:{self.server2.http_port};'
            f'failover_max_attempts=1;'
            f'failover_backoff_initial_ms=1;'
            f'failover_backoff_max_ms=2')
        sql = 'SELECT * FROM failover_test ORDER BY val'

        sys.stderr.write(
            f'spawning {self.exhaustion_client_bin.name} '
            f'addr=#1({self.server1.http_port}),#2({self.server2.http_port})\n')
        proc = subprocess.Popen(
            [str(self.exhaustion_client_bin), conf, sql],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1)

        try:
            stdout, stderr = self._drive_exhaustion(
                proc, [self.server1, self.server2])
        finally:
            if proc.poll() is None:
                proc.kill()
                try:
                    proc.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    pass

        # The helper exits 0 only if every Reader operation on the
        # poisoned reader returned an Err (not a panic, not an Ok).
        # Non-zero status means one of:
        #   2  panic (caught as `expect` unwind, not in our control)
        #   10 first batch never arrived
        #   11 first next_batch errored unexpectedly
        #   12 next_batch returned Ok after both servers were killed
        #   13 server_version returned Ok on poisoned reader
        #   14 query.execute returned Ok on poisoned reader
        if proc.returncode != 0:
            self.fail(
                f'exhaustion_client exited non-zero ({proc.returncode}). '
                f'See helper FAIL line in stderr.\n'
                f'STDOUT:\n{stdout}\nSTDERR:\n{stderr}')

        # Beyond exit code, also verify the recorded exhaustion code
        # is one of the documented outcomes. The Rust unit test sees
        # `SocketError | ProtocolError` because its cursor fails before
        # any batch is delivered. The Python helper deliberately drains
        # one batch first (for harness sync), so when failover is
        # attempted in Phase 3 the `would_silently_duplicate` safety net
        # kicks in and surfaces `FailoverWouldDuplicate` (no
        # `on_failover_reset` callback is installed). All three codes
        # are correct semantic outcomes — neither is a config/auth-class
        # mismatch.
        expected = {'SocketError', 'ProtocolError', 'FailoverWouldDuplicate'}

        exhausted = self._extract_field(stderr, 'exhausted_code')
        self.assertIn(
            exhausted, expected,
            f'unexpected exhaustion error code: {exhausted!r}.\n'
            f'STDERR:\n{stderr}')

        sv_code = self._extract_field(stderr, 'poisoned_server_version_code')
        # The Rust test pins this to SocketError specifically (the doc
        # comment on `Reader::server_version` promises that). Don't
        # accept ProtocolError here.
        self.assertEqual(
            sv_code, 'SocketError',
            f'server_version on poisoned reader: {sv_code!r}, '
            f'expected SocketError.\nSTDERR:\n{stderr}')

        exec_code = self._extract_field(stderr, 'poisoned_execute_code')
        self.assertEqual(
            exec_code, 'SocketError',
            f'query.execute on poisoned reader: {exec_code!r}, '
            f'expected SocketError.\nSTDERR:\n{stderr}')

    def test_single_endpoint_failover_exhausts_budget(self):
        """
        Mirrors `single_endpoint_failover_exhausts_budget` in
        `questdb-rs/tests/egress_failover.rs`:

        With a single address in the connect list, the failover
        rotation `(0+1+attempt) % 1` collapses to the same endpoint.
        If that endpoint stays dead, the cursor MUST eventually
        surface a hard error rather than retry indefinitely.

        Server #1 is the only endpoint. After the first batch arrives
        we SIGKILL it; subsequent failover attempts dial the same
        (now-dead) port `failover_max_attempts + 1` more times before
        giving up. `next_batch()` then returns Err with a
        transport-class code, not a panic. As with the multi-endpoint
        exhaustion test, the dropped cursor leaves the Reader
        poisoned (transport=None), so the helper also exercises
        `server_version()` and a fresh `query.execute()` on it —
        both must surface SocketError, not panic.

        Reuses `exhaustion_client`: that helper is endpoint-agnostic,
        and the connect string carries the single-address topology.
        """
        self.assertTrue(self.server1.is_alive())

        conf = (
            f'ws::addr=127.0.0.1:{self.server1.http_port};'
            # `failover_max_attempts=2` matches the Rust test. The
            # backoff is tiny so exhaustion lands within seconds even
            # with three loopback dials per attempt.
            f'failover_max_attempts=2;'
            f'failover_backoff_initial_ms=1;'
            f'failover_backoff_max_ms=2')
        sql = 'SELECT * FROM failover_test ORDER BY val'

        sys.stderr.write(
            f'spawning {self.exhaustion_client_bin.name} '
            f'addr=#1({self.server1.http_port}) [single endpoint]\n')
        proc = subprocess.Popen(
            [str(self.exhaustion_client_bin), conf, sql],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1)

        try:
            stdout, stderr = self._drive_exhaustion(proc, [self.server1])
        finally:
            if proc.poll() is None:
                proc.kill()
                try:
                    proc.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    pass

        if proc.returncode != 0:
            self.fail(
                f'exhaustion_client exited non-zero ({proc.returncode}). '
                f'See helper FAIL line in stderr.\n'
                f'STDOUT:\n{stdout}\nSTDERR:\n{stderr}')

        # Same expected codes as the multi-endpoint exhaustion test:
        # transport-class or the `FailoverWouldDuplicate` safety net
        # (which fires here because the helper drains one batch before
        # triggering failover, and no `on_failover_reset` callback is
        # installed). The two poisoned-reader probes are pinned to
        # SocketError per `Reader::server_version`'s documented
        # contract.
        expected = {'SocketError', 'ProtocolError', 'FailoverWouldDuplicate'}

        exhausted = self._extract_field(stderr, 'exhausted_code')
        self.assertIn(
            exhausted, expected,
            f'unexpected single-endpoint exhaustion code: '
            f'{exhausted!r}.\nSTDERR:\n{stderr}')

        sv_code = self._extract_field(stderr, 'poisoned_server_version_code')
        self.assertEqual(
            sv_code, 'SocketError',
            f'server_version on poisoned reader: {sv_code!r}, '
            f'expected SocketError.\nSTDERR:\n{stderr}')

        exec_code = self._extract_field(stderr, 'poisoned_execute_code')
        self.assertEqual(
            exec_code, 'SocketError',
            f'query.execute on poisoned reader: {exec_code!r}, '
            f'expected SocketError.\nSTDERR:\n{stderr}')

    def _drive_exhaustion(self, proc, servers_to_kill):
        """
        Synchronization for the failover-exhaustion family of tests:
          1. Read BATCH_RECEIVED on stdout.
          2. SIGKILL every server in `servers_to_kill`. Whichever
             endpoints the failover machinery would rotate to must be
             dead before the green-light, otherwise failover would
             succeed instead of exhausting its budget.
          3. Send GO\\n on stdin.
          4. Wait for the helper to exit; return (stdout, stderr).

        Tests differ only in which servers they kill — multi-endpoint
        exhaustion kills both, single-endpoint exhaustion kills the
        lone server.
        """
        deadline = time.monotonic() + HELPER_READY_TIMEOUT_SEC
        ready = False
        stdout_acc = []
        while time.monotonic() < deadline:
            line = proc.stdout.readline()
            if line == '':
                break
            stdout_acc.append(line)
            if line.strip() == 'BATCH_RECEIVED':
                ready = True
                break
        if not ready:
            proc.kill()
            stdout_rest, stderr = proc.communicate()
            self.fail(
                f'helper did not print BATCH_RECEIVED within '
                f'{HELPER_READY_TIMEOUT_SEC}s.\n'
                f'STDOUT:\n{"".join(stdout_acc)}{stdout_rest}\n'
                f'STDERR:\n{stderr}')

        labels = ', '.join(s.label for s in servers_to_kill)
        sys.stderr.write(f'SIGKILLing {labels}...\n')
        for srv in servers_to_kill:
            srv.kill()

        try:
            proc.stdin.write('GO\n')
            proc.stdin.flush()
        except (BrokenPipeError, OSError) as e:
            sys.stderr.write(f'failed to signal helper: {e}\n')

        try:
            stdout_rest, stderr = proc.communicate(
                timeout=HELPER_DONE_TIMEOUT_SEC)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout_rest, stderr = proc.communicate()
            self.fail(
                f'helper did not exit within {HELPER_DONE_TIMEOUT_SEC}s '
                f'after green-light.\n'
                f'STDOUT:\n{"".join(stdout_acc)}{stdout_rest}\n'
                f'STDERR:\n{stderr}')

        return ''.join(stdout_acc) + stdout_rest, stderr

    @staticmethod
    def _extract_field(stderr, name):
        """
        Pull the value of a `name=value` token out of helper stderr.
        The helpers emit lines like
        `exhausted_code=SocketError exhausted_msg=...`; this picks
        whichever line carries `name=` first and returns the bare
        variant string.
        """
        for line in stderr.splitlines():
            for tok in line.split():
                if tok.startswith(f'{name}='):
                    return tok.split('=', 1)[1]
        return None


def _parse_args():
    """
    Argument parsing mirrors test.py's interface so users who already
    invoke `python3 system_test/test.py run --repo ./questdb` can run
    this script with the identical command. The `run` subcommand
    carries the same flags (`--repo`, `--versions`, `-v`) and is the
    only supported subcommand here — there's no `list` mode.
    """
    parser = argparse.ArgumentParser(
        'Mid-query failover system test for the QWP egress reader.')
    sub = parser.add_subparsers(dest='command')

    run_p = sub.add_parser('run', help='Run the failover test.')
    _add_run_flags(run_p)

    # Allow flags at top level too (i.e. without the `run` subcommand)
    # so `python3 test_egress_failover.py --repo ./questdb` keeps working.
    _add_run_flags(parser)

    return parser.parse_known_args()


def _add_run_flags(p):
    p.add_argument(
        '--repo',
        help='Path to a built QuestDB repo (e.g. ./questdb).')
    p.add_argument(
        '--versions', nargs='+',
        help='Test against this specific QuestDB version (only the '
             'first is used).')
    p.add_argument(
        '-v', '--verbose', action='store_true',
        help='Pass -v through to unittest.')


def main():
    global _ARGS
    _ARGS, unittest_argv = _parse_args()
    sys.argv = sys.argv[:1] + unittest_argv
    if _ARGS.verbose:
        sys.argv.append('-v')
    unittest.main()


if __name__ == '__main__':
    main()
