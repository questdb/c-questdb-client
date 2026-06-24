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

import sys

sys.dont_write_bytecode = True

import os
import re
import pathlib
import json
import tarfile
import shutil
import signal
import subprocess
import tempfile
import time
import socket
import atexit
import textwrap
import urllib.request
import urllib.parse
import urllib.error
import concurrent.futures
import threading
import base64
from pprint import pformat

AUTH_TXT = """admin ec-p-256-sha256 fLKYEaoEb9lrn3nkwLDA-M_xnuFOdSt9y0Z7_vWSHLU Dt5tbS1dEDMSYfym3fgMv0B99szno-dFc1rYF9t0aac
# [key/user id] [key type] {keyX keyY}"""

# Valid keys as registered with the QuestDB fixture.
AUTH = dict(
    username="admin",
    token="5UjEMuA0Pj5pjK8a-fa24dyIf-Es5mYny3oE_Wmus48",
    token_x="fLKYEaoEb9lrn3nkwLDA-M_xnuFOdSt9y0Z7_vWSHLU",
    token_y="Dt5tbS1dEDMSYfym3fgMv0B99szno-dFc1rYF9t0aac")

HTTP_AUTH = dict(
    username="admin",
    password="quest")

CA_PATH = (pathlib.Path(__file__).parent.parent /
           'tls_certs' / 'server_rootCA.pem')

# Posts a console control event to the QuestDB JVM on Windows. Run as
# `python -c <this> <pid> <ctrl_c|ctrl_break>` in a separate process: a
# control event can only be sent from inside the target's console —
# GenerateConsoleCtrlEvent() reaches just the processes attached to the
# caller's own console — and the test runner cannot abandon its console
# to go borrow the JVM's, but a throwaway helper process can.
_WIN_CONSOLE_CTRL_HELPER = r'''
import ctypes
import ctypes.wintypes
import sys

CTRL_C_EVENT = 0
CTRL_BREAK_EVENT = 1

pid = int(sys.argv[1])
event = {'ctrl_c': CTRL_C_EVENT, 'ctrl_break': CTRL_BREAK_EVENT}[sys.argv[2]]
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)


def bail(code, what):
    sys.stderr.write(
        f'console-ctrl helper: {what} failed, '
        f'winerror={ctypes.get_last_error()}\n')
    sys.exit(code)


# The posted event reaches every process on the console, this helper
# included. A handler that claims each event keeps the default handler
# (ExitProcess) from killing the helper before it can report success.
# Merely ignoring would not do: SetConsoleCtrlHandler(NULL, TRUE)
# covers Ctrl+C only, not Ctrl+Break.
handler_t = ctypes.WINFUNCTYPE(ctypes.wintypes.BOOL, ctypes.wintypes.DWORD)
claim_all = handler_t(lambda _event: True)
if not kernel32.SetConsoleCtrlHandler(claim_all, True):
    bail(2, 'SetConsoleCtrlHandler')
kernel32.FreeConsole()  # Failure is fine: it means we had no console.
if not kernel32.AttachConsole(pid):
    bail(3, 'AttachConsole')
# Process group 0 == everyone on this console, which is exactly the JVM
# (and this helper): the JVM was launched with CREATE_NO_WINDOW, so its
# console hosts nothing else. Group 0 rather than the JVM's pid because
# Ctrl+C cannot be addressed to a process group: with a non-zero group
# id, GenerateConsoleCtrlEvent(CTRL_C_EVENT, ...) reports success
# without delivering anything.
if not kernel32.GenerateConsoleCtrlEvent(event, 0):
    bail(4, 'GenerateConsoleCtrlEvent')
'''


def retry(
        predicate_task,
        timeout_sec=30,
        every=0.05,
        msg='Timed out retrying',
        backoff_till=5.0,
        lead_sleep=0.001):
    """
    Repeat task every `interval` until it returns a truthy value or times out.
    """
    begin = time.monotonic()
    threshold = begin + timeout_sec
    if lead_sleep:
        time.sleep(lead_sleep)
    while True:
        res = predicate_task()
        if res:
            return res
        elif time.monotonic() < threshold:
            time.sleep(every)
            if backoff_till:
                every = min(backoff_till, every * 1.25)
        else:
            raise TimeoutError(msg)


def discover_avail_ports(num_required):
    """Discover available TCP listening ports."""
    # We need to find free ports.
    # Note: This a hack. We bind and then close.
    # There's obviously a race condition here.
    sockets = [
        socket.socket()
        for _ in range(num_required)]
    for sock in sockets:
        sock.bind(('', 0))
    free_ports = [
        sock.getsockname()[1]
        for sock in sockets]
    for sock in sockets:
        sock.close()
    return free_ports


def discover_avail_udp_port():
    """Discover an available UDP port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class Project:
    def __init__(self):
        self.system_test_dir = pathlib.Path(__file__).absolute().parent
        self.root_dir = self.system_test_dir.parent
        self.build_dir = pathlib.Path(os.environ.get(
            'BUILD_DIR_PATH',
            self.root_dir / 'build'))
        if not self.build_dir.exists():
            self.build_dir.mkdir()
        self.tls_certs_dir = self.root_dir / 'tls_certs'
        self.questdb_dir = self.build_dir / 'questdb'
        self.questdb_dir.mkdir(exist_ok=True)
        self.questdb_downloads_dir = self.questdb_dir / 'downloads'
        self.questdb_downloads_dir.mkdir(exist_ok=True)


def list_questdb_releases(max_results=1):
    url = (
            'https://api.github.com/repos/questdb/questdb/releases?' +
            urllib.parse.urlencode({'per_page': max_results}))
    req = urllib.request.Request(
        url,
        headers={
            'User-Agent': 'system-testing-script',
            'Accept': "Accept: application/vnd.github.v3+json"},
        method='GET')
    resp = urllib.request.urlopen(req, timeout=30)
    data = resp.read()
    releases = json.loads(data.decode('utf8'))
    for release in releases:
        vers = release['name']
        no_jre_assets = [
            asset for asset
            in release['assets']
            if 'no-jre' in asset['name']]
        if no_jre_assets:
            download_url = no_jre_assets[0]['browser_download_url']
            yield (vers, download_url)


def install_questdb(vers: str, download_url: str):
    proj = Project()
    version_dir = proj.questdb_dir / vers
    if version_dir.exists():
        sys.stderr.write(f'Resetting pre-existing QuestDB v.{vers} install.\n')
        shutil.rmtree(version_dir / 'data')
        (version_dir / 'data' / 'log').mkdir(parents=True)
        return version_dir
    sys.stderr.write(f'Downloading QuestDB v.{vers} from {download_url!r}.\n')
    archive_path = proj.questdb_downloads_dir / f'{vers}.tar.gz'

    response = urllib.request.urlopen(download_url, timeout=300)
    data = response.read()
    with open(archive_path, 'wb') as archive_file:
        archive_file.write(data)
    tmp_version_dir = proj.questdb_dir / f'_tmp_{vers}'
    try:
        archive = tarfile.open(archive_path)
        archive.extractall(tmp_version_dir)
        archive.close()
    except:
        shutil.rmtree(tmp_version_dir, ignore_errors=True)
        raise
    bin_dir = tmp_version_dir / 'bin'
    next(tmp_version_dir.glob("**/questdb.jar")).parent.rename(bin_dir)
    (tmp_version_dir / 'data' / 'log').mkdir(parents=True)
    tmp_version_dir.rename(version_dir)
    return version_dir


def install_questdb_from_repo(repo: pathlib.Path):
    repo = repo.absolute()
    target_dir = repo / 'core' / 'target'
    try:
        repo_jar = next(target_dir.glob("**/questdb*-SNAPSHOT.jar"))
    except StopIteration:
        raise RuntimeError(
            f'Could not find QuestDB jar in repo {repo}. ' +
            'Check path and ensure you built correctly.')
    print(f'Starting QuestDB from jar {repo_jar}')
    proj = Project()
    vers = 'repo'
    questdb_dir = proj.questdb_dir / vers
    if questdb_dir.exists():
        shutil.rmtree(questdb_dir)
    (questdb_dir / 'data' / 'log').mkdir(parents=True)
    bin_dir = questdb_dir / 'bin'
    bin_dir.mkdir(parents=True)
    conf_dir = questdb_dir / 'conf'
    conf_dir.mkdir(parents=True)
    data_conf_dir = questdb_dir / 'data' / 'conf'
    data_conf_dir.mkdir(parents=True)
    shutil.copy(repo_jar, bin_dir / 'questdb.jar')
    repo_conf_dir = target_dir / 'classes' / 'io' / 'questdb' / 'site' / 'conf'
    shutil.copy(repo_conf_dir / 'server.conf', conf_dir / 'server.conf')
    shutil.copy(repo_conf_dir / 'mime.types', data_conf_dir / 'mime.types')
    return questdb_dir


def _parse_version(vers_str):
    def try_int(vers_part):
        try:
            return int(vers_part)
        except ValueError:
            return vers_part

    return tuple(
        try_int(vers_part)
        for vers_part in vers_str.split('.'))


def _find_java():
    search_path = None
    java_home = os.environ.get('JAVA_HOME')
    if java_home:
        search_path = pathlib.Path(java_home) / 'bin'
    res = shutil.which('java', path=str(search_path))
    if res is None:
        res = shutil.which('java')
    if res is None:
        raise RuntimeError('Could not find `java` executable.')
    return res


# The docker CLI used by the docker-backed fixtures. Overridable so a CI
# agent can point at podman or a wrapper without code changes.
DOCKER_BIN = os.environ.get('QUESTDB_SYSTEST_DOCKER_BIN', 'docker')

# Monotonic suffix so concurrent/sequential containers never collide on a
# name within one test process.
_docker_name_counter = 0


def _docker(*args, check=True, capture=False, timeout=None):
    """Run a `docker` CLI sub-command. With ``capture`` the combined
    stdout/stderr is returned on the CompletedProcess; otherwise it is
    inherited. ``check`` controls whether a non-zero exit raises."""
    return subprocess.run(
        [DOCKER_BIN, *args],
        check=check,
        timeout=timeout,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None)


def _unique_container_name(prefix):
    global _docker_name_counter
    _docker_name_counter += 1
    return f'{prefix}_{os.getpid()}_{_docker_name_counter}'


class QueryError(Exception):
    """An error querying the database with SQL over HTTP."""
    pass


class QuestDbStopTimeout(RuntimeError):
    """QuestDB did not shut down within the graceful timeout and had to
    be force-killed. Raised by ``stop()`` so the test fails instead of
    silently absorbing a server that refuses to stop."""
    pass


class QuestDbFixtureBase:
    def print_log(self):
        """Print the QuestDB log to stderr."""
        sys.stderr.write('questdb log output skipped.\n')

    def http_headers(self):
        if not getattr(self, 'http_auth', False):
            return {}
        credentials = (
            f'{HTTP_AUTH["username"]}:{HTTP_AUTH["password"]}'
            .encode('utf-8'))
        encoded = base64.b64encode(credentials).decode('ascii')
        return {'Authorization': f'Basic {encoded}'}

    def http_sql_query(self, sql_query):
        url = (
                f'http://{self.host}:{self.http_server_port}/exec?' +
                urllib.parse.urlencode({'query': sql_query}))
        buf = None
        try:
            req = urllib.request.Request(
                url,
                headers=self.http_headers(),
                method='GET')
            resp = urllib.request.urlopen(req, timeout=5)
            buf = resp.read()
        except urllib.error.HTTPError as http_error:
            buf = http_error.read()
        try:
            data = json.loads(buf)
        except json.JSONDecodeError as jde:
            # Include buffer in error message for easier debugging.
            raise json.JSONDecodeError(
                f'Could not parse response: {buf!r}: {jde.msg}',
                jde.doc,
                jde.pos)
        if 'error' in data:
            raise QueryError(data['error'])
        return data

    def _assert_server_alive(self):
        """Raise if the server died during startup.

        The readiness probe calls this before each attempt so a crashed
        server fails fast instead of looping until the timeout. The base
        fixture has no process to inspect; the managed and docker fixtures
        override it.
        """

    def _check_main_http_up(self):
        # Probe the main HTTP server's /ping. The initial start gates on
        # this: query_version() and every test SQL query run against the main
        # HTTP server, so it must be accepting before start() returns. There
        # is no QWP ingest at initial-start time, so /ping can't be starved
        # by the shared-network pool that serves it.
        return self._probe_http(
            self.http_server_port, '/ping', lambda status: status == 204)

    def _check_min_http_up(self):
        # Probe the dedicated min-HTTP health endpoint. A bounce restart gates
        # on this: the min server runs on its own worker pool, so a heavy QWP
        # ingest load on the shared-network pool (which serves the main HTTP
        # server) can't starve the readiness check. HealthCheckProcessor
        # answers any path with 200 "Status: Healthy". The bounce path issues
        # no SQL after the probe, so main-HTTP readiness isn't required there.
        return self._probe_http(
            self.http_min_port, '/status', lambda status: 200 <= status < 300)

    def _probe_http(self, port, path, status_ok):
        self._assert_server_alive()
        req = urllib.request.Request(
            f'http://{self.host}:{port}{path}',
            headers=self.http_headers(),
            method='GET')
        try:
            resp = urllib.request.urlopen(req, timeout=1)
            if status_ok(resp.status):
                return True
        except OSError:
            # The server isn't accepting yet. A not-yet-ready local process
            # refuses the connection (urllib.error.URLError); docker
            # publishes the host port before QuestDB binds, so an early probe
            # can connect and then be reset (RemoteDisconnected /
            # ConnectionResetError). URLError and socket.timeout are both
            # OSError subclasses, so one handler covers every case.
            pass
        return False

    def query_version(self):
        try:
            res = self.http_sql_query('select build')
        except QueryError as qe:
            # For old versions that don't support `build` yet, parse from path.
            return self.version

        vers = res['dataset'][0][0]
        print(vers)

        # This returns a string like:
        # 'Build Information: QuestDB 7.3.2, JDK 11.0.8, Commit Hash 19059deec7b0fd19c53182b297a5d59774a51892'
        # We want the '7.3.2' part.
        vers = re.compile(r'.*QuestDB ([0-9.]+).*').search(vers).group(1)
        return _parse_version(vers)

    def retry_check_table(
            self,
            table_name,
            *,
            min_rows=1,
            timeout_sec=300,
            log=True,
            log_ctx=None):
        sql_query = f"select * from '{table_name}'"
        http_response_log = []

        def check_table():
            try:
                resp = self.http_sql_query(sql_query)
                http_response_log.append((time.time(), resp))
                if not resp.get('dataset'):
                    return False
                elif len(resp['dataset']) < min_rows:
                    return False
                return resp
            except QueryError:
                return None
            except TimeoutError:
                # A single poll stalling its 5s socket timeout (server
                # busy catching up after a bounce) must not abort the
                # whole wait: the enclosing retry() budget decides when
                # to give up. Without this, the handler below would also
                # mislabel one stalled poll as the full timeout_sec.
                return None

        try:
            return retry(check_table, timeout_sec=timeout_sec)
        except TimeoutError as toe:
            if log:
                if log_ctx:
                    log_ctx_str = log_ctx.decode('utf-8', errors='replace')
                    log_ctx = f'\n{textwrap.indent(log_ctx_str, "    ")}\n'
                sys.stderr.write(
                    f'Timed out after {timeout_sec} seconds ' +
                    f'waiting for query {sql_query!r}. ' +
                    f'Context: {log_ctx}' +
                    f'Client response log:\n' +
                    pformat(http_response_log) +
                    f'\nQuestDB log:\n')
                self.print_log()
            raise toe
        
    def show_tables(self):
        """Return a list of tables in the database."""
        sql_query = "show tables"
        try:
            resp = self.http_sql_query(sql_query)
            return [row[0] for row in resp['dataset']]
        except QueryError as qe:
            raise qe
        
    def drop_table(self, table_name):
        self.http_sql_query(f"drop table '{table_name}'")

    def drop_all_tables(self):
        """Drop all tables in the database."""
        all_tables = self.show_tables()
        # if all_tables:
        #     print(f'Dropping {len(all_tables)} tables: {all_tables!r}')
        for table_name in all_tables:
            self.drop_table(table_name)


class QuestDbExternalFixture(QuestDbFixtureBase):
    def __init__(
            self,
            host,
            line_tcp_port,
            http_server_port,
            version,
            http,
            auth,
            protocol_version,
            qwp_udp=False,
            qwp_udp_port=None,
            http_auth=False):
        self.host = host
        self.line_tcp_port = line_tcp_port
        self.http_server_port = http_server_port
        self.version = version
        self.http = http
        self.auth = auth
        self.http_auth = http_auth
        self.protocol_version = protocol_version
        self.qwp_udp = qwp_udp
        self.qwp_udp_port = qwp_udp_port


class QuestDbFixture(QuestDbFixtureBase):
    def __init__(
            self,
            root_dir: pathlib.Path,
            auth=False,
            wrap_tls=False,
            http=False,
            protocol_version=None,
            qwp_udp=False,
            http_auth=False):
        self._root_dir = root_dir
        self.version = _parse_version(self._root_dir.name)
        # Set once start() has refined `version` from the live server.
        self._version_queried = False
        self._data_dir = self._root_dir / 'data'
        self._log_path = self._data_dir / 'log' / 'log.txt'
        self._conf_dir = self._data_dir / 'conf'
        self._conf_dir.mkdir(exist_ok=True)
        self._conf_path = self._conf_dir / 'server.conf'
        self._log = None
        self._proc = None
        self.host = '127.0.0.1'
        self.http_server_port = None
        self.line_tcp_port = None
        self.qwp_udp_port = None
        self.pg_port = None
        # Dedicated min-HTTP health port. The min server runs on its own
        # worker pool, so the readiness probe can't be starved by QWP
        # ingest saturating the shared-network pool that serves the main
        # HTTP server (where /ping lives).
        self.http_min_port = None

        self.wrap_tls = wrap_tls
        self._tls_proxy = None
        self.tls_line_tcp_port = None

        self.auth = auth
        if self.auth:
            auth_txt_path = self._conf_dir / 'auth.txt'
            with open(auth_txt_path, 'w', encoding='utf-8') as auth_file:
                auth_file.write(AUTH_TXT)
        self.http_auth = http_auth
        self.http = http
        self.protocol_version = protocol_version
        self.qwp_udp = qwp_udp

    def print_log(self):
        # Read as bytes and replace undecodable sequences: a force-kill
        # can truncate the log mid-character, which would crash a plain
        # utf-8 text read.
        with open(self._log_path, 'rb') as log_file:
            log = log_file.read().decode('utf-8', errors='replace')
        sys.stderr.write(textwrap.indent(log, '    '))
        sys.stderr.write('\n\n')

    def _assert_server_alive(self):
        if self._proc.poll() is not None:
            raise RuntimeError('QuestDB died during startup.')

    def start(self, start_timeout_sec=300, probe_min_http=False):
        # start_timeout_sec bounds the wait for the readiness probe to pass.
        # The generous default flags only a genuinely stuck boot; the bounce
        # fuzz thread passes a tighter, drain-budget-aware value so a
        # pathologically slow restart fails as an infra error rather than
        # starving the producers' close_drain.
        #
        # probe_min_http selects which server gates readiness. The initial
        # start probes the main HTTP server (/ping): query_version() and all
        # test SQL hit it, so it must be accepting before start() returns,
        # and there is no ingest yet to starve it. A bounce restart sets
        # probe_min_http=True to gate on the dedicated min-HTTP pool instead,
        # which reconnecting producers on the shared-network pool can't
        # starve; that path issues no SQL, so main-HTTP readiness isn't
        # needed.
        if self.http_server_port is None:
            (self.http_server_port, self.line_tcp_port,
             self.pg_port, self.http_min_port) = discover_avail_ports(4)
        if self.qwp_udp and self.qwp_udp_port is None:
            self.qwp_udp_port = discover_avail_udp_port()
        auth_config = 'line.tcp.auth.db.path=conf/auth.txt' if self.auth else ''
        http_auth_config = (
            f'http.user={HTTP_AUTH["username"]}\n'
            '                '
            f'http.password={HTTP_AUTH["password"]}'
            if self.http_auth else '')
        ilp_over_http_config = 'line.http.enabled=true' if self.http else ''
        qwp_udp_enabled = 'true' if self.qwp_udp else 'false'
        qwp_udp_bind = (
            f'qwp.udp.bind.to=0.0.0.0:{self.qwp_udp_port}'
            if self.qwp_udp else '')
        qwp_udp_unicast = 'qwp.udp.unicast=true' if self.qwp_udp else ''
        qwp_udp_commit_rate = 'qwp.udp.commit.rate=1' if self.qwp_udp else ''
        with open(self._conf_path, 'w', encoding='utf-8') as conf_file:
            conf_file.write(textwrap.dedent(rf'''
                http.bind.to=0.0.0.0:{self.http_server_port}
                line.tcp.net.bind.to=0.0.0.0:{self.line_tcp_port}
                pg.net.bind.to=0.0.0.0:{self.pg_port}
                http.min.enabled=true
                http.min.net.bind.to=0.0.0.0:{self.http_min_port}
                http.min.worker.count=1
                line.udp.enabled=false
                qwp.udp.enabled={qwp_udp_enabled}
                {qwp_udp_bind}
                {qwp_udp_unicast}
                {qwp_udp_commit_rate}
                line.tcp.maintenance.job.interval=100
                line.tcp.min.idle.ms.before.writer.release=300
                telemetry.enabled=false
                cairo.commit.lag=100
                cairo.writer.data.append.page.size=64k
                cairo.writer.data.index.value.append.page.size=64k
                line.tcp.commit.interval.fraction=0.1
                {auth_config}
                {http_auth_config}
                {ilp_over_http_config}
                ''').lstrip('\n'))

        java = _find_java()
        launch_args = [
            java,
            '-DQuestDB-Runtime-0',
            '-ea',
            '-Dnoebug',
            # '-Debug',
            '-XX:+UnlockExperimentalVMOptions',
            '-XX:+AlwaysPreTouch',
            # QuestDB's worker pools use jdk.internal.vm.ContinuationScope via
            # io.questdb.mp.continuation.WorkerContinuation. When the server is
            # launched as the named module io.questdb (-m below), java.base does
            # not export jdk.internal.vm to it, so every worker thread dies with
            # IllegalAccessError and the HTTP service never comes up. QuestDB's
            # own launcher passes this flag; mirror it here.
            '--add-exports=java.base/jdk.internal.vm=io.questdb',
            '-p', str(self._root_dir / 'bin' / 'questdb.jar'),
            '-m', 'io.questdb/io.questdb.ServerMain',
            '-d', str(self._data_dir)]
        sys.stderr.write(
            f'Starting QuestDB: {launch_args!r} '
            f'(auth: {self.auth}, http_auth: {self.http_auth}, '
            f'http: {self.http}, qwp_udp: {self.qwp_udp})\n')
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        self._log = open(self._log_path, 'ab')
        # On Windows, Popen.terminate() maps to TerminateProcess(), which kills
        # the JVM without running shutdown hooks. That leaves QuestDB's writers
        # mid-update and can corrupt the sequencer's _meta/_txnlog ordering.
        # The graceful equivalent of SIGTERM for a JVM is a Ctrl+C console
        # event, which it maps to SIGINT. (Ctrl+Break is NOT that: HotSpot
        # answers it with a thread dump and keeps running.) Ctrl+C cannot be
        # addressed to a single process, though — it goes to every process on
        # the target console — so CREATE_NO_WINDOW gives the JVM a fresh,
        # windowless console of its own, where stop() can post Ctrl+C (via
        # _win_send_console_ctrl) and hit nothing else. CREATE_NEW_PROCESS_GROUP
        # is deliberately absent: it would start the child with the
        # ignore-Ctrl+C flag set, which the JVM never clears, making it deaf
        # to the shutdown request.
        creationflags = (
            subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0)
        try:
            self._proc = subprocess.Popen(
                launch_args,
                close_fds=True,
                cwd=self._data_dir,
                # env=launch_env,
                stdout=self._log,
                stderr=subprocess.STDOUT,
                creationflags=creationflags)

            sys.stderr.write('Waiting until HTTP service is up.\n')
            check_up = (
                self._check_min_http_up if probe_min_http
                else self._check_main_http_up)
            retry(
                check_up,
                timeout_sec=start_timeout_sec,
                msg=f'Timed out waiting for HTTP service to come up '
                    f'within {start_timeout_sec}s.')
        except:
            sys.stderr.write(f'QuestDB log at `{self._log_path}`:\n')
            self.print_log()
            raise

        atexit.register(self.stop)
        sys.stderr.write('QuestDB fixture instance is ready.\n')

        # Read the actual version from the running process; it can be more
        # precise than the path-parsed one (e.g. `7.3.2-SNAPSHOT`). Only on
        # the first start, which always precedes client load: the binary
        # doesn't change across restarts, and a bounce restart must stay
        # clear of SQL — right after it the reconnecting fuzz producers
        # can keep the network workers busy past the 5s query timeout,
        # failing the bounce even though the min-HTTP health endpoint
        # already vouched for liveness.
        if not self._version_queried:
            self.version = self.query_version()
            self._version_queried = True

        if self.wrap_tls:
            self._tls_proxy = TlsProxyFixture(self.line_tcp_port)
            self._tls_proxy.start()
            self.tls_line_tcp_port = self._tls_proxy.listen_port

    def __enter__(self):
        self.start()

    def _win_send_console_ctrl(self, event):
        """Post a console control event to the QuestDB JVM on Windows.

        `event` is 'ctrl_c' (graceful shutdown: the JVM maps it to
        SIGINT and runs shutdown hooks) or 'ctrl_break' (HotSpot prints
        a thread dump to the server log and keeps running). Runs
        _WIN_CONSOLE_CTRL_HELPER in a separate process; see its comment
        for why one is needed. Returns True when the event was posted.
        Never raises: stop() must always reach its force-kill cleanup,
        however delivery fails.
        """
        try:
            res = subprocess.run(
                [sys.executable, '-c', _WIN_CONSOLE_CTRL_HELPER,
                 str(self._proc.pid), event],
                creationflags=subprocess.CREATE_NO_WINDOW,
                timeout=15)
        except (OSError, subprocess.SubprocessError) as e:
            sys.stderr.write(
                f'Failed to post {event} to QuestDB '
                f'(pid {self._proc.pid}): {e!r}\n')
            return False
        if res.returncode != 0:
            # The helper wrote a winerror diagnostic to stderr already.
            sys.stderr.write(
                f'Failed to post {event} to QuestDB '
                f'(pid {self._proc.pid}); helper exited with '
                f'{res.returncode}.\n')
            return False
        return True

    def stop(self, wait_timeout_sec=30):
        if self._tls_proxy:
            self._tls_proxy.stop()
        # A graceful shutdown that overruns `wait_timeout_sec` is treated
        # as a failure, not something to live with: we still force-kill
        # the process so nothing is leaked, but then raise so the test
        # fails loudly. `wait_timeout_sec` must therefore be sized
        # generously enough that only a genuinely stuck server exceeds it.
        shutdown_timed_out = False
        kill_pid = None
        if self._proc:
            if sys.platform == 'win32':
                # Post Ctrl+C to the JVM's private console: the JVM maps it
                # to SIGINT and runs shutdown hooks, making it the closest
                # Windows analogue of SIGTERM. (Ctrl+Break would not do:
                # HotSpot answers it with a thread dump to the server log
                # and keeps running.) Delivery failure is not fatal here:
                # the wait below times out, force-kills and raises.
                self._win_send_console_ctrl('ctrl_c')
            else:
                self._proc.terminate()
            try:
                self._proc.wait(timeout=wait_timeout_sec)
            except subprocess.TimeoutExpired:
                shutdown_timed_out = True
                kill_pid = self._proc.pid
                sys.stderr.write(
                    f'QuestDB (pid {self._proc.pid}) did not exit within '
                    f'{wait_timeout_sec}s of being asked to shut down; '
                    'escalating to SIGKILL.\n')
                # Make the JVM print a thread dump into the server log
                # first, so a hung shutdown identifies the blocked thread
                # instead of vanishing without a trace: SIGQUIT on POSIX,
                # Ctrl+Break on Windows.
                dump_requested = False
                if sys.platform == 'win32':
                    dump_requested = self._win_send_console_ctrl(
                        'ctrl_break')
                elif hasattr(signal, 'SIGQUIT'):
                    try:
                        self._proc.send_signal(signal.SIGQUIT)
                        dump_requested = True
                    except OSError:
                        pass
                if dump_requested:
                    sys.stderr.write(
                        'Requested a JVM thread dump; it goes to '
                        f'`{self._log_path}`.\n')
                    try:
                        # The JVM keeps running after the dump; this wait
                        # is just a grace period for it to finish writing.
                        self._proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        pass
                self._proc.kill()
                self._proc.wait()
            self._proc = None
        if self._log:
            self._log.close()
            self._log = None
        if shutdown_timed_out:
            # Cleanup is done (process reaped, log closed); now fail.
            raise QuestDbStopTimeout(
                f'QuestDB (pid {kill_pid}) did not shut down gracefully '
                f'within {wait_timeout_sec}s and had to be force-killed. '
                'A graceful shutdown overrunning this budget means the '
                f'server is stuck; see the JVM thread dump in '
                f'`{self._log_path}`.')

    def wipe_data_dir(self):
        """Remove everything under the data dir except ``conf/``.

        Reclaims disk space accumulated by dropped tables whose async purge
        hasn't run yet. Must be called only after stop(); refuses to wipe
        while QuestDB is running.
        """
        if self._proc is not None:
            raise RuntimeError(
                'wipe_data_dir() called while QuestDB is still running')
        if not self._data_dir.exists():
            return
        for child in self._data_dir.iterdir():
            if child.name == 'conf':
                continue
            if child.is_dir():
                shutil.rmtree(child, ignore_errors=True)
            else:
                try:
                    child.unlink()
                except OSError:
                    pass

    def __exit__(self, _ty, _value, _tb):
        self.stop()


class QuestDbDockerFixture(QuestDbFixtureBase):
    """A QuestDB server running inside a docker container.

    Drop-in replacement for ``QuestDbFixture`` that runs a prebuilt
    QuestDB image (e.g. ``questdb/questdb:nightly``) instead of building
    and launching the jar locally. It exposes the same public surface
    (the same port attributes, ``start()`` / ``stop()`` / ``kill()`` /
    ``wipe_data_dir()`` / ``print_log()``) so the test bodies are
    unchanged.

    Configuration is injected via ``QDB_*`` environment variables rather
    than a ``server.conf`` file, so nothing is mounted for the common
    case; data is kept inside the container and discarded when the
    container is removed in ``stop()``. The server log is read with
    ``docker logs`` (the image logs to stdout). Container ports are
    published 1:1 on loopback to the host ports discovered up front, so
    a client connecting to ``127.0.0.1:<port>`` behaves exactly as
    against the local-process fixture.
    """

    def __init__(
            self,
            image,
            auth=False,
            wrap_tls=False,
            http=False,
            protocol_version=None,
            qwp_udp=False,
            http_auth=False):
        self.image = image
        # Refined from the live server on first start, like QuestDbFixture.
        self.version = None
        self._version_queried = False
        self._container = None
        self._auth_file = None
        self.host = '127.0.0.1'
        self.http_server_port = None
        self.line_tcp_port = None
        self.qwp_udp_port = None
        self.pg_port = None
        self.http_min_port = None  # see QuestDbFixture.__init__

        self.wrap_tls = wrap_tls
        self._tls_proxy = None
        self.tls_line_tcp_port = None

        self.auth = auth
        self.http_auth = http_auth
        self.http = http
        self.protocol_version = protocol_version
        self.qwp_udp = qwp_udp

    def _env_config(self):
        # Mirrors the server.conf that QuestDbFixture.start() writes, but
        # as QDB_* env overrides. Run the in-container server as the host
        # user so any bind-mounted file (auth.txt) stays host-owned;
        # harmless when nothing is mounted.
        env = {
            'QDB_HTTP_BIND_TO': f'0.0.0.0:{self.http_server_port}',
            'QDB_LINE_TCP_NET_BIND_TO': f'0.0.0.0:{self.line_tcp_port}',
            'QDB_PG_NET_BIND_TO': f'0.0.0.0:{self.pg_port}',
            'QDB_HTTP_MIN_ENABLED': 'true',
            'QDB_HTTP_MIN_NET_BIND_TO': f'0.0.0.0:{self.http_min_port}',
            'QDB_HTTP_MIN_WORKER_COUNT': '1',
            'QDB_LINE_UDP_ENABLED': 'false',
            'QDB_QWP_UDP_ENABLED': 'true' if self.qwp_udp else 'false',
            'QDB_LINE_TCP_MAINTENANCE_JOB_INTERVAL': '100',
            'QDB_LINE_TCP_MIN_IDLE_MS_BEFORE_WRITER_RELEASE': '300',
            'QDB_TELEMETRY_ENABLED': 'false',
            'QDB_CAIRO_COMMIT_LAG': '100',
            'QDB_CAIRO_WRITER_DATA_APPEND_PAGE_SIZE': '64k',
            'QDB_CAIRO_WRITER_DATA_INDEX_VALUE_APPEND_PAGE_SIZE': '64k',
            'QDB_LINE_TCP_COMMIT_INTERVAL_FRACTION': '0.1',
        }
        if hasattr(os, 'getuid'):
            env['QUESTDB_UID'] = str(os.getuid())
            env['QUESTDB_GID'] = str(os.getgid())
        if self.qwp_udp:
            env['QDB_QWP_UDP_BIND_TO'] = f'0.0.0.0:{self.qwp_udp_port}'
            env['QDB_QWP_UDP_UNICAST'] = 'true'
            env['QDB_QWP_UDP_COMMIT_RATE'] = '1'
        if self.http:
            env['QDB_LINE_HTTP_ENABLED'] = 'true'
        if self.http_auth:
            env['QDB_HTTP_USER'] = HTTP_AUTH['username']
            env['QDB_HTTP_PASSWORD'] = HTTP_AUTH['password']
        if self.auth:
            env['QDB_LINE_TCP_AUTH_DB_PATH'] = 'conf/auth.txt'
        return env

    def start(self, start_timeout_sec=300, probe_min_http=False):
        # start_timeout_sec / probe_min_http: see QuestDbFixture.start.
        if self.http_server_port is None:
            (self.http_server_port, self.line_tcp_port,
             self.pg_port, self.http_min_port) = discover_avail_ports(4)
        if self.qwp_udp and self.qwp_udp_port is None:
            self.qwp_udp_port = discover_avail_udp_port()

        cmd = ['run', '-d', '--name', _unique_container_name('qdb_systest')]
        self._container = cmd[3]
        for key, value in self._env_config().items():
            cmd += ['-e', f'{key}={value}']
        for port in (self.http_server_port, self.line_tcp_port,
                     self.pg_port, self.http_min_port):
            cmd += ['-p', f'127.0.0.1:{port}:{port}']
        if self.qwp_udp:
            cmd += ['-p', f'127.0.0.1:{self.qwp_udp_port}:{self.qwp_udp_port}/udp']
        if self.auth:
            # QuestDB resolves the auth db path relative to the data root,
            # so the file must land under /var/lib/questdb. A read-only
            # single-file bind mount overlays it onto the image-seeded
            # conf/ dir; the entrypoint's chown of a read-only file fails
            # harmlessly and the server still reads it.
            handle = tempfile.NamedTemporaryFile(
                mode='w', suffix='_auth.txt', delete=False, encoding='utf-8')
            handle.write(AUTH_TXT + '\n')
            handle.close()
            self._auth_file = handle.name
            cmd += ['-v',
                    f'{self._auth_file}:/var/lib/questdb/conf/auth.txt:ro']
        cmd += [self.image]

        sys.stderr.write(
            f'Starting QuestDB container {self._container} from '
            f'{self.image!r} (auth: {self.auth}, http_auth: {self.http_auth}, '
            f'http: {self.http}, qwp_udp: {self.qwp_udp})\n')
        _docker(*cmd)

        try:
            sys.stderr.write('Waiting until HTTP service is up.\n')
            check_up = (
                self._check_min_http_up if probe_min_http
                else self._check_main_http_up)
            retry(
                check_up,
                timeout_sec=start_timeout_sec,
                msg=f'Timed out waiting for HTTP service to come up '
                    f'within {start_timeout_sec}s.')
        except:
            sys.stderr.write('QuestDB container log:\n')
            self.print_log()
            self.stop()
            raise

        atexit.register(self.stop)
        sys.stderr.write('QuestDB docker fixture instance is ready.\n')

        if not self._version_queried:
            self.version = self.query_version()
            self._version_queried = True

        if self.wrap_tls:
            self._tls_proxy = TlsProxyFixture(self.line_tcp_port)
            self._tls_proxy.start()
            self.tls_line_tcp_port = self._tls_proxy.listen_port

    def _is_running(self):
        res = _docker(
            'inspect', '-f', '{{.State.Running}}', self._container,
            check=False, capture=True)
        return res.returncode == 0 and res.stdout.strip() == b'true'

    def _assert_server_alive(self):
        if not self._is_running():
            raise RuntimeError('QuestDB container died during startup.')

    def __enter__(self):
        self.start()

    def print_log(self):
        if self._container is None:
            sys.stderr.write('questdb container log unavailable.\n')
            return
        res = _docker('logs', self._container, check=False, capture=True)
        log = (res.stdout or b'').decode('utf-8', errors='replace')
        sys.stderr.write(textwrap.indent(log, '    '))
        sys.stderr.write('\n\n')

    def _dump_log_to_file(self):
        # Persist the container log where the CI "archive log on failure"
        # step looks, since stop() removes the container (and its logs).
        if self._container is None:
            return
        try:
            log_dir = Project().questdb_dir / 'docker' / 'data' / 'log'
            log_dir.mkdir(parents=True, exist_ok=True)
            res = _docker('logs', self._container, check=False, capture=True)
            with open(log_dir / 'log.txt', 'wb') as log_file:
                log_file.write(res.stdout or b'')
        except Exception:
            pass

    def _remove_container(self, signal_args):
        if self._tls_proxy:
            self._tls_proxy.stop()
            self._tls_proxy = None
        if self._container is not None:
            self._dump_log_to_file()
            _docker(*signal_args, self._container, check=False)
            _docker('rm', '-f', self._container, check=False)
            self._container = None
        if self._auth_file is not None:
            try:
                os.unlink(self._auth_file)
            except OSError:
                pass
            self._auth_file = None

    def stop(self, wait_timeout_sec=30):
        # `docker stop` sends SIGTERM (graceful: the JVM runs shutdown
        # hooks), then SIGKILLs after the grace period. Equivalent to
        # QuestDbFixture.stop()'s terminate()-then-kill().
        #
        # docker's `-t` takes integer seconds; bounce callers pass a float
        # budget (e.g. 120.0), which docker rejects ("invalid argument") —
        # coerce to int so the graceful grace period is honoured rather
        # than silently skipped, leaving only the immediate `rm -f`.
        self._remove_container(
            ['stop', '-t', str(int(wait_timeout_sec))])

    def kill(self):
        # `docker kill` sends SIGKILL: an ungraceful crash with no
        # shutdown hooks. Equivalent to QuestDbFixture force-kill.
        self._remove_container(['kill'])

    def wipe_data_dir(self):
        # The container and its data are removed in stop(); the next
        # start() runs a fresh container, so there is nothing to wipe.
        pass

    def __exit__(self, _ty, _value, _tb):
        self.stop()


class TlsProxyFixture:
    def __init__(self, qdb_ilp_port):
        self.qdb_ilp_port = qdb_ilp_port
        self.listen_port = None
        proj = Project()
        self._code_dir = proj.root_dir / 'system_test' / 'tls_proxy'
        self._target_dir = proj.build_dir / 'tls_proxy'
        self._proc = None
        self._port_future = None

    def _capture_output(self, pipe, port_future):
        """Capture output from subprocess and forward to stderr while watching for port"""
        try:
            for line in iter(pipe.readline, b''):
                line_str = line.decode('utf-8', errors='replace')
                # Write to stderr
                sys.stderr.write(line_str)
                sys.stderr.flush()
                
                # Check for port if we haven't found it yet
                if not port_future.done():
                    listening_msg = '[TLS PROXY] TLS Proxy is listening on localhost:'
                    if line_str.startswith(listening_msg) and line_str.endswith('.\n'):
                        port_str = line_str[len(listening_msg):-2]
                        try:
                            port = int(port_str)
                            port_future.set_result(port)
                        except ValueError:
                            pass  # Invalid port, keep looking
        except Exception as e:
            if not port_future.done():
                port_future.set_exception(e)
        finally:
            pipe.close()

    def start(self):
        self._target_dir.mkdir(exist_ok=True)
        env = dict(os.environ)
        env['CARGO_TARGET_DIR'] = str(self._target_dir)

        # Compile before running `cargo run`.
        # Note that errors and output are purposely suppressed.
        # This is just to exclude the build time from the start-up time.
        # If there are build errors, they'll be reported later in the `run`
        # call below.
        subprocess.call(
            ['cargo', 'build'],
            cwd=self._code_dir,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)

        self._proc = subprocess.Popen(
            ['cargo', 'run', str(self.qdb_ilp_port)],
            cwd=self._code_dir,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT)

        # Create future for port detection
        self._port_future = concurrent.futures.Future()

        # Start thread to capture and forward output
        self._output_thread = threading.Thread(
            target=self._capture_output,
            args=(self._proc.stdout, self._port_future))
        self._output_thread.daemon = True
        self._output_thread.start()

        # Wait for port detection with timeout
        try:
            self.listen_port = self._port_future.result(timeout=180)
        except concurrent.futures.TimeoutError as toe:
            raise RuntimeError('Timed out waiting for `tls_proxy` to start.') from toe

        def connect_to_listening_port():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.connect(('localhost', self.listen_port))
            except ConnectionRefusedError:
                return False
            finally:
                sock.close()
            return True

        retry(
            connect_to_listening_port,
            msg='Timed out connecting to `tls_proxy`')
        atexit.register(self.stop)

    def stop(self):
        if self._proc:
            if self._output_thread.is_alive():
                self._output_thread.join(timeout=5)
            self._proc.terminate()
            self._proc.wait()
            self._proc = None
