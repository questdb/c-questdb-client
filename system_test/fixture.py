################################################################################
##     ___                  _   ____  ____
##    / _ \ _   _  ___  ___| |_|  _ \| __ )
##   | | | | | | |/ _ \/ __| __| | | |  _ \
##   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
##    \__\_\\__,_|\___||___/\__|____/|____/
##
##  Copyright (c) 2014-2019 Appsicle
##  Copyright (c) 2019-2023 QuestDB
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
import pathlib
import textwrap
import json
import tarfile
import shutil
import subprocess
import time
import socket
import atexit
import textwrap
import urllib.request
import urllib.parse
import urllib.error
from pprint import pformat


AUTH_TXT = """testUser1 ec-p-256-sha256 fLKYEaoEb9lrn3nkwLDA-M_xnuFOdSt9y0Z7_vWSHLU Dt5tbS1dEDMSYfym3fgMv0B99szno-dFc1rYF9t0aac
# [key/user id] [key type] {keyX keyY}"""


# Valid keys as registered with the QuestDB fixture.
AUTH = (
    "testUser1",
    "5UjEMuA0Pj5pjK8a-fa24dyIf-Es5mYny3oE_Wmus48",
    "fLKYEaoEb9lrn3nkwLDA-M_xnuFOdSt9y0Z7_vWSHLU",
    "Dt5tbS1dEDMSYfym3fgMv0B99szno-dFc1rYF9t0aac")


CA_PATH = (pathlib.Path(__file__).parent.parent /
    'tls_certs' / 'server_rootCA.pem')


def retry(
    predicate_task,
    timeout_sec=30,
    every=0.05,
    msg='Timed out retrying',
    backoff_till=5.0,
    lead_sleep=0.1):
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


class QueryError(Exception):
    """An error querying the database with SQL over HTTP."""
    pass


class QuestDbFixture:
    def __init__(self, root_dir: pathlib.Path, auth=False, wrap_tls=False):
        self._root_dir = root_dir
        self.version = _parse_version(self._root_dir.name)
        self._data_dir = self._root_dir / 'data'
        self._log_path = self._data_dir / 'log' / 'log.txt'
        self._conf_dir = self._data_dir / 'conf'
        self._conf_dir.mkdir(exist_ok=True)
        self._conf_path = self._conf_dir / 'server.conf'
        self._log = None
        self._proc = None
        self.host = 'localhost'
        self.http_server_port = None
        self.line_tcp_port = None
        self.pg_port = None

        self.wrap_tls = wrap_tls
        self._tls_proxy = None
        self.tls_line_tcp_port = None

        self.auth = auth
        if self.auth:
            auth_txt_path = self._conf_dir / 'auth.txt'
            with open(auth_txt_path, 'w', encoding='utf-8') as auth_file:
                auth_file.write(AUTH_TXT)

    def print_log(self):
        with open(self._log_path, 'r', encoding='utf-8') as log_file:
            log = log_file.read()
            sys.stderr.write(textwrap.indent(log, '    '))
            sys.stderr.write('\n\n')

    def start(self):
        ports = discover_avail_ports(3)
        self.http_server_port, self.line_tcp_port, self.pg_port = ports
        auth_config = 'line.tcp.auth.db.path=conf/auth.txt' if self.auth else ''
        with open(self._conf_path, 'w', encoding='utf-8') as conf_file:
            conf_file.write(textwrap.dedent(rf'''
                http.bind.to=0.0.0.0:{self.http_server_port}
                line.tcp.net.bind.to=0.0.0.0:{self.line_tcp_port}
                pg.net.bind.to=0.0.0.0:{self.pg_port}
                http.min.enabled=false
                line.udp.enabled=false
                line.tcp.maintenance.job.interval=100
                line.tcp.min.idle.ms.before.writer.release=300
                telemetry.enabled=false
                cairo.commit.lag=100
                lne.tcp.commit.interval.fraction=0.1
                {auth_config}
                ''').lstrip('\n'))

        java = _find_java()
        launch_args = [
            java,
            '-DQuestDB-Runtime-0',
            '-ea',
            #'-Dnoebug',
            '-Debug',
            '-XX:+UnlockExperimentalVMOptions',
            '-XX:+AlwaysPreTouch',
            '-XX:+UseParallelOldGC',
            '-p', str(self._root_dir / 'bin' / 'questdb.jar'),
            '-m', 'io.questdb/io.questdb.ServerMain',
            '-d', str(self._data_dir)]
        sys.stderr.write(
            f'Starting QuestDB: {launch_args!r} (auth: {self.auth})\n')
        self._log = open(self._log_path, 'ab')
        try:
            self._proc = subprocess.Popen(
                launch_args,
                close_fds=True,
                cwd=self._data_dir,
                # env=launch_env,
                stdout=self._log,
                stderr=subprocess.STDOUT)

            def check_http_up():
                if self._proc.poll() is not None:
                    raise RuntimeError('QuestDB died during startup.')
                req = urllib.request.Request(
                    f'http://localhost:{self.http_server_port}',
                    method='HEAD')
                try:
                    resp = urllib.request.urlopen(req, timeout=1)
                    if resp.status == 200:
                        return True
                except socket.timeout:
                    pass
                except urllib.error.URLError:
                    pass
                return False

            sys.stderr.write('Waiting until HTTP service is up.\n')
            retry(
                check_http_up,
                timeout_sec=60,
                msg='Timed out waiting for HTTP service to come up.')
        except:
            sys.stderr.write(f'QuestDB log at `{self._log_path}`:\n')
            self.print_log()
            raise

        atexit.register(self.stop)
        sys.stderr.write('QuestDB fixture instance is ready.\n')

        if self.wrap_tls:
            self._tls_proxy = TlsProxyFixture(self.line_tcp_port)
            self._tls_proxy.start()
            self.tls_line_tcp_port = self._tls_proxy.listen_port

    def http_sql_query(self, sql_query):
        url = (
            f'http://{self.host}:{self.http_server_port}/exec?' +
            urllib.parse.urlencode({'query': sql_query}))
        buf = None
        try:
            resp = urllib.request.urlopen(url, timeout=5)
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

    def retry_check_table(
            self,
            table_name,
            *,
            min_rows=1,
            timeout_sec=30,
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

        try:
            return retry(check_table, timeout_sec=timeout_sec)
        except TimeoutError as toe:
            if log:
                if log_ctx:
                    log_ctx = f'\n{textwrap.indent(log_ctx, "    ")}\n'
                sys.stderr.write(
                    f'Timed out after {timeout_sec} seconds ' +
                    f'waiting for query {sql_query!r}. ' +
                    f'Context: {log_ctx}' +
                    f'Client response log:\n' +
                    pformat(http_response_log) +
                    f'\nQuestDB log:\n')
                self.print_log()
            raise toe

    def __enter__(self):
        self.start()

    def stop(self):
        if self._tls_proxy:
            self._tls_proxy.stop()
        if self._proc:
            self._proc.terminate()
            self._proc.wait()
            self._proc = None
        if self._log:
            self._log.close()
            self._log = None

    def __exit__(self, _ty, _value, _tb):
        self.stop()


class TlsProxyFixture:
    def __init__(self, qdb_ilp_port):
        self.qdb_ilp_port = qdb_ilp_port
        self.listen_port = None
        proj = Project()
        self._code_dir = proj.root_dir / 'system_test' / 'tls_proxy'
        self._target_dir = proj.build_dir / 'tls_proxy'
        self._log_path = self._target_dir / 'log.txt'
        self._log_file = None
        self._proc = None

    def start(self):
        self._target_dir.mkdir(exist_ok=True)
        env = dict(os.environ)
        env['CARGO_TARGET_DIR'] = str(self._target_dir)
        self._log_file = open(self._log_path, 'wb')
        self._proc = subprocess.Popen(
            ['cargo', 'run', str(self.qdb_ilp_port)],
            cwd=self._code_dir,
            env=env,
            stdout=self._log_file,
            stderr=subprocess.STDOUT)

        def check_started():
            with open(self._log_path, 'r', encoding='utf-8') as log_reader:
                lines = log_reader.readlines()
                for line in lines:
                    listening_msg = 'TLS Proxy is listening on localhost:'
                    if line.startswith(listening_msg) and line.endswith('.\n'):
                        port_str = line[len(listening_msg):-2]
                        port = int(port_str)
                        return port
            return None

        self.listen_port = retry(
            check_started,
            timeout_sec=180,  # Longer to include time to compile.
            msg='Timed out waiting for `tls_proxy` to start.',)

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
            self._proc.terminate()
            self._proc.wait()
            self._proc = None
