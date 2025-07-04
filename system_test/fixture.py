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
import subprocess
import time
import socket
import atexit
import textwrap
import urllib.request
import urllib.parse
import urllib.error
import concurrent.futures
import threading
from pprint import pformat

AUTH_TXT = """admin ec-p-256-sha256 fLKYEaoEb9lrn3nkwLDA-M_xnuFOdSt9y0Z7_vWSHLU Dt5tbS1dEDMSYfym3fgMv0B99szno-dFc1rYF9t0aac
# [key/user id] [key type] {keyX keyY}"""

# Valid keys as registered with the QuestDB fixture.
AUTH = dict(
    username="admin",
    token="5UjEMuA0Pj5pjK8a-fa24dyIf-Es5mYny3oE_Wmus48",
    token_x="fLKYEaoEb9lrn3nkwLDA-M_xnuFOdSt9y0Z7_vWSHLU",
    token_y="Dt5tbS1dEDMSYfym3fgMv0B99szno-dFc1rYF9t0aac")

CA_PATH = (pathlib.Path(__file__).parent.parent /
           'tls_certs' / 'server_rootCA.pem')


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


class QueryError(Exception):
    """An error querying the database with SQL over HTTP."""
    pass


class QuestDbFixtureBase:
    def print_log(self):
        """Print the QuestDB log to stderr."""
        sys.stderr.write('questdb log output skipped.\n')

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
    def __init__(self, host, line_tcp_port, http_server_port, version, http, auth, protocol_version):
        self.host = host
        self.line_tcp_port = line_tcp_port
        self.http_server_port = http_server_port
        self.version = version
        self.http = http
        self.auth = auth
        self.protocol_version = protocol_version


class QuestDbFixture(QuestDbFixtureBase):
    def __init__(self, root_dir: pathlib.Path, auth=False, wrap_tls=False, http=False, protocol_version=None):
        self._root_dir = root_dir
        self.version = _parse_version(self._root_dir.name)
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
        self.pg_port = None

        self.wrap_tls = wrap_tls
        self._tls_proxy = None
        self.tls_line_tcp_port = None

        self.auth = auth
        if self.auth:
            auth_txt_path = self._conf_dir / 'auth.txt'
            with open(auth_txt_path, 'w', encoding='utf-8') as auth_file:
                auth_file.write(AUTH_TXT)
        self.http = http
        self.protocol_version = protocol_version

    def print_log(self):
        with open(self._log_path, 'r', encoding='utf-8') as log_file:
            log = log_file.read()
            sys.stderr.write(textwrap.indent(log, '    '))
            sys.stderr.write('\n\n')

    def start(self):
        ports = discover_avail_ports(3)
        self.http_server_port, self.line_tcp_port, self.pg_port = ports
        auth_config = 'line.tcp.auth.db.path=conf/auth.txt' if self.auth else ''
        ilp_over_http_config = 'line.http.enabled=true' if self.http else ''
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
                line.tcp.commit.interval.fraction=0.1
                {auth_config}
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
            '-p', str(self._root_dir / 'bin' / 'questdb.jar'),
            '-m', 'io.questdb/io.questdb.ServerMain',
            '-d', str(self._data_dir)]
        sys.stderr.write(
            f'Starting QuestDB: {launch_args!r} (auth: {self.auth}, http: {self.http})\n')
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
                    f'http://127.0.0.1:{self.http_server_port}/ping',
                    method='GET')
                try:
                    resp = urllib.request.urlopen(req, timeout=1)
                    if resp.status == 204:
                        return True
                except socket.timeout:
                    pass
                except urllib.error.URLError:
                    pass
                return False

            sys.stderr.write('Waiting until HTTP service is up.\n')
            retry(
                check_http_up,
                timeout_sec=300,
                msg='Timed out waiting for HTTP service to come up.')
        except:
            sys.stderr.write(f'QuestDB log at `{self._log_path}`:\n')
            self.print_log()
            raise

        atexit.register(self.stop)
        sys.stderr.write('QuestDB fixture instance is ready.\n')

        # Read the actual version from the running process.
        # This is to support a version like `7.3.2-SNAPSHOT`
        # from an externally started QuestDB instance.
        self.version = self.query_version()

        if self.wrap_tls:
            self._tls_proxy = TlsProxyFixture(self.line_tcp_port)
            self._tls_proxy.start()
            self.tls_line_tcp_port = self._tls_proxy.listen_port

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
