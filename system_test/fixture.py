################################################################################
##     ___                  _   ____  ____
##    / _ \ _   _  ___  ___| |_|  _ \| __ )
##   | | | | | | |/ _ \/ __| __| | | |  _ \
##   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
##    \__\_\\__,_|\___||___/\__|____/|____/
##
##  Copyright (c) 2014-2019 Appsicle
##  Copyright (c) 2019-2022 QuestDB
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
import shlex
import textwrap
import urllib.request
import urllib.parse
import urllib.error


AUTH_TXT = """testUser1 ec-p-256-sha256 fLKYEaoEb9lrn3nkwLDA-M_xnuFOdSt9y0Z7_vWSHLU Dt5tbS1dEDMSYfym3fgMv0B99szno-dFc1rYF9t0aac
# [key/user id] [key type] {keyX keyY}"""


def retry(predicate_task, timeout_sec=30, every=0.05, msg='Timed out retrying'):
    """
    Repeat task every `interval` until it returns a truthy value or times out.
    """
    begin = time.monotonic()
    threshold = begin + timeout_sec
    while True:
        res = predicate_task()
        if res:
            return res
        elif time.monotonic() < threshold:
            time.sleep(every)
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
            raise RuntimeError('Build before running tests.')
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
    return shutil.which('java', path=str(search_path))


class QuestDbFixture:
    def __init__(self, root_dir: pathlib.Path, auth=False):
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

        self.auth = auth
        if self.auth:
            auth_txt_path = self._conf_dir / 'auth.txt'
            with open(auth_txt_path, 'w', encoding='utf-8') as auth_file:
                auth_file.write(AUTH_TXT)

    def print_log_tail(self):
        with open(self._log_path, 'r', encoding='utf-8') as log_file:
            lines = log_file.readlines()
            buf = ''.join(lines[-300:])
            sys.stderr.write(textwrap.indent(buf, '    '))
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
                cairo.max.uncommitted.rows=1
                line.tcp.maintenance.job.interval=100
                line.tcp.min.idle.ms.before.writer.release=300
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
                    f'http://127.0.0.1:{self.http_server_port}',
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
                timeout_sec=45,
                msg='Timed out waiting for HTTP service to come up.')
        except:
            sys.stderr.write(f'Failed to start, see full log: `{self._log_path}`. Tail:\n')
            self.print_log_tail()
            raise

        atexit.register(self.stop)
        sys.stderr.write('QuestDB fixture instance is ready.\n')

    def __enter__(self):
        self.start()

    def stop(self):
        if self._proc:
            self._proc.terminate()
            self._proc.wait()
            self._proc = None
        if self._log:
            self._log.close()
            self._log = None

    def __exit__(self, _ty, _value, _tb):
        self.stop()


HAPROXY_CFG = """
defaults
    timeout connect 5s
    timeout client 600s
    timeout server 600s

frontend ilpfront
    bind 0.0.0.0:{listen_port} ssl crt {pem_path}
    mode tcp
    default_backend ilp

backend ilp
    mode tcp
    balance leastconn
    server questdb localhost:{qdb_ilp_port} verify none
"""


class HaProxyFixture:
    def __init__(self, qdb_ilp_port):
        proj = Project()
        self.listen_port = discover_avail_ports(1)[0]
        self.qdb_ilp_port = qdb_ilp_port
        haproxy_dir = proj.build_dir / 'haproxy'
        haproxy_dir.mkdir(exist_ok=True)
        self.haproxy_cfg_path = haproxy_dir / 'haproxy.cfg'
        with open(self.haproxy_cfg_path, 'w', encoding='utf-8') as haproxy_cfg:
            haproxy_cfg.write(HAPROXY_CFG.format(
                listen_port=self.listen_port,
                pem_path=str(proj.system_test_dir / 'haproxy.pem'),
                qdb_ilp_port=qdb_ilp_port))
        self._proc = None

    def start(self):
        args = ['haproxy', '-f', str(self.haproxy_cfg_path)]
        self._proc = subprocess.Popen(args)

        def connect_to_listening_port():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.connect(('127.0.0.1', self.listen_port))
            except ConnectionRefusedError:
                return False
            finally:
                sock.close()
            return True

        retry(connect_to_listening_port, msg='Timed out waiting for `haproxy`')
        atexit.register(self.stop)

    def stop(self):
        if self._proc:
            self._proc.terminate()
            self._proc.wait()
            self._proc = None
