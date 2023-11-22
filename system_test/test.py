#!/usr/bin/env python3

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
import textwrap

import math
import datetime
import argparse
import unittest
import time
import questdb_line_sender as qls
import uuid
from fixture import (
    Project,
    QuestDbFixture,
    TlsProxyFixture,
    install_questdb,
    list_questdb_releases,
    AUTH)
import subprocess
from collections import namedtuple


QDB_FIXTURE: QuestDbFixture = None
TLS_PROXY_FIXTURE: TlsProxyFixture = None


def retry_check_table(*args, **kwargs):
    return QDB_FIXTURE.retry_check_table(*args, **kwargs)


def ns_to_qdb_date(at_ts_ns):
    # We first need to match QuestDB's internal microsecond resolution.
    at_ts_us = int(at_ts_ns / 1000.0)
    at_ts_sec = at_ts_us / 1000000.0
    at_td = datetime.datetime.fromtimestamp(at_ts_sec)
    return at_td.isoformat() + 'Z'


# Valid keys, but not registered with the QuestDB fixture.
AUTH_UNRECOGNIZED = (
    "testUser2",
    "xiecEl-2zbg6aYCFbxDMVWaly9BlCTaEChvcxCH5BCk",
    "-nSHz3evuPl-rGLIlbIZjwOJeWao0rbk53Cll6XEgak",
    "9iYksF4L5mfmArupv0CMoyVAWjQ4gNIoupdg6N5noG8")


# Bad malformed key
AUTH_MALFORMED1 = (
    "testUser3",
    "xiecEl-zzbg6aYCFbxDMVWaly9BlCTaEChvcxCH5BCk",
    "-nSHz3evuPl-rGLIlbIZjwOJeWao0rbk53Cll6XEgak",
    "9iYksF4L6mfmArupv0CMoyVAWjQ4gNIoupdg6N5noG8")


# Another malformed key where the keys invalid base 64.
AUTH_MALFORMED2 = (
    "testUser4",
    "xiecEl-zzbg6aYCFbxDMVWaly9BlCTaECH5BCk",
    "-nSHz3evuPl-rGLIlbIZjwOJeWao0rbk5XEgak",
    "9iYksF4L6mfmArupv0CMoyVAWjQ4gNIou5noG8")


class TestSender(unittest.TestCase):
    def _mk_linesender(self):
        return qls.Sender(
            QDB_FIXTURE.host,
            QDB_FIXTURE.line_tcp_port,
            auth=AUTH if QDB_FIXTURE.auth else None)

    def _expect_eventual_disconnect(self, sender):
        with self.assertRaisesRegex(
                qls.SenderError, r'.*Could not flush buffer'):
            table_name = uuid.uuid4().hex
            for _ in range(1000):
                time.sleep(0.1)
                (sender
                    .table(table_name)
                    .symbol('s1', 'v1')
                    .at_now())
                sender.flush()

    def test_insert_three_rows(self):
        table_name = uuid.uuid4().hex
        pending = None
        with self._mk_linesender() as sender:
            for _ in range(3):
                (sender
                    .table(table_name)
                    .symbol('name_a', 'val_a')
                    .column('name_b', True)
                    .column('name_c', 42)
                    .column('name_d', 2.5)
                    .column('name_e', 'val_b')
                    .at_now())
            pending = sender.buffer.peek()
            sender.flush()

        resp = retry_check_table(table_name, min_rows=3, log_ctx=pending)
        exp_columns = [
            {'name': 'name_a', 'type': 'SYMBOL'},
            {'name': 'name_b', 'type': 'BOOLEAN'},
            {'name': 'name_c', 'type': 'LONG'},
            {'name': 'name_d', 'type': 'DOUBLE'},
            {'name': 'name_e', 'type': 'STRING'},
            {'name': 'timestamp', 'type': 'TIMESTAMP'}]
        self.assertEqual(resp['columns'], exp_columns)

        exp_dataset = [  # Comparison excludes timestamp column.
            ['val_a', True, 42, 2.5, 'val_b'],
            ['val_a', True, 42, 2.5, 'val_b'],
            ['val_a', True, 42, 2.5, 'val_b']]
        scrubbed_dataset = [row[:-1] for row in resp['dataset']]
        self.assertEqual(scrubbed_dataset, exp_dataset)

    def test_repeated_symbol_and_column_names(self):
        if QDB_FIXTURE.version <= (6, 1, 2):
            self.skipTest('No support for duplicate column names.')
            return
        table_name = uuid.uuid4().hex
        pending = None
        with self._mk_linesender() as sender:
            (sender
                .table(table_name)
                .symbol('a', 'A')
                .symbol('a', 'B')
                .column('b', False)
                .column('b', 'C')
                .at_now())
            pending = sender.buffer.peek()

        resp = retry_check_table(table_name, log_ctx=pending)
        exp_columns = [
            {'name': 'a', 'type': 'SYMBOL'},
            {'name': 'b', 'type': 'BOOLEAN'},
            {'name': 'timestamp', 'type': 'TIMESTAMP'}]
        self.assertEqual(resp['columns'], exp_columns)

        exp_dataset = [['A', False]]  # Comparison excludes timestamp column.
        scrubbed_dataset = [row[:-1] for row in resp['dataset']]
        self.assertEqual(scrubbed_dataset, exp_dataset)

    def test_same_symbol_and_col_name(self):
        if QDB_FIXTURE.version <= (6, 1, 2):
            self.skipTest('No support for duplicate column names.')
            return
        table_name = uuid.uuid4().hex
        pending = None
        with self._mk_linesender() as sender:
            (sender
                .table(table_name)
                .symbol('a', 'A')
                .column('a', 'B')
                .at_now())
            pending = sender.buffer.peek()

        resp = retry_check_table(table_name, log_ctx=pending)
        exp_columns = [
            {'name': 'a', 'type': 'SYMBOL'},
            {'name': 'timestamp', 'type': 'TIMESTAMP'}]
        self.assertEqual(resp['columns'], exp_columns)

        exp_dataset = [['A']]  # Comparison excludes timestamp column.
        scrubbed_dataset = [row[:-1] for row in resp['dataset']]
        self.assertEqual(scrubbed_dataset, exp_dataset)

    def _test_single_symbol_impl(self, sender):
        table_name = uuid.uuid4().hex
        pending = None
        with sender:
            (sender
                .table(table_name)
                .symbol('a', 'A')
                .at_now())
            pending = sender.buffer.peek()

        resp = retry_check_table(table_name, log_ctx=pending)
        exp_columns = [
            {'name': 'a', 'type': 'SYMBOL'},
            {'name': 'timestamp', 'type': 'TIMESTAMP'}]
        self.assertEqual(resp['columns'], exp_columns)

        exp_dataset = [['A']]  # Comparison excludes timestamp column.
        scrubbed_dataset = [row[:-1] for row in resp['dataset']]
        self.assertEqual(scrubbed_dataset, exp_dataset)

    def test_single_symbol(self):
        self._test_single_symbol_impl(self._mk_linesender())

    def test_two_columns(self):
        table_name = uuid.uuid4().hex
        pending = None
        with self._mk_linesender() as sender:
            (sender
                .table(table_name)
                .column('a', 'A')
                .column('b', 'B')
                .at_now())
            pending = sender.buffer.peek()

        resp = retry_check_table(table_name, log_ctx=pending)
        exp_columns = [
            {'name': 'a', 'type': 'STRING'},
            {'name': 'b', 'type': 'STRING'},
            {'name': 'timestamp', 'type': 'TIMESTAMP'}]
        self.assertEqual(resp['columns'], exp_columns)

        exp_dataset = [['A', 'B']]  # Comparison excludes timestamp column.
        scrubbed_dataset = [row[:-1] for row in resp['dataset']]
        self.assertEqual(scrubbed_dataset, exp_dataset)

    def test_mismatched_types_across_rows(self):
        table_name = uuid.uuid4().hex
        pending = None
        with self._mk_linesender() as sender:
            (sender
                .table(table_name)
                .column('a', 'A')  # STRING
                .at_now())
            (sender
                .table(table_name)
                .symbol('a', 'B')  # SYMBOL
                .at_now())

            pending = sender.buffer.peek()

        # We only ever get the first row back.
        resp = retry_check_table(table_name, log_ctx=pending)
        exp_columns = [
            {'name': 'a', 'type': 'STRING'},
            {'name': 'timestamp', 'type': 'TIMESTAMP'}]
        self.assertEqual(resp['columns'], exp_columns)

        exp_dataset = [['A']]  # Comparison excludes timestamp column.
        scrubbed_dataset = [row[:-1] for row in resp['dataset']]
        self.assertEqual(scrubbed_dataset, exp_dataset)

        # The second one is dropped and will not appear in results.
        with self.assertRaises(TimeoutError):
            retry_check_table(table_name, min_rows=2, timeout_sec=1, log=False)

    def test_at(self):
        if QDB_FIXTURE.version <= (6, 0, 7, 1):
            self.skipTest('No support for user-provided timestamps.')
            return
        table_name = uuid.uuid4().hex
        at_ts_ns = 1647357688714369403
        pending = None
        with self._mk_linesender() as sender:
            (sender
                .table(table_name)
                .symbol('a', 'A')
                .at(at_ts_ns))
            pending = sender.buffer.peek()

        resp = retry_check_table(table_name, log_ctx=pending)
        exp_dataset = [['A', ns_to_qdb_date(at_ts_ns)]]
        self.assertEqual(resp['dataset'], exp_dataset)

    def test_neg_at(self):
        if QDB_FIXTURE.version <= (6, 0, 7, 1):
            self.skipTest('No support for user-provided timestamps.')
            return
        table_name = uuid.uuid4().hex
        at_ts_ns = -10000000
        with self.assertRaisesRegex(qls.SenderError, r'Bad call to'):
            with self._mk_linesender() as sender:
                with self.assertRaisesRegex(qls.SenderError, r'.*Timestamp .* is negative.*'):
                    (sender
                        .table(table_name)
                        .symbol('a', 'A')
                        .at(at_ts_ns))

    def test_timestamp_col(self):
        if QDB_FIXTURE.version <= (6, 0, 7, 1):
            self.skipTest('No support for user-provided timestamps.')
            return
        table_name = uuid.uuid4().hex
        pending = None
        with self._mk_linesender() as sender:
            (sender
                .table(table_name)
                .column('a', qls.TimestampMicros(-1000000))
                .at_now())
            (sender
                .table(table_name)
                .column('a', qls.TimestampMicros(1000000))
                .at_now())
            pending = sender.buffer.peek()

        resp = retry_check_table(table_name, log_ctx=pending)
        exp_columns = [
            {'name': 'a', 'type': 'TIMESTAMP'},
            {'name': 'timestamp', 'type': 'TIMESTAMP'}]
        self.assertEqual(resp['columns'], exp_columns)

        exp_dataset = [['1969-12-31T23:59:59.000000Z'], ['1970-01-01T00:00:01.000000Z']]
        scrubbed_dataset = [row[:-1] for row in resp['dataset']]
        self.assertEqual(scrubbed_dataset, exp_dataset)
        

    def test_underscores(self):
        table_name = f'_{uuid.uuid4().hex}_'
        pending = None
        with self._mk_linesender() as sender:
            (sender
                .table(table_name)
                .symbol('_a_b_c_', 'A')
                .column('_d_e_f_', True)
                .at_now())
            pending = sender.buffer.peek()

        resp = retry_check_table(table_name, log_ctx=pending)
        exp_columns = [
            {'name': '_a_b_c_', 'type': 'SYMBOL'},
            {'name': '_d_e_f_', 'type': 'BOOLEAN'},
            {'name': 'timestamp', 'type': 'TIMESTAMP'}]
        self.assertEqual(resp['columns'], exp_columns)

        exp_dataset = [['A', True]]  # Comparison excludes timestamp column.
        scrubbed_dataset = [row[:-1] for row in resp['dataset']]
        self.assertEqual(scrubbed_dataset, exp_dataset)

    def test_funky_chars(self):
        if QDB_FIXTURE.version <= (6, 0, 7, 1):
            self.skipTest('No unicode support.')
            return
        table_name = uuid.uuid4().hex
        smilie = b'\xf0\x9f\x98\x81'.decode('utf-8')
        pending = None
        with self._mk_linesender() as sender:
            sender.table(table_name)
            sender.symbol(smilie, smilie)
            # for num in range(1, 32):
            #     char = chr(num)
            #     sender.column(char, char)
            sender.at_now()
            pending = sender.buffer.peek()

        resp = retry_check_table(table_name, log_ctx=pending)
        exp_columns = [
            {'name': smilie, 'type': 'SYMBOL'},
            {'name': 'timestamp', 'type': 'TIMESTAMP'}]
        self.assertEqual(resp['columns'], exp_columns)

        exp_dataset = [[smilie]]  # Comparison excludes timestamp column.
        scrubbed_dataset = [row[:-1] for row in resp['dataset']]
        self.assertEqual(scrubbed_dataset, exp_dataset)

    def test_floats(self):
        if QDB_FIXTURE.version <= (6, 1, 2):
            self.skipTest('Float issues support')
        numbers = [
            0.0,
            -0.0,
            1.0,
            -1.0,
            10.0,
            0.1,
            0.01,
            0.000001,
            -0.000001,
            100.0,
            1.2,
            1234.5678,
            -1234.5678,
            1.23456789012,
            1000000000000000000000000.0,
            -1000000000000000000000000.0,
            float("nan"),   # Converted to `None`.
            float("inf"),   # Converted to `None`.
            float("-inf")]  # Converted to `None`.

            # These values below do not round-trip properly: QuestDB limitation.
            # 1.2345678901234567,
            # 2.2250738585072014e-308,
            # -2.2250738585072014e-308,
            # 1.7976931348623157e+308,
            # -1.7976931348623157e+308]
        table_name = uuid.uuid4().hex
        pending = None
        with self._mk_linesender() as sender:
            for num in numbers:
                sender.table(table_name)
                sender.column('n', num)
                sender.at_now()
            pending = sender.buffer.peek()

        resp = retry_check_table(
            table_name,
            min_rows=len(numbers),
            log_ctx=pending)
        exp_columns = [
            {'name': 'n', 'type': 'DOUBLE'},
            {'name': 'timestamp', 'type': 'TIMESTAMP'}]
        self.assertEqual(resp['columns'], exp_columns)

        def massage(num):
            if math.isnan(num) or math.isinf(num):
                return None
            elif num == -0.0:
                return 0.0
            else:
                return num

        # Comparison excludes timestamp column.
        exp_dataset = [[massage(num)] for num in numbers]
        scrubbed_dataset = [row[:-1] for row in resp['dataset']]
        self.assertEqual(scrubbed_dataset, exp_dataset)

    def test_timestamp_column(self):
        table_name = uuid.uuid4().hex
        pending = None
        ts = qls.TimestampMicros(3600000000)  # One hour past epoch.
        with self._mk_linesender() as sender:
            (sender
                .table(table_name)
                .column('ts1', ts)
                .at_now())
            pending = sender.buffer.peek()

        resp = retry_check_table(table_name, log_ctx=pending)
        exp_columns = [
            {'name': 'ts1', 'type': 'TIMESTAMP'},
            {'name': 'timestamp', 'type': 'TIMESTAMP'}]
        self.assertEqual(resp['columns'], exp_columns)
        exp_dataset = [['1970-01-01T01:00:00.000000Z']]
        scrubbed_dataset = [row[:-1] for row in resp['dataset']]
        self.assertEqual(scrubbed_dataset, exp_dataset)

    def _test_example(self, bin_name, table_name, tls=False):
        if tls and not QDB_FIXTURE.auth:
            self.skipTest('No auth')
        # Call the example program.
        proj = Project()
        ext = '.exe' if sys.platform == 'win32' else ''
        bin_path = next(proj.build_dir.glob(f'**/{bin_name}{ext}'))
        port = QDB_FIXTURE.line_tcp_port
        args = [str(bin_path)]
        if tls:
            ca_path = proj.tls_certs_dir / 'server_rootCA.pem'
            args.append(str(ca_path))
            port = TLS_PROXY_FIXTURE.listen_port
        args.extend(['localhost', str(port)])
        subprocess.check_call(args, cwd=bin_path.parent)

        # Check inserted data.
        resp = retry_check_table(table_name)
        exp_columns = [
            {'name': 'id', 'type': 'SYMBOL'},
            {'name': 'x', 'type': 'DOUBLE'},
            {'name': 'y', 'type': 'DOUBLE'},
            {'name': 'booked', 'type': 'BOOLEAN'},
            {'name': 'passengers', 'type': 'LONG'},
            {'name': 'driver', 'type': 'STRING'},
            {'name': 'timestamp', 'type': 'TIMESTAMP'}]
        self.assertEqual(resp['columns'], exp_columns)

        exp_dataset = [[
            'd6e5fe92-d19f-482a-a97a-c105f547f721',
            30.5,
            -150.25,
            True,
            3,
            'John Doe']]  # Comparison excludes timestamp column.
        scrubbed_dataset = [row[:-1] for row in resp['dataset']]
        self.assertEqual(scrubbed_dataset, exp_dataset)

    def test_c_example(self):
        suffix = '_auth' if QDB_FIXTURE.auth else ''
        self._test_example(
            f'line_sender_c_example{suffix}',
            f'c_cars{suffix}')

    def test_cpp_example(self):
        suffix = '_auth' if QDB_FIXTURE.auth else ''
        self._test_example(
            f'line_sender_cpp_example{suffix}',
            f'cpp_cars{suffix}')

    def test_c_tls_example(self):
        self._test_example(
            'line_sender_c_example_tls_ca',
            'c_cars_tls',
            tls=True)

    def test_cpp_tls_example(self):
        self._test_example(
            'line_sender_cpp_example_tls_ca',
            'cpp_cars_tls',
            tls=True)

    def test_opposite_auth(self):
        """
        We simulate incorrectly connecting either:
          * An authenticating client to a non-authenticating DB instance.
          * Or a non-authenticating client to an authenticating DB instance.
        """
        client_auth = None if QDB_FIXTURE.auth else AUTH
        sender = qls.Sender(
            QDB_FIXTURE.host,
            QDB_FIXTURE.line_tcp_port,
            auth=client_auth)
        if client_auth:
            with self.assertRaisesRegex(
                    qls.SenderError,
                    r'.*not receive auth challenge.*'):
                sender.connect()
        else:
            table_name = uuid.uuid4().hex
            with sender:  # Connecting will not fail.

                # The sending the first line will not fail.
                (sender
                    .table(table_name)
                    .symbol('s1', 'v1')
                    .at_now())
                sender.flush()

                self._expect_eventual_disconnect(sender)

    def test_unrecognized_auth(self):
        if not QDB_FIXTURE.auth:
            self.skipTest('No auth')

        sender = qls.Sender(
            QDB_FIXTURE.host,
            QDB_FIXTURE.line_tcp_port,
            auth=AUTH_UNRECOGNIZED)

        with sender:
            self._expect_eventual_disconnect(sender)

    def test_malformed_auth1(self):
        if not QDB_FIXTURE.auth:
            self.skipTest('No auth')

        sender = qls.Sender(
            QDB_FIXTURE.host,
            QDB_FIXTURE.line_tcp_port,
            auth=AUTH_MALFORMED1)

        with self.assertRaisesRegex(
                qls.SenderError,
                r'.*Bad private key.*'):
            sender.connect()

    def test_malformed_auth2(self):
        if not QDB_FIXTURE.auth:
            self.skipTest('No auth')

        sender = qls.Sender(
            QDB_FIXTURE.host,
            QDB_FIXTURE.line_tcp_port,
            auth=AUTH_MALFORMED2)

        with self.assertRaisesRegex(
                qls.SenderError,
                r'.*invalid Base64.*'):
            sender.connect()

    def test_tls_insecure_skip_verify(self):
        sender = qls.Sender(
            QDB_FIXTURE.host,
            TLS_PROXY_FIXTURE.listen_port,
            auth=AUTH if QDB_FIXTURE.auth else None,
            tls='insecure_skip_verify')
        self._test_single_symbol_impl(sender)

    def test_tls_ca(self):
        sender = qls.Sender(
            QDB_FIXTURE.host,
            TLS_PROXY_FIXTURE.listen_port,
            auth=AUTH if QDB_FIXTURE.auth else None,
            tls=Project().tls_certs_dir / 'server_rootCA.pem')
        self._test_single_symbol_impl(sender)

    def _test_tls_special(self, tls_mode):
        prev_ssl_cert_file = os.environ.get('SSL_CERT_FILE')
        try:
            os.environ['SSL_CERT_FILE'] = str(
                Project().tls_certs_dir / 'server_rootCA.pem')
            sender = qls.Sender(
                QDB_FIXTURE.host,
                TLS_PROXY_FIXTURE.listen_port,
                auth=AUTH if QDB_FIXTURE.auth else None,
                tls=tls_mode)
            self._test_single_symbol_impl(sender)
        finally:
            if prev_ssl_cert_file:
                os.environ['SSL_CERT_FILE'] = prev_ssl_cert_file
            else:
                del os.environ['SSL_CERT_FILE']

    def test_tls_os_roots(self):
        self._test_tls_special('os_roots')

    def test_tls_webpki_and_os_roots(self):
        self._test_tls_special('webpki_and_os_roots')

def parse_args():
    parser = argparse.ArgumentParser('Run system tests.')
    sub_p = parser.add_subparsers(dest='command')
    run_p = sub_p.add_parser('run', help='Run tests')
    run_p.add_argument(
        '--unittest-help',
        action='store_true',
        help='Show unittest --help')
    version_g = run_p.add_mutually_exclusive_group()
    version_g.add_argument(
        '--last-n',
        type=int,
        help='test against last N versions')
    version_g.add_argument(
        '--versions',
        type=str,
        nargs='+',
        help='List of versions, e.g. `6.1.2`')
    version_g.add_argument(
        '--existing',
        type=str,
        metavar='HOST:ILP_PORT:HTTP_PORT',
        help=('Test against existing running instance. ' +
              'e.g. `localhost:9009:9000`'))
    list_p = sub_p.add_parser('list', help='List latest -n releases.')
    list_p.set_defaults(command='list')
    list_p.add_argument('-n', type=int, default=30, help='number of releases')
    return parser.parse_known_args()


def list(args):
    print('List of releases:')
    for vers, _ in list_questdb_releases(args.n or 1):
        print(f'    {vers}')


def run_with_existing(args):
    global QDB_FIXTURE
    MockFixture = namedtuple(
        'MockFixture',
        ('host', 'line_tcp_port', 'http_server_port', 'version'))
    host, line_tcp_port, http_server_port = args.existing.split(':')
    QDB_FIXTURE = MockFixture(
        host,
        int(line_tcp_port),
        int(http_server_port),
        (999, 999, 999))
    unittest.main()


def run_with_fixtures(args):
    global QDB_FIXTURE
    global TLS_PROXY_FIXTURE
    versions = None
    versions_args = getattr(args, 'versions', None)
    if versions_args:
        versions = {
            version: (
                'https://github.com/questdb/questdb/releases/download/' +
                version +
                '/questdb-' +
                version +
                '-no-jre-bin.tar.gz')
            for version in versions_args}
    else:
        last_n = getattr(args, 'last_n', None) or 1
        versions = {
            vers: download_url
            for vers, download_url
            in list_questdb_releases(last_n)}
    for version, download_url in versions.items():
        questdb_dir = install_questdb(version, download_url)
        for auth in (False, True):
            QDB_FIXTURE = QuestDbFixture(questdb_dir, auth=auth)
            TLS_PROXY_FIXTURE = None
            try:
                QDB_FIXTURE.start()
                TLS_PROXY_FIXTURE = TlsProxyFixture(QDB_FIXTURE.line_tcp_port)
                TLS_PROXY_FIXTURE.start()

                test_prog = unittest.TestProgram(exit=False)
                if not test_prog.result.wasSuccessful():
                    sys.exit(1)
            finally:
                if TLS_PROXY_FIXTURE:
                    TLS_PROXY_FIXTURE.stop()
                QDB_FIXTURE.stop()


def run(args, show_help=False):
    if show_help:
        sys.argv.append('--help')
        unittest.main()
        return

    existing_instance = getattr(args, 'existing', None)
    if existing_instance:
        run_with_existing(args)
    else:
        run_with_fixtures(args)


def main():
    args, extra_args = parse_args()
    if args.command == 'list':
        list(args)
    else:
        # Repackage args for unittest's own arg parser.
        sys.argv[:] = sys.argv[:1] + extra_args
        show_help = getattr(args, 'unittest_help', False)
        run(args, show_help)


if __name__ == '__main__':
    main()
