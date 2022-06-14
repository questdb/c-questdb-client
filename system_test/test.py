#!/usr/bin/env python3

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

import math
import datetime
import argparse
import unittest
import questdb_line_sender as qls
import uuid
from fixture import (
    Project,
    QuestDbFixture,
    install_questdb,
    list_questdb_releases,
    retry)
import urllib.request
import urllib.parse
import urllib.error
import json
import subprocess
from collections import namedtuple


QDB_FIXTURE: QuestDbFixture = None


AUTH_CLIENT_KEYS = {
  "kty": "EC",
  "d": "5UjEMuA0Pj5pjK8a-fa24dyIf-Es5mYny3oE_Wmus48",  # PRIVATE_KEY
  "crv": "P-256",
  "kid": "testUser1",
  "x": "fLKYEaoEb9lrn3nkwLDA-M_xnuFOdSt9y0Z7_vWSHLU",  # PUBLIC_KEY.x
  "y": "Dt5tbS1dEDMSYfym3fgMv0B99szno-dFc1rYF9t0aac"   # PUBLIC_KEY.y
}


class QueryError(Exception):
    pass


def http_sql_query(sql_query):
    host, port = QDB_FIXTURE.host, QDB_FIXTURE.http_server_port
    url = (
        f'http://{host}:{port}/exec?' +
        urllib.parse.urlencode({'query': sql_query}))
    buf = None
    try:
        resp = urllib.request.urlopen(url, timeout=0.2)
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


def retry_check_table(table_name, min_rows=1, timeout_sec=5):
    def check_table():
        try:
            resp = http_sql_query(f"select * from '{table_name}'")
            if not resp.get('dataset'):
                return False
            elif len(resp['dataset']) < min_rows:
                return False
            return resp
        except QueryError:
            return None

    return retry(check_table, timeout_sec=timeout_sec)


def ns_to_qdb_date(at_ts_ns):
    # We first need to match QuestDB's internal microsecond resolution.
    at_ts_us = int(at_ts_ns / 1000.0)
    at_ts_sec = at_ts_us / 1000000.0
    at_td = datetime.datetime.fromtimestamp(at_ts_sec)
    return at_td.isoformat() + 'Z'


class TestLineSender(unittest.TestCase):
    def _mk_linesender(self):
        return qls.LineSender(
            QDB_FIXTURE.host,
            QDB_FIXTURE.line_tcp_port)

    def test_insert_three_rows(self):
        table_name = uuid.uuid4().hex
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

            sender.flush()

        resp = retry_check_table(table_name)
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
        with self._mk_linesender() as sender:
            (sender
                .table(table_name)
                .symbol('a', 'A')
                .symbol('a', 'B')
                .column('b', False)
                .column('b', 'C')
                .at_now())

        resp = retry_check_table(table_name)
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
        with self._mk_linesender() as sender:
            (sender
                .table(table_name)
                .symbol('a', 'A')
                .column('a', 'B')
                .at_now())

        resp = retry_check_table(table_name)
        exp_columns = [
            {'name': 'a', 'type': 'SYMBOL'},
            {'name': 'timestamp', 'type': 'TIMESTAMP'}]
        self.assertEqual(resp['columns'], exp_columns)

        exp_dataset = [['A']]  # Comparison excludes timestamp column.
        scrubbed_dataset = [row[:-1] for row in resp['dataset']]
        self.assertEqual(scrubbed_dataset, exp_dataset)

    def test_single_symbol(self):
        table_name = uuid.uuid4().hex
        with self._mk_linesender() as sender:
            (sender
                .table(table_name)
                .symbol('a', 'A')
                .at_now())

        resp = retry_check_table(table_name)
        exp_columns = [
            {'name': 'a', 'type': 'SYMBOL'},
            {'name': 'timestamp', 'type': 'TIMESTAMP'}]
        self.assertEqual(resp['columns'], exp_columns)

        exp_dataset = [['A']]  # Comparison excludes timestamp column.
        scrubbed_dataset = [row[:-1] for row in resp['dataset']]
        self.assertEqual(scrubbed_dataset, exp_dataset)

    def test_two_columns(self):
        table_name = uuid.uuid4().hex
        with self._mk_linesender() as sender:
            (sender
                .table(table_name)
                .column('a', 'A')
                .column('b', 'B')
                .at_now())

        resp = retry_check_table(table_name)
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
        with self._mk_linesender() as sender:
            (sender
                .table(table_name)
                .symbol('a', 'A')  # SYMBOL
                .at_now())
            (sender
                .table(table_name)
                .column('a', 'B')  # STRING
                .at_now())

        # We only ever get the first row back.
        resp = retry_check_table(table_name)
        exp_columns = [
            {'name': 'a', 'type': 'SYMBOL'},
            {'name': 'timestamp', 'type': 'TIMESTAMP'}]
        self.assertEqual(resp['columns'], exp_columns)

        exp_dataset = [['A']]  # Comparison excludes timestamp column.
        scrubbed_dataset = [row[:-1] for row in resp['dataset']]
        self.assertEqual(scrubbed_dataset, exp_dataset)

        # The second one is dropped and will not appear in results.
        with self.assertRaises(TimeoutError):
            retry_check_table(table_name, min_rows=2, timeout_sec=1)

    def test_at(self):
        if QDB_FIXTURE.version <= (6, 0, 7, 1):
            self.skipTest('No support for user-provided timestamps.')
            return
        table_name = uuid.uuid4().hex
        at_ts_ns = 1647357688714369403
        with qls.LineSender('localhost', QDB_FIXTURE.line_tcp_port) as sender:
            (sender
                .table(table_name)
                .symbol('a', 'A')
                .at(at_ts_ns))

        resp = retry_check_table(table_name)
        exp_dataset = [['A', ns_to_qdb_date(at_ts_ns)]]
        self.assertEqual(resp['dataset'], exp_dataset)

    def test_bad_at(self):
        if QDB_FIXTURE.version <= (6, 0, 7, 1):
            self.skipTest('No support for user-provided timestamps.')
            return
        table_name = uuid.uuid4().hex
        at_ts_ns1 = 1648032959100000000
        at_ts_ns2 = 1648032958100000000  # A second before `at_ts_ns1`.
        with self._mk_linesender() as sender:
            (sender
                .table(table_name)
                .symbol('a', 'A')
                .at(at_ts_ns1))
            (sender
                .table(table_name)
                .symbol('a', 'B')
                .at(at_ts_ns2))

        resp = retry_check_table(table_name)
        exp_dataset = [['A', ns_to_qdb_date(at_ts_ns1)]]
        self.assertEqual(resp['dataset'], exp_dataset)

        # The second time stamp is dropped and will not appear in results.
        with self.assertRaises(TimeoutError):
            retry_check_table(table_name, min_rows=2, timeout_sec=1)


    def test_underscores(self):
        table_name = f'_{uuid.uuid4().hex}_'
        with self._mk_linesender() as sender:
            (sender
                .table(table_name)
                .symbol('_a_b_c_', 'A')
                .column('_d_e_f_', True)
                .at_now())

        resp = retry_check_table(table_name)
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
        with self._mk_linesender() as sender:
            sender.table(table_name)
            sender.symbol(smilie, smilie)
            # for num in range(1, 32):
            #     char = chr(num)
            #     sender.column(char, char)
            sender.at_now()

        resp = retry_check_table(table_name)
        exp_columns = [
            {'name': smilie, 'type': 'SYMBOL'},
            {'name': 'timestamp', 'type': 'TIMESTAMP'}]
        self.assertEqual(resp['columns'], exp_columns)

        exp_dataset = [[smilie]]  # Comparison excludes timestamp column.
        scrubbed_dataset = [row[:-1] for row in resp['dataset']]
        self.assertEqual(scrubbed_dataset, exp_dataset)

    def test_floats(self):
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
        with self._mk_linesender() as sender:
            for num in numbers:
                sender.table(table_name)
                sender.column('n', num)
                sender.at_now()

        resp = retry_check_table(table_name, len(numbers))
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

    def _test_example(self, bin_name, table_name):
        # Call the example program.
        proj = Project()
        ext = '.exe' if sys.platform == 'win32' else ''
        bin_path = next(proj.build_dir.glob(f'**/{bin_name}{ext}'))
        args = [str(bin_path), "localhost", str(QDB_FIXTURE.line_tcp_port)]
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
            'Ranjit Singh']]  # Comparison excludes timestamp column.
        scrubbed_dataset = [row[:-1] for row in resp['dataset']]
        self.assertEqual(scrubbed_dataset, exp_dataset)

    def test_c_example(self):
        self._test_example('line_sender_c_example', 'c_cars')

    def test_cpp_example(self):
        self._test_example('line_sender_cpp_example', 'cpp_cars')


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

    last_n = 1
    if getattr(args, 'last_n', None):
        last_n = args.last_n
    elif getattr(args, 'versions', None):
        last_n = 30  # Hack, can't test older releases.
    versions = {
        vers: download_url
        for vers, download_url
        in list_questdb_releases(last_n)}
    versions_args = getattr(args, 'versions', None)
    if versions_args:
        versions = {
            vers: versions[vers]
            for vers in versions_args}

    for version, download_url in versions.items():
        questdb_dir = install_questdb(version, download_url)
        for auth in (False, True):
            QDB_FIXTURE = QuestDbFixture(questdb_dir, auth=auth)
            try:
                QDB_FIXTURE.start()
                test_prog = unittest.TestProgram(exit=False)
                if not test_prog.result.wasSuccessful():
                    sys.exit(1)
            finally:
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
        # Repackage args for unittests own arg parser.
        sys.argv[:] = sys.argv[:1] + extra_args
        show_help = getattr(args, 'unittest_help', False)
        run(args, show_help)


if __name__ == '__main__':
    main()
