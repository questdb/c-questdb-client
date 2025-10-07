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

import sys

sys.dont_write_bytecode = True
import os
import pathlib
import math
import datetime
import argparse
import unittest
import itertools
import numpy as np
import time
import questdb_line_sender as qls
import uuid
from fixture import (
    Project,
    QuestDbFixtureBase,
    QuestDbExternalFixture,
    QuestDbFixture,
    TlsProxyFixture,
    install_questdb,
    install_questdb_from_repo,
    list_questdb_releases,
    AUTH)
import subprocess
from collections import namedtuple

QDB_FIXTURE: QuestDbFixtureBase = None
TLS_PROXY_FIXTURE: TlsProxyFixture = None
BUILD_MODE = None

# The first QuestDB version that supports array types.
FIRST_ARRAYS_RELEASE = (8, 3, 3)


def retry_check_table(*args, **kwargs):
    return QDB_FIXTURE.retry_check_table(*args, **kwargs)


def ns_to_qdb_date(at_ts_ns):
    # We first need to match QuestDB's internal microsecond resolution.
    at_ts_us = int(at_ts_ns / 1000.0)
    at_ts_sec = at_ts_us / 1000000.0
    at_td = datetime.datetime.utcfromtimestamp(at_ts_sec)
    return at_td.isoformat() + 'Z'


# Valid keys, but not registered with the QuestDB fixture.
AUTH_UNRECOGNIZED = dict(
    username="testUser2",
    token="xiecEl-2zbg6aYCFbxDMVWaly9BlCTaEChvcxCH5BCk",
    token_x="-nSHz3evuPl-rGLIlbIZjwOJeWao0rbk53Cll6XEgak",
    token_y="9iYksF4L5mfmArupv0CMoyVAWjQ4gNIoupdg6N5noG8")

# Bad malformed key
AUTH_MALFORMED1 = dict(
    username="testUser3",
    token="xiecEl-zzbg6aYCFbxDMVWaly9BlCTaEChvcxCH5BCk",
    token_x="-nSHz3evuPl-rGLIlbIZjwOJeWao0rbk53Cll6XEgak",
    token_y="9iYksF4L6mfmArupv0CMoyVAWjQ4gNIoupdg6N5noG8")

# Another malformed key where the keys invalid base 64.
AUTH_MALFORMED2 = dict(
    username="testUser4",
    token="xiecEl-zzbg6aYCFbxDMVWaly9BlCTaECH5BCk",
    token_x="-nSHz3evuPl-rGLIlbIZjwOJeWao0rbk5XEgak",
    token_y="9iYksF4L6mfmArupv0CMoyVAWjQ4gNIou5noG8")

# All the keys are valid, but the username is wrong.
AUTH_MALFORMED3 = dict(
    username="wrongUser",
    token=AUTH['token'],
    token_x=AUTH['token_x'],
    token_y=AUTH['token_y'])


class TestSender(unittest.TestCase):
    def _mk_linesender(self):
        # N.B.: We never connect with TLS here.
        kwargs = AUTH if QDB_FIXTURE.auth else {}
        if QDB_FIXTURE.protocol_version:
            kwargs["protocol_version"] = QDB_FIXTURE.protocol_version
        return qls.Sender(
            BUILD_MODE,
            qls.Protocol.HTTP if QDB_FIXTURE.http else qls.Protocol.TCP,
            QDB_FIXTURE.host,
            QDB_FIXTURE.http_server_port if QDB_FIXTURE.http else QDB_FIXTURE.line_tcp_port,
            **kwargs)

    @property
    def expected_protocol_version(self) -> qls.ProtocolVersion:
        """The protocol version that we expect to be handling."""
        if QDB_FIXTURE.protocol_version is None:
            if not QDB_FIXTURE.http:
                return qls.ProtocolVersion.V1

            if QDB_FIXTURE.version >= FIRST_ARRAYS_RELEASE:
                return qls.ProtocolVersion.V2

            return qls.ProtocolVersion.V1

        return QDB_FIXTURE.protocol_version

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

    def setUp(self):
        test_name = self.id()
        QDB_FIXTURE.http_sql_query(f'select * from long_sequence(1) -- >>>>>>>>> BEGIN PYTHON UNIT TEST: {test_name}')

    def tearDown(self):
        test_name = self.id()
        QDB_FIXTURE.http_sql_query(f'select * from long_sequence(1) -- <<<<<<<<< END PYTHON UNIT TEST: {test_name}')

    def test_default_max_name_len(self):
        with self._mk_linesender() as sender:
            self.assertEqual(sender.max_name_len, 127)

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
            {'name': 'name_e', 'type': 'VARCHAR'},
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
            (sender
             .table(table_name)
             .symbol('a', 'B')
             .at_now())
            pending = sender.buffer.peek()

        resp = retry_check_table(table_name, log_ctx=pending, min_rows=2)
        exp_columns = [
            {'name': 'a', 'type': 'SYMBOL'},
            {'name': 'timestamp', 'type': 'TIMESTAMP'}]
        self.assertEqual(resp['columns'], exp_columns)

        exp_dataset = [['A'], ['B']]  # Comparison excludes timestamp column.
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
            {'name': 'a', 'type': 'VARCHAR'},
            {'name': 'b', 'type': 'VARCHAR'},
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
             .column('a', 1)  # LONG
             .at_now())
            (sender
             .table(table_name)
             .symbol('a', 'B')  # SYMBOL
             .at_now())

            pending = sender.buffer.peek()

            try:
                sender.flush()
            except qls.SenderError as e:
                if not QDB_FIXTURE.http:
                    raise e
                self.assertIn('Could not flush buffer', str(e))
                self.assertIn('cast error from', str(e))
                self.assertIn('LONG', str(e))
                self.assertIn('error in line 2', str(e))

        if QDB_FIXTURE.http:
            # If HTTP, the error should cause the whole batch to be ignored.
            # We assert that the table is empty.
            with self.assertRaises(TimeoutError):
                retry_check_table(table_name, timeout_sec=0.25, log=False)
        else:
            # We only ever get the first row back.
            resp = retry_check_table(table_name, log_ctx=pending)
            exp_columns = [
                {'name': 'a', 'type': 'LONG'},
                {'name': 'timestamp', 'type': 'TIMESTAMP'}]
            self.assertEqual(resp['columns'], exp_columns)

            exp_dataset = [[1]]  # Comparison excludes timestamp column.
            scrubbed_dataset = [row[:-1] for row in resp['dataset']]
            self.assertEqual(scrubbed_dataset, exp_dataset)

            # The second one is dropped and will not appear in results.
            with self.assertRaises(TimeoutError):
                retry_check_table(table_name, min_rows=2, timeout_sec=0.25, log=False)

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
                    
    def test_micros_at(self):
        if QDB_FIXTURE.version <= (6, 0, 7, 1):
            self.skipTest('No support for user-provided timestamps.')
            return
        table_name = uuid.uuid4().hex
        at_ts_ns = 1647357688714369403
        at_ts_us = at_ts_ns // 1000
        pending = None
        with self._mk_linesender() as sender:
            (sender
             .table(table_name)
             .symbol('a', 'A')
             .at_micros(at_ts_us))
            pending = sender.buffer.peek()
        resp = retry_check_table(table_name, log_ctx=pending)
        exp_dataset = [['A', ns_to_qdb_date(at_ts_ns)]]
        self.assertEqual(resp['dataset'], exp_dataset)

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
            float("nan"),  # Converted to `None`.
            float("inf"),  # Converted to `None`.
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

    def test_f64_arr_column(self):
        if self.expected_protocol_version < qls.ProtocolVersion.V2:
            self.skipTest('communicating over old protocol which does not support arrays')

        table_name = uuid.uuid4().hex
        array1 = np.array(
            [
                [[1.1, 2.2], [3.3, 4.4]],
                [[5.5, 6.6], [7.7, 8.8]]
            ],
            dtype=np.float64
        )
        array2 = array1.T
        array3 = array1[::-1, ::-1]

        with self._mk_linesender() as sender:
            (sender
             .table(table_name)
             .column_f64_arr('f64_arr1', array1)
             .column_f64_arr('f64_arr2', array2)
             .column_f64_arr('f64_arr3', array3)
             .at_now())

        resp = retry_check_table(table_name)
        exp_columns = [{'dim': 3, 'elemType': 'DOUBLE', 'name': 'f64_arr1', 'type': 'ARRAY'},
                       {'dim': 3, 'elemType': 'DOUBLE', 'name': 'f64_arr2', 'type': 'ARRAY'},
                       {'dim': 3, 'elemType': 'DOUBLE', 'name': 'f64_arr3', 'type': 'ARRAY'},
                       {'name': 'timestamp', 'type': 'TIMESTAMP'}]
        self.assertEqual(resp['columns'], exp_columns)
        expected_data = [[[[[1.1, 2.2], [3.3, 4.4]], [[5.5, 6.6], [7.7, 8.8]]],
                          [[[1.1, 5.5], [3.3, 7.7]], [[2.2, 6.6], [4.4, 8.8]]],
                          [[[7.7, 8.8], [5.5, 6.6]], [[3.3, 4.4], [1.1, 2.2]]]]]
        scrubbed_data = [row[:-1] for row in resp['dataset']]
        self.assertEqual(scrubbed_data, expected_data)

    def test_f64_arr_empty(self):
        if self.expected_protocol_version < qls.ProtocolVersion.V2:
            self.skipTest('communicating over old protocol which does not support arrays')

        table_name = uuid.uuid4().hex
        empty_array = np.array([], dtype=np.float64).reshape(0, 0, 0)
        with self._mk_linesender() as sender:
            (sender.table(table_name)
             .column_f64_arr('empty', empty_array)
             .at_now())

        resp = retry_check_table(table_name)
        exp_columns = [{'dim': 3, 'elemType': 'DOUBLE', 'name': 'empty', 'type': 'ARRAY'},
                       {'name': 'timestamp', 'type': 'TIMESTAMP'}]
        self.assertEqual(exp_columns, resp['columns'])
        self.assertEqual(resp['dataset'][0][0], [])

    def test_f64_arr_non_contiguous(self):
        if self.expected_protocol_version < qls.ProtocolVersion.V2:
            self.skipTest('communicating over old protocol which does not support arrays')

        table_name = uuid.uuid4().hex
        array = np.array([[1.1, 2.2], [3.3, 4.4]], dtype=np.float64)[:, ::2]
        with self._mk_linesender() as sender:
            (sender.table(table_name)
             .column_f64_arr('non_contiguous', array)
             .at_now())

        resp = retry_check_table(table_name)
        exp_columns = [{'dim': 2, 'elemType': 'DOUBLE', 'name': 'non_contiguous', 'type': 'ARRAY'},
                       {'name': 'timestamp', 'type': 'TIMESTAMP'}]
        self.assertEqual(exp_columns, resp['columns'])
        self.assertEqual(resp['dataset'][0][0], [[1.1], [3.3]])

    def test_f64_arr_zero_dimensional(self):
        if self.expected_protocol_version < qls.ProtocolVersion.V2:
            self.skipTest('communicating over old protocol which does not support arrays')

        table_name = uuid.uuid4().hex
        array = np.array(42.0, dtype=np.float64)
        try:
            with self._mk_linesender() as sender:
                (sender.table(table_name)
                 .column_f64_arr('scalar', array)
                 .at_now())
        except qls.SenderError as e:
            self.assertIn('Zero-dimensional arrays are not supported', str(e))

    def test_f64_arr_wrong_datatype(self):
        if self.expected_protocol_version < qls.ProtocolVersion.V2:
            self.skipTest('communicating over old protocol which does not support arrays')

        table_name = uuid.uuid4().hex
        array = np.array([1, 2], dtype=np.int32)
        try:
            with self._mk_linesender() as sender:
                (sender.table(table_name)
                 .column_f64_arr('wrong', array)
                 .at_now())
        except ValueError as e:
            self.assertIn('expect float64 array', str(e))

    def test_f64_arr_mix_dims(self):
        if self.expected_protocol_version < qls.ProtocolVersion.V2:
            self.skipTest('communicating over old protocol which does not support arrays')

        array_2d = np.array([[1.1, 2.2], [3.3, 4.4]], dtype=np.float64)
        array_1d = np.array([1.1], dtype=np.float64)
        table_name = uuid.uuid4().hex
        try:
            with self._mk_linesender() as sender:
                (sender.table(table_name)
                 .column_f64_arr('array', array_2d)
                 .at_now()
                 )
                (sender.table(table_name)
                 .column_f64_arr('array', array_1d)
                 .at_now()
                 )
        except qls.SenderError as e:
            self.assertIn('cast error from protocol type: DOUBLE[] to column type: DOUBLE[][]', str(e))

    def test_f64_arr_dims_length_overflow(self):
        if self.expected_protocol_version < qls.ProtocolVersion.V2:
            self.skipTest('communicating over old protocol which does not support arrays')

        table_name = uuid.uuid4().hex
        array = np.empty((1 << 29, 0), dtype=np.float64)
        try:
            with self._mk_linesender() as sender:
                (sender.table(table_name)
                 .column_f64_arr('array', array)
                 .at_now())
        except qls.SenderError as e:
            self.assertIn('dimension length out of range', str(e))

    def test_f64_arr_max_dims(self):
        if self.expected_protocol_version < qls.ProtocolVersion.V2:
            self.skipTest('communicating over old protocol which does not support arrays')

        table_name = uuid.uuid4().hex
        dims = (1,) * 33
        array = np.empty(dims, dtype=np.float64)
        try:
            with self._mk_linesender() as sender:
                (sender.table(table_name)
                 .column_f64_arr('array', array)
                 .at_now())
        except qls.SenderError as e:
            self.assertIn('Array dimension mismatch: expected at most 32 dimensions, but got 33', str(e))

    def test_protocol_version_v1(self):
        if self.expected_protocol_version >= qls.ProtocolVersion.V2:
            self.skipTest('we are only validating the older protocol here')
        if QDB_FIXTURE.version <= (6, 1, 2):
            self.skipTest('Float issues support')
        numbers = [
            0.0,
            -0.0,
            1.0,
            -1.0]

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

    def test_protocol_version_v1_array_unsupported(self):
        if self.expected_protocol_version >= qls.ProtocolVersion.V2:
            self.skipTest('communicating over a newer protocl that DOES support arrays')

        array1 = np.array(
            [
                [[1.1, 2.2], [3.3, 4.4]],
                [[5.5, 6.6], [7.7, 8.8]]
            ],
            dtype=np.float64
        )
        table_name = uuid.uuid4().hex
        try:
            with self._mk_linesender() as sender:
                sender.table(table_name)
                sender.column_f64_arr('f64_arr1', array1)
                sender.at_now()
        except qls.SenderError as e:
            self.assertIn('Protocol version v1 does not support array datatype', str(e))

    def _test_example(self, bin_name, table_name, tls=False):
        if BUILD_MODE != qls.BuildMode.API:
            self.skipTest('BuildMode.API-only test')
        if tls and not QDB_FIXTURE.auth:
            self.skipTest('No auth')
        # Call the example program.
        proj = Project()
        ext = '.exe' if sys.platform == 'win32' else ''
        try:
            bin_path = next(proj.build_dir.glob(f'**/{bin_name}{ext}'))
        except StopIteration:
            raise RuntimeError(f'Could not find {bin_name}{ext} in {proj.build_dir}')
        port = QDB_FIXTURE.http_server_port if QDB_FIXTURE.http else QDB_FIXTURE.line_tcp_port
        args = [str(bin_path)]
        if tls:
            ca_path = proj.tls_certs_dir / 'server_rootCA.pem'
            args.append(str(ca_path))
            port = TLS_PROXY_FIXTURE.listen_port
            args.extend(['localhost', str(port)])
        else:
            args.extend(['127.0.0.1', str(port)])
        subprocess.check_call(args, cwd=bin_path.parent)

        # Check inserted data.
        resp = retry_check_table(table_name)
        exp_columns = [
            {'name': 'symbol', 'type': 'SYMBOL'},
            {'name': 'side', 'type': 'SYMBOL'},
            {'name': 'price', 'type': 'DOUBLE'},
            {'name': 'amount', 'type': 'DOUBLE'},
            {'name': 'timestamp', 'type': 'TIMESTAMP'}]
        self.assertEqual(resp['columns'], exp_columns)

        exp_dataset = [['ETH-USD',
                        'sell',
                        2615.54,
                        0.00044]]
        # Comparison excludes timestamp column.
        scrubbed_dataset = [row[:-1] for row in resp['dataset']]
        self.assertEqual(scrubbed_dataset, exp_dataset)

    def test_c_example(self):
        suffix = '_auth' if QDB_FIXTURE.auth else ''
        suffix += '_http' if QDB_FIXTURE.http else ''
        self._test_example(
            f'line_sender_c_example{suffix}',
            f'c_trades{suffix}')

    def test_cpp_example(self):
        suffix = '_auth' if QDB_FIXTURE.auth else ''
        suffix += '_http' if QDB_FIXTURE.http else ''
        self._test_example(
            f'line_sender_cpp_example{suffix}',
            f'cpp_trades{suffix}')

    def test_c_tls_example(self):
        self._test_example(
            'line_sender_c_example_tls_ca',
            'c_trades_tls_ca',
            tls=True)

    def test_cpp_tls_example(self):
        self._test_example(
            'line_sender_cpp_example_tls_ca',
            'cpp_trades_tls_ca',
            tls=True)

    def test_cpp_array_example(self):
        self._test_array_example(
            'line_sender_cpp_example_array_byte_strides',
            'cpp_market_orders_byte_strides', )
        self._test_array_example(
            'line_sender_cpp_example_array_elem_strides',
            'cpp_market_orders_elem_strides', )
        self._test_array_example(
            'line_sender_cpp_example_array_c_major',
            'cpp_market_orders_c_major', )

    def test_c_array_example(self):
        self._test_array_example(
            'line_sender_c_example_array_byte_strides',
            'market_orders_byte_strides', )
        self._test_array_example(
            'line_sender_c_example_array_elem_strides',
            'market_orders_elem_strides', )
        self._test_array_example(
            'line_sender_c_example_array_c_major',
            'market_orders_c_major', )

    def _test_array_example(self, bin_name, table_name):
        if self.expected_protocol_version < qls.ProtocolVersion.V2:
            self.skipTest('communicating over old protocol which does not support arrays')
        if QDB_FIXTURE.http:
            self.skipTest('TCP-only test')
        if BUILD_MODE != qls.BuildMode.API:
            self.skipTest('BuildMode.API-only test')
        if QDB_FIXTURE.auth:
            self.skipTest('auth')

        proj = Project()
        ext = '.exe' if sys.platform == 'win32' else ''
        try:
            bin_path = next(proj.build_dir.glob(f'**/{bin_name}{ext}'))
        except StopIteration:
            raise RuntimeError(f'Could not find {bin_name}{ext} in {proj.build_dir}')
        port = QDB_FIXTURE.line_tcp_port
        args = [str(bin_path)]
        args.extend(['127.0.0.1', str(port)])
        subprocess.check_call(args, cwd=bin_path.parent)
        resp = retry_check_table(table_name)
        exp_columns = [
            {'name': 'symbol', 'type': 'SYMBOL'},
            {'dim': 3, 'elemType': 'DOUBLE', 'name': 'order_book', 'type': 'ARRAY'},
            {'name': 'timestamp', 'type': 'TIMESTAMP'}]
        self.assertEqual(resp['columns'], exp_columns)
        exp_dataset = [['BTC-USD',
                        [[[48123.5, 2.4], [48124.0, 1.8], [48124.5, 0.9]],
                         [[48122.5, 3.1], [48122.0, 2.7], [48121.5, 4.3]]]]]
        scrubbed_dataset = [row[:-1] for row in resp['dataset']]
        self.assertEqual(scrubbed_dataset, exp_dataset)

    def test_opposite_auth(self):
        """
        We simulate incorrectly connecting either:
          * An authenticating client to a non-authenticating DB instance.
          * Or a non-authenticating client to an authenticating DB instance.
        """
        if QDB_FIXTURE.http:
            self.skipTest('TCP-only test')
        if BUILD_MODE != qls.BuildMode.API:
            self.skipTest('BuildMode.API-only test')
        auth = {} if QDB_FIXTURE.auth else AUTH
        sender = qls.Sender(
            BUILD_MODE,
            qls.Protocol.TCP,
            QDB_FIXTURE.host,
            QDB_FIXTURE.line_tcp_port,
            **auth)
        if auth:
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
        if QDB_FIXTURE.http:
            self.skipTest('TCP-only test')

        if not QDB_FIXTURE.auth:
            self.skipTest('No auth')

        if BUILD_MODE != qls.BuildMode.API:
            self.skipTest('BuildMode.API-only test')

        sender = qls.Sender(
            BUILD_MODE,
            qls.Protocol.TCP,
            QDB_FIXTURE.host,
            QDB_FIXTURE.line_tcp_port,
            **AUTH_UNRECOGNIZED)

        with sender:
            self._expect_eventual_disconnect(sender)

    def test_malformed_auth1(self):
        if QDB_FIXTURE.http:
            self.skipTest('TCP-only test')

        if not QDB_FIXTURE.auth:
            self.skipTest('No auth')

        if BUILD_MODE != qls.BuildMode.API:
            self.skipTest('BuildMode.API-only test')

        sender = qls.Sender(
            BUILD_MODE,
            qls.Protocol.TCP,
            QDB_FIXTURE.host,
            QDB_FIXTURE.line_tcp_port,
            **AUTH_MALFORMED1)

        with self.assertRaisesRegex(
                qls.SenderError,
                r'Misconfigured ILP authentication keys: .*. Hint: Check the keys for a possible typo.'):
            sender.connect()

    def test_malformed_auth2(self):
        if QDB_FIXTURE.http:
            self.skipTest('TCP-only test')

        if not QDB_FIXTURE.auth:
            self.skipTest('No auth')

        if BUILD_MODE != qls.BuildMode.API:
            self.skipTest('BuildMode.API-only test')

        sender = qls.Sender(
            BUILD_MODE,
            qls.Protocol.TCP,
            QDB_FIXTURE.host,
            QDB_FIXTURE.line_tcp_port,
            **AUTH_MALFORMED2)

        with self.assertRaisesRegex(
                qls.SenderError,
                r'.*invalid Base64.*'):
            sender.connect()

    def test_malformed_auth3(self):
        if QDB_FIXTURE.http:
            self.skipTest('TCP-only test')

        if not QDB_FIXTURE.auth:
            self.skipTest('No auth')

        if BUILD_MODE != qls.BuildMode.API:
            self.skipTest('BuildMode.API-only test')

        sender = qls.Sender(
            BUILD_MODE,
            qls.Protocol.TCP,
            QDB_FIXTURE.host,
            QDB_FIXTURE.line_tcp_port,
            **AUTH_MALFORMED3)

        with sender:
            self._expect_eventual_disconnect(sender)

    def test_tls_insecure_skip_verify(self):
        if BUILD_MODE != qls.BuildMode.API:
            self.skipTest('BuildMode.API-only test')
        if QDB_FIXTURE.protocol_version != sorted(list(qls.ProtocolVersion))[-1]:
            self.skipTest('Skipping tls test for non-latest protocol version')
        protocol = qls.Protocol.HTTPS if QDB_FIXTURE.http else qls.Protocol.TCPS
        auth = AUTH if QDB_FIXTURE.auth else {}
        sender = qls.Sender(
            BUILD_MODE,
            protocol,
            QDB_FIXTURE.host,
            TLS_PROXY_FIXTURE.listen_port,
            tls_verify=False,
            **auth)
        self._test_single_symbol_impl(sender)

    def test_tls_roots(self):
        if BUILD_MODE != qls.BuildMode.API:
            self.skipTest('BuildMode.API-only test')
        if QDB_FIXTURE.protocol_version != sorted(list(qls.ProtocolVersion))[-1]:
            self.skipTest('Skipping tls test for non-latest protocol version')
        protocol = qls.Protocol.HTTPS if QDB_FIXTURE.http else qls.Protocol.TCPS
        auth = auth = AUTH if QDB_FIXTURE.auth else {}
        sender = qls.Sender(
            BUILD_MODE,
            protocol,
            QDB_FIXTURE.host,
            TLS_PROXY_FIXTURE.listen_port,
            **auth,
            tls_roots=str(Project().tls_certs_dir / 'server_rootCA.pem'))
        self._test_single_symbol_impl(sender)

    def _test_tls_ca(self, tls_ca):
        if BUILD_MODE != qls.BuildMode.API:
            self.skipTest('BuildMode.API-only test')
        if QDB_FIXTURE.protocol_version != sorted(list(qls.ProtocolVersion))[-1]:
            self.skipTest('Skipping tls test for non-latest protocol version')
        protocol = qls.Protocol.HTTPS if QDB_FIXTURE.http else qls.Protocol.TCPS
        prev_ssl_cert_file = os.environ.get('SSL_CERT_FILE')
        try:
            os.environ['SSL_CERT_FILE'] = str(
                Project().tls_certs_dir / 'server_rootCA.pem')
            auth = auth = AUTH if QDB_FIXTURE.auth else {}
            sender = qls.Sender(
                BUILD_MODE,
                protocol,
                QDB_FIXTURE.host,
                TLS_PROXY_FIXTURE.listen_port,
                tls_ca=tls_ca,
                **auth)
            self._test_single_symbol_impl(sender)
        finally:
            if prev_ssl_cert_file:
                os.environ['SSL_CERT_FILE'] = prev_ssl_cert_file
            else:
                del os.environ['SSL_CERT_FILE']

    def test_tls_ca_os_roots(self):
        self._test_tls_ca(qls.CertificateAuthority.OS_ROOTS)

    def test_tls_ca_webpki_and_os_roots(self):
        self._test_tls_ca(qls.CertificateAuthority.WEBPKI_AND_OS_ROOTS)

    def test_http_transactions(self):
        if not QDB_FIXTURE.http:
            self.skipTest('HTTP-only test')
        if QDB_FIXTURE.version <= (7, 3, 7):
            self.skipTest('No ILP/HTTP support')
        table_name = uuid.uuid4().hex
        with self._mk_linesender() as sender:
            sender.table(table_name).column('col1', 'v1').at(time.time_ns())
            sender.table(table_name).column('col1', 'v2').at(time.time_ns())
            sender.table(table_name).column('col1', 42.5).at(time.time_ns())

            try:
                sender.flush(transactional=True)
            except qls.SenderError as e:
                if not QDB_FIXTURE.http:
                    raise e
                self.assertIn('Could not flush buffer', str(e))
                self.assertIn('cast error from', str(e))
                self.assertIn('VARCHAR', str(e))
                self.assertIn('error in line 3', str(e))

        with self.assertRaises(TimeoutError):
            retry_check_table(table_name, timeout_sec=0.25, log=False)

    def test_tcp_transactions(self):
        if QDB_FIXTURE.http:
            self.skipTest('TCP-only test')
        if QDB_FIXTURE.version <= (7, 3, 7):
            self.skipTest('No ILP/HTTP support')
        buf = qls.Buffer(self.expected_protocol_version)
        buf.table('t1').column('c1', 'v1').at(time.time_ns())
        with self.assertRaisesRegex(qls.SenderError, r'.*Transactional .* not supported.*'):
            with self._mk_linesender() as sender:
                sender.flush(buf, transactional=True)

    def test_bad_env_var(self):
        if not BUILD_MODE == qls.BuildMode.API:
            self.skipTest('BuildMode.API-only test')
        env_var = 'QDB_CLIENT_CONF'
        if env_var in os.environ:
            del os.environ[env_var]
        with self.assertRaisesRegex(qls.SenderError, r'.*Environment variable QDB_CLIENT_CONF not set.*'):
            qls._error_wrapped_call(qls._DLL.line_sender_from_env)

    def test_manifest_yaml(self):
        # Check the manifest file can be read as yaml.
        try:
            import yaml
        except ImportError:
            self.skipTest('Python version does not support yaml')
        proj = Project()
        manifest_path = proj.root_dir / 'examples.manifest.yaml'
        with open(manifest_path, 'r') as f:
            yaml.safe_load(f)


def parse_args():
    parser = argparse.ArgumentParser('Run system tests.')
    sub_p = parser.add_subparsers(dest='command')
    run_p = sub_p.add_parser('run', help='Run tests')
    run_p.add_argument(
        '--unittest-help',
        action='store_true',
        help='Show unittest --help')
    run_p.add_argument(
        '--profile',
        action='store_true',
        help='Run with cProfile')
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
    version_g.add_argument(
        '--repo',
        type=str,
        metavar='PATH',
        help=('Test against existing jar from a ' +
              '`mvn install -DskipTests -P build-web-console`' +
              '-ed questdb repo such as `~/questdb/repos/questdb/`'))
    list_p = sub_p.add_parser('list', help='List latest -n releases.')
    list_p.set_defaults(command='list')
    list_p.add_argument('-n', type=int, default=30, help='number of releases')
    return parser.parse_known_args()


def list_releases(args):
    print('List of releases:')
    for vers, _ in list_questdb_releases(args.n or 1):
        print(f'    {vers}')


def run_with_existing(args):
    global QDB_FIXTURE
    host, line_tcp_port, http_server_port = args.existing.split(':')
    QDB_FIXTURE = QuestDbExternalFixture(
        host,
        int(line_tcp_port),
        int(http_server_port),
        (999, 999, 999),
        True,
        False,
        qls.ProtocolVersion.V2
    )
    unittest.main()


def iter_versions(args):
    """
    Iterate target versions.
    Returns a generator of prepared questdb directories.
    Ensure that the DB is stopped after each use.
    """
    if getattr(args, 'repo', None):
        # A specific repo path was provided.
        repo = pathlib.Path(args.repo)
        yield install_questdb_from_repo(repo)
        return

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
        yield questdb_dir


def run_with_fixtures(args):
    global QDB_FIXTURE
    global TLS_PROXY_FIXTURE
    global BUILD_MODE

    latest_protocol = sorted(list(qls.ProtocolVersion))[-1]
    for questdb_dir, auth in itertools.product(iter_versions(args), (False, True)):
        QDB_FIXTURE = QuestDbFixture(
            questdb_dir,
            auth=auth)
        TLS_PROXY_FIXTURE = None
        try:
            sys.stderr.write(f'>>>> STARTING {questdb_dir} [auth={auth}] <<<<\n')
            QDB_FIXTURE.start()
            for http, protocol_version, build_mode in itertools.product(
                    (False, True),  # http
                    [None] + list(qls.ProtocolVersion),  # None is for `auto`
                    list(qls.BuildMode)):
                if (build_mode in (qls.BuildMode.API, qls.BuildMode.ENV)) and (protocol_version != latest_protocol):
                    continue
                if http and auth:
                    continue
                if auth and (protocol_version != latest_protocol):
                    continue
                sys.stderr.write(
                    f'>>>> Running tests [auth={auth}, http={http}, build_mode={build_mode}, protocol_version={protocol_version}]\n')
                # Read the version _after_ a first start so it can rely
                # on the live one from the `select build` query.
                BUILD_MODE = build_mode
                QDB_FIXTURE.http = http
                QDB_FIXTURE.protocol_version = protocol_version
                port_to_proxy = QDB_FIXTURE.http_server_port \
                    if http else QDB_FIXTURE.line_tcp_port
                TLS_PROXY_FIXTURE = TlsProxyFixture(port_to_proxy)
                TLS_PROXY_FIXTURE.start()
                try:
                    QDB_FIXTURE.drop_all_tables()
                    test_prog = unittest.TestProgram(exit=False)
                    if not test_prog.result.wasSuccessful():
                        sys.exit(1)
                finally:
                    if TLS_PROXY_FIXTURE:
                        TLS_PROXY_FIXTURE.stop()
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
        list_releases(args)
    else:
        profile = args.profile
        if profile:
            sys.argv.remove("--profile")
            import cProfile
            cProfile.run('main()', filename='profile.out')
            return
        # Repackage args for unittest's own arg parser.
        sys.argv[:] = sys.argv[:1] + extra_args
        show_help = getattr(args, 'unittest_help', False)
        run(args, show_help)


if __name__ == '__main__':
    main()
