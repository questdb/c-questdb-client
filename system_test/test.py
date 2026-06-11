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
import inspect
import numpy as np
import time
import tempfile
import socket
import threading
import questdb_line_sender as qls
import qwp_ws_fuzz
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
    AUTH,
    HTTP_AUTH)
import subprocess
from decimal import Decimal

QDB_FIXTURE: QuestDbFixtureBase = None
TLS_PROXY_FIXTURE: TlsProxyFixture = None
BUILD_MODE = None
QWP_WS_SMOKE_TLS = False

SUITE_MATRIX = 'matrix'
SUITE_QWP_WS_SMOKE = 'qwp_ws_smoke'
SUITE_QWP_WS_PROTOCOL = 'qwp_ws_protocol'
SUITE_QWP_WS_RESTART = 'qwp_ws_restart'
SUITE_QWP_WS_FUZZ = 'qwp_ws_fuzz'
QWP_WS_STATUS_SCHEMA_MISMATCH = 0x03

# The first QuestDB version that supports array types.
FIRST_ARRAYS_RELEASE = (8, 3, 3)
DECIMAL_RELEASE = (9, 2, 0)
QWP_MIN_RELEASE = (9, 4, 3)
QWP_DECIMAL256_POSITIVE_OVERFLOW = Decimal(
    "57896044618658097711785492504343953926634992332820282019728792003956564819968")
QWP_DECIMAL256_SIGNED_RESCALE_OVERFLOW_BASE = Decimal(
    "5789604461865809771178549250434395392663499233282028201972879200395656481997")


def retry_check_table(*args, **kwargs):
    return QDB_FIXTURE.retry_check_table(*args, **kwargs)

def sql_query(query: str):
    return QDB_FIXTURE.http_sql_query(query)


class _ParsedUnittestProgram(unittest.TestProgram):
    def runTests(self):
        pass


def _parse_unittest_args():
    return _ParsedUnittestProgram(
        module=sys.modules[__name__],
        argv=sys.argv,
        exit=False)


def _load_requested_suite():
    return _parse_unittest_args().test


def _iter_tests(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from _iter_tests(test)
        else:
            yield test


def _suite_kind(test):
    class_name = test.__class__.__name__
    if class_name == 'TestQwpWsSender':
        return SUITE_QWP_WS_SMOKE
    if class_name == 'TestQwpWsProtocol':
        return SUITE_QWP_WS_PROTOCOL
    if class_name == 'TestQwpWsRestart':
        return SUITE_QWP_WS_RESTART
    if class_name == 'TestQwpWsFuzz':
        return SUITE_QWP_WS_FUZZ
    return SUITE_MATRIX


def _select_tests(suite_kind):
    suite = unittest.TestSuite()
    for test in _iter_tests(_load_requested_suite()):
        if _suite_kind(test) == suite_kind:
            suite.addTest(test)
    return suite


def _run_selected_tests(suite_kind):
    suite = _select_tests(suite_kind)
    if suite.countTestCases() == 0:
        return True
    program = _parse_unittest_args()
    if program.catchbreak:
        unittest.installHandler()

    runner_args = {
        'verbosity': program.verbosity,
        'failfast': program.failfast,
        'buffer': program.buffer,
        'warnings': program.warnings,
    }
    runner_params = inspect.signature(unittest.TextTestRunner).parameters
    if 'tb_locals' in runner_params:
        runner_args['tb_locals'] = getattr(program, 'tb_locals', False)
    if 'durations' in runner_params:
        runner_args['durations'] = getattr(program, 'durations', None)
    runner = unittest.TextTestRunner(**runner_args)
    return runner.run(suite).wasSuccessful()


def _read_exact(sock, byte_count, pending=b''):
    if len(pending) >= byte_count:
        return pending[:byte_count], pending[byte_count:]

    chunks = [pending] if pending else []
    remaining = byte_count - len(pending)
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError(
                f'unexpected EOF while reading {byte_count} bytes')
        chunks.append(chunk)
        remaining -= len(chunk)
    return b''.join(chunks), b''


def _read_until_headers(sock):
    data = bytearray()
    marker = b'\r\n\r\n'
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError('unexpected EOF while reading HTTP headers')
        data.extend(chunk)
    header_end = data.index(marker) + len(marker)
    return bytes(data[:header_end]), bytes(data[header_end:])


def _read_ws_frame(sock, pending=b''):
    raw_parts = []
    header, pending = _read_exact(sock, 2, pending)
    raw_parts.append(header)
    length = header[1] & 0x7f
    masked = (header[1] & 0x80) != 0
    if length == 126:
        length_bytes, pending = _read_exact(sock, 2, pending)
        raw_parts.append(length_bytes)
        length = int.from_bytes(length_bytes, 'big')
    elif length == 127:
        length_bytes, pending = _read_exact(sock, 8, pending)
        raw_parts.append(length_bytes)
        length = int.from_bytes(length_bytes, 'big')

    mask = b''
    if masked:
        mask, pending = _read_exact(sock, 4, pending)
        raw_parts.append(mask)
    payload, pending = _read_exact(sock, length, pending)
    raw_parts.append(payload)
    if masked:
        decoded_payload = bytes(byte ^ mask[index % 4]
                                for index, byte in enumerate(payload))
    else:
        decoded_payload = payload
    return b''.join(raw_parts), decoded_payload, pending


class QwpWsDropAckProxy:
    def __init__(self, target_host, target_port):
        self._target_host = target_host
        self._target_port = target_port
        self._listener = None
        self._thread = None
        self._error = None
        self.port = None

    def start(self):
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(('127.0.0.1', 0))
        self._listener.listen(1)
        self._listener.settimeout(10)
        self.port = self._listener.getsockname()[1]
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def close(self):
        if self._listener is not None:
            self._listener.close()
            self._listener = None

    def is_alive(self):
        return self._thread is not None and self._thread.is_alive()

    def join(self, timeout=10):
        self._thread.join(timeout)
        if self.is_alive():
            self.close()
            raise TimeoutError(
                'timed out waiting for QWP/WebSocket drop-frame proxy')
        if self._error is not None:
            raise self._error

    def _run(self):
        try:
            self._run_inner()
        except BaseException as e:
            self._error = e
        finally:
            self.close()

    def _run_inner(self):
        with self._listener:
            client, _ = self._listener.accept()
            self._listener = None
        with client:
            client.settimeout(10)
            with socket.create_connection(
                    (self._target_host, self._target_port),
                    timeout=10) as upstream:
                upstream.settimeout(10)
                request, pending_client = _read_until_headers(client)
                upstream.sendall(request)
                response, _ = _read_until_headers(upstream)
                status_line = response.split(b'\r\n', 1)[0]
                if b' 101 ' not in status_line:
                    raise RuntimeError(
                        f'expected WebSocket upgrade, got {status_line!r}')
                client.sendall(response)

                client_frame, payload, _ = _read_ws_frame(client, pending_client)
                if not payload.startswith(b'QWP1'):
                    raise RuntimeError(
                        'expected first WebSocket payload to be a QWP frame')
                upstream.sendall(client_frame)

                _, server_payload, _ = _read_ws_frame(upstream)
                if not server_payload:
                    raise RuntimeError('expected non-empty QWP server response')
                if server_payload[0] not in (0x00, 0x02):
                    raise RuntimeError(
                        f'expected QWP OK/ACK response, got status 0x{server_payload[0]:02x}')


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

    def _ns_to_qdb_date(self, at_ts_ns, exp_nanos: bool):
        # We first need to match QuestDB's internal microsecond resolution.
        at_ts_us = at_ts_ns // 1000
        trimmed_ns = at_ts_ns % 1000
        at_ts_sec = at_ts_us / 1000000.0

        # Commented out for now. Uncomment when CI catches up to a newer Python version.
        # at_td = datetime.datetime.fromtimestamp(at_ts_sec, datetime.UTC).replace(tzinfo=None)
        at_td = datetime.datetime.utcfromtimestamp(at_ts_sec)
        extra_precision = ''
        if exp_nanos:
            extra_precision = f'{trimmed_ns:03}'
        return at_td.isoformat() + extra_precision + 'Z'

    @property
    def client_driven_nanos_supported(self) -> bool:
        # """True if the QuestDB server supports nanos and also respects the client's precision for the designated timestamp."""
        if QDB_FIXTURE.version <= (9, 1, 0):
            return False

        if QDB_FIXTURE.http:
            return QDB_FIXTURE.protocol_version != qls.ProtocolVersion.V1
        elif QDB_FIXTURE.protocol_version is None:
            return False # TCP defaults to ProtocolVersion.V1
        else:
            return QDB_FIXTURE.protocol_version >= qls.ProtocolVersion.V2

    @property
    def expected_protocol_version(self) -> qls.ProtocolVersion:
        """The protocol version that we expect to be handling."""
        if QDB_FIXTURE.protocol_version is None:
            if not QDB_FIXTURE.http:
                return qls.ProtocolVersion.V1

            if QDB_FIXTURE.version >= FIRST_ARRAYS_RELEASE:
                return qls.ProtocolVersion.V2

            if QDB_FIXTURE.version >= DECIMAL_RELEASE:
                return qls.ProtocolVersion.V3

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
             .column('b', qls.TimestampNanos(at_ts_ns))
             .at(at_ts_ns))
            pending = sender.buffer.peek()
        resp = retry_check_table(table_name, log_ctx=pending)
        exp_dataset = [[
            'A',
            self._ns_to_qdb_date(at_ts_ns, exp_nanos=self.client_driven_nanos_supported),
            self._ns_to_qdb_date(at_ts_ns, exp_nanos=self.client_driven_nanos_supported)]]
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
             .column('b', qls.TimestampMicros(at_ts_us))
             .at_micros(at_ts_us))
            pending = sender.buffer.peek()
        resp = retry_check_table(table_name, log_ctx=pending)
        exp_dataset = [[
            'A',
            self._ns_to_qdb_date(at_ts_ns, exp_nanos=False),
            self._ns_to_qdb_date(at_ts_ns, exp_nanos=False)]]
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

    def test_decimal_column(self):
        if QDB_FIXTURE.version < DECIMAL_RELEASE:
            self.skipTest('No decimal support in this version of QuestDB.')
        if self.expected_protocol_version < qls.ProtocolVersion.V3:
            self.skipTest('communicating over old protocol which does not support decimals')

        table_name = uuid.uuid4().hex
        sql_query(f'CREATE TABLE "{table_name}" (dec DECIMAL(18,3), timestamp TIMESTAMP) TIMESTAMP(timestamp) PARTITION BY DAY;')

        pending = None
        decimals = [
            Decimal("12.99"),
            Decimal("-12.34"),
            Decimal("0.001"),
            Decimal("10000000.0"),
            Decimal("NaN"),
            Decimal("Infinity"),
            Decimal("0"),
            Decimal("-0"),
            Decimal("1e3")
        ]
        with self._mk_linesender() as sender:
            for dec in decimals:
                sender.table(table_name)
                sender.column('dec', dec)
                sender.at_now()
            pending = sender.buffer.peek()

        resp = retry_check_table(table_name, min_rows=len(decimals), log_ctx=pending)
        exp_columns = [
            {'name': 'dec', 'type': 'DECIMAL(18,3)'},
            {'name': 'timestamp', 'type': 'TIMESTAMP'}]
        self.assertEqual(resp['columns'], exp_columns)
        # By default, the decimal created as a scale of 3
        exp_dataset = [['12.990'], ['-12.340'], ['0.001'], ['10000000.000'], [None], [None], ['0.000'], ['0.000'], ['1000.000']]
        scrubbed_dataset = [row[:-1] for row in resp['dataset']]
        self.assertEqual(scrubbed_dataset, exp_dataset)

    def test_decimal_invalid_characters(self):
        if QDB_FIXTURE.version < DECIMAL_RELEASE:
            self.skipTest('No decimal support in this version of QuestDB.')
        if self.expected_protocol_version < qls.ProtocolVersion.V3:
            self.skipTest('communicating over old protocol which does not support decimals')

        table_name = uuid.uuid4().hex
        with self.assertRaisesRegex(qls.SenderError, r'Bad call to'):
            with self._mk_linesender() as sender:
                with self.assertRaisesRegex(qls.SenderError, r'.*Decimal string contains invalid character*'):
                    (sender
                    .table(table_name)
                    .column_dec_str('dec', "12.34abc")
                    .at_now())

    def test_decimal_not_available(self):
        if QDB_FIXTURE.version >= DECIMAL_RELEASE or QDB_FIXTURE.version >= (9, 1, 1): # remove the second condition when 9.2.0 is released
            self.skipTest('Decimal support is available in this version of QuestDB.')
        if self.expected_protocol_version >= qls.ProtocolVersion.V3:
            self.skipTest('communicating over new protocol which supports decimals')
        table_name = uuid.uuid4().hex
        with self.assertRaisesRegex(qls.SenderError, r'Bad call to'):
            with self._mk_linesender() as sender:
                with self.assertRaisesRegex(qls.SenderError, r'.*does not support the decimal datatype*'):
                    (sender
                    .table(table_name)
                    .column('dec', Decimal("12.34"))
                    .at_now())

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

        exp_ts_type = 'TIMESTAMP_NS' if self.client_driven_nanos_supported else 'TIMESTAMP'
        # Decimal columns must be created manually beforehand.
        sql_query(f'''CREATE TABLE "{table_name}" (price DECIMAL(18,3), timestamp {exp_ts_type}) TIMESTAMP(timestamp) PARTITION BY DAY;''')

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
            {'name': 'price', 'type': 'DECIMAL(18,3)'},
            {'name': 'timestamp', 'type': exp_ts_type},
            {'name': 'symbol', 'type': 'SYMBOL'},
            {'name': 'side', 'type': 'SYMBOL'},
            {'name': 'amount', 'type': 'DOUBLE'}
        ]
        self.assertEqual(resp['columns'], exp_columns)

        exp_dataset = [['2615.540',
                        'ETH-USD',
                        'sell',
                        0.00044]]
        # Comparison excludes timestamp column.
        scrubbed_dataset = [row[:1] + row[2:] for row in resp['dataset']]
        self.assertEqual(scrubbed_dataset, exp_dataset)

    def test_c_example(self):
        if QDB_FIXTURE.version < DECIMAL_RELEASE:
            self.skipTest('No decimal support in this version of QuestDB.')

        suffix = '_auth' if QDB_FIXTURE.auth else ''
        suffix += '_http' if QDB_FIXTURE.http else ''
        self._test_example(
            f'line_sender_c_example{suffix}',
            f'c_trades{suffix}')

    def test_cpp_example(self):
        if QDB_FIXTURE.version < DECIMAL_RELEASE:
            self.skipTest('No decimal support in this version of QuestDB.')

        suffix = '_auth' if QDB_FIXTURE.auth else ''
        suffix += '_http' if QDB_FIXTURE.http else ''
        self._test_example(
            f'line_sender_cpp_example{suffix}',
            f'cpp_trades{suffix}')

    def test_c_tls_example(self):
        if QDB_FIXTURE.version < DECIMAL_RELEASE:
            self.skipTest('No decimal support in this version of QuestDB.')

        self._test_example(
            'line_sender_c_example_tls_ca',
            'c_trades_tls_ca',
            tls=True)

    def test_cpp_tls_example(self):
        if QDB_FIXTURE.version < DECIMAL_RELEASE:
            self.skipTest('No decimal support in this version of QuestDB.')

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
        exp_ts_type = 'TIMESTAMP_NS' if self.client_driven_nanos_supported else 'TIMESTAMP'
        exp_columns = [
            {'name': 'symbol', 'type': 'SYMBOL'},
            {'dim': 3, 'elemType': 'DOUBLE', 'name': 'order_book', 'type': 'ARRAY'},
            {'name': 'timestamp', 'type': exp_ts_type}]
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


class QwpWsTestSupport:
    BASE_TS_US = 1_700_000_000_000_000
    TS_STEP_US = 1_000

    @staticmethod
    def _require_qwp_ws_protocol():
        if QDB_FIXTURE.version < QWP_MIN_RELEASE:
            raise unittest.SkipTest(
                f'Server version {".".join(map(str, QDB_FIXTURE.version))} does not '
                'support the QWP protocol version we can test. Minimum version we need: '
                f'(QuestDB >= {".".join(map(str, QWP_MIN_RELEASE))})')

    @staticmethod
    def _create_qwp_ws_table(table_name):
        sql_query(
            f'CREATE TABLE "{table_name}" '
            '(id LONG, val DOUBLE, ts TIMESTAMP) '
            'TIMESTAMP(ts) PARTITION BY DAY WAL '
            'DEDUP UPSERT KEYS(ts, id)')

    @staticmethod
    def _sender_conf(
            sender_id,
            sf_dir,
            port=None,
            scheme='qwpws',
            host=None,
            endpoints=None,
            **settings):
        host = QDB_FIXTURE.host if host is None else host
        port = QDB_FIXTURE.http_server_port if port is None else port
        if endpoints is None:
            endpoints = [(host, port)]
        addr = ','.join(
            f'{endpoint_host}:{endpoint_port}'
            for endpoint_host, endpoint_port in endpoints)
        conf = [
            f'{scheme}::addr={addr};',
            f'sender_id={sender_id};',
            f'sf_dir={sf_dir};']
        for key, value in settings.items():
            conf.append(f'{key}={value};')
        return ''.join(conf)

    @staticmethod
    def _is_unsupported_qwp_ws_fixture_error(error):
        message = str(error).lower()
        unsupported_markers = (
            'unsupported protocol',
            'unknown protocol',
            'unknown scheme',
            'missing endpoint',
            'endpoint not found',
            'websocket upgrade failed: http status 404',
            'websocket upgrade failed: http status 405',
            'websocket upgrade failed: http status 501',
        )
        return any(marker in message for marker in unsupported_markers)

    def _connect_sender(self, conf):
        sender = None
        try:
            sender = qls.Sender.from_conf(conf)
            sender.connect()
            sender._buffer = qls.Buffer.from_sender(sender._impl)
        except qls.SenderError as e:
            if sender is not None:
                sender.close(False)
            root_dir = getattr(QDB_FIXTURE, '_root_dir', None)
            if (
                    root_dir is not None and
                    root_dir.name != 'repo' and
                    self._is_unsupported_qwp_ws_fixture_error(e)):
                self.skipTest(f'QWP/WebSocket is not supported by this QuestDB fixture: {e}')
            raise
        return sender

    def _write_rows(self, sender, table_name, first_id, count):
        for row_id in range(first_id, first_id + count):
            (sender
             .table(table_name)
             .column('id', row_id)
             .column('val', row_id * 0.5)
             .at_micros(self.BASE_TS_US + row_id * self.TS_STEP_US))

    def _write_row(self, sender, table_name, row_id):
        self._write_rows(sender, table_name, row_id, 1)

    @staticmethod
    def _unused_tcp_port():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(('127.0.0.1', 0))
            return sock.getsockname()[1]

    @staticmethod
    def _sfa_file_count(sf_dir, sender_id):
        slot_dir = pathlib.Path(sf_dir) / sender_id
        if not slot_dir.exists():
            return 0
        return sum(
            1 for path in slot_dir.iterdir()
            if path.name.endswith('.sfa'))

    def _retry_assert_aggregates(
            self,
            table_name,
            expected_count,
            expected_distinct_id,
            expected_min_id=None,
            expected_max_id=None,
            timeout_sec=30):
        deadline = time.monotonic() + timeout_sec
        query = (
            f"select count(), count_distinct(id), min(id), max(id) "
            f"from '{table_name}'")
        last_resp = None
        last_error = None
        while time.monotonic() < deadline:
            try:
                last_resp = sql_query(query)
                row = last_resp['dataset'][0]
                count = int(row[0])
                distinct_id = int(row[1])
                min_id = None if row[2] is None else int(row[2])
                max_id = None if row[3] is None else int(row[3])
                if (
                        count == expected_count and
                        distinct_id == expected_distinct_id and
                        (expected_min_id is None or min_id == expected_min_id) and
                        (expected_max_id is None or max_id == expected_max_id)):
                    return last_resp
            except Exception as e:
                last_error = e
            time.sleep(0.05)
        self.fail(
            f'Timed out waiting for aggregates from {query!r}; '
            f'last_resp={last_resp!r}; last_error={last_error!r}')

    def _retry_query_rows(self, query, expected_rows, timeout_sec=30):
        deadline = time.monotonic() + timeout_sec
        last_resp = None
        last_error = None
        while time.monotonic() < deadline:
            try:
                last_resp = sql_query(query)
                if len(last_resp.get('dataset') or []) >= expected_rows:
                    return last_resp
            except Exception as e:
                last_error = e
            time.sleep(0.05)
        self.fail(
            f'Timed out waiting for {expected_rows} rows from {query!r}; '
            f'last_resp={last_resp!r}; last_error={last_error!r}')

    def _retry_poll_qwp_ws_error(self, sender, timeout_sec=10):
        deadline = time.monotonic() + timeout_sec
        while time.monotonic() < deadline:
            error = sender.poll_qwp_ws_error()
            if error is not None:
                return error
            time.sleep(0.05)
        self.fail('Timed out waiting for QWP/WebSocket diagnostic')


class TestQwpWsSender(QwpWsTestSupport, unittest.TestCase):
    ROWS = 3

    def setUp(self):
        self._require_smoke_fixture()
        test_name = self.id()
        QDB_FIXTURE.http_sql_query(
            f'select * from long_sequence(1) -- >>>>>>>>> BEGIN PYTHON UNIT TEST: {test_name}')

    def tearDown(self):
        if isinstance(QDB_FIXTURE, QuestDbFixture) and QDB_FIXTURE._proc:
            test_name = self.id()
            QDB_FIXTURE.http_sql_query(
                f'select * from long_sequence(1) -- <<<<<<<<< END PYTHON UNIT TEST: {test_name}')

    def _require_smoke_fixture(self):
        self._require_qwp_ws_protocol()
        if not isinstance(QDB_FIXTURE, QuestDbFixture):
            self.skipTest('QWP/WebSocket smoke tests require a managed QuestDB fixture')
        if QDB_FIXTURE.auth:
            self.skipTest('QWP/WebSocket smoke tests use HTTP auth, not line TCP auth')
        if QWP_WS_SMOKE_TLS and TLS_PROXY_FIXTURE is None:
            self.skipTest('QWP/WebSocket TLS smoke tests require a TLS proxy fixture')

    @staticmethod
    def _variant_name():
        auth_name = 'http_auth' if getattr(QDB_FIXTURE, 'http_auth', False) else 'plain'
        tls_name = 'tls' if QWP_WS_SMOKE_TLS else 'no_tls'
        return f'{auth_name}_{tls_name}'

    def _sender_conf_for_variant(
            self,
            sender_id,
            sf_dir,
            include_auth=True,
            password=None,
            auth_timeout_ms=None):
        scheme = 'qwpws'
        host = QDB_FIXTURE.host
        port = QDB_FIXTURE.http_server_port
        settings = {
            'reconnect_max_duration_millis': 30000,
            'close_flush_timeout_millis': 30000,
        }
        if auth_timeout_ms is not None:
            settings['auth_timeout_ms'] = auth_timeout_ms
        if QWP_WS_SMOKE_TLS:
            scheme = 'qwpwss'
            host = 'localhost'
            port = TLS_PROXY_FIXTURE.listen_port
            settings['tls_roots'] = str(Project().tls_certs_dir / 'server_rootCA.pem')
        if include_auth and getattr(QDB_FIXTURE, 'http_auth', False):
            settings['username'] = HTTP_AUTH['username']
            settings['password'] = password or HTTP_AUTH['password']
        return self._sender_conf(
            sender_id,
            sf_dir,
            port=port,
            scheme=scheme,
            host=host,
            **settings)

    def _assert_auth_rejected(self, sender_id, sf_dir, include_auth, password=None):
        if not getattr(QDB_FIXTURE, 'http_auth', False):
            return
        sender = qls.Sender.from_conf(self._sender_conf_for_variant(
            sender_id,
            sf_dir,
            include_auth=include_auth,
            password=password,
            auth_timeout_ms=5000))
        try:
            with self.assertRaises(qls.SenderError) as ctx:
                sender.connect()
            native_error = ctx.exception.__cause__ or ctx.exception
            root_dir = getattr(QDB_FIXTURE, '_root_dir', None)
            if (
                    root_dir is not None and
                    root_dir.name != 'repo' and
                    self._is_unsupported_qwp_ws_fixture_error(native_error)):
                self.skipTest(
                    f'QWP/WebSocket is not supported by this QuestDB fixture: {native_error}')
            self.assertRegex(
                str(native_error),
                r'(?i)(401|403|unauthor|forbidden|authentication)')
        finally:
            sender.close(False)

    def _assert_auth_failures_rejected(self, sender_id, sf_dir):
        self._assert_auth_rejected(
            sender_id + '-noauth',
            sf_dir,
            include_auth=False)
        self._assert_auth_rejected(
            sender_id + '-badauth',
            sf_dir,
            include_auth=True,
            password='wrong')

    def test_auth_failures_rejected(self):
        sender_id = 'auth-' + self._variant_name() + '-' + uuid.uuid4().hex[:8]
        with tempfile.TemporaryDirectory(prefix='qwp-ws-auth-') as sf_dir:
            self._assert_auth_failures_rejected(sender_id, sf_dir)

    def test_single_batch_round_trip(self):
        table_name = 'qwp_ws_smoke_' + uuid.uuid4().hex[:8]
        self._create_qwp_ws_table(table_name)
        sender_id = 'smoke-' + self._variant_name() + '-' + uuid.uuid4().hex[:8]

        with tempfile.TemporaryDirectory(prefix='qwp-ws-smoke-') as sf_dir:
            sender = self._connect_sender(self._sender_conf_for_variant(
                sender_id,
                sf_dir))
            try:
                self._write_rows(sender, table_name, 0, self.ROWS)
                sender.flush()
                sender.close_drain()
            finally:
                sender.close(False)

            self.assertEqual(
                self._sfa_file_count(sf_dir, sender_id),
                0,
                'close-drained QWP/WebSocket smoke sender left SFA frame files behind')

        self._retry_assert_aggregates(
            table_name,
            expected_count=self.ROWS,
            expected_distinct_id=self.ROWS,
            expected_min_id=0,
            expected_max_id=self.ROWS - 1)


class TestQwpWsProtocol(QwpWsTestSupport, unittest.TestCase):
    def setUp(self):
        self._require_protocol_fixture()
        test_name = self.id()
        QDB_FIXTURE.http_sql_query(
            f'select * from long_sequence(1) -- >>>>>>>>> BEGIN PYTHON UNIT TEST: {test_name}')

    def tearDown(self):
        if isinstance(QDB_FIXTURE, QuestDbFixture) and QDB_FIXTURE._proc:
            test_name = self.id()
            QDB_FIXTURE.http_sql_query(
                f'select * from long_sequence(1) -- <<<<<<<<< END PYTHON UNIT TEST: {test_name}')

    def _require_protocol_fixture(self):
        self._require_qwp_ws_protocol()
        if not isinstance(QDB_FIXTURE, QuestDbFixture):
            self.skipTest('QWP/WebSocket protocol tests require a managed QuestDB fixture')
        if QDB_FIXTURE.auth:
            self.skipTest('QWP/WebSocket protocol tests run without line TCP auth')
        if getattr(QDB_FIXTURE, 'http_auth', False):
            self.skipTest('QWP/WebSocket protocol tests run without HTTP auth')
        if QDB_FIXTURE.http:
            self.skipTest('QWP/WebSocket protocol tests run outside the HTTP ILP matrix')

    def _connect_protocol_sender(self, sender_id, sf_dir, endpoints=None, **settings):
        conf_settings = {
            'reconnect_max_duration_millis': 30000,
            'close_flush_timeout_millis': 30000,
        }
        conf_settings.update(settings)
        return self._connect_sender(self._sender_conf(
            sender_id,
            sf_dir,
            endpoints=endpoints,
            **conf_settings))

    def test_initial_connect_skips_dead_endpoint_and_ack_progresses(self):
        table_name = 'qwp_ws_failover_' + uuid.uuid4().hex[:8]
        self._create_qwp_ws_table(table_name)
        sender_id = 'proto-failover-' + uuid.uuid4().hex[:8]
        dead_port = self._unused_tcp_port()
        endpoints = [
            (QDB_FIXTURE.host, dead_port),
            (QDB_FIXTURE.host, QDB_FIXTURE.http_server_port),
        ]

        with tempfile.TemporaryDirectory(prefix='qwp-ws-failover-') as sf_dir:
            sender = self._connect_protocol_sender(
                sender_id,
                sf_dir,
                endpoints=endpoints)
            try:
                self._write_row(sender, table_name, 0)
                fsn = sender.flush_and_get_fsn()
                self.assertEqual(fsn, 0)
                self.assertTrue(sender.await_acked_fsn(fsn, 30000))
                self.assertEqual(sender.acked_fsn(), fsn)
                sender.close_drain()
            finally:
                sender.close(False)

            self.assertEqual(
                self._sfa_file_count(sf_dir, sender_id),
                0,
                'close-drained failover sender left SFA frame files behind')

        self._retry_assert_aggregates(
            table_name,
            expected_count=1,
            expected_distinct_id=1,
            expected_min_id=0,
            expected_max_id=0)

    def test_schema_evolution_across_batches(self):
        table_name = 'qwp_ws_schema_' + uuid.uuid4().hex[:8]
        sender_id = 'proto-schema-' + uuid.uuid4().hex[:8]

        with tempfile.TemporaryDirectory(prefix='qwp-ws-schema-') as sf_dir:
            sender = self._connect_protocol_sender(sender_id, sf_dir)
            try:
                (sender
                 .table(table_name)
                 .symbol('host', 'r1')
                 .at_micros(self.BASE_TS_US))
                first_fsn = sender.flush_and_get_fsn()
                self.assertEqual(first_fsn, 0)

                (sender
                 .table(table_name)
                 .symbol('host', 'r2')
                 .column('qty', 2)
                 .column('note', 'two')
                 .at_micros(self.BASE_TS_US + self.TS_STEP_US))
                second_fsn = sender.flush_and_get_fsn()
                self.assertEqual(second_fsn, 1)

                (sender
                 .table(table_name)
                 .symbol('host', 'r3')
                 .column('note', 'three')
                 .at_micros(self.BASE_TS_US + 2 * self.TS_STEP_US))
                third_fsn = sender.flush_and_get_fsn()
                self.assertEqual(third_fsn, 2)

                self.assertTrue(sender.await_acked_fsn(third_fsn, 30000))
                sender.close_drain()
            finally:
                sender.close(False)

            self.assertEqual(
                self._sfa_file_count(sf_dir, sender_id),
                0,
                'close-drained QWP/WebSocket schema sender left SFA frame files behind')

        resp = self._retry_query_rows(
            f"select host, qty, note from '{table_name}' order by host",
            3,
            timeout_sec=30)
        self.assertEqual(
            resp['dataset'],
            [
                ['r1', None, None],
                ['r2', 2, 'two'],
                ['r3', None, 'three'],
            ])

    def test_write_rejection_drops_and_sender_continues(self):
        table_name = 'qwp_ws_reject_' + uuid.uuid4().hex[:8]
        sql_query(
            f'CREATE TABLE "{table_name}" '
            '(id LONG, px DOUBLE, bad LONG, ts TIMESTAMP) '
            'TIMESTAMP(ts) PARTITION BY DAY WAL')
        sender_id = 'proto-reject-' + uuid.uuid4().hex[:8]

        with tempfile.TemporaryDirectory(prefix='qwp-ws-reject-') as sf_dir:
            sender = self._connect_protocol_sender(sender_id, sf_dir)
            try:
                (sender
                 .table(table_name)
                 .column('id', 0)
                 .column('px', 10.5)
                 .at_micros(self.BASE_TS_US))
                first_fsn = sender.flush_and_get_fsn()

                (sender
                 .table(table_name)
                 .column('id', 1)
                 .column('bad', 'not-a-long')
                 .at_micros(self.BASE_TS_US + self.TS_STEP_US))
                rejected_fsn = sender.flush_and_get_fsn()

                (sender
                 .table(table_name)
                 .column('id', 2)
                 .column('px', 20.5)
                 .at_micros(self.BASE_TS_US + 2 * self.TS_STEP_US))
                final_fsn = sender.flush_and_get_fsn()

                self.assertEqual((first_fsn, rejected_fsn, final_fsn), (0, 1, 2))
                self.assertTrue(sender.await_acked_fsn(final_fsn, 30000))
                diagnostic = self._retry_poll_qwp_ws_error(sender)
                self.assertEqual(diagnostic.category, qls.QwpWsErrorCategory.SCHEMA_MISMATCH)
                self.assertEqual(diagnostic.applied_policy, qls.QwpWsErrorPolicy.DROP_AND_CONTINUE)
                self.assertEqual(diagnostic.status, QWP_WS_STATUS_SCHEMA_MISMATCH)
                self.assertEqual(diagnostic.from_fsn, rejected_fsn)
                self.assertEqual(diagnostic.to_fsn, rejected_fsn)
                self.assertIsNone(sender.poll_qwp_ws_error())
                self.assertEqual(sender.qwp_ws_errors_dropped(), 0)
                sender.close_drain()
            finally:
                sender.close(False)

            self.assertEqual(
                self._sfa_file_count(sf_dir, sender_id),
                0,
                'close-drained rejection sender left SFA frame files behind')

        resp = self._retry_query_rows(
            f"select id, px from '{table_name}' order by id",
            2,
            timeout_sec=30)
        self.assertEqual(
            resp['dataset'],
            [
                [0, 10.5],
                [2, 20.5],
            ])


class TestQwpWsRestart(QwpWsTestSupport, unittest.TestCase):
    ROWS_PER_PHASE = 500
    ROWS_PER_RECOVERY_EPOCH = 5000
    CONTINUOUS_BOUNCES = 3
    CONTINUOUS_BATCH_ROWS = 25
    MULTI_EPOCH_ROWS = (500, 997, 1499)

    def setUp(self):
        self._require_restart_fixture()
        test_name = self.id()
        QDB_FIXTURE.http_sql_query(
            f'select * from long_sequence(1) -- >>>>>>>>> BEGIN PYTHON UNIT TEST: {test_name}')

    def tearDown(self):
        if isinstance(QDB_FIXTURE, QuestDbFixture) and QDB_FIXTURE._proc:
            test_name = self.id()
            QDB_FIXTURE.http_sql_query(
                f'select * from long_sequence(1) -- <<<<<<<<< END PYTHON UNIT TEST: {test_name}')

    def _require_restart_fixture(self):
        self._require_qwp_ws_protocol()
        if not isinstance(QDB_FIXTURE, QuestDbFixture):
            self.skipTest('QWP/WebSocket restart tests require a managed QuestDB fixture')
        root_dir = getattr(QDB_FIXTURE, '_root_dir', None)
        # QWP/WebSocket restart coverage currently requires a repo-built
        # QuestDB because the fixed release matrix still uses 9.2.0, which
        # does not expose the QWP/WebSocket endpoint. After QWP/WebSocket
        # server support is released, replace this repo-only guard with a
        # capability or version gate so release fixtures run these tests too.
        if root_dir is not None and root_dir.name != 'repo':
            self.skipTest('QWP/WebSocket restart tests require a QuestDB repo fixture')
        if QDB_FIXTURE.auth:
            self.skipTest('QWP/WebSocket restart tests run without auth')
        if getattr(QDB_FIXTURE, 'http_auth', False):
            self.skipTest('QWP/WebSocket restart tests run without HTTP auth')
        if QDB_FIXTURE.http:
            self.skipTest('QWP/WebSocket restart tests run outside the HTTP ILP matrix')

    def _write_server_accepted_unacked_qwp_frame_then_restart(
            self,
            table_name,
            sender_id,
            sf_dir,
            first_id,
            count):
        proxy = QwpWsDropAckProxy(
            QDB_FIXTURE.host,
            QDB_FIXTURE.http_server_port)
        proxy.start()
        sender = None
        server_stopped = False
        try:
            sender = self._connect_sender(self._sender_conf(
                sender_id,
                sf_dir,
                port=proxy.port,
                reconnect_max_duration_millis=120000,
                close_flush_timeout_millis=0))
            self._write_rows(sender, table_name, first_id, count)
            sender.flush()
            proxy.join()
            QDB_FIXTURE.stop()
            server_stopped = True
        finally:
            if sender is not None:
                sender.close(False)
            if proxy.is_alive():
                proxy.close()
            if server_stopped:
                QDB_FIXTURE.start()

        self.assertGreater(
            self._sfa_file_count(sf_dir, sender_id),
            0,
            'server-accepted unacked QWP frame did not leave recoverable SFA files')

    def _recover_sf_dir(self, sender_id, sf_dir):
        sender = self._connect_sender(self._sender_conf(
            sender_id,
            sf_dir,
            reconnect_max_duration_millis=120000,
            close_flush_timeout_millis=120000))
        try:
            sender.close_drain()
        finally:
            sender.close(False)
        self.assertEqual(
            self._sfa_file_count(sf_dir, sender_id),
            0,
            'close-drained recovery sender left SFA frame files behind')

    def test_same_sender_survives_server_restart(self):
        table_name = 'qwp_ws_restart_' + uuid.uuid4().hex[:8]
        self._create_qwp_ws_table(table_name)
        sender_id = 's2-' + uuid.uuid4().hex[:12]

        with tempfile.TemporaryDirectory(prefix='qwp-ws-s2-') as sf_dir:
            sender = self._connect_sender(self._sender_conf(
                sender_id,
                sf_dir,
                reconnect_max_duration_millis=120000,
                close_flush_timeout_millis=120000))
            try:
                self._write_rows(sender, table_name, 0, self.ROWS_PER_PHASE)
                sender.flush()

                QDB_FIXTURE.stop()
                QDB_FIXTURE.start()

                self._write_rows(
                    sender,
                    table_name,
                    self.ROWS_PER_PHASE,
                    self.ROWS_PER_PHASE)
                sender.flush()
                sender.close_drain()
            finally:
                sender.close(False)

        self._retry_assert_aggregates(
            table_name,
            expected_count=self.ROWS_PER_PHASE * 2,
            expected_distinct_id=self.ROWS_PER_PHASE * 2,
            expected_min_id=0,
            expected_max_id=self.ROWS_PER_PHASE * 2 - 1)

    def test_reconnect_gives_up_after_cap(self):
        table_name = 'qwp_ws_cap_' + uuid.uuid4().hex[:8]
        self._create_qwp_ws_table(table_name)
        sender_id = 's1-' + uuid.uuid4().hex[:12]
        observed_error = None

        with tempfile.TemporaryDirectory(prefix='qwp-ws-s1-') as sf_dir:
            sender = self._connect_sender(self._sender_conf(
                sender_id,
                sf_dir,
                reconnect_max_duration_millis=500,
                reconnect_initial_backoff_millis=10,
                reconnect_max_backoff_millis=50,
                close_flush_timeout_millis=0))
            server_stopped = False
            try:
                self._write_row(sender, table_name, 0)
                sender.flush()
                self._retry_assert_aggregates(
                    table_name,
                    expected_count=1,
                    expected_distinct_id=1,
                    expected_min_id=0,
                    expected_max_id=0)

                QDB_FIXTURE.stop()
                server_stopped = True
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    try:
                        self._write_row(sender, table_name, 1)
                        sender.flush()
                    except qls.SenderError as e:
                        observed_error = e
                        break
                    time.sleep(0.05)

                self.assertIsNotNone(
                    observed_error,
                    'sender did not surface reconnect-cap failure within 5 seconds')
                self.assertRegex(
                    str(observed_error),
                    r'(?i)(reconnect|connect|terminal|refused)')
            finally:
                sender.close(False)
                if server_stopped:
                    QDB_FIXTURE.start()

        self._retry_assert_aggregates(
            table_name,
            expected_count=1,
            expected_distinct_id=1,
            expected_min_id=0,
            expected_max_id=0)

    def test_new_sender_recovers_from_sf_dir(self):
        table_name = 'qwp_ws_recover_' + uuid.uuid4().hex[:8]
        self._create_qwp_ws_table(table_name)
        sender_id = 's3-' + uuid.uuid4().hex[:12]

        with tempfile.TemporaryDirectory(prefix='qwp-ws-s3-') as sf_dir:
            self._write_server_accepted_unacked_qwp_frame_then_restart(
                table_name,
                sender_id,
                sf_dir,
                0,
                self.ROWS_PER_RECOVERY_EPOCH)

            second = self._connect_sender(self._sender_conf(
                sender_id,
                sf_dir,
                reconnect_max_duration_millis=120000,
                close_flush_timeout_millis=120000))
            try:
                self._write_rows(
                    second,
                    table_name,
                    self.ROWS_PER_RECOVERY_EPOCH,
                    self.ROWS_PER_RECOVERY_EPOCH)
                second.flush()
                second.close_drain()
            finally:
                second.close(False)

            expected_count = self.ROWS_PER_RECOVERY_EPOCH * 2
            self._retry_assert_aggregates(
                table_name,
                expected_count=expected_count,
                expected_distinct_id=expected_count,
                expected_min_id=0,
                expected_max_id=expected_count - 1,
                timeout_sec=60)
            self.assertEqual(
                self._sfa_file_count(sf_dir, sender_id),
                0,
                'close-drained recovery sender left SFA frame files behind')

    def test_sender_pushes_continuously_while_server_bounces(self):
        table_name = 'qwp_ws_bounce_' + uuid.uuid4().hex[:8]
        self._create_qwp_ws_table(table_name)
        sender_id = 's4-' + uuid.uuid4().hex[:12]
        stop_producer = threading.Event()
        rows_produced = 0
        producer_error = []

        def producer(sf_dir):
            nonlocal rows_produced
            sender = None
            next_id = 0
            try:
                sender = self._connect_sender(self._sender_conf(
                    sender_id,
                    sf_dir,
                    reconnect_max_duration_millis=120000,
                    close_flush_timeout_millis=120000))
                while not stop_producer.is_set():
                    batch_first_id = next_id
                    self._write_rows(
                        sender,
                        table_name,
                        batch_first_id,
                        self.CONTINUOUS_BATCH_ROWS)
                    next_id += self.CONTINUOUS_BATCH_ROWS
                    sender.flush()
                    rows_produced = next_id
                    time.sleep(0.002)
                sender.close_drain()
            except BaseException as e:
                producer_error.append(e)
            finally:
                if sender is not None:
                    sender.close(False)

        with tempfile.TemporaryDirectory(prefix='qwp-ws-s4-') as sf_dir:
            producer_thread = threading.Thread(
                target=producer,
                args=(sf_dir,),
                name='qwp-ws-restart-producer',
                daemon=True)
            producer_thread.start()
            try:
                startup_deadline = time.monotonic() + 5
                while (
                        rows_produced == 0 and
                        not producer_error and
                        time.monotonic() < startup_deadline):
                    time.sleep(0.01)
                if producer_error:
                    raise AssertionError(
                        'producer failed before first server bounce') from producer_error[0]
                self.assertGreater(
                    rows_produced,
                    0,
                    'producer did not flush an initial batch before first bounce')
                for bounce_index in range(self.CONTINUOUS_BOUNCES):
                    rows_before_stop = rows_produced
                    QDB_FIXTURE.stop()
                    time.sleep(0.05)
                    QDB_FIXTURE.start()
                    rows_at_restart = rows_produced
                    restart_deadline = time.monotonic() + 10
                    while (
                            rows_produced <= rows_at_restart and
                            not producer_error and
                            time.monotonic() < restart_deadline):
                        time.sleep(0.01)
                    if producer_error:
                        raise AssertionError(
                            f'producer failed after server restart #{bounce_index + 1}') from producer_error[0]
                    self.assertGreater(
                        rows_produced,
                        rows_at_restart,
                        f'producer did not flush any rows after restart #{bounce_index + 1} completed')
                    self.assertGreater(
                        rows_produced,
                        rows_before_stop,
                        f'producer did not flush any rows after bounce #{bounce_index + 1} began')
                    time.sleep(0.2)
                time.sleep(0.2)
            finally:
                stop_producer.set()
                producer_thread.join(180)

            self.assertFalse(
                producer_thread.is_alive(),
                f'producer did not finish within 180s '
                f'(rows_produced={rows_produced})')
            if producer_error:
                raise AssertionError(
                    'producer must not surface failures across server bounces '
                    f'(rows_produced={rows_produced})') from producer_error[0]
            self.assertGreater(rows_produced, 0, 'producer wrote zero rows')

            self._retry_assert_aggregates(
                table_name,
                expected_count=rows_produced,
                expected_distinct_id=rows_produced,
                expected_min_id=0,
                expected_max_id=rows_produced - 1,
                timeout_sec=60)
            self.assertEqual(
                self._sfa_file_count(sf_dir, sender_id),
                0,
                'close-drained continuous sender left SFA frame files behind')

    def test_fuzz_multiple_restarts_new_sender(self):
        table_name = 'qwp_ws_multi_' + uuid.uuid4().hex[:8]
        self._create_qwp_ws_table(table_name)
        sender_id = 's5-' + uuid.uuid4().hex[:12]
        expected_count = 0

        with tempfile.TemporaryDirectory(prefix='qwp-ws-s5-') as sf_dir:
            for rows_in_epoch in self.MULTI_EPOCH_ROWS:
                self._write_server_accepted_unacked_qwp_frame_then_restart(
                    table_name,
                    sender_id,
                    sf_dir,
                    expected_count,
                    rows_in_epoch)
                expected_count += rows_in_epoch

                self._recover_sf_dir(sender_id, sf_dir)
                self._retry_assert_aggregates(
                    table_name,
                    expected_count=expected_count,
                    expected_distinct_id=expected_count,
                    expected_min_id=0,
                    expected_max_id=expected_count - 1,
                    timeout_sec=60)


class TestQwpWsFuzz(QwpWsTestSupport, unittest.TestCase):
    """Schema-fuzz suite ported from
    `io.questdb.test.cutlass.qwp.e2e.QwpSenderFuzzTest`.

    Each test seeds a master RNG, prints the seed to stderr, and uses it to
    derive everything downstream — load shape, fuzz factors, per-thread RNGs
    and the optional ALTER thread RNG. Freeze the printed seed via
    ``QWP_WS_FUZZ_SEED=0x...`` to reproduce a failure, then filter unittest
    to just that method.
    """

    BASE_TIMESTAMP_US = 1_465_839_830_102_300
    POLL_INTERVAL_SEC = 0.05
    DRAIN_TIMEOUT_SEC = 120

    def setUp(self):
        self._require_fuzz_fixture()
        seed = qwp_ws_fuzz.derive_master_seed()
        self._master_rng = qwp_ws_fuzz.Rng(seed)
        self._seed_label = (
            f'{self.id()} seed={qwp_ws_fuzz.format_seed(seed)}')
        self._created_tables = []
        sys.stderr.write(f'[qwp_ws_fuzz seed] {self._seed_label}\n')
        sys.stderr.flush()
        QDB_FIXTURE.http_sql_query(
            f'select * from long_sequence(1) -- >>>>>>>>> BEGIN PYTHON UNIT TEST: {self.id()}')

    def tearDown(self):
        if isinstance(QDB_FIXTURE, QuestDbFixture) and QDB_FIXTURE._proc:
            for name in self._created_tables:
                self._drop_table_if_exists(name)
            QDB_FIXTURE.http_sql_query(
                f'select * from long_sequence(1) -- <<<<<<<<< END PYTHON UNIT TEST: {self.id()}')

    def _require_fuzz_fixture(self):
        self._require_qwp_ws_protocol()
        if isinstance(QDB_FIXTURE, QuestDbFixture):
            # Same repo-only gate as TestQwpWsRestart: the release-matrix server
            # builds on the fixed version list do not expose QWP/WebSocket.
            root_dir = getattr(QDB_FIXTURE, '_root_dir', None)
            if root_dir is not None and root_dir.name != 'repo':
                self.skipTest('QWP/WebSocket fuzz tests require a QuestDB repo fixture')
            if QDB_FIXTURE.http:
                self.skipTest('QWP/WebSocket fuzz tests run outside the HTTP ILP matrix')
        elif not isinstance(QDB_FIXTURE, QuestDbExternalFixture):
            self.skipTest('QWP/WebSocket fuzz tests require a managed or --existing QuestDB fixture')
        if QDB_FIXTURE.auth:
            self.skipTest('QWP/WebSocket fuzz tests run without auth')
        if getattr(QDB_FIXTURE, 'http_auth', False):
            self.skipTest('QWP/WebSocket fuzz tests run without HTTP auth')

    @staticmethod
    def _is_windows():
        return qwp_ws_fuzz.is_windows()

    def _log(self, msg: str):
        sys.stderr.write(f'[qwp_ws_fuzz] {msg}\n')
        sys.stderr.flush()

    def _list_columns(self, table_name: str):
        try:
            resp = sql_query(f'SHOW COLUMNS FROM \'{table_name}\'')
        except Exception:
            return []
        cols = resp.get('columns') or []
        dataset = resp.get('dataset') or []
        name_idx = type_idx = None
        for i, c in enumerate(cols):
            if c.get('name') == 'column':
                name_idx = i
            elif c.get('name') == 'type':
                type_idx = i
        if name_idx is None or type_idx is None:
            return []
        return [
            {'name': row[name_idx], 'type': row[type_idx]}
            for row in dataset
        ]

    def _query_table_sorted(self, table_name: str):
        # Verifies through the QWP egress reader, not /exec REST. /exec
        # renders BINARY columns as the literal JSON `[]` (see
        # JsonQueryProcessorState.putBinValue in QuestDB), which would make
        # every BINARY round-trip fail regardless of what the sender wrote.
        # Reading through the QWP egress reader exercises the column types we
        # actually ingest end-to-end. Values come back in the same Python
        # shape /exec used to return, with BINARY as real bytes that
        # format_actual_cell can hex-encode.
        import qwp_egress_reader
        # The reader's connect-string scheme is `ws::` (egress side), distinct
        # from the sender's `qwpws::` (ingress side) — both hit the HTTP port.
        conf = f'ws::addr={QDB_FIXTURE.host}:{QDB_FIXTURE.http_server_port};'
        return qwp_egress_reader.query_table_sorted(conf, table_name)

    def _wait_for_row_count(self, table_name: str, expected: int):
        deadline = time.monotonic() + self.DRAIN_TIMEOUT_SEC
        last = -1
        last_error = None
        while time.monotonic() < deadline:
            try:
                resp = sql_query(f'SELECT count() FROM \'{table_name}\'')
                row = (resp.get('dataset') or [[0]])[0]
                last = int(row[0])
                if last >= expected:
                    return last
            except Exception as e:  # noqa: BLE001 — table may not exist yet
                last_error = e
            time.sleep(self.POLL_INTERVAL_SEC)
        self.fail(
            f'[{self._seed_label}] timed out waiting for {expected} rows in '
            f'{table_name!r}; last_count={last}, last_error={last_error!r}')

    def _drop_table_if_exists(self, table_name: str):
        try:
            sql_query(f'DROP TABLE IF EXISTS \'{table_name}\'')
        except Exception as e:  # noqa: BLE001 — table may already be absent
            self._log(f'DROP TABLE IF EXISTS {table_name!r} ignored: {e}')

    @staticmethod
    def _create_dedup_fuzz_table(table_name: str):
        # Failover tests bounce the server mid-stream, which forces the
        # QWP/WS sender to replay any sent-but-not-yet-acked FSN range
        # after reconnect. The protocol is at-least-once on the wire,
        # so the server can see byte-identical re-transmits of rows it
        # already persisted. Pre-create with DEDUP UPSERT KEYS on the
        # designated TIMESTAMP column — every fuzz row gets a globally
        # unique µs timestamp from the harness's locked counter, so
        # dedup-by-timestamp collapses retransmits while leaving
        # legitimate rows untouched. Additional columns are added by
        # ILP on first sight.
        sql_query(
            f'CREATE TABLE \'{table_name}\' '
            '(timestamp TIMESTAMP) '
            'TIMESTAMP(timestamp) PARTITION BY DAY WAL '
            'DEDUP UPSERT KEYS(timestamp)')

    def _run_fuzz(self, load: 'qwp_ws_fuzz.LoadParams',
                  fuzz: 'qwp_ws_fuzz.FuzzParams'):
        # Pre-create per-table buffers. Java keys by lowercase name (case-
        # insensitive) so 'WEATHER0' and 'weather0' resolve to the same
        # table on both client- and server-side.
        tables = {}
        for i in range(load.num_of_tables):
            name = qwp_ws_fuzz.canonical_table_name(i)
            tables[name] = qwp_ws_fuzz.TableData(name)
            self._drop_table_if_exists(name)
            if fuzz.max_bounces > 0:
                self._create_dedup_fuzz_table(name)
            self._created_tables.append(name)

        run_id = uuid.uuid4().hex[:8]
        timestamp_us = [self.BASE_TIMESTAMP_US]
        ts_lock = threading.Lock()

        def next_ts():
            with ts_lock:
                timestamp_us[0] += 1
                return timestamp_us[0]

        failure_counter = [0]
        failure_messages = []
        fail_lock = threading.Lock()

        def record_failure(msg: str):
            with fail_lock:
                failure_messages.append(msg)
                failure_counter[0] += 1
            self._log(msg)

        if fuzz.max_bounces > 0 and not (
                hasattr(QDB_FIXTURE, 'stop') and hasattr(QDB_FIXTURE, 'start')):
            self.skipTest(
                'bounce fuzz tests require a managed QuestDB fixture '
                'with stop()/start() control')

        producers_done = threading.Event()
        stop_event = threading.Event()

        with tempfile.TemporaryDirectory(prefix='qwp-ws-fuzz-') as sf_root:
            producer_threads = []
            for thread_index in range(load.num_of_threads):
                thread_seed_rng = self._master_rng.child()
                sender_id = f'fuzz-{run_id}-t{thread_index}'
                producer_sf = os.path.join(sf_root, f'producer-{thread_index}')
                os.makedirs(producer_sf, exist_ok=True)
                thread = threading.Thread(
                    target=self._producer_loop,
                    name=f'qwp-ws-fuzz-producer-{thread_index}',
                    args=(
                        sender_id, producer_sf, load, fuzz, thread_seed_rng,
                        tables, next_ts, record_failure))
                producer_threads.append(thread)
                thread.start()

            alter_thread = None
            if fuzz.column_convert_prob > 0:
                budget = max(1, int(
                    load.num_of_lines
                    * load.num_of_tables
                    * fuzz.column_convert_prob))
                alter_thread = qwp_ws_fuzz.AlterThread(
                    sql_query=sql_query,
                    list_columns=self._list_columns,
                    tables=list(tables.keys()),
                    convert_budget=budget,
                    rnd=self._master_rng.child(),
                    producers_done=producers_done,
                    stop_event=stop_event,
                    record_failure=record_failure,
                    failure_counter=failure_counter,
                    log=self._log)
                alter_thread.start()

            bounce_thread = None
            if fuzz.max_bounces > 0:
                bounce_thread = qwp_ws_fuzz.BounceThread(
                    fixture=QDB_FIXTURE,
                    rnd=self._master_rng.child(),
                    max_bounces=fuzz.max_bounces,
                    min_interval_s=fuzz.min_bounce_interval_s,
                    max_interval_s=fuzz.max_bounce_interval_s,
                    stop_timeout_s=fuzz.bounce_stop_timeout_s,
                    writers_done=producers_done,
                    stop_event=stop_event,
                    record_failure=record_failure,
                    failure_counter=failure_counter,
                    log=self._log)
                bounce_thread.start()

            try:
                for thread in producer_threads:
                    thread.join()
            finally:
                producers_done.set()

            if alter_thread is not None:
                alter_thread.join(timeout=30)
                if alter_thread.is_alive():
                    stop_event.set()
                    alter_thread.join(timeout=30)

            if bounce_thread is not None:
                # Bounces are inherently slower (process restart + HTTP-up
                # wait), so give the thread a generous wind-down budget.
                bounce_thread.join(timeout=60)
                if bounce_thread.is_alive():
                    stop_event.set()
                    bounce_thread.join(timeout=60)
                if bounce_thread.bounces_performed > 0:
                    self._log(
                        f'fuzz bounce summary: '
                        f'{bounce_thread.bounces_performed}'
                        f'/{fuzz.max_bounces} performed')

        self.assertEqual(
            failure_counter[0], 0,
            f'[{self._seed_label}] producer/alter/bounce failures: '
            f'{failure_messages}')

        for name, table in tables.items():
            expected = table.valid_count()
            if expected == 0:
                continue
            self._wait_for_row_count(name, expected)

        for name, table in tables.items():
            if table.valid_count() == 0:
                continue
            columns, rows = self._query_table_sorted(name)
            try:
                qwp_ws_fuzz.compare_table(
                    table=table,
                    server_columns=columns,
                    server_rows=rows,
                    seed_label=self._seed_label)
            except qwp_ws_fuzz.TableMismatch as e:
                self.fail(str(e))

    def _producer_loop(self, sender_id, sf_root, load, fuzz, rnd,
                       tables, next_ts, record_failure):
        # `reconnect_max_duration_millis` is the explicit knob; the
        # library auto-promotes `initial_connect_retry` to `sync` when
        # any `reconnect_*` key is set, so a producer that races a
        # bounce reuses the same 120s budget on its very first connect
        # instead of getting one shot.
        conf = self._sender_conf(
            sender_id,
            sf_root,
            # Bounce tests can SIGTERM the server before every producer has
            # finished its initial connect. Without retry on the initial
            # connect, the producer that races the bounce fails fast with
            # an upgrade-response read error. `sync` makes the constructor
            # wait through the bounce up to reconnect_max_duration_millis.
            initial_connect_retry='sync',
            reconnect_max_duration_millis=120000,
            # The bounce tests restart the server faster than the reconnect
            # backoff cap can track, so the client keeps backing off and
            # misses the brief windows the server is up between restarts —
            # close_drain then can't drain and times out. A tighter cap keeps
            # reconnect attempts landing inside those windows. (Harmless for
            # the non-bounce tests, which never reconnect, so the backoff
            # never engages.)
            reconnect_max_backoff_millis=250,
            # 2 min on close_drain — bounce-test variants need a long
            # enough budget for SFA to replay queued frames into a
            # freshly-restarted server.
            close_flush_timeout_millis=120000)
        try:
            sender = self._connect_sender(conf)
        except Exception as e:  # noqa: BLE001
            record_failure(f'connect failed for {sender_id}: {e}')
            return
        try:
            points = 0
            for _ in range(load.num_of_iterations):
                for _ in range(load.num_of_lines):
                    table_name = qwp_ws_fuzz.pick_table_name(
                        load.num_of_tables, rnd)
                    table_data = tables[table_name.lower()]
                    line = qwp_ws_fuzz.generate_line(
                        table_name, sender, fuzz, next_ts(), rnd,
                        table_data)
                    table_data.add_line(line)
                    points += 1
                    if points % qwp_ws_fuzz.BATCH_SIZE == 0:
                        sender.flush()
                sender.flush()
                if load.wait_between_iterations_ms > 0:
                    time.sleep(load.wait_between_iterations_ms / 1000.0)
            sender.close_drain()
        except Exception as e:  # noqa: BLE001
            record_failure(f'producer {sender_id} failed: {e}')
        finally:
            try:
                sender.close(False)
            except Exception:  # noqa: BLE001
                pass

    def _r(self):
        """Shorthand alias for the master RNG used in test parameterization."""
        return self._master_rng

    def test_add_columns(self):
        r = self._r()
        load = qwp_ws_fuzz.LoadParams(
            num_of_lines=15 + r.next_int(100),
            num_of_iterations=5 + r.next_int(5),
            num_of_threads=2 + r.next_int(5 if self._is_windows() else 20),
            num_of_tables=1 + r.next_int(4),
            wait_between_iterations_ms=r.next_int(75))
        fuzz = qwp_ws_fuzz.FuzzParams(
            column_reordering_factor=-1,
            column_skip_factor=1,
            new_column_factor=1 + r.next_int(3),
            non_ascii_value_factor=6,
            diff_cases_in_col_names=False,
            exercise_symbols=True,
            send_symbols_with_space=False,
            column_convert_prob=0.1)
        self._run_fuzz(load, fuzz)

    def test_add_columns_no_symbols(self):
        load = qwp_ws_fuzz.LoadParams(15, 2, 2, 5, 75)
        fuzz = qwp_ws_fuzz.FuzzParams(
            column_reordering_factor=-1,
            column_skip_factor=-1,
            new_column_factor=4,
            non_ascii_value_factor=3,
            diff_cases_in_col_names=True,
            exercise_symbols=False,
            send_symbols_with_space=False,
            column_convert_prob=0.15)
        self._run_fuzz(load, fuzz)

    def test_add_convert_columns(self):
        load = qwp_ws_fuzz.LoadParams(15, 2, 2, 5, 75)
        fuzz = qwp_ws_fuzz.FuzzParams(
            column_reordering_factor=-1,
            column_skip_factor=-1,
            new_column_factor=4,
            non_ascii_value_factor=-1,
            diff_cases_in_col_names=False,
            exercise_symbols=True,
            send_symbols_with_space=True,
            column_convert_prob=0.2)
        self._run_fuzz(load, fuzz)

    def test_all_mixed(self):
        load = qwp_ws_fuzz.LoadParams(
            50, 3 if self._is_windows() else 5, 5, 5, 50)
        fuzz = qwp_ws_fuzz.FuzzParams(
            duplicates_factor=3,
            column_reordering_factor=4,
            column_skip_factor=5,
            new_column_factor=10,
            non_ascii_value_factor=5,
            diff_cases_in_col_names=True,
            exercise_symbols=True,
            send_symbols_with_space=True,
            column_convert_prob=0.05)
        self._run_fuzz(load, fuzz)

    def test_all_mixed_no_symbols(self):
        load = qwp_ws_fuzz.LoadParams(
            50, 3 if self._is_windows() else 5, 5, 5, 50)
        fuzz = qwp_ws_fuzz.FuzzParams(
            duplicates_factor=3,
            column_reordering_factor=4,
            column_skip_factor=5,
            new_column_factor=10,
            non_ascii_value_factor=5,
            diff_cases_in_col_names=True,
            exercise_symbols=False,
            send_symbols_with_space=True,
            column_convert_prob=0.05)
        self._run_fuzz(load, fuzz)

    def test_all_mixed_single_table(self):
        load = qwp_ws_fuzz.LoadParams(
            50, 3 if self._is_windows() else 5, 5, 1, 50)
        fuzz = qwp_ws_fuzz.FuzzParams(
            duplicates_factor=3,
            column_reordering_factor=4,
            column_skip_factor=5,
            new_column_factor=10,
            non_ascii_value_factor=5,
            diff_cases_in_col_names=True,
            exercise_symbols=True,
            send_symbols_with_space=True,
            column_convert_prob=0.05)
        self._run_fuzz(load, fuzz)

    def test_all_mixed_split_part(self):
        load = qwp_ws_fuzz.LoadParams(
            50, 3 if self._is_windows() else 5, 5, 1, 50)
        fuzz = qwp_ws_fuzz.FuzzParams(
            column_reordering_factor=-1,
            column_skip_factor=-1,
            new_column_factor=-1,
            non_ascii_value_factor=10,
            diff_cases_in_col_names=False,
            exercise_symbols=True,
            send_symbols_with_space=False,
            column_convert_prob=0.05)
        self._run_fuzz(load, fuzz)

    def test_case_variation_reordering_columns(self):
        load = qwp_ws_fuzz.LoadParams(
            100, 3 if self._is_windows() else 5, 5, 5, 50)
        fuzz = qwp_ws_fuzz.FuzzParams(
            column_reordering_factor=4,
            column_skip_factor=-1,
            new_column_factor=2,
            non_ascii_value_factor=-1,
            diff_cases_in_col_names=True,
            exercise_symbols=True,
            send_symbols_with_space=False)
        self._run_fuzz(load, fuzz)

    def test_case_variation_reordering_columns_no_symbols(self):
        load = qwp_ws_fuzz.LoadParams(
            100, 3 if self._is_windows() else 5, 5, 5, 50)
        fuzz = qwp_ws_fuzz.FuzzParams(
            column_reordering_factor=4,
            column_skip_factor=-1,
            new_column_factor=-1,
            non_ascii_value_factor=-1,
            diff_cases_in_col_names=True,
            exercise_symbols=False,
            send_symbols_with_space=False)
        self._run_fuzz(load, fuzz)

    def test_case_variation_reordering_columns_send_symbols_with_space(self):
        load = qwp_ws_fuzz.LoadParams(
            100, 3 if self._is_windows() else 5, 5, 5, 50)
        fuzz = qwp_ws_fuzz.FuzzParams(
            column_reordering_factor=4,
            column_skip_factor=-1,
            new_column_factor=3,
            non_ascii_value_factor=-1,
            diff_cases_in_col_names=True,
            exercise_symbols=True,
            send_symbols_with_space=True)
        self._run_fuzz(load, fuzz)

    def test_duplicates_reordering_columns(self):
        load = qwp_ws_fuzz.LoadParams(
            100, 3 if self._is_windows() else 5, 5, 5, 50)
        fuzz = qwp_ws_fuzz.FuzzParams(
            duplicates_factor=4,
            column_reordering_factor=4,
            column_skip_factor=-1,
            new_column_factor=-1,
            non_ascii_value_factor=-1,
            diff_cases_in_col_names=True,
            exercise_symbols=True,
            send_symbols_with_space=False,
            column_convert_prob=0.05)
        self._run_fuzz(load, fuzz)

    def test_duplicates_reordering_columns_no_symbols(self):
        load = qwp_ws_fuzz.LoadParams(
            100, 3 if self._is_windows() else 5, 5, 5, 50)
        fuzz = qwp_ws_fuzz.FuzzParams(
            duplicates_factor=4,
            column_reordering_factor=4,
            column_skip_factor=-1,
            new_column_factor=-1,
            non_ascii_value_factor=-1,
            diff_cases_in_col_names=True,
            exercise_symbols=False,
            send_symbols_with_space=False,
            column_convert_prob=0.05)
        self._run_fuzz(load, fuzz)

    def test_duplicates_reordering_columns_send_symbols_with_space(self):
        load = qwp_ws_fuzz.LoadParams(
            100, 3 if self._is_windows() else 5, 5, 5, 50)
        fuzz = qwp_ws_fuzz.FuzzParams(
            duplicates_factor=4,
            column_reordering_factor=4,
            column_skip_factor=-1,
            new_column_factor=-1,
            non_ascii_value_factor=-1,
            diff_cases_in_col_names=True,
            exercise_symbols=True,
            send_symbols_with_space=True,
            column_convert_prob=0.05)
        self._run_fuzz(load, fuzz)

    def test_load(self):
        load = qwp_ws_fuzz.LoadParams(
            100, 3 if self._is_windows() else 5, 7, 12, 20)
        fuzz = qwp_ws_fuzz.FuzzParams()
        self._run_fuzz(load, fuzz)

    def test_load_large_payload(self):
        load = qwp_ws_fuzz.LoadParams(
            500, 3 if self._is_windows() else 5, 5, 5, 10)
        fuzz = qwp_ws_fuzz.FuzzParams()
        self._run_fuzz(load, fuzz)

    def test_load_no_symbols(self):
        load = qwp_ws_fuzz.LoadParams(
            100, 3 if self._is_windows() else 5, 7, 12, 20)
        fuzz = qwp_ws_fuzz.FuzzParams(
            column_reordering_factor=-1,
            column_skip_factor=-1,
            new_column_factor=-1,
            non_ascii_value_factor=5,
            diff_cases_in_col_names=True,
            exercise_symbols=False,
            send_symbols_with_space=False,
            column_convert_prob=0.05)
        self._run_fuzz(load, fuzz)

    def test_load_send_symbols_with_space(self):
        load = qwp_ws_fuzz.LoadParams(
            100, 3 if self._is_windows() else 5, 4, 8, 20)
        fuzz = qwp_ws_fuzz.FuzzParams(
            column_reordering_factor=-1,
            column_skip_factor=-1,
            new_column_factor=2,
            non_ascii_value_factor=-1,
            diff_cases_in_col_names=False,
            exercise_symbols=True,
            send_symbols_with_space=True)
        self._run_fuzz(load, fuzz)

    def test_load_small_buffer(self):
        load = qwp_ws_fuzz.LoadParams(
            100, 3 if self._is_windows() else 5, 5, 5, 20)
        fuzz = qwp_ws_fuzz.FuzzParams()
        # Note: Java sets recvBufferSize=2048 on the server fixture; the
        # Python tests run against the standard server config, so this
        # variant exercises the same fuzz axes at smaller batch sizes only.
        self._run_fuzz(load, fuzz)

    def test_non_ascii_values(self):
        load = qwp_ws_fuzz.LoadParams(
            100, 3 if self._is_windows() else 5, 5, 5, 50)
        fuzz = qwp_ws_fuzz.FuzzParams(
            column_reordering_factor=-1,
            column_skip_factor=-1,
            new_column_factor=3,
            non_ascii_value_factor=4,
            diff_cases_in_col_names=False,
            exercise_symbols=True,
            send_symbols_with_space=False)
        self._run_fuzz(load, fuzz)

    def test_non_ascii_values_no_symbols(self):
        load = qwp_ws_fuzz.LoadParams(
            100, 3 if self._is_windows() else 5, 5, 5, 50)
        fuzz = qwp_ws_fuzz.FuzzParams(
            column_reordering_factor=-1,
            column_skip_factor=-1,
            new_column_factor=-1,
            non_ascii_value_factor=4,
            diff_cases_in_col_names=False,
            exercise_symbols=False,
            send_symbols_with_space=False)
        self._run_fuzz(load, fuzz)

    def test_reordering_columns(self):
        load = qwp_ws_fuzz.LoadParams(
            100, 3 if self._is_windows() else 5, 5, 5, 50)
        fuzz = qwp_ws_fuzz.FuzzParams(
            column_reordering_factor=4,
            column_skip_factor=-1,
            new_column_factor=-1,
            non_ascii_value_factor=8,
            diff_cases_in_col_names=False,
            exercise_symbols=True,
            send_symbols_with_space=True,
            column_convert_prob=0.05)
        self._run_fuzz(load, fuzz)

    def test_reordering_columns_no_symbols(self):
        load = qwp_ws_fuzz.LoadParams(
            100, 3 if self._is_windows() else 5, 5, 5, 50)
        fuzz = qwp_ws_fuzz.FuzzParams(
            column_reordering_factor=4,
            column_skip_factor=-1,
            new_column_factor=-1,
            non_ascii_value_factor=-1,
            diff_cases_in_col_names=True,
            exercise_symbols=False,
            send_symbols_with_space=False,
            column_convert_prob=0.05)
        self._run_fuzz(load, fuzz)

    def test_reordering_many_threads(self):
        r = self._r()
        load = qwp_ws_fuzz.LoadParams(
            num_of_lines=15 + r.next_int(100),
            num_of_iterations=5 + r.next_int(5),
            num_of_threads=2 + r.next_int(5 if self._is_windows() else 20),
            num_of_tables=1 + r.next_int(4),
            wait_between_iterations_ms=r.next_int(75))
        fuzz = qwp_ws_fuzz.FuzzParams(
            column_reordering_factor=3,
            column_skip_factor=-1,
            new_column_factor=1 + r.next_int(3),
            non_ascii_value_factor=-1,
            diff_cases_in_col_names=False,
            exercise_symbols=True,
            send_symbols_with_space=False)
        self._run_fuzz(load, fuzz)

    def test_reordering_non_ascii(self):
        load = qwp_ws_fuzz.LoadParams(
            100, 3 if self._is_windows() else 5, 5, 5, 50)
        fuzz = qwp_ws_fuzz.FuzzParams(
            column_reordering_factor=4,
            column_skip_factor=-1,
            new_column_factor=2,
            non_ascii_value_factor=4,
            diff_cases_in_col_names=False,
            exercise_symbols=True,
            send_symbols_with_space=False)
        self._run_fuzz(load, fuzz)

    def test_reordering_skip_columns_with_non_ascii(self):
        load = qwp_ws_fuzz.LoadParams(
            100, 3 if self._is_windows() else 5, 5, 5, 50)
        fuzz = qwp_ws_fuzz.FuzzParams(
            column_reordering_factor=4,
            column_skip_factor=4,
            new_column_factor=2,
            non_ascii_value_factor=4,
            diff_cases_in_col_names=True,
            exercise_symbols=True,
            send_symbols_with_space=False)
        self._run_fuzz(load, fuzz)

    def test_reordering_skip_columns_with_non_ascii_no_symbols(self):
        load = qwp_ws_fuzz.LoadParams(
            100, 3 if self._is_windows() else 5, 5, 5, 50)
        fuzz = qwp_ws_fuzz.FuzzParams(
            column_reordering_factor=4,
            column_skip_factor=4,
            new_column_factor=-1,
            non_ascii_value_factor=4,
            diff_cases_in_col_names=True,
            exercise_symbols=False,
            send_symbols_with_space=False)
        self._run_fuzz(load, fuzz)

    def test_reordering_skip_duplicate_columns_with_non_ascii(self):
        load = qwp_ws_fuzz.LoadParams(
            100, 3 if self._is_windows() else 5, 5, 5, 50)
        fuzz = qwp_ws_fuzz.FuzzParams(
            duplicates_factor=4,
            column_reordering_factor=4,
            column_skip_factor=4,
            new_column_factor=-1,
            non_ascii_value_factor=4,
            diff_cases_in_col_names=True,
            exercise_symbols=True,
            send_symbols_with_space=False,
            column_convert_prob=0.05)
        self._run_fuzz(load, fuzz)

    def test_reordering_skip_duplicate_columns_with_non_ascii_no_symbols(self):
        load = qwp_ws_fuzz.LoadParams(
            100, 3 if self._is_windows() else 5, 5, 5, 50)
        fuzz = qwp_ws_fuzz.FuzzParams(
            duplicates_factor=4,
            column_reordering_factor=4,
            column_skip_factor=4,
            new_column_factor=-1,
            non_ascii_value_factor=4,
            diff_cases_in_col_names=True,
            exercise_symbols=False,
            send_symbols_with_space=False,
            column_convert_prob=0.05)
        self._run_fuzz(load, fuzz)

    # --- Bounce-during-fuzz variants ----------------------------------
    #
    # Each variant stops + starts the QDB fixture at random intervals
    # while producers are mid-batch. The QWP/WebSocket sender's SFA
    # layer must keep queued frames durable across the bounce so all
    # producer-acknowledged rows still land on the other side.

    def test_load_with_bounce(self):
        # Pad the per-iteration wait so producers stay alive long enough
        # for the chaos thread to actually fire its bounces — without
        # the inter-iteration sleep, 5 threads × 5 iterations × 100
        # rows finishes in under a second and the bounce thread never
        # gets a chance to run.
        load = qwp_ws_fuzz.LoadParams(
            100, 5 if not self._is_windows() else 3, 5, 5, 400)
        fuzz = qwp_ws_fuzz.FuzzParams(
            max_bounces=3,
            min_bounce_interval_s=0.3,
            max_bounce_interval_s=1.5)
        self._run_fuzz(load, fuzz)

    def test_all_mixed_with_bounce(self):
        load = qwp_ws_fuzz.LoadParams(
            50, 5 if not self._is_windows() else 3, 5, 5, 400)
        fuzz = qwp_ws_fuzz.FuzzParams(
            duplicates_factor=3,
            column_reordering_factor=4,
            column_skip_factor=5,
            new_column_factor=10,
            non_ascii_value_factor=5,
            diff_cases_in_col_names=True,
            exercise_symbols=True,
            send_symbols_with_space=True,
            column_convert_prob=0.05,
            max_bounces=3,
            min_bounce_interval_s=0.3,
            max_bounce_interval_s=1.5)
        self._run_fuzz(load, fuzz)

    # --- Type-side coverage extensions --------------------------------
    #
    # Each variant tightens one of the value-shape axes flagged in the
    # review: unicode/emoji/RTL/empty/long strings, negative & large
    # decimals & integers, pre-1970 & far-future timestamps, negative
    # zero in arrays. The new fuzz factors all default to -1 in
    # FuzzParams so existing tests keep their established behaviour.

    def test_extreme_strings(self):
        load = qwp_ws_fuzz.LoadParams(
            80, 3 if self._is_windows() else 5, 4, 3, 30)
        fuzz = qwp_ws_fuzz.FuzzParams(
            column_reordering_factor=3,
            new_column_factor=4,
            non_ascii_value_factor=3,
            diff_cases_in_col_names=True,
            extreme_string_factor=2)
        self._run_fuzz(load, fuzz)

    def test_extreme_numerics(self):
        load = qwp_ws_fuzz.LoadParams(
            80, 3 if self._is_windows() else 5, 4, 3, 30)
        fuzz = qwp_ws_fuzz.FuzzParams(
            column_reordering_factor=3,
            new_column_factor=4,
            diff_cases_in_col_names=True,
            extreme_numeric_factor=2,
            negative_zero_factor=4)
        self._run_fuzz(load, fuzz)

    def test_extreme_timestamps(self):
        load = qwp_ws_fuzz.LoadParams(
            80, 3 if self._is_windows() else 5, 4, 3, 30)
        fuzz = qwp_ws_fuzz.FuzzParams(
            column_reordering_factor=3,
            extreme_timestamp_factor=2)
        self._run_fuzz(load, fuzz)

    def test_extreme_everything(self):
        load = qwp_ws_fuzz.LoadParams(
            80, 3 if self._is_windows() else 5, 4, 3, 30)
        fuzz = qwp_ws_fuzz.FuzzParams(
            duplicates_factor=4,
            column_reordering_factor=3,
            column_skip_factor=5,
            new_column_factor=4,
            non_ascii_value_factor=3,
            diff_cases_in_col_names=True,
            exercise_symbols=True,
            extreme_string_factor=3,
            extreme_numeric_factor=3,
            extreme_timestamp_factor=3,
            negative_zero_factor=4,
            column_convert_prob=0.05)
        self._run_fuzz(load, fuzz)

    def test_n_bounce_sweep(self):
        # Many short bounces so the chaos thread gets multiple chances
        # to land mid-flush. Each bounce is ~3-5s of process restart so
        # the test takes ~30-60s including the producers' SFA replay.
        load = qwp_ws_fuzz.LoadParams(
            100, 10 if not self._is_windows() else 6, 5, 5, 400)
        fuzz = qwp_ws_fuzz.FuzzParams(
            column_reordering_factor=4,
            new_column_factor=5,
            non_ascii_value_factor=4,
            diff_cases_in_col_names=True,
            exercise_symbols=True,
            send_symbols_with_space=False,
            max_bounces=10,
            min_bounce_interval_s=0.3,
            max_bounce_interval_s=1.2)
        self._run_fuzz(load, fuzz)


class TestQwpUdpSender(unittest.TestCase):
    def setUp(self):
        test_name = self.id()
        QDB_FIXTURE.http_sql_query(
            f'select * from long_sequence(1) -- >>>>>>>>> BEGIN PYTHON UNIT TEST: {test_name}')

    def tearDown(self):
        test_name = self.id()
        QDB_FIXTURE.http_sql_query(
            f'select * from long_sequence(1) -- <<<<<<<<< END PYTHON UNIT TEST: {test_name}')

    def _mk_qwpudp_sender(self, **kwargs):
        return qls.Sender(
            BUILD_MODE,
            qls.Protocol.QWPUDP,
            QDB_FIXTURE.host,
            QDB_FIXTURE.qwp_udp_port,
            **kwargs)

    @staticmethod
    def _micros_to_qdb_date(timestamp_us):
        secs, remaining_us = divmod(timestamp_us, 1_000_000)
        return datetime.datetime.fromtimestamp(
            secs, datetime.timezone.utc).replace(
            microsecond=remaining_us).strftime('%Y-%m-%dT%H:%M:%S.%fZ')

    @staticmethod
    def _nanos_to_qdb_date(timestamp_ns):
        secs, remaining_ns = divmod(timestamp_ns, 1_000_000_000)
        base = datetime.datetime.fromtimestamp(
            secs, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S')
        return f'{base}.{remaining_ns:09d}Z'

    def _require_qwp_udp_system_test(self):
        # TODO: Remove this repo-only gate once QWP/UDP receiver support is
        # available in released QuestDB builds.
        if not getattr(QDB_FIXTURE, 'qwp_udp', False):
            self.skipTest('QWP/UDP system test requires repo-backed QWP receiver support')
        if QDB_FIXTURE.http:
            self.skipTest('QWP/UDP test only runs in the non-HTTP pass')
        if QDB_FIXTURE.auth:
            self.skipTest('QWP/UDP auth is not supported')
        if (
                BUILD_MODE == qls.BuildMode.CONF and
                QDB_FIXTURE.protocol_version is not None):
            self.skipTest('QWP/UDP development system test uses no ILP protocol version override')

    def _test_qwp_udp_example(
            self,
            bin_name,
            table_name,
            expected_rows,
            expected_columns=None):
        self._require_qwp_udp_system_test()
        if BUILD_MODE != qls.BuildMode.API:
            self.skipTest('BuildMode.API-only test')

        proj = Project()
        ext = '.exe' if sys.platform == 'win32' else ''
        try:
            bin_path = next(proj.build_dir.glob(f'**/{bin_name}{ext}'))
        except StopIteration:
            raise RuntimeError(f'Could not find {bin_name}{ext} in {proj.build_dir}')

        args = [
            str(bin_path),
            '127.0.0.1',
            str(QDB_FIXTURE.qwp_udp_port),
            table_name]
        subprocess.check_call(args, cwd=bin_path.parent)

        resp = retry_check_table(
            table_name, min_rows=len(expected_rows), timeout_sec=30)
        if expected_columns is None:
            expected_columns = [
                {'name': 'host', 'type': 'SYMBOL'},
                {'name': 'active', 'type': 'BOOLEAN'},
                {'name': 'qty', 'type': 'LONG'},
                {'name': 'temp', 'type': 'DOUBLE'},
                {'name': 'note', 'type': 'VARCHAR'},
                {'name': 'timestamp', 'type': 'TIMESTAMP'},
            ]
        self.assertEqual(resp['columns'], expected_columns)
        self.assertEqual(
            sorted(row[:-1] for row in resp['dataset']),
            sorted(expected_rows))

    def test_c_example_qwp_udp(self):
        table_name = 'c_qwp_ex_' + uuid.uuid4().hex[:8]
        self._test_qwp_udp_example(
            'line_sender_c_example_qwpudp',
            table_name,
            [[
                'srv-api',
                True,
                7,
                3,
                9009,
                42,
                21.5,
                21.5,
                '090a0b0c-0d0e-0f10-0102-030405060708',
                '2023-11-14T22:13:20.000Z',
                '1.25',
                'kxb2v',
                'example-row',
            ]],
            [
                {'name': 'host', 'type': 'SYMBOL'},
                {'name': 'active', 'type': 'BOOLEAN'},
                {'name': 'qty', 'type': 'LONG'},
                {'name': 'retries', 'type': 'BYTE'},
                {'name': 'port', 'type': 'SHORT'},
                {'name': 'region', 'type': 'INT'},
                {'name': 'temp', 'type': 'DOUBLE'},
                {'name': 'temp_f', 'type': 'FLOAT'},
                {'name': 'trace_id', 'type': 'UUID'},
                {'name': 'first_seen', 'type': 'DATE'},
                {'name': 'price', 'type': 'DECIMAL(18,2)'},
                {'name': 'loc', 'type': 'GEOHASH(5c)'},
                {'name': 'note', 'type': 'VARCHAR'},
                {'name': 'timestamp', 'type': 'TIMESTAMP'},
            ])

    def test_cpp_example_qwp_udp(self):
        table_name = 'cpp_qwp_ex_' + uuid.uuid4().hex[:8]
        self._test_qwp_udp_example(
            'line_sender_cpp_example_qwpudp',
            table_name,
            [[
                'srv-api',
                True,
                7,
                3,
                9009,
                42,
                21.5,
                21.5,
                '090a0b0c-0d0e-0f10-0102-030405060708',
                '2023-11-14T22:13:20.000Z',
                '1.25',
                'kxb2v',
                'example-row',
            ]],
            [
                {'name': 'host', 'type': 'SYMBOL'},
                {'name': 'active', 'type': 'BOOLEAN'},
                {'name': 'qty', 'type': 'LONG'},
                {'name': 'retries', 'type': 'BYTE'},
                {'name': 'port', 'type': 'SHORT'},
                {'name': 'region', 'type': 'INT'},
                {'name': 'temp_f', 'type': 'FLOAT'},
                {'name': 'temp', 'type': 'DOUBLE'},
                {'name': 'trace_id', 'type': 'UUID'},
                {'name': 'first_seen', 'type': 'DATE'},
                {'name': 'price', 'type': 'DECIMAL(18,2)'},
                {'name': 'loc', 'type': 'GEOHASH(5c)'},
                {'name': 'note', 'type': 'VARCHAR'},
                {'name': 'timestamp', 'type': 'TIMESTAMP'},
            ])

    def test_c_batch_example_qwp_udp(self):
        table_name = 'c_qwp_bt_' + uuid.uuid4().hex[:8]
        self._test_qwp_udp_example(
            'line_sender_c_example_qwpudp_batch',
            table_name,
            [
                ['srv-a', True, 1, 20.5, 'batch-a'],
                ['srv-b', False, 2, 22.5, 'batch-b'],
            ])

    def test_cpp_batch_example_qwp_udp(self):
        table_name = 'cpp_qwp_bt_' + uuid.uuid4().hex[:8]
        self._test_qwp_udp_example(
            'line_sender_cpp_example_qwpudp_batch',
            table_name,
            [
                ['srv-a', True, 1, 20.5, 'batch-a'],
                ['srv-b', False, 2, 22.5, 'batch-b'],
            ])

    def test_insert_rows_over_qwp_udp(self):
        self._require_qwp_udp_system_test()

        table_name = 'qwp_udp_' + uuid.uuid4().hex
        with self._mk_qwpudp_sender() as sender:
            self.assertEqual(sender.protocol, qls.Protocol.QWPUDP)
            for i in range(3):
                (sender
                 .table(table_name)
                 .symbol('host', f'srv-{i}')
                 .column('active', i % 2 == 0)
                 .column('qty', i + 1)
                 .column('temp', 20.5 + i)
                 .column('note', f'row-{i}')
                 .at_micros(1_700_000_000_000_000 + i))
            sender.flush()

        resp = retry_check_table(table_name, min_rows=3, timeout_sec=30)
        exp_columns = [
            {'name': 'host', 'type': 'SYMBOL'},
            {'name': 'active', 'type': 'BOOLEAN'},
            {'name': 'qty', 'type': 'LONG'},
            {'name': 'temp', 'type': 'DOUBLE'},
            {'name': 'note', 'type': 'VARCHAR'},
            {'name': 'timestamp', 'type': 'TIMESTAMP'}]
        self.assertEqual(resp['columns'], exp_columns)

        scrubbed_dataset = [row[:-1] for row in resp['dataset']]
        self.assertEqual(
            scrubbed_dataset,
            [
                ['srv-0', True, 1, 20.5, 'row-0'],
                ['srv-1', False, 2, 21.5, 'row-1'],
                ['srv-2', True, 3, 22.5, 'row-2'],
            ])

    def test_f64_array_columns_round_trip_over_qwp_udp(self):
        self._require_qwp_udp_system_test()
        if QDB_FIXTURE.version < FIRST_ARRAYS_RELEASE:
            self.skipTest('No array support in this version of QuestDB.')

        table_name = 'qwp_arr_' + uuid.uuid4().hex[:8]
        array1 = np.array(
            [
                [[1.1, 2.2], [3.3, 4.4]],
                [[5.5, 6.6], [7.7, 8.8]]
            ],
            dtype=np.float64
        )
        array2 = array1.T
        array3 = array1[::-1, ::-1]

        with self._mk_qwpudp_sender() as sender:
            (sender
             .table(table_name)
             .column_f64_arr('f64_arr1', array1)
             .column_f64_arr('f64_arr2', array2)
             .column_f64_arr('f64_arr3', array3)
             .at_now())
            sender.flush()

        resp = retry_check_table(table_name, min_rows=1, timeout_sec=30)
        exp_columns = [
            {'dim': 3, 'elemType': 'DOUBLE', 'name': 'f64_arr1', 'type': 'ARRAY'},
            {'dim': 3, 'elemType': 'DOUBLE', 'name': 'f64_arr2', 'type': 'ARRAY'},
            {'dim': 3, 'elemType': 'DOUBLE', 'name': 'f64_arr3', 'type': 'ARRAY'},
            {'name': 'timestamp', 'type': 'TIMESTAMP'}]
        self.assertEqual(resp['columns'], exp_columns)
        expected_data = [[[[[1.1, 2.2], [3.3, 4.4]], [[5.5, 6.6], [7.7, 8.8]]],
                          [[[1.1, 5.5], [3.3, 7.7]], [[2.2, 6.6], [4.4, 8.8]]],
                          [[[7.7, 8.8], [5.5, 6.6]], [[3.3, 4.4], [1.1, 2.2]]]]]
        scrubbed_data = [row[:-1] for row in resp['dataset']]
        self.assertEqual(scrubbed_data, expected_data)

    def test_decimal_columns_round_trip_over_qwp_udp(self):
        self._require_qwp_udp_system_test()
        if QDB_FIXTURE.version < DECIMAL_RELEASE:
            self.skipTest('No decimal support in this version of QuestDB.')

        table_name = 'qwp_dec_' + uuid.uuid4().hex[:8]
        sql_query(
            f"CREATE TABLE '{table_name}' ("
            "d DECIMAL(18,4), "
            "ts TIMESTAMP"
            ") TIMESTAMP(ts) PARTITION BY DAY WAL")

        decimals = [
            Decimal("0.0015"),
            Decimal("-3.45"),
            Decimal("1.2"),
            Decimal("NaN"),
            Decimal("Infinity"),
            Decimal("-0"),
        ]
        base_ts = 1_700_000_000_000_000

        with self._mk_qwpudp_sender() as sender:
            for idx, dec in enumerate(decimals):
                (sender
                 .table(table_name)
                 .column('d', dec)
                 .at_micros(base_ts + idx))
            sender.flush()

        resp = retry_check_table(table_name, min_rows=len(decimals), timeout_sec=30)
        self.assertEqual(
            resp['columns'],
            [
                {'name': 'd', 'type': 'DECIMAL(18,4)'},
                {'name': 'ts', 'type': 'TIMESTAMP'},
            ])

        resp = sql_query(f"select d from '{table_name}' order by ts")
        self.assertEqual(
            [row[0] for row in resp['dataset']],
            ['0.0015', '-3.4500', '1.2000', None, None, '0.0000'])

    def test_decimal_signed_overflow_is_rejected_over_qwp_udp(self):
        self._require_qwp_udp_system_test()
        if QDB_FIXTURE.version < DECIMAL_RELEASE:
            self.skipTest('No decimal support in this version of QuestDB.')

        table_name = 'qwp_dec_over_' + uuid.uuid4().hex[:8]
        with self._mk_qwpudp_sender() as sender:
            (sender
             .table(table_name)
             .column('d', QWP_DECIMAL256_POSITIVE_OVERFLOW)
             .at_now())
            with self.assertRaisesRegex(qls.SenderError, r'.*signed DECIMAL256 range.*'):
                sender.flush()

    def test_decimal_signed_rescale_overflow_is_rejected_over_qwp_udp(self):
        self._require_qwp_udp_system_test()
        if QDB_FIXTURE.version < DECIMAL_RELEASE:
            self.skipTest('No decimal support in this version of QuestDB.')

        table_name = 'qwp_dec_scale_' + uuid.uuid4().hex[:8]
        with self._mk_qwpudp_sender() as sender:
            (sender
             .table(table_name)
             .column('d', Decimal('0.1'))
             .at_now())
            (sender
             .table(table_name)
             .column('d', QWP_DECIMAL256_SIGNED_RESCALE_OVERFLOW_BASE)
             .at_now())
            with self.assertRaisesRegex(qls.SenderError, r'.*signed DECIMAL256 range.*'):
                sender.flush()

    def test_insert_rows_over_qwp_udp_with_mixed_at_now(self):
        self._require_qwp_udp_system_test()

        first_ts_us = 1_700_000_000_000_000
        third_ts_us = 1_700_000_000_100_000
        table_name = 'qwp_udp_at_now_' + uuid.uuid4().hex
        with self._mk_qwpudp_sender() as sender:
            (sender
             .table(table_name)
             .symbol('host', 'exp-a')
             .column('qty', 1)
             .at_micros(first_ts_us))
            (sender
             .table(table_name)
             .symbol('host', 'srv-now')
             .column('qty', 2)
             .at_now())
            (sender
             .table(table_name)
             .symbol('host', 'exp-b')
             .column('qty', 3)
             .at_micros(third_ts_us))
            sender.flush()

        retry_check_table(table_name, min_rows=3, timeout_sec=30)
        resp = sql_query(
            f"select host, qty, timestamp from '{table_name}' order by host")
        self.assertEqual(
            resp['columns'],
            [
                {'name': 'host', 'type': 'SYMBOL'},
                {'name': 'qty', 'type': 'LONG'},
                {'name': 'timestamp', 'type': 'TIMESTAMP'},
            ])

        rows_by_host = {row[0]: row[1:] for row in resp['dataset']}
        self.assertEqual(
            rows_by_host['exp-a'],
            [1, self._micros_to_qdb_date(first_ts_us)])
        self.assertEqual(
            rows_by_host['exp-b'],
            [3, self._micros_to_qdb_date(third_ts_us)])

        server_row = rows_by_host['srv-now']
        self.assertEqual(server_row[0], 2)
        self.assertIsInstance(server_row[1], str)
        self.assertTrue(server_row[1].endswith('Z'))
        self.assertNotEqual(server_row[1], self._micros_to_qdb_date(first_ts_us))
        self.assertNotEqual(server_row[1], self._micros_to_qdb_date(third_ts_us))

    def test_flush_and_keep_resends_rows_over_qwp_udp(self):
        self._require_qwp_udp_system_test()

        row_ts_us = 1_700_000_000_200_000
        table_name = 'qwp_udp_keep_' + uuid.uuid4().hex
        with self._mk_qwpudp_sender() as sender:
            (sender
             .table(table_name)
             .symbol('host', 'dup-host')
             .column('qty', 7)
             .at_micros(row_ts_us))
            sender.flush(sender.buffer, clear=False)
            sender.flush()

        resp = retry_check_table(table_name, min_rows=2, timeout_sec=30)
        self.assertEqual(
            resp['columns'],
            [
                {'name': 'host', 'type': 'SYMBOL'},
                {'name': 'qty', 'type': 'LONG'},
                {'name': 'timestamp', 'type': 'TIMESTAMP'},
            ])

        self.assertEqual(
            resp['dataset'],
            [
                ['dup-host', 7, self._micros_to_qdb_date(row_ts_us)],
                ['dup-host', 7, self._micros_to_qdb_date(row_ts_us)],
            ])

    def test_small_max_datagram_size_splits_qwp_udp_flush(self):
        self._require_qwp_udp_system_test()

        table_name = 'q' + uuid.uuid4().hex[:8]
        with self._mk_qwpudp_sender(max_datagram_size=58) as sender:
            (sender
             .table(table_name)
             .symbol('sym', 'ETH-USD')
             .column('qty', 1)
             .at_now())
            (sender
             .table(table_name)
             .symbol('sym', 'BTC-USD')
             .column('qty', 2)
             .at_now())
            sender.flush()

        resp = retry_check_table(table_name, min_rows=2, timeout_sec=30)
        self.assertEqual(
            resp['columns'],
            [
                {'name': 'sym', 'type': 'SYMBOL'},
                {'name': 'qty', 'type': 'LONG'},
                {'name': 'timestamp', 'type': 'TIMESTAMP'},
            ])

        scrubbed_dataset = sorted(row[:-1] for row in resp['dataset'])
        self.assertEqual(
            scrubbed_dataset,
            [
                ['BTC-USD', 2],
                ['ETH-USD', 1],
            ])

    def test_switching_tables_and_back_preserves_qwp_udp_rows(self):
        self._require_qwp_udp_system_test()

        trades_table = 'qwp_tr_' + uuid.uuid4().hex[:8]
        quotes_table = 'qwp_qt_' + uuid.uuid4().hex[:8]
        with self._mk_qwpudp_sender() as sender:
            (sender
             .table(trades_table)
             .symbol('sym', 'ETH-USD')
             .column('qty', 1)
             .at_now())
            (sender
             .table(quotes_table)
             .symbol('sym', 'BTC-USD')
             .column('qty', 2)
             .at_now())
            (sender
             .table(trades_table)
             .symbol('sym', 'SOL-USD')
             .column('qty', 3)
             .at_now())
            sender.flush()

        trades_resp = retry_check_table(trades_table, min_rows=2, timeout_sec=30)
        quotes_resp = retry_check_table(quotes_table, min_rows=1, timeout_sec=30)
        self.assertEqual(
            sorted(row[:-1] for row in trades_resp['dataset']),
            [
                ['ETH-USD', 1],
                ['SOL-USD', 3],
            ])
        self.assertEqual(
            [row[:-1] for row in quotes_resp['dataset']],
            [['BTC-USD', 2]])

    def test_schema_expansion_backfills_qwp_udp_rows(self):
        self._require_qwp_udp_system_test()

        table_name = 'qwp_schema_' + uuid.uuid4().hex[:8]
        with self._mk_qwpudp_sender() as sender:
            (sender
             .table(table_name)
             .symbol('host', 'r1')
             .at_now())
            (sender
             .table(table_name)
             .symbol('host', 'r2')
             .column('qty', 2)
             .column('note', 'two')
             .at_now())
            (sender
             .table(table_name)
             .symbol('host', 'r3')
             .column('note', 'three')
             .at_now())
            sender.flush()

        resp = retry_check_table(table_name, min_rows=3, timeout_sec=30)
        self.assertEqual(
            resp['columns'],
            [
                {'name': 'host', 'type': 'SYMBOL'},
                {'name': 'qty', 'type': 'LONG'},
                {'name': 'note', 'type': 'VARCHAR'},
                {'name': 'timestamp', 'type': 'TIMESTAMP'},
            ])
        self.assertEqual(
            sorted(row[:-1] for row in resp['dataset']),
            [
                ['r1', None, None],
                ['r2', 2, 'two'],
                ['r3', None, 'three'],
            ])

    def test_sparse_boolean_columns_fill_false_for_qwp_udp(self):
        self._require_qwp_udp_system_test()

        table_name = 'qwp_bool_' + uuid.uuid4().hex[:8]
        with self._mk_qwpudp_sender() as sender:
            (sender
             .table(table_name)
             .symbol('host', 'r1')
             .at_now())
            (sender
             .table(table_name)
             .symbol('host', 'r2')
             .column('active', True)
             .at_now())
            (sender
             .table(table_name)
             .symbol('host', 'r3')
             .column('active', False)
             .at_now())
            sender.flush()

        resp = retry_check_table(table_name, min_rows=3, timeout_sec=30)
        self.assertEqual(
            resp['columns'],
            [
                {'name': 'host', 'type': 'SYMBOL'},
                {'name': 'active', 'type': 'BOOLEAN'},
                {'name': 'timestamp', 'type': 'TIMESTAMP'},
            ])
        self.assertEqual(
            sorted(row[:-1] for row in resp['dataset']),
            [
                ['r1', False],
                ['r2', True],
                ['r3', False],
            ])

    def test_sparse_long_and_double_columns_fill_null_for_qwp_udp(self):
        self._require_qwp_udp_system_test()

        table_name = 'qwp_num_' + uuid.uuid4().hex[:8]
        with self._mk_qwpudp_sender() as sender:
            (sender
             .table(table_name)
             .symbol('host', 'r1')
             .at_now())
            (sender
             .table(table_name)
             .symbol('host', 'r2')
             .column('qty', 2)
             .at_now())
            (sender
             .table(table_name)
             .symbol('host', 'r3')
             .column('temp', 33.5)
             .at_now())
            (sender
             .table(table_name)
             .symbol('host', 'r4')
             .column('qty', 4)
             .column('temp', 44.5)
             .at_now())
            sender.flush()

        resp = retry_check_table(table_name, min_rows=4, timeout_sec=30)
        self.assertEqual(
            resp['columns'],
            [
                {'name': 'host', 'type': 'SYMBOL'},
                {'name': 'qty', 'type': 'LONG'},
                {'name': 'temp', 'type': 'DOUBLE'},
                {'name': 'timestamp', 'type': 'TIMESTAMP'},
            ])
        self.assertEqual(
            sorted(row[:-1] for row in resp['dataset']),
            [
                ['r1', None, None],
                ['r2', 2, None],
                ['r3', None, 33.5],
                ['r4', 4, 44.5],
            ])

    def test_sparse_timestamp_columns_fill_null_for_qwp_udp(self):
        self._require_qwp_udp_system_test()

        table_name = 'qwp_sts_' + uuid.uuid4().hex[:8]
        event_ts_us = 123_456
        with self._mk_qwpudp_sender() as sender:
            (sender
             .table(table_name)
             .symbol('host', 'r1')
             .at_now())
            (sender
             .table(table_name)
             .symbol('host', 'r2')
             .column('event_ts', qls.TimestampMicros(event_ts_us))
             .at_now())
            (sender
             .table(table_name)
             .symbol('host', 'r3')
             .at_now())
            sender.flush()

        resp = retry_check_table(table_name, min_rows=3, timeout_sec=30)
        self.assertEqual(
            resp['columns'],
            [
                {'name': 'host', 'type': 'SYMBOL'},
                {'name': 'event_ts', 'type': 'TIMESTAMP'},
                {'name': 'timestamp', 'type': 'TIMESTAMP'},
            ])
        self.assertEqual(
            sorted(row[:-1] for row in resp['dataset']),
            [
                ['r1', None],
                ['r2', self._micros_to_qdb_date(event_ts_us)],
                ['r3', None],
            ])

    def test_timestamp_nanos_columns_round_trip_over_qwp_udp(self):
        self._require_qwp_udp_system_test()

        table_name = 'qwp_nts_' + uuid.uuid4().hex[:8]
        event_ts_ns = 123_456_789
        with self._mk_qwpudp_sender() as sender:
            (sender
             .table(table_name)
             .symbol('host', 'r1')
             .at_now())
            (sender
             .table(table_name)
             .symbol('host', 'r2')
             .column('event_ts', qls.TimestampNanos(event_ts_ns))
             .at_now())
            (sender
             .table(table_name)
             .symbol('host', 'r3')
             .at_now())
            sender.flush()

        resp = retry_check_table(table_name, min_rows=3, timeout_sec=30)
        self.assertEqual(
            resp['columns'],
            [
                {'name': 'host', 'type': 'SYMBOL'},
                {'name': 'event_ts', 'type': 'TIMESTAMP_NS'},
                {'name': 'timestamp', 'type': 'TIMESTAMP'},
            ])
        self.assertEqual(
            sorted(row[:-1] for row in resp['dataset']),
            [
                ['r1', None],
                ['r2', self._nanos_to_qdb_date(event_ts_ns)],
                ['r3', None],
            ])

    def test_timestamp_micros_column_converts_into_existing_timestamp_ns_column_over_qwp_udp(self):
        self._require_qwp_udp_system_test()

        table_name = 'qwp_cmu_' + uuid.uuid4().hex[:8]
        event_ts_us = 123_456
        row_ts_us = 1_700_000_000_000_123
        sql_query(
            f'''CREATE TABLE "{table_name}" (
                    host SYMBOL,
                    event_ts TIMESTAMP_NS,
                    timestamp TIMESTAMP
                ) TIMESTAMP(timestamp) PARTITION BY DAY;''')

        with self._mk_qwpudp_sender() as sender:
            (sender
             .table(table_name)
             .symbol('host', 'r1')
             .column('event_ts', qls.TimestampMicros(event_ts_us))
             .at_micros(row_ts_us))
            sender.flush()

        resp = retry_check_table(table_name, min_rows=1, timeout_sec=30)
        self.assertEqual(
            resp['columns'],
            [
                {'name': 'host', 'type': 'SYMBOL'},
                {'name': 'event_ts', 'type': 'TIMESTAMP_NS'},
                {'name': 'timestamp', 'type': 'TIMESTAMP'},
            ])
        self.assertEqual(
            resp['dataset'],
            [['r1', self._nanos_to_qdb_date(event_ts_us * 1000), self._micros_to_qdb_date(row_ts_us)]])

    def test_timestamp_nanos_column_converts_into_existing_timestamp_column_over_qwp_udp(self):
        self._require_qwp_udp_system_test()

        table_name = 'qwp_cnu_' + uuid.uuid4().hex[:8]
        event_ts_ns = 123_456_789
        row_ts_us = 1_700_000_000_000_456
        sql_query(
            f'''CREATE TABLE "{table_name}" (
                    host SYMBOL,
                    event_ts TIMESTAMP,
                    timestamp TIMESTAMP
                ) TIMESTAMP(timestamp) PARTITION BY DAY;''')

        with self._mk_qwpudp_sender() as sender:
            (sender
             .table(table_name)
             .symbol('host', 'r1')
             .column('event_ts', qls.TimestampNanos(event_ts_ns))
             .at_micros(row_ts_us))
            sender.flush()

        resp = retry_check_table(table_name, min_rows=1, timeout_sec=30)
        self.assertEqual(
            resp['columns'],
            [
                {'name': 'host', 'type': 'SYMBOL'},
                {'name': 'event_ts', 'type': 'TIMESTAMP'},
                {'name': 'timestamp', 'type': 'TIMESTAMP'},
            ])
        self.assertEqual(
            resp['dataset'],
            [['r1', self._micros_to_qdb_date(event_ts_ns // 1000), self._micros_to_qdb_date(row_ts_us)]])

    def test_designated_timestamp_nanos_round_trip_over_qwp_udp(self):
        self._require_qwp_udp_system_test()

        table_name = 'qwp_dtns_' + uuid.uuid4().hex[:8]
        row_ts_ns = 1_700_000_000_000_000_123
        with self._mk_qwpudp_sender() as sender:
            (sender
             .table(table_name)
             .symbol('host', 'nano-row')
             .column('qty', 7)
             .at(row_ts_ns))
            sender.flush()

        resp = retry_check_table(table_name, min_rows=1, timeout_sec=30)
        self.assertEqual(
            resp['columns'],
            [
                {'name': 'host', 'type': 'SYMBOL'},
                {'name': 'qty', 'type': 'LONG'},
                {'name': 'timestamp', 'type': 'TIMESTAMP_NS'},
            ])
        self.assertEqual(
            resp['dataset'],
            [['nano-row', 7, self._nanos_to_qdb_date(row_ts_ns)]])

    def test_designated_timestamp_micros_converts_into_existing_timestamp_ns_table_over_qwp_udp(self):
        self._require_qwp_udp_system_test()

        table_name = 'qwp_dtmu_' + uuid.uuid4().hex[:8]
        row_ts_us = 1_700_000_000_000_123
        sql_query(
            f'''CREATE TABLE "{table_name}" (
                    host SYMBOL,
                    qty LONG,
                    timestamp TIMESTAMP_NS
                ) TIMESTAMP(timestamp) PARTITION BY DAY;''')

        with self._mk_qwpudp_sender() as sender:
            (sender
             .table(table_name)
             .symbol('host', 'micro-row')
             .column('qty', 7)
             .at_micros(row_ts_us))
            sender.flush()

        resp = retry_check_table(table_name, min_rows=1, timeout_sec=30)
        self.assertEqual(
            resp['columns'],
            [
                {'name': 'host', 'type': 'SYMBOL'},
                {'name': 'qty', 'type': 'LONG'},
                {'name': 'timestamp', 'type': 'TIMESTAMP_NS'},
            ])
        self.assertEqual(
            resp['dataset'],
            [['micro-row', 7, self._nanos_to_qdb_date(row_ts_us * 1000)]])

    def test_designated_timestamp_nanos_converts_into_existing_timestamp_table_over_qwp_udp(self):
        self._require_qwp_udp_system_test()

        table_name = 'qwp_dtnu_' + uuid.uuid4().hex[:8]
        row_ts_ns = 1_700_000_000_000_456_789
        sql_query(
            f'''CREATE TABLE "{table_name}" (
                    host SYMBOL,
                    qty LONG,
                    timestamp TIMESTAMP
                ) TIMESTAMP(timestamp) PARTITION BY DAY;''')

        with self._mk_qwpudp_sender() as sender:
            (sender
             .table(table_name)
             .symbol('host', 'nano-row')
             .column('qty', 7)
             .at(row_ts_ns))
            sender.flush()

        resp = retry_check_table(table_name, min_rows=1, timeout_sec=30)
        self.assertEqual(
            resp['columns'],
            [
                {'name': 'host', 'type': 'SYMBOL'},
                {'name': 'qty', 'type': 'LONG'},
                {'name': 'timestamp', 'type': 'TIMESTAMP'},
            ])
        self.assertEqual(
            resp['dataset'],
            [['nano-row', 7, self._micros_to_qdb_date(row_ts_ns // 1000)]])

    def test_utf8_and_empty_varchar_values_round_trip_over_qwp_udp(self):
        self._require_qwp_udp_system_test()

        table_name = 'qwp_utf8_' + uuid.uuid4().hex[:8]
        with self._mk_qwpudp_sender() as sender:
            (sender
             .table(table_name)
             .symbol('host', 'r1')
             .symbol('label', 'm\u00fcnchen')
             .column('note', '')
             .at_micros(1_700_000_000_000_001))
            (sender
             .table(table_name)
             .symbol('host', 'r2')
             .symbol('label', '\u6771\u4eac')
             .column('note', 'na\u00efve caf\u00e9')
             .at_micros(1_700_000_000_000_002))
            (sender
             .table(table_name)
             .symbol('host', 'r3')
             .symbol('label', '\u043f\u0440\u0438\u0432\u0435\u0442')
             .at_micros(1_700_000_000_000_003))
            sender.flush()

        retry_check_table(table_name, min_rows=3, timeout_sec=30)
        resp = sql_query(f"select host, label, note from '{table_name}' order by host")
        self.assertEqual(
            resp['columns'],
            [
                {'name': 'host', 'type': 'SYMBOL'},
                {'name': 'label', 'type': 'SYMBOL'},
                {'name': 'note', 'type': 'VARCHAR'},
            ])
        self.assertEqual(
            resp['dataset'],
            [
                ['r1', 'm\u00fcnchen', ''],
                ['r2', '\u6771\u4eac', 'na\u00efve caf\u00e9'],
                ['r3', '\u043f\u0440\u0438\u0432\u0435\u0442', None],
            ])

    def test_transactional_flush_flag_is_rejected_for_qwp_udp(self):
        self._require_qwp_udp_system_test()

        table_name = 'qwp_txn_' + uuid.uuid4().hex[:8]
        with self.assertRaisesRegex(qls.SenderError, r'Transactional flushes are not supported for QWP/UDP'):
            with self._mk_qwpudp_sender() as sender:
                (sender
                 .table(table_name)
                 .symbol('host', 'txn-host')
                 .column('qty', 1)
                 .at_now())
                sender.flush(transactional=True)

    def test_markers_rewind_qwp_udp_rows_before_flush(self):
        self._require_qwp_udp_system_test()

        table_name = 'qwp_mk_' + uuid.uuid4().hex[:8]
        with self._mk_qwpudp_sender() as sender:
            (sender
             .table(table_name)
             .symbol('host', 'keep-a')
             .column('qty', 1)
             .at_now())
            sender.buffer.set_marker()
            (sender
             .table(table_name)
             .symbol('host', 'drop-me')
             .column('qty', 2))
            sender.buffer.rewind_to_marker()
            (sender
             .table(table_name)
             .symbol('host', 'keep-b')
             .column('qty', 3)
             .at_now())
            sender.flush()

        resp = retry_check_table(table_name, min_rows=2, timeout_sec=30)
        self.assertEqual(
            resp['columns'],
            [
                {'name': 'host', 'type': 'SYMBOL'},
                {'name': 'qty', 'type': 'LONG'},
                {'name': 'timestamp', 'type': 'TIMESTAMP'},
            ])
        self.assertEqual(
            sorted(row[:-1] for row in resp['dataset']),
            [
                ['keep-a', 1],
                ['keep-b', 3],
            ])

    def test_mixed_designated_timestamp_precisions_are_rejected_for_qwp_udp(self):
        self._require_qwp_udp_system_test()

        table_name = 'qwp_dts_' + uuid.uuid4().hex[:8]
        with self.assertRaisesRegex(
                qls.SenderError,
                r'QWP/UDP designated timestamp changes type within a batched table'):
            with self._mk_qwpudp_sender() as sender:
                (sender
                 .table(table_name)
                 .symbol('host', 'micros-row')
                 .column('qty', 1)
                 .at_micros(123_456))
                (sender
                 .table(table_name)
                 .symbol('host', 'nanos-row')
                 .column('qty', 2)
                 .at(789_000))
                sender.flush()

    def test_mixed_timestamp_column_precisions_are_rejected_for_qwp_udp(self):
        self._require_qwp_udp_system_test()

        table_name = 'qwp_cts_' + uuid.uuid4().hex[:8]
        with self.assertRaisesRegex(qls.SenderError, r'QWP/UDP column "event_ts" changes type within a batched table'):
            with self._mk_qwpudp_sender() as sender:
                (sender
                 .table(table_name)
                 .symbol('host', 'micros-row')
                 .column('event_ts', qls.TimestampMicros(123_456))
                 .at_now())
                (sender
                 .table(table_name)
                 .symbol('host', 'nanos-row')
                 .column('event_ts', qls.TimestampNanos(789_000))
                 .at_now())
                sender.flush()


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
        qls.ProtocolVersion.V3
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


def _stop_and_maybe_wipe(fixture):
    """Stop ``fixture``, reclaiming its data dir only on a clean run.

    Called from the ``finally`` of each suite block. ``wipe_data_dir()``
    deletes everything under ``data/`` (including ``data/log/log.txt``) to
    reclaim disk between runs, but on failure we re-raise via ``sys.exit(1)``
    and want that server log to survive for the CI "Compress QuestDB server
    log on failure" archive step. So skip the wipe whenever an exception is
    propagating — including the ``SystemExit`` from ``sys.exit(1)`` —
    detected via ``sys.exc_info()`` captured before ``stop()`` runs.
    """
    failed = sys.exc_info()[0] is not None
    fixture.stop()
    if not failed:
        fixture.wipe_data_dir()


def run_with_fixtures(args):
    global QDB_FIXTURE
    global TLS_PROXY_FIXTURE
    global BUILD_MODE
    global QWP_WS_SMOKE_TLS

    latest_protocol = sorted(list(qls.ProtocolVersion))[-1]
    run_matrix_suite = _select_tests(SUITE_MATRIX).countTestCases() > 0
    run_qwp_ws_smoke_suite = _select_tests(SUITE_QWP_WS_SMOKE).countTestCases() > 0
    run_qwp_ws_protocol_suite = _select_tests(SUITE_QWP_WS_PROTOCOL).countTestCases() > 0
    run_qwp_ws_restart_suite = _select_tests(SUITE_QWP_WS_RESTART).countTestCases() > 0
    run_qwp_ws_fuzz_suite = _select_tests(SUITE_QWP_WS_FUZZ).countTestCases() > 0

    for questdb_dir in iter_versions(args):
        if run_matrix_suite:
            for auth in (False, True):
                QDB_FIXTURE = QuestDbFixture(
                    questdb_dir,
                    auth=auth,
                    qwp_udp=bool(getattr(args, 'repo', None)))
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
                            if not _run_selected_tests(SUITE_MATRIX):
                                sys.exit(1)
                        finally:
                            if TLS_PROXY_FIXTURE:
                                TLS_PROXY_FIXTURE.stop()
                                TLS_PROXY_FIXTURE = None
                finally:
                    _stop_and_maybe_wipe(QDB_FIXTURE)

        if run_qwp_ws_smoke_suite:
            for http_auth in (False, True):
                QDB_FIXTURE = QuestDbFixture(
                    questdb_dir,
                    auth=False,
                    http_auth=http_auth,
                    qwp_udp=False)
                TLS_PROXY_FIXTURE = None
                try:
                    sys.stderr.write(
                        f'>>>> STARTING {questdb_dir} [qwp_ws_smoke http_auth={http_auth}] <<<<\n')
                    QDB_FIXTURE.start()
                    BUILD_MODE = qls.BuildMode.CONF
                    QDB_FIXTURE.http = False
                    QDB_FIXTURE.protocol_version = latest_protocol
                    for tls in (False, True):
                        QWP_WS_SMOKE_TLS = tls
                        if tls:
                            TLS_PROXY_FIXTURE = TlsProxyFixture(QDB_FIXTURE.http_server_port)
                            TLS_PROXY_FIXTURE.start()
                        try:
                            sys.stderr.write(
                                f'>>>> Running tests [suite=qwp_ws_smoke http_auth={http_auth}, tls={tls}]\n')
                            QDB_FIXTURE.drop_all_tables()
                            if not _run_selected_tests(SUITE_QWP_WS_SMOKE):
                                sys.exit(1)
                        finally:
                            if TLS_PROXY_FIXTURE:
                                TLS_PROXY_FIXTURE.stop()
                                TLS_PROXY_FIXTURE = None
                            QWP_WS_SMOKE_TLS = False
                finally:
                    _stop_and_maybe_wipe(QDB_FIXTURE)

        if run_qwp_ws_protocol_suite:
            QDB_FIXTURE = QuestDbFixture(
                questdb_dir,
                auth=False,
                qwp_udp=False)
            TLS_PROXY_FIXTURE = None
            try:
                sys.stderr.write(f'>>>> STARTING {questdb_dir} [qwp_ws_protocol] <<<<\n')
                QDB_FIXTURE.start()
                BUILD_MODE = qls.BuildMode.CONF
                QDB_FIXTURE.http = False
                QDB_FIXTURE.protocol_version = latest_protocol
                QDB_FIXTURE.drop_all_tables()
                if not _run_selected_tests(SUITE_QWP_WS_PROTOCOL):
                    sys.exit(1)
            finally:
                _stop_and_maybe_wipe(QDB_FIXTURE)

        if run_qwp_ws_restart_suite:
            QDB_FIXTURE = QuestDbFixture(
                questdb_dir,
                auth=False,
                qwp_udp=False)
            TLS_PROXY_FIXTURE = None
            try:
                sys.stderr.write(f'>>>> STARTING {questdb_dir} [qwp_ws_restart] <<<<\n')
                QDB_FIXTURE.start()
                BUILD_MODE = qls.BuildMode.CONF
                QDB_FIXTURE.http = False
                QDB_FIXTURE.protocol_version = latest_protocol
                QDB_FIXTURE.drop_all_tables()
                if not _run_selected_tests(SUITE_QWP_WS_RESTART):
                    sys.exit(1)
            finally:
                _stop_and_maybe_wipe(QDB_FIXTURE)

        if run_qwp_ws_fuzz_suite:
            QDB_FIXTURE = QuestDbFixture(
                questdb_dir,
                auth=False,
                qwp_udp=False)
            TLS_PROXY_FIXTURE = None
            try:
                sys.stderr.write(f'>>>> STARTING {questdb_dir} [qwp_ws_fuzz] <<<<\n')
                QDB_FIXTURE.start()
                BUILD_MODE = qls.BuildMode.CONF
                QDB_FIXTURE.http = False
                QDB_FIXTURE.protocol_version = latest_protocol
                QDB_FIXTURE.drop_all_tables()
                if not _run_selected_tests(SUITE_QWP_WS_FUZZ):
                    sys.exit(1)
            finally:
                _stop_and_maybe_wipe(QDB_FIXTURE)


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
