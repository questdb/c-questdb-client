#!/usr/bin/env python3

import sys
sys.dont_write_bytecode = True
import os
import datetime
import importlib.util
import shutil
import unittest
import uuid
import pathlib
import numpy as np
import decimal

import patch_path
PROJ_ROOT = patch_path.PROJ_ROOT
sys.path.append(str(PROJ_ROOT / 'c-questdb-client' / 'system_test'))
from fixture import \
    QuestDbFixture, install_questdb, install_questdb_from_repo, CA_PATH, AUTH


try:
    import pandas as pd
    import numpy
    import pyarrow
except ImportError:
    pd = None
    pyarrow = None


import questdb.ingress as qi


QUESTDB_VERSION = '9.2.0'
QUESTDB_PLAIN_INSTALL_PATH = None
QUESTDB_AUTH_INSTALL_PATH = None
FIRST_ARRAY_RELEASE = (8, 4, 0)
FIRST_DECIMAL_RELEASE = (9, 2, 0)

def may_install_questdb():
    global QUESTDB_PLAIN_INSTALL_PATH
    global QUESTDB_AUTH_INSTALL_PATH
    if QUESTDB_PLAIN_INSTALL_PATH:
        return

    install_path = None
    if os.environ.get('QDB_REPO_PATH'):
        repo = pathlib.Path(os.environ['QDB_REPO_PATH'])
        install_path = install_questdb_from_repo(repo)
    else:
        url = ('https://github.com/questdb/questdb/releases/download/' +
            QUESTDB_VERSION +
            '/questdb-' +
            QUESTDB_VERSION +
            '-no-jre-bin.tar.gz')
        install_path = install_questdb(QUESTDB_VERSION, url)

    QUESTDB_PLAIN_INSTALL_PATH = PROJ_ROOT / 'build' / 'questdb' / 'plain'
    shutil.copytree(
        install_path, QUESTDB_PLAIN_INSTALL_PATH, dirs_exist_ok=True)

    QUESTDB_AUTH_INSTALL_PATH = PROJ_ROOT / 'build' / 'questdb' / 'auth'
    shutil.copytree(
        install_path, QUESTDB_AUTH_INSTALL_PATH, dirs_exist_ok=True)


class TestWithDatabase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        may_install_questdb()

        cls.qdb_plain = None
        cls.qdb_auth = None
        cls._qwp_udp_enabled = bool(os.environ.get('QDB_REPO_PATH'))

        cls.qdb_plain = QuestDbFixture(
            QUESTDB_PLAIN_INSTALL_PATH,
            auth=False,
            wrap_tls=True,
            http=True,
            qwp_udp=cls._qwp_udp_enabled)
        cls.qdb_plain.start()

        cls.qdb_auth = QuestDbFixture(
            QUESTDB_AUTH_INSTALL_PATH, auth=True, wrap_tls=True)
        cls.qdb_auth.start()

    @classmethod
    def tearDownClass(cls):
        if cls.qdb_auth:
            cls.qdb_auth.stop()
        if cls.qdb_plain:
            cls.qdb_plain.stop()

    def _require_qwp_udp(self):
        if not self.qdb_plain.qwp_udp:
            self.skipTest(
                'QWP/UDP integration tests require repo-backed QWP receiver support')

    def _mk_qwpudp_sender(self, **kwargs):
        self._require_qwp_udp()
        return qi.Sender(
            qi.Protocol.QwpUdp,
            self.qdb_plain.host,
            self.qdb_plain.qwp_udp_port,
            **kwargs)

    def _mk_qwpudp_conf(self, **kwargs):
        self._require_qwp_udp()
        conf = f'qwpudp::addr={self.qdb_plain.host}:{self.qdb_plain.qwp_udp_port};'
        for key, value in kwargs.items():
            conf += f'{key}={value};'
        return conf

    def _test_scenario(self, qdb, protocol, **kwargs):
        protocol = qi.Protocol.parse(protocol)
        port = qdb.tls_line_tcp_port if protocol.tls_enabled else qdb.line_tcp_port
        pending = None
        table_name = uuid.uuid4().hex
        with qi.Sender(protocol, 'localhost', port, **kwargs) as sender:
            for _ in range(3):
                sender.row(
                    table_name,
                    symbols={
                        'name_a': 'val_a'},
                    columns={
                        'name_b': True,
                        'name_c': 42,
                        'name_d': 2.5,
                        'name_e': 'val_b'},
                   at=qi.ServerTimestamp)
            pending = bytes(sender)

        resp = qdb.retry_check_table(table_name, min_rows=3, log_ctx=pending)
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

    def test_plain(self):
        self._test_scenario(self.qdb_plain, 'tcp')

    def test_plain_tls_insecure_skip_verify(self):
        self._test_scenario(self.qdb_plain, 'tcps', tls_verify=False)

    def test_plain_tls_insecure_skip_verify_str(self):
        self._test_scenario(self.qdb_plain, 'tcps', tls_verify='unsafe_off')

    def test_plain_tls_ca(self):
        self._test_scenario(self.qdb_plain, 'tcps', tls_roots=CA_PATH)

    def test_plain_tls_ca_str(self):
        self._test_scenario(self.qdb_plain, 'tcps', tls_roots=str(CA_PATH))

    def test_auth(self):
        self._test_scenario(self.qdb_auth, 'tcp', **AUTH, auth_timeout=5000)

    def test_auth_tls_insecure_skip_verify(self):
        self._test_scenario(self.qdb_auth, 'tcps', tls_verify=False, **AUTH)

    def test_auth_tls_insecure_skip_verify_str(self):
        self._test_scenario(self.qdb_auth, 'tcps', tls_verify=False, **AUTH)

    def test_auth_tls_ca(self):
        self._test_scenario(self.qdb_auth, 'tcps', tls_verify=True, tls_roots=CA_PATH, **AUTH)

    def test_auth_tls_ca_str(self):
        self._test_scenario(self.qdb_auth, 'tcps', tls_verify='on', tls_roots=str(CA_PATH), **AUTH)

    @unittest.skipIf(not pd, 'pandas not installed')
    def test_basic_dataframe(self):
        port = self.qdb_plain.line_tcp_port
        pending = None
        table_name = uuid.uuid4().hex
        df = pd.DataFrame({
            'col_a': [1, 2, 3],
            'col_b': ['a', 'b', 'c'],
            'col_c': [True, False, True],
            'col_d': [1.5, 2.5, 3.5],
            'col_e': pd.Categorical(['A', 'B', 'C']),
            'col_f': [
                numpy.datetime64('2021-01-01'),
                numpy.datetime64('2021-01-02'),
                numpy.datetime64('2021-01-03')]})
        df.index.name = table_name
        with qi.Sender('tcp', 'localhost', port) as sender:
            sender.dataframe(df, at=qi.ServerTimestamp)
            pending = bytes(sender)

        resp = self.qdb_plain.retry_check_table(
            table_name, min_rows=3, log_ctx=pending)
        exp_columns = [
            {'name': 'col_e', 'type': 'SYMBOL'},
            {'name': 'col_a', 'type': 'LONG'},
            {'name': 'col_b', 'type': 'VARCHAR'},
            {'name': 'col_c', 'type': 'BOOLEAN'},
            {'name': 'col_d', 'type': 'DOUBLE'},
            {'name': 'col_f', 'type': 'TIMESTAMP'},
            {'name': 'timestamp', 'type': 'TIMESTAMP'}]
        self.assertEqual(resp['columns'], exp_columns)

        exp_dataset = [  # Comparison excludes timestamp column.
            ['A', 1, 'a', True, 1.5, '2021-01-01T00:00:00.000000Z'],
            ['B', 2, 'b', False, 2.5, '2021-01-02T00:00:00.000000Z'],
            ['C', 3, 'c', True, 3.5, '2021-01-03T00:00:00.000000Z']]
        scrubbed_dataset = [row[:-1] for row in resp['dataset']]
        self.assertEqual(scrubbed_dataset, exp_dataset)

    def test_http(self):
        port = self.qdb_plain.http_server_port
        table_name = uuid.uuid4().hex
        with qi.Sender('http', 'localhost', port) as sender:
            for _ in range(3):
                sender.row(
                    table_name,
                    symbols={
                        'name_a': 'val_a'},
                    columns={
                        'name_b': True,
                        'name_c': 42,
                        'name_d': 2.5,
                        'name_e': 'val_b'},
                    at=qi.TimestampNanos.now())

            if self.qdb_plain.version <= (7, 3, 7):
                with self.assertRaisesRegex(
                        qi.IngressError,
                        r'.*HTTP endpoint does not support ILP.*'):
                    sender.flush()
                return

        resp = self.qdb_plain.retry_check_table(table_name, min_rows=3)

        exp_ts_type = 'TIMESTAMP' if self.qdb_plain.version < (9, 1, 0) else 'TIMESTAMP_NS'

        exp_columns = [
            {'name': 'name_a', 'type': 'SYMBOL'},
            {'name': 'name_b', 'type': 'BOOLEAN'},
            {'name': 'name_c', 'type': 'LONG'},
            {'name': 'name_d', 'type': 'DOUBLE'},
            {'name': 'name_e', 'type': 'VARCHAR'},
            {'name': 'timestamp', 'type': exp_ts_type}]
        self.assertEqual(resp['columns'], exp_columns)

        exp_dataset = [  # Comparison excludes timestamp column.
            ['val_a', True, 42, 2.5, 'val_b'],
            ['val_a', True, 42, 2.5, 'val_b'],
            ['val_a', True, 42, 2.5, 'val_b']]
        scrubbed_dataset = [row[:-1] for row in resp['dataset']]
        self.assertEqual(scrubbed_dataset, exp_dataset)

    def test_qwp_udp_protocol_enum(self):
        self.assertEqual(qi.Protocol.parse('qwpudp'), qi.Protocol.QwpUdp)
        self.assertFalse(qi.Protocol.QwpUdp.tls_enabled)

    def test_qwp_udp_basic(self):
        self._require_qwp_udp()
        table_name = uuid.uuid4().hex
        with self._mk_qwpudp_sender() as sender:
            sender.row(
                table_name,
                symbols={'name_a': 'val_a'},
                columns={'name_b': True, 'name_c': 42, 'name_d': 2.5},
                at=qi.ServerTimestamp)
            self.assertEqual(bytes(sender), b'')
            self.assertGreater(len(sender), 0)
            sender.flush()
            self.assertEqual(len(sender), 0)

        resp = self.qdb_plain.retry_check_table(table_name, min_rows=1)
        exp_columns = [
            {'name': 'name_a', 'type': 'SYMBOL'},
            {'name': 'name_b', 'type': 'BOOLEAN'},
            {'name': 'name_c', 'type': 'LONG'},
            {'name': 'name_d', 'type': 'DOUBLE'},
            {'name': 'timestamp', 'type': 'TIMESTAMP'}]
        self.assertEqual(resp['columns'], exp_columns)
        scrubbed_dataset = [row[:-1] for row in resp['dataset']]
        self.assertEqual(scrubbed_dataset, [['val_a', True, 42, 2.5]])

    def test_qwp_udp_from_conf_with_opts(self):
        self._require_qwp_udp()
        table_name = uuid.uuid4().hex
        conf = self._mk_qwpudp_conf(max_datagram_size=1200, multicast_ttl=2)
        with qi.Sender.from_conf(conf) as sender:
            self.assertEqual(sender.auto_flush_bytes, 1200)
            sender.row(
                table_name,
                columns={'price': 1.5},
                at=qi.ServerTimestamp)

        resp = self.qdb_plain.retry_check_table(table_name, min_rows=1)
        scrubbed_dataset = [row[:-1] for row in resp['dataset']]
        self.assertEqual(scrubbed_dataset, [[1.5]])

    def test_qwp_udp_from_conf_override(self):
        self._require_qwp_udp()
        table_name = uuid.uuid4().hex
        conf = self._mk_qwpudp_conf()
        with qi.Sender.from_conf(
                conf,
                max_datagram_size=1200,
                multicast_ttl=2) as sender:
            self.assertEqual(sender.auto_flush_bytes, 1200)
            sender.row(
                table_name,
                columns={'price': 2.5},
                at=qi.ServerTimestamp)

        resp = self.qdb_plain.retry_check_table(table_name, min_rows=1)
        scrubbed_dataset = [row[:-1] for row in resp['dataset']]
        self.assertEqual(scrubbed_dataset, [[2.5]])

    def test_qwp_udp_from_env_override(self):
        self._require_qwp_udp()
        table_name = uuid.uuid4().hex
        old_conf = os.environ.get('QDB_CLIENT_CONF')
        os.environ['QDB_CLIENT_CONF'] = self._mk_qwpudp_conf()
        try:
            with qi.Sender.from_env(
                    max_datagram_size=1200,
                    multicast_ttl=2) as sender:
                self.assertEqual(sender.auto_flush_bytes, 1200)
                sender.row(
                    table_name,
                    columns={'price': 4.5},
                    at=qi.ServerTimestamp)
        finally:
            if old_conf is None:
                del os.environ['QDB_CLIENT_CONF']
            else:
                os.environ['QDB_CLIENT_CONF'] = old_conf

        resp = self.qdb_plain.retry_check_table(table_name, min_rows=1)
        scrubbed_dataset = [row[:-1] for row in resp['dataset']]
        self.assertEqual(scrubbed_dataset, [[4.5]])

    def test_qwp_udp_from_conf_override_conflict(self):
        self._require_qwp_udp()
        conf = self._mk_qwpudp_conf(max_datagram_size=1200)
        with self.assertRaisesRegex(
                ValueError,
                r'"max_datagram_size" is already present in the conf_str'):
            qi.Sender.from_conf(conf, max_datagram_size=900)

    def test_qwp_udp_auto_flush_bytes_default(self):
        self._require_qwp_udp()
        sender = self._mk_qwpudp_sender()
        try:
            self.assertTrue(sender.auto_flush)
            self.assertEqual(sender.auto_flush_bytes, 1400)
        finally:
            sender.close(flush=False)

        sender = self._mk_qwpudp_sender(max_datagram_size=1200)
        try:
            self.assertEqual(sender.auto_flush_bytes, 1200)
        finally:
            sender.close(flush=False)

    def test_qwp_udp_new_buffer(self):
        self._require_qwp_udp()
        table_name = uuid.uuid4().hex
        with self._mk_qwpudp_sender(init_buf_size=1024, max_name_len=64) as sender:
            buffer = sender.new_buffer()
            self.assertEqual(buffer.init_buf_size, 1024)
            self.assertEqual(buffer.max_name_len, 64)
            buffer.row(
                table_name,
                columns={'price': 3.5},
                at=qi.ServerTimestamp)
            self.assertEqual(bytes(buffer), b'')
            self.assertGreater(len(buffer), 0)
            sender.flush(buffer)
            self.assertEqual(len(buffer), 0)

        resp = self.qdb_plain.retry_check_table(table_name, min_rows=1)
        scrubbed_dataset = [row[:-1] for row in resp['dataset']]
        self.assertEqual(scrubbed_dataset, [[3.5]])

    def test_qwp_udp_new_buffer_requires_establish(self):
        self._require_qwp_udp()
        sender = self._mk_qwpudp_sender()
        try:
            with self.assertRaisesRegex(
                    qi.IngressError,
                    r"new_buffer\(\) can't be called before establish\(\)"):
                sender.new_buffer()
        finally:
            sender.close(flush=False)

    def test_qwp_udp_new_buffer_rejects_closed_sender(self):
        self._require_qwp_udp()
        sender = self._mk_qwpudp_sender()
        sender.close(flush=False)
        with self.assertRaisesRegex(
                qi.IngressError,
                r"new_buffer\(\) can't be called: Sender is closed"):
            sender.new_buffer()

    def test_qwp_udp_transaction_rejected(self):
        self._require_qwp_udp()
        with self._mk_qwpudp_sender() as sender:
            with self.assertRaisesRegex(
                    qi.IngressError,
                    'Transactions are only supported for ILP/HTTP'):
                sender.transaction('trades')

    def test_qwp_udp_protocol_version_rejected(self):
        self._require_qwp_udp()
        with self._mk_qwpudp_sender() as sender:
            with self.assertRaisesRegex(
                    qi.IngressError,
                    'protocol_version is not applicable for QWP/UDP senders'):
                sender.protocol_version

    def test_qwp_udp_example(self):
        self._require_qwp_udp()
        table_name = uuid.uuid4().hex
        example_path = PROJ_ROOT / 'examples' / 'qwp_udp.py'
        spec = importlib.util.spec_from_file_location(
            'questdb_qwp_udp_example',
            example_path)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        mod.example(
            host=self.qdb_plain.host,
            port=self.qdb_plain.qwp_udp_port,
            table_name=table_name)

        resp = self.qdb_plain.retry_check_table(table_name, min_rows=1)
        scrubbed_dataset = [row[:-1] for row in resp['dataset']]
        self.assertEqual(scrubbed_dataset, [['ETH-USD', 'sell', 2615.54, 0.00044]])

    @unittest.skipIf(not pd, 'pandas not installed')
    def test_qwp_udp_dataframe(self):
        self._require_qwp_udp()
        table_name = uuid.uuid4().hex
        df = pd.DataFrame({
            'name_a': ['a', 'b'],
            'name_b': [True, False],
            'name_c': [1, 2],
            'name_d': [1.5, 2.5],
        })
        with self._mk_qwpudp_sender() as sender:
            sender.dataframe(df, table_name=table_name, at=qi.ServerTimestamp)

        resp = self.qdb_plain.retry_check_table(table_name, min_rows=2)
        exp_columns = [
            {'name': 'name_a', 'type': 'VARCHAR'},
            {'name': 'name_b', 'type': 'BOOLEAN'},
            {'name': 'name_c', 'type': 'LONG'},
            {'name': 'name_d', 'type': 'DOUBLE'},
            {'name': 'timestamp', 'type': 'TIMESTAMP'}]
        self.assertEqual(resp['columns'], exp_columns)
        scrubbed_dataset = [row[:-1] for row in resp['dataset']]
        self.assertEqual(scrubbed_dataset, [['a', True, 1, 1.5], ['b', False, 2, 2.5]])

    def test_qwp_udp_timestamp_columns(self):
        self._require_qwp_udp()
        table_name = uuid.uuid4().hex
        ts_micros = qi.TimestampMicros(1_700_000_000_000_000)
        ts_nanos = qi.TimestampNanos(1_700_000_000_123_456_789)
        dt = datetime.datetime(2024, 6, 15, 12, 0, 0, tzinfo=datetime.timezone.utc)
        with self._mk_qwpudp_sender() as sender:
            sender.row(
                table_name,
                columns={
                    'ts_micros': ts_micros,
                    'ts_nanos': ts_nanos,
                    'ts_dt': dt},
                at=qi.TimestampNanos.now())
            sender.flush()

        resp = self.qdb_plain.retry_check_table(table_name, min_rows=1)
        col_types = {c['name']: c['type'] for c in resp['columns']}
        self.assertEqual(col_types['ts_micros'], 'TIMESTAMP')
        self.assertEqual(col_types['ts_nanos'], 'TIMESTAMP_NS')
        self.assertEqual(col_types['ts_dt'], 'TIMESTAMP')
        row = resp['dataset'][0]
        # ts_micros: 1_700_000_000_000_000 micros
        self.assertEqual(row[0], '2023-11-14T22:13:20.000000Z')
        # ts_dt: 2024-06-15T12:00:00Z
        self.assertEqual(row[2], '2024-06-15T12:00:00.000000Z')

    def test_qwp_udp_f64_array(self):
        self._require_qwp_udp()
        if self.qdb_plain.version < FIRST_ARRAY_RELEASE:
            self.skipTest('old server does not support array')
        table_name = uuid.uuid4().hex
        array1 = np.array([[1.1, 2.2], [3.3, 4.4]], dtype=np.float64)
        array2 = array1.T  # non-contiguous
        with self._mk_qwpudp_sender() as sender:
            sender.row(
                table_name,
                columns={
                    'arr_c': array1,
                    'arr_t': array2},
                at=qi.TimestampNanos.now())
            sender.flush()

        resp = self.qdb_plain.retry_check_table(table_name, min_rows=1)
        col_types = {c['name']: c['type'] for c in resp['columns']}
        self.assertEqual(col_types['arr_c'], 'ARRAY')
        self.assertEqual(col_types['arr_t'], 'ARRAY')
        scrubbed = [row[:-1] for row in resp['dataset']]
        self.assertEqual(scrubbed, [[[[1.1, 2.2], [3.3, 4.4]],
                                     [[1.1, 3.3], [2.2, 4.4]]]])

    def test_qwp_udp_decimal(self):
        self._require_qwp_udp()
        if self.qdb_plain.version < FIRST_DECIMAL_RELEASE:
            self.skipTest('old server does not support decimal')
        table_name = uuid.uuid4().hex
        self.qdb_plain.http_sql_query(
            f'CREATE TABLE {table_name} '
            f'(price DECIMAL(18,3), timestamp TIMESTAMP) '
            f'TIMESTAMP(timestamp) PARTITION BY DAY;')
        with self._mk_qwpudp_sender() as sender:
            sender.row(
                table_name,
                columns={'price': decimal.Decimal('12345.678')},
                at=qi.TimestampNanos.now())
            sender.flush()

        resp = self.qdb_plain.retry_check_table(table_name, min_rows=1)
        exp_columns = [
            {'name': 'price', 'type': 'DECIMAL(18,3)'},
            {'name': 'timestamp', 'type': 'TIMESTAMP'}]
        self.assertEqual(resp['columns'], exp_columns)
        scrubbed = [row[:-1] for row in resp['dataset']]
        self.assertEqual(scrubbed, [['12345.678']])

    def test_qwp_udp_string_column(self):
        self._require_qwp_udp()
        table_name = uuid.uuid4().hex
        with self._mk_qwpudp_sender() as sender:
            sender.row(
                table_name,
                columns={'label': 'hello world', 'value': 42},
                at=qi.TimestampNanos.now())
            sender.flush()

        resp = self.qdb_plain.retry_check_table(table_name, min_rows=1)
        col_types = {c['name']: c['type'] for c in resp['columns']}
        self.assertEqual(col_types['label'], 'VARCHAR')
        self.assertEqual(col_types['value'], 'LONG')
        scrubbed = [row[:-1] for row in resp['dataset']]
        self.assertEqual(scrubbed, [['hello world', 42]])

    def test_qwp_udp_auto_flush_bytes_triggers(self):
        self._require_qwp_udp()
        table_name = uuid.uuid4().hex
        with self._mk_qwpudp_sender(
                max_datagram_size=200,
                auto_flush_rows=False,
                auto_flush_interval=False) as sender:
            self.assertEqual(sender.auto_flush_bytes, 200)
            for i in range(20):
                sender.row(
                    table_name,
                    symbols={'tag': f'v_{i}'},
                    columns={'value': i},
                    at=qi.TimestampNanos.now())
        resp = self.qdb_plain.retry_check_table(table_name, min_rows=10)
        self.assertGreaterEqual(resp['count'], 10)

    def test_qwp_udp_auto_flush_rows_triggers(self):
        self._require_qwp_udp()
        table_name = uuid.uuid4().hex
        with self._mk_qwpudp_sender(
                auto_flush_rows=5,
                auto_flush_bytes=False,
                auto_flush_interval=False) as sender:
            for i in range(10):
                sender.row(
                    table_name,
                    columns={'value': i},
                    at=qi.TimestampNanos.now())
        resp = self.qdb_plain.retry_check_table(table_name, min_rows=10)
        self.assertEqual(resp['count'], 10)

    def test_qwp_udp_auto_flush_disabled(self):
        self._require_qwp_udp()
        table_name = uuid.uuid4().hex
        sender = self._mk_qwpudp_sender(auto_flush=False)
        sender.establish()
        try:
            for i in range(5):
                sender.row(
                    table_name,
                    columns={'value': i},
                    at=qi.TimestampNanos.now())
            self.assertGreater(len(sender), 0)
            sender.flush()
        finally:
            sender.close(flush=False)
        resp = self.qdb_plain.retry_check_table(table_name, min_rows=5)
        self.assertEqual(resp['count'], 5)

    def test_qwp_udp_multi_table(self):
        self._require_qwp_udp()
        t1 = uuid.uuid4().hex
        t2 = uuid.uuid4().hex
        with self._mk_qwpudp_sender() as sender:
            sender.row(t1, columns={'x': 1}, at=qi.TimestampNanos.now())
            sender.row(t2, columns={'y': 2}, at=qi.TimestampNanos.now())
            sender.row(t1, columns={'x': 3}, at=qi.TimestampNanos.now())
            sender.flush()
        r1 = self.qdb_plain.retry_check_table(t1, min_rows=2)
        r2 = self.qdb_plain.retry_check_table(t2, min_rows=1)
        self.assertEqual(r1['count'], 2)
        self.assertEqual(r2['count'], 1)

    def test_qwp_udp_buffer_reuse_after_flush(self):
        self._require_qwp_udp()
        t1 = uuid.uuid4().hex
        t2 = uuid.uuid4().hex
        with self._mk_qwpudp_sender() as sender:
            buf = sender.new_buffer()
            buf.row(t1, columns={'batch': 1}, at=qi.TimestampNanos.now())
            sender.flush(buf)
            self.assertEqual(len(buf), 0)
            buf.row(t2, columns={'batch': 2}, at=qi.TimestampNanos.now())
            sender.flush(buf)
        r1 = self.qdb_plain.retry_check_table(t1, min_rows=1)
        r2 = self.qdb_plain.retry_check_table(t2, min_rows=1)
        self.assertEqual([row[:-1] for row in r1['dataset']], [[1]])
        self.assertEqual([row[:-1] for row in r2['dataset']], [[2]])

    def test_qwp_udp_independent_buffers(self):
        self._require_qwp_udp()
        t1 = uuid.uuid4().hex
        t2 = uuid.uuid4().hex
        with self._mk_qwpudp_sender() as sender:
            buf_a = sender.new_buffer()
            buf_b = sender.new_buffer()
            buf_a.row(t1, columns={'src': 'a'}, at=qi.TimestampNanos.now())
            buf_b.row(t2, columns={'src': 'b'}, at=qi.TimestampNanos.now())
            sender.flush(buf_a)
            self.assertEqual(len(buf_a), 0)
            self.assertGreater(len(buf_b), 0)
            sender.flush(buf_b)
        r1 = self.qdb_plain.retry_check_table(t1, min_rows=1)
        r2 = self.qdb_plain.retry_check_table(t2, min_rows=1)
        self.assertEqual([row[:-1] for row in r1['dataset']], [['a']])
        self.assertEqual([row[:-1] for row in r2['dataset']], [['b']])

    def test_qwp_udp_flush_clear_false(self):
        self._require_qwp_udp()
        table_name = uuid.uuid4().hex
        with self._mk_qwpudp_sender() as sender:
            buf = sender.new_buffer()
            buf.row(table_name, columns={'val': 99}, at=qi.TimestampNanos.now())
            sender.flush(buf, clear=False)
            self.assertGreater(len(buf), 0)
            buf.clear()
            self.assertEqual(len(buf), 0)
        resp = self.qdb_plain.retry_check_table(table_name, min_rows=1)
        self.assertEqual([row[:-1] for row in resp['dataset']], [[99]])

    def test_qwp_udp_unicode(self):
        self._require_qwp_udp()
        table_name = uuid.uuid4().hex
        with self._mk_qwpudp_sender() as sender:
            sender.row(
                table_name,
                symbols={'city': 'Zürich'},
                columns={'greeting': '你好世界', 'emoji': '🚀'},
                at=qi.TimestampNanos.now())
            sender.flush()
        resp = self.qdb_plain.retry_check_table(table_name, min_rows=1)
        row = resp['dataset'][0]
        self.assertEqual(row[0], 'Zürich')
        self.assertEqual(row[1], '你好世界')
        self.assertEqual(row[2], '🚀')

    def test_qwp_udp_none_columns_skipped(self):
        self._require_qwp_udp()
        table_name = uuid.uuid4().hex
        with self._mk_qwpudp_sender() as sender:
            sender.row(
                table_name,
                symbols={'tag': 'a', 'skip_sym': None},
                columns={'present': 42, 'absent': None},
                at=qi.TimestampNanos.now())
            sender.flush()
        resp = self.qdb_plain.retry_check_table(table_name, min_rows=1)
        col_names = [c['name'] for c in resp['columns']]
        self.assertIn('present', col_names)
        self.assertNotIn('absent', col_names)
        self.assertNotIn('skip_sym', col_names)

    def test_qwp_udp_empty_flush(self):
        self._require_qwp_udp()
        with self._mk_qwpudp_sender() as sender:
            self.assertEqual(len(sender), 0)
            sender.flush()
            sender.flush()
            buf = sender.new_buffer()
            sender.flush(buf)

    def test_qwp_udp_double_close(self):
        self._require_qwp_udp()
        sender = self._mk_qwpudp_sender()
        sender.establish()
        sender.close(flush=False)
        sender.close(flush=False)

    def test_qwp_udp_context_manager_flush_on_exit(self):
        self._require_qwp_udp()
        table_name = uuid.uuid4().hex
        with self._mk_qwpudp_sender(auto_flush=False) as sender:
            sender.row(
                table_name, columns={'val': 7},
                at=qi.TimestampNanos.now())
        resp = self.qdb_plain.retry_check_table(table_name, min_rows=1)
        self.assertEqual([row[:-1] for row in resp['dataset']], [[7]])

    def test_qwp_udp_server_vs_explicit_timestamp(self):
        self._require_qwp_udp()
        t1 = uuid.uuid4().hex
        t2 = uuid.uuid4().hex
        explicit_ts = qi.TimestampNanos(1_700_000_000_000_000_000)
        with self._mk_qwpudp_sender() as sender:
            sender.row(t1, columns={'x': 1}, at=qi.ServerTimestamp)
            sender.row(t2, columns={'x': 2}, at=explicit_ts)
            sender.flush()
        r2 = self.qdb_plain.retry_check_table(t2, min_rows=1)
        ts = r2['dataset'][0][1]
        self.assertIn('2023-11-14', ts)

    def test_qwp_udp_many_rows(self):
        self._require_qwp_udp()
        table_name = uuid.uuid4().hex
        with self._mk_qwpudp_sender() as sender:
            for i in range(500):
                sender.row(
                    table_name,
                    symbols={'batch': 'stress'},
                    columns={'seq': i, 'payload': f'row_{i:04d}'},
                    at=qi.TimestampNanos.now())
        resp = self.qdb_plain.retry_check_table(table_name, min_rows=500)
        self.assertEqual(resp['count'], 500)

    def test_qwp_udp_max_name_len(self):
        self._require_qwp_udp()
        with self._mk_qwpudp_sender(max_name_len=20) as sender:
            buf = sender.new_buffer()
            buf.row('t', columns={'a' * 20: 1}, at=qi.ServerTimestamp)
            self.assertGreater(len(buf), 0)

            buf2 = sender.new_buffer()
            with self.assertRaises(qi.IngressError):
                buf2.row('t', columns={'a' * 21: 1}, at=qi.ServerTimestamp)

    def test_qwp_udp_standalone_buffer_reuse(self):
        self._require_qwp_udp()
        t1 = uuid.uuid4().hex
        t2 = uuid.uuid4().hex
        buf = qi.Buffer.qwp()
        buf.row(t1, columns={'round': 1}, at=qi.TimestampNanos.now())
        with self._mk_qwpudp_sender() as sender:
            sender.flush(buf)
            self.assertEqual(len(buf), 0)
            buf.row(t2, columns={'round': 2}, at=qi.TimestampNanos.now())
            sender.flush(buf)
        r1 = self.qdb_plain.retry_check_table(t1, min_rows=1)
        r2 = self.qdb_plain.retry_check_table(t2, min_rows=1)
        self.assertEqual([row[:-1] for row in r1['dataset']], [[1]])
        self.assertEqual([row[:-1] for row in r2['dataset']], [[2]])

    def test_qwp_udp_auto_flush_interval(self):
        self._require_qwp_udp()
        table_name = uuid.uuid4().hex
        import time as _time
        with self._mk_qwpudp_sender(
                auto_flush_rows=False,
                auto_flush_bytes=False,
                auto_flush_interval=500) as sender:
            sender.row(
                table_name, columns={'seq': 1},
                at=qi.TimestampNanos.now())
            self.assertGreater(len(sender), 0)
            _time.sleep(0.7)
            sender.row(
                table_name, columns={'seq': 2},
                at=qi.TimestampNanos.now())
        resp = self.qdb_plain.retry_check_table(table_name, min_rows=2)
        self.assertEqual(resp['count'], 2)

    def test_qwp_udp_datagram_splitting(self):
        self._require_qwp_udp()
        table_name = uuid.uuid4().hex
        with self._mk_qwpudp_sender(
                max_datagram_size=200,
                auto_flush=False) as sender:
            for i in range(30):
                sender.row(
                    table_name,
                    symbols={'tag': f'val_{i:03d}'},
                    columns={'seq': i, 'data': f'payload_{i:06d}'},
                    at=qi.TimestampNanos.now())
            sender.flush()
        resp = self.qdb_plain.retry_check_table(table_name, min_rows=30)
        self.assertEqual(resp['count'], 30)

    def test_qwp_udp_interleave_with_http(self):
        self._require_qwp_udp()
        t_http = uuid.uuid4().hex
        t_qwp = uuid.uuid4().hex
        with qi.Sender(
                qi.Protocol.Http, self.qdb_plain.host,
                self.qdb_plain.http_server_port) as http_sender, \
             self._mk_qwpudp_sender() as qwp_sender:
            http_sender.row(
                t_http, columns={'src': 'http', 'val': 1},
                at=qi.TimestampNanos.now())
            qwp_sender.row(
                t_qwp, columns={'src': 'qwp', 'val': 2},
                at=qi.TimestampNanos.now())
            qwp_sender.flush()
        r_http = self.qdb_plain.retry_check_table(t_http, min_rows=1)
        r_qwp = self.qdb_plain.retry_check_table(t_qwp, min_rows=1)
        self.assertEqual(r_http['dataset'][0][0], 'http')
        self.assertEqual(r_qwp['dataset'][0][0], 'qwp')

    def test_qwp_udp_from_env(self):
        self._require_qwp_udp()
        table_name = uuid.uuid4().hex
        old = os.environ.get('QDB_CLIENT_CONF')
        os.environ['QDB_CLIENT_CONF'] = self._mk_qwpudp_conf()
        try:
            with qi.Sender.from_env() as sender:
                sender.row(
                    table_name, columns={'val': 123},
                    at=qi.TimestampNanos.now())
                sender.flush()
        finally:
            if old is None:
                del os.environ['QDB_CLIENT_CONF']
            else:
                os.environ['QDB_CLIENT_CONF'] = old
        resp = self.qdb_plain.retry_check_table(table_name, min_rows=1)
        self.assertEqual(
            [row[:-1] for row in resp['dataset']], [[123]])

    def test_qwp_udp_sender_reuse(self):
        self._require_qwp_udp()
        t1 = uuid.uuid4().hex
        t2 = uuid.uuid4().hex
        with self._mk_qwpudp_sender() as sender:
            sender.row(t1, columns={'session': 1},
                       at=qi.TimestampNanos.now())
            sender.flush()
        with self._mk_qwpudp_sender() as sender:
            sender.row(t2, columns={'session': 2},
                       at=qi.TimestampNanos.now())
            sender.flush()
        r1 = self.qdb_plain.retry_check_table(t1, min_rows=1)
        r2 = self.qdb_plain.retry_check_table(t2, min_rows=1)
        self.assertEqual([row[:-1] for row in r1['dataset']], [[1]])
        self.assertEqual([row[:-1] for row in r2['dataset']], [[2]])

    def test_qwp_udp_large_string(self):
        self._require_qwp_udp()
        table_name = uuid.uuid4().hex
        big_str = 'x' * 1000
        with self._mk_qwpudp_sender() as sender:
            sender.row(
                table_name, columns={'payload': big_str},
                at=qi.TimestampNanos.now())
            sender.flush()
        resp = self.qdb_plain.retry_check_table(table_name, min_rows=1)
        self.assertEqual(resp['dataset'][0][0], big_str)

    def test_qwp_udp_symbols_only(self):
        self._require_qwp_udp()
        table_name = uuid.uuid4().hex
        with self._mk_qwpudp_sender() as sender:
            sender.row(
                table_name,
                symbols={'exchange': 'NYSE', 'ticker': 'AAPL'},
                at=qi.TimestampNanos.now())
            sender.flush()
        resp = self.qdb_plain.retry_check_table(table_name, min_rows=1)
        col_types = {c['name']: c['type'] for c in resp['columns']}
        self.assertEqual(col_types['exchange'], 'SYMBOL')
        self.assertEqual(col_types['ticker'], 'SYMBOL')
        self.assertEqual(resp['dataset'][0][0], 'NYSE')
        self.assertEqual(resp['dataset'][0][1], 'AAPL')

    def test_qwp_udp_mixed_timestamps(self):
        self._require_qwp_udp()
        table_name = uuid.uuid4().hex
        explicit = qi.TimestampNanos(1_700_000_000_000_000_000)
        with self._mk_qwpudp_sender() as sender:
            sender.row(table_name, columns={'seq': 1},
                       at=qi.ServerTimestamp)
            sender.row(table_name, columns={'seq': 2}, at=explicit)
            sender.row(table_name, columns={'seq': 3},
                       at=qi.ServerTimestamp)
            sender.flush()
        resp = self.qdb_plain.retry_check_table(table_name, min_rows=3)
        self.assertEqual(resp['count'], 3)
        rows = sorted(resp['dataset'], key=lambda row: row[0])
        self.assertIn('2023-11-14', rows[1][1])

    @unittest.skipIf(not pd, 'pandas not installed')
    def test_qwp_udp_dataframe_ts_column(self):
        self._require_qwp_udp()
        table_name = uuid.uuid4().hex
        df = pd.DataFrame({
            'sensor': ['A', 'B'],
            'temp': [22.5, 23.1],
            'ts': pd.to_datetime(
                ['2024-01-01 12:00:00', '2024-01-01 12:01:00'],
                utc=True),
        })
        with self._mk_qwpudp_sender() as sender:
            sender.dataframe(df, table_name=table_name, at='ts')
        resp = self.qdb_plain.retry_check_table(table_name, min_rows=2)
        self.assertEqual(resp['count'], 2)
        col_names = [c['name'] for c in resp['columns']]
        self.assertIn('timestamp', col_names)
        for row in resp['dataset']:
            self.assertIn('2024-01-01', row[-1])

    def test_qwp_udp_new_buffer_inherits_settings(self):
        self._require_qwp_udp()
        with self._mk_qwpudp_sender(
                init_buf_size=2048, max_name_len=32) as sender:
            buf = sender.new_buffer()
            self.assertEqual(buf.init_buf_size, 2048)
            self.assertEqual(buf.max_name_len, 32)
            buf.row('t', columns={'a' * 32: 1}, at=qi.ServerTimestamp)
            self.assertGreater(len(buf), 0)
            with self.assertRaises(qi.IngressError):
                buf.row('t', columns={'a' * 33: 1}, at=qi.ServerTimestamp)

    def test_qwp_udp_ilp_buffer_rejected(self):
        self._require_qwp_udp()
        buf = qi.Buffer.ilp(protocol_version=2)
        buf.row('t', columns={'x': 1}, at=qi.ServerTimestamp)
        with self._mk_qwpudp_sender() as sender:
            with self.assertRaisesRegex(
                    qi.IngressError, 'QWP/UDP sender requires a QWP buffer'):
                sender.flush(buf)

    def test_qwp_udp_buffer_rejected_by_http(self):
        self._require_qwp_udp()
        buf = qi.Buffer.qwp()
        buf.row('t', columns={'x': 1}, at=qi.ServerTimestamp)
        with qi.Sender(
                qi.Protocol.Http, self.qdb_plain.host,
                self.qdb_plain.http_server_port) as sender:
            with self.assertRaisesRegex(
                    qi.IngressError,
                    'ILP sender requires an ILP buffer'):
                sender.flush(buf)

    def test_qwp_udp_wrong_port_silent(self):
        """UDP flush to wrong port succeeds silently (fire-and-forget)."""
        self._require_qwp_udp()
        with qi.Sender(
                qi.Protocol.QwpUdp,
                self.qdb_plain.host, 19007) as sender:
            sender.row('t', columns={'x': 1}, at=qi.TimestampNanos.now())
            sender.flush()  # no error — data goes nowhere

    def test_qwp_udp_unresolvable_host(self):
        """Unresolvable host fails at establish()."""
        self._require_qwp_udp()
        with self.assertRaisesRegex(qi.IngressError, 'Could not resolve'):
            with qi.Sender(
                    qi.Protocol.QwpUdp,
                    'this.host.does.not.exist.invalid', 9007) as sender:
                pass

    def test_qwp_udp_wide_row(self):
        """50 columns + 5 symbols in a single row."""
        self._require_qwp_udp()
        table_name = uuid.uuid4().hex
        cols = {f'col_{i:02d}': float(i) for i in range(50)}
        syms = {f'sym_{i}': f'val_{i}' for i in range(5)}
        with self._mk_qwpudp_sender() as sender:
            sender.row(table_name, symbols=syms, columns=cols,
                       at=qi.TimestampNanos.now())
            sender.flush()
        resp = self.qdb_plain.retry_check_table(table_name, min_rows=1)
        # 50 cols + 5 syms + 1 timestamp = 56
        self.assertEqual(len(resp['columns']), 56)

    def test_qwp_udp_row_ordering(self):
        """100 rows with explicit timestamps, split across datagrams."""
        self._require_qwp_udp()
        table_name = uuid.uuid4().hex
        n = 100
        base_ts = 1_700_000_000_000_000_000
        with self._mk_qwpudp_sender(
                max_datagram_size=200, auto_flush=False) as sender:
            for i in range(n):
                sender.row(
                    table_name, columns={'seq': i},
                    at=qi.TimestampNanos(base_ts + i * 1000))
            sender.flush()
        resp = self.qdb_plain.retry_check_table(table_name, min_rows=n)
        seqs = sorted(row[0] for row in resp['dataset'])
        self.assertEqual(seqs, list(range(n)))

    def test_qwp_udp_tiny_datagram_rejected(self):
        """max_datagram_size=1: row exceeds datagram, flush errors."""
        self._require_qwp_udp()
        with self._mk_qwpudp_sender(
                max_datagram_size=1, auto_flush=False) as sender:
            sender.row('t', columns={'x': 1}, at=qi.TimestampNanos.now())
            with self.assertRaisesRegex(
                    qi.IngressError, 'exceeds maximum datagram size'):
                sender.flush()

    def test_qwp_udp_rapid_fire_auto_flush(self):
        """2000 rows with pure auto-flush, no explicit flush.
        UDP may drop datagrams under load, so we accept >= 90% arrival."""
        self._require_qwp_udp()
        table_name = uuid.uuid4().hex
        n = 2000
        with self._mk_qwpudp_sender() as sender:
            for i in range(n):
                sender.row(
                    table_name, columns={'seq': i},
                    at=qi.TimestampNanos.now())
        import time
        time.sleep(3)
        resp = self.qdb_plain.retry_check_table(
            table_name, min_rows=int(n * 0.9))
        self.assertGreaterEqual(resp['count'], int(n * 0.9))

    def test_qwp_udp_protocol_version_in_conf_rejected(self):
        self._require_qwp_udp()
        conf = self._mk_qwpudp_conf(protocol_version=2)
        with self.assertRaisesRegex(
                qi.IngressError,
                'protocol_version.*not supported.*QWP'):
            qi.Sender.from_conf(conf)

    def test_qwp_udp_concurrent_senders(self):
        """Two senders from different threads to the same port."""
        self._require_qwp_udp()
        import threading
        t1 = uuid.uuid4().hex
        t2 = uuid.uuid4().hex
        errors = []
        def writer(table, n=50):
            try:
                with self._mk_qwpudp_sender() as sender:
                    for i in range(n):
                        sender.row(
                            table, columns={'seq': i},
                            at=qi.TimestampNanos.now())
                    sender.flush()
            except Exception as e:
                errors.append(e)
        th1 = threading.Thread(target=writer, args=(t1,))
        th2 = threading.Thread(target=writer, args=(t2,))
        th1.start()
        th2.start()
        th1.join()
        th2.join()
        self.assertEqual(errors, [])
        r1 = self.qdb_plain.retry_check_table(t1, min_rows=50)
        r2 = self.qdb_plain.retry_check_table(t2, min_rows=50)
        self.assertEqual(r1['count'], 50)
        self.assertEqual(r2['count'], 50)

    def test_qwp_udp_double_establish_rejected(self):
        self._require_qwp_udp()
        sender = self._mk_qwpudp_sender()
        sender.establish()
        try:
            with self.assertRaisesRegex(
                    qi.IngressError, "establish.*can't be called"):
                sender.establish()
        finally:
            sender.close(flush=False)

    def test_qwp_udp_establish_after_close_rejected(self):
        self._require_qwp_udp()
        sender = self._mk_qwpudp_sender()
        sender.establish()
        sender.close(flush=False)
        with self.assertRaisesRegex(
                qi.IngressError, "establish.*can't be called"):
            sender.establish()

    def test_qwp_udp_decimal_zero_and_negative(self):
        self._require_qwp_udp()
        if self.qdb_plain.version < FIRST_DECIMAL_RELEASE:
            self.skipTest('old server does not support decimal')
        table_name = uuid.uuid4().hex
        self.qdb_plain.http_sql_query(
            f'CREATE TABLE {table_name} '
            f'(val DECIMAL(18,3), timestamp TIMESTAMP) '
            f'TIMESTAMP(timestamp) PARTITION BY DAY;')
        with self._mk_qwpudp_sender() as sender:
            sender.row(table_name,
                       columns={'val': decimal.Decimal('0.000')},
                       at=qi.TimestampNanos.now())
            sender.row(table_name,
                       columns={'val': decimal.Decimal('-0.000')},
                       at=qi.TimestampNanos.now())
            sender.row(table_name,
                       columns={'val': decimal.Decimal('-123456789.012')},
                       at=qi.TimestampNanos.now())
            sender.flush()
        resp = self.qdb_plain.retry_check_table(table_name, min_rows=3)
        vals = [row[0] for row in resp['dataset']]
        self.assertEqual(vals[0], '0.000')
        self.assertIn(vals[1], ('0.000', '-0.000'))
        self.assertEqual(vals[2], '-123456789.012')

    def test_qwp_udp_decimal_max_precision(self):
        self._require_qwp_udp()
        if self.qdb_plain.version < FIRST_DECIMAL_RELEASE:
            self.skipTest('old server does not support decimal')
        table_name = uuid.uuid4().hex
        self.qdb_plain.http_sql_query(
            f'CREATE TABLE {table_name} '
            f'(val DECIMAL(18,3), timestamp TIMESTAMP) '
            f'TIMESTAMP(timestamp) PARTITION BY DAY;')
        with self._mk_qwpudp_sender() as sender:
            sender.row(table_name,
                       columns={'val': decimal.Decimal('999999999999999.999')},
                       at=qi.TimestampNanos.now())
            sender.row(table_name,
                       columns={'val': decimal.Decimal('0.001')},
                       at=qi.TimestampNanos.now())
            sender.flush()
        resp = self.qdb_plain.retry_check_table(table_name, min_rows=2)
        vals = [row[0] for row in resp['dataset']]
        self.assertEqual(vals[0], '999999999999999.999')
        self.assertEqual(vals[1], '0.001')

    def test_qwp_udp_decimal_nan_inf_rejected(self):
        self._require_qwp_udp()
        if self.qdb_plain.version < FIRST_DECIMAL_RELEASE:
            self.skipTest('old server does not support decimal')
        table_name = uuid.uuid4().hex
        self.qdb_plain.http_sql_query(
            f'CREATE TABLE {table_name} '
            f'(val DECIMAL(18,3), timestamp TIMESTAMP) '
            f'TIMESTAMP(timestamp) PARTITION BY DAY;')
        with self._mk_qwpudp_sender() as sender:
            with self.assertRaises(qi.IngressError):
                sender.row(table_name,
                           columns={'val': decimal.Decimal('NaN')},
                           at=qi.TimestampNanos.now())
            with self.assertRaises(qi.IngressError):
                sender.row(table_name,
                           columns={'val': decimal.Decimal('Inf')},
                           at=qi.TimestampNanos.now())

    def test_qwp_udp_decimal_multiple_columns(self):
        self._require_qwp_udp()
        if self.qdb_plain.version < FIRST_DECIMAL_RELEASE:
            self.skipTest('old server does not support decimal')
        table_name = uuid.uuid4().hex
        self.qdb_plain.http_sql_query(
            f'CREATE TABLE {table_name} '
            f'(price DECIMAL(18,2), fee DECIMAL(18,6), timestamp TIMESTAMP) '
            f'TIMESTAMP(timestamp) PARTITION BY DAY;')
        with self._mk_qwpudp_sender() as sender:
            sender.row(table_name,
                       columns={
                           'price': decimal.Decimal('199.99'),
                           'fee': decimal.Decimal('0.000123')},
                       at=qi.TimestampNanos.now())
            sender.flush()
        resp = self.qdb_plain.retry_check_table(table_name, min_rows=1)
        row = resp['dataset'][0]
        self.assertEqual(row[0], '199.99')
        self.assertEqual(row[1], '0.000123')

    @unittest.skipIf(not pyarrow, 'pyarrow not installed')
    @unittest.skipIf(not pd, 'pandas not installed')
    def test_qwp_udp_decimal_pyarrow_nulls(self):
        self._require_qwp_udp()
        if self.qdb_plain.version < FIRST_DECIMAL_RELEASE:
            self.skipTest('old server does not support decimal')
        table_name = uuid.uuid4().hex
        self.qdb_plain.http_sql_query(
            f'CREATE TABLE {table_name} '
            f'(val DECIMAL(18,3), seq LONG, timestamp TIMESTAMP) '
            f'TIMESTAMP(timestamp) PARTITION BY DAY;')
        df = pd.DataFrame({
            'val': pd.array(
                [decimal.Decimal('1.5'), None, decimal.Decimal('3.25')],
                dtype=pd.ArrowDtype(pyarrow.decimal128(18, 3))),
            'seq': [1, 2, 3],
        })
        with self._mk_qwpudp_sender() as sender:
            sender.dataframe(df, table_name=table_name, at=qi.ServerTimestamp)
        resp = self.qdb_plain.retry_check_table(table_name, min_rows=3)
        vals = [row[0] for row in resp['dataset']]
        self.assertIn('1.500', vals)
        self.assertIn(None, vals)
        self.assertIn('3.250', vals)

    @unittest.skipIf(not pyarrow, 'pyarrow not installed')
    @unittest.skipIf(not pd, 'pandas not installed')
    def test_qwp_udp_decimal_pyarrow(self):
        self._require_qwp_udp()
        if self.qdb_plain.version < FIRST_DECIMAL_RELEASE:
            self.skipTest('old server does not support decimal')
        table_name = uuid.uuid4().hex
        self.qdb_plain.http_sql_query(
            f'CREATE TABLE {table_name} '
            f'(prices DECIMAL(18,3), timestamp TIMESTAMP) '
            f'TIMESTAMP(timestamp) PARTITION BY DAY;')
        df = pd.DataFrame({
            'prices': pd.array(
                [
                    decimal.Decimal('-99999.99'),
                    decimal.Decimal('-678'),
                ],
                dtype=pd.ArrowDtype(pyarrow.decimal128(18, 2))
            )
        })
        with self._mk_qwpudp_sender() as sender:
            sender.dataframe(df, table_name=table_name, at=qi.ServerTimestamp)
        resp = self.qdb_plain.retry_check_table(table_name, min_rows=2)
        exp_columns = [
            {'name': 'prices', 'type': 'DECIMAL(18,3)'},
            {'name': 'timestamp', 'type': 'TIMESTAMP'}]
        self.assertEqual(resp['columns'], exp_columns)
        scrubbed = [row[:-1] for row in resp['dataset']]
        self.assertEqual(scrubbed, [['-99999.990'], ['-678.000']])

    def test_f64_arr(self):
        if self.qdb_plain.version < FIRST_ARRAY_RELEASE:
            self.skipTest('old server does not support array')
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
        with qi.Sender('http', 'localhost', self.qdb_plain.http_server_port) as sender:
            sender.row(
                table_name,
                columns={
                    'f64_arr1': array1,
                    'f64_arr2': array2,
                    'f64_arr3': array3},
                at=qi.ServerTimestamp)
        resp = self.qdb_plain.retry_check_table(table_name)
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

    def test_decimal_py_obj(self):
        if self.qdb_plain.version < FIRST_DECIMAL_RELEASE:
            self.skipTest('old server does not support decimal')

        table_name = uuid.uuid4().hex
        self.qdb_plain.http_sql_query(f'CREATE TABLE {table_name} (dec_col DECIMAL(18,3), timestamp TIMESTAMP) TIMESTAMP(timestamp) PARTITION BY DAY;')

        pending = None
        with qi.Sender('http', 'localhost', self.qdb_plain.http_server_port) as sender:
            sender.row(
                table_name,
                columns={
                    'dec_col': decimal.Decimal('12345.678')},
                at=qi.ServerTimestamp)
            pending = bytes(sender)
        
        resp = self.qdb_plain.retry_check_table(table_name, min_rows=1, log_ctx=pending)
        exp_columns = [{'name': 'dec_col', 'type': 'DECIMAL(18,3)'},
                       {'name': 'timestamp', 'type': 'TIMESTAMP'}]
        self.assertEqual(resp['columns'], exp_columns)
        expected_data = [['12345.678']]
        scrubbed_data = [row[:-1] for row in resp['dataset']]
        self.assertEqual(scrubbed_data, expected_data)

    @unittest.skipIf(not pyarrow, 'pyarrow not installed')
    @unittest.skipIf(not pd, 'pandas not installed')
    def test_decimal_pyarrow(self):
        if self.qdb_plain.version < FIRST_DECIMAL_RELEASE:
            self.skipTest('old server does not support decimal')

        table_name = uuid.uuid4().hex
        self.qdb_plain.http_sql_query(f'CREATE TABLE {table_name} (prices DECIMAL(18,3), timestamp TIMESTAMP) TIMESTAMP(timestamp) PARTITION BY DAY;')

        df = pd.DataFrame({
            'prices': pd.array(
                [
                    decimal.Decimal('-99999.99'),
                    decimal.Decimal('-678'),
                ],
                dtype=pd.ArrowDtype(pyarrow.decimal128(18, 2))
            )
        })

        pending = None
        with qi.Sender('http', 'localhost', self.qdb_plain.http_server_port) as sender:
            sender.dataframe(df, table_name=table_name, at=qi.ServerTimestamp)
            pending = bytes(sender)

        resp = self.qdb_plain.retry_check_table(table_name, min_rows=2, log_ctx=pending)
        exp_columns = [{'name': 'prices', 'type': 'DECIMAL(18,3)'},
                       {'name': 'timestamp', 'type': 'TIMESTAMP'}]
        self.assertEqual(resp['columns'], exp_columns)
        expected_data = [
            ['-99999.990'],
            ['-678.000'],
        ]
        scrubbed_data = [row[:-1] for row in resp['dataset']]
        self.assertEqual(scrubbed_data, expected_data)

if __name__ == '__main__':
    unittest.main()
