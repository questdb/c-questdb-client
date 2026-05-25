#!/usr/bin/env python3
import sys

sys.dont_write_bytecode = True
import os
import unittest
import datetime
import timeit
import time
from enum import Enum
import random
import pathlib
import tempfile
import numpy as np

import patch_path

from test_tools import (
    _float_binary_bytes,
    _array_binary_bytes,
    TimestampEncodingMixin)

PROJ_ROOT = patch_path.PROJ_ROOT
sys.path.append(str(PROJ_ROOT / 'c-questdb-client' / 'system_test'))

from mock_server import (Server, HttpServer, SETTINGS_WITHOUT_PROTOCOL_VERSION,
                         SETTINGS_WITH_PROTOCOL_VERSION_V1, SETTINGS_WITH_PROTOCOL_VERSION_V2,
                         SETTINGS_WITH_PROTOCOL_VERSION_V1_V2_V3,SETTINGS_WITH_PROTOCOL_VERSION_V4)

import questdb.ingress as qi

if os.environ.get('TEST_QUESTDB_INTEGRATION') == '1':
    from system_test import TestWithDatabase

from fixture import _parse_version

NUMPY_VERSION = _parse_version(np.__version__)

try:
    import pandas as pd
    import numpy
    import pyarrow
except ImportError:
    pd = None

if pd is not None:
    from test_dataframe import TestPandasProtocolVersionV1
    from test_dataframe import TestPandasProtocolVersionV2
    from test_dataframe import TestPandasProtocolVersionV3
else:
    class TestNoPandas(unittest.TestCase):
        def test_no_pandas(self):
            buf = qi.Buffer(protocol_version=2)
            exp = 'Missing.*`pandas.*pyarrow`.*readthedocs.*installation.html.'
            with self.assertRaisesRegex(ImportError, exp):
                buf.dataframe(None, at=qi.ServerTimestamp)


class TestManifest(unittest.TestCase):
    def test_valid_yaml(self):
        try:
            import yaml
        except ImportError:
            self.skipTest('Python version does not support yaml')
        examples_manifest_file = pathlib.Path(__file__).parent.parent / 'examples.manifest.yaml'
        with open(examples_manifest_file, 'r') as f:
            yaml.safe_load(f)


class TestQwpWebSocketApi(unittest.TestCase):
    def test_protocol_enum(self):
        self.assertEqual(qi.Protocol.parse('qwpws'), qi.Protocol.QwpWs)
        self.assertEqual(qi.Protocol.parse('qwpwss'), qi.Protocol.QwpWss)
        self.assertFalse(qi.Protocol.QwpWs.tls_enabled)
        self.assertTrue(qi.Protocol.QwpWss.tls_enabled)

    def test_progress_enum(self):
        self.assertEqual(
            qi.QwpWsProgress.parse('background'),
            qi.QwpWsProgress.Background)
        self.assertEqual(
            qi.QwpWsProgress.parse('manual'),
            qi.QwpWsProgress.Manual)

    def test_ingress_error_can_carry_qwpws_diagnostic(self):
        err = qi.IngressError(
            qi.IngressErrorCode.SocketError,
            'sender halted',
            (
                qi.QwpWsErrorCategory.ParseError.c_value,
                qi.QwpWsErrorPolicy.Halt.c_value,
                2,
                'bad line',
                44,
                5,
                6,
            ))

        diagnostic = err.qwp_ws_error

        self.assertEqual(diagnostic.category, qi.QwpWsErrorCategory.ParseError)
        self.assertEqual(diagnostic.applied_policy, qi.QwpWsErrorPolicy.Halt)
        self.assertEqual(diagnostic.status, 2)
        self.assertEqual(diagnostic.message, 'bad line')
        self.assertEqual(diagnostic.message_sequence, 44)
        self.assertEqual(diagnostic.from_fsn, 5)
        self.assertEqual(diagnostic.to_fsn, 6)
        self.assertIs(err.qwp_ws_error, diagnostic)

    def test_server_rejection_error_is_specific_subclass(self):
        err = qi.IngressServerRejectionError(
            qi.IngressErrorCode.ServerRejection,
            'sender halted',
            (
                qi.QwpWsErrorCategory.ParseError.c_value,
                qi.QwpWsErrorPolicy.Halt.c_value,
                2,
                'bad line',
                44,
                5,
                6,
            ))

        self.assertIsInstance(err, qi.IngressError)
        self.assertEqual(err.code, qi.IngressErrorCode.ServerRejection)
        self.assertEqual(err.qwp_ws_error.category, qi.QwpWsErrorCategory.ParseError)

    def test_python_only_error_codes_do_not_overlap_ffi_codes(self):
        self.assertNotEqual(
            qi.IngressErrorCode.BadDataFrame,
            qi.IngressErrorCode.ServerRejection)

    def test_from_conf_preserves_qwpws_progress(self):
        sender = qi.Sender.from_conf(
            'qwpws::addr=localhost:9000;qwp_ws_progress=manual;')
        try:
            with self.assertRaisesRegex(
                    qi.IngressError,
                    r'drive_once\(\) can\'t be called: Sender is closed'):
                sender.drive_once()
        finally:
            sender.close(False)

    def test_from_conf_preserves_c_only_qwpws_keys(self):
        with self.assertRaisesRegex(
                qi.IngressError,
                'invalid sf_max_bytes'):
            qi.Sender.from_conf('qwpws::addr=localhost:9000;sf_max_bytes=64mi;')

    def test_from_conf_accepts_qwpwss_tls_roots_password(self):
        with tempfile.NamedTemporaryFile() as roots:
            sender = qi.Sender.from_conf(
                'qwpwss::addr=localhost:9000;'
                f'tls_roots={roots.name};'
                'tls_roots_password=secret;')
            try:
                self.assertIsInstance(sender, qi.Sender)
            finally:
                sender.close(False)

    def test_tls_roots_password_rejects_non_qwp_websocket(self):
        with tempfile.NamedTemporaryFile() as roots:
            with self.assertRaisesRegex(
                    qi.IngressError,
                    'only supported for QWP/WebSocket'):
                qi.Sender.from_conf(
                    'tcps::addr=localhost:9009;'
                    f'tls_roots={roots.name};'
                    'tls_roots_password=secret;')

    def test_from_conf_preserves_http_retry_max_backoff(self):
        with self.assertRaisesRegex(
                qi.IngressError,
                'retry_max_backoff_millis.*at least 10'):
            qi.Sender.from_conf(
                'http::addr=localhost:9000;retry_max_backoff_millis=3;')

    def test_retry_max_backoff_rejects_non_http_protocol(self):
        with self.assertRaisesRegex(
                qi.IngressError,
                'retry_max_backoff_millis is supported only in ILP over HTTP'):
            qi.Sender(
                qi.Protocol.Tcp,
                '127.0.0.1',
                9009,
                retry_max_backoff=250)

    def test_from_conf_preserves_escaped_semicolon_in_c_only_qwpws_key(self):
        sender = qi.Sender.from_conf(
            'qwpws::addr=localhost:9000;sf_dir=/tmp/qdb;;sf;')
        try:
            self.assertIsInstance(sender, qi.Sender)
        finally:
            sender.close(False)

    def test_qwpws_progress_rejects_non_websocket_protocol(self):
        with self.assertRaisesRegex(
                qi.IngressError,
                'only supported for QWP/WebSocket'):
            qi.Sender(
                qi.Protocol.QwpUdp,
                '127.0.0.1',
                9009,
                qwp_ws_progress=qi.QwpWsProgress.Manual)

    def test_qwpws_error_handler_can_be_registered(self):
        sender = qi.Sender(
            qi.Protocol.QwpWs,
            '127.0.0.1',
            9000,
            qwp_ws_error_handler=lambda error: None)
        try:
            self.assertIsInstance(sender, qi.Sender)
        finally:
            sender.close(False)

    def test_qwpws_error_handler_rejects_non_websocket_protocol(self):
        with self.assertRaisesRegex(
                qi.IngressError,
                'only supported for QWP/WebSocket'):
            qi.Sender(
                qi.Protocol.QwpUdp,
                '127.0.0.1',
                9009,
                qwp_ws_error_handler=lambda error: None)

    def test_qwpws_fsn_helpers_reject_non_websocket_sender_even_when_empty(self):
        sender = qi.Sender(
            qi.Protocol.QwpUdp,
            '127.0.0.1',
            9009)
        try:
            sender.establish()
            with self.assertRaisesRegex(
                    qi.IngressError,
                    'only supported for QWP/WebSocket'):
                sender.flush_and_get_fsn()
            with self.assertRaisesRegex(
                    qi.IngressError,
                    'only supported for QWP/WebSocket'):
                sender.flush_and_keep_and_get_fsn()
        finally:
            sender.close(False)

    def test_qwpws_progress_conf_override_conflict(self):
        with self.assertRaisesRegex(ValueError, '"qwp_ws_progress" is already present'):
            qi.Sender.from_conf(
                'qwpws::addr=localhost:9000;qwp_ws_progress=manual;',
                qwp_ws_progress=qi.QwpWsProgress.Background)


class TestBases:
    """
    Dummy class that's only used so that we can create subclasses of testcases.

    By nesting these base classes within another class, Python's `unittest` will
    not find them.

    The discoverable subclasses can drive extra parameters.
    """

    class TestBuffer(unittest.TestCase, TimestampEncodingMixin):
        def _test_buffer_row_ts(self, ts):
            buffer = qi.Buffer(protocol_version=self.version)
            buffer.row('trades', columns={'t': ts}, at=ts)
            ec = self.enc_ts
            ed = self.enc_des_ts
            exp = f'trades t={ec(ts)} {ed(ts)}\n'.encode()
            self.assertEqual(bytes(buffer), exp)

        def test_buffer_row_ts_micros(self):
            self._test_buffer_row_ts(qi.TimestampMicros(10001))

        def test_buffer_row_ts_nanos(self):
            self._test_buffer_row_ts(qi.TimestampNanos(10000333))

        def test_buffer_row_ts_datetime(self):
            self._test_buffer_row_ts(datetime.datetime.now())

        def test_buffer_row_at_disallows_none(self):
            with self.assertRaisesRegex(
                    qi.IngressError,
                    'must be of type TimestampNanos, datetime, or ServerTimestamp'):
                buffer = qi.Buffer(protocol_version=self.version)
                buffer.row('tbl1', symbols={'sym1': 'val1'}, at=None)
            with self.assertRaisesRegex(
                    TypeError,
                    'needs keyword-only argument at'):
                buffer = qi.Buffer(protocol_version=self.version)
                buffer.row('tbl1', symbols={'sym1': 'val1'})

        @unittest.skipIf(not pd, 'pandas not installed')
        def test_buffer_dataframe_at_disallows_none(self):
            with self.assertRaisesRegex(
                    qi.IngressError,
                    'must be of type TimestampNanos, datetime, or ServerTimestamp'):
                buffer = qi.Buffer(protocol_version=self.version)
                buffer.dataframe(pd.DataFrame(), at=None)
            with self.assertRaisesRegex(
                    TypeError,
                    'needs keyword-only argument at'):
                buffer = qi.Buffer(protocol_version=self.version)
                buffer.dataframe(pd.DataFrame())

        def test_new(self):
            buf = qi.Buffer(protocol_version=self.version)
            self.assertEqual(len(buf), 0)
            self.assertEqual(buf.capacity(), 64 * 1024)

        def test_basic(self):
            buf = qi.Buffer(protocol_version=self.version)
            buf.row('tbl1', symbols={'sym1': 'val1', 'sym2': 'val2'}, at=qi.ServerTimestamp)
            self.assertEqual(len(buf), 25)
            self.assertEqual(bytes(buf), b'tbl1,sym1=val1,sym2=val2\n')

        def test_bad_table(self):
            buf = qi.Buffer(protocol_version=self.version)
            with self.assertRaisesRegex(
                    qi.IngressError,
                    'Table names must have a non-zero length'):
                buf.row('', symbols={'sym1': 'val1'}, at=qi.ServerTimestamp)
            with self.assertRaisesRegex(
                    qi.IngressError,
                    'Bad string "x..y": Found invalid dot `.` at position 2.'):
                buf.row('x..y', symbols={'sym1': 'val1'}, at=qi.ServerTimestamp)

        def test_symbol(self):
            buf = qi.Buffer(protocol_version=self.version)
            buf.row('tbl1', symbols={'sym1': 'val1', 'sym2': 'val2'}, at=qi.ServerTimestamp)
            self.assertEqual(bytes(buf), b'tbl1,sym1=val1,sym2=val2\n')

        def test_bad_symbol_column_name(self):
            buf = qi.Buffer(protocol_version=self.version)
            with self.assertRaisesRegex(
                    qi.IngressError,
                    'Column names must have a non-zero length.'):
                buf.row('tbl1', symbols={'': 'val1'}, at=qi.ServerTimestamp)
            with self.assertRaisesRegex(
                    qi.IngressError,
                    'Bad string "sym.bol": '
                    'Column names can\'t contain a \'.\' character, '
                    'which was found at byte position 3.'):
                buf.row('tbl1', symbols={'sym.bol': 'val1'}, at=qi.ServerTimestamp)

        def test_column(self):
            two_h_after_epoch = datetime.datetime(
                1970, 1, 1, 2, tzinfo=datetime.timezone.utc)
            buf = qi.Buffer(protocol_version=self.version)
            buf.row('tbl1', columns={
                'col1': True,
                'col2': False,
                'col3': -1,
                'col4': 0.5,
                'col5': 'val',
                'col6': qi.TimestampMicros(12345),
                'col7': qi.TimestampNanos(12345678),
                'col8': two_h_after_epoch,
                'col9': None}, at=qi.ServerTimestamp)
            et = self.enc_ts_t
            en = self.enc_ts_n
            exp = (
                b'tbl1 col1=t,col2=f,col3=-1i,col4' + _float_binary_bytes(0.5, self.version == 1) +
                f',col5="val",col6={et(12345)},col7={en(12345678)},col8={et(7200000000)}\n'.encode())
            self.assertEqual(bytes(buf), exp)

        def test_none_symbol(self):
            buf = qi.Buffer(protocol_version=self.version)
            buf.row('tbl1', symbols={'sym1': 'val1', 'sym2': None}, at=qi.ServerTimestamp)
            exp = b'tbl1,sym1=val1\n'
            self.assertEqual(bytes(buf), exp)
            self.assertEqual(len(buf), len(exp))

            # No fields to write, no fields written, therefore a no-op.
            buf.row('tbl1', symbols={'sym1': None, 'sym2': None}, at=qi.ServerTimestamp)
            self.assertEqual(bytes(buf), exp)
            self.assertEqual(len(buf), len(exp))

        def test_none_column(self):
            buf = qi.Buffer(protocol_version=self.version)
            buf.row('tbl1', columns={'col1': 1}, at=qi.ServerTimestamp)
            exp = b'tbl1 col1=1i\n'
            self.assertEqual(bytes(buf), exp)
            self.assertEqual(len(buf), len(exp))

            # No fields to write, no fields written, therefore a no-op.
            buf.row('tbl1', columns={'col1': None, 'col2': None}, at=qi.ServerTimestamp)
            self.assertEqual(bytes(buf), exp)
            self.assertEqual(len(buf), len(exp))

        def test_no_symbol_or_col_args(self):
            buf = qi.Buffer(protocol_version=self.version)
            buf.row('table_name', at=qi.ServerTimestamp)
            self.assertEqual(bytes(buf), b'')

        def test_unicode(self):
            buf = qi.Buffer(protocol_version=self.version)
            buf.row(
                'tbl1',  # ASCII
                symbols={'questdb1': 'q❤️p'},  # Mixed ASCII and UCS-2
                columns={'questdb2': '❤️' * 1200},
                at=qi.ServerTimestamp)  # Over the 1024 buffer prealloc.
            buf.row(
                'tbl1',
                symbols={
                    'Questo è il nome di una colonna':  # Non-ASCII UCS-1
                        'Це символьне значення'},  # UCS-2, 2 bytes for UTF-8.
                columns={
                    'questdb1': '',  # Empty string
                    'questdb2': '嚜꓂',  # UCS-2, 3 bytes for UTF-8.
                    'questdb3': '💩🦞'},
                at=qi.ServerTimestamp)  # UCS-4, 4 bytes for UTF-8.
            self.assertEqual(bytes(buf),
                             (f'tbl1,questdb1=q❤️p questdb2="{"❤️" * 1200}"\n' +
                             'tbl1,Questo\\ è\\ il\\ nome\\ di\\ una\\ colonna=' +
                             'Це\\ символьне\\ значення ' +
                             'questdb1="",questdb2="嚜꓂",questdb3="💩🦞"\n').encode('utf-8'))

            buf.clear()
            buf.row('tbl1', symbols={'questdb1': 'q❤️p'}, at=qi.ServerTimestamp)
            self.assertEqual(bytes(buf), 'tbl1,questdb1=q❤️p\n'.encode('utf-8'))

            # A bad char in Python.
            with self.assertRaisesRegex(
                    qi.IngressError,
                    '.*codepoint 0xd800 in string .*'):
                buf.row('tbl1', symbols={'questdb1': 'a\ud800'}, at=qi.ServerTimestamp)

            # Strong exception safety: no partial writes.
            # Ensure we can continue using the buffer after an error.
            buf.row('tbl1', symbols={'questdb1': 'another line of input'}, at=qi.ServerTimestamp)
            self.assertEqual(
                bytes(buf),
                ('tbl1,questdb1=q❤️p\n' +
                # Note: No partially written failed line here.
                'tbl1,questdb1=another\\ line\\ of\\ input\n').encode('utf-8'))

        def test_float(self):
            buf = qi.Buffer(protocol_version=self.version)
            buf.row('tbl1', columns={'num': 1.2345678901234567}, at=qi.ServerTimestamp)
            self.assertEqual(bytes(buf), b'tbl1 num' + _float_binary_bytes(1.2345678901234567, self.version == 1) + b'\n')

        def test_array_basic(self):
            if self.version == 1:
                self.skipTest('Protocol version v1 doesn\'t support arrays')
            buf = qi.Buffer(protocol_version=self.version)
            arr = np.array([1.2345678901234567, 2.3456789012345678], dtype=np.float64)
            buf.row('tbl1', columns={'array': arr}, at=qi.ServerTimestamp)
            self.assertEqual(bytes(buf), b'tbl1 array=' + _array_binary_bytes(arr) + b'\n')

        def test_array_edge_cases(self):
            if self.version == 1:
                self.skipTest('Protocol version v1 doesn\'t support arrays')
            # empty array
            buf = qi.Buffer(protocol_version=self.version)
            empty_arr = np.array([], dtype=np.float64)
            buf.row('empty_table', columns={'col': empty_arr}, at=qi.ServerTimestamp)
            empty_expected = b'empty_table col=' + _array_binary_bytes(empty_arr) + b'\n'
            self.assertEqual(bytes(buf), empty_expected)

            # non contigious array
            base = np.arange(6, dtype=np.float64).reshape(2, 3)
            non_contig_arr = base[:, ::2]  # shape (2, 2), strides (24, 16)
            buf = qi.Buffer(protocol_version=self.version)
            buf.row('non_contig_table', columns={'col': non_contig_arr}, at=qi.ServerTimestamp)
            non_contig_expected = b'non_contig_table col=' + _array_binary_bytes(non_contig_arr) + b'\n'
            self.assertEqual(bytes(buf), non_contig_expected)

            # minus stride
            reversed_arr = np.array([1.1, 2.2, 3.3], dtype=np.float64)[::-1]  # strides -8
            buf = qi.Buffer(protocol_version=self.version)
            buf.row('reversed_table', columns={'col': reversed_arr}, at=qi.ServerTimestamp)
            reversed_expected = b'reversed_table col=' + _array_binary_bytes(reversed_arr) + b'\n'
            self.assertEqual(bytes(buf), reversed_expected)

            # zero dimensional array
            with self.assertRaisesRegex(qi.IngressError, "Zero-dimensional arrays are not supported"):
                scalar_arr = np.array(42.0, dtype=np.float64)
                buf = qi.Buffer(protocol_version=self.version)
                buf.row('scalar_table', columns={'col': scalar_arr}, at=qi.ServerTimestamp)

            # not f64 dtype array
            with self.assertRaisesRegex(qi.IngressError, "Only float64 numpy arrays are supported, got dtype: complex64"):
                complex_arr = np.array([1 + 2j], dtype=np.complex64)
                buf.row('invalid_table', columns={'col': complex_arr}, at=qi.ServerTimestamp)

        def test_int_range(self):
            buf = qi.Buffer(protocol_version=self.version)
            buf.row('tbl1', columns={'num': 0}, at=qi.ServerTimestamp)
            self.assertEqual(bytes(buf), f'tbl1 num=0i\n'.encode('utf-8'))
            buf.clear()

            # 32-bit int range.
            buf.row('tbl1', columns={'min': -2 ** 31, 'max': 2 ** 31 - 1}, at=qi.ServerTimestamp)
            self.assertEqual(bytes(buf), f'tbl1 min=-2147483648i,max=2147483647i\n'.encode('utf-8'))
            buf.clear()

            # 64-bit int range.
            buf.row('tbl1', columns={'min': -2 ** 63, 'max': 2 ** 63 - 1}, at=qi.ServerTimestamp)
            self.assertEqual(bytes(buf), f'tbl1 min=-9223372036854775808i,max=9223372036854775807i\n'.encode('utf-8'))
            buf.clear()

            # Overflow.
            with self.assertRaises(OverflowError):
                buf.row('tbl1', columns={'num': 2 ** 63}, at=qi.ServerTimestamp)

            # Underflow.
            with self.assertRaises(OverflowError):
                buf.row('tbl1', columns={'num': -2 ** 63 - 1}, at=qi.ServerTimestamp)

    class TestSender(unittest.TestCase, TimestampEncodingMixin):
        def test_transaction_row_at_disallows_none(self):
            with HttpServer() as server, self.builder('http', '127.0.0.1', server.port) as sender:
                with self.assertRaisesRegex(
                        qi.IngressError,
                        'must be of type TimestampNanos, datetime, or ServerTimestamp'):
                    with sender.transaction("foo") as txn:
                        txn.row(symbols={'sym1': 'val1'}, at=None)
                with self.assertRaisesRegex(
                        TypeError,
                        'needs keyword-only argument at'):
                    with sender.transaction("foo") as txn:
                        txn.row(symbols={'sym1': 'val1'})

        @unittest.skipIf(not pd, 'pandas not installed')
        def test_transaction_dataframe_at_disallows_none(self):
            with HttpServer() as server, self.builder('http', '127.0.0.1', server.port) as sender:
                with self.assertRaisesRegex(
                        qi.IngressError,
                        'must be of type TimestampNanos, datetime, or ServerTimestamp'):
                    with sender.transaction("foo") as txn:
                        txn.dataframe(pd.DataFrame(), at=None)
                with self.assertRaisesRegex(
                        TypeError,
                        'needs keyword-only argument at'):
                    with sender.transaction("foo") as txn:
                        txn.dataframe(pd.DataFrame())

        def test_sender_row_at_disallows_none(self):
            with Server() as server, self.builder('tcp', '127.0.0.1', server.port) as sender:
                with self.assertRaisesRegex(
                        qi.IngressError,
                        'must be of type TimestampNanos, datetime, or ServerTimestamp'):
                    sender.row('tbl1', symbols={'sym1': 'val1'}, at=None)
                with self.assertRaisesRegex(
                        TypeError,
                        'needs keyword-only argument at'):
                    sender.row('tbl1', symbols={'sym1': 'val1'})

        @unittest.skipIf(not pd, 'pandas not installed')
        def test_sender_dataframe_at_disallows_none(self):
            with Server() as server, self.builder('tcp', '127.0.0.1', server.port) as sender:
                with self.assertRaisesRegex(
                        qi.IngressError,
                        'must be of type TimestampNanos, datetime, or ServerTimestamp'):
                    sender.dataframe(pd.DataFrame(), at=None)
                with self.assertRaisesRegex(
                        TypeError,
                        'needs keyword-only argument at'):
                    sender.dataframe(pd.DataFrame())

        def test_basic(self):
            with Server() as server, \
                    self.builder(
                        'tcp',
                        '127.0.0.1',
                        server.port,
                        bind_interface='0.0.0.0',
                        protocol_version='2') as sender:
                server.accept()
                self.assertEqual(server.recv(), [])
                sender.row(
                    'tab1',
                    symbols={
                        't1': 'val1',
                        't2': 'val2'},
                    columns={
                        'f1': True,
                        'f2': 12345,
                        'f3': 10.75,
                        'f4': 'val3'},
                    at=qi.TimestampNanos(111222233333))
                sender.row(
                    'tab1',
                    symbols={
                        'tag3': 'value 3',
                        'tag4': 'value:4'},
                    columns={
                        'field5': False},
                    at=qi.ServerTimestamp)
                sender.flush()
                msgs = server.recv()
                self.assertEqual(msgs, [
                    (b'tab1,t1=val1,t2=val2 '
                     b'f1=t,f2=12345i,f3' + _float_binary_bytes(10.75) + b',f4="val3" ' +
                     self.enc_des_ts_n(111222233333, v=2).encode()),
                    b'tab1,tag3=value\\ 3,tag4=value:4 field5=f'])
                
        def test_bad_protocol_versions(self):
            bad_versions = [
                '0',
                'automatic',
                0,
                4,
                '4',
                '1.5',
                '2.0',
            ]

            for version in bad_versions:
                with self.assertRaisesRegex(
                        qi.IngressError,
                        '"protocol_version" must be None, "auto", 1-3'):
                    self.builder('tcp', '127.0.0.1', 12345, protocol_version=version)
                    self.fail('Should not have reached here - constructing sender')

            bad_versions.append(None)
            for version in bad_versions:
                with self.assertRaises(Exception) as capture:
                    qi.Buffer(protocol_version=version)
                    self.fail('Should not have reached here - constructing buffer')

                self.assertIn(type(capture.exception), (qi.IngressError, TypeError))

                if isinstance(capture.exception, qi.IngressError):
                    self.assertEqual(capture.exception.code, qi.IngressErrorCode.ProtocolVersionError)
                    self.assertIn('Invalid protocol version', str(capture.exception))

        def test_connect_close(self):
            with Server() as server:
                sender = None
                try:
                    sender = self.builder('tcp', '127.0.0.1', server.port)
                    sender.establish()
                    server.accept()
                    self.assertEqual(server.recv(), [])
                    sender.row('tbl1', symbols={'sym1': 'val1'}, at=qi.ServerTimestamp)
                    sender.flush()
                    msgs = server.recv()
                    self.assertEqual(msgs, [b'tbl1,sym1=val1'])
                finally:
                    sender.close()

        def test_row_before_connect(self):
            try:
                sender = self.builder('tcp', '127.0.0.1', 12345)
                with self.assertRaisesRegex(qi.IngressError, 'Sender is closed'):
                    sender.row('tbl1', symbols={'sym1': 'val1'}, at=qi.ServerTimestamp)
            finally:
                sender.close()

        def test_flush_1(self):
            with Server() as server:
                with self.builder('tcp', '127.0.0.1', server.port) as sender:
                    server.accept()
                    with self.assertRaisesRegex(qi.IngressError, 'Column names'):
                        sender.row('tbl1', symbols={'...bad name..': 'val1'}, at=qi.ServerTimestamp)
                    self.assertEqual(bytes(sender), b'')
                    sender.flush()
                    self.assertEqual(bytes(sender), b'')
                msgs = server.recv()
                self.assertEqual(msgs, [])

        def test_flush_2(self):
            with Server() as server:
                with self.builder('tcp', '127.0.0.1', server.port) as sender:
                    server.accept()
                    server.close()

                    # We enter a bad state where we can't flush again.
                    with self.assertRaises(qi.IngressError):
                        for _ in range(1000):
                            time.sleep(0.01)
                            sender.row('tbl1', symbols={'a': 'b'}, at=qi.ServerTimestamp)
                            sender.flush()

                    # We should still be in a bad state.
                    with self.assertRaises(qi.IngressError):
                        sender.row('tbl1', symbols={'a': 'b'}, at=qi.ServerTimestamp)
                        sender.flush()

                # Leaving the `with` scope will call __exit__ and here we test
                # that a prior exception will not cause subsequent problems.

        def test_flush_3(self):
            # Same as test_flush_2, but we catch the exception _outside_ the
            # sender's `with` block, to ensure no exceptions get trapped.
            with Server() as server:
                with self.assertRaises(qi.IngressError):
                    with self.builder('tcp', '127.0.0.1', server.port) as sender:
                        server.accept()
                        server.close()
                        for _ in range(1000):
                            time.sleep(0.01)
                            sender.row('tbl1', symbols={'a': 'b'}, at=qi.ServerTimestamp)
                            sender.flush()

        def test_flush_4(self):
            # Clearing of the internal buffer is not allowed.
            with Server() as server:
                with self.assertRaises(ValueError):
                    with self.builder('tcp', '127.0.0.1', server.port) as sender:
                        server.accept()
                        sender.row('tbl1', symbols={'a': 'b'}, at=qi.ServerTimestamp)
                        sender.flush(buffer=None, clear=False)

        def test_two_rows_explicit_buffer(self):
            with Server() as server, self.builder('tcp', '127.0.0.1', server.port, protocol_version='2') as sender:
                server.accept()
                self.assertEqual(server.recv(), [])
                buffer = sender.new_buffer()
                buffer.row(
                    'line_sender_buffer_example2',
                    symbols={'id': 'Hola'},
                    columns={'price': '111222233333i', 'qty': 3.5},
                    at=qi.TimestampNanos(111222233333))
                buffer.row(
                    'line_sender_example',
                    symbols={'id': 'Adios'},
                    columns={'price': '111222233343i', 'qty': 2.5},
                    at=qi.TimestampNanos(111222233343))
                exp = (
                    b'line_sender_buffer_example2,id=Hola price="111222233333i",qty' + _float_binary_bytes(3.5) + b' 111222233333n\n'
                    b'line_sender_example,id=Adios price="111222233343i",qty' + _float_binary_bytes(2.5) + b' 111222233343n\n')
                self.assertEqual(bytes(buffer), exp)
                sender.flush(buffer)
                msgs = server.recv()
                bexp = [msg for msg in exp.rstrip().split(b'\n')]
                self.assertEqual(msgs, bexp)

        def test_independent_buffer(self):
            buf = qi.Buffer(protocol_version=2)
            buf.row('tbl1', symbols={'sym1': 'val1'}, at=qi.ServerTimestamp)
            exp = b'tbl1,sym1=val1\n'
            self.assertEqual(bytes(buf), exp)

            with Server() as server1, Server() as server2:
                with self.builder('tcp', '127.0.0.1', server1.port, protocol_version='2') as sender1, \
                        self.builder('tcp', '127.0.0.1', server2.port, protocol_version='2') as sender2:
                    server1.accept()
                    server2.accept()

                    sender1.flush(buf, clear=False)
                    self.assertEqual(bytes(buf), exp)

                    sender2.flush(buf, clear=False)
                    self.assertEqual(bytes(buf), exp)

                    msgs1 = server1.recv()
                    msgs2 = server2.recv()
                    self.assertEqual(msgs1, [exp[:-1]])
                    self.assertEqual(msgs2, [exp[:-1]])

                    sender1.flush(buf)
                    self.assertEqual(server1.recv(), [exp[:-1]])

                    # The buffer is now auto-cleared.
                    self.assertEqual(bytes(buf), b'')

        def test_auto_flush_settings_defaults(self):
            for protocol in ('tcp', 'tcps', 'http', 'https'):
                sender = self.builder(protocol, '127.0.0.1', 9009)
                self.assertTrue(sender.auto_flush)
                self.assertEqual(sender.auto_flush_bytes, None)
                self.assertEqual(
                    sender.auto_flush_rows,
                    75000 if protocol.startswith('http') else 600)
                self.assertEqual(sender.auto_flush_interval, datetime.timedelta(seconds=1))

        def test_auto_flush_settings_off(self):
            for protocol in ('tcp', 'tcps', 'http', 'https'):
                sender = self.builder(protocol, '127.0.0.1', 9009, auto_flush=False)
                self.assertFalse(sender.auto_flush)
                self.assertEqual(sender.auto_flush_bytes, None)
                self.assertEqual(sender.auto_flush_rows, None)
                self.assertEqual(sender.auto_flush_interval, None)

        def test_auto_flush_settings_on(self):
            for protocol in ('tcp', 'tcps', 'http', 'https'):
                sender = self.builder(protocol, '127.0.0.1', 9009, auto_flush=True)
                # Same as default.
                self.assertEqual(sender.auto_flush_bytes, None)
                self.assertEqual(
                    sender.auto_flush_rows,
                    75000 if protocol.startswith('http') else 600)
                self.assertEqual(sender.auto_flush_interval, datetime.timedelta(seconds=1))

        def test_auto_flush_settings_specified(self):
            for protocol in ('tcp', 'tcps', 'http', 'https'):
                sender = self.builder(
                    protocol,
                    '127.0.0.1',
                    9009,
                    auto_flush_bytes=1024,
                    auto_flush_rows=100,
                    auto_flush_interval=datetime.timedelta(milliseconds=50))
                self.assertTrue(sender.auto_flush)
                self.assertEqual(sender.auto_flush_bytes, 1024)
                self.assertEqual(sender.auto_flush_rows, 100)
                self.assertEqual(sender.auto_flush_interval, datetime.timedelta(milliseconds=50))

        def test_auto_flush(self):
            with Server() as server:
                with self.builder(
                        'tcp',
                        '127.0.0.1',
                        server.port,
                        auto_flush_bytes=4,
                        auto_flush_rows=False,
                        auto_flush_interval=False) as sender:
                    server.accept()
                    sender.row('tbl1', symbols={'sym1': 'val1'}, at=qi.ServerTimestamp)
                    self.assertEqual(len(sender), 0)  # auto-flushed buffer.
                    msgs = server.recv()
                    self.assertEqual(msgs, [b'tbl1,sym1=val1'])

        def test_immediate_auto_flush(self):
            with Server() as server:
                with self.builder('tcp', '127.0.0.1', server.port, auto_flush_rows=1) as sender:
                    server.accept()
                    sender.row('tbl1', symbols={'sym1': 'val1'}, at=qi.ServerTimestamp)
                    self.assertEqual(len(sender), 0)  # auto-flushed buffer.
                    msgs = server.recv()
                    self.assertEqual(msgs, [b'tbl1,sym1=val1'])

        def test_auto_flush_on_closed_socket(self):
            with Server() as server:
                with self.builder('tcp', '127.0.0.1', server.port, auto_flush_rows=1) as sender:
                    server.accept()
                    server.close()
                    exp_err = 'Could not flush buffer.* - See https'
                    with self.assertRaisesRegex(qi.IngressError, exp_err):
                        for _ in range(1000):
                            time.sleep(0.01)
                            sender.row('tbl1', symbols={'a': 'b'}, at=qi.ServerTimestamp)

        def test_dont_auto_flush(self):
            msg_counter = 0
            with Server() as server:
                with self.builder('tcp', '127.0.0.1', server.port, auto_flush=False) as sender:
                    server.accept()
                    while len(sender) < 32768:  # 32KiB
                        sender.row('tbl1', symbols={'sym1': 'val1'}, at=qi.ServerTimestamp)
                        msg_counter += 1
                    msgs = server.recv()
                    self.assertEqual(msgs, [])
                start = time.monotonic()
                msgs = []
                while len(msgs) < msg_counter:
                    msgs += server.recv()
                    elapsed = time.monotonic() - start
                    if elapsed > 30.0:
                        raise TimeoutError()

        def test_dont_flush_on_exception(self):
            with Server() as server:
                with self.assertRaises(RuntimeError):
                    with self.builder('tcp', '127.0.0.1', server.port) as sender:
                        server.accept()
                        sender.row('tbl1', symbols={'sym1': 'val1'}, at=qi.ServerTimestamp)
                        self.assertEqual(bytes(sender), b'tbl1,sym1=val1\n')
                        raise RuntimeError('Test exception')
                msgs = server.recv()
                self.assertEqual(msgs, [])

        @unittest.skipIf(not pd, 'pandas not installed')
        def test_dataframe(self):
            with Server() as server:
                with self.builder('tcp', '127.0.0.1', server.port, protocol_version='2') as sender:
                    server.accept()
                    df = pd.DataFrame({'a': [1, 2], 'b': [3.0, 4.0]})
                    sender.dataframe(df, table_name='tbl1', at=qi.ServerTimestamp)
                msgs = server.recv()
                self.assertEqual(
                    msgs,
                    [b'tbl1 a=1i,b' + _float_binary_bytes(3.0),
                     b'tbl1 a=2i,b' + _float_binary_bytes(4.0)])

        @unittest.skipIf(not pd, 'pandas not installed')
        def test_dataframe_auto_flush(self):
            with Server() as server:
                # An auto-flush size of 25 bytes is enough to auto-flush the first
                # row, but not the second.
                with self.builder(
                        'tcp',
                        '127.0.0.1',
                        server.port,
                        auto_flush_bytes=25,
                        auto_flush_rows=False,
                        auto_flush_interval=False,
                        protocol_version=2) as sender:
                    server.accept()
                    df = pd.DataFrame({'a': [100000, 2], 'b': [3.0, 4.0]})
                    sender.dataframe(df, table_name='tbl1', at=qi.ServerTimestamp)
                    msgs = server.recv()
                    self.assertEqual(
                        msgs,
                        [b'tbl1 a=100000i,b' + _float_binary_bytes(3.0),])

                    # The second row is still pending send.
                    self.assertEqual(len(sender), 23)

                    # So we give it some more data and we should see it flush.
                    sender.row('tbl1', columns={'a': 3, 'b': 5.0}, at=qi.ServerTimestamp)
                    msgs = server.recv()
                    self.assertEqual(
                        msgs,
                        [b'tbl1 a=2i,b' + _float_binary_bytes(4.0),
                         b'tbl1 a=3i,b' + _float_binary_bytes(5.0)])

                    self.assertEqual(len(sender), 0)

                    # We can now disconnect the server and see auto flush failing.
                    server.close()

                    exp_err = 'Could not flush buffer.* - See https'
                    with self.assertRaisesRegex(qi.IngressError, exp_err):
                        for _ in range(1000):
                            time.sleep(0.01)
                            sender.dataframe(df.head(1), table_name='tbl1', at=qi.ServerTimestamp)

        def test_new_buffer(self):
            with Server() as server:
                with self.builder(
                protocol='tcp',
                host='127.0.0.1',
                port=server.port,
                init_buf_size=1024,
                max_name_len=20) as sender:
                    buffer = sender.new_buffer()
                    self.assertEqual(buffer.init_buf_size, 1024)
                    self.assertEqual(buffer.max_name_len, 20)
                    self.assertEqual(buffer.init_buf_size, sender.init_buf_size)
                    self.assertEqual(buffer.max_name_len, sender.max_name_len)

        def test_connect_after_close(self):
            with Server() as server, self.builder('tcp', '127.0.0.1', server.port) as sender:
                server.accept()
                sender.row('tbl1', symbols={'sym1': 'val1'}, at=qi.ServerTimestamp)
                sender.close()
                with self.assertRaises(qi.IngressError):
                    sender.establish()

        def test_bad_init_args(self):
            with self.assertRaises(OverflowError):
                self.builder(protocol='tcp', host='127.0.0.1', port=9009, auth_timeout=-1)

            with self.assertRaises(OverflowError):
                self.builder(protocol='tcp', host='127.0.0.1', port=9009, init_buf_size=-1)

            with self.assertRaises(OverflowError):
                self.builder(protocol='tcp', host='127.0.0.1', port=9009, max_name_len=-1)

        def test_transaction_over_tcp(self):
            with Server() as server, self.builder('tcp', '127.0.0.1', server.port) as sender:
                server.accept()
                self.assertRaisesRegex(
                    qi.IngressError,
                    'Transactions are only supported for ILP/HTTP.',
                    sender.transaction, 'table_name')

        def test_transaction_basic(self):
            ts = qi.TimestampNanos.now()
            e = lambda ts: self.enc_des_ts(ts, v=2)
            expected = (
                    f'table_name,sym1=val1 {e(ts)}\n' +
                    f'table_name,sym2=val2 {e(ts)}\n').encode('utf-8')
            with HttpServer() as server, self.builder('http', '127.0.0.1', server.port) as sender:
                with sender.transaction('table_name') as txn:
                    self.assertIs(txn.row(symbols={'sym1': 'val1'}, at=ts), txn)
                    self.assertIs(txn.row(symbols={'sym2': 'val2'}, at=ts), txn)
                self.assertEqual(len(server.requests), 1)
                self.assertEqual(server.requests[0], expected)

        @unittest.skipIf(not pd, 'pandas not installed')
        def test_transaction_basic_df(self):
            ts = qi.TimestampNanos.now()
            e = lambda num: self.enc_des_ts(num, v=2)
            expected = (
                    f'table_name,sym1=val1 {e(ts)}\n' +
                    f'table_name,sym2=val2 {e(ts)}\n').encode('utf-8')
            with HttpServer() as server, self.builder('http', '127.0.0.1', server.port) as sender:
                with sender.transaction('table_name') as txn:
                    df = pd.DataFrame({'sym1': ['val1', None], 'sym2': [None, 'val2']})
                    self.assertIs(txn.dataframe(df, symbols=['sym1', 'sym2'], at=ts), txn)
                self.assertEqual(len(server.requests), 1)
                self.assertEqual(server.requests[0], expected)

        def test_transaction_no_auto_flush(self):
            ts = qi.TimestampNanos.now()
            e = lambda ts: self.enc_des_ts(ts, v=2)
            expected = (
                    f'table_name,sym1=val1 {e(ts)}\n' +
                    f'table_name,sym2=val2 {e(ts)}\n').encode('utf-8')
            with HttpServer() as server, self.builder('http', '127.0.0.1', server.port, auto_flush=False) as sender:
                with sender.transaction('table_name') as txn:
                    txn.row(symbols={'sym1': 'val1'}, at=ts)
                    txn.row(symbols={'sym2': 'val2'}, at=ts)
                self.assertEqual(len(server.requests), 1)
                self.assertEqual(server.requests[0], expected)

        @unittest.skipIf(not pd, 'pandas not installed')
        def test_transaction_no_auto_flush_df(self):
            ts = qi.TimestampNanos.now()
            e = lambda ts: self.enc_des_ts(ts, v=2)
            expected = (
                    f'table_name,sym1=val1 {e(ts)}\n' +
                    f'table_name,sym2=val2 {e(ts)}\n').encode('utf-8')
            with HttpServer() as server, self.builder('http', '127.0.0.1', server.port, auto_flush=False) as sender:
                with sender.transaction('table_name') as txn:
                    df = pd.DataFrame({'sym1': ['val1', None], 'sym2': [None, 'val2']})
                    txn.dataframe(df, symbols=['sym1', 'sym2'], at=ts)
                self.assertEqual(len(server.requests), 1)
                self.assertEqual(server.requests[0], expected)

        def test_transaction_auto_flush_pending_buf(self):
            ts = qi.TimestampNanos.now()
            e = lambda ts: self.enc_des_ts(ts, v=2)
            expected1 = (
                    f'tbl1,sym1=val1 {e(ts)}\n' +
                    f'tbl1,sym2=val2 {e(ts)}\n').encode('utf-8')
            expected2 = (
                    f'tbl2,sym3=val3 {e(ts)}\n' +
                    f'tbl2,sym4=val4 {e(ts)}\n').encode('utf-8')
            with HttpServer() as server, self.builder('http', '127.0.0.1', server.port, auto_flush=True) as sender:
                self.assertIs(sender.row('tbl1', symbols={'sym1': 'val1'}, at=ts), sender)
                self.assertIs(sender.row('tbl1', symbols={'sym2': 'val2'}, at=ts), sender)
                with sender.transaction('tbl2') as txn:
                    txn.row(symbols={'sym3': 'val3'}, at=ts)
                    txn.row(symbols={'sym4': 'val4'}, at=ts)
                self.assertEqual(len(server.requests), 2)
                self.assertEqual(server.requests[0], expected1)
                self.assertEqual(server.requests[1], expected2)

        def test_transaction_no_auto_flush_pending_buf(self):
            ts = qi.TimestampNanos.now()
            exp_err = (
                    'Sender buffer must be clear when starting a transaction. ' +
                    'You must call ..flush... before this call.')
            with HttpServer() as server, self.builder('http', '127.0.0.1', server.port, auto_flush=False) as sender:
                self.assertIs(sender.row('tbl1', symbols={'sym1': 'val1'}, at=ts), sender)
                self.assertIs(sender.row('tbl1', symbols={'sym2': 'val2'}, at=ts), sender)
                with self.assertRaisesRegex(qi.IngressError, exp_err):
                    with sender.transaction('tbl2') as _txn:
                        pass

        def test_transaction_immediate_auto_flush(self):
            ts = qi.TimestampNanos.now()
            e = lambda num: self.enc_des_ts(num, v=2)
            expected1 = f'tbl1,sym1=val1 {e(ts)}\n'.encode('utf-8')
            expected2 = f'tbl2,sym2=val2 {e(ts)}\n'.encode('utf-8')
            expected3 = (
                    f'tbl3,sym3=val3 {e(ts)}\n' +
                    f'tbl3,sym4=val4 {e(ts)}\n').encode('utf-8')
            with HttpServer() as server, self.builder('http', '127.0.0.1', server.port, auto_flush_rows=1) as sender:
                self.assertIs(sender.row('tbl1', symbols={'sym1': 'val1'}, at=ts), sender)
                self.assertIs(sender.row('tbl2', symbols={'sym2': 'val2'}, at=ts), sender)
                with sender.transaction('tbl3') as txn:
                    # The transaction is not broken up by the auto-flush logic.
                    txn.row(symbols={'sym3': 'val3'}, at=ts)
                    txn.row(symbols={'sym4': 'val4'}, at=ts)
                self.assertEqual(len(server.requests), 3)
                self.assertEqual(server.requests[0], expected1)
                self.assertEqual(server.requests[1], expected2)
                self.assertEqual(server.requests[2], expected3)

        @unittest.skipIf(not pd, 'pandas not installed')
        def test_transaction_immediate_auto_flush_df(self):
            ts = qi.TimestampNanos.now()
            e = lambda ts: self.enc_des_ts(ts, v=2)
            expected1 = f'tbl1,sym1=val1 {e(ts)}\n'.encode('utf-8')
            expected2 = f'tbl2,sym2=val2 {e(ts)}\n'.encode('utf-8')
            expected3 = (
                    f'tbl3,sym3=val3 {e(ts)}\n' +
                    f'tbl3,sym4=val4 {e(ts)}\n').encode('utf-8')
            with HttpServer() as server, self.builder('http', '127.0.0.1', server.port, auto_flush_rows=1) as sender:
                self.assertIs(sender.row('tbl1', symbols={'sym1': 'val1'}, at=ts), sender)
                self.assertIs(sender.row('tbl2', symbols={'sym2': 'val2'}, at=ts), sender)
                with sender.transaction('tbl3') as txn:
                    df = pd.DataFrame({'sym3': ['val3', None], 'sym4': [None, 'val4']})
                    txn.dataframe(df, symbols=['sym3', 'sym4'], at=ts)
                self.assertEqual(len(server.requests), 3)
                self.assertEqual(server.requests[0], expected1)
                self.assertEqual(server.requests[1], expected2)
                self.assertEqual(server.requests[2], expected3)

        @unittest.skipIf(not pd, 'pandas not installed')
        def test_http_illegal_ops_in_txn(self):
            with HttpServer() as server, self.builder('http', '127.0.0.1', server.port, auto_flush_rows=1) as sender:
                with sender.transaction('tbl1') as txn:
                    txn.row(symbols={'sym1': 'val1'}, at=qi.ServerTimestamp)
                    txn.row(symbols={'sym2': 'val2'}, at=qi.ServerTimestamp)

                    with self.assertRaisesRegex(qi.IngressError, 'Cannot append rows explicitly inside a transaction'):
                        sender.row('tbl2', symbols={'sym3': 'val3'}, at=qi.ServerTimestamp)

                    with self.assertRaisesRegex(qi.IngressError, 'Cannot append rows explicitly inside a transaction'):
                        sender.dataframe(None, at=qi.ServerTimestamp)

                    with self.assertRaisesRegex(qi.IngressError, 'Cannot flush explicitly inside a transaction'):
                        sender.flush()

                    with self.assertRaisesRegex(qi.IngressError, 'Already inside a transaction, can\'t start another.'):
                        with sender.transaction('tbl2') as _txn2:
                            pass

                    txn.commit()
                    with self.assertRaisesRegex(qi.IngressError, 'Transaction already completed, can\'t commit'):
                        txn.commit()
                    with self.assertRaisesRegex(qi.IngressError, 'Transaction already completed, can\'t rollback.'):
                        txn.rollback()
                self.assertEqual(len(server.requests), 1)

        def test_auto_flush_rows(self):
            auto_flush_rows = 3

            def into_requests(xs):
                return [
                    b''.join(xs[i:i + auto_flush_rows])
                    for i in range(0, len(xs), auto_flush_rows)]

            expected = []
            with HttpServer() as server, self.builder(
                    'http',
                    '127.0.0.1',
                    server.port,
                    auto_flush_rows=auto_flush_rows,
                    auto_flush_interval=False,
                    auto_flush_bytes=False) as sender:
                for i in range(10):
                    sender.row('tbl1', columns={'x': i}, at=qi.ServerTimestamp)
                    expected.append(f'tbl1 x={i}i\n'.encode('utf-8'))

                # Before the end of the `with` block we should already have 3 requests.
                self.assertEqual(len(server.requests), 3)
                self.assertEqual(server.requests, into_requests(expected)[:3])

            # Closing the buffer should flush the last remaining row.
            self.assertEqual(len(server.requests), 4)
            self.assertEqual(server.requests, into_requests(expected))

        def _do_test_auto_flush_interval(self):
            with HttpServer() as server, self.builder(
                    'http',
                    '127.0.0.1',
                    server.port,
                    auto_flush_interval=10,
                    auto_flush_rows=False,
                    auto_flush_bytes=False) as sender:
                start_time = timeit.default_timer()
                while True:
                    sender.row('tbl1', columns={'x': 1}, at=qi.ServerTimestamp)
                    elapsed_ms = int((timeit.default_timer() - start_time) * 1000)
                    if elapsed_ms < 5:
                        self.assertEqual(len(server.requests), 0)
                    if elapsed_ms >= 15:  # 5ms grace period.
                        break
                    time.sleep(1 / 1000)  # 1ms

                return len(server.requests)

        def test_auto_flush_interval(self):
            # This test is timing-sensitive,
            # so it has a tendency to go wrong in CI.
            # To work around this we'll repeat the test up to 10 times
            # until it passes.
            for _ in range(10):
                requests_len = self._do_test_auto_flush_interval()
                if requests_len > 0:
                    break

            # If this fails, it failed 10 attempts.
            # Due to CI timing delays there may have been multiple flushes.
            self.assertGreaterEqual(requests_len, 1)

        def _do_test_auto_flush_interval2(self):
            with HttpServer() as server, self.builder(
                    'http',
                    '127.0.0.1',
                    server.port,
                    auto_flush_interval=100,
                    auto_flush_rows=False,
                    auto_flush_bytes=False) as sender:
                sender.row('t', columns={'x': 1}, at=qi.ServerTimestamp)
                sender.row('t', columns={'x': 2}, at=qi.ServerTimestamp)
                time.sleep(0.2)
                sender.row('t', columns={'x': 3}, at=qi.ServerTimestamp)
                sender.row('t', columns={'x': 4}, at=qi.ServerTimestamp)
                time.sleep(0.2)
                sender.row('t', columns={'x': 5}, at=qi.ServerTimestamp)
                sender.row('t', columns={'x': 6}, at=qi.ServerTimestamp)
            return server.requests

        def test_auto_flush_interval2(self):
            # This test is timing-sensitive,
            # so it has a tendency to go wrong in CI.
            # To work around this we'll repeat the test up to 10 times
            # until it passes.
            for _ in range(10):
                requests = self._do_test_auto_flush_interval2()
                if len(requests) == 3:
                    self.assertEqual(requests, [
                        b't x=1i\nt x=2i\nt x=3i\n',
                        b't x=4i\nt x=5i\n',
                        b't x=6i\n'])
                    break

            # If this fails, it failed 10 attempts.
            # Due to CI timing delays there may have been multiple flushes.
            self.assertEqual(len(requests), 3)

        def test_http_username_password(self):
            with HttpServer() as server, self.builder('http', '127.0.0.1', server.port, username='user',
                                                      password='pass') as sender:
                sender.row('tbl1', columns={'x': 42}, at=qi.ServerTimestamp)
            self.assertEqual(len(server.requests), 1)
            self.assertEqual(server.requests[0], b'tbl1 x=42i\n')
            self.assertEqual(server.headers[1]['authorization'], 'Basic dXNlcjpwYXNz')

        def test_http_token(self):
            with HttpServer() as server, self.builder('http', '127.0.0.1', server.port, token='Yogi') as sender:
                sender.row('tbl1', columns={'x': 42}, at=qi.ServerTimestamp)
            self.assertEqual(len(server.requests), 1)
            self.assertEqual(server.requests[0], b'tbl1 x=42i\n')
            self.assertEqual(server.headers[1]['authorization'], 'Bearer Yogi')

        def test_max_buf_size(self):
            with HttpServer() as server, self.builder('http', '127.0.0.1', server.port, max_buf_size=1024,
                                                      auto_flush=False) as sender:
                while len(sender) < 1024:
                    sender.row('tbl1', columns={'x': 42}, at=qi.ServerTimestamp)
                with self.assertRaisesRegex(qi.IngressError, 'Could not flush .*exceeds maximum'):
                    sender.flush()

        def test_http_err(self):
            with HttpServer() as server, self.builder(
                    'http',
                    '127.0.0.1',
                    server.port,
                    retry_timeout=datetime.timedelta(milliseconds=1)) as sender:
                server.responses.append((0, 500, 'text/plain', b'Internal Server Error'))
                with self.assertRaisesRegex(qi.IngressError, 'Could not flush.*: Internal Server'):
                    sender.row('tbl1', columns={'x': 42}, at=qi.ServerTimestamp)
                    sender.flush()
                self.assertEqual(len(sender), 0)  # buffer is still cleared after error.

        def test_http_err_retry(self):
            exp_payload = b'tbl1 x=42i\n'
            with HttpServer() as server, self.builder(
                    'http',
                    '127.0.0.1',
                    server.port,
                    retry_timeout=datetime.timedelta(seconds=1)) as sender:
                server.responses.append((0, 500, 'text/plain', b'retriable error'))
                server.responses.append((0, 200, 'text/plain', b'OK'))
                sender.row('tbl1', columns={'x': 42}, at=qi.ServerTimestamp)
                sender.flush()
                self.assertEqual(len(server.requests), 2)
                self.assertEqual(server.requests[0], exp_payload)
                self.assertEqual(server.requests[1], exp_payload)

        def test_http_request_min_throughput(self):
            with HttpServer(delay_seconds=2) as server, self.builder(
                    'http',
                    '127.0.0.1',
                    server.port,
                    request_timeout=1000,
                    protocol_version='2',
                    # request_timeout is sufficiently high since it's also used as a connect timeout and we want to
                    # survive hiccups on CI. it should be lower than the server delay though to actually test the
                    # effect of request_min_throughput.
                    request_min_throughput=1) as sender:
                sender.row('tbl1', columns={'x': 42}, at=qi.ServerTimestamp)
                sender.flush()
                self.assertEqual(len(server.requests), 1)

        def test_http_request_min_throughput_timeout(self):
            with HttpServer() as server, self.builder(
                    'http',
                    '127.0.0.1',
                    server.port,
                    auto_flush='off',
                    request_timeout=100,
                    retry_timeout=0,
                    # effectively calculates a ~1ms timeout
                    request_min_throughput=100000000,
                    protocol_version=2) as sender:
                buffer = sender.new_buffer()
                buffer.row('tbl1', columns={'x': 42}, at=qi.ServerTimestamp)
                buffer.row('tbl1', columns={'x': 42}, at=qi.ServerTimestamp)
                buffer.row('tbl1', columns={'x': 42}, at=qi.ServerTimestamp)
                buffer.row('tbl1', columns={'x': 42}, at=qi.ServerTimestamp)
                buffer.row('tbl1', columns={'x': 42}, at=qi.ServerTimestamp)

                # wait 50ms in the server to simulate a slow response
                with self.assertRaisesRegex(qi.IngressError, 'timeout: per call') as cm:
                    for _ in range(10):
                        server.responses.append((500, 200, 'text/plain', b'OK'))
                        # We retry in case the network thread gets descheduled
                        # and is only rescheduled after the timeout elapsed.
                        sender.flush(buffer, clear=False)

        def test_http_request_timeout(self):
            with HttpServer() as server, self.builder(
                    'http',
                    '127.0.0.1',
                    server.port,
                    retry_timeout=0,
                    request_min_throughput=0,  # disable
                    protocol_version=2,
                    request_timeout=datetime.timedelta(milliseconds=5)) as sender:
                # wait for 50ms in the server to simulate a slow response
                server.responses.append((50, 200, 'text/plain', b'OK'))
                sender.row('tbl1', columns={'x': 42}, at=qi.ServerTimestamp)
                with self.assertRaisesRegex(qi.IngressError, 'timeout: per call'):
                    sender.flush()

        def test_http_server_not_serve(self):
            with self.assertRaisesRegex(qi.IngressError, 'Could not detect server\'s line protocol version, settings url: http://127.0.0.1:1234/settings'):
                with self.builder(
                    'http',
                    '127.0.0.1',
                    1234,
                    protocol_version='auto') as sender:
                        sender.row('tbl1', columns={'x': 42})

        def test_http_auto_protocol_version_only_v1(self):
            self._test_sender_http_auto_protocol_version(SETTINGS_WITH_PROTOCOL_VERSION_V1, 1)

        def test_http_auto_protocol_version_only_v2(self):
            self._test_sender_http_auto_protocol_version(SETTINGS_WITH_PROTOCOL_VERSION_V2, 2)

        def test_http_auto_protocol_version_v1_v2_v3(self):
            self._test_sender_http_auto_protocol_version(SETTINGS_WITH_PROTOCOL_VERSION_V1_V2_V3, 3)

        def test_http_auto_protocol_version_without_version(self):
            self._test_sender_http_auto_protocol_version(SETTINGS_WITHOUT_PROTOCOL_VERSION, 1)

        def _test_sender_http_auto_protocol_version(self, settings, expected_version: int):
            with HttpServer(settings) as server, self.builder('http', '127.0.0.1', server.port) as sender:
                self.assertEqual(sender.protocol_version, expected_version)
                buffer = sender.new_buffer()
                buffer.row(
                    'line_sender_buffer_old_server2',
                    symbols={'id': 'Hola'},
                    columns={'price': '111222233333i', 'qty': 3.5},
                    at=qi.TimestampNanos(111222233333))
                e = lambda num: self.enc_des_ts_n(num, v=expected_version)
                exp = b'line_sender_buffer_old_server2,id=Hola price="111222233333i",qty' + _float_binary_bytes(
                    3.5, expected_version == 1) + f' {e(111222233333)}\n'.encode()
                self.assertEqual(bytes(buffer), exp)
                sender.flush(buffer)
                self.assertEqual(len(server.requests), 1)
                self.assertEqual(server.requests[0], exp)

        def test_http_auto_protocol_version_unsupported_client(self):
            with self.assertRaisesRegex(qi.IngressError, r'Server does not support any of the client protocol versions.*'):
                with HttpServer(SETTINGS_WITH_PROTOCOL_VERSION_V4) as server, self.builder('http', '127.0.0.1', server.port) as sender:
                    sender.row('tbl1', columns={'x': 42})

        def test_specify_line_protocol_explicitly(self):
            with HttpServer() as server, self.builder('http', '127.0.0.1', server.port, protocol_version='1') as sender:
                buffer = sender.new_buffer()
                buffer.row(
                    'line_sender_buffer',
                    symbols={'id': 'Hola'},
                    columns={'qty': 3.5},
                    at=qi.TimestampNanos(111222233333))
                exp = b'line_sender_buffer,id=Hola qty' + _float_binary_bytes(
                    3.5, True) + b' 111222233333\n'
                self.assertEqual(bytes(buffer), exp)
                sender.flush(buffer)
                self.assertEqual(len(server.requests), 1)
                self.assertEqual(server.requests[0], exp)

        def test_line_protocol_version_on_tcp(self):
            with Server() as server, self.builder('tcp', '127.0.0.1', server.port, protocol_version='1') as sender:
                server.accept()
                self.assertEqual(server.recv(), [])
                buffer = sender.new_buffer()
                buffer.row(
                    'line_sender_buffer_tcp_v1',
                    symbols={'id': 'Hola'},
                    columns={'qty': 3.5},
                    at=qi.TimestampNanos(111222233333))
                exp = b'line_sender_buffer_tcp_v1,id=Hola qty=3.5 111222233333\n'
                self.assertEqual(bytes(buffer), exp)
                sender.flush(buffer)
                self.assertEqual(server.recv()[0] + b'\n', exp)

            with Server() as server, self.builder('tcp', '127.0.0.1', server.port, protocol_version='2') as sender:
                server.accept()
                self.assertEqual(server.recv(), [])
                buffer = sender.new_buffer()
                buffer.row(
                    'line_sender_buffer_tcp_v1',
                    symbols={'id': 'Hola'},
                    columns={'qty': 3.5},
                    at=qi.TimestampNanos(111222233333))
                exp = b'line_sender_buffer_tcp_v1,id=Hola qty' + _float_binary_bytes(3.5) + b' 111222233333n\n'
                self.assertEqual(bytes(buffer), exp)
                sender.flush(buffer)
                self.assertEqual(server.recv()[0] + b'\n', exp)

            with Server() as server, self.builder('tcp', '127.0.0.1', server.port, protocol_version='auto') as sender:
                server.accept()
                self.assertEqual(server.recv(), [])
                buffer = sender.new_buffer()
                buffer.row(
                    'line_sender_buffer_tcp_v1',
                    symbols={'id': 'Hola'},
                    columns={'qty': 3.5},
                    at=qi.TimestampNanos(111222233333))
                exp = b'line_sender_buffer_tcp_v1,id=Hola qty=3.5 111222233333\n'
                self.assertEqual(bytes(buffer), exp)
                sender.flush(buffer)
                self.assertEqual(server.recv()[0] + b'\n', exp)\

        def _test_array_basic(self, arr: np.ndarray):
            # http
            with HttpServer() as server, self.builder('http', '127.0.0.1', server.port) as sender:
                sender.row(
                    'array_test',
                    columns={'array': arr},
                    at=qi.TimestampNanos(11111))
                exp = b'array_test array=' + _array_binary_bytes(arr) + b' 11111n\n'
                sender.flush()
                self.assertEqual(len(server.requests), 1)
                self.assertEqual(server.requests[0], exp)

            #tcp
            with Server() as server, self.builder('tcp', '127.0.0.1', server.port, protocol_version=2) as sender:
                server.accept()
                self.assertEqual(server.recv(), [])
                sender.row(
                    'array_test',
                    columns={'array': arr},
                    at=qi.TimestampNanos(11111))
                exp = b'array_test array=' + _array_binary_bytes(arr) + b' 11111n\n'
                self.assertEqual(bytes(sender), exp)
                sender.flush()
                self.assertEqual(server.recv()[0] + b'\n', exp)

        def test_array_basic(self):
            self._test_array_basic(np.array([1.2345678901234567, 2.3456789012345678], dtype=np.float64))

        def test_empty_array(self):
            self._test_array_basic(np.array([], dtype=np.float64))

        def test_non_contigious_array(self):
            base = np.arange(6, dtype=np.float64).reshape(2, 3)
            non_contig_arr = base[:, ::2]
            self._test_array_basic(non_contig_arr)

        def test_minus_stride_array(self):
            self._test_array_basic(np.array([1.1, 2.2, 3.3], dtype=np.float64)[::-1])

        def test_array_error_cases(self):
            # zero dimensional array
            with self.assertRaisesRegex(qi.IngressError, "Zero-dimensional arrays are not supported"):
                scalar_arr = np.array(42.0, dtype=np.float64)
                with HttpServer() as server, self.builder('http', '127.0.0.1', server.port) as sender:
                    sender.row(
                        'array_test',
                        columns={'array': scalar_arr},
                        at=qi.TimestampNanos(11111))

            # not f64 dtype array
            with self.assertRaisesRegex(qi.IngressError, "Only float64 numpy arrays are supported, got dtype: complex64"):
                complex_arr = np.array([1 + 2j], dtype=np.complex64)
                with HttpServer() as server, self.builder('http', '127.0.0.1', server.port) as sender:
                    sender.row(
                        'array_test',
                        columns={'array': complex_arr},
                        at=qi.TimestampNanos(11111))

            # max dims
            if NUMPY_VERSION >= (2,):
                # Note: Older numpy versions don't support more than 32 dimensions.
                with self.assertRaisesRegex(qi.IngressError, "Array dimension mismatch: expected at most 32 dimensions, but got 33"):
                    dims = (1,) * 33
                    array = np.empty(dims, dtype=np.float64)
                    with Server() as server, self.builder('tcp', '127.0.0.1', server.port, protocol_version="2") as sender:
                        sender.row(
                            'array_test',
                            columns={'array': array},
                            at=qi.TimestampNanos(11111))

            # default protocol version is v1, which does not support array datatype.
            with self.assertRaisesRegex(qi.IngressError, "Protocol version v1 does not support array datatype"):
                array = np.zeros([1,2], dtype=np.float64)
                with Server() as server, self.builder('tcp', '127.0.0.1', server.port) as sender:
                    sender.row(
                        'array_test',
                        columns={'array': array},
                        at=qi.TimestampNanos(11111))

    class Timestamp(unittest.TestCase):
        def test_from_int(self):
            ns = 1670857929778202000
            num = ns // self.ns_scale
            ts = self.timestamp_cls(num)
            self.assertEqual(ts.value, num)

            ts0 = self.timestamp_cls(0)
            self.assertEqual(ts0.value, 0)

            with self.assertRaisesRegex(ValueError, 'value must be a positive'):
                self.timestamp_cls(-1)

        def test_from_datetime(self):
            utc = datetime.timezone.utc

            dt1 = datetime.datetime(2022, 1, 1, 12, 0, 0, 0, tzinfo=utc)
            ts1 = self.timestamp_cls.from_datetime(dt1)
            self.assertEqual(ts1.value, 1641038400000000000 // self.ns_scale)
            self.assertEqual(
                ts1.value,
                int(dt1.timestamp() * 1000000000 // self.ns_scale))

            dt2 = datetime.datetime(1970, 1, 1, tzinfo=utc)
            ts2 = self.timestamp_cls.from_datetime(dt2)
            self.assertEqual(ts2.value, 0)

            with self.assertRaisesRegex(ValueError, 'value must be a positive'):
                self.timestamp_cls.from_datetime(
                    datetime.datetime(1969, 12, 31, tzinfo=utc))

            dt_naive = datetime.datetime(2022, 1, 1, 12, 0, 0, 0,
                                         tzinfo=utc).astimezone(None).replace(tzinfo=None)
            ts3 = self.timestamp_cls.from_datetime(dt_naive)
            self.assertEqual(ts3.value, 1641038400000000000 // self.ns_scale)

        def test_now(self):
            expected = time.time_ns() // self.ns_scale
            actual = self.timestamp_cls.now().value
            delta = abs(expected - actual)
            one_sec = 1000000000 // self.ns_scale
            self.assertLess(delta, one_sec)


class TestTimestampMicros(TestBases.Timestamp):
    timestamp_cls = qi.TimestampMicros
    ns_scale = 1000


class TestTimestampNanos(TestBases.Timestamp):
    timestamp_cls = qi.TimestampNanos
    ns_scale = 1


def build_conf(protocol, host, port, **kwargs):
    protocol = qi.Protocol.parse(protocol)

    def encode_duration(v):
        if isinstance(v, datetime.timedelta):
            return str(v.seconds * 1000 + v.microseconds // 1000)
        return str(v)

    def encode_duration_or_off(v):
        if v is False:
            return 'off'
        return encode_duration(v)

    def encode_int_or_off(v):
        if v is False:
            return 'off'
        return str(v)

    encoders = {
        'bind_interface': str,
        'username': str,
        'password': str,
        'token': str,
        'token_x': str,
        'token_y': str,
        'auth_timeout': encode_duration,
        'tls_verify': lambda v: 'on' if v else 'unsafe_off',
        'tls_ca': str,
        'tls_roots': str,
        'tls_roots_password': str,
        'max_buf_size': str,
        'retry_timeout': encode_duration,
        'retry_max_backoff': encode_duration,
        'request_min_throughput': str,
        'request_timeout': encode_duration,
        'auto_flush': lambda v: 'on' if v else 'off',
        'auto_flush_rows': encode_int_or_off,
        'auto_flush_bytes': encode_int_or_off,
        'auto_flush_interval': encode_duration_or_off,
        'protocol_version': str,
        'init_buf_size': str,
        'max_name_len': str,
    }

    def encode(k, v):
        encoder = encoders.get(k, str)
        return encoder(v)

    def conf_key(k):
        if k == 'retry_max_backoff':
            return 'retry_max_backoff_millis'
        return k

    return f'{protocol.tag}::addr={host}:{port};' + ''.join(
        f'{conf_key(k)}={encode(k, v)};'
        for k, v in kwargs.items()
        if v is not None)


def split_dict_randomly(original, seed=None):
    if seed is None:
        seed = random.randint(0, 2 ** 32 - 1)
    sys.stderr.write(f'\nsplit_dict_randomly seed {seed}\n')
    random.seed(seed)
    keys = list(original.keys())
    random.shuffle(keys)
    split_point = random.randint(0, len(keys))
    return (
        {k: original[k] for k in keys[:split_point]},
        {k: original[k] for k in keys[split_point:]})


class Builder(Enum):
    INIT = 1
    CONF = 2
    ENV = 3

    def __call__(self, protocol, host, port, **kwargs):
        if self is Builder.INIT:
            return qi.Sender(protocol, host, port, **kwargs)
        else:
            # Specify some of the params via the conf string,
            # and the rest via the API.
            via_conf, via_params = split_dict_randomly(kwargs)
            conf = build_conf(protocol, host, port, **via_conf)
            if self is Builder.CONF:
                return qi.Sender.from_conf(conf, **via_params)
            elif self is Builder.ENV:
                os.environ['QDB_CLIENT_CONF'] = conf
                sender = qi.Sender.from_env(**via_params)
                del os.environ['QDB_CLIENT_CONF']
                return sender


class TestSenderInit(TestBases.TestSender):
    name = 'init'
    builder = Builder.INIT


class TestSenderConf(TestBases.TestSender):
    name = 'conf'
    builder = Builder.CONF


class TestSenderEnv(TestBases.TestSender):
    name = 'env'
    builder = Builder.ENV


class TestBufferProtocolVersionV1(TestBases.TestBuffer):
    name = 'protocol version 1'
    version = 1


class TestBufferProtocolVersionV2(TestBases.TestBuffer):
    name = 'protocol version 2'
    version = 2


class TestBufferProtocolVersionV3(TestBases.TestBuffer):
    name = 'protocol version 3'
    version = 3


class TestUninitializedBuffer(unittest.TestCase):
    """Verify that Buffer.__new__(Buffer) raises instead of segfaulting."""

    def _make_uninit(self):
        return qi.Buffer.__new__(qi.Buffer)

    def test_len(self):
        with self.assertRaisesRegex(qi.IngressError, 'Buffer is not initialized'):
            len(self._make_uninit())

    def test_bytes(self):
        with self.assertRaisesRegex(qi.IngressError, 'Buffer is not initialized'):
            bytes(self._make_uninit())

    def test_capacity(self):
        with self.assertRaisesRegex(qi.IngressError, 'Buffer is not initialized'):
            self._make_uninit().capacity()

    def test_clear(self):
        with self.assertRaisesRegex(qi.IngressError, 'Buffer is not initialized'):
            self._make_uninit().clear()

    def test_reserve(self):
        with self.assertRaisesRegex(qi.IngressError, 'Buffer is not initialized'):
            self._make_uninit().reserve(1)

    def test_row(self):
        with self.assertRaisesRegex(qi.IngressError, 'Buffer is not initialized'):
            self._make_uninit().row('t', columns={'x': 1}, at=qi.ServerTimestamp)

    @unittest.skipIf(not pd, 'pandas not installed')
    def test_dataframe(self):
        import pandas as _pd
        with self.assertRaisesRegex(qi.IngressError, 'Buffer is not initialized'):
            self._make_uninit().dataframe(
                _pd.DataFrame({'x': [1]}),
                table_name='t',
                at=qi.ServerTimestamp)

    def test_flush(self):
        with self.assertRaisesRegex(qi.IngressError, 'Buffer is not initialized'):
            with Server() as server, \
                    qi.Sender(qi.Protocol.Tcp, '127.0.0.1', server.port) as sender:
                server.accept()
                sender.flush(self._make_uninit())


if __name__ == '__main__':
    if os.environ.get('TEST_QUESTDB_PROFILE') == '1':
        import cProfile

        cProfile.run('unittest.main()', sort='cumtime')
    else:
        unittest.main()
