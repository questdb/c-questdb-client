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


"""

    WARNING: This is a lower-level API that's not intended for general use.

    If you're after Python bindings for QuestDB, see the official bindings:

        https://py-questdb.readthedocs.io/en/latest/

        https://github.com/questdb/py-questdb-client

        https://pypi.org/project/questdb/

"""


from ast import arg
import sys
sys.dont_write_bytecode = True

import pathlib
import ctypes
import os
from datetime import datetime

from ctypes import (
    c_bool,
    c_size_t,
    c_char_p,
    c_int,
    c_int64,
    c_double,
    c_uint16,
    c_uint64,
    c_void_p,
    c_ssize_t)

from typing import Optional, Tuple, Union


class c_line_sender(ctypes.Structure):
    pass

class c_line_sender_buffer(ctypes.Structure):
    pass

class c_line_sender_opts(ctypes.Structure):
    pass

class c_line_sender_error(ctypes.Structure):
    pass

c_size_t_p = ctypes.POINTER(c_size_t)
c_line_sender_p = ctypes.POINTER(c_line_sender)
c_line_sender_buffer_p = ctypes.POINTER(c_line_sender_buffer)
c_line_sender_opts_p = ctypes.POINTER(c_line_sender_opts)
c_line_sender_error_p = ctypes.POINTER(c_line_sender_error)
c_line_sender_error_p_p = ctypes.POINTER(c_line_sender_error_p)
class c_line_sender_utf8(ctypes.Structure):
    _fields_ = [("len", c_size_t),
                ("buf", c_char_p)]
c_line_sender_utf8_p = ctypes.POINTER(c_line_sender_utf8)
class c_line_sender_table_name(ctypes.Structure):
    _fields_ = [("len", c_size_t),
                ("buf", c_char_p)]
c_line_sender_table_name_p = ctypes.POINTER(c_line_sender_table_name)
class c_line_sender_column_name(ctypes.Structure):
    _fields_ = [("len", c_size_t),
                ("buf", c_char_p)]
c_line_sender_column_name_p = ctypes.POINTER(c_line_sender_column_name)


def _setup_cdll():
    root_dir = pathlib.Path(__file__).absolute().parent.parent
    build_dir = pathlib.Path(os.environ.get(
        'BUILD_DIR_PATH',
        root_dir / 'build'))
    if not build_dir.exists():
        raise RuntimeError('Build before running tests.')
    dll_ext = {
        'linux': 'so',
        'cygwin': 'so',
        'darwin': 'dylib',
        'win32': 'dll'}[sys.platform]
    dll_path = next(
       build_dir.glob(f'**/*questdb_client*.{dll_ext}'))

    dll = ctypes.CDLL(str(dll_path))

    def set_sig(fn, restype, *argtypes):
        fn.restype = restype
        fn.argtypes = argtypes

    set_sig(
        dll.line_sender_error_get_code,
        c_line_sender_error_p,
        c_int,
        c_void_p)
    set_sig(
        dll.line_sender_error_msg,
        c_line_sender_error_p,
        c_void_p,
        c_size_t_p)
    set_sig(
        dll.line_sender_error_free,
        None,
        c_line_sender_error_p)
    set_sig(
        dll.line_sender_utf8_init,
        c_bool,
        c_line_sender_utf8_p,
        c_size_t,
        c_char_p,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_table_name_init,
        c_bool,
        c_line_sender_table_name_p,
        c_size_t,
        c_char_p,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_column_name_init,
        c_bool,
        c_line_sender_column_name_p,
        c_size_t,
        c_char_p,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_buffer_with_max_name_len,
        c_line_sender_buffer_p,
        c_size_t)
    set_sig(
        dll.line_sender_buffer_free,
        None,
        c_line_sender_buffer_p)
    set_sig(
        dll.line_sender_buffer_size,
        c_size_t,
        c_line_sender_buffer_p)
    set_sig(
        dll.line_sender_buffer_capacity,
        c_size_t,
        c_line_sender_buffer_p)
    set_sig(
        dll.line_sender_buffer_peek,
        c_char_p,
        c_line_sender_buffer_p,
        c_size_t_p)
    set_sig(
        dll.line_sender_buffer_clear,
        None,
        c_line_sender_buffer_p)
    set_sig(
        dll.line_sender_buffer_table,
        c_bool,
        c_line_sender_buffer_p,
        c_line_sender_table_name,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_buffer_symbol,
        c_bool,
        c_line_sender_buffer_p,
        c_line_sender_column_name,
        c_line_sender_utf8,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_buffer_column_bool,
        c_bool,
        c_line_sender_buffer_p,
        c_line_sender_column_name,
        c_bool,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_buffer_column_i64,
        c_bool,
        c_line_sender_buffer_p,
        c_line_sender_column_name,
        c_int64,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_buffer_column_f64,
        c_bool,
        c_line_sender_buffer_p,
        c_line_sender_column_name,
        c_double,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_buffer_column_str,
        c_bool,
        c_line_sender_buffer_p,
        c_line_sender_column_name,
        c_line_sender_utf8,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_buffer_column_ts_nanos,
        c_bool,
        c_line_sender_buffer_p,
        c_line_sender_column_name,
        c_int64,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_buffer_column_ts_micros,
        c_bool,
        c_line_sender_buffer_p,
        c_line_sender_column_name,
        c_int64,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_buffer_at_nanos,
        c_bool,
        c_line_sender_buffer_p,
        c_int64,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_buffer_at_micros,
        c_bool,
        c_line_sender_buffer_p,
        c_int64,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_buffer_at_now,
        c_bool,
        c_line_sender_buffer_p,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_opts_new,
        c_line_sender_opts_p,
        c_line_sender_utf8,
        c_uint16)
    set_sig(
        dll.line_sender_opts_new_service,
        c_line_sender_opts_p,
        c_line_sender_utf8,
        c_line_sender_utf8)
    set_sig(
        dll.line_sender_opts_net_interface,
        None,
        c_line_sender_opts_p,
        c_line_sender_utf8)
    set_sig(
        dll.line_sender_opts_auth,
        None,
        c_line_sender_opts_p,
        c_line_sender_utf8,
        c_line_sender_utf8,
        c_line_sender_utf8,
        c_line_sender_utf8)
    set_sig(
        dll.line_sender_opts_tls,
        None,
        c_line_sender_opts_p)
    set_sig(
        dll.line_sender_opts_tls_os_roots,
        None,
        c_line_sender_opts_p)
    set_sig(
        dll.line_sender_opts_tls_webpki_and_os_roots,
        None,
        c_line_sender_opts_p)
    set_sig(
        dll.line_sender_opts_tls_ca,
        None,
        c_line_sender_opts_p,
        c_line_sender_utf8)
    set_sig(
        dll.line_sender_opts_tls_insecure_skip_verify,
        None,
        c_line_sender_opts_p)
    set_sig(
        dll.line_sender_opts_read_timeout,
        None,
        c_line_sender_opts_p,
        c_uint64)
    set_sig(
        dll.line_sender_opts_clone,
        c_line_sender_opts_p,
        c_line_sender_opts_p)
    set_sig(
        dll.line_sender_opts_free,
        None,
        c_line_sender_opts_p)
    set_sig(
        dll.line_sender_connect,
        c_line_sender_p,
        c_line_sender_opts_p,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_must_close,
        None,
        c_line_sender_p)
    set_sig(
        dll.line_sender_close,
        None,
        c_line_sender_p)
    set_sig(
        dll.line_sender_flush,
        c_bool,
        c_line_sender_p,
        c_line_sender_buffer_p,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_flush_and_keep,
        c_bool,
        c_line_sender_p,
        c_line_sender_buffer_p,
        c_line_sender_error_p_p)
    return dll


_DLL = _setup_cdll()

_PY_DLL = ctypes.pythonapi
_PY_DLL.PyUnicode_FromKindAndData.restype = ctypes.py_object
_PY_DLL.PyUnicode_FromKindAndData.argtypes = [c_int, c_void_p, c_ssize_t]
_PY_DLL.PyUnicode_FromStringAndSize.restype = ctypes.py_object
_PY_DLL.PyUnicode_FromStringAndSize.argtypes = [c_char_p, c_ssize_t]


class SenderError(Exception):
    """An error whilst using the line sender."""
    pass


def _c_err_to_py(err_p):
    try:
        c_len = c_size_t(0)
        msg_p = _DLL.line_sender_error_msg(err_p, ctypes.byref(c_len))
        py_msg = _PY_DLL.PyUnicode_FromKindAndData(
            1,  # PyUnicode_1BYTE_KIND
            msg_p,
            c_ssize_t(c_len.value))
        return SenderError(py_msg)
    finally:
        _DLL.line_sender_error_free(err_p)


def _error_wrapped_call(c_fn, *args):
    err_p = c_line_sender_error_p()
    ok = c_fn(
        *args,
        ctypes.byref(err_p))
    if ok:
        return ok
    else:
        raise _c_err_to_py(err_p)


def _utf8(s: str):
    c_utf8 = c_line_sender_utf8(0, None)
    # We attach the object to the struct to extend the parent object's lifetime.
    # If we didn't do this we'd end up with a use-after-free.
    c_utf8._py_obj = s.encode('utf-8')
    _error_wrapped_call(
        _DLL.line_sender_utf8_init,
        ctypes.byref(c_utf8),
        len(c_utf8._py_obj),
        c_utf8._py_obj)
    return c_utf8


def _table_name(s: str):
    c_name = c_line_sender_table_name(0, None)
    # We attach the object to the struct to extend the parent object's lifetime.
    # If we didn't do this we'd end up with a use-after-free.
    c_name._py_obj = s.encode('utf-8')
    _error_wrapped_call(
        _DLL.line_sender_table_name_init,
        ctypes.byref(c_name),
        len(c_name._py_obj),
        c_name._py_obj)
    return c_name


def _column_name(s: str):
    c_name = c_line_sender_column_name(0, None)
    # We attach the object to the struct to extend the parent object's lifetime.
    # If we didn't do this we'd end up with a use-after-free.
    c_name._py_obj = s.encode('utf-8')
    _error_wrapped_call(
        _DLL.line_sender_column_name_init,
        ctypes.byref(c_name),
        len(c_name._py_obj),
        c_name._py_obj)
    return c_name


def _fully_qual_name(obj):
    ty = type(obj)
    module = ty.__module__
    qn = ty.__qualname__
    if module == 'builtins':
        return qn
    else:
        return module + '.' + qn


class _Opts:
    def __init__(self, host, port):
        self.impl = _error_wrapped_call(
            _DLL.line_sender_opts_new_service,
            _utf8(str(host)),
            _utf8(str(port)))

    def __getattr__(self, name: str):
        fn = getattr(_DLL, 'line_sender_opts_' + name)
        def wrapper(*args):
            mapped_args = [
                (_utf8(arg) if isinstance(arg, str) else arg)
                for arg in args]
            if fn.argtypes[-1] == c_line_sender_error_p_p:
                return _error_wrapped_call(fn, self.impl, *mapped_args)
            else:
                return fn(self.impl, *mapped_args)
        return wrapper

    def __del__(self):
        _DLL.line_sender_opts_free(self.impl)


class TimestampMicros:
    def __init__(self, micros: int):
        self.value = micros


class Buffer:
    def __init__(self, init_capacity=65536, max_name_len=127):
        self._impl = _DLL.line_sender_buffer_with_max_name_len(
            c_size_t(max_name_len))
        _DLL.line_sender_buffer_reserve(self._impl, c_size_t(init_capacity))

    def __len__(self):
        return _DLL.line_sender_buffer_size(self._impl)

    def peek(self) -> str:
        # This is a hacky way of doing it because it copies the whole buffer.
        # Instead the `buffer` should be made to support the buffer protocol:
        # https://docs.python.org/3/c-api/buffer.html
        # This way we would not need to `bytes(..)` the object to keep it alive.
        # Then we could call `PyMemoryView_FromObject`.
        size = c_size_t(0)
        buf = _DLL.line_sender_buffer_peek(self._impl, ctypes.byref(size))
        if size:
            size = c_ssize_t(size.value)
            return _PY_DLL.PyUnicode_FromStringAndSize(buf, size)
        else:
            return ''

    def reserve(self, additional):
        _DLL.line_sender_buffer_reserve(self._impl, c_size_t(additional))

    @property
    def capacity(self):
        return _DLL.line_sender_buffer_capacity(self._impl)

    def clear(self):
        _DLL.line_sender_buffer_clear(self._impl)

    def table(self, table: str):
        table_name = _table_name(table)
        _error_wrapped_call(
            _DLL.line_sender_buffer_table,
            self._impl,
            table_name)
        return self

    def symbol(self, name: str, value: str):
        _error_wrapped_call(
            _DLL.line_sender_buffer_symbol,
            self._impl,
            _column_name(name),
            _utf8(value))
        return self

    def column(
            self, name: str,
            value: Union[bool, int, float, str, TimestampMicros, datetime]):
        if isinstance(value, bool):
            _error_wrapped_call(
                _DLL.line_sender_buffer_column_bool,
                self._impl,
                _column_name(name),
                bool(value))
        elif isinstance(value, int):
            _error_wrapped_call(
                _DLL.line_sender_buffer_column_i64,
                self._impl,
                _column_name(name),
                int(value))
        elif isinstance(value, float):
            _error_wrapped_call(
                _DLL.line_sender_buffer_column_f64,
                self._impl,
                _column_name(name),
                float(value))
        elif isinstance(value, str):
            _error_wrapped_call(
                _DLL.line_sender_buffer_column_str,
                self._impl,
                _column_name(name),
                _utf8(value))
        elif isinstance(value, TimestampMicros):
            _error_wrapped_call(
                _DLL.line_sender_buffer_column_ts_micros,
                self._impl,
                _column_name(name),
                value.value)
        elif isinstance(value, datetime):
            micros_epoch = int(value.timestamp()) * 1e6 + value.microsecond
            _error_wrapped_call(
                _DLL.line_sender_buffer_column_ts_micros,
                self._impl,
                _column_name(name),
                micros_epoch)
        else:
            fqn = _fully_qual_name(value)
            raise ValueError(
                f'Bad field value of type {fqn}: Expected one of '
                '`bool`, `int`, `float` or `str`.')
        return self

    def at_now(self):
        _error_wrapped_call(
            _DLL.line_sender_buffer_at_now,
            self._impl)

    def at(self, timestamp: int):
        _error_wrapped_call(
            _DLL.line_sender_buffer_at_nanos,
            self._impl,
            timestamp)

    def __del__(self):
        _DLL.line_sender_buffer_free(self._impl)


class Sender:
    def __init__(
            self,
            host: str,
            port: Union[str, int],
            *,
            interface: Optional[str] = None,
            auth: Optional[Tuple[str, str, str, str]] = None,
            tls: Union[bool, str] = False,
            read_timeout: Optional[int] = None):

        opts = _Opts(host, port)
        if interface:
            opts.net_interface(interface)

        if auth:
            opts.auth(*auth)

        if tls:
            if tls is True:
                opts.tls()
            elif tls == 'os_roots':
                opts.tls_os_roots()
            elif tls == 'webpki_and_os_roots':
                opts.tls_webpki_and_os_roots()
            elif tls == 'insecure_skip_verify':
                opts.tls_insecure_skip_verify()
            else:
                opts.tls_ca(str(tls))

        if read_timeout is not None:
            opts.read_timeout(read_timeout)

        self._buffer = Buffer()
        self._opts = opts
        self._impl = None

    @property
    def buffer(self):
        return self._buffer

    def connect(self):
        if self._impl:
            raise SenderError('Already connected')
        self._impl = _error_wrapped_call(
            _DLL.line_sender_connect,
            self._opts.impl)

    def __enter__(self):
        self.connect()
        return self

    def _check_connected(self):
        if not self._impl:
            raise SenderError('Not connected.')

    def table(self, table: str):
        self._buffer.table(table)
        return self

    def symbol(self, name: str, value: str):
        self._buffer.symbol(name, value)
        return self

    def column(
            self, name: str,
            value: Union[bool, int, float, str, TimestampMicros, datetime]):
        self._buffer.column(name, value)
        return self

    def at_now(self):
        self._buffer.at_now()

    def at(self, timestamp: int):
        self._buffer.at(timestamp)

    def flush(self, buffer: Optional[Buffer]=None, clear=True):
        if (buffer is None) and not clear:
            raise ValueError(
                'Clear flag must be True when using internal buffer')
        buffer = buffer or self._buffer
        self._check_connected()
        if len(buffer) == 0:
            return
        try:
            if clear:
                _error_wrapped_call(
                    _DLL.line_sender_flush,
                    self._impl,
                    buffer._impl)
            else:
                _error_wrapped_call(
                    _DLL.line_sender_flush_and_keep,
                    self._impl,
                    buffer._impl)
        except:
            # Prevent `.close()` from erroring if it was called
            # after a flush exception was raised, trapped and discarded.
            if buffer is self._buffer:
                self._buffer.clear()
            raise

    def close(self, flush=True):
        if self._impl and not _DLL.line_sender_must_close(self._impl) and flush:
            self.flush()
        if self._impl:
            _DLL.line_sender_close(self._impl)
            self._impl = None

    def __exit__(self, exc_type, _exc_val, _exc_tb):
        self.close(not exc_type)

    def __del__(self):
        self.close(False)
