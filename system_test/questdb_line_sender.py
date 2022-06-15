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

import pathlib
import ctypes
import os

from ctypes import (
    c_bool,
    c_size_t,
    c_char_p,
    c_int,
    c_int64,
    c_double,
    c_void_p,
    c_ssize_t)

from typing import Union


class c_line_sender(ctypes.Structure):
    pass

class c_line_sender_error(ctypes.Structure):
    pass

c_size_t_p = ctypes.POINTER(c_size_t)
c_line_sender_p = ctypes.POINTER(c_line_sender)
c_line_sender_error_p = ctypes.POINTER(c_line_sender_error)
c_line_sender_error_p_p = ctypes.POINTER(c_line_sender_error_p)
class c_line_sender_utf8(ctypes.Structure):
    _fields_ = [("len", c_size_t),
                ("buf", c_char_p)]
c_line_sender_utf8_p = ctypes.POINTER(c_line_sender_utf8)
class c_line_sender_name(ctypes.Structure):
    _fields_ = [("len", c_size_t),
                ("buf", c_char_p)]
c_line_sender_name_p = ctypes.POINTER(c_line_sender_name)
class c_line_sender_sec_opts(ctypes.Structure):
    _fields_ = [("auth_username", c_char_p),
                ("auth_private_key", c_char_p)]
c_line_sender_sec_opts_p = ctypes.POINTER(c_line_sender_sec_opts)


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
        dll.line_sender_name_init,
        c_bool,
        c_line_sender_name_p,
        c_size_t,
        c_char_p,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_connect,
        c_line_sender_p,
        c_char_p,
        c_char_p,
        c_char_p,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_connect_secure,
        c_line_sender_p,
        c_char_p,
        c_char_p,
        c_char_p,
        c_line_sender_sec_opts_p,
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
        dll.line_sender_table,
        c_bool,
        c_line_sender_p,
        c_line_sender_name,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_symbol,
        c_bool,
        c_line_sender_p,
        c_line_sender_name,
        c_line_sender_utf8,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_column_bool,
        c_bool,
        c_line_sender_p,
        c_line_sender_name,
        c_bool,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_column_i64,
        c_bool,
        c_line_sender_p,
        c_line_sender_name,
        c_int64,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_column_f64,
        c_bool,
        c_line_sender_p,
        c_line_sender_name,
        c_double,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_column_str,
        c_bool,
        c_line_sender_p,
        c_line_sender_name,
        c_line_sender_utf8,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_at,
        c_bool,
        c_line_sender_p,
        c_int64,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_at_now,
        c_bool,
        c_line_sender_p,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_pending_size,
        c_size_t,
        c_line_sender_p)
    set_sig(
        dll.line_sender_flush,
        c_bool,
        c_line_sender_p,
        c_line_sender_error_p_p)
    return dll


_DLL = _setup_cdll()

_PY_DLL = ctypes.pythonapi
_PY_DLL.PyUnicode_FromKindAndData.restype = ctypes.py_object
_PY_DLL.PyUnicode_FromKindAndData.argtypes = [c_int, c_void_p, c_ssize_t]


class LineSenderError(Exception):
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
        return LineSenderError(py_msg)
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


def _name(s: str):
    c_name = c_line_sender_name(0, None)
    # We attach the object to the struct to extend the parent object's lifetime.
    # If we didn't do this we'd end up with a use-after-free.
    c_name._py_obj = s.encode('utf-8')
    _error_wrapped_call(
        _DLL.line_sender_name_init,
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


# This code is *just good enough* for testing purposes and is not intended to
# be used as Python bindings. If you are looking for Python bindings and come
# across this code, contact us on https://slack.questdb.io/ where we may offer
# you more robust alternatives.
class LineSender:
    def __init__(
            self,
            host,
            port,
            *,
            interface='0.0.0.0',
            auth=None):
        self._impl = None
        if auth:
            # We need to keep bytes objects around or they get GCd before
            # native C call.
            self._c_auth = (
                auth[0].encode('utf-8'),
                auth[1].encode('utf-8'))
            self._sec_opts = c_line_sender_sec_opts(
                self._c_auth[0], self._c_auth[1])
        else:
            self._sec_opts = None
        self._connect_secure_args = (
            interface.encode('ascii'),
            host.encode('ascii'),
            str(port).encode('ascii'),
            self._sec_opts)

    def connect(self):
        if self._impl:
            raise LineSenderError('Already connected')

        self._impl = _error_wrapped_call(
            _DLL.line_sender_connect_secure,
            self._connect_secure_args[0],
            self._connect_secure_args[1],
            self._connect_secure_args[2],
            self._connect_secure_args[3])

    def __enter__(self):
        self.connect()
        return self

    def _check_connected(self):
        if not self._impl:
            raise LineSenderError('Not connected.')

    def table(self, table: str):
        table_name = _name(table)
        _error_wrapped_call(
            _DLL.line_sender_table,
            self._impl,
            table_name)
        return self

    def symbol(self, name, value: str):
        _error_wrapped_call(
            _DLL.line_sender_symbol,
            self._impl,
            _name(name),
            _utf8(value))
        return self

    def column(self, name: str, value: Union[bool, int, float, str]):
        if isinstance(value, bool):
            _error_wrapped_call(
                _DLL.line_sender_column_bool,
                self._impl,
                _name(name),
                bool(value))
        elif isinstance(value, int):
            _error_wrapped_call(
                _DLL.line_sender_column_i64,
                self._impl,
                _name(name),
                int(value))
        elif isinstance(value, float):
            _error_wrapped_call(
                _DLL.line_sender_column_f64,
                self._impl,
                _name(name),
                float(value))
        elif isinstance(value, str):
            _error_wrapped_call(
                _DLL.line_sender_column_str,
                self._impl,
                _name(name),
                _utf8(value))
        else:
            fqn = _fully_qual_name(value)
            raise ValueError(
                f'Bad field value of type {fqn}: Expected one of '
                '`bool`, `int`, `float` or `str`.')
        return self

    def at_now(self):
        _error_wrapped_call(
            _DLL.line_sender_at_now,
            self._impl)

    def at(self, timestamp: int):
        _error_wrapped_call(
            _DLL.line_sender_at,
            self._impl,
            timestamp)

    @property
    def pending_size(self):
        if self._impl:
            return _DLL.line_sender_pending_size(self._impl)
        else:
            return 0

    def flush(self):
        self._check_connected()
        if self.pending_size == 0:
            return
        _error_wrapped_call(
            _DLL.line_sender_flush,
            self._impl)

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
