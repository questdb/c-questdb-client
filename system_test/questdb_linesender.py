# This code is *just good enough*

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


class c_linesender(ctypes.Structure):
    pass

class c_linesender_error(ctypes.Structure):
    pass

c_size_t_p = ctypes.POINTER(c_size_t)
c_linesender_p = ctypes.POINTER(c_linesender)
c_linesender_error_p = ctypes.POINTER(c_linesender_error)
c_linesender_error_p_p = ctypes.POINTER(c_linesender_error_p)


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
        dll.linesender_error_errnum,
        c_linesender_error_p,
        c_int,
        c_void_p)
    set_sig(
        dll.linesender_error_msg,
        c_linesender_error_p,
        c_void_p,
        c_size_t_p)
    set_sig(
        dll.linesender_error_free,
        None,
        c_linesender_error_p)
    set_sig(
        dll.linesender_connect,
        c_linesender_p,
        c_char_p,
        c_char_p,
        c_char_p,
        c_linesender_error_p_p)
    set_sig(
        dll.linesender_must_close,
        None,
        c_linesender_p)
    set_sig(
        dll.linesender_close,
        None,
        c_linesender_p)
    set_sig(
        dll.linesender_table,
        c_bool,
        c_linesender_p,
        c_size_t,
        c_char_p,
        c_linesender_error_p_p)
    set_sig(
        dll.linesender_symbol,
        c_bool,
        c_linesender_p,
        c_size_t,
        c_char_p,
        c_size_t,
        c_char_p,
        c_linesender_error_p_p)
    set_sig(
        dll.linesender_column_bool,
        c_bool,
        c_linesender_p,
        c_size_t,
        c_char_p,
        c_bool,
        c_linesender_error_p_p)
    set_sig(
        dll.linesender_column_i64,
        c_bool,
        c_linesender_p,
        c_size_t,
        c_char_p,
        c_int64,
        c_linesender_error_p_p)
    set_sig(
        dll.linesender_column_f64,
        c_bool,
        c_linesender_p,
        c_size_t,
        c_char_p,
        c_double,
        c_linesender_error_p_p)
    set_sig(
        dll.linesender_column_str,
        c_bool,
        c_linesender_p,
        c_size_t,
        c_char_p,
        c_size_t,
        c_char_p,
        c_linesender_error_p_p)
    set_sig(
        dll.linesender_at,
        c_bool,
        c_linesender_p,
        c_int64,
        c_linesender_error_p_p)
    set_sig(
        dll.linesender_at_now,
        c_bool,
        c_linesender_p,
        c_linesender_error_p_p)
    set_sig(
        dll.linesender_pending_size,
        c_size_t,
        c_linesender_p)
    set_sig(
        dll.linesender_flush,
        c_bool,
        c_linesender_p,
        c_linesender_error_p_p)
    return dll


_DLL = _setup_cdll()

_PY_DLL = ctypes.pythonapi
_PY_DLL.PyUnicode_FromKindAndData.restype = ctypes.py_object
_PY_DLL.PyUnicode_FromKindAndData.argtypes = [c_int, c_void_p, c_ssize_t]


class SenderError(ConnectionError):
    """An error whilst using the line sender."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


def _c_err_to_py(err_p):
    try:
        c_len = c_size_t(0)
        msg_p = _DLL.linesender_error_msg(err_p, ctypes.byref(c_len))
        py_msg = _PY_DLL.PyUnicode_FromKindAndData(
            1,  # PyUnicode_1BYTE_KIND
            msg_p,
            c_ssize_t(c_len.value))
        return SenderError(py_msg)
    finally:
        _DLL.linesender_error_free(err_p)


def _error_wrapped_call(c_fn, *args):
    err_p = c_linesender_error_p()
    ok = c_fn(
        *args,
        ctypes.byref(err_p))
    if ok:
        return ok
    else:
        raise _c_err_to_py(err_p)


def _fully_qual_name(obj):
    ty = type(obj)
    module = ty.__module__
    qn = ty.__qualname__
    if module == 'builtins':
        return qn
    else:
        return module + '.' + qn


class Sender:
    def __init__(
            self,
            host,
            port,
            *,
            interface='0.0.0.0'):
        self._impl = None
        self._connect_args = (
            interface.encode('ascii'),
            host.encode('ascii'),
            str(port).encode('ascii'))

    def connect(self):
        if self._impl:
            raise SenderError('Already connected')

        self._impl = _error_wrapped_call(
            _DLL.linesender_connect,
            self._connect_args[0],
            self._connect_args[1],
            self._connect_args[2])

    def __enter__(self):
        self.connect()
        return self

    def _check_connected(self):
        if not self._impl:
            raise SenderError('Not connected.')

    def table(self, table: str):
        table_b = table.encode('utf-8')
        _error_wrapped_call(
            _DLL.linesender_table,
            self._impl,
            len(table_b),
            table_b)
        return self

    def symbol(self, name, value: str):
        name_b = name.encode('utf-8')
        value_b = value.encode('utf-8')
        _error_wrapped_call(
            _DLL.linesender_symbol,
            self._impl,
            len(name_b),
            name_b,
            len(value_b),
            value_b)
        return self

    def column(self, name: str, value: Union[bool, int, float, str]):
        name_b = name.encode('utf-8')
        name_len = len(name_b)
        if isinstance(value, bool):
            _error_wrapped_call(
                _DLL.linesender_column_bool,
                self._impl,
                name_len,
                name_b,
                bool(value))
        elif isinstance(value, int):
            _error_wrapped_call(
                _DLL.linesender_column_i64,
                self._impl,
                name_len,
                name_b,
                int(value))
        elif isinstance(value, float):
            _error_wrapped_call(
                _DLL.linesender_column_f64,
                self._impl,
                name_len,
                name_b,
                float(value))
        elif isinstance(value, str):
            value_b = value.encode('utf-8')
            _error_wrapped_call(
                _DLL.linesender_column_str,
                    self._impl,
                    name_len,
                    name_b,
                    len(value_b),
                    value_b)
        else:
            fqn = _fully_qual_name(value)
            raise ValueError(
                f'Bad field value of type {fqn}: Expected one of '
                '`bool`, `int`, `float` or `str`.')
        return self

    def at_now(self):
        _error_wrapped_call(
            _DLL.linesender_at_now,
            self._impl)

    def at(self, timestamp: int):
        _error_wrapped_call(
            _DLL.linesender_at,
            self._impl,
            timestamp)

    @property
    def pending_size(self):
        if self._impl:
            return _DLL.linesender_pending_size(self._impl)
        else:
            return 0

    def flush(self):
        self._check_connected()
        if self.pending_size == 0:
            return
        _error_wrapped_call(
            _DLL.linesender_flush,
            self._impl)

    def close(self, flush=True):
        if self._impl and not _DLL.linesender_must_close(self._impl) and flush:
            self.flush()
        if self._impl:
            _DLL.linesender_close(self._impl)
            self._impl = None

    def __exit__(self, exc_type, _exc_val, _exc_tb):
        self.close(not exc_type)

    def __del__(self):
        self.close(False)
