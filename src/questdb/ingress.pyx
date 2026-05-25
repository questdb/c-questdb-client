################################################################################
##     ___                  _   ____  ____
##    / _ \ _   _  ___  ___| |_|  _ \| __ )
##   | | | | | | |/ _ \/ __| __| | | |  _ \
##   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
##    \__\_\\__,_|\___||___/\__|____/|____/
##
##  Copyright (c) 2014-2019 Appsicle
##  Copyright (c) 2019-2024 QuestDB
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

# distutils: language=c
# cython: language_level=3
# cython: binding=True

"""
API for fast data ingestion into QuestDB.
"""

__all__ = [
    'Buffer',
    'IngressError',
    'IngressErrorCode',
    'IngressServerRejectionError',
    'Protocol',
    'Sender',
    'QwpWsError',
    'QwpWsErrorCategory',
    'QwpWsErrorPolicy',
    'QwpWsProgress',
    'ServerTimestamp',
    'ServerTimestampType',
    'TimestampMicros',
    'TimestampNanos',
    'TlsCa',
    'WARN_HIGH_RECONNECTS'
]

# For prototypes: https://github.com/cython/cython/tree/master/Cython/Includes
from libc.stdint cimport uint8_t, uint64_t, int64_t, uint32_t, uintptr_t, \
    INT64_MAX, INT64_MIN
from libc.stdlib cimport malloc, calloc, realloc, free, abort, qsort
from libc.string cimport strncmp, memset
from libc.math cimport isnan
from libc.errno cimport errno
# from libc.stdio cimport stderr, fprintf
from cpython.datetime cimport datetime as cp_datetime
from cpython.datetime cimport timedelta as cp_timedelta
from cpython.bool cimport bool
from cpython.weakref cimport PyWeakref_NewRef, PyWeakref_GetObject
from cpython.object cimport PyObject
from cpython.buffer cimport Py_buffer, PyObject_CheckBuffer, \
    PyObject_GetBuffer, PyBuffer_Release, PyBUF_SIMPLE
from cpython.memoryview cimport PyMemoryView_FromMemory

from .line_sender cimport *
from .rpyutils cimport *
from .conf_str cimport *
from .arrow_c_data_interface cimport *
from .extra_cpython cimport *
from .ingress_helper cimport *

# An int we use only for error reporting.
#  0 is success.
# -1 is failure.
ctypedef int void_int

import cython
include "dataframe.pxi"

from enum import Enum
from typing import List, Tuple, Dict, Union, Any, Optional, Callable, \
    Iterable
from dataclasses import dataclass
import pathlib
from cpython.bytes cimport PyBytes_FromStringAndSize

import sys
import datetime
import os
import threading
import collections
import time
import heapq
import warnings
import logging

import numpy
cimport numpy as cnp
from numpy cimport NPY_DOUBLE, PyArrayObject

# Functions we need to import as `PyObject` to avoid Cython's `object` type
from .extra_numpy cimport *

cnp.import_array()


# This value is automatically updated by the `bump2version` tool.
# If you need to update it, also update the search definition in
# .bumpversion.cfg.
VERSION = '4.1.0'

WARN_HIGH_RECONNECTS = True


cdef bint _has_gil(PyThreadState** gs):
    return gs[0] == NULL


cdef bint _ensure_doesnt_have_gil(PyThreadState** gs):
    """Returns True if previously had the GIL, False otherwise."""
    if _has_gil(gs):
        gs[0] = PyEval_SaveThread()
        return True
    return False


cdef void _ensure_has_gil(PyThreadState** gs):
    if not _has_gil(gs):
        PyEval_RestoreThread(gs[0])
        gs[0] = NULL


class IngressErrorCode(Enum):
    """Category of Error."""
    CouldNotResolveAddr = line_sender_error_could_not_resolve_addr
    InvalidApiCall = line_sender_error_invalid_api_call
    SocketError = line_sender_error_socket_error
    InvalidUtf8 = line_sender_error_invalid_utf8
    InvalidName = line_sender_error_invalid_name
    InvalidTimestamp = line_sender_error_invalid_timestamp
    AuthError = line_sender_error_auth_error
    TlsError = line_sender_error_tls_error
    HttpNotSupported = line_sender_error_http_not_supported
    ServerFlushError = line_sender_error_server_flush_error
    ServerRejection = line_sender_error_server_rejection
    ConfigError = line_sender_error_config_error
    ArrayError = line_sender_error_array_error
    ProtocolVersionError = line_sender_error_protocol_version_error
    DecimalError = line_sender_error_invalid_decimal
    BadDataFrame = <int>line_sender_error_server_rejection + 1

    def __str__(self) -> str:
        """Return the name of the enum."""
        return self.name


class IngressError(Exception):
    """An error whilst using the ``Sender`` or constructing its ``Buffer``."""
    def __init__(self, code, msg, qwp_ws_error=None):
        super().__init__(msg)
        self._code = code
        self._qwp_ws_error = qwp_ws_error

    @property
    def code(self) -> IngressErrorCode:
        """Return the error code."""
        return self._code

    @property
    def qwp_ws_error(self):
        """
        Return the structured QWP/WebSocket HALT diagnostic, if this error
        carries one from a terminal QWP/WebSocket sender failure.
        """
        if self._qwp_ws_error is not None:
            self._qwp_ws_error = _qwp_ws_error_from_raw(self._qwp_ws_error)
        return self._qwp_ws_error


class IngressServerRejectionError(IngressError):
    """
    A terminal QWP/WebSocket server rejection.

    The structured server payload is available through
    :attr:`IngressError.qwp_ws_error`.
    """


cdef inline object c_err_code_to_py(line_sender_error_code code):
    if code == line_sender_error_could_not_resolve_addr:
        return IngressErrorCode.CouldNotResolveAddr
    elif code == line_sender_error_invalid_api_call:
        return IngressErrorCode.InvalidApiCall
    elif code == line_sender_error_socket_error:
        return IngressErrorCode.SocketError
    elif code == line_sender_error_invalid_utf8:
        return IngressErrorCode.InvalidUtf8
    elif code == line_sender_error_invalid_name:
        return IngressErrorCode.InvalidName
    elif code == line_sender_error_invalid_timestamp:
        return IngressErrorCode.InvalidTimestamp
    elif code == line_sender_error_auth_error:
        return IngressErrorCode.AuthError
    elif code == line_sender_error_tls_error:
        return IngressErrorCode.TlsError
    elif code == line_sender_error_http_not_supported:
        return IngressErrorCode.HttpNotSupported
    elif code == line_sender_error_server_flush_error:
        return IngressErrorCode.ServerFlushError
    elif code == line_sender_error_server_rejection:
        return IngressErrorCode.ServerRejection
    elif code == line_sender_error_config_error:
        return IngressErrorCode.ConfigError
    elif code == line_sender_error_array_error:
        return IngressErrorCode.ArrayError
    elif code == line_sender_error_protocol_version_error:
        return IngressErrorCode.ProtocolVersionError
    elif code == line_sender_error_invalid_decimal:
        return IngressErrorCode.DecimalError
    else:
        raise ValueError('Internal error converting error code.')


cdef inline object c_qwp_ws_error_view_to_raw(
        line_sender_qwpws_error_view view):
    cdef object message
    if view.message == NULL:
        message = ''
    else:
        message = PyUnicode_FromStringAndSize(
            view.message, <Py_ssize_t>view.message_len)
    return (
        <int>view.category,
        <int>view.applied_policy,
        view.status if view.has_status else None,
        message,
        view.message_sequence if view.has_message_sequence else None,
        view.from_fsn,
        view.to_fsn)


cdef inline object c_err_to_fields(line_sender_error* err):
    """Construct a ``SenderError`` from a C error, which will be freed."""
    cdef line_sender_error_code code = line_sender_error_get_code(err)
    cdef size_t c_len = 0
    cdef const char* c_msg = line_sender_error_msg(err, &c_len)
    cdef line_sender_qwpws_error_view qwp_ws_view
    cdef object py_msg
    cdef object py_code
    cdef object py_qwp_ws_error = None
    try:
        py_code = c_err_code_to_py(code)
        py_msg = PyUnicode_FromStringAndSize(c_msg, <Py_ssize_t>c_len)
        if line_sender_error_qwpws_get_view(err, &qwp_ws_view):
            py_qwp_ws_error = c_qwp_ws_error_view_to_raw(qwp_ws_view)
        return (py_code, py_msg, py_qwp_ws_error)
    finally:
        line_sender_error_free(err)


cdef inline object c_err_to_py(line_sender_error* err):
    """Construct an ``IngressError`` from a C error, which will be freed."""
    cdef object tup = c_err_to_fields(err)
    if tup[0] == IngressErrorCode.ServerRejection:
        return IngressServerRejectionError(tup[0], tup[1], tup[2])
    return IngressError(tup[0], tup[1], tup[2])


cdef inline object c_err_to_py_fmt(line_sender_error* err, str fmt):
    """Construct an ``IngressError`` from a C error, which will be freed."""
    cdef object tup = c_err_to_fields(err)
    if tup[0] == IngressErrorCode.ServerRejection:
        return IngressServerRejectionError(tup[0], fmt.format(tup[1]), tup[2])
    return IngressError(tup[0], fmt.format(tup[1]), tup[2])


cdef inline void_int reserve_buffer(
        line_sender_buffer* buffer,
        size_t additional) except -1:
    cdef line_sender_error* err = NULL
    if not line_sender_buffer_reserve(buffer, additional, &err):
        raise c_err_to_py(err)


cdef object _utf8_decode_error(
        PyObject* string, uint32_t bad_codepoint):
    cdef str s = <str><object>string
    return IngressError(
        IngressErrorCode.InvalidUtf8,
        f'Invalid codepoint 0x{bad_codepoint:x} in string {s!r}: ' +
        'Cannot be encoded as UTF-8.')


cdef str _fqn(type obj):
    if obj.__module__ == 'builtins':
        return obj.__qualname__
    else:
        return f'{obj.__module__}.{obj.__qualname__}'


cdef inline void_int _encode_utf8(
        qdb_pystr_buf* b,
        PyObject* string,
        line_sender_utf8* utf8_out) except -1:
    cdef uint32_t bad_codepoint = 0
    cdef size_t count = <size_t>(PyUnicode_GET_LENGTH(string))
    cdef int kind = PyUnicode_KIND(string)
    if kind == PyUnicode_1BYTE_KIND:
        # No error handling for UCS1: All code points translate into valid UTF8.
        qdb_ucs1_to_utf8(
            b,
            count,
            PyUnicode_1BYTE_DATA(string),
            &utf8_out.len,
            &utf8_out.buf)
    elif kind == PyUnicode_2BYTE_KIND:
        if not qdb_ucs2_to_utf8(
                b,
                count,
                PyUnicode_2BYTE_DATA(string),
                &utf8_out.len,
                &utf8_out.buf,
                &bad_codepoint):
            raise _utf8_decode_error(string, bad_codepoint)
    elif kind == PyUnicode_4BYTE_KIND:
        if not qdb_ucs4_to_utf8(
                b,
                count,

                # This cast is required and is possibly a Cython compiler bug.
                # It doesn't recognize that `const Py_UCS4*`
                # is the same as `const uint32_t*`.
                <const uint32_t*>PyUnicode_4BYTE_DATA(string),

                &utf8_out.len,
                &utf8_out.buf,
                &bad_codepoint):
            raise _utf8_decode_error(string, bad_codepoint)
    else:
        raise ValueError(f'Unknown UCS kind: {kind}.')


cdef void_int str_to_utf8(
        qdb_pystr_buf* b,
        PyObject* string,
        line_sender_utf8* utf8_out) except -1:
    """
    Convert a Python string to a UTF-8 borrowed buffer.
    This is done without allocating new Python `bytes` objects.
    In case the string is an ASCII string, it's also generally zero-copy.
    The `utf8_out` param will point to (borrow from) either the ASCII buffer
    inside the original Python object or a part of memory allocated inside the
    `b` buffer.

    If you need to use `utf8_out` without the GIL, call `qdb_pystr_buf_copy`.
    """
    if not PyUnicode_CheckExact(string):
        raise TypeError(
            'Expected a str object, not an object of type ' +
            _fqn(type(<str><object>string)))
    PyUnicode_READY(string)

    # We optimize the common case of ASCII strings.
    # This avoid memory allocations and copies altogether.
    # We get away with this because ASCII is a subset of UTF-8.
    if PyUnicode_IS_COMPACT_ASCII(string):
        utf8_out.len = <size_t>(PyUnicode_GET_LENGTH(string))
        utf8_out.buf = <const char*>(PyUnicode_1BYTE_DATA(string))
        return 0

    _encode_utf8(b, string, utf8_out)



cdef void_int str_to_utf8_copy(
        qdb_pystr_buf* b,
        PyObject* string,
        line_sender_utf8* utf8_out) except -1:
    """
    Variant of `str_to_utf8` that always copies the string to a new buffer.

    The resulting `utf8_out` can be used when not holding the GIL:
    The pointed-to memory is owned by `b`.
    """
    if not PyUnicode_CheckExact(string):
        raise TypeError(
            'Expected a str object, not an object of type ' +
            _fqn(type(<str><object>string)))

    PyUnicode_READY(string)
    _encode_utf8(b, string, utf8_out)


cdef void_int str_to_table_name(
        qdb_pystr_buf* b,
        PyObject* string,
        line_sender_table_name* name_out) except -1:
    """
    Python string to borrowed C table name.
    Also see `str_to_utf8`.
    """
    cdef line_sender_error* err = NULL
    cdef line_sender_utf8 utf8
    str_to_utf8(b, string, &utf8)
    if not line_sender_table_name_init(name_out, utf8.len, utf8.buf, &err):
        raise c_err_to_py(err)


cdef void_int str_to_table_name_copy(
        qdb_pystr_buf* b,
        PyObject* string,
        line_sender_table_name* name_out) except -1:
    """
    Python string to copied C table name.
    Also see `str_to_utf8_copy`.
    """
    cdef line_sender_error* err = NULL
    cdef line_sender_utf8 utf8
    str_to_utf8_copy(b, string, &utf8)
    if not line_sender_table_name_init(name_out, utf8.len, utf8.buf, &err):
        raise c_err_to_py(err)


cdef void_int str_to_column_name(
        qdb_pystr_buf* b,
        str string,
        line_sender_column_name* name_out) except -1:
    """
    Python string to borrowed C column name.
    Also see `str_to_utf8`.
    """
    cdef line_sender_error* err = NULL
    cdef line_sender_utf8 utf8
    str_to_utf8(b, <PyObject*>string, &utf8)
    if not line_sender_column_name_init(name_out, utf8.len, utf8.buf, &err):
        raise c_err_to_py(err)


cdef void_int str_to_column_name_copy(
        qdb_pystr_buf* b,
        str string,
        line_sender_column_name* name_out) except -1:
    """
    Python string to copied C column name.
    Also see `str_to_utf8_copy`.
    """
    cdef line_sender_error* err = NULL
    cdef line_sender_utf8 utf8
    str_to_utf8_copy(b, <PyObject*>string, &utf8)
    if not line_sender_column_name_init(name_out, utf8.len, utf8.buf, &err):
        raise c_err_to_py(err)


cdef int64_t datetime_to_micros(cp_datetime dt):
    """
    Convert a :class:`datetime.datetime` to microseconds since the epoch.
    """
    return (
        <int64_t>(dt.timestamp()) *
        <int64_t>(1000000) +
        <int64_t>(dt.microsecond))


cdef int64_t datetime_to_nanos(cp_datetime dt):
    """
    Convert a `datetime.datetime` to nanoseconds since the epoch.
    """
    return (
        <int64_t>(dt.timestamp()) *
        <int64_t>(1000000000) +
        <int64_t>(dt.microsecond * 1000))


class ServerTimestampType:
    """
    A placeholder value to indicate that the data should be inserted
    using a server-generated-timestamp.

    Don't instantiate this class directly, use the singleton
    :data:`ServerTimestamp` instead.

    This feature is mostly provided for legacy compatibility.
    We recommend always specifying an explicit timestamp.

    Using ``ServerTimestamp`` will prevent QuestDB's deduplication
    feature from working as it would generate unique rows on resubmission.
    """
    pass


#: Singleton instance used to request server-side timestamping.
#: See :class:`ServerTimestampType` for more details.
ServerTimestamp = ServerTimestampType()


cdef class TimestampMicros:
    """
    A timestamp in microseconds since the UNIX epoch (UTC).

    You may construct a ``TimestampMicros`` from an integer or a
    ``datetime.datetime``, or simply call the :func:`TimestampMicros.now`
    method.

    .. code-block:: python

        # Recommended way to get the current timestamp.
        TimestampMicros.now()

        # The above is equivalent to:
        TimestampMicros(time.time_ns() // 1000)

        # You can provide a numeric timestamp too. It can't be negative.
        TimestampMicros(1657888365426838)

    ``TimestampMicros`` can also be constructed from a ``datetime.datetime``
    object.

    .. code-block:: python

        TimestampMicros.from_datetime(
            datetime.datetime.now(tz=datetime.timezone.utc))

    We recommend that when using ``datetime`` objects, you explicitly pass in
    the timezone to use. This is because ``datetime`` objects without an
    associated timezone are assumed to be in the local timezone and it is easy
    to make mistakes (e.g. passing ``datetime.datetime.utcnow()`` is a likely
    bug).
    """
    cdef int64_t _value

    def __cinit__(self, value: int):
        if value < 0:
            raise ValueError('value must be a positive integer.')
        self._value = value

    @classmethod
    def from_datetime(cls, dt: datetime.datetime):
        """
        Construct a ``TimestampMicros`` from a :class:`datetime.datetime` object.
        """
        if not isinstance(dt, cp_datetime):
            raise TypeError('dt must be a datetime object.')
        return cls(datetime_to_micros(dt))

    @classmethod
    def now(cls):
        """
        Construct a ``TimestampMicros`` from the current time as UTC.
        """
        cdef int64_t value = line_sender_now_micros()
        return cls(value)

    @property
    def value(self) -> int:
        """Number of microseconds (Unix epoch timestamp, UTC)."""
        return self._value

    def __repr__(self):
        return f'TimestampMicros.({self._value})'


cdef class TimestampNanos:
    """
    A timestamp in nanoseconds since the UNIX epoch (UTC).

    You may construct a ``TimestampNanos`` from an integer or a
    ``datetime.datetime``, or simply call the :func:`TimestampNanos.now`
    method.

    .. code-block:: python

        # Recommended way to get the current timestamp.
        TimestampNanos.now()

        # The above is equivalent to:
        TimestampNanos(time.time_ns())

        # You can provide a numeric timestamp too. It can't be negative.
        TimestampNanos(1657888365426838016)

    ``TimestampNanos`` can also be constructed from a ``datetime`` object.

    .. code-block:: python

        TimestampNanos.from_datetime(
            datetime.datetime.now(tz=datetime.timezone.utc))

    We recommend that when using ``datetime`` objects, you explicitly pass in
    the timezone to use. This is because ``datetime`` objects without an
    associated timezone are assumed to be in the local timezone and it is easy
    to make mistakes (e.g. passing ``datetime.datetime.utcnow()`` is a likely
    bug).
    """
    cdef int64_t _value

    def __cinit__(self, value: int):
        if value < 0:
            raise ValueError('value must be a positive integer.')
        self._value = value

    @classmethod
    def from_datetime(cls, dt: datetime.datetime):
        """
        Construct a ``TimestampNanos`` from a ``datetime.datetime`` object.
        """
        if not isinstance(dt, cp_datetime):
            raise TypeError('dt must be a datetime object.')
        return cls(datetime_to_nanos(dt))

    @classmethod
    def now(cls):
        """
        Construct a ``TimestampNanos`` from the current time as UTC.
        """
        cdef int64_t value = line_sender_now_nanos()
        return cls(value)

    @property
    def value(self) -> int:
        """Number of nanoseconds (Unix epoch timestamp, UTC)."""
        return self._value

    def __repr__(self):
        return f'TimestampNanos({self.value})'


cdef class Sender
cdef class Buffer


cdef void_int may_flush_on_row_complete(Buffer buffer, Sender sender) except -1:
    if should_auto_flush(
            &sender._auto_flush_mode,
            buffer._impl,
            sender._last_flush_ms[0]):
        sender.flush(buffer)


cdef bint _is_tcp_protocol(line_sender_protocol protocol):
    return (
        (protocol == line_sender_protocol_tcp) or
        (protocol == line_sender_protocol_tcps))


cdef bint _is_http_protocol(line_sender_protocol protocol):
    return (
        (protocol == line_sender_protocol_http) or
        (protocol == line_sender_protocol_https))


cdef bint _is_qwp_udp_protocol(line_sender_protocol protocol):
    return protocol == line_sender_protocol_qwpudp


cdef bint _is_qwp_ws_protocol(line_sender_protocol protocol):
    return (
        (protocol == line_sender_protocol_qwpws) or
        (protocol == line_sender_protocol_qwpwss))


cdef class SenderTransaction:
    """
    A transaction for a specific table.

    Transactions are only supported with ILP/HTTP.

    The sender API can only operate on one transaction at a time.

    To create a transaction:

    .. code-block:: python

        with sender.transaction('table_name') as txn:
            txn.row(..)
            txn.dataframe(..)
    """
    cdef Sender _sender
    cdef str _table_name
    cdef bint _complete

    def __cinit__(self, Sender sender, str table_name):
        if not _is_http_protocol(sender._c_protocol):
            raise IngressError(
                IngressErrorCode.InvalidApiCall,
                'Transactions are only supported for ILP/HTTP.')
        self._sender = sender
        self._table_name = table_name
        self._complete = False

    def __enter__(self):
        if self._sender._in_txn:
            raise IngressError(
                IngressErrorCode.InvalidApiCall,
                'Already inside a transaction, can\'t start another.')
        if self._sender._buffer is not None and len(self._sender._buffer):
            if self._sender._auto_flush_mode.enabled:
                self._sender.flush()
            else:
                raise IngressError(
                    IngressErrorCode.InvalidApiCall,
                    'Sender buffer must be clear when starting a ' +
                    'transaction. You must call `.flush()` before this call.')
        self._sender._in_txn = True
        return self

    def __exit__(self, exc_type, _exc_value, _traceback):
        if exc_type is not None:
            if not self._complete:
                self.rollback()
            return False
        else:
            if not self._complete:
                self.commit()
            return True

    def row(
            self,
            *,
            symbols: Optional[Dict[str, Optional[str]]]=None,
            columns: Optional[Dict[
                str,
                Union[None, bool, int, float, str, TimestampMicros, TimestampNanos, datetime.datetime, numpy.ndarray]]
                ]=None,
            at: Union[ServerTimestampType, TimestampNanos, datetime.datetime]):
        """
        Write a row for the table in the transaction.

        The table name is taken from the transaction.

        **Note**: Support for NumPy arrays (``numpy.array``) requires QuestDB server version 9.0.0 or higher.
        """
        if at is None:
            raise IngressError(
                IngressErrorCode.InvalidTimestamp,
                "`at` must be of type TimestampNanos, datetime, or ServerTimestamp"
            )

        if self._sender._buffer is None:
            raise IngressError(
                IngressErrorCode.InvalidApiCall,
                "row() can\'t be called: Sender is closed."
            )

        self._sender._buffer._row(
            False,  # allow_auto_flush
            self._table_name,
            symbols=symbols,
            columns=columns,
            at=at)
        return self

    def dataframe(
            self,
            df,  # : pd.DataFrame
            *,
            symbols: Union[str, bool, List[int], List[str]] = 'auto',
            at: Union[ServerTimestampType, int, str, TimestampNanos, datetime.datetime]):
        """
        Write a dataframe for the table in the transaction.

        The table name is taken from the transaction.
        """
        if at is None:
            raise IngressError(
                IngressErrorCode.InvalidTimestamp,
                "`at` must be of type TimestampNanos, datetime, or ServerTimestamp"
            )
        if self._sender._buffer is None:
            raise IngressError(
                IngressErrorCode.InvalidApiCall,
                "dataframe() can\'t be called: Sender is closed."
            )
        _dataframe(
            auto_flush_blank(),
            self._sender._buffer._impl,
            self._sender._buffer._b,
            df,
            self._table_name,
            None, # table_name_col,
            symbols,
            at)
        return self

    def commit(self):
        """
        Commit the transaction.
        
        A commit is also automatic at the end of a successful `with` block.

        This will flush the buffer.
        """
        if self._complete:
            raise IngressError(
                IngressErrorCode.InvalidApiCall,
                'Transaction already completed, can\'t commit')
        self._sender._in_txn = False
        self._complete = True
        if len(self._sender._buffer):
            self._sender.flush(transactional=True)

    def rollback(self):
        """
        Roll back the transaction.

        A rollback is also automatic at the end of a failed `with` block.

        This will clear the buffer.
        """
        if self._complete:
            raise IngressError(
                IngressErrorCode.InvalidApiCall,
                'Transaction already completed, can\'t rollback.')
        if self._sender._buffer is not None:
            self._sender._buffer.clear()
        self._sender._in_txn = False
        self._complete = True

cdef class Buffer:
    """
    Buffer for serializing rows before flushing through a
    :func:`Sender <questdb.ingress.Sender>`.

    Use the factory class methods to create a buffer:

    * :func:`Buffer.ilp` for ILP (InfluxDB Line Protocol) buffers.
    * :func:`Buffer.qwp` for QWP (QuestWire Protocol) buffers.

    .. code-block:: python

        from questdb.ingress import Buffer, Sender, Protocol, TimestampNanos

        buf = Buffer.ilp(protocol_version=2)
        buf.row(
            'table_name',
            symbols={'s1': 'v1'},
            columns={'c1': True, 'c2': 0.5},
            at=TimestampNanos.now())

        with Sender(Protocol.Http, 'localhost', 9000) as sender:
            sender.flush(buf)

    Alternatively, call :func:`Sender.new_buffer` which creates the
    correct buffer type (ILP or QWP) matching the sender's protocol:

    .. code-block:: python

        from questdb.ingress import Sender, Protocol

        with Sender(Protocol.Http, 'localhost', 9000) as sender:
            buf = sender.new_buffer()

    """
    cdef line_sender_buffer* _impl
    cdef qdb_pystr_buf* _b
    cdef size_t _init_buf_size
    cdef size_t _max_name_len
    cdef object _row_complete_sender

    def __cinit__(self):
        self._impl = NULL
        self._b = NULL
        self._init_buf_size = 0
        self._max_name_len = 0
        self._row_complete_sender = None

    def __init__(
            self,
            protocol_version: int,
            init_buf_size: int=65536,
            max_name_len: int=127):
        """
        .. deprecated::
            Use :func:`Buffer.ilp` or :func:`Buffer.qwp` instead.
        """
        warnings.warn(
            'Buffer() is deprecated, use Buffer.ilp() or Buffer.qwp() instead.',
            DeprecationWarning,
            stacklevel=2)
        if protocol_version not in range(1, 4):
            raise IngressError(
                IngressErrorCode.ProtocolVersionError,
                'Invalid protocol version. Supported versions are 1-3.')
        self._init_ilp_impl(protocol_version, init_buf_size, max_name_len)

    @staticmethod
    def ilp(
            protocol_version: int=2,
            init_buf_size: int=65536,
            max_name_len: int=127):
        """
        Create an ILP (InfluxDB Line Protocol) buffer.

        :param int protocol_version: The protocol version to use (1-3).
            Defaults to ``2``.
        :param int init_buf_size: Initial capacity of the buffer in bytes.
            Defaults to ``65536`` (64KiB).
        :param int max_name_len: Maximum length of a table or column name.
            Defaults to ``127``.
        """
        if protocol_version not in range(1, 4):
            raise IngressError(
                IngressErrorCode.ProtocolVersionError,
                'Invalid protocol version. Supported versions are 1-3.')
        cdef Buffer buf = Buffer.__new__(Buffer)
        buf._init_ilp_impl(protocol_version, init_buf_size, max_name_len)
        return buf

    @staticmethod
    def qwp(
            init_buf_size: int=65536,
            max_name_len: int=127):
        """
        Create a QWP (QuestWire Protocol) buffer.

        :param int init_buf_size: Initial capacity of the buffer in bytes.
            Defaults to ``65536`` (64KiB).
        :param int max_name_len: Maximum length of a table or column name.
            Defaults to ``127``.
        """
        cdef Buffer buf = Buffer.__new__(Buffer)
        buf._init_qwp_impl(init_buf_size, max_name_len)
        return buf

    cdef inline _init_ilp_impl(self, line_sender_protocol_version version, size_t init_buf_size, size_t max_name_len):
        self._impl = line_sender_buffer_with_max_name_len(version, max_name_len)
        self._b = qdb_pystr_buf_new()
        reserve_buffer(self._impl, init_buf_size)
        self._init_buf_size = init_buf_size
        self._max_name_len = max_name_len
        self._row_complete_sender = None

    cdef inline _init_qwp_impl(self, size_t init_buf_size, size_t max_name_len):
        self._impl = line_sender_buffer_new_qwp_with_max_name_len(max_name_len)
        self._b = qdb_pystr_buf_new()
        reserve_buffer(self._impl, init_buf_size)
        self._init_buf_size = init_buf_size
        self._max_name_len = max_name_len
        self._row_complete_sender = None


    def __dealloc__(self):
        self._row_complete_sender = None
        qdb_pystr_buf_free(self._b)
        line_sender_buffer_free(self._impl)

    cdef inline void_int _check_impl(self) except -1:
        if self._impl == NULL:
            raise IngressError(
                IngressErrorCode.InvalidApiCall,
                'Buffer is not initialized.')

    @property
    def init_buf_size(self) -> int:
        """
        The initial capacity of the buffer when first created.

        This may grow over time, see ``capacity()``.
        """
        return self._init_buf_size

    @property
    def max_name_len(self) -> int:
        """Maximum length of a table or column name."""
        return self._max_name_len

    def reserve(self, additional: int):
        """
        Ensure the buffer has at least `additional` bytes of future capacity.

        :param int additional: Additional bytes to reserve.
        """
        if additional < 0:
            raise ValueError('additional must be non-negative.')
        self._check_impl()
        reserve_buffer(self._impl, additional)

    def capacity(self) -> int:
        """The current buffer capacity."""
        self._check_impl()
        return line_sender_buffer_capacity(self._impl)

    def clear(self):
        """
        Reset the buffer.

        Note that flushing a buffer will (unless otherwise specified)
        also automatically clear it.

        This method is designed to be called only in conjunction with
        ``sender.flush(buffer, clear=False)``.
        """
        self._check_impl()
        line_sender_buffer_clear(self._impl)
        qdb_pystr_buf_clear(self._b)

    def __len__(self) -> int:
        """
        The current number of bytes currently in the buffer.

        Equivalent (but cheaper) to ``len(bytes(buffer))``.
        """
        self._check_impl()
        return line_sender_buffer_size(self._impl)

    def __bytes__(self) -> bytes:
        """Return the constructed buffer as bytes. Use for debugging."""
        return self._to_bytes()

    cdef inline object _to_bytes(self):
        self._check_impl()
        cdef line_sender_buffer_view view = line_sender_buffer_peek(self._impl)
        return PyBytes_FromStringAndSize(<const char *> view.buf, <Py_ssize_t> view.len)

    cdef inline void_int _set_marker(self) except -1:
        cdef line_sender_error* err = NULL
        if not line_sender_buffer_set_marker(self._impl, &err):
            raise c_err_to_py(err)

    cdef inline void_int _rewind_to_marker(self) except -1:
        cdef line_sender_error* err = NULL
        if not line_sender_buffer_rewind_to_marker(self._impl, &err):
            raise c_err_to_py(err)

    cdef inline _clear_marker(self):
        line_sender_buffer_clear_marker(self._impl)

    cdef inline void_int _table(self, str table_name) except -1:
        cdef line_sender_error* err = NULL
        cdef line_sender_table_name c_table_name
        str_to_table_name(
            self._cleared_b(), <PyObject*>table_name, &c_table_name)
        if not line_sender_buffer_table(self._impl, c_table_name, &err):
            raise c_err_to_py(err)

    cdef inline qdb_pystr_buf* _cleared_b(self):
        qdb_pystr_buf_clear(self._b)
        return self._b

    cdef inline void_int _symbol(self, str name, str value) except -1:
        cdef line_sender_error* err = NULL
        cdef line_sender_column_name c_name
        cdef line_sender_utf8 c_value
        str_to_column_name(self._cleared_b(), name, &c_name)
        str_to_utf8(self._b, <PyObject*>value, &c_value)
        if not line_sender_buffer_symbol(self._impl, c_name, c_value, &err):
            raise c_err_to_py(err)

    cdef inline void_int _column_bool(
            self, line_sender_column_name c_name, bint value) except -1:
        cdef line_sender_error* err = NULL
        if not line_sender_buffer_column_bool(self._impl, c_name, value, &err):
            raise c_err_to_py(err)

    cdef inline void_int _column_decimal(
            self, line_sender_column_name c_name, object value) except -1:
        return serialize_decimal_py_obj(self._impl, c_name, <PyObject*>value)

    cdef inline void_int _column_i64(
            self, line_sender_column_name c_name, int64_t value) except -1:
        cdef line_sender_error* err = NULL
        if not line_sender_buffer_column_i64(self._impl, c_name, value, &err):
            raise c_err_to_py(err)
        return 0

    cdef inline void_int _column_f64(
            self, line_sender_column_name c_name, double value) except -1:
        cdef line_sender_error* err = NULL
        if not line_sender_buffer_column_f64(self._impl, c_name, value, &err):
            raise c_err_to_py(err)

    cdef inline void_int _column_str(
            self, line_sender_column_name c_name, str value) except -1:
        cdef line_sender_error* err = NULL
        cdef line_sender_utf8 c_value
        str_to_utf8(self._b, <PyObject*>value, &c_value)
        if not line_sender_buffer_column_str(self._impl, c_name, c_value, &err):
            raise c_err_to_py(err)

    cdef inline void_int _column_ts_micros(
            self, line_sender_column_name c_name, TimestampMicros ts) except -1:
        cdef line_sender_error* err = NULL
        if not line_sender_buffer_column_ts_micros(self._impl, c_name, ts._value, &err):
            raise c_err_to_py(err)

    cdef inline void_int _column_ts_nanos(
            self, line_sender_column_name c_name, TimestampNanos ts) except -1:
        cdef line_sender_error* err = NULL
        if not line_sender_buffer_column_ts_nanos(self._impl, c_name, ts._value, &err):
            raise c_err_to_py(err)

    cdef inline void_int _column_numpy(
            self, line_sender_column_name c_name, cnp.ndarray arr) except -1:
        if cnp.PyArray_TYPE(arr) != cnp.NPY_FLOAT64:
            raise IngressError(
                IngressErrorCode.ArrayError,
                f'Only float64 numpy arrays are supported, got dtype: {arr.dtype}')
        cdef:
            size_t rank = cnp.PyArray_NDIM(arr)
            const double * data_ptr = <const double*> cnp.PyArray_DATA(arr)
            line_sender_error * err = NULL

        if cnp.PyArray_FLAGS(arr) & cnp.NPY_ARRAY_C_CONTIGUOUS != 0:
            if not line_sender_buffer_column_f64_arr_c_major(
                    self._impl,
                    c_name,
                    rank,
                    <const size_t*> cnp.PyArray_DIMS(arr),
                    data_ptr,
                    cnp.PyArray_SIZE(arr),
                    &err):
                raise c_err_to_py(err)
        else:
            if not line_sender_buffer_column_f64_arr_byte_strides(
                    self._impl,
                    c_name,
                    rank,
                    <const size_t*> cnp.PyArray_DIMS(arr),
                    <const ssize_t*> cnp.PyArray_STRIDES(arr), # N.B.: Strides expressed as byte jumps
                    data_ptr,
                    cnp.PyArray_SIZE(arr),
                    &err):
                raise c_err_to_py(err)

    cdef inline void_int _column_dt(
            self, line_sender_column_name c_name, cp_datetime dt) except -1:
        cdef line_sender_error* err = NULL
        # We limit ourselves to micros, since this is the maxium precision
        # exposed by the datetime library in Python.
        if not line_sender_buffer_column_ts_micros(
                self._impl, c_name, datetime_to_micros(dt), &err):
            raise c_err_to_py(err)

    cdef inline void_int _column(self, str name, object value) except -1:
        cdef line_sender_column_name c_name
        str_to_column_name(self._cleared_b(), name, &c_name)
        if PyBool_Check(<PyObject*>value):
            self._column_bool(c_name, value)
        elif PyLong_CheckExact(<PyObject*>value):
            self._column_i64(c_name, value)
        elif PyFloat_CheckExact(<PyObject*>value):
            self._column_f64(c_name, value)
        elif PyUnicode_CheckExact(<PyObject*>value):
            self._column_str(c_name, value)
        elif isinstance(value, TimestampMicros):
            self._column_ts_micros(c_name, value)
        elif isinstance(value, TimestampNanos):
            self._column_ts_nanos(c_name, value)
        elif PyArray_CheckExact(<PyObject *> value):
            self._column_numpy(c_name, value)
        elif isinstance(value, cp_datetime):
            self._column_dt(c_name, value)
        elif isinstance(value, Decimal):
            self._column_decimal(c_name, value)
        else:
            valid = ', '.join((
                'bool',
                'int',
                'float',
                'str',
                'TimestampMicros',
                'datetime.datetime',
                'numpy.ndarray'))
            raise TypeError(
                f'Unsupported type: {_fqn(type(value))}. Must be one of: {valid}')

    cdef inline void_int _may_trigger_row_complete(self) except -1:
        cdef line_sender_error* err = NULL
        cdef PyObject* sender = NULL
        if self._row_complete_sender != None:
            sender = PyWeakref_GetObject(self._row_complete_sender)
            if sender != NULL:
                may_flush_on_row_complete(self, <Sender><object>sender)

    cdef inline void_int _at_ts_us(self, TimestampMicros ts) except -1:
        cdef line_sender_error* err = NULL
        if not line_sender_buffer_at_micros(self._impl, ts._value, &err):
            raise c_err_to_py(err)

    cdef inline void_int _at_ts_ns(self, TimestampNanos ts) except -1:
        cdef line_sender_error* err = NULL
        if not line_sender_buffer_at_nanos(self._impl, ts._value, &err):
            raise c_err_to_py(err)

    cdef inline void_int _at_dt(self, cp_datetime dt) except -1:
        cdef int64_t value = datetime_to_micros(dt)
        cdef line_sender_error* err = NULL
        if not line_sender_buffer_at_micros(self._impl, value, &err):
            raise c_err_to_py(err)

    cdef inline void_int _at_now(self) except -1:
        cdef line_sender_error* err = NULL
        if not line_sender_buffer_at_now(self._impl, &err):
            raise c_err_to_py(err)

    cdef inline void_int _at(self, object ts) except -1:
        if ts is None:
            self._at_now()
        elif isinstance(ts, TimestampMicros):
            self._at_ts_us(ts)
        elif isinstance(ts, TimestampNanos):
            self._at_ts_ns(ts)
        elif isinstance(ts, cp_datetime):
            self._at_dt(ts)
        else:
            raise TypeError(
                f'Unsupported type: {_fqn(type(ts))}. Must be one of: ' +
                'TimestampNanos, datetime, None')

    cdef void_int _row(
            self,
            bint allow_auto_flush,
            str table_name,
            dict symbols=None,
            dict columns=None,
            object at=None) except -1:
        """
        Add a row to the buffer.
        """
        cdef bint wrote_fields = False
        self._check_impl()
        self._set_marker()
        try:
            self._table(table_name)
            if symbols is not None:
                for name, value in symbols.items():
                    if value is not None:
                        self._symbol(name, value)
                        wrote_fields = True
            if columns is not None:
                for name, value in columns.items():
                    if value is not None:
                        self._column(name, value)
                        wrote_fields = True
            if wrote_fields:
                self._at(at if not isinstance(at, ServerTimestampType) else None)
                self._clear_marker()
            else:
                self._rewind_to_marker()
        except:
            self._rewind_to_marker()
            raise
        if wrote_fields and allow_auto_flush:
            self._may_trigger_row_complete()

    def row(
            self,
            table_name: str,
            *,
            symbols: Optional[Dict[str, Optional[str]]]=None,
            columns: Optional[Dict[
                str,
                Union[None, bool, int, float, str, TimestampMicros, TimestampNanos, datetime.datetime, numpy.ndarray]]
                ]=None,
            at: Union[ServerTimestampType, TimestampNanos, datetime.datetime]):
        """
        Add a single row (line) to the buffer.

        .. code-block:: python

            # All fields specified.
            buffer.row(
                'table_name',
                symbols={'sym1': 'abc', 'sym2': 'def', 'sym3': None},
                columns={
                    'col1': True,
                    'col2': 123,
                    'col3': 3.14,
                    'col4': 'xyz',
                    'col5': TimestampMicros(123456789),
                    'col6': datetime(2019, 1, 1, 12, 0, 0),
                    'col7': numpy.array([[1.0, 2.0, 3.0], [4.0, 5.0, 6.0]]),
                    'col8': None},
                at=TimestampNanos(123456789))

            # Only symbols specified. Designated timestamp assigned by the db.
            buffer.row(
                'table_name',
                symbols={'sym1': 'abc', 'sym2': 'def'}, at=Server.Timestamp)

            # Float columns and timestamp specified as `datetime.datetime`.
            # Pay special attention to the timezone, which if unspecified is
            # assumed to be the local timezone (and not UTC).
            buffer.row(
                'sensor data',
                columns={
                    'temperature': 24.5,
                    'humidity': 0.5},
                at=datetime.datetime.now(tz=datetime.timezone.utc))


        Python strings passed as values to ``symbols`` are going to be encoded
        as the ``SYMBOL`` type in QuestDB, whilst Python strings passed as
        values to ``columns`` are going to be encoded as the ``STRING`` type.

        Refer to the
        `QuestDB documentation <https://questdb.com/docs/concept/symbol/>`_ to
        understand the difference between the ``SYMBOL`` and ``STRING`` types
        (TL;DR: symbols are interned strings).

        Column values can be specified with Python types directly and map as so:

        .. list-table::
            :header-rows: 1

            * - Python type
              - Serialized as ILP type
            * - ``bool``
              - `BOOLEAN <https://questdb.com/docs/reference/api/ilp/columnset-types#boolean>`_
            * - ``decimal``
              - `DECIMAL <https://questdb.com/docs/reference/api/ilp/columnset-types#decimal>`_
            * - ``int``
              - `INTEGER <https://questdb.com/docs/reference/api/ilp/columnset-types#integer>`_
            * - ``float``
              - `FLOAT <https://questdb.com/docs/reference/api/ilp/columnset-types#float>`_
            * - ``str``
              - `STRING <https://questdb.com/docs/reference/api/ilp/columnset-types#string>`_
            * - ``numpy.ndarray``
              - `ARRAY <https://questdb.com/docs/reference/api/ilp/columnset-types#array>`_
            * - ``datetime.datetime`` and ``TimestampMicros``
              - `TIMESTAMP <https://questdb.com/docs/reference/api/ilp/columnset-types#timestamp>`_
            * - ``None``
              - *Column is skipped and not serialized.*

        **Note**: Support for NumPy arrays (``numpy.array``) requires QuestDB server version 9.0.0 or higher.

        If the destination table was already created, then the columns types
        will be cast to the types of the existing columns whenever possible
        (Refer to the QuestDB documentation pages linked above).

        Adding a row can trigger auto-flushing behaviour.

        :param table_name: The name of the table to which the row belongs.
        :param symbols: A dictionary of symbol column names to ``str`` values.
            As a convenience, you can also pass a ``None`` value which will
            have the same effect as skipping the key: If the column already
            existed, it will be recorded as ``NULL``, otherwise it will not be
            created.
        :param columns: A dictionary of column names to ``bool``, ``int``,
            ``float``, ``str``, ``TimestampMicros`` or ``datetime`` values.
            As a convenience, you can also pass a ``None`` value which will
            have the same effect as skipping the key: If the column already
            existed, it will be recorded as ``NULL``, otherwise it will not be
            created.
        :param at: The timestamp of the row. This is required!
            If ``ServerTimestamp``, timestamp is assigned by QuestDB.
            If ``datetime``, the timestamp is converted to nanoseconds.
            A nanosecond unix epoch timestamp can be passed
            explicitly as a ``TimestampNanos`` object.
        """
        if at is None:
            raise IngressError(
                IngressErrorCode.InvalidTimestamp,
                "`at` must be of type TimestampNanos, datetime, or ServerTimestamp"
            )
        self._row(
            True,  # allow_auto_flush
            table_name,
            symbols,
            columns,
            at)
        return self

    def dataframe(
            self,
            df,  # : pd.DataFrame
            *,
            table_name: Optional[str] = None,
            table_name_col: Union[None, int, str] = None,
            symbols: Union[str, bool, List[int], List[str]] = 'auto',
            at: Union[ServerTimestampType, int, str, TimestampNanos, datetime.datetime]):
        """
        Add a pandas DataFrame to the buffer.

        Also see the :func:`Sender.dataframe` method if you're
        not using the buffer explicitly. It supports the same parameters
        and also supports auto-flushing.

        This feature requires the ``pandas``, ``numpy`` and ``pyarrow``
        package to be installed.

        Adding a dataframe can trigger auto-flushing behaviour,
        even between rows of the same dataframe. To avoid this, you can
        use HTTP and transactions (see :func:`Sender.transaction`).

        :param df: The pandas DataFrame to serialize to the buffer.
        :type df: pandas.DataFrame

        :param table_name: The name of the table to which the rows belong.

            If ``None``, the table name is taken from the ``table_name_col``
            parameter. If both ``table_name`` and ``table_name_col`` are
            ``None``, the table name is taken from the DataFrame's index
            name (``df.index.name`` attribute).
        :type table_name: str or None

        :param table_name_col: The name or index of the column in the DataFrame
            that contains the table name.
            
            If ``None``, the table name is taken
            from the ``table_name`` parameter. If both ``table_name`` and
            ``table_name_col`` are ``None``, the table name is taken from the
            DataFrame's index name (``df.index.name`` attribute).

            If ``table_name_col`` is an integer, it is interpreted as the index
            of the column starting from ``0``. The index of the column can be
            negative, in which case it is interpreted as an offset from the end
            of the DataFrame. E.g. ``-1`` is the last column.
        :type table_name_col: str or int or None

        :param symbols: The columns to be serialized as symbols.
        
            If ``'auto'`` (default), all columns of dtype ``'categorical'`` are
            serialized as symbols. If ``True``, all ``str`` columns are
            serialized as symbols. If ``False``, no columns are serialized as
            symbols.
            
            The list of symbols can also be specified explicitly as a ``list``
            of column names (``str``) or indices (``int``). Integer indices
            start at ``0`` and can be negative, offset from the end of the
            DataFrame. E.g. ``-1`` is the last column.

            Only columns containing strings can be serialized as symbols.

        :type symbols: str or bool or list[str] or list[int]

        :param at: The designated timestamp of the rows.
        
            You can specify a single value for all rows or column name or index.
            If ``ServerTimestamp``, timestamp is assigned by the server for all rows.
            To pass in a timestamp explicitly as an integer use the
            ``TimestampNanos`` wrapper type. To get the current timestamp,
            use ``TimestampNanos.now()``.
            When passing a ``datetime.datetime`` object, the timestamp is
            converted to nanoseconds.
            A ``datetime`` object is assumed to be in the local timezone unless
            one is specified explicitly (so call
            ``datetime.datetime.now(tz=datetime.timezone.utc)`` instead
            of ``datetime.datetime.utcnow()`` for the current timestamp to
            avoid bugs).

            To specify a different timestamp for each row, pass in a column name
            (``str``) or index (``int``, 0-based index, negative index
            supported): In this case, the column needs to be of dtype
            ``datetime64[ns]`` (assumed to be in the **UTC timezone** and not
            local, due to differences in Pandas and Python datetime handling) or
            ``datetime64[ns, tz]``. When a timezone is specified in the column,
            it is converted to UTC automatically.

            A timestamp column can also contain ``None`` values. The server will
            assign the current timestamp to those rows.

            **Note**: All timestamps are always converted to nanoseconds and in
            the UTC timezone. Timezone information is dropped before sending and
            QuestDB will not store any timezone information.
        :type at: TimestampNanos, datetime.datetime, int or str or None

        **Note**: It is an error to specify both ``table_name`` and
        ``table_name_col``.

        **Note**: The "index" column of the DataFrame is never serialized,
        even if it is named.

        Example:

        .. code-block:: python

            import pandas as pd
            import questdb.ingress as qi

            buf = qi.Buffer.ilp(protocol_version=2)
            # ...

            df = pd.DataFrame({
                'location': ['London', 'Managua', 'London'],
                'temperature': [24.5, 35.0, 25.5],
                'humidity': [0.5, 0.6, 0.45],
                'ts': pd.date_range('2021-07-01', periods=3)})
            buf.dataframe(
                df, table_name='weather', at='ts', symbols=['location'])

            # ...
            sender.flush(buf)

        **Pandas to ILP datatype mappings**

        .. seealso:: https://questdb.com/docs/reference/api/ilp/columnset-types/

        .. list-table:: Pandas Mappings
            :header-rows: 1

            * - Pandas ``dtype``
              - Nulls
              - ILP Datatype
            * - ``'bool'``
              - N
              - ``BOOLEAN``
            * - ``'boolean'``
              - N **α**
              - ``BOOLEAN``
            * - ``'object'`` (``bool`` objects)
              - N **α**
              - ``BOOLEAN``
            * - ``'uint8'``
              - N
              - ``INTEGER``
            * - ``'int8'``
              - N
              - ``INTEGER``
            * - ``'uint16'``
              - N
              - ``INTEGER``
            * - ``'int16'``
              - N
              - ``INTEGER``
            * - ``'uint32'``
              - N
              - ``INTEGER``
            * - ``'int32'``
              - N
              - ``INTEGER``
            * - ``'uint64'``
              - N
              - ``INTEGER`` **β**
            * - ``'int64'``
              - N
              - ``INTEGER``
            * - ``'UInt8'``
              - Y
              - ``INTEGER``
            * - ``'Int8'``
              - Y
              - ``INTEGER``
            * - ``'UInt16'``
              - Y
              - ``INTEGER``
            * - ``'Int16'``
              - Y
              - ``INTEGER``
            * - ``'UInt32'``
              - Y
              - ``INTEGER``
            * - ``'Int32'``
              - Y
              - ``INTEGER``
            * - ``'UInt64'``
              - Y
              - ``INTEGER`` **β**
            * - ``'Int64'``
              - Y
              - ``INTEGER``
            * - ``'object'`` (``int`` objects)
              - Y
              - ``INTEGER`` **β**
            * - ``'float32'`` **γ**
              - Y (``NaN``)
              - ``FLOAT``
            * - ``'float64'``
              - Y (``NaN``)
              - ``FLOAT``
            * - ``'object'`` (``float`` objects)
              - Y (``NaN``)
              - ``FLOAT``
            * - ``'string'`` (``str`` objects)
              - Y
              - ``STRING`` (default), ``SYMBOL`` via ``symbols`` arg. **δ**
            * - ``'string[pyarrow]'``
              - Y
              - ``STRING`` (default), ``SYMBOL`` via ``symbols`` arg. **δ**
            * - ``'category'`` (``str`` objects) **ε**
              - Y
              - ``SYMBOL`` (default), ``STRING`` via ``symbols`` arg. **δ**
            * - ``'object'`` (``str`` objects)
              - Y
              - ``STRING`` (default), ``SYMBOL`` via ``symbols`` arg. **δ**
            * - ``'datetime64[ns]'``
              - Y
              - ``TIMESTAMP`` **ζ**
            * - ``'datetime64[ns, tz]'``
              - Y
              - ``TIMESTAMP`` **ζ**
            * - ``'object'`` (``Decimal`` objects)
              - Y (``NaN``)
              - ``DECIMAL``

        .. note::

            * **α**: Note some pandas dtypes allow nulls (e.g. ``'boolean'``),
              where the QuestDB database does not.

            * **β**: The valid range for integer values is -2^63 to 2^63-1.
              Any ``'uint64'``, ``'UInt64'`` or python ``int`` object values
              outside this range will raise an error during serialization.

            * **γ**: Upcast to 64-bit float during serialization.

            * **δ**: Columns containing strings can also be used to specify the
              table name. See ``table_name_col``.

            * **ε**: We only support categories containing strings. If the
              category contains non-string values, an error will be raised.

            * **ζ**: The '.dataframe()' method only supports datetimes with
              nanosecond precision. The designated timestamp column (see ``at``
              parameter) maintains the nanosecond precision, whilst values
              stored as columns have their precision truncated to microseconds.
              All dates are sent as UTC and any additional timezone information
              is dropped. If no timezone is specified, we follow
              the pandas convention of assuming the timezone is UTC.
              Datetimes before 1970-01-01 00:00:00 UTC are not supported.
              If a datetime value is specified as ``None`` (``NaT``), it is
              interpreted as the current QuestDB server time set on receipt of
              message.

        **Error Handling and Recovery**

        In case an exception is raised during dataframe serialization, the
        buffer is left in its previous state.
        The buffer remains in a valid state and can be used for further calls
        even after an error.

        For clarification, as an example, if an invalid ``None``
        value appears at the 3rd row for a ``bool`` column, neither the 3rd nor
        the preceding rows are added to the buffer.

        **Note**: This differs from the :func:`Sender.dataframe` method, which
        modifies this guarantee due to its ``auto_flush`` logic.

        **Performance Considerations**

        The Python GIL is released during serialization if it is not needed.
        If any column requires the GIL, the entire serialization is done whilst
        holding the GIL.

        Column types that require the GIL are:

        * Columns of ``str``, ``float`` or ``int`` or ``float`` Python objects.
        * The ``'string[python]'`` dtype.
        """
        if at is None:
            raise IngressError(
                IngressErrorCode.InvalidTimestamp,
                "`at` must be of type TimestampNanos, datetime, or ServerTimestamp"
            )
        self._check_impl()
        _dataframe(
            auto_flush_blank(),
            self._impl,
            self._b,
            df,
            table_name,
            table_name_col,
            symbols,
            at)
        return self


_FLUSH_FMT = ('{} - See https://py-questdb-client.readthedocs.io/en/'
    'v' + VERSION +
    '/troubleshooting.html#inspecting-and-debugging-errors#flush-failed')


cdef uint64_t _timedelta_to_millis(cp_timedelta timedelta):
    """
    Convert a timedelta to milliseconds.
    """
    cdef int64_t millis = (
        (timedelta.microseconds // 1000) +
        (int(timedelta.total_seconds()) * 1000))
    if millis < 0:
        raise ValueError(
            f'Negative timedelta not allowed: {timedelta!r}.')
    return millis


cdef int64_t auto_flush_rows_default(line_sender_protocol protocol):
    if _is_http_protocol(protocol):
        return 75000
    else:
        return 600


cdef void_int _parse_auto_flush(
    line_sender_protocol protocol,
    object auto_flush,
    object auto_flush_rows,
    object auto_flush_bytes,
    object auto_flush_interval,
    auto_flush_mode_t* c_auto_flush,
    size_t max_datagram_size
) except -1:
    # Set defaults.
    if auto_flush_rows is None:
        auto_flush_rows = auto_flush_rows_default(protocol)

    if auto_flush_bytes is None:
        if _is_qwp_udp_protocol(protocol):
            auto_flush_bytes = max_datagram_size if max_datagram_size else 1400
        else:
            auto_flush_bytes = False

    if auto_flush_interval is None:
        auto_flush_interval = 1000

    if isinstance(auto_flush, str):
        if auto_flush == 'off':
            auto_flush = False
        elif auto_flush == 'on':
            auto_flush = True
        else:
            raise IngressError(
                IngressErrorCode.ConfigError,
                '"auto_flush" must be None, bool, "on" or "off", ' +
                f'not {auto_flush!r}')

    # Normalise auto_flush parameters to ints or False.
    if isinstance(auto_flush_rows, str):
        if auto_flush_rows == 'on':
            raise IngressError(
                IngressErrorCode.ConfigError,
                '"auto_flush_rows" cannot be "on"')
        elif auto_flush_rows == 'off':
            auto_flush_rows = False
        else:
            auto_flush_rows = int(auto_flush_rows)
    elif auto_flush_rows is False or isinstance(auto_flush_rows, int):
        pass
    else:
        raise TypeError(
            '"auto_flush_rows" must be an int, False or "off", ' +
            f'not {auto_flush_rows!r}')

    if isinstance(auto_flush_bytes, str):
        if auto_flush_bytes == 'on':
            raise IngressError(
                IngressErrorCode.ConfigError,
                '"auto_flush_bytes" cannot be "on"')
        elif auto_flush_bytes == 'off':
            auto_flush_bytes = False
        else:
            auto_flush_bytes = int(auto_flush_bytes)
    elif auto_flush_bytes is False or isinstance(auto_flush_bytes, int):
        pass
    else:
        raise TypeError(
            '"auto_flush_bytes" must be an int, False or "off", ' +
            f'not {auto_flush_bytes!r}')

    if isinstance(auto_flush_interval, str):
        if auto_flush_interval == 'on':
            raise IngressError(
                IngressErrorCode.ConfigError,
                '"auto_flush_interval" cannot be "on"')
        elif auto_flush_interval == 'off':
            auto_flush_interval = False
        else:
            auto_flush_interval = int(auto_flush_interval)
    elif auto_flush_interval is False or isinstance(auto_flush_interval, int):
        pass
    elif isinstance(auto_flush_interval, cp_timedelta):
        auto_flush_interval = _timedelta_to_millis(auto_flush_interval)
    else:
        raise TypeError(
            '"auto_flush_interval" must be an int, timedelta, False or "off", ' +
            f'not {auto_flush_interval!r}')

    # Coerce auto_flush to bool if None.
    if auto_flush is None:
        auto_flush = (
            (auto_flush_rows is not False) or
            (auto_flush_bytes is not False) or
            (auto_flush_interval is not False))
    elif not isinstance(auto_flush, bool):
        raise ValueError(
            '"auto_flush" must be None, bool, "on" or "off", ' +
            f'not {auto_flush!r}')

    # Validate auto_flush parameters.
    if auto_flush and \
            (auto_flush_rows is False) and \
            (auto_flush_bytes is False) and \
            (auto_flush_interval is False):
        raise ValueError(
            '"auto_flush" is enabled but no other auto-flush '
            'parameters are enabled. Please set at least one of '
            '"auto_flush_rows", "auto_flush_bytes" or '
            '"auto_flush_interval".')

    if auto_flush_rows is not False and auto_flush_rows < 1:
        raise ValueError(
            '"auto_flush_rows" must be >= 1, '
            f'not {auto_flush_rows}')

    if auto_flush_bytes is not False and auto_flush_bytes < 1:
        raise ValueError(
            '"auto_flush_bytes" must be >= 1, '
            f'not {auto_flush_bytes}')

    if auto_flush_interval is not False and auto_flush_interval < 1:
        raise ValueError(
            '"auto_flush_interval" must be >= 1, '
            f'not {auto_flush_interval}')

    # Parse individual auto_flush parameters to C struct.
    c_auto_flush.enabled = auto_flush

    if auto_flush_rows is False:
        c_auto_flush.row_count = -1
    else:
        c_auto_flush.row_count = auto_flush_rows

    if auto_flush_bytes is False:
        c_auto_flush.byte_count = -1
    else:
        c_auto_flush.byte_count = auto_flush_bytes

    if auto_flush_interval is False:
        c_auto_flush.interval = -1
    else:
        c_auto_flush.interval = auto_flush_interval


class TaggedEnum(Enum):
    """
    Base class for tagged enums.
    """

    @property
    def tag(self):
        """
        Short name.
        """
        return self.value[0]

    @property
    def c_value(self):
        return self.value[1]

    @classmethod
    def parse(cls, tag):
        """
        Parse from the tag name.
        """
        if tag is None:
            return None
        elif isinstance(tag, str):
            for entry in cls:
                if entry.tag == tag:
                    return entry
        elif isinstance(tag, cls):
            return tag
        else:
            raise ValueError(f'Invalid value for {cls.__name__}: {tag!r}')


class Protocol(TaggedEnum):
    """
    Protocol to use for sending data to QuestDB.

    See :ref:`sender_which_protocol` for more information.
    """
    Tcp = ('tcp', 0)
    Tcps = ('tcps', 1)
    Http = ('http', 2)
    Https = ('https', 3)
    QwpUdp = ('qwpudp', 4)
    QwpWs = ('qwpws', 5)
    QwpWss = ('qwpwss', 6)

    @property
    def tls_enabled(self):
        return self in (Protocol.Tcps, Protocol.Https, Protocol.QwpWss)


class QwpWsProgress(TaggedEnum):
    """
    Progress mode for QWP/WebSocket senders.
    """
    Background = ('background', LINE_SENDER_QWPWS_PROGRESS_BACKGROUND)
    Manual = ('manual', LINE_SENDER_QWPWS_PROGRESS_MANUAL)


class QwpWsErrorCategory(TaggedEnum):
    """
    Category of a structured QWP/WebSocket diagnostic.
    """
    SchemaMismatch = (
        'schema_mismatch',
        LINE_SENDER_QWPWS_ERROR_SCHEMA_MISMATCH)
    ParseError = ('parse_error', LINE_SENDER_QWPWS_ERROR_PARSE_ERROR)
    InternalError = ('internal_error', LINE_SENDER_QWPWS_ERROR_INTERNAL_ERROR)
    SecurityError = ('security_error', LINE_SENDER_QWPWS_ERROR_SECURITY_ERROR)
    WriteError = ('write_error', LINE_SENDER_QWPWS_ERROR_WRITE_ERROR)
    ProtocolViolation = (
        'protocol_violation',
        LINE_SENDER_QWPWS_ERROR_PROTOCOL_VIOLATION)
    Unknown = ('unknown', LINE_SENDER_QWPWS_ERROR_UNKNOWN)


class QwpWsErrorPolicy(TaggedEnum):
    """
    Applied policy for a structured QWP/WebSocket diagnostic.
    """
    DropAndContinue = (
        'drop_and_continue',
        LINE_SENDER_QWPWS_ERROR_DROP_AND_CONTINUE)
    Halt = ('halt', LINE_SENDER_QWPWS_ERROR_HALT)


@dataclass(frozen=True)
class QwpWsError:
    category: QwpWsErrorCategory
    applied_policy: QwpWsErrorPolicy
    status: Optional[int]
    message: str
    message_sequence: Optional[int]
    from_fsn: int
    to_fsn: int


def _qwp_ws_error_from_raw(raw):
    if raw is None or isinstance(raw, QwpWsError):
        return raw

    (
        category,
        applied_policy,
        status,
        message,
        message_sequence,
        from_fsn,
        to_fsn,
    ) = raw

    py_category = QwpWsErrorCategory.Unknown
    for entry in QwpWsErrorCategory:
        if entry.c_value == category:
            py_category = entry
            break

    py_policy = QwpWsErrorPolicy.Halt
    for entry in QwpWsErrorPolicy:
        if entry.c_value == applied_policy:
            py_policy = entry
            break

    return QwpWsError(
        py_category,
        py_policy,
        status,
        message,
        message_sequence,
        from_fsn,
        to_fsn)


def _default_qwp_ws_error_handler(error):
    level = (
        logging.ERROR
        if error.applied_policy is QwpWsErrorPolicy.Halt
        else logging.WARNING)
    logging.getLogger("questdb.ingress").log(
        level,
        "QWP/WebSocket server rejection: "
        "category=%s policy=%s status=%s fsn=[%s,%s] seq=%s message=%s",
        error.category.tag,
        error.applied_policy.tag,
        error.status,
        error.from_fsn,
        error.to_fsn,
        error.message_sequence,
        error.message)


cdef void _qwp_ws_error_trampoline(
        void* user_data,
        const line_sender_qwpws_error_view* view) noexcept with gil:
    cdef object handler = <object>user_data
    try:
        handler(_qwp_ws_error_from_raw(c_qwp_ws_error_view_to_raw(view[0])))
    except BaseException:
        logging.getLogger("questdb.ingress").exception(
            "QWP/WebSocket error handler failed")


class TlsCa(TaggedEnum):
    """
    Verification mechanism for the server's certificate.

    Here ``webpki`` refers to the
    `WebPKI library <https://github.com/rustls/webpki-roots>`_ and
    ``os`` refers to the operating system's certificate store.

    See :ref:`sender_conf_tls` for more information.
    """
    WebpkiRoots = ('webpki_roots', line_sender_ca_webpki_roots)
    OsRoots = ('os_roots', line_sender_ca_os_roots)
    WebpkiAndOsRoots = ('webpki_and_os_roots', line_sender_ca_webpki_and_os_roots)
    PemFile = ('pem_file', line_sender_ca_pem_file)


cdef object c_parse_conf_err_to_py(questdb_conf_str_parse_err* err):
    cdef str msg = PyUnicode_FromStringAndSize(
        err.msg, <Py_ssize_t>err.msg_len)
    cdef object py_err = IngressError(IngressErrorCode.ConfigError, msg)
    questdb_conf_str_parse_err_free(err)
    return py_err


cdef object parse_conf_str(
        qdb_pystr_buf* b,
        str conf_str):
    """
    Parse a config string to a tuple of (Protocol, dict[str, str]).
    """
    cdef size_t c_len1
    cdef const char* c_buf1
    cdef size_t c_len2
    cdef const char* c_buf2
    cdef str service
    cdef questdb_conf_str_iter* c_iter
    cdef str key
    cdef str value
    cdef dict params = {}
    cdef line_sender_utf8 c_conf_str_utf8
    cdef questdb_conf_str_parse_err* err
    cdef questdb_conf_str* c_conf_str
    str_to_utf8(b, <PyObject*>conf_str, &c_conf_str_utf8)
    c_conf_str = questdb_conf_str_parse(
        c_conf_str_utf8.buf,
        c_conf_str_utf8.len,
        &err)
    if c_conf_str == NULL:
        raise c_parse_conf_err_to_py(err)

    c_buf1 = questdb_conf_str_service(c_conf_str, &c_len1)
    service = PyUnicode_FromStringAndSize(c_buf1, <Py_ssize_t>c_len1)

    c_iter = questdb_conf_str_iter_pairs(c_conf_str)
    while questdb_conf_str_iter_next(c_iter, &c_buf1, &c_len1, &c_buf2, &c_len2):
        key = PyUnicode_FromStringAndSize(c_buf1, <Py_ssize_t>c_len1)
        value = PyUnicode_FromStringAndSize(c_buf2, <Py_ssize_t>c_len2)
        params[key] = value

    questdb_conf_str_iter_free(c_iter)
    questdb_conf_str_free(c_conf_str)

    # We now need to parse the various values in the dict from their
    # string values to their Python types, as expected by the overrides
    # API of Sender.from_conf and Sender.from_env.
    # Note that some of these values, such as `tls_ca` or `auto_flush`
    # are kept as strings and are parsed by Sender._set_sender_fields.
    type_mappings = {
        'bind_interface': str,
        'max_datagram_size': int,
        'multicast_ttl': int,
        'username': str,
        'password': str,
        'token': str,
        'token_x': str,
        'token_y': str,
        'auth_timeout': int,
        'tls_verify': str,
        'tls_ca': str,
        'tls_roots': str,
        'tls_roots_password': str,
        'max_buf_size': int,
        'retry_timeout': int,
        'retry_max_backoff_millis': int,
        'request_min_throughput': int,
        'request_timeout': int,
        'auto_flush': str,
        'auto_flush_rows': str,
        'auto_flush_bytes': str,
        'auto_flush_interval': str,
        'init_buf_size': int,
        'max_name_len': int,
        'qwp_ws_progress': str,
    }
    params = {
        k: type_mappings.get(k, str)(v)
        for k, v in params.items()
    }
    return (Protocol.parse(service), params)


cdef str conf_str_value(object value):
    return str(value).replace(';', ';;')


cdef class Sender:
    """
    Ingest data into QuestDB.

    See the :ref:`sender` documentation for more information.
    """

    # We need the Buffer held by a Sender can hold a weakref to its Sender.
    # This avoids a circular reference that requires the GC to clean up.
    cdef object __weakref__

    cdef line_sender_protocol _c_protocol
    cdef line_sender_opts* _opts
    cdef line_sender* _impl
    cdef Buffer _buffer
    cdef object _qwp_ws_error_handler
    cdef auto_flush_mode_t _auto_flush_mode
    cdef int64_t* _last_flush_ms
    cdef size_t _init_buf_size
    cdef bint _in_txn
    cdef int64_t _slot_id

    cdef void_int _set_sender_fields(
            self,
            qdb_pystr_buf* b,
            object protocol,
            str bind_interface,
            str username,
            str password,
            str token,
            str token_x,
            str token_y,
            object auth_timeout,
            object tls_verify,
            object tls_ca,
            object tls_roots,
            object tls_roots_password,
            object max_buf_size,
            object retry_timeout,
            object retry_max_backoff,
            object request_min_throughput,
            object request_timeout,
            object auto_flush,
            object auto_flush_rows,
            object auto_flush_bytes,
            object auto_flush_interval,
            object max_datagram_size,
            object multicast_ttl,
            object protocol_version,
            object qwp_ws_progress,
            object qwp_ws_error_handler,
            object init_buf_size,
            object max_name_len) except -1:
        """
        Set optional parameters for the sender.
        """
        cdef line_sender_error* err = NULL
        cdef str user_agent = 'questdb/python/' + VERSION
        cdef line_sender_utf8 c_user_agent
        cdef line_sender_utf8 c_bind_interface
        cdef line_sender_utf8 c_username
        cdef line_sender_utf8 c_password
        cdef line_sender_utf8 c_token
        cdef line_sender_utf8 c_token_x
        cdef line_sender_utf8 c_token_y
        cdef uint64_t c_auth_timeout
        cdef bint c_tls_verify
        cdef line_sender_ca c_tls_ca
        cdef line_sender_utf8 c_tls_roots
        cdef line_sender_utf8 c_tls_roots_password
        cdef uint64_t c_max_buf_size
        cdef uint64_t c_retry_timeout
        cdef uint64_t c_retry_max_backoff
        cdef uint64_t c_request_min_throughput
        cdef uint64_t c_request_timeout
        cdef size_t c_max_datagram_size = 0
        cdef uint32_t c_multicast_ttl = 0
        cdef line_sender_qwpws_progress c_qwp_ws_progress

        self._c_protocol = protocol.c_value

        # It's OK to override this setting.
        str_to_utf8(b, <PyObject*>user_agent, &c_user_agent)
        if not line_sender_opts_user_agent(self._opts, c_user_agent, &err):
            raise c_err_to_py(err)

        if bind_interface is not None:
            str_to_utf8(b, <PyObject*>bind_interface, &c_bind_interface)
            if not line_sender_opts_bind_interface(
                    self._opts, c_bind_interface, &err):
                raise c_err_to_py(err)

        if max_datagram_size is not None:
            if not isinstance(max_datagram_size, int) or isinstance(max_datagram_size, bool):
                raise TypeError(
                    '"max_datagram_size" must be a positive int, '
                    f'not {_fqn(type(max_datagram_size))}')
            if max_datagram_size <= 0 or max_datagram_size > 65507:
                raise ValueError(
                    '"max_datagram_size" must be an int between 1 and 65507, '
                    f'not {max_datagram_size!r}')
            c_max_datagram_size = max_datagram_size
            if not line_sender_opts_max_datagram_size(
                    self._opts, c_max_datagram_size, &err):
                raise c_err_to_py(err)

        if multicast_ttl is not None:
            if not isinstance(multicast_ttl, int) or isinstance(multicast_ttl, bool):
                raise TypeError(
                    '"multicast_ttl" must be an int (0-255), '
                    f'not {_fqn(type(multicast_ttl))}')
            if multicast_ttl < 0 or multicast_ttl > 255:
                raise ValueError(
                    '"multicast_ttl" must be an int (0-255), '
                    f'not {multicast_ttl!r}')
            c_multicast_ttl = multicast_ttl
            if not line_sender_opts_multicast_ttl(
                    self._opts, c_multicast_ttl, &err):
                raise c_err_to_py(err)

        if qwp_ws_progress is not None:
            c_qwp_ws_progress = QwpWsProgress.parse(qwp_ws_progress).c_value
            if not line_sender_opts_qwpws_progress(
                    self._opts, c_qwp_ws_progress, &err):
                raise c_err_to_py(err)

        if qwp_ws_error_handler is not None and not callable(qwp_ws_error_handler):
            raise TypeError(
                '"qwp_ws_error_handler" must be callable or None, '
                f'not {_fqn(type(qwp_ws_error_handler))}')
        if qwp_ws_error_handler is not None and not _is_qwp_ws_protocol(self._c_protocol):
            raise IngressError(
                IngressErrorCode.InvalidApiCall,
                'qwp_ws_error_handler is only supported for QWP/WebSocket senders.')
        if _is_qwp_ws_protocol(self._c_protocol):
            if qwp_ws_error_handler is None:
                qwp_ws_error_handler = _default_qwp_ws_error_handler
            self._qwp_ws_error_handler = qwp_ws_error_handler
            if not line_sender_opts_qwpws_error_handler(
                    self._opts,
                    _qwp_ws_error_trampoline,
                    <void*>self._qwp_ws_error_handler,
                    &err):
                self._qwp_ws_error_handler = None
                raise c_err_to_py(err)

        if username is not None:
            str_to_utf8(b, <PyObject*>username, &c_username)
            if not line_sender_opts_username(self._opts, c_username, &err):
                raise c_err_to_py(err)

        if password is not None:
            str_to_utf8(b, <PyObject*>password, &c_password)
            if not line_sender_opts_password(self._opts, c_password, &err):
                raise c_err_to_py(err)

        if token is not None:
            str_to_utf8(b, <PyObject*>token, &c_token)
            if not line_sender_opts_token(self._opts, c_token, &err):
                raise c_err_to_py(err)

        if token_x is not None:
            str_to_utf8(b, <PyObject*>token_x, &c_token_x)
            if not line_sender_opts_token_x(self._opts, c_token_x, &err):
                raise c_err_to_py(err)

        if token_y is not None:
            str_to_utf8(b, <PyObject*>token_y, &c_token_y)
            if not line_sender_opts_token_y(self._opts, c_token_y, &err):
                raise c_err_to_py(err)

        if protocol_version is not None:
            if protocol_version == 'auto':
                pass
            elif (protocol_version == 1) or (protocol_version == '1'):
                if not line_sender_opts_protocol_version(
                        self._opts, line_sender_protocol_version_1, &err):
                    raise c_err_to_py(err)
            elif (protocol_version == 2) or (protocol_version == '2'):
                if not line_sender_opts_protocol_version(
                        self._opts, line_sender_protocol_version_2, &err):
                    raise c_err_to_py(err)
            elif (protocol_version == 3) or (protocol_version == '3'):
                if not line_sender_opts_protocol_version(
                        self._opts, line_sender_protocol_version_3, &err):
                    raise c_err_to_py(err)
            else:
                raise IngressError(
                    IngressErrorCode.ConfigError,
                    '"protocol_version" must be None, "auto", 1-3' +
                    f' not {protocol_version!r}')

        if auth_timeout is not None:
            if isinstance(auth_timeout, int):
                c_auth_timeout = auth_timeout
            elif isinstance(auth_timeout, cp_timedelta):
                c_auth_timeout = _timedelta_to_millis(auth_timeout)
            else:
                raise TypeError(
                    '"auth_timeout" must be an int or a timedelta, '
                    f'not {_fqn(type(auth_timeout))}')
            if not line_sender_opts_auth_timeout(self._opts, c_auth_timeout, &err):
                raise c_err_to_py(err)

        if tls_verify is not None:
            if (tls_verify is True) or (tls_verify == 'on'):
                c_tls_verify = True
            elif (tls_verify is False) or (tls_verify == 'unsafe_off'):
                c_tls_verify = False
            else:
                raise ValueError(
                    '"tls_verify" must be a bool, "on" or "unsafe_off", '
                    f'not {tls_verify!r}')
            if not line_sender_opts_tls_verify(self._opts, c_tls_verify, &err):
                raise c_err_to_py(err)

        if tls_roots is not None:
            tls_roots = str(tls_roots)
            str_to_utf8(b, <PyObject*>tls_roots, &c_tls_roots)
            if not line_sender_opts_tls_roots(self._opts, c_tls_roots, &err):
                raise c_err_to_py(err)

        if tls_roots_password is not None:
            str_to_utf8(b, <PyObject*>tls_roots_password, &c_tls_roots_password)
            if not line_sender_opts_tls_roots_password(
                    self._opts, c_tls_roots_password, &err):
                raise c_err_to_py(err)

        if tls_ca is not None:
            c_tls_ca = TlsCa.parse(tls_ca).c_value
            if not line_sender_opts_tls_ca(self._opts, c_tls_ca, &err):
                raise c_err_to_py(err)
        elif protocol.tls_enabled and tls_roots is None:
            # Set different default for Python than the the Rust default.
            # We don't set it if `tls_roots` is set, as it would override it.
            c_tls_ca = line_sender_ca_webpki_and_os_roots
            if not line_sender_opts_tls_ca(self._opts, c_tls_ca, &err):
                raise c_err_to_py(err)

        if max_buf_size is not None:
            c_max_buf_size = max_buf_size
            if not line_sender_opts_max_buf_size(self._opts, c_max_buf_size, &err):
                raise c_err_to_py(err)

        if retry_timeout is not None:
            if isinstance(retry_timeout, int):
                c_retry_timeout = retry_timeout
                if not line_sender_opts_retry_timeout(self._opts, c_retry_timeout, &err):
                    raise c_err_to_py(err)
            elif isinstance(retry_timeout, cp_timedelta):
                c_retry_timeout = _timedelta_to_millis(retry_timeout)
                if not line_sender_opts_retry_timeout(self._opts, c_retry_timeout, &err):
                    raise c_err_to_py(err)
            else:
                raise TypeError(
                    '"retry_timeout" must be an int or a timedelta, '
                    f'not {_fqn(type(retry_timeout))}')

        if retry_max_backoff is not None:
            if isinstance(retry_max_backoff, int):
                c_retry_max_backoff = retry_max_backoff
                if not line_sender_opts_retry_max_backoff(
                        self._opts, c_retry_max_backoff, &err):
                    raise c_err_to_py(err)
            elif isinstance(retry_max_backoff, cp_timedelta):
                c_retry_max_backoff = _timedelta_to_millis(retry_max_backoff)
                if not line_sender_opts_retry_max_backoff(
                        self._opts, c_retry_max_backoff, &err):
                    raise c_err_to_py(err)
            else:
                raise TypeError(
                    '"retry_max_backoff" must be an int or a timedelta, '
                    f'not {_fqn(type(retry_max_backoff))}')

        if request_min_throughput is not None:
            c_request_min_throughput = request_min_throughput
            if not line_sender_opts_request_min_throughput(self._opts, c_request_min_throughput, &err):
                raise c_err_to_py(err)

        if max_name_len is not None:
            c_max_name_len = max_name_len
            if not line_sender_opts_max_name_len(self._opts, c_max_name_len, &err):
                raise c_err_to_py(err)

        if request_timeout is not None:
            if isinstance(request_timeout, int):
                c_request_timeout = request_timeout
                if not line_sender_opts_request_timeout(self._opts, c_request_timeout, &err):
                    raise c_err_to_py(err)
            elif isinstance(request_timeout, cp_timedelta):
                c_request_timeout = _timedelta_to_millis(request_timeout)
                if not line_sender_opts_request_timeout(self._opts, c_request_timeout, &err):
                    raise c_err_to_py(err)
            else:
                raise TypeError(
                    '"request_timeout" must be an int or a timedelta, '
                    f'not {_fqn(type(request_timeout))}')

        _parse_auto_flush(
            self._c_protocol,
            auto_flush,
            auto_flush_rows,
            auto_flush_bytes,
            auto_flush_interval,
            &self._auto_flush_mode,
            c_max_datagram_size)

        self._init_buf_size = init_buf_size or 65536
        self._last_flush_ms = <int64_t*>calloc(1, sizeof(int64_t))

    def __cinit__(self):
        self._c_protocol = line_sender_protocol_tcp
        self._opts = NULL
        self._impl = NULL
        self._buffer = None
        self._qwp_ws_error_handler = None
        self._auto_flush_mode.enabled = False
        self._last_flush_ms = NULL
        self._init_buf_size = 0
        self._in_txn = False
        self._slot_id = -1

    def __init__(
            self,
            object protocol,
            str host,
            object port,
            *,
            str bind_interface=None,
            str username=None,
            str password=None,
            str token=None,
            str token_x=None,
            str token_y=None,
            object auth_timeout=None,  # default: 15000 milliseconds
            object tls_verify=None,  # default: True
            object tls_ca=None,  # default: TlsCa.WebpkiRoots
            object tls_roots=None,
            str tls_roots_password=None,
            object max_buf_size=None,  # 100 * 1024 * 1024 - 100MiB
            object retry_timeout=None,  # default: 10000 milliseconds
            object retry_max_backoff=None,  # default: 1000 milliseconds
            object request_min_throughput=None, # default: 100 * 1024 - 100KiB/s
            object request_timeout=None,
            object auto_flush=None,  # Default True
            object auto_flush_rows=None,  # Default 75000 (HTTP) or 600 (TCP)
            object auto_flush_bytes=None,  # Default off
            object auto_flush_interval=None,  # Default 1000 milliseconds
            object max_datagram_size=None,  # Default 1400 for QWP/UDP
            object multicast_ttl=None,  # Default 1 for QWP/UDP
            object qwp_ws_progress=None,  # Default background for QWP/WebSocket
            object qwp_ws_error_handler=None,
            object protocol_version=None,  # Default auto
            object init_buf_size=None,  # 64KiB
            object max_name_len=None):  # 127

        cdef line_sender_utf8 c_host
        cdef str port_str
        cdef line_sender_protocol c_protocol
        cdef line_sender_utf8 c_port
        cdef qdb_pystr_buf* b = qdb_pystr_buf_new()
        try:
            protocol = Protocol.parse(protocol)
            c_protocol = protocol.c_value
            if PyLong_CheckExact(<PyObject*>port):
                port_str = str(port)
            elif PyUnicode_CheckExact(<PyObject*>port):
                port_str = port
            else:
                raise TypeError(
                    f'port must be an int or a str, not {_fqn(type(port))}')
            str_to_utf8(b, <PyObject*>host, &c_host)
            str_to_utf8(b, <PyObject*>port_str, &c_port)
            self._opts = line_sender_opts_new_service(c_protocol, c_host, c_port)

            self._set_sender_fields(
                b,
                protocol,
                bind_interface,
                username,
                password,
                token,
                token_x,
                token_y,
                auth_timeout,
                tls_verify,
                tls_ca,
                tls_roots,
                tls_roots_password,
                max_buf_size,
                retry_timeout,
                retry_max_backoff,
                request_min_throughput,
                request_timeout,
                auto_flush,
                auto_flush_rows,
                auto_flush_bytes,
                auto_flush_interval,
                max_datagram_size,
                multicast_ttl,
                protocol_version,
                qwp_ws_progress,
                qwp_ws_error_handler,
                init_buf_size,
                max_name_len)
        finally:
            qdb_pystr_buf_free(b)

    @staticmethod
    def from_conf(
            str conf_str,
            *,
            str bind_interface=None,
            str username=None,
            str password=None,
            str token=None,
            str token_x=None,
            str token_y=None,
            object auth_timeout=None,  # default: 15000 milliseconds
            object tls_verify=None,  # default: True
            object tls_ca=None,  # default: TlsCa.WebpkiRoots
            object tls_roots=None,
            str tls_roots_password=None,
            object max_buf_size=None,  # 100 * 1024 * 1024 - 100MiB
            object retry_timeout=None,  # default: 10000 milliseconds
            object retry_max_backoff=None,  # default: 1000 milliseconds
            object request_min_throughput=None, # default: 100 * 1024 - 100KiB/s
            object request_timeout=None,
            object auto_flush=None,  # Default True
            object auto_flush_rows=None,  # Default 75000 (HTTP) or 600 (TCP)
            object auto_flush_bytes=None,  # Default off
            object auto_flush_interval=None,  # Default 1000 milliseconds
            object max_datagram_size=None,  # Default 1400 for QWP/UDP
            object multicast_ttl=None,  # Default 1 for QWP/UDP
            object qwp_ws_progress=None,  # Default background for QWP/WebSocket
            object qwp_ws_error_handler=None,
            object protocol_version=None,  # Default auto
            object init_buf_size=None,  # 64KiB
            object max_name_len=None):  # 127
        """
        Construct a sender from a :ref:`configuration string <sender_conf>`.

        The additional arguments are used to specify additional parameters
        which are not present in the configuration string.

        Note that any parameters already present in the configuration string
        cannot be overridden.
        """

        cdef line_sender_error* err = NULL
        cdef object protocol
        cdef Sender sender
        cdef str synthetic_conf_str
        cdef line_sender_utf8 c_synthetic_conf_str
        cdef dict params
        cdef qdb_pystr_buf* b = qdb_pystr_buf_new()
        try:
            protocol, params = parse_conf_str(b, conf_str)

            addr = params.get('addr')
            if addr is None:
                raise IngressError(
                    IngressErrorCode.ConfigError,
                    'Missing "addr" parameter in config string')
            
            # add fields to the dictionary, so long as they aren't already
            # present in the params dictionary
            for override_key, override_value in {
                'bind_interface': bind_interface,
                'username': username,
                'password': password,
                'token': token,
                'token_x': token_x,
                'token_y': token_y,
                'auth_timeout': auth_timeout,
                'tls_verify': tls_verify,
                'tls_ca': tls_ca,
                'tls_roots': tls_roots,
                'tls_roots_password': tls_roots_password,
                'max_buf_size': max_buf_size,
                'retry_timeout': retry_timeout,
                'retry_max_backoff_millis': retry_max_backoff,
                'request_min_throughput': request_min_throughput,
                'request_timeout': request_timeout,
                'auto_flush': auto_flush,
                'auto_flush_rows': auto_flush_rows,
                'auto_flush_bytes': auto_flush_bytes,
                'auto_flush_interval': auto_flush_interval,
                'max_datagram_size': max_datagram_size,
                'multicast_ttl': multicast_ttl,
                'qwp_ws_progress': qwp_ws_progress,
                'protocol_version': protocol_version,
                'init_buf_size': init_buf_size,
                'max_name_len': max_name_len,
            }.items():
                if override_value is None:
                    continue
                if override_key in params:
                    raise ValueError(
                        f'"{override_key}" is already present in the conf_str '
                        'and cannot be overridden.')
                params[override_key] = override_value

            sender = Sender.__new__(Sender)

            python_handled_keys = {
                'addr',
                'bind_interface',
                'username',
                'password',
                'token',
                'token_x',
                'token_y',
                'auth_timeout',
                'tls_verify',
                'tls_ca',
                'tls_roots',
                'tls_roots_password',
                'max_buf_size',
                'retry_timeout',
                'retry_max_backoff_millis',
                'request_min_throughput',
                'request_timeout',
                'auto_flush',
                'auto_flush_rows',
                'auto_flush_bytes',
                'auto_flush_interval',
                'max_datagram_size',
                'multicast_ttl',
                'qwp_ws_progress',
                'protocol_version',
                'init_buf_size',
                'max_name_len',
            }
            synthetic_params = {'addr': addr}
            if protocol in (Protocol.QwpWs, Protocol.QwpWss):
                for key, value in params.items():
                    if key not in python_handled_keys:
                        synthetic_params[key] = value
            synthetic_conf_str = protocol.tag + '::' + ''.join(
                f'{key}={conf_str_value(value)};'
                for key, value in synthetic_params.items())
            str_to_utf8(b, <PyObject*>synthetic_conf_str, &c_synthetic_conf_str)
            sender._opts = line_sender_opts_from_conf(
                c_synthetic_conf_str, &err)
            if sender._opts == NULL:
                raise c_err_to_py(err)

            sender._set_sender_fields(
                b,
                protocol,
                params.get('bind_interface'),
                params.get('username'),
                params.get('password'),
                params.get('token'),
                params.get('token_x'),
                params.get('token_y'),
                params.get('auth_timeout'),
                params.get('tls_verify'),
                params.get('tls_ca'),
                params.get('tls_roots'),
                params.get('tls_roots_password'),
                params.get('max_buf_size'),
                params.get('retry_timeout'),
                params.get('retry_max_backoff_millis'),
                params.get('request_min_throughput'),
                params.get('request_timeout'),
                params.get('auto_flush'),
                params.get('auto_flush_rows'),
                params.get('auto_flush_bytes'),
                params.get('auto_flush_interval'),
                params.get('max_datagram_size'),
                params.get('multicast_ttl'),
                params.get('protocol_version'),
                params.get('qwp_ws_progress'),
                qwp_ws_error_handler,
                params.get('init_buf_size'),
                params.get('max_name_len'))
            
            return sender
        finally:
            qdb_pystr_buf_free(b)

    @staticmethod
    def from_env(
            *,
            str bind_interface=None,
            str username=None,
            str password=None,
            str token=None,
            str token_x=None,
            str token_y=None,
            object auth_timeout=None,  # default: 15000 milliseconds
            object tls_verify=None,  # default: True
            object tls_ca=None,  # default: TlsCa.WebpkiRoots
            object tls_roots=None,
            str tls_roots_password=None,
            object max_buf_size=None,  # 100 * 1024 * 1024 - 100MiB
            object retry_timeout=None,  # default: 10000 milliseconds
            object retry_max_backoff=None,  # default: 1000 milliseconds
            object request_min_throughput=None, # default: 100 * 1024 - 100KiB/s
            object request_timeout=None,
            object auto_flush=None,  # Default True
            object auto_flush_rows=None,  # Default 75000 (HTTP) or 600 (TCP)
            object auto_flush_bytes=None,  # Default off
            object auto_flush_interval=None,  # Default 1000 milliseconds
            object max_datagram_size=None,  # Default 1400 for QWP/UDP
            object multicast_ttl=None,  # Default 1 for QWP/UDP
            object qwp_ws_progress=None,  # Default background for QWP/WebSocket
            object qwp_ws_error_handler=None,
            object protocol_version=None,  # Default auto
            object init_buf_size=None,  # 64KiB
            object max_name_len=None):  # 127
        """
        Construct a sender from the ``QDB_CLIENT_CONF`` environment variable.

        The environment variable must be set to a valid
        :ref:`configuration string <sender_conf>`.

        The additional arguments are used to specify additional parameters
        which are not present in the configuration string.

        Note that any parameters already present in the configuration string
        cannot be overridden.
        """
        cdef str conf_str = os.environ.get('QDB_CLIENT_CONF')
        if conf_str is None:
            raise IngressError(
                IngressErrorCode.ConfigError,
                'Environment variable QDB_CLIENT_CONF is not set.')
        return Sender.from_conf(
            conf_str,
            bind_interface=bind_interface,
            username=username,
            password=password,
            token=token,
            token_x=token_x,
            token_y=token_y,
            auth_timeout=auth_timeout,
            tls_verify=tls_verify,
            tls_ca=tls_ca,
            tls_roots=tls_roots,
            tls_roots_password=tls_roots_password,
            max_buf_size=max_buf_size,
            retry_timeout=retry_timeout,
            retry_max_backoff=retry_max_backoff,
            request_min_throughput=request_min_throughput,
            request_timeout=request_timeout,
            auto_flush=auto_flush,
            auto_flush_rows=auto_flush_rows,
            auto_flush_bytes=auto_flush_bytes,
            auto_flush_interval=auto_flush_interval,
            max_datagram_size=max_datagram_size,
            multicast_ttl=multicast_ttl,
            qwp_ws_progress=qwp_ws_progress,
            qwp_ws_error_handler=qwp_ws_error_handler,
            protocol_version=protocol_version,
            init_buf_size=init_buf_size,
            max_name_len=max_name_len)


    cdef inline object _new_buffer_for_sender(self):
        cdef Buffer buf = Buffer.__new__(Buffer)
        buf._impl = line_sender_buffer_new_for_sender(self._impl)
        buf._b = qdb_pystr_buf_new()
        reserve_buffer(buf._impl, self._init_buf_size)
        buf._init_buf_size = self._init_buf_size
        buf._max_name_len = line_sender_get_max_name_len(self._impl)
        return buf

    def new_buffer(self):
        """
        Make a new configured buffer.

        The buffer is set up with the configured `init_buf_size` and
        `max_name_len`.
        """
        if self._impl == NULL:
            if self._opts == NULL:
                raise IngressError(
                    IngressErrorCode.InvalidApiCall,
                    'new_buffer() can\'t be called: Sender is closed.')
            raise IngressError(
                IngressErrorCode.InvalidApiCall,
                'new_buffer() can\'t be called before establish().')
        return self._new_buffer_for_sender()

    @property
    def init_buf_size(self) -> int:
        """The initial capacity of the sender's internal buffer."""
        return self._init_buf_size

    @property
    def max_name_len(self) -> int:
        """Maximum length of a table or column name."""
        if self._impl == NULL:
            raise IngressError(
                IngressErrorCode.InvalidApiCall,
                'max_name_len() can\'t be called: Sender is closed.')
        return line_sender_get_max_name_len(self._impl)

    @property
    def auto_flush(self) -> bint:
        """
        Auto-flushing is enabled.
        
        Consult the `.auto_flush_rows`, `.auto_flush_bytes` and
        `.auto_flush_interval` properties for the current active thresholds.
        """
        return self._auto_flush_mode.enabled

    @property
    def auto_flush_rows(self) -> Optional[int]:
        """
        Row count threshold for the auto-flush logic, or None if disabled.
        """
        if not self._auto_flush_mode.enabled:
            return None
        if self._auto_flush_mode.row_count == -1:
            return None
        return self._auto_flush_mode.row_count

    @property
    def auto_flush_bytes(self) -> Optional[int]:
        """
        Byte-count threshold for the auto-flush logic, or None if disabled.
        """
        if not self._auto_flush_mode.enabled:
            return None
        if self._auto_flush_mode.byte_count == -1:
            return None
        return self._auto_flush_mode.byte_count
    
    @property
    def auto_flush_interval(self) -> Optional[datetime.timedelta]:
        """
        Time interval threshold for the auto-flush logic, or None if disabled.
        """
        if not self._auto_flush_mode.enabled:
            return None
        if self._auto_flush_mode.interval == -1:
            return None
        return cp_timedelta(milliseconds=self._auto_flush_mode.interval)

    @property
    def protocol_version(self) -> int:
        """
        The protocol version used by the sender.

        Protocol version 1 is retained for backwards compatibility with
        older QuestDB versions.

        Protocol version 2 introduces binary floating point support and
        the array datatype.
        """
        if self._impl == NULL:
            raise IngressError(
                IngressErrorCode.InvalidApiCall,
                'protocol_version() can\'t be called: Sender is closed.')
        if _is_qwp_udp_protocol(self._c_protocol):
            raise IngressError(
                IngressErrorCode.InvalidApiCall,
                'protocol_version is not applicable for QWP/UDP senders.')
        return <int>line_sender_get_protocol_version(self._impl)

    def establish(self):
        """
        Prepare the sender for use.

        If using ILP/HTTP this will initialize the HTTP connection pool.

        If using ILP/TCP this will cause connection to the server and 
        block until the connection is established.

        If the TCP connection is set up with authentication and/or TLS, this
        method will return only *after* the handshake(s) is/are complete.
        """
        cdef line_sender_error* err = NULL
        cdef PyThreadState * gs = NULL
        if self._opts == NULL:
            raise IngressError(
                IngressErrorCode.InvalidApiCall,
                'establish() can\'t be called after close().')

        # We disable the GIL when calling `line_sender_build` since for HTTP
        # it can make HTTP requests to auto-detect the protocol version.
        _ensure_doesnt_have_gil(&gs)
        self._impl = line_sender_build(self._opts, &err)
        _ensure_has_gil(&gs)

        if self._impl == NULL:
            raise c_err_to_py(err)

        if self._buffer is None:
            self._buffer = self._new_buffer_for_sender()

        line_sender_opts_free(self._opts)
        self._opts = NULL

        # Request callbacks when rows are complete.
        self._buffer._row_complete_sender = PyWeakref_NewRef(self, None)
        self._last_flush_ms[0] = line_sender_now_micros() // 1000

        # Track and warn about overly quick reconnections to the server.
        cdef bint warn = False
        if WARN_HIGH_RECONNECTS:
            self._slot_id = <int32_t> qdb_active_senders_track_established(&warn)
            if warn:
                warnings.warn(
                    "questdb.ingress.Sender: "
                    f"Detected a burst of reconnections. "
                    "This may indicate an inefficient coding pattern where the sender is "
                    "frequently created and destroyed. "
                    "Consider reusing sender instance whenever possible."
                    "See: https://py-questdb-client.readthedocs.io/en/latest/sender.html#reuse-sender-objects",
                    UserWarning,
                    stacklevel=1
                )

    def __enter__(self) -> Sender:
        """Call :func:`Sender.establish` at the start of a ``with`` block."""
        self.establish()
        return self

    def __bytes__(self) -> bytes:
        """
        Inspect the contents of the internal buffer.

        The ``bytes`` value returned represents the unsent data.

        For QWP/UDP senders this always returns ``b''`` because encoding
        is deferred to flush. Use :func:`Sender.__len__` instead for a
        size estimate.

        Also see :func:`Sender.__len__`.
        """
        if self._buffer is None:
            return b''
        else:
            return bytes(self._buffer)

    def __len__(self) -> int:
        """
        Number of bytes of unsent data in the internal buffer.

        Equivalent (but cheaper) to ``len(bytes(sender))``.

        For QWP/UDP senders this returns an estimated size hint, not the
        exact serialized byte count.
        """
        if self._buffer is None:
            return 0
        else:
            return len(self._buffer)

    def transaction(self, table_name: str):
        """
        Start a :ref:`sender_transaction` block.
        """
        return SenderTransaction(self, table_name)

    def row(self,
            table_name: str,
            *,
            symbols: Optional[Dict[str, str]]=None,
            columns: Optional[Dict[
                str,
                Union[None, bool, int, float, str, TimestampMicros, datetime.datetime, numpy.ndarray]]]=None,
            at: Union[TimestampNanos, datetime.datetime, ServerTimestampType]):
        """
        Write a row to the internal buffer.

        This may be sent automatically depending on the ``auto_flush`` setting
        in the constructor.

        Refer to the :func:`Buffer.row` documentation for details on arguments.

        **Note**: Support for NumPy arrays (``numpy.array``) requires QuestDB server version 9.0.0 or higher.
        """
        if self._in_txn:
            raise IngressError(
                IngressErrorCode.InvalidApiCall,
                'Cannot append rows explicitly inside a transaction')
        if at is None:
            raise IngressError(
                IngressErrorCode.InvalidTimestamp,
                "`at` must be of type TimestampNanos, datetime, or ServerTimestamp"
            )
        if self._buffer is None:
            raise IngressError(
                IngressErrorCode.InvalidApiCall,
                "row() can\'t be called: Sender is closed."
            )

        self._buffer.row(table_name, symbols=symbols, columns=columns, at=at)
        return self

    def dataframe(
            self,
            df,  # : pd.DataFrame
            *,
            table_name: Optional[str] = None,
            table_name_col: Union[None, int, str] = None,
            symbols: Union[str, bool, List[int], List[str]] = 'auto',
            at: Union[ServerTimestampType, int, str, TimestampNanos, datetime.datetime]):
        """
        Write a Pandas DataFrame to the internal buffer.

        Example:

        .. code-block:: python

            import pandas as pd
            import questdb.ingress as qi

            df = pd.DataFrame({
                'car': pd.Categorical(['Nic 42', 'Eddi', 'Nic 42', 'Eddi']),
                'position': [1, 2, 1, 2],
                'speed': [89.3, 98.2, 3, 4],
                'lat_gforce': [0.1, -0.2, -0.6, 0.4],
                'accelleration': [0.1, -0.2, 0.6, 4.4],
                'tyre_pressure': [2.6, 2.5, 2.6, 2.5],
                'ts': [
                    pd.Timestamp('2022-08-09 13:56:00'),
                    pd.Timestamp('2022-08-09 13:56:01'),
                    pd.Timestamp('2022-08-09 13:56:02'),
                    pd.Timestamp('2022-08-09 13:56:03')]})

            with qi.Sender.from_env() as sender:
                sender.dataframe(df, table_name='race_metrics', at='ts')

        This method builds on top of the :func:`Buffer.dataframe` method.
        See its documentation for details on arguments.

        Additionally, this method also supports auto-flushing the buffer
        as specified in the ``Sender``'s ``auto_flush`` constructor argument.
        Auto-flushing is implemented incrementally, meanting that when
        calling ``sender.dataframe(df)`` with a large ``df``, the sender may
        have sent some of the rows to the server already whist the rest of the
        rows are going to be sent at the next auto-flush or next explicit call
        to :func:`Sender.flush`.

        In case of data errors with auto-flushing enabled, some of the rows
        may have been transmitted to the server already.
        """
        cdef auto_flush_t af = auto_flush_blank()
        if self._in_txn:
            raise IngressError(
                IngressErrorCode.InvalidApiCall,
                'Cannot append rows explicitly inside a transaction')
        if at is None:
            raise IngressError(
                IngressErrorCode.InvalidTimestamp,
                "`at` must be of type TimestampNanos, datetime, or ServerTimestamp"
            )
        if self._auto_flush_mode.enabled:
            af.sender = self._impl
            af.mode = self._auto_flush_mode
            af.last_flush_ms = self._last_flush_ms

        if self._buffer is None:
            raise IngressError(
                IngressErrorCode.InvalidApiCall,
                "dataframe() can\'t be called: Sender is closed."
            )
        _dataframe(
            af,
            self._buffer._impl,
            self._buffer._b,
            df,
            table_name,
            table_name_col,
            symbols,
            at)
        return self

    cpdef flush(
            self,
            Buffer buffer=None,
            bint clear=True,
            bint transactional=False):
        """
        If called with no arguments, immediately flushes the internal buffer.

        Alternatively you can flush a buffer that was constructed explicitly
        by passing ``buffer``.

        The buffer will be cleared by default, unless ``clear`` is set to
        ``False``.

        This method does nothing if the provided or internal buffer is empty.

        :param buffer: The buffer to flush. If ``None``, the internal buffer
            is flushed.

        With QWP/WebSocket, this publishes the buffer into the local sender
        queue and returns before the server necessarily ACKs the frame. Later
        terminal diagnostics fail subsequent sender calls and are available as
        :attr:`IngressError.qwp_ws_error`. Server diagnostics are also
        available through :func:`Sender.poll_qwp_ws_error`.

        :param clear: If ``True``, the flushed buffer is cleared (default).
            If ``False``, the flushed buffer is left in the internal buffer.
            Note that ``clear=False`` is only supported if ``buffer`` is also
            specified.

        :param transactional: If ``True`` ensures that the flushed buffer
            contains row for a single table, ensuring all data can be written
            transactionally. This feature requires ILP/HTTP and is not available
            when connecting over TCP. *Default: False.*

        The Python GIL is released during the network IO operation.
        """
        cdef line_sender* sender = self._impl
        cdef line_sender_error* err = NULL
        cdef line_sender_buffer* c_buf = NULL
        cdef PyThreadState* gs = NULL  # GIL state. NULL means we have the GIL.
        cdef bint ok = False

        if self._in_txn:
            raise IngressError(
                IngressErrorCode.InvalidApiCall,
                'Cannot flush explicitly inside a transaction')

        if buffer is None and not clear:
            raise ValueError('The internal buffer must always be cleared.')

        if sender == NULL:
            raise IngressError(
                IngressErrorCode.InvalidApiCall,
                'flush() can\'t be called: Sender is closed.')
        if buffer is not None:
            buffer._check_impl()
            c_buf = buffer._impl
        else:
            c_buf = self._buffer._impl
        if line_sender_buffer_size(c_buf) == 0 and not _is_qwp_ws_protocol(self._c_protocol):
            return

        # We might be blocking on IO, so temporarily release the GIL.
        _ensure_doesnt_have_gil(&gs)
        if transactional:
            ok = line_sender_flush_and_keep_with_flags(
                    sender,
                    c_buf,
                    transactional,
                    &err)
            if ok and clear:
                line_sender_buffer_clear(c_buf)
        elif clear:
            ok = line_sender_flush(sender, c_buf, &err)
        else:
            ok = line_sender_flush_and_keep(sender, c_buf, &err)
        if ok and c_buf == self._buffer._impl:
            self._last_flush_ms[0] = line_sender_now_micros() // 1000
        _ensure_has_gil(&gs)
        if not ok:
            if c_buf == self._buffer._impl:
                # Prevent a follow-up call to `.close(flush=True)` (as is
                # usually called from `__exit__`) to raise after the sender
                # entered an error state following a failed call to `.flush()`.
                # Note: In this case `clear` is always `True`.
                line_sender_buffer_clear(c_buf)
            if _is_tcp_protocol(self._c_protocol):
                # Provide further context pointing to the logs.
                raise c_err_to_py_fmt(err, _FLUSH_FMT)
            else:
                raise c_err_to_py(err)

    def flush_and_get_fsn(self, Buffer buffer=None):
        """
        Publish a QWP/WebSocket buffer locally, clear it on success, and return
        the assigned frame sequence number.
        """
        cdef line_sender* sender = self._impl
        cdef line_sender_error* err = NULL
        cdef line_sender_buffer* c_buf = NULL
        cdef line_sender_qwpws_fsn fsn
        cdef PyThreadState* gs = NULL
        cdef bint ok = False

        if self._in_txn:
            raise IngressError(
                IngressErrorCode.InvalidApiCall,
                'Cannot flush explicitly inside a transaction')
        if sender == NULL:
            raise IngressError(
                IngressErrorCode.InvalidApiCall,
                'flush_and_get_fsn() can\'t be called: Sender is closed.')
        if buffer is not None:
            buffer._check_impl()
            c_buf = buffer._impl
        else:
            c_buf = self._buffer._impl

        _ensure_doesnt_have_gil(&gs)
        ok = line_sender_qwpws_flush_and_get_fsn(sender, c_buf, &fsn, &err)
        _ensure_has_gil(&gs)
        if not ok:
            raise c_err_to_py(err)
        if c_buf == self._buffer._impl:
            self._last_flush_ms[0] = line_sender_now_micros() // 1000
        if fsn.has_value:
            return fsn.value
        return None

    def flush_and_keep_and_get_fsn(self, Buffer buffer=None):
        """
        Publish a QWP/WebSocket buffer locally without clearing it and return
        the assigned frame sequence number.
        """
        cdef line_sender* sender = self._impl
        cdef line_sender_error* err = NULL
        cdef line_sender_buffer* c_buf = NULL
        cdef line_sender_qwpws_fsn fsn
        cdef PyThreadState* gs = NULL
        cdef bint ok = False

        if self._in_txn:
            raise IngressError(
                IngressErrorCode.InvalidApiCall,
                'Cannot flush explicitly inside a transaction')
        if sender == NULL:
            raise IngressError(
                IngressErrorCode.InvalidApiCall,
                'flush_and_keep_and_get_fsn() can\'t be called: Sender is closed.')
        if buffer is not None:
            buffer._check_impl()
            c_buf = buffer._impl
        else:
            c_buf = self._buffer._impl

        _ensure_doesnt_have_gil(&gs)
        ok = line_sender_qwpws_flush_and_keep_and_get_fsn(
            sender, c_buf, &fsn, &err)
        _ensure_has_gil(&gs)
        if not ok:
            raise c_err_to_py(err)
        if c_buf == self._buffer._impl:
            self._last_flush_ms[0] = line_sender_now_micros() // 1000
        if fsn.has_value:
            return fsn.value
        return None

    def published_fsn(self):
        """
        Highest QWP/WebSocket frame sequence number published locally.
        """
        cdef line_sender_qwpws_fsn fsn
        cdef line_sender_error* err = NULL

        if self._impl == NULL:
            raise IngressError(
                IngressErrorCode.InvalidApiCall,
                'published_fsn() can\'t be called: Sender is closed.')
        if not line_sender_qwpws_published_fsn(self._impl, &fsn, &err):
            raise c_err_to_py(err)
        if fsn.has_value:
            return fsn.value
        return None

    def acked_fsn(self):
        """
        Highest QWP/WebSocket frame sequence number completed by ACK or
        drop-and-continue rejection.
        """
        cdef line_sender_qwpws_fsn fsn
        cdef line_sender_error* err = NULL

        if self._impl == NULL:
            raise IngressError(
                IngressErrorCode.InvalidApiCall,
                'acked_fsn() can\'t be called: Sender is closed.')
        if not line_sender_qwpws_acked_fsn(self._impl, &fsn, &err):
            raise c_err_to_py(err)
        if fsn.has_value:
            return fsn.value
        return None

    def await_acked_fsn(self, fsn, timeout_millis):
        """
        Wait until the QWP/WebSocket completion watermark reaches ``fsn``.
        """
        cdef line_sender_error* err = NULL
        cdef PyThreadState* gs = NULL
        cdef uint64_t c_fsn
        cdef uint64_t c_timeout_millis
        cdef cbool reached = False
        cdef bint ok = False

        if self._impl == NULL:
            raise IngressError(
                IngressErrorCode.InvalidApiCall,
                'await_acked_fsn() can\'t be called: Sender is closed.')
        if not isinstance(fsn, int) or isinstance(fsn, bool):
            raise TypeError('"fsn" must be a non-negative int.')
        if fsn < 0:
            raise ValueError('"fsn" must be a non-negative int.')
        if not isinstance(timeout_millis, int) or isinstance(timeout_millis, bool):
            raise TypeError('"timeout_millis" must be a non-negative int.')
        if timeout_millis < 0:
            raise ValueError('"timeout_millis" must be a non-negative int.')
        c_fsn = fsn
        c_timeout_millis = timeout_millis

        _ensure_doesnt_have_gil(&gs)
        ok = line_sender_qwpws_await_acked_fsn(
            self._impl, c_fsn, c_timeout_millis, &reached, &err)
        _ensure_has_gil(&gs)
        if not ok:
            raise c_err_to_py(err)
        return bool(reached)

    def drive_once(self):
        """
        Drive one QWP/WebSocket progress step for manual progress senders.
        """
        cdef line_sender_error* err = NULL
        cdef PyThreadState* gs = NULL
        cdef cbool progressed = False
        cdef bint ok = False

        if self._impl == NULL:
            raise IngressError(
                IngressErrorCode.InvalidApiCall,
                'drive_once() can\'t be called: Sender is closed.')
        _ensure_doesnt_have_gil(&gs)
        ok = line_sender_qwpws_drive_once(self._impl, &progressed, &err)
        _ensure_has_gil(&gs)
        if not ok:
            raise c_err_to_py(err)
        return bool(progressed)

    def poll_qwp_ws_error(self):
        """
        Poll the next structured QWP/WebSocket diagnostic.
        """
        cdef line_sender_error* err = NULL
        cdef line_sender_qwpws_error* qwp_err = NULL
        cdef line_sender_qwpws_error_view view

        if self._impl == NULL:
            raise IngressError(
                IngressErrorCode.InvalidApiCall,
                'poll_qwp_ws_error() can\'t be called: Sender is closed.')
        if not line_sender_qwpws_poll_error(self._impl, &qwp_err, &err):
            raise c_err_to_py(err)
        if qwp_err == NULL:
            return None
        try:
            view = line_sender_qwpws_error_get_view(qwp_err)
            return _qwp_ws_error_from_raw(c_qwp_ws_error_view_to_raw(view))
        finally:
            line_sender_qwpws_error_free(qwp_err)

    def qwp_ws_errors_dropped(self):
        """
        Number of QWP/WebSocket diagnostics dropped from the bounded ring.
        """
        cdef line_sender_error* err = NULL
        cdef uint64_t dropped = 0

        if self._impl == NULL:
            raise IngressError(
                IngressErrorCode.InvalidApiCall,
                'qwp_ws_errors_dropped() can\'t be called: Sender is closed.')
        if not line_sender_qwpws_errors_dropped(self._impl, &dropped, &err):
            raise c_err_to_py(err)
        return dropped

    def close_drain(self):
        """
        Stop accepting new QWP/WebSocket publications and wait for already
        published frames to resolve.
        """
        cdef line_sender_error* err = NULL
        cdef PyThreadState* gs = NULL
        cdef bint ok = False

        if self._impl == NULL:
            raise IngressError(
                IngressErrorCode.InvalidApiCall,
                'close_drain() can\'t be called: Sender is closed.')
        _ensure_doesnt_have_gil(&gs)
        ok = line_sender_qwpws_close_drain(self._impl, &err)
        _ensure_has_gil(&gs)
        if not ok:
            raise c_err_to_py(err)

    cdef _close(self):
        self._buffer = None
        line_sender_opts_free(self._opts)
        self._opts = NULL
        line_sender_close(self._impl)
        self._impl = NULL
        self._qwp_ws_error_handler = None
        if self._slot_id != -1:
            qdb_active_senders_track_closed(<uint32_t>self._slot_id)
            self._slot_id = -1

    cpdef close(self, bint flush=True):
        """
        Disconnect.

        This method is idempotent and can be called repeatedly.

        Once a sender is closed, it can't be re-used.

        :param bool flush: If ``True``, flush the internal buffer before closing.
            For QWP/WebSocket, this also drains already-published frames before
            closing.
        """
        try:
            if (flush and (self._impl != NULL) and
                    (not line_sender_must_close(self._impl))):
                self.flush(None, True)
                if _is_qwp_ws_protocol(self._c_protocol):
                    self.close_drain()
        finally:
            self._close()

    def __exit__(self, exc_type, _exc_val, _exc_tb):
        """
        Flush pending and disconnect at the end of a ``with`` block.

        If the ``with`` block raises an exception, any pending data will
        *NOT* be flushed.

        This is implemented by calling :func:`Sender.close`.
        """
        self.close(not exc_type)

    def __dealloc__(self):
        self._close()
        free(self._last_flush_ms)
