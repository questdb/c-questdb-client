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


"""

    WARNING: This is a lower-level API that's not intended for general use.

    If you're after Python bindings for QuestDB, see the official bindings:

        https://py-questdb.readthedocs.io/en/latest/

        https://github.com/questdb/py-questdb-client

        https://pypi.org/project/questdb/

"""

import sys

import numpy

sys.dont_write_bytecode = True

import pathlib
import ctypes
import os
from datetime import datetime
from functools import total_ordering
from enum import Enum
from decimal import Decimal

from ctypes import (
    c_bool,
    c_size_t,
    c_char_p,
    c_int,
    c_int64,
    c_double,
    c_uint8,
    c_uint16,
    c_uint32,
    c_uint64,
    c_void_p,
    c_ssize_t)

from typing import Optional, Union


class c_line_sender(ctypes.Structure):
    pass


class c_line_sender_buffer(ctypes.Structure):
    pass


c_line_sender_protocol = ctypes.c_int


class Protocol(Enum):
    TCP = (c_line_sender_protocol(0), 'tcp')
    TCPS = (c_line_sender_protocol(1), 'tcps')
    HTTP = (c_line_sender_protocol(2), 'http')
    HTTPS = (c_line_sender_protocol(3), 'https')
    QWPUDP = (c_line_sender_protocol(4), 'qwpudp')
    QWPWS = (c_line_sender_protocol(5), 'qwpws')
    QWPWSS = (c_line_sender_protocol(6), 'qwpwss')

    @classmethod
    def from_int(cls, value: c_line_sender_protocol):
        for member in cls:
            if member.value[0].value == value:
                return member
        raise ValueError(f"invalid protocol: {value}")


c_line_sender_ca = ctypes.c_int


class CertificateAuthority(Enum):
    WEBPKI_ROOTS = (c_line_sender_ca(0), 'webpki_roots')
    OS_ROOTS = (c_line_sender_ca(1), 'os_roots')
    WEBPKI_AND_OS_ROOTS = (c_line_sender_ca(2), 'webpki_and_os_roots')
    PEM_FILE = (c_line_sender_ca(3), 'pem_file')


c_protocol_version = ctypes.c_int


@total_ordering
class ProtocolVersion(Enum):
    V1 = (c_protocol_version(1), '1')
    V2 = (c_protocol_version(2), '2')
    V3 = (c_protocol_version(3), '3')

    @classmethod
    def from_int(cls, value: c_protocol_version):
        for member in cls:
            if member.value[0].value == value:
                return member
        raise ValueError(f"invalid protocol version: {value}")

    def __lt__(self, other):
        if not isinstance(other, ProtocolVersion):
            return NotImplemented
        return self.value[0].value < other.value[0].value

    def __eq__(self, other):
        if not isinstance(other, ProtocolVersion):
            return NotImplemented
        return self.value[0].value == other.value[0].value


class QwpWsErrorCategory(Enum):
    SCHEMA_MISMATCH = 0
    PARSE_ERROR = 1
    INTERNAL_ERROR = 2
    SECURITY_ERROR = 3
    WRITE_ERROR = 4
    PROTOCOL_VIOLATION = 5
    UNKNOWN = 6

    @classmethod
    def from_int(cls, value: int):
        for member in cls:
            if member.value == value:
                return member
        return cls.UNKNOWN


class QwpWsErrorPolicy(Enum):
    DROP_AND_CONTINUE = 0
    HALT = 1

    @classmethod
    def from_int(cls, value: int):
        for member in cls:
            if member.value == value:
                return member
        return cls.HALT


class c_line_sender_opts(ctypes.Structure):
    pass


class c_line_sender_error(ctypes.Structure):
    pass


class c_line_sender_qwpws_error(ctypes.Structure):
    pass


c_size_t_p = ctypes.POINTER(c_size_t)
c_ssize_t_p = ctypes.POINTER(c_ssize_t)
c_line_sender_p = ctypes.POINTER(c_line_sender)
c_line_sender_buffer_p = ctypes.POINTER(c_line_sender_buffer)
c_line_sender_opts_p = ctypes.POINTER(c_line_sender_opts)
c_line_sender_error_p = ctypes.POINTER(c_line_sender_error)
c_line_sender_error_p_p = ctypes.POINTER(c_line_sender_error_p)
c_line_sender_qwpws_error_p = ctypes.POINTER(c_line_sender_qwpws_error)
c_line_sender_qwpws_error_p_p = ctypes.POINTER(c_line_sender_qwpws_error_p)
c_uint8_p = ctypes.POINTER(c_uint8)
c_double_p = ctypes.POINTER(c_double)


class c_line_sender_utf8(ctypes.Structure):
    _fields_ = [("len", c_size_t),
                ("buf", c_char_p)]


c_line_sender_utf8_p = ctypes.POINTER(c_line_sender_utf8)


class c_line_sender_table_name(ctypes.Structure):
    _fields_ = [("len", c_size_t),
                ("buf", c_char_p)]


class line_sender_buffer_view(ctypes.Structure):
    _fields_ = [("len", c_size_t),
                ("buf", c_uint8_p)]


class line_sender_qwpws_fsn(ctypes.Structure):
    _fields_ = [("has_value", c_bool),
                ("value", c_uint64)]


class line_sender_qwpws_error_view(ctypes.Structure):
    _fields_ = [("category", c_int),
                ("applied_policy", c_int),
                ("has_status", c_bool),
                ("status", c_uint8),
                ("has_message_sequence", c_bool),
                ("message_sequence", c_uint64),
                ("from_fsn", c_uint64),
                ("to_fsn", c_uint64),
                ("message", c_void_p),
                ("message_len", c_size_t)]


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
        c_protocol_version,
        c_size_t)
    set_sig(
        dll.line_sender_buffer_new_for_sender,
        c_line_sender_buffer_p,
        c_line_sender_p)
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
        line_sender_buffer_view,
        c_line_sender_buffer_p)
    set_sig(
        dll.line_sender_buffer_clear,
        None,
        c_line_sender_buffer_p)
    set_sig(
        dll.line_sender_buffer_set_marker,
        c_bool,
        c_line_sender_buffer_p,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_buffer_rewind_to_marker,
        c_bool,
        c_line_sender_buffer_p,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_buffer_clear_marker,
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
        dll.line_sender_buffer_column_i8,
        c_bool,
        c_line_sender_buffer_p,
        c_line_sender_column_name,
        ctypes.c_int8,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_buffer_column_i16,
        c_bool,
        c_line_sender_buffer_p,
        c_line_sender_column_name,
        ctypes.c_int16,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_buffer_column_i32,
        c_bool,
        c_line_sender_buffer_p,
        c_line_sender_column_name,
        ctypes.c_int32,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_buffer_column_f32,
        c_bool,
        c_line_sender_buffer_p,
        c_line_sender_column_name,
        ctypes.c_float,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_buffer_column_dec64_str,
        c_bool,
        c_line_sender_buffer_p,
        c_line_sender_column_name,
        c_char_p,
        c_size_t,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_buffer_column_dec64,
        c_bool,
        c_line_sender_buffer_p,
        c_line_sender_column_name,
        ctypes.c_uint32,
        c_char_p,
        c_size_t,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_buffer_column_dec128_str,
        c_bool,
        c_line_sender_buffer_p,
        c_line_sender_column_name,
        c_char_p,
        c_size_t,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_buffer_column_dec128,
        c_bool,
        c_line_sender_buffer_p,
        c_line_sender_column_name,
        ctypes.c_uint32,
        c_char_p,
        c_size_t,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_buffer_column_uuid,
        c_bool,
        c_line_sender_buffer_p,
        c_line_sender_column_name,
        ctypes.c_uint64,
        ctypes.c_uint64,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_buffer_column_long256,
        c_bool,
        c_line_sender_buffer_p,
        c_line_sender_column_name,
        c_char_p,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_buffer_column_ipv4,
        c_bool,
        c_line_sender_buffer_p,
        c_line_sender_column_name,
        ctypes.c_uint32,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_buffer_column_date,
        c_bool,
        c_line_sender_buffer_p,
        c_line_sender_column_name,
        c_int64,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_buffer_column_char,
        c_bool,
        c_line_sender_buffer_p,
        c_line_sender_column_name,
        ctypes.c_uint16,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_buffer_column_binary,
        c_bool,
        c_line_sender_buffer_p,
        c_line_sender_column_name,
        c_char_p,
        c_size_t,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_buffer_column_geohash,
        c_bool,
        c_line_sender_buffer_p,
        c_line_sender_column_name,
        ctypes.c_uint64,
        ctypes.c_uint8,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_buffer_column_i64_arr_c_major,
        c_bool,
        c_line_sender_buffer_p,
        c_line_sender_column_name,
        c_size_t,
        c_size_t_p,
        ctypes.POINTER(c_int64),
        c_size_t,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_buffer_column_i64_arr_byte_strides,
        c_bool,
        c_line_sender_buffer_p,
        c_line_sender_column_name,
        c_size_t,
        c_size_t_p,
        c_ssize_t_p,
        ctypes.POINTER(c_int64),
        c_size_t,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_buffer_column_i64_arr_elem_strides,
        c_bool,
        c_line_sender_buffer_p,
        c_line_sender_column_name,
        c_size_t,
        c_size_t_p,
        c_ssize_t_p,
        ctypes.POINTER(c_int64),
        c_size_t,
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
        dll.line_sender_buffer_column_dec_str,
        c_bool,
        c_line_sender_buffer_p,
        c_line_sender_column_name,
        c_char_p,
        c_size_t,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_buffer_column_f64_arr_byte_strides,
        c_bool,
        c_line_sender_buffer_p,
        c_line_sender_column_name,
        c_size_t,
        c_size_t_p,
        c_ssize_t_p,
        c_double_p,
        c_size_t,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_buffer_column_f64_arr_elem_strides,
        c_bool,
        c_line_sender_buffer_p,
        c_line_sender_column_name,
        c_size_t,
        c_size_t_p,
        c_ssize_t_p,
        c_double_p,
        c_size_t,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_buffer_column_f64_arr_c_major,
        c_bool,
        c_line_sender_buffer_p,
        c_line_sender_column_name,
        c_size_t,
        c_size_t_p,
        c_double_p,
        c_size_t,
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
        dll.line_sender_buffer_check_can_flush,
        c_bool,
        c_line_sender_buffer_p,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_opts_new,
        c_line_sender_opts_p,
        c_line_sender_protocol,
        c_line_sender_utf8,
        c_uint16)
    set_sig(
        dll.line_sender_opts_new_service,
        c_line_sender_opts_p,
        c_line_sender_protocol,
        c_line_sender_utf8,
        c_line_sender_utf8)
    set_sig(
        dll.line_sender_opts_bind_interface,
        c_bool,
        c_line_sender_opts_p,
        c_line_sender_utf8,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_opts_max_datagram_size,
        c_bool,
        c_line_sender_opts_p,
        c_size_t,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_opts_multicast_ttl,
        c_bool,
        c_line_sender_opts_p,
        c_uint32,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_opts_username,
        c_bool,
        c_line_sender_opts_p,
        c_line_sender_utf8,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_opts_password,
        c_bool,
        c_line_sender_opts_p,
        c_line_sender_utf8,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_opts_token,
        c_bool,
        c_line_sender_opts_p,
        c_line_sender_utf8,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_opts_token_x,
        c_bool,
        c_line_sender_opts_p,
        c_line_sender_utf8,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_opts_token_y,
        c_bool,
        c_line_sender_opts_p,
        c_line_sender_utf8,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_opts_protocol_version,
        c_bool,
        c_line_sender_opts_p,
        c_protocol_version,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_opts_auth_timeout,
        c_bool,
        c_line_sender_opts_p,
        c_uint64,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_opts_tls_verify,
        c_bool,
        c_line_sender_opts_p,
        c_bool,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_opts_tls_ca,
        c_bool,
        c_line_sender_opts_p,
        c_line_sender_ca,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_opts_tls_roots,
        c_bool,
        c_line_sender_opts_p,
        c_line_sender_utf8,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_opts_max_buf_size,
        c_bool,
        c_line_sender_opts_p,
        c_size_t,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_opts_retry_timeout,
        c_bool,
        c_line_sender_opts_p,
        c_uint64,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_opts_retry_max_backoff,
        c_bool,
        c_line_sender_opts_p,
        c_uint64,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_opts_request_min_throughput,
        c_bool,
        c_line_sender_opts_p,
        c_uint64,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_opts_request_timeout,
        c_bool,
        c_line_sender_opts_p,
        c_uint64,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_opts_clone,
        c_line_sender_opts_p,
        c_line_sender_opts_p)
    set_sig(
        dll.line_sender_opts_free,
        None,
        c_line_sender_opts_p)
    set_sig(
        dll.line_sender_build,
        c_line_sender_p,
        c_line_sender_opts_p,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_from_conf,
        c_line_sender_p,
        c_line_sender_utf8,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_from_env,
        c_line_sender_p,
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
    set_sig(
        dll.line_sender_flush_and_keep_with_flags,
        c_bool,
        c_line_sender_p,
        c_line_sender_buffer_p,
        c_bool,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_get_protocol,
        c_line_sender_protocol,
        c_line_sender_p)
    set_sig(
        dll.line_sender_get_protocol_version,
        c_protocol_version,
        c_line_sender_p)
    set_sig(
        dll.line_sender_get_max_name_len,
        c_size_t,
        c_line_sender_p)
    set_sig(
        dll.line_sender_qwpws_flush_and_get_fsn,
        c_bool,
        c_line_sender_p,
        c_line_sender_buffer_p,
        ctypes.POINTER(line_sender_qwpws_fsn),
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_qwpws_published_fsn,
        c_bool,
        c_line_sender_p,
        ctypes.POINTER(line_sender_qwpws_fsn),
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_qwpws_acked_fsn,
        c_bool,
        c_line_sender_p,
        ctypes.POINTER(line_sender_qwpws_fsn),
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_qwpws_await_acked_fsn,
        c_bool,
        c_line_sender_p,
        c_uint64,
        c_uint64,
        ctypes.POINTER(c_bool),
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_qwpws_poll_error,
        c_bool,
        c_line_sender_p,
        c_line_sender_qwpws_error_p_p,
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_qwpws_error_get_view,
        line_sender_qwpws_error_view,
        c_line_sender_qwpws_error_p)
    set_sig(
        dll.line_sender_error_qwpws_get_view,
        c_bool,
        c_line_sender_error_p,
        ctypes.POINTER(line_sender_qwpws_error_view))
    set_sig(
        dll.line_sender_qwpws_error_free,
        None,
        c_line_sender_qwpws_error_p)
    set_sig(
        dll.line_sender_qwpws_errors_dropped,
        c_bool,
        c_line_sender_p,
        ctypes.POINTER(c_uint64),
        c_line_sender_error_p_p)
    set_sig(
        dll.line_sender_qwpws_close_drain,
        c_bool,
        c_line_sender_p,
        c_line_sender_error_p_p)
    return dll


_DLL = _setup_cdll()

_PY_DLL = ctypes.pythonapi
_PY_DLL.PyUnicode_FromKindAndData.restype = ctypes.py_object
_PY_DLL.PyUnicode_FromKindAndData.argtypes = [c_int, c_void_p, c_ssize_t]
_PY_DLL.PyBytes_FromStringAndSize.restype = ctypes.py_object
_PY_DLL.PyBytes_FromStringAndSize.argtypes = [ctypes.c_char_p, ctypes.c_ssize_t]


class QwpWsError:
    def __init__(
            self,
            category: QwpWsErrorCategory,
            applied_policy: QwpWsErrorPolicy,
            status: Optional[int],
            message_sequence: Optional[int],
            from_fsn: int,
            to_fsn: int,
            message: str):
        self.category = category
        self.applied_policy = applied_policy
        self.status = status
        self.message_sequence = message_sequence
        self.from_fsn = from_fsn
        self.to_fsn = to_fsn
        self.message = message

    def __repr__(self):
        return (
            'QwpWsError('
            f'category={self.category}, '
            f'applied_policy={self.applied_policy}, '
            f'status={self.status}, '
            f'message_sequence={self.message_sequence}, '
            f'from_fsn={self.from_fsn}, '
            f'to_fsn={self.to_fsn}, '
            f'message={self.message!r})')


class SenderError(Exception):
    """An error whilst using the line sender."""
    def __init__(self, message: str, qwp_ws_error: Optional[QwpWsError] = None):
        super().__init__(message)
        self.qwp_ws_error = qwp_ws_error


def _qwpws_error_view_to_py(view):
    if view.message and view.message_len:
        message = _PY_DLL.PyUnicode_FromKindAndData(
            1,  # PyUnicode_1BYTE_KIND
            c_void_p(view.message),
            c_ssize_t(view.message_len))
    else:
        message = ''
    return QwpWsError(
        QwpWsErrorCategory.from_int(view.category),
        QwpWsErrorPolicy.from_int(view.applied_policy),
        view.status if view.has_status else None,
        view.message_sequence if view.has_message_sequence else None,
        view.from_fsn,
        view.to_fsn,
        message)


def _qwpws_error_from_sender_error(err_p):
    view = line_sender_qwpws_error_view()
    if _DLL.line_sender_error_qwpws_get_view(err_p, ctypes.byref(view)):
        return _qwpws_error_view_to_py(view)
    return None


def _c_err_to_py(err_p):
    try:
        c_len = c_size_t(0)
        msg_p = _DLL.line_sender_error_msg(err_p, ctypes.byref(c_len))
        py_msg = _PY_DLL.PyUnicode_FromKindAndData(
            1,  # PyUnicode_1BYTE_KIND
            msg_p,
            c_ssize_t(c_len.value))
        return SenderError(py_msg, _qwpws_error_from_sender_error(err_p))
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
    def __init__(self, host, port, protocol=Protocol.TCP):
        self.impl = _error_wrapped_call(
            _DLL.line_sender_opts_new_service,
            protocol.value[0],
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


class TimestampNanos:
    def __init__(self, nanos: int):
        self.value = nanos


class Buffer:
    def __init__(self, protocol_version: ProtocolVersion, init_buf_size=65536, max_name_len=127, ):
        self._impl = _DLL.line_sender_buffer_with_max_name_len(
            protocol_version.value[0],
            c_size_t(max_name_len))
        _error_wrapped_call(
            _DLL.line_sender_buffer_reserve,
            self._impl,
            c_size_t(init_buf_size))

    @classmethod
    def from_sender(cls, sender_impl, init_buf_size=65536):
        self = cls.__new__(cls)
        self._impl = _DLL.line_sender_buffer_new_for_sender(sender_impl)
        _error_wrapped_call(
            _DLL.line_sender_buffer_reserve,
            self._impl,
            c_size_t(init_buf_size))
        return self

    def __len__(self):
        return _DLL.line_sender_buffer_size(self._impl)

    def peek(self) -> bytes:
        # Copy buffer
        view = _DLL.line_sender_buffer_peek(self._impl)
        if view.len:
            c_buf = ctypes.cast(view.buf, c_char_p)  # uint8_t* → char*
            return _PY_DLL.PyBytes_FromStringAndSize(c_buf, view.len)
        else:
            return ''

    def reserve(self, additional):
        _error_wrapped_call(
            _DLL.line_sender_buffer_reserve,
            self._impl,
            c_size_t(additional))

    @property
    def capacity(self):
        return _DLL.line_sender_buffer_capacity(self._impl)

    def clear(self):
        _DLL.line_sender_buffer_clear(self._impl)

    def set_marker(self):
        _error_wrapped_call(
            _DLL.line_sender_buffer_set_marker,
            self._impl)
        return self

    def rewind_to_marker(self):
        _error_wrapped_call(
            _DLL.line_sender_buffer_rewind_to_marker,
            self._impl)
        return self

    def clear_marker(self):
        _DLL.line_sender_buffer_clear_marker(self._impl)
        return self

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

    def column_dec_str(self, name: str, value: str):
        c_utf8 = value.encode('utf-8')
        _error_wrapped_call(
            _DLL.line_sender_buffer_column_dec_str,
            self._impl,
            _column_name(name),
            c_utf8,
            len(c_utf8))

    def column_i8(self, name: str, value: int):
        _error_wrapped_call(
            _DLL.line_sender_buffer_column_i8,
            self._impl,
            _column_name(name),
            int(value))
        return self

    def column_i16(self, name: str, value: int):
        _error_wrapped_call(
            _DLL.line_sender_buffer_column_i16,
            self._impl,
            _column_name(name),
            int(value))
        return self

    def column_i32(self, name: str, value: int):
        _error_wrapped_call(
            _DLL.line_sender_buffer_column_i32,
            self._impl,
            _column_name(name),
            int(value))
        return self

    def column_f32(self, name: str, value: float):
        _error_wrapped_call(
            _DLL.line_sender_buffer_column_f32,
            self._impl,
            _column_name(name),
            ctypes.c_float(value))
        return self

    def column_dec64_str(self, name: str, value: str):
        c_utf8 = value.encode('utf-8')
        _error_wrapped_call(
            _DLL.line_sender_buffer_column_dec64_str,
            self._impl,
            _column_name(name),
            c_utf8,
            len(c_utf8))
        return self

    def column_dec64(self, name: str, scale: int, le_bytes: bytes):
        _error_wrapped_call(
            _DLL.line_sender_buffer_column_dec64,
            self._impl,
            _column_name(name),
            ctypes.c_uint32(scale),
            le_bytes,
            len(le_bytes))
        return self

    def column_dec128_str(self, name: str, value: str):
        c_utf8 = value.encode('utf-8')
        _error_wrapped_call(
            _DLL.line_sender_buffer_column_dec128_str,
            self._impl,
            _column_name(name),
            c_utf8,
            len(c_utf8))
        return self

    def column_dec128(self, name: str, scale: int, le_bytes: bytes):
        _error_wrapped_call(
            _DLL.line_sender_buffer_column_dec128,
            self._impl,
            _column_name(name),
            ctypes.c_uint32(scale),
            le_bytes,
            len(le_bytes))
        return self

    def column_uuid(self, name: str, lo: int, hi: int):
        _error_wrapped_call(
            _DLL.line_sender_buffer_column_uuid,
            self._impl,
            _column_name(name),
            ctypes.c_uint64(lo),
            ctypes.c_uint64(hi))
        return self

    def column_long256(self, name: str, value: bytes):
        if len(value) != 32:
            raise ValueError('column_long256 value must be exactly 32 bytes')
        _error_wrapped_call(
            _DLL.line_sender_buffer_column_long256,
            self._impl,
            _column_name(name),
            value)
        return self

    def column_ipv4(self, name: str, value: int):
        _error_wrapped_call(
            _DLL.line_sender_buffer_column_ipv4,
            self._impl,
            _column_name(name),
            ctypes.c_uint32(value))
        return self

    def column_date(self, name: str, millis: int):
        _error_wrapped_call(
            _DLL.line_sender_buffer_column_date,
            self._impl,
            _column_name(name),
            int(millis))
        return self

    def column_char(self, name: str, value: int):
        _error_wrapped_call(
            _DLL.line_sender_buffer_column_char,
            self._impl,
            _column_name(name),
            ctypes.c_uint16(value))
        return self

    def column_binary(self, name: str, value: bytes):
        _error_wrapped_call(
            _DLL.line_sender_buffer_column_binary,
            self._impl,
            _column_name(name),
            value,
            len(value))
        return self

    def column_geohash(self, name: str, bits: int, precision_bits: int):
        _error_wrapped_call(
            _DLL.line_sender_buffer_column_geohash,
            self._impl,
            _column_name(name),
            ctypes.c_uint64(bits),
            ctypes.c_uint8(precision_bits))
        return self

    def column_i64_arr(self, name: str, array):
        arr = numpy.ascontiguousarray(array, dtype=numpy.int64)
        c_shape = (c_size_t * arr.ndim)(*arr.shape)
        _error_wrapped_call(
            _DLL.line_sender_buffer_column_i64_arr_c_major,
            self._impl,
            _column_name(name),
            c_size_t(arr.ndim),
            c_shape,
            arr.ctypes.data_as(ctypes.POINTER(c_int64)),
            c_size_t(arr.size))
        return self

    def column_i64_arr_byte_strides(self, name: str, array):
        arr = numpy.asarray(array, dtype=numpy.int64)
        c_shape = (c_size_t * arr.ndim)(*arr.shape)
        c_strides = (c_ssize_t * arr.ndim)(*arr.strides)
        _error_wrapped_call(
            _DLL.line_sender_buffer_column_i64_arr_byte_strides,
            self._impl,
            _column_name(name),
            c_size_t(arr.ndim),
            c_shape,
            c_strides,
            arr.ctypes.data_as(ctypes.POINTER(c_int64)),
            c_size_t(arr.size))
        return self

    def column_i64_arr_elem_strides(self, name: str, array):
        arr = numpy.asarray(array, dtype=numpy.int64)
        c_shape = (c_size_t * arr.ndim)(*arr.shape)
        c_strides = (c_ssize_t * arr.ndim)(
            *(s // arr.itemsize for s in arr.strides))
        _error_wrapped_call(
            _DLL.line_sender_buffer_column_i64_arr_elem_strides,
            self._impl,
            _column_name(name),
            c_size_t(arr.ndim),
            c_shape,
            c_strides,
            arr.ctypes.data_as(ctypes.POINTER(c_int64)),
            c_size_t(arr.size))
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
        elif isinstance(value, Decimal):
            self.column_dec_str(name, str(value))
        elif isinstance(value, TimestampMicros):
            _error_wrapped_call(
                _DLL.line_sender_buffer_column_ts_micros,
                self._impl,
                _column_name(name),
                value.value)
        elif isinstance(value, TimestampNanos):
            _error_wrapped_call(
                _DLL.line_sender_buffer_column_ts_nanos,
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
                '`bool`, `int`, `float`, `str`, `Decimal`, `TimestampMicros`, or `datetime`.')
        return self

    def column_f64_arr(self, name: str,
                       rank: int,
                       shape: tuple[int, ...],
                       strides: tuple[int, ...],
                       data: c_void_p,
                       length: int):
        def _convert_tuple(tpl: tuple[int, ...], c_type: type, name: str) -> ctypes.POINTER:
            arr_type = c_type * len(tpl)
            try:
                return arr_type(*[c_type(v) for v in tpl])
            except OverflowError as e:
                raise ValueError(
                    f"{name} value exceeds {c_type.__name__} range"
                ) from e

        c_shape = _convert_tuple(shape, c_size_t, "shape")
        c_strides = _convert_tuple(strides, c_ssize_t, "strides")
        _error_wrapped_call(
            _DLL.line_sender_buffer_column_f64_arr_byte_strides,
            self._impl,
            _column_name(name),
            c_size_t(rank),
            c_shape,
            c_strides,
            ctypes.cast(data, c_double_p),
            c_size_t(length)
        )

    def column_f64_arr_c_major(self, name: str,
                               rank: int,
                               shape: tuple[int, ...],
                               data: c_void_p,
                               length: int):
        def _convert_tuple(tpl: tuple[int, ...], c_type: type, name: str) -> ctypes.POINTER:
            arr_type = c_type * len(tpl)
            try:
                return arr_type(*[c_type(v) for v in tpl])
            except OverflowError as e:
                raise ValueError(
                    f"{name} value exceeds {c_type.__name__} range"
                ) from e

        c_shape = _convert_tuple(shape, c_size_t, "shape")
        _error_wrapped_call(
            _DLL.line_sender_buffer_column_f64_arr_c_major,
            self._impl,
            _column_name(name),
            c_size_t(rank),
            c_shape,
            ctypes.cast(data, c_double_p),
            c_size_t(length)
        )

    def at_now(self):
        _error_wrapped_call(
            _DLL.line_sender_buffer_at_now,
            self._impl)

    def at(self, timestamp: int):
        _error_wrapped_call(
            _DLL.line_sender_buffer_at_nanos,
            self._impl,
            timestamp)

    def at_micros(self, timestamp: int):
        _error_wrapped_call(
            _DLL.line_sender_buffer_at_micros,
            self._impl,
            timestamp)

    def __del__(self):
        _DLL.line_sender_buffer_free(self._impl)


class BuildMode(Enum):
    API = 1
    CONF = 2
    ENV = 3


def _map_value(key, value):
    """
    Return a pair of option C object and string value.
    """
    if isinstance(value, bool):
        if key == 'tls_verify':
            return (value, 'on' if value else 'unsafe_off')
        else:
            return (value, 'on' if value else 'off')
    elif isinstance(value, (CertificateAuthority, ProtocolVersion)):
        return value.value  # a tuple of `(c enum value, str)`
    else:
        return (value, f'{value}')


class Sender:
    def __init__(
            self,
            build_mode: BuildMode,
            protocol,
            host: str,
            port: Union[str, int],
            **kwargs):

        if protocol in (Protocol.TCPS, Protocol.HTTPS, Protocol.QWPWSS):
            if host == '127.0.0.1':
                host = 'localhost'  # for TLS connections we need a hostname

        self._build_mode = build_mode
        self._impl = None
        self._conf = [
            protocol.value[1],
            '::',
            f'addr={host}:{port};']
        self._opts = None
        opts = _Opts(host, port, protocol)
        for key, value in kwargs.items():
            # Build the config string param pair.
            c_value, conf_value = _map_value(key, value)
            self._conf.append(f'{key}={conf_value};')

            # Set the option in the C object.
            getattr(opts, key)(c_value)

        self._conf = ''.join(self._conf)
        self._opts = opts

    @classmethod
    def from_conf(cls, conf: str):
        sender = cls.__new__(cls)
        sender._build_mode = BuildMode.CONF
        sender._impl = None
        sender._conf = conf
        sender._opts = None
        return sender

    @property
    def buffer(self):
        return self._buffer

    def connect(self):
        if self._impl:
            raise SenderError('Already connected')
        if self._build_mode == BuildMode.CONF:
            try:
                self._impl = _error_wrapped_call(
                    _DLL.line_sender_from_conf,
                    _utf8(self._conf))
            except SenderError as e:
                raise SenderError(
                    f'Failed to connect to QuestDB with conf `{self._conf}`: {e}') from e
        elif self._build_mode == BuildMode.ENV:
            env_var = 'QDB_CLIENT_CONF'
            os.environ[env_var] = self._conf
            self._impl = _error_wrapped_call(
                _DLL.line_sender_from_env)
            del os.environ[env_var]
        else:
            self._impl = _error_wrapped_call(
                _DLL.line_sender_build,
                self._opts.impl)

    def __enter__(self):
        self.connect()
        self._buffer = Buffer.from_sender(self._impl)
        return self

    def _check_connected(self):
        if not self._impl:
            raise SenderError('Not connected.')

    @property
    def protocol(self):
        self._check_connected()
        return Protocol.from_int(_DLL.line_sender_get_protocol(self._impl))

    @property
    def protocol_version(self):
        self._check_connected()
        return ProtocolVersion.from_int(
            _DLL.line_sender_get_protocol_version(self._impl))

    @property
    def max_name_len(self):
        self._check_connected()
        return _DLL.line_sender_get_max_name_len(self._impl)

    def table(self, table: str):
        self._buffer.table(table)
        return self

    def symbol(self, name: str, value: str):
        self._buffer.symbol(name, value)
        return self

    def column(
            self, name: str,
            value: Union[bool, int, float, str, Decimal, TimestampMicros, TimestampNanos, datetime]):
        self._buffer.column(name, value)
        return self
    
    def column_dec_str(
            self, name: str,
            value: str):
        self._buffer.column_dec_str(name, value)
        return self

    def column_i8(self, name: str, value: int):
        self._buffer.column_i8(name, value)
        return self

    def column_i16(self, name: str, value: int):
        self._buffer.column_i16(name, value)
        return self

    def column_i32(self, name: str, value: int):
        self._buffer.column_i32(name, value)
        return self

    def column_f32(self, name: str, value: float):
        self._buffer.column_f32(name, value)
        return self

    def column_dec64_str(self, name: str, value: str):
        self._buffer.column_dec64_str(name, value)
        return self

    def column_dec64(self, name: str, scale: int, le_bytes: bytes):
        self._buffer.column_dec64(name, scale, le_bytes)
        return self

    def column_dec128_str(self, name: str, value: str):
        self._buffer.column_dec128_str(name, value)
        return self

    def column_dec128(self, name: str, scale: int, le_bytes: bytes):
        self._buffer.column_dec128(name, scale, le_bytes)
        return self

    def column_uuid(self, name: str, lo: int, hi: int):
        self._buffer.column_uuid(name, lo, hi)
        return self

    def column_long256(self, name: str, value: bytes):
        self._buffer.column_long256(name, value)
        return self

    def column_ipv4(self, name: str, value: int):
        self._buffer.column_ipv4(name, value)
        return self

    def column_date(self, name: str, millis: int):
        self._buffer.column_date(name, millis)
        return self

    def column_char(self, name: str, value: int):
        self._buffer.column_char(name, value)
        return self

    def column_binary(self, name: str, value: bytes):
        self._buffer.column_binary(name, value)
        return self

    def column_geohash(self, name: str, bits: int, precision_bits: int):
        self._buffer.column_geohash(name, bits, precision_bits)
        return self

    def column_i64_arr(self, name: str, array):
        self._buffer.column_i64_arr(name, array)
        return self

    def column_i64_arr_byte_strides(self, name: str, array):
        self._buffer.column_i64_arr_byte_strides(name, array)
        return self

    def column_i64_arr_elem_strides(self, name: str, array):
        self._buffer.column_i64_arr_elem_strides(name, array)
        return self

    def column_f64_arr(
            self, name: str,
            array: numpy.ndarray):
        if array.dtype != numpy.float64:
            raise ValueError('expect float64 array')
        if array.flags.c_contiguous:
            self._buffer.column_f64_arr_c_major(name, array.ndim, array.shape, array.ctypes.data, array.size)
        else:
            self._buffer.column_f64_arr(name, array.ndim, array.shape, array.strides, array.ctypes.data, array.size)
        return self

    def at_now(self):
        self._buffer.at_now()

    def at(self, timestamp: int):
        self._buffer.at(timestamp)

    def at_micros(self, timestamp: int):
        self._buffer.at_micros(timestamp)

    def flush(self, buffer: Optional[Buffer] = None, clear=True, transactional=None):
        if (buffer is None) and not clear:
            raise ValueError(
                'Clear flag must be True when using internal buffer')
        buffer = buffer or self._buffer
        self._check_connected()
        if len(buffer) == 0:
            return
        try:
            if transactional is not None:
                if not isinstance(transactional, bool):
                    raise ValueError('Transactional flag must be a boolean')
                _error_wrapped_call(
                    _DLL.line_sender_flush_and_keep_with_flags,
                    self._impl,
                    buffer._impl,
                    transactional)
                if clear:
                    buffer.clear()
            else:
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

    def flush_and_get_fsn(self, buffer: Optional[Buffer] = None) -> Optional[int]:
        buffer = buffer or self._buffer
        self._check_connected()
        fsn = line_sender_qwpws_fsn()
        _error_wrapped_call(
            _DLL.line_sender_qwpws_flush_and_get_fsn,
            self._impl,
            buffer._impl,
            ctypes.byref(fsn))
        if fsn.has_value:
            return fsn.value
        return None

    def published_fsn(self) -> Optional[int]:
        self._check_connected()
        fsn = line_sender_qwpws_fsn()
        _error_wrapped_call(
            _DLL.line_sender_qwpws_published_fsn,
            self._impl,
            ctypes.byref(fsn))
        if fsn.has_value:
            return fsn.value
        return None

    def acked_fsn(self) -> Optional[int]:
        self._check_connected()
        fsn = line_sender_qwpws_fsn()
        _error_wrapped_call(
            _DLL.line_sender_qwpws_acked_fsn,
            self._impl,
            ctypes.byref(fsn))
        if fsn.has_value:
            return fsn.value
        return None

    def await_acked_fsn(self, fsn: int, timeout_millis: int) -> bool:
        self._check_connected()
        reached = c_bool(False)
        _error_wrapped_call(
            _DLL.line_sender_qwpws_await_acked_fsn,
            self._impl,
            c_uint64(fsn),
            c_uint64(timeout_millis),
            ctypes.byref(reached))
        return bool(reached.value)

    def poll_qwp_ws_error(self) -> Optional[QwpWsError]:
        self._check_connected()
        qwp_error = c_line_sender_qwpws_error_p()
        _error_wrapped_call(
            _DLL.line_sender_qwpws_poll_error,
            self._impl,
            ctypes.byref(qwp_error))
        if not qwp_error:
            return None
        try:
            view = _DLL.line_sender_qwpws_error_get_view(qwp_error)
            return _qwpws_error_view_to_py(view)
        finally:
            _DLL.line_sender_qwpws_error_free(qwp_error)

    def qwp_ws_errors_dropped(self) -> int:
        self._check_connected()
        dropped = c_uint64(0)
        _error_wrapped_call(
            _DLL.line_sender_qwpws_errors_dropped,
            self._impl,
            ctypes.byref(dropped))
        return dropped.value

    def close(self, flush=True):
        if self._impl and not _DLL.line_sender_must_close(self._impl) and flush:
            self.flush()
        if self._impl:
            _DLL.line_sender_close(self._impl)
            self._impl = None

    def close_drain(self):
        self._check_connected()
        _error_wrapped_call(
            _DLL.line_sender_qwpws_close_drain,
            self._impl)

    def __exit__(self, exc_type, _exc_val, _exc_tb):
        self.close(not exc_type)

    def __del__(self):
        self.close(False)
