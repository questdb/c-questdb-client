"""Thin ctypes wrapper around the QWP egress reader FFI.

Why this exists: the Python qwp_ws fuzz harness used to verify ingested rows
via the REST `/exec` endpoint. `/exec` hard-codes BINARY column values to the
literal JSON `[]` (see `JsonQueryProcessorState.putBinValue`), so any
BINARY round-trip failed regardless of what the sender actually wrote. Reading
the same rows back through the QWP egress reader gives us the real bytes.

The wrapper is intentionally narrow: open a Reader from a config string, run
one SELECT, drain it to in-memory rows, close. No streaming, no cursor reuse,
no bind parameters. Values are decoded into Python types whose shape matches
what `/exec` JSON used to return, so `qwp_ws_fuzz.format_actual_cell` keeps
working unchanged (except BINARY, which now returns real `bytes`).

Memory model: every pointer the FFI hands back is borrowed from the batch and
gets invalidated by the next `cursor_next_batch` call. Decoders materialize
every value out of the batch before advancing.
"""

from __future__ import annotations

import ctypes
import math
import struct
from typing import Any, List, Optional, Tuple

import numpy as np  # used to render FLOAT in the short f32 form /exec uses
# Reuse the sender module's struct types (and its already-installed argtypes
# for `line_sender_utf8_init` / `line_sender_error_msg` / `line_sender_error_free`).
# ctypes treats two structurally-identical `Structure` subclasses as distinct
# types, so a parallel set of definitions here would silently override the
# sender's argtypes the moment this module is imported, then break every
# subsequent sender-side call with `TypeError: expected LP__LineSenderUtf8 ...`.
from questdb_line_sender import (  # type: ignore[attr-defined]
    _DLL,
    c_line_sender_error as _LineSenderError,
    c_line_sender_utf8 as _LineSenderUtf8,
)


# ---------------------------------------------------------------------------
# Column-kind discriminants (mirror `reader_column_kind` in
# `include/questdb/egress/reader.h`).
# ---------------------------------------------------------------------------

KIND_BOOLEAN = 0x01
KIND_BYTE = 0x02
KIND_SHORT = 0x03
KIND_INT = 0x04
KIND_LONG = 0x05
KIND_FLOAT = 0x06
KIND_DOUBLE = 0x07
KIND_SYMBOL = 0x09
KIND_TIMESTAMP = 0x0A
KIND_DATE = 0x0B
KIND_UUID = 0x0C
KIND_LONG256 = 0x0D
KIND_GEOHASH = 0x0E
KIND_VARCHAR = 0x0F
KIND_TIMESTAMP_NANOS = 0x10
KIND_DOUBLE_ARRAY = 0x11
KIND_LONG_ARRAY = 0x12
KIND_DECIMAL64 = 0x13
KIND_DECIMAL128 = 0x14
KIND_DECIMAL256 = 0x15
KIND_CHAR = 0x16
KIND_BINARY = 0x17
KIND_IPV4 = 0x18
KIND_UNKNOWN = 0xFF


# QuestDB column-type sentinel for NULL values. Mirrors `Numbers.LONG_NULL`,
# `Numbers.INT_NULL`, `Numbers.SHORT_NULL`. BYTE is non-nullable on the server,
# but the wire still carries a slot per row.
_LONG_NULL = -(1 << 63)
_INT_NULL = -(1 << 31)


# ---------------------------------------------------------------------------
# ctypes type aliases.
# ---------------------------------------------------------------------------

_c_size_t = ctypes.c_size_t
_c_int8 = ctypes.c_int8
_c_uint8 = ctypes.c_uint8
_c_int16 = ctypes.c_int16
_c_uint16 = ctypes.c_uint16
_c_int32 = ctypes.c_int32
_c_uint32 = ctypes.c_uint32
_c_int64 = ctypes.c_int64
_c_uint64 = ctypes.c_uint64
_c_float = ctypes.c_float
_c_double = ctypes.c_double
_c_char_p = ctypes.c_char_p
_c_void_p = ctypes.c_void_p
_c_bool = ctypes.c_bool


# Opaque handles.
class _LineReader(ctypes.Structure):
    pass


class _LineReaderQuery(ctypes.Structure):
    pass


class _LineReaderCursor(ctypes.Structure):
    pass


class _LineReaderBatch(ctypes.Structure):
    pass


class _LineReaderError(ctypes.Structure):
    pass


# `line_sender_utf8` / `line_sender_error` come from the sender module so the
# reader and sender share a single ctypes type per C struct (see import above).


# `reader_column_data` from `reader.h:1156`.
class _LineReaderColumnData(ctypes.Structure):
    _fields_ = [
        ("kind", _c_uint32),
        ("row_count", _c_size_t),
        ("validity", ctypes.POINTER(_c_uint8)),
        ("values", _c_void_p),
        ("value_stride", _c_size_t),
        ("var_offsets", ctypes.POINTER(_c_uint32)),
        ("var_data", ctypes.POINTER(_c_uint8)),
        ("var_data_len", _c_size_t),
        ("symbol_codes", ctypes.POINTER(_c_uint32)),
        ("decimal_scale", _c_int8),
        ("geohash_precision_bits", _c_uint8),
    ]


# `reader_array_data` from `reader.h:1208`.
class _LineReaderArrayData(ctypes.Structure):
    _fields_ = [
        ("kind", _c_uint32),
        ("row_count", _c_size_t),
        ("validity", ctypes.POINTER(_c_uint8)),
        ("data", ctypes.POINTER(_c_uint8)),
        ("data_len", _c_size_t),
        ("data_offsets", ctypes.POINTER(_c_uint32)),
        ("shapes", ctypes.POINTER(_c_uint32)),
        ("shapes_len", _c_size_t),
        ("shape_offsets", ctypes.POINTER(_c_uint32)),
    ]


# `reader_symbol_entry`.
class _LineReaderSymbolEntry(ctypes.Structure):
    _fields_ = [("offset", _c_uint32), ("length", _c_uint32)]


# `reader_symbol_dict`.
class _LineReaderSymbolDict(ctypes.Structure):
    _fields_ = [
        ("entry_count", _c_size_t),
        ("heap", ctypes.POINTER(_c_uint8)),
        ("heap_len", _c_size_t),
        ("entries", ctypes.POINTER(_LineReaderSymbolEntry)),
    ]


# ---------------------------------------------------------------------------
# FFI signature setup. The DLL itself is loaded by `questdb_line_sender` —
# we just refine signatures here so ctypes coerces handle types correctly.
# ---------------------------------------------------------------------------

def _setsig(name: str, restype, *argtypes) -> None:
    fn = getattr(_DLL, name)
    fn.restype = restype
    fn.argtypes = argtypes


# `line_sender_utf8_init`, `line_sender_error_msg`, `line_sender_error_free`
# already have their argtypes installed by `questdb_line_sender._setup_cdll`.
# Don't re-register them: ctypes uses one function object per DLL symbol, so
# a second `argtypes = ...` here would clobber the sender's and break every
# sender-side call (the reader and sender now share the underlying struct
# types, but the sender's signatures stay the source of truth).

# Reader lifecycle.
_setsig(
    "reader_from_conf",
    ctypes.POINTER(_LineReader),
    _LineSenderUtf8,
    ctypes.POINTER(ctypes.POINTER(_LineReaderError)),
)
_setsig("reader_close", None, ctypes.POINTER(_LineReader))

_setsig(
    "reader_execute",
    ctypes.POINTER(_LineReaderCursor),
    ctypes.POINTER(_LineReader),
    _LineSenderUtf8,
    ctypes.POINTER(ctypes.POINTER(_LineReaderError)),
)

# Cursor.
_setsig("reader_cursor_free", None, ctypes.POINTER(_LineReaderCursor))
_setsig(
    "reader_cursor_next_batch",
    ctypes.POINTER(_LineReaderBatch),
    ctypes.POINTER(_LineReaderCursor),
    ctypes.POINTER(ctypes.POINTER(_LineReaderError)),
)

# Batch introspection.
_setsig("reader_batch_row_count", _c_size_t, ctypes.POINTER(_LineReaderBatch))
_setsig("reader_batch_column_count", _c_size_t, ctypes.POINTER(_LineReaderBatch))
_setsig(
    "reader_batch_column_kind",
    _c_bool,
    ctypes.POINTER(_LineReaderBatch),
    _c_size_t,
    ctypes.POINTER(_c_uint32),
    ctypes.POINTER(ctypes.POINTER(_LineReaderError)),
)
_setsig(
    "reader_batch_column_name",
    _c_bool,
    ctypes.POINTER(_LineReaderBatch),
    _c_size_t,
    ctypes.POINTER(_c_char_p),
    ctypes.POINTER(_c_size_t),
    ctypes.POINTER(ctypes.POINTER(_LineReaderError)),
)
_setsig(
    "reader_batch_column_data",
    _c_bool,
    ctypes.POINTER(_LineReaderBatch),
    _c_size_t,
    ctypes.POINTER(_LineReaderColumnData),
    ctypes.POINTER(ctypes.POINTER(_LineReaderError)),
)
_setsig(
    "reader_batch_array_column_data",
    _c_bool,
    ctypes.POINTER(_LineReaderBatch),
    _c_size_t,
    ctypes.POINTER(_LineReaderArrayData),
    ctypes.POINTER(ctypes.POINTER(_LineReaderError)),
)
_setsig(
    "reader_batch_symbol_dict",
    _c_bool,
    ctypes.POINTER(_LineReaderBatch),
    ctypes.POINTER(_LineReaderSymbolDict),
    ctypes.POINTER(ctypes.POINTER(_LineReaderError)),
)

# Reader error handling.
_setsig("reader_error_get_code", _c_int32, ctypes.POINTER(_LineReaderError))
_setsig(
    "reader_error_msg",
    _c_char_p,
    ctypes.POINTER(_LineReaderError),
    ctypes.POINTER(_c_size_t),
)
_setsig("reader_error_free", None, ctypes.POINTER(_LineReaderError))


# ---------------------------------------------------------------------------
# Error helpers.
# ---------------------------------------------------------------------------

class ReaderError(RuntimeError):
    """Raised when an FFI call sets `err_out` or a handle comes back NULL."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(f"reader error (code={code}): {message}")
        self.code = code
        self.message = message


def _take_error(err_ptr) -> ReaderError:
    """Build a ReaderError from a populated `reader_error*` and free it.

    `err_ptr` is the pointer variable the FFI wrote into (i.e. an
    instance of `ctypes.POINTER(_LineReaderError)`), not a byref to it.
    """
    code = int(_DLL.reader_error_get_code(err_ptr))
    msg_len = _c_size_t(0)
    raw = _DLL.reader_error_msg(err_ptr, ctypes.byref(msg_len))
    msg = (
        bytes(ctypes.string_at(raw, msg_len.value)).decode("utf-8", "replace")
        if raw and msg_len.value
        else ""
    )
    _DLL.reader_error_free(err_ptr)
    return ReaderError(code, msg)


def _utf8(s: str) -> _LineSenderUtf8:
    encoded = s.encode("utf-8")
    holder = _LineSenderUtf8()
    sender_err = ctypes.POINTER(_LineSenderError)()
    if not _DLL.line_sender_utf8_init(
        ctypes.byref(holder),
        len(encoded),
        encoded,
        ctypes.byref(sender_err),
    ):
        msg_len = _c_size_t(0)
        msg = _DLL.line_sender_error_msg(sender_err, ctypes.byref(msg_len))
        text = (
            ctypes.string_at(msg, msg_len.value).decode("utf-8", "replace")
            if msg and msg_len.value
            else ""
        )
        _DLL.line_sender_error_free(sender_err)
        raise ReaderError(-1, f"invalid utf8 in config/sql: {text}")
    # Keep the encoded bytes alive for the duration of the FFI call by stashing
    # them on the struct — ctypes only stores the pointer.
    holder._payload = encoded  # type: ignore[attr-defined]
    return holder


# ---------------------------------------------------------------------------
# Validity bitmap helpers.
# ---------------------------------------------------------------------------

def _is_null(validity_ptr, row_idx: int) -> bool:
    if not validity_ptr:
        return False
    byte = validity_ptr[row_idx >> 3]
    return bool(byte & (1 << (row_idx & 7)))


def _read_bytes(ptr, length: int) -> bytes:
    if not ptr or length == 0:
        return b""
    return ctypes.string_at(ptr, length)


# ---------------------------------------------------------------------------
# Per-kind decoders. Each returns (type_str, values_list).
#
# Values match what `/exec` JSON would return for the same column, with two
# carve-outs: BINARY is `bytes` (so the existing oracle can hex-encode it)
# and TIMESTAMP / TIMESTAMP_NS are int nanos (oracle already accepts ints).
# ---------------------------------------------------------------------------

def _decode_fixed_scalar(
    col: _LineReaderColumnData,
    fmt: str,
    null_sentinel: Optional[int],
    type_str: str,
    cast,
) -> Tuple[str, list]:
    row_count = int(col.row_count)
    if row_count == 0:
        return type_str, []
    stride = int(col.value_stride)
    raw = _read_bytes(col.values, row_count * stride)
    out: List[Any] = []
    validity = col.validity
    for r in range(row_count):
        if _is_null(validity, r):
            out.append(None)
            continue
        (v,) = struct.unpack_from(fmt, raw, r * stride)
        if null_sentinel is not None and v == null_sentinel:
            out.append(None)
        else:
            out.append(cast(v))
    return type_str, out


def _decode_boolean(col: _LineReaderColumnData) -> Tuple[str, list]:
    row_count = int(col.row_count)
    if row_count == 0:
        return "BOOLEAN", []
    raw = _read_bytes(col.values, row_count)
    # BOOLEAN is non-nullable on the server but the validity bitmap may still
    # be present; honour it for safety.
    validity = col.validity
    out: List[Any] = []
    for r in range(row_count):
        if _is_null(validity, r):
            out.append(None)
        else:
            out.append(raw[r] != 0)
    return "BOOLEAN", out


def _decode_byte(col: _LineReaderColumnData) -> Tuple[str, list]:
    row_count = int(col.row_count)
    if row_count == 0:
        return "BYTE", []
    raw = _read_bytes(col.values, row_count)
    validity = col.validity
    out: List[Any] = []
    for r in range(row_count):
        if _is_null(validity, r):
            out.append(None)
        else:
            out.append(struct.unpack_from("<b", raw, r)[0])
    return "BYTE", out


def _decode_short(col: _LineReaderColumnData) -> Tuple[str, list]:
    return _decode_fixed_scalar(col, "<h", None, "SHORT", int)


def _decode_int(col: _LineReaderColumnData) -> Tuple[str, list]:
    return _decode_fixed_scalar(col, "<i", _INT_NULL, "INT", int)


def _decode_long(col: _LineReaderColumnData) -> Tuple[str, list]:
    return _decode_fixed_scalar(col, "<q", _LONG_NULL, "LONG", int)


def _decode_float(col: _LineReaderColumnData) -> Tuple[str, list]:
    row_count = int(col.row_count)
    if row_count == 0:
        return "FLOAT", []
    raw = _read_bytes(col.values, row_count * 4)
    validity = col.validity
    out: List[Any] = []
    for r in range(row_count):
        if _is_null(validity, r):
            out.append(None)
            continue
        (v,) = struct.unpack_from("<f", raw, r * 4)
        if math.isnan(v):
            out.append(None)
            continue
        # /exec serialises FLOAT through QuestDB's f32-short formatter; once
        # JSON has parsed it on the Python side, repr() returns the short
        # decimal string. Promoting the raw f32 bits to f64 here would give
        # the long "865.9099731445312" form. Round through numpy's f32 short
        # str so the oracle's _format_float (repr) prints the same as
        # format_expected_cell's str(np.float32(...)).
        out.append(float(str(np.float32(v))))
    return "FLOAT", out


def _decode_double(col: _LineReaderColumnData) -> Tuple[str, list]:
    row_count = int(col.row_count)
    if row_count == 0:
        return "DOUBLE", []
    raw = _read_bytes(col.values, row_count * 8)
    validity = col.validity
    out: List[Any] = []
    for r in range(row_count):
        if _is_null(validity, r):
            out.append(None)
            continue
        (v,) = struct.unpack_from("<d", raw, r * 8)
        out.append(None if math.isnan(v) else v)
    return "DOUBLE", out


def _decode_timestamp_micros(col: _LineReaderColumnData) -> Tuple[str, list]:
    # /exec returns ISO strings; format_actual_cell also accepts int. We return
    # nanoseconds so it matches whatever the producer wrote (the oracle
    # canonicalises to ns anyway).
    type_str, values = _decode_fixed_scalar(col, "<q", _LONG_NULL, "TIMESTAMP", int)
    return type_str, [None if v is None else v * 1_000 for v in values]


def _decode_timestamp_nanos(col: _LineReaderColumnData) -> Tuple[str, list]:
    return _decode_fixed_scalar(col, "<q", _LONG_NULL, "TIMESTAMP_NS", int)


def _decode_date(col: _LineReaderColumnData) -> Tuple[str, list]:
    # DATE on the wire is millis (i64). format_actual_cell DATE accepts int.
    return _decode_fixed_scalar(col, "<q", _LONG_NULL, "DATE", int)


def _decode_uuid(col: _LineReaderColumnData) -> Tuple[str, list]:
    row_count = int(col.row_count)
    if row_count == 0:
        return "UUID", []
    raw = _read_bytes(col.values, row_count * 16)
    validity = col.validity
    out: List[Any] = []
    for r in range(row_count):
        if _is_null(validity, r):
            out.append(None)
            continue
        lo, hi = struct.unpack_from("<QQ", raw, r * 16)
        if lo == 0 and hi == _LONG_NULL & ((1 << 64) - 1):
            # QuestDB UUID NULL sentinel — lo=0, hi=Long.MIN_VALUE.
            out.append(None)
            continue
        combined = (hi << 64) | lo
        hex_str = f"{combined:032x}"
        out.append(
            f"{hex_str[0:8]}-{hex_str[8:12]}-{hex_str[12:16]}-"
            f"{hex_str[16:20]}-{hex_str[20:32]}"
        )
    return "UUID", out


def _decode_long256(col: _LineReaderColumnData) -> Tuple[str, list]:
    row_count = int(col.row_count)
    if row_count == 0:
        return "LONG256", []
    raw = _read_bytes(col.values, row_count * 32)
    validity = col.validity
    out: List[Any] = []
    for r in range(row_count):
        if _is_null(validity, r):
            out.append(None)
            continue
        chunk = raw[r * 32 : (r + 1) * 32]
        # Wire is little-endian 4×u64; LONG256 string format is big-endian hex
        # with full leading zero bytes stripped (pairs of '0', never partial).
        rev = bytes(reversed(chunk))
        hex_str = rev.hex()
        while len(hex_str) > 2 and hex_str.startswith("00"):
            hex_str = hex_str[2:]
        out.append("0x" + hex_str)
    return "LONG256", out


_GEOHASH_BASE32 = "0123456789bcdefghjkmnpqrstuvwxyz"


def _decode_geohash(col: _LineReaderColumnData) -> Tuple[str, list]:
    precision_bits = int(col.geohash_precision_bits)
    bytes_per_value = (
        1 if precision_bits <= 8
        else 2 if precision_bits <= 16
        else 4 if precision_bits <= 32
        else 8
    )
    # QuestDB renders GEOHASH(<n>c) when precision_bits is a multiple of 5,
    # else GEOHASH(<n>b). The producer always feeds 25 bits in this harness,
    # which maps to GEOHASH(5c) — but we still derive the form so the wire
    # path stays general.
    is_char_form = precision_bits > 0 and precision_bits % 5 == 0
    if is_char_form:
        n_chars = precision_bits // 5
        type_str = f"GEOHASH({n_chars}c)"
    else:
        type_str = f"GEOHASH({precision_bits}b)"
    row_count = int(col.row_count)
    if row_count == 0:
        return type_str, []
    stride = int(col.value_stride) or bytes_per_value
    raw = _read_bytes(col.values, row_count * stride)
    validity = col.validity
    out: List[Any] = []
    # NULL sentinels for each width: -1 (all bits set) in signed form.
    null_sentinels = {1: 0xFF, 2: 0xFFFF, 4: 0xFFFFFFFF, 8: 0xFFFFFFFFFFFFFFFF}
    null_val = null_sentinels[bytes_per_value]
    for r in range(row_count):
        if _is_null(validity, r):
            out.append(None)
            continue
        slot = raw[r * stride : r * stride + bytes_per_value]
        v = int.from_bytes(slot, "little", signed=False)
        if v == null_val:
            out.append(None)
            continue
        if is_char_form:
            # /exec renders char-form geohashes as the base32 string, MSB
            # character first. We mirror that here so the oracle's straight
            # `str(value)` path matches.
            chars = [
                _GEOHASH_BASE32[(v >> (i * 5)) & 0x1F]
                for i in range(n_chars)
            ]
            out.append("".join(reversed(chars)))
        else:
            # Bit-form: /exec renders as a sequence of '0'/'1' chars, MSB
            # first.
            bits_str = "".join(
                "1" if (v >> i) & 1 else "0"
                for i in range(precision_bits)
            )
            out.append("".join(reversed(bits_str)))
    return type_str, out


def _decode_varchar(col: _LineReaderColumnData) -> Tuple[str, list]:
    return _decode_varlen(col, "VARCHAR", as_bytes=False)


def _decode_binary(col: _LineReaderColumnData) -> Tuple[str, list]:
    return _decode_varlen(col, "BINARY", as_bytes=True)


def _decode_varlen(
    col: _LineReaderColumnData, type_str: str, *, as_bytes: bool
) -> Tuple[str, list]:
    row_count = int(col.row_count)
    if row_count == 0:
        return type_str, []
    offsets_raw = _read_bytes(col.var_offsets, (row_count + 1) * 4)
    offsets = struct.unpack(f"<{row_count + 1}I", offsets_raw)
    data = _read_bytes(col.var_data, int(col.var_data_len))
    validity = col.validity
    out: List[Any] = []
    for r in range(row_count):
        if _is_null(validity, r):
            out.append(None)
            continue
        start, end = offsets[r], offsets[r + 1]
        blob = data[start:end]
        out.append(blob if as_bytes else blob.decode("utf-8", "replace"))
    return type_str, out


def _decode_char(col: _LineReaderColumnData) -> Tuple[str, list]:
    row_count = int(col.row_count)
    if row_count == 0:
        return "CHAR", []
    raw = _read_bytes(col.values, row_count * 2)
    validity = col.validity
    out: List[Any] = []
    for r in range(row_count):
        if _is_null(validity, r):
            out.append(None)
            continue
        (code,) = struct.unpack_from("<H", raw, r * 2)
        if code == 0:
            out.append(None)
        else:
            out.append(chr(code))
    return "CHAR", out


def _decode_ipv4(col: _LineReaderColumnData) -> Tuple[str, list]:
    row_count = int(col.row_count)
    if row_count == 0:
        return "IPv4", []
    raw = _read_bytes(col.values, row_count * 4)
    validity = col.validity
    out: List[Any] = []
    for r in range(row_count):
        if _is_null(validity, r):
            out.append(None)
            continue
        (v,) = struct.unpack_from("<I", raw, r * 4)
        if v == 0:
            # QuestDB IPv4 NULL sentinel is 0.
            out.append(None)
            continue
        out.append(
            f"{(v >> 24) & 0xFF}.{(v >> 16) & 0xFF}.{(v >> 8) & 0xFF}.{v & 0xFF}"
        )
    return "IPv4", out


def _decode_symbol(col: _LineReaderColumnData, dict_heap: bytes,
                   dict_entries: List[Tuple[int, int]]) -> Tuple[str, list]:
    row_count = int(col.row_count)
    if row_count == 0:
        return "SYMBOL", []
    codes_raw = _read_bytes(col.symbol_codes, row_count * 4)
    codes = struct.unpack(f"<{row_count}I", codes_raw)
    validity = col.validity
    out: List[Any] = []
    for r in range(row_count):
        if _is_null(validity, r):
            out.append(None)
            continue
        code = codes[r]
        if code >= len(dict_entries):
            out.append(None)
            continue
        offset, length = dict_entries[code]
        out.append(dict_heap[offset : offset + length].decode("utf-8", "replace"))
    return "SYMBOL", out


def _decimal_string(value: int, scale: int) -> str:
    if scale <= 0:
        return str(value)
    sign = "-" if value < 0 else ""
    magnitude = abs(value)
    s = str(magnitude).rjust(scale + 1, "0")
    return f"{sign}{s[:-scale]}.{s[-scale:]}"


def _decode_decimal64(col: _LineReaderColumnData) -> Tuple[str, list]:
    scale = int(col.decimal_scale)
    row_count = int(col.row_count)
    if row_count == 0:
        return f"DECIMAL({scale})", []
    raw = _read_bytes(col.values, row_count * 8)
    validity = col.validity
    out: List[Any] = []
    for r in range(row_count):
        if _is_null(validity, r):
            out.append(None)
            continue
        (v,) = struct.unpack_from("<q", raw, r * 8)
        out.append(_decimal_string(v, scale))
    return f"DECIMAL({scale})", out


def _decode_decimal128(col: _LineReaderColumnData) -> Tuple[str, list]:
    scale = int(col.decimal_scale)
    row_count = int(col.row_count)
    if row_count == 0:
        return f"DECIMAL({scale})", []
    raw = _read_bytes(col.values, row_count * 16)
    validity = col.validity
    out: List[Any] = []
    for r in range(row_count):
        if _is_null(validity, r):
            out.append(None)
            continue
        # Wire layout from `QwpColumnWriter.writeDecimal128Column` is lo:u64
        # then hi:i64 (little-endian within each).
        lo, hi = struct.unpack_from("<QQ", raw, r * 16)
        # Re-assemble as signed 128-bit.
        if hi >= 1 << 63:
            hi_signed = hi - (1 << 64)
        else:
            hi_signed = hi
        value = (hi_signed << 64) | lo
        out.append(_decimal_string(value, scale))
    return f"DECIMAL({scale})", out


def _decode_decimal256(col: _LineReaderColumnData) -> Tuple[str, list]:
    scale = int(col.decimal_scale)
    row_count = int(col.row_count)
    if row_count == 0:
        return f"DECIMAL({scale})", []
    raw = _read_bytes(col.values, row_count * 32)
    validity = col.validity
    out: List[Any] = []
    for r in range(row_count):
        if _is_null(validity, r):
            out.append(None)
            continue
        # Wire order (see `writeDecimal256Column`): lo, mid, mhi, hi — each u64
        # little-endian. Re-assemble as signed 256-bit.
        l0, l1, l2, l3 = struct.unpack_from("<QQQQ", raw, r * 32)
        if l3 >= 1 << 63:
            l3_signed = l3 - (1 << 64)
        else:
            l3_signed = l3
        value = (l3_signed << 192) | (l2 << 128) | (l1 << 64) | l0
        out.append(_decimal_string(value, scale))
    return f"DECIMAL({scale})", out


def _decode_array(arr: _LineReaderArrayData, elem_type: str) -> Tuple[str, list]:
    row_count = int(arr.row_count)
    if row_count == 0:
        return f"{elem_type}[]", []
    data_blob = _read_bytes(arr.data, int(arr.data_len))
    shapes_raw = _read_bytes(arr.shapes, int(arr.shapes_len) * 4)
    shapes = struct.unpack(f"<{int(arr.shapes_len)}I", shapes_raw) if shapes_raw else ()
    data_offsets = struct.unpack(
        f"<{row_count + 1}I",
        _read_bytes(arr.data_offsets, (row_count + 1) * 4),
    )
    shape_offsets = struct.unpack(
        f"<{row_count + 1}I",
        _read_bytes(arr.shape_offsets, (row_count + 1) * 4),
    )
    validity = arr.validity
    out: List[Any] = []
    elem_stride = 8  # both DOUBLE and LONG arrays store 8 bytes/element
    fmt = "<d" if elem_type == "DOUBLE" else "<q"

    def _walk(shape, data_off):
        if len(shape) == 1:
            count = shape[0]
            values: List[Any] = []
            for i in range(count):
                (v,) = struct.unpack_from(fmt, data_blob, data_off + i * elem_stride)
                if elem_type == "DOUBLE" and math.isnan(v):
                    values.append(None)
                else:
                    values.append(v)
            return values, data_off + count * elem_stride
        head, *rest = shape
        sub = []
        for _ in range(head):
            child, data_off = _walk(rest, data_off)
            sub.append(child)
        return sub, data_off

    max_rank = 1
    for r in range(row_count):
        if _is_null(validity, r):
            out.append(None)
            continue
        shape_slice = shapes[shape_offsets[r] : shape_offsets[r + 1]]
        if not shape_slice:
            out.append([])
            continue
        max_rank = max(max_rank, len(shape_slice))
        nested, _ = _walk(list(shape_slice), data_offsets[r])
        out.append(nested)
    type_str = f"{elem_type}{'[]' * max_rank}"
    return type_str, out


# ---------------------------------------------------------------------------
# Top-level Reader wrapper.
# ---------------------------------------------------------------------------

class QwpEgressReader:
    """Open a reader, run one or more SELECTs against it, then close."""

    def __init__(self, conf: str):
        utf8 = _utf8(conf)
        err_ref = ctypes.POINTER(_LineReaderError)()
        handle = _DLL.reader_from_conf(utf8, ctypes.byref(err_ref))
        if not handle:
            raise _take_error(err_ref)
        self._handle = handle
        self._closed = False

    def __enter__(self) -> "QwpEgressReader":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def close(self) -> None:
        if not self._closed:
            _DLL.reader_close(self._handle)
            self._closed = True

    def select(self, sql: str) -> Tuple[List[dict], List[list]]:
        """Run a SELECT and drain it into (columns, rows).

        `columns` mirrors /exec's `columns` array: list of
        `{'name': ..., 'type': ...}` dicts in column order.
        `rows` is a list of lists, one per row, with cells decoded to the
        same Python shapes /exec used to return (except BINARY = bytes,
        TIMESTAMPs = int nanos).
        """
        if self._closed:
            raise RuntimeError("reader is closed")
        sql_utf8 = _utf8(sql)
        err_ref = ctypes.POINTER(_LineReaderError)()
        cursor = _DLL.reader_execute(
            self._handle, sql_utf8, ctypes.byref(err_ref)
        )
        if not cursor:
            raise _take_error(err_ref)
        try:
            return self._drain_cursor(cursor)
        finally:
            _DLL.reader_cursor_free(cursor)

    def _drain_cursor(self, cursor) -> Tuple[List[dict], List[list]]:
        columns: List[dict] = []
        rows: List[list] = []
        first_batch = True
        while True:
            err_ref = ctypes.POINTER(_LineReaderError)()
            batch = _DLL.reader_cursor_next_batch(
                cursor, ctypes.byref(err_ref)
            )
            if not batch:
                # NULL with err_out unset = stream terminated normally.
                if err_ref:
                    raise _take_error(err_ref)
                return columns, rows
            col_count = int(_DLL.reader_batch_column_count(batch))
            row_count = int(_DLL.reader_batch_row_count(batch))
            # Cache column names on the first batch; QuestDB guarantees they
            # don't change mid-query.
            if first_batch:
                columns = self._collect_column_names(batch, col_count)
                first_batch = False

            # Snapshot any symbol dictionary up front so all SYMBOL columns
            # share one resolution table.
            dict_heap, dict_entries = self._snapshot_symbol_dict(batch)

            decoded_cols: List[Tuple[str, list]] = []
            for col_idx in range(col_count):
                decoded_cols.append(
                    self._decode_column(
                        batch, col_idx, dict_heap, dict_entries
                    )
                )
            # Resolve final type strings (some — e.g. arrays, decimals — are
            # only known after decoding the data) and pivot to per-row.
            for col_idx, (type_str, _values) in enumerate(decoded_cols):
                columns[col_idx]["type"] = type_str
            for r in range(row_count):
                rows.append([decoded_cols[c][1][r] for c in range(col_count)])

    def _collect_column_names(self, batch, col_count: int) -> List[dict]:
        cols: List[dict] = []
        for col_idx in range(col_count):
            name_ptr = _c_char_p()
            name_len = _c_size_t(0)
            err_ref = ctypes.POINTER(_LineReaderError)()
            ok = _DLL.reader_batch_column_name(
                batch,
                col_idx,
                ctypes.byref(name_ptr),
                ctypes.byref(name_len),
                ctypes.byref(err_ref),
            )
            if not ok:
                raise _take_error(err_ref)
            name = (
                ctypes.string_at(name_ptr, name_len.value).decode(
                    "utf-8", "replace"
                )
                if name_ptr.value and name_len.value
                else ""
            )
            cols.append({"name": name, "type": ""})  # type filled in after decode
        return cols

    def _snapshot_symbol_dict(self, batch) -> Tuple[bytes, List[Tuple[int, int]]]:
        dict_struct = _LineReaderSymbolDict()
        err_ref = ctypes.POINTER(_LineReaderError)()
        ok = _DLL.reader_batch_symbol_dict(
            batch, ctypes.byref(dict_struct), ctypes.byref(err_ref)
        )
        if not ok:
            # No SYMBOL columns in the batch is not an error — but the FFI
            # signals it via err_out anyway. Free the error and return empty.
            if err_ref:
                _DLL.reader_error_free(err_ref)
            return b"", []
        heap = _read_bytes(dict_struct.heap, int(dict_struct.heap_len))
        entries: List[Tuple[int, int]] = []
        ec = int(dict_struct.entry_count)
        if ec and dict_struct.entries:
            raw = _read_bytes(dict_struct.entries, ec * 8)
            for i in range(ec):
                offset, length = struct.unpack_from("<II", raw, i * 8)
                entries.append((offset, length))
        return heap, entries

    def _decode_column(
        self, batch, col_idx: int,
        dict_heap: bytes,
        dict_entries: List[Tuple[int, int]],
    ) -> Tuple[str, list]:
        kind_out = _c_uint32(0)
        err_ref = ctypes.POINTER(_LineReaderError)()
        if not _DLL.reader_batch_column_kind(
            batch, col_idx, ctypes.byref(kind_out), ctypes.byref(err_ref)
        ):
            raise _take_error(err_ref)
        kind = int(kind_out.value)
        if kind in (KIND_DOUBLE_ARRAY, KIND_LONG_ARRAY):
            arr = _LineReaderArrayData()
            err_ref = ctypes.POINTER(_LineReaderError)()
            if not _DLL.reader_batch_array_column_data(
                batch, col_idx, ctypes.byref(arr), ctypes.byref(err_ref)
            ):
                raise _take_error(err_ref)
            elem = "DOUBLE" if kind == KIND_DOUBLE_ARRAY else "LONG"
            return _decode_array(arr, elem)
        col = _LineReaderColumnData()
        err_ref = ctypes.POINTER(_LineReaderError)()
        if not _DLL.reader_batch_column_data(
            batch, col_idx, ctypes.byref(col), ctypes.byref(err_ref)
        ):
            raise _take_error(err_ref)
        return _DISPATCH[kind](col, dict_heap, dict_entries) if kind in _SYMBOLLIKE \
            else _DISPATCH[kind](col)


# Kinds that need the symbol dict in their decoder.
_SYMBOLLIKE = {KIND_SYMBOL}

# Decoder dispatch table. SYMBOL is special-cased because it needs the
# batch-level dictionary; everything else takes just the column data.
_DISPATCH = {
    KIND_BOOLEAN: _decode_boolean,
    KIND_BYTE: _decode_byte,
    KIND_SHORT: _decode_short,
    KIND_INT: _decode_int,
    KIND_LONG: _decode_long,
    KIND_FLOAT: _decode_float,
    KIND_DOUBLE: _decode_double,
    KIND_TIMESTAMP: _decode_timestamp_micros,
    KIND_DATE: _decode_date,
    KIND_UUID: _decode_uuid,
    KIND_LONG256: _decode_long256,
    KIND_GEOHASH: _decode_geohash,
    KIND_VARCHAR: _decode_varchar,
    KIND_TIMESTAMP_NANOS: _decode_timestamp_nanos,
    KIND_DECIMAL64: _decode_decimal64,
    KIND_DECIMAL128: _decode_decimal128,
    KIND_DECIMAL256: _decode_decimal256,
    KIND_CHAR: _decode_char,
    KIND_BINARY: _decode_binary,
    KIND_IPV4: _decode_ipv4,
    KIND_SYMBOL: _decode_symbol,
}


def query_table_sorted(conf: str, table_name: str) -> Tuple[List[dict], List[list]]:
    """Convenience: open reader, run `SELECT * FROM '<t>' ORDER BY timestamp`,
    close. Returns the same `(columns, rows)` shape `_query_table_sorted` used
    to return from /exec."""
    sql = f"SELECT * FROM '{table_name}' ORDER BY timestamp"
    with QwpEgressReader(conf) as r:
        return r.select(sql)
