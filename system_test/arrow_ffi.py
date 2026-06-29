"""ctypes bindings for the Apache Arrow C Data Interface exports.

Wraps `reader_cursor_next_arrow_batch` (egress) and
`column_sender_flush_arrow_batch_at_now[_at_column]` (ingress) from
`libquestdb_client`. Layout of `ArrowArray` / `ArrowSchema` mirrors
the Apache Arrow spec:
<https://arrow.apache.org/docs/format/CDataInterface.html>.
"""

from __future__ import annotations

import ctypes
from typing import Optional, Tuple

from questdb_line_sender import (  # type: ignore[attr-defined]
    _DLL,
    SenderError as _SenderError,
    c_line_sender_error as _LineSenderError,
    c_line_sender_error_p as _LineSenderErrorPtr,
    c_line_sender_table_name as _LineSenderTableName,
    c_line_sender_buffer as _LineSenderBuffer,
)
from qwp_egress_reader import (  # type: ignore[attr-defined]
    _LineReaderCursor,
    _LineReaderError,
)


# Opaque handles defined in `include/questdb/ingress/column_sender.h`.
class _QuestdbDb(ctypes.Structure):
    """Opaque `questdb_db*` (connection pool)."""


class _QwpwsConn(ctypes.Structure):
    """Opaque `column_sender*` (borrowed pooled connection)."""


class _DirectColumnSender(ctypes.Structure):
    """Opaque `direct_column_sender*` (borrowed pipelined connection)."""


class ArrowSenderError(_SenderError):
    """`SenderError` carrying the `line_sender_error_code` discriminant."""

    def __init__(self, message: str, code: int, qwp_ws_error=None) -> None:
        super().__init__(message, qwp_ws_error)
        self.code = code

    def __str__(self) -> str:
        base = super().__str__()
        return f"[code={self.code}] {base}"


def _take_sender_error(err_ptr) -> ArrowSenderError:
    code = int(_DLL.line_sender_error_get_code(err_ptr))
    c_len = ctypes.c_size_t(0)
    raw = _DLL.line_sender_error_msg(err_ptr, ctypes.byref(c_len))
    msg = (
        ctypes.string_at(raw, c_len.value).decode("utf-8", "replace")
        if raw and c_len.value
        else ""
    )
    from questdb_line_sender import _qwpws_error_from_sender_error  # late bind
    qwp_view = _qwpws_error_from_sender_error(err_ptr)
    _DLL.line_sender_error_free(err_ptr)
    return ArrowSenderError(msg, code, qwp_view)


class ArrowArray(ctypes.Structure):
    pass


ArrowArray._fields_ = [
    ("length", ctypes.c_int64),
    ("null_count", ctypes.c_int64),
    ("offset", ctypes.c_int64),
    ("n_buffers", ctypes.c_int64),
    ("n_children", ctypes.c_int64),
    ("buffers", ctypes.POINTER(ctypes.c_void_p)),
    ("children", ctypes.POINTER(ctypes.POINTER(ArrowArray))),
    ("dictionary", ctypes.POINTER(ArrowArray)),
    ("release", ctypes.CFUNCTYPE(None, ctypes.POINTER(ArrowArray))),
    ("private_data", ctypes.c_void_p),
]


class ArrowSchema(ctypes.Structure):
    pass


ArrowSchema._fields_ = [
    ("format", ctypes.c_char_p),
    ("name", ctypes.c_char_p),
    ("metadata", ctypes.c_char_p),
    ("flags", ctypes.c_int64),
    ("n_children", ctypes.c_int64),
    ("children", ctypes.POINTER(ctypes.POINTER(ArrowSchema))),
    ("dictionary", ctypes.POINTER(ArrowSchema)),
    ("release", ctypes.CFUNCTYPE(None, ctypes.POINTER(ArrowSchema))),
    ("private_data", ctypes.c_void_p),
]


NEXT_ARROW_BATCH_OK = 0
NEXT_ARROW_BATCH_END = 1
NEXT_ARROW_BATCH_ERROR = 2


class SenderErrorCode:
    """`line_sender_error_code` discriminants. Pinned in
    `questdb-rs-ffi/src/lib.rs::line_sender_error_code_discriminants_are_abi_stable`."""
    COULD_NOT_RESOLVE_ADDR = 0
    INVALID_API_CALL = 1
    SOCKET_ERROR = 2
    INVALID_UTF8 = 3
    INVALID_NAME = 4
    INVALID_TIMESTAMP = 5
    AUTH_ERROR = 6
    TLS_ERROR = 7
    HTTP_NOT_SUPPORTED = 8
    SERVER_FLUSH_ERROR = 9
    CONFIG_ERROR = 10
    ARRAY_ERROR = 11
    PROTOCOL_VERSION_ERROR = 12
    INVALID_DECIMAL = 13
    SERVER_REJECTION = 14
    ARROW_UNSUPPORTED_COLUMN_KIND = 15
    ARROW_INGEST = 16


class ReaderErrorCode:
    """`reader_error_code` discriminants. Pinned in
    `questdb-rs-ffi/src/egress.rs::reader_error_code`."""
    COULD_NOT_RESOLVE_ADDR = 0
    CONFIG_ERROR = 1
    INVALID_API_CALL = 2
    SOCKET_ERROR = 3
    TLS_ERROR = 4
    HANDSHAKE_ERROR = 5
    AUTH_ERROR = 6
    UNSUPPORTED_SERVER = 7
    ROLE_MISMATCH = 8
    PROTOCOL_ERROR = 9
    INVALID_UTF8 = 10
    INVALID_BIND = 11
    SERVER_SCHEMA_MISMATCH = 14
    SERVER_PARSE_ERROR = 15
    SERVER_INTERNAL_ERROR = 16
    SERVER_SECURITY_ERROR = 17
    LIMIT_EXCEEDED = 18
    SERVER_LIMIT_EXCEEDED = 19
    CANCELLED = 20
    FAILOVER_WOULD_DUPLICATE = 21
    SCHEMA_DRIFT = 22
    NO_SCHEMA = 23
    ARROW_EXPORT = 24


def _setsig(name, restype, *argtypes):
    fn = getattr(_DLL, name)
    fn.restype = restype
    fn.argtypes = list(argtypes)
    return fn


_next_arrow_batch = _setsig(
    "reader_cursor_next_arrow_batch",
    ctypes.c_int,
    ctypes.POINTER(_LineReaderCursor),
    ctypes.POINTER(ArrowArray),
    ctypes.POINTER(ArrowSchema),
    ctypes.POINTER(ctypes.POINTER(_LineReaderError)),
)

from questdb_line_sender import c_line_sender_column_name  # noqa: E402

# Conn-pool lifecycle (column_sender.h).
_db_connect = _setsig(
    "questdb_db_connect",
    ctypes.POINTER(_QuestdbDb),
    ctypes.c_char_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.POINTER(_LineSenderError)),
)

_db_close = _setsig(
    "questdb_db_close",
    None,
    ctypes.POINTER(_QuestdbDb),
)

_db_borrow_conn = _setsig(
    "questdb_db_borrow_sf_column_sender",
    ctypes.POINTER(_QwpwsConn),
    ctypes.POINTER(_QuestdbDb),
    ctypes.POINTER(ctypes.POINTER(_LineSenderError)),
)

_db_borrow_conn_with_retry = _setsig(
    "questdb_db_borrow_sf_column_sender_with_retry",
    ctypes.POINTER(_QwpwsConn),
    ctypes.POINTER(_QuestdbDb),
    ctypes.c_uint64,
    ctypes.POINTER(ctypes.POINTER(_LineSenderError)),
)

_db_borrow_direct_conn_with_retry = _setsig(
    "questdb_db_borrow_direct_column_sender_with_retry",
    ctypes.POINTER(_DirectColumnSender),
    ctypes.POINTER(_QuestdbDb),
    ctypes.c_uint64,
    ctypes.POINTER(ctypes.POINTER(_LineSenderError)),
)

_db_return_conn = _setsig(
    "questdb_db_return_sf_column_sender",
    None,
    ctypes.POINTER(_QuestdbDb),
    ctypes.POINTER(_QwpwsConn),
)

_db_drop_conn = _setsig(
    "questdb_db_drop_sf_column_sender",
    None,
    ctypes.POINTER(_QuestdbDb),
    ctypes.POINTER(_QwpwsConn),
)

_conn_must_close = _setsig(
    "sf_column_sender_must_close",
    ctypes.c_bool,
    ctypes.POINTER(_QwpwsConn),
)

class _ColumnSenderArrowOverride(ctypes.Structure):
    _fields_ = [
        ("column", ctypes.c_char_p),
        ("column_len", ctypes.c_size_t),
        ("kind", ctypes.c_uint32),
        ("arg", ctypes.c_uint32),
    ]


# Conn-level Arrow batch flush.
_flush_arrow_batch = _setsig(
    "sf_column_sender_flush_arrow_batch_at_now",
    ctypes.c_bool,
    ctypes.POINTER(_QwpwsConn),
    _LineSenderTableName,
    ctypes.POINTER(ArrowArray),
    ctypes.POINTER(ArrowSchema),
    ctypes.POINTER(_ColumnSenderArrowOverride),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.POINTER(_LineSenderError)),
)

_flush_arrow_batch_at_column = _setsig(
    "sf_column_sender_flush_arrow_batch_at_column",
    ctypes.c_bool,
    ctypes.POINTER(_QwpwsConn),
    _LineSenderTableName,
    ctypes.POINTER(ArrowArray),
    ctypes.POINTER(ArrowSchema),
    c_line_sender_column_name,
    ctypes.POINTER(_ColumnSenderArrowOverride),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.POINTER(_LineSenderError)),
)


# Sync after deferred flushes (mirrors `column_sender_sync` in
# `column_sender.h`). Acknowledgement levels:
#   0 → wait for WAL-commit
#   1 → wait for object-store durability watermarks
_column_sender_sync = _setsig(
    "sf_column_sender_wait",
    ctypes.c_bool,
    ctypes.POINTER(_QwpwsConn),
    ctypes.c_uint32,
    ctypes.c_uint64,
    ctypes.POINTER(ctypes.POINTER(_LineSenderError)),
)


def next_arrow_batch(cursor_ptr) -> Tuple[int, ArrowArray, ArrowSchema]:
    """Drive `reader_cursor_next_arrow_batch`. On OK, returns the
    populated structs; the caller becomes responsible for invoking the
    `release` callback inside each struct."""
    arr = ArrowArray()
    sch = ArrowSchema()
    err_ref = ctypes.POINTER(_LineReaderError)()
    rc = _next_arrow_batch(
        cursor_ptr,
        ctypes.byref(arr),
        ctypes.byref(sch),
        ctypes.byref(err_ref),
    )
    if rc == NEXT_ARROW_BATCH_ERROR:
        from qwp_egress_reader import _take_error  # type: ignore[attr-defined]
        raise _take_error(err_ref)
    return rc, arr, sch


def conn_flush_arrow_batch(
    conn_ptr,
    table_name: _LineSenderTableName,
    array_ptr,
    schema_ptr,
    ts_column_name: Optional[bytes] = None,
) -> None:
    """Drive `column_sender_flush_arrow_batch_at_now` (or its
    `_at_column` variant when `ts_column_name` is set). Consumes `array_ptr`'s
    ownership; `schema_ptr` remains the caller's."""
    err_ref = ctypes.POINTER(_LineSenderError)()
    overrides_ptr = ctypes.POINTER(_ColumnSenderArrowOverride)()
    if ts_column_name:
        ts_col = c_line_sender_column_name(
            len(ts_column_name),
            ctypes.c_char_p(ts_column_name),
        )
        ok = _flush_arrow_batch_at_column(
            conn_ptr,
            table_name,
            array_ptr,
            schema_ptr,
            ts_col,
            overrides_ptr,
            0,
            ctypes.byref(err_ref),
        )
    else:
        ok = _flush_arrow_batch(
            conn_ptr,
            table_name,
            array_ptr,
            schema_ptr,
            overrides_ptr,
            0,
            ctypes.byref(err_ref),
        )
    if not ok:
        raise _take_sender_error(err_ref)


def db_connect(conf: bytes):
    """Open a `questdb_db*` connection pool from a conf string."""
    err_ref = ctypes.POINTER(_LineSenderError)()
    db = _db_connect(conf, len(conf), ctypes.byref(err_ref))
    if not db:
        raise _take_sender_error(err_ref)
    return db


def db_close(db_ptr) -> None:
    if db_ptr:
        _db_close(db_ptr)


def db_borrow_conn(db_ptr):
    """Borrow a pooled `column_sender*`."""
    err_ref = ctypes.POINTER(_LineSenderError)()
    conn = _db_borrow_conn(db_ptr, ctypes.byref(err_ref))
    if not conn:
        raise _take_sender_error(err_ref)
    return conn


def db_borrow_conn_with_retry(db_ptr, budget_ms: int):
    """Borrow a store-and-forward `column_sender*`, retrying the connect
    within `budget_ms` (`0` makes a single attempt)."""
    err_ref = ctypes.POINTER(_LineSenderError)()
    conn = _db_borrow_conn_with_retry(db_ptr, budget_ms, ctypes.byref(err_ref))
    if not conn:
        raise _take_sender_error(err_ref)
    return conn


def db_borrow_direct_conn_with_retry(db_ptr, budget_ms: int):
    """Borrow a pipelined (Direct) `direct_column_sender*`, retrying the
    connect within `budget_ms` (`0` makes a single attempt)."""
    err_ref = ctypes.POINTER(_LineSenderError)()
    conn = _db_borrow_direct_conn_with_retry(db_ptr, budget_ms, ctypes.byref(err_ref))
    if not conn:
        raise _take_sender_error(err_ref)
    return conn


def db_return_conn(db_ptr, conn_ptr) -> None:
    if db_ptr and conn_ptr:
        _db_return_conn(db_ptr, conn_ptr)


def db_drop_conn(db_ptr, conn_ptr) -> None:
    if db_ptr and conn_ptr:
        _db_drop_conn(db_ptr, conn_ptr)


def conn_must_close(conn_ptr) -> bool:
    return bool(_conn_must_close(conn_ptr))


def column_sender_sync(
    conn_ptr, ack_level: int = 0, timeout_millis: int = 0
) -> None:
    err_ref = ctypes.POINTER(_LineSenderError)()
    ok = _column_sender_sync(
        conn_ptr, ack_level, timeout_millis, ctypes.byref(err_ref))
    if not ok:
        raise _take_sender_error(err_ref)


def pyarrow_export_record_batch(record_batch) -> Tuple[ArrowArray, ArrowSchema]:
    """Materialize a pyarrow.RecordBatch as ArrowArray + ArrowSchema using
    pyarrow's `_export_to_c`. Wraps the batch as a StructArray first because
    the Arrow C Data Interface represents a record batch as a struct array."""
    import pyarrow as pa
    struct_arr = pa.StructArray.from_arrays(
        record_batch.columns,
        fields=record_batch.schema,
    )
    arr = ArrowArray()
    sch = ArrowSchema()
    arr_addr = ctypes.addressof(arr)
    sch_addr = ctypes.addressof(sch)
    struct_arr._export_to_c(arr_addr, sch_addr)
    return arr, sch


def pyarrow_import_record_batch(arr: ArrowArray, sch: ArrowSchema):
    """Reverse of `pyarrow_export_record_batch`. Consumes the structs."""
    import pyarrow as pa
    struct_arr = pa.Array._import_from_c(ctypes.addressof(arr), ctypes.addressof(sch))
    return pa.RecordBatch.from_struct_array(struct_arr)
