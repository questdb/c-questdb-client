"""ctypes bindings for the Apache Arrow C Data Interface exports.

Wraps `line_reader_cursor_next_arrow_batch` (egress) and
`line_sender_buffer_append_arrow` (ingress) from `libquestdb_client`.
Layout of `ArrowArray` / `ArrowSchema` mirrors the Apache Arrow spec:
<https://arrow.apache.org/docs/format/CDataInterface.html>.
"""

from __future__ import annotations

import ctypes
from typing import Tuple

from questdb_line_sender import (  # type: ignore[attr-defined]
    _DLL,
    c_line_sender_error as _LineSenderError,
    c_line_sender_table_name as _LineSenderTableName,
    c_line_sender_buffer as _LineSenderBuffer,
)
from qwp_egress_reader import (  # type: ignore[attr-defined]
    _LineReaderCursor,
    _LineReaderError,
)


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


DTS_COLUMN = 0
DTS_NOW = 1
DTS_SERVER_NOW = 2


def _setsig(name, restype, *argtypes):
    fn = getattr(_DLL, name)
    fn.restype = restype
    fn.argtypes = list(argtypes)
    return fn


_next_arrow_batch = _setsig(
    "line_reader_cursor_next_arrow_batch",
    ctypes.c_int,
    ctypes.POINTER(_LineReaderCursor),
    ctypes.POINTER(ArrowArray),
    ctypes.POINTER(ArrowSchema),
    ctypes.POINTER(ctypes.POINTER(_LineReaderError)),
)

_append_arrow = _setsig(
    "line_sender_buffer_append_arrow",
    ctypes.c_bool,
    ctypes.POINTER(_LineSenderBuffer),
    _LineSenderTableName,
    ctypes.POINTER(ArrowArray),
    ctypes.POINTER(ArrowSchema),
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.POINTER(_LineSenderError)),
)


def next_arrow_batch(cursor_ptr) -> Tuple[int, ArrowArray, ArrowSchema]:
    """Drive `line_reader_cursor_next_arrow_batch`. On OK, returns the
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


def buffer_append_arrow(
    buf_ptr,
    table_name: _LineSenderTableName,
    array_ptr,
    schema_ptr,
    ts_kind: int,
    ts_column_name: bytes,
) -> None:
    """Drive `line_sender_buffer_append_arrow`. Consumes `array_ptr`'s
    ownership; `schema_ptr` remains the caller's."""
    err_ref = ctypes.POINTER(_LineSenderError)()
    name_bytes = ts_column_name if ts_column_name is not None else b""
    ok = _append_arrow(
        buf_ptr,
        table_name,
        array_ptr,
        schema_ptr,
        ctypes.c_int(ts_kind),
        ctypes.c_char_p(name_bytes if name_bytes else None),
        ctypes.c_size_t(len(name_bytes)),
        ctypes.byref(err_ref),
    )
    if not ok:
        from questdb_line_sender import _c_err_to_py  # type: ignore[attr-defined]
        raise _c_err_to_py(err_ref)


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
