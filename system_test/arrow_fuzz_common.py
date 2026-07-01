from __future__ import annotations

import contextlib
import ctypes
import math
import os
import shutil
import struct
import sys
import tempfile
import time
import unittest
import urllib.error
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple

import pyarrow as pa

import qwp_ws_fuzz
from qwp_ws_fuzz import Rng, derive_master_seed, format_seed

from arrow_ffi import (
    ArrowArray,
    ArrowSchema,
    NEXT_ARROW_BATCH_END,
    NEXT_ARROW_BATCH_ERROR,
    NEXT_ARROW_BATCH_OK,
    column_sender_sync,
    conn_flush_arrow_batch,
    db_borrow_conn,
    db_close,
    db_connect,
    db_return_conn,
    next_arrow_batch,
    pyarrow_export_record_batch,
    pyarrow_import_record_batch,
)
from qwp_egress_reader import (
    ReaderError,
    _DLL,
    _LineReaderError,
    _take_error,
    _utf8,
)
from questdb_line_sender import (
    Buffer,
    Sender,
    SenderError,
    _table_name as _c_table_name,
)

__all__ = [
    "Rng",
    "derive_master_seed",
    "format_seed",
    "ReaderError",
    "SenderError",
    "ArrowFuzzBase",
    "KIND_REGISTRY",
    "KindSpec",
    "EDGE_INTS_I8",
    "EDGE_INTS_I16",
    "EDGE_INTS_I32",
    "EDGE_INTS_I64",
    "EDGE_INTS_U16",
    "EDGE_INTS_U32",
    "EDGE_FLOATS",
    "EDGE_STRINGS",
    "EDGE_GEOHASH_BITS",
    "arrow_cursor",
    "existing_sender",
    "borrowed_column_sender",
    "temp_sf_dir",
    "sfa_file_count",
    "wait_for_rows",
    "make_table_name",
    "drop_table_safe",
    "egress_conf",
    "ingress_conf",
    "ingest_via_arrow",
    "read_back_arrow_batches",
    "read_back_arrow_concat",
    "assert_pyarrow_records_equal",
    "get_live_fixture",
]

def get_live_fixture(testcase: unittest.TestCase):
    from test import (
        QDB_FIXTURE,
        QuestDbDockerFixture,
        QuestDbExternalFixture,
        QuestDbFixture,
    )
    if not isinstance(
        QDB_FIXTURE,
        (QuestDbFixture, QuestDbExternalFixture, QuestDbDockerFixture),
    ):
        testcase.skipTest("requires a live QuestDB fixture")
    return QDB_FIXTURE

def egress_conf(fixture) -> str:
    return f"ws::addr={fixture.host}:{fixture.http_server_port};"

def ingress_conf(fixture, **extras: str) -> str:
    parts = [f"qwpws::addr={fixture.host}:{fixture.http_server_port};"]
    for k, v in extras.items():
        parts.append(f"{k}={v};")
    return "".join(parts)

@contextlib.contextmanager
def arrow_cursor(fixture, sql: str):
    from test import skip_if_unsupported_qwp_ws_fixture
    conf_utf8 = _utf8(egress_conf(fixture))
    err_ref = ctypes.POINTER(_LineReaderError)()
    reader = _DLL.reader_from_conf(conf_utf8, ctypes.byref(err_ref))
    if not reader:
        err = _take_error(err_ref)
        skip_if_unsupported_qwp_ws_fixture(err, fixture)
        raise err
    try:
        sql_utf8 = _utf8(sql)
        err_ref = ctypes.POINTER(_LineReaderError)()
        cursor = _DLL.reader_execute(reader, sql_utf8, ctypes.byref(err_ref))
        if not cursor:
            raise _take_error(err_ref)
        try:
            yield cursor
        finally:
            _DLL.reader_cursor_free(cursor)
    finally:
        _DLL.reader_close(reader)

@contextlib.contextmanager
def existing_sender(fixture, *, sender_id: Optional[str] = None,
                    **conf_extras: str):
    from test import skip_if_unsupported_qwp_ws_fixture
    with tempfile.TemporaryDirectory(prefix="arrow_sfa_") as sf_dir:
        sid = sender_id or f"arrow-{uuid.uuid4().hex[:8]}"
        conf = ingress_conf(fixture, sender_id=sid, sf_dir=sf_dir,
                            **conf_extras)
        sender = Sender.from_conf(conf)
        try:
            try:
                sender.connect()
            except SenderError as e:
                skip_if_unsupported_qwp_ws_fixture(e, fixture)
                raise
            sender._buffer = Buffer.from_sender(sender._impl)
            yield sender
            sender.flush()
            sender.close_drain()
        finally:
            sender.close(flush=False)

@contextlib.contextmanager
def temp_sf_dir(prefix: str = "arrow_"):
    d = tempfile.mkdtemp(prefix=prefix)
    try:
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)

def sfa_file_count(sf_dir: str, sender_id: str) -> int:
    slot_dir = os.path.join(sf_dir, sender_id)
    if not os.path.isdir(slot_dir):
        return 0
    return sum(1 for name in os.listdir(slot_dir) if name.endswith(".sfa"))

def wait_for_rows(
    fixture, table: str, expected: int, *, timeout: float = 20.0
) -> int:
    import json
    from fixture import QueryError
    deadline = time.monotonic() + timeout
    delay = 0.02
    last_seen = -1
    last_err: Optional[BaseException] = None
    while time.monotonic() < deadline:
        try:
            resp = fixture.http_sql_query(f"select count() from '{table}'")
            last_seen = int(resp["dataset"][0][0])
            if last_seen >= expected:
                return last_seen
        except (urllib.error.URLError, ConnectionError,
                json.JSONDecodeError, QueryError) as e:
            last_err = e
        time.sleep(delay)
        delay = min(delay * 1.5, 0.5)
    raise AssertionError(
        f"timed out waiting for {expected} rows in {table}; "
        f"last_seen={last_seen}, last_err={last_err!r}"
    )

def make_table_name(prefix: str, rnd: Rng) -> str:
    return f"{prefix}_{rnd.next_int(2**32):08x}"

def exec_ddl(fixture, sql: str) -> None:
    """Run a DDL statement, tolerating QuestDB versions that return an
    empty HTTP body on success (which makes the fixture's strict JSON
    parse explode)."""
    import json
    try:
        fixture.http_sql_query(sql)
    except json.JSONDecodeError:
        pass


def drop_table_safe(fixture, table: str) -> None:
    try:
        exec_ddl(fixture, f"DROP TABLE IF EXISTS '{table}'")
    except Exception as e:
        sys.stderr.write(
            f"[arrow_fuzz_common] table drop failed for {table!r}: {e!r}\n"
        )

@contextlib.contextmanager
def borrowed_column_sender(fixture, *, sync_on_exit: bool = True, **conf_extras: str):
    """Open a `questdb_db*` pool from the fixture, borrow one
    `column_sender*`, and yield the raw conn pointer. Returns the conn
    to the pool on exit (or drops it if the conn latched as terminal)
    and closes the pool. Set `sync_on_exit=False` when a test needs to
    assert the exact `column_sender_sync` error."""
    from test import skip_if_unsupported_qwp_ws_fixture
    conf = ingress_conf(fixture, **conf_extras).encode("utf-8")
    try:
        db = db_connect(conf)
    except SenderError as e:
        skip_if_unsupported_qwp_ws_fixture(e, fixture)
        raise
    try:
        try:
            conn = db_borrow_conn(db)
        except SenderError as e:
            skip_if_unsupported_qwp_ws_fixture(e, fixture)
            raise
        try:
            yield conn
            if sync_on_exit:
                try:
                    column_sender_sync(conn, 0)
                except SenderError:
                    pass
        finally:
            db_return_conn(db, conn)
    finally:
        db_close(db)


def ingest_via_arrow(
    fixture,
    table: str,
    record_batch: pa.RecordBatch,
    *,
    ts_col: Optional[bytes] = b"ts",
    sender_conf_extras: Optional[Dict[str, str]] = None,
    slice_window: Optional[Tuple[int, int]] = None,
) -> None:
    """Ingest one RecordBatch through `column_sender_flush_arrow_batch_at_column`
    (when `ts_col` is set) or `column_sender_flush_arrow_batch_at_now`
    (when `ts_col` is None — the server stamps each row on arrival).

    When `slice_window=(offset, length)` is supplied the batch is sliced to
    that window *before* the C Data Interface export. A sliced pyarrow
    array carries a non-zero `offset` that survives the FFI boundary, so
    the Rust encoder receives arrays with `offset() != 0` — exercising the
    offset/slice-sensitive paths (bit-packed booleans, re-based varlen
    offset tables, FixedSizeBinary `offset * elem` value-data slicing,
    designated-timestamp slicing) end-to-end against the live server.
    Nothing else in `system_test/` produced non-zero-offset arrays before,
    so this is the only system-level coverage of that surface."""
    extras = sender_conf_extras or {}
    if slice_window is not None:
        window_offset, window_length = slice_window
        record_batch = record_batch.slice(window_offset, window_length)
    with borrowed_column_sender(fixture, **extras) as conn:
        table_name = _c_table_name(table)
        arr, sch = pyarrow_export_record_batch(record_batch)
        try:
            conn_flush_arrow_batch(
                conn, table_name,
                ctypes.byref(arr), ctypes.byref(sch),
                ts_column_name=ts_col,
            )
        finally:
            if sch.release:
                sch.release(ctypes.byref(sch))

def read_back_arrow_batches(fixture, sql: str) -> List[pa.RecordBatch]:
    batches: List[pa.RecordBatch] = []
    with arrow_cursor(fixture, sql) as cursor:
        while True:
            rc, arr, sch = next_arrow_batch(cursor)
            if rc == NEXT_ARROW_BATCH_END:
                break
            if rc != NEXT_ARROW_BATCH_OK:
                raise AssertionError(f"unexpected next_arrow_batch rc={rc}")
            batches.append(pyarrow_import_record_batch(arr, sch))
    return batches

def read_back_arrow_concat(fixture, sql: str) -> pa.RecordBatch:
    batches = read_back_arrow_batches(fixture, sql)
    if not batches:
        raise AssertionError(f"no Arrow batches returned for sql={sql!r}")
    if len(batches) == 1:
        return batches[0]
    table = pa.Table.from_batches(batches).combine_chunks()
    chunks = table.to_batches()
    if len(chunks) != 1:
        raise AssertionError(
            f"combine_chunks() returned {len(chunks)} batches, expected 1"
        )
    return chunks[0]

def assert_pyarrow_records_equal(
    testcase: unittest.TestCase,
    expected: pa.RecordBatch,
    actual: pa.RecordBatch,
    kinds: List[Tuple[str, "KindSpec"]],
    *,
    label: str = "",
) -> None:
    """Compare row-by-row, dispatching to KindSpec.compare for tolerant kinds."""
    testcase.assertEqual(
        actual.num_rows, expected.num_rows,
        f"row count {label}: got {actual.num_rows} vs expected {expected.num_rows}"
    )
    for col_idx, (col_name, spec) in enumerate(kinds):
        exp_col = expected.column(col_idx)
        act_col = actual.column(col_idx)
        for r in range(expected.num_rows):
            ev = exp_col[r].as_py()
            av = act_col[r].as_py()
            if not spec.compare(av, ev):
                testcase.fail(
                    f"{label} kind={spec.name} col={col_name} row={r}: "
                    f"expected {ev!r}, got {av!r}"
                )

EDGE_INTS_I8 = [-128, -1, 0, 1, 127]
EDGE_INTS_I16 = [-32768, -1, 0, 1, 32767]
EDGE_INTS_I32 = [-(1 << 31), -1, 0, 1, (1 << 31) - 1]
EDGE_INTS_I64 = [-(1 << 63), -1, 0, 1, (1 << 63) - 1]
EDGE_INTS_U16 = [0, 1, 0x7FFF, 0xFFFE, 0xFFFF]
EDGE_INTS_U32 = [0, 1, 0x7FFF_FFFF, 0xFFFF_FFFE, 0xFFFF_FFFF]

EDGE_FLOATS = [
    0.0,
    -0.0,
    1.0,
    -1.0,
    float("nan"),
    float("inf"),
    float("-inf"),
    sys.float_info.min,
    sys.float_info.max,
    -sys.float_info.max,
    5e-324,
]

EDGE_STRINGS = [
    "",
    "a",
    "ascii",
    "日本語",
    "🚀🌟",
    "​﻿",
    "x" * 4096,
]

EDGE_GEOHASH_BITS = [1, 5, 32, 60]

def all_valid_mask(n: int) -> List[bool]:
    return [True] * n

def all_null_mask(n: int) -> List[bool]:
    return [False] * n

def partial_null_mask(rnd: Rng, n: int, *, null_p: float = 0.2) -> List[bool]:
    return [rnd.next_int(1000) >= int(null_p * 1000) for _ in range(n)]

def _apply_mask(values: List[Any], mask: List[bool]) -> List[Any]:
    return [v if keep else None for v, keep in zip(values, mask)]

def _gen_bool(rnd: Rng, n: int, mask, *, edge: bool) -> List[Any]:
    vs = [rnd.next_boolean() for _ in range(n)]
    if edge:
        for i in range(min(n, 2)):
            vs[i] = bool(i)
    return _apply_mask(vs, mask)

def _gen_signed_int(rnd: Rng, n: int, mask, *, edge: bool, corpus, bound) -> List[Any]:
    vs = [rnd.next_int(2 * bound) - bound for _ in range(n)]
    if edge:
        for i, v in enumerate(corpus):
            if i < n:
                vs[i] = v
    return _apply_mask(vs, mask)

def _gen_unsigned_int(rnd: Rng, n: int, mask, *, edge: bool, corpus, ubound) -> List[Any]:
    vs = [rnd.next_int(ubound) for _ in range(n)]
    if edge:
        for i, v in enumerate(corpus):
            if i < n:
                vs[i] = v
    return _apply_mask(vs, mask)

def _gen_float(rnd: Rng, n: int, mask, *, edge: bool, dtype: str) -> List[Any]:
    span = 1e6 if dtype == "double" else 1e3
    vs = [(rnd.next_int(2_000_000) - 1_000_000) / 1_000_000.0 * span for _ in range(n)]
    if edge:
        for i, v in enumerate(EDGE_FLOATS):
            if i < n:
                vs[i] = float(v) if dtype == "double" else _f32_round(v)
    return _apply_mask(vs, mask)

def _f32_round(v: float) -> float:
    if v != v:
        return v
    try:
        return struct.unpack("<f", struct.pack("<f", v))[0]
    except OverflowError:
        return math.copysign(math.inf, v)

def _gen_string(rnd: Rng, n: int, mask, *, edge: bool) -> List[Any]:
    def one() -> str:
        length = rnd.next_int(16)
        return "".join(chr(0x61 + rnd.next_int(26)) for _ in range(length))
    vs = [one() for _ in range(n)]
    if edge:
        for i, v in enumerate(EDGE_STRINGS):
            if i < n:
                vs[i] = v
    return _apply_mask(vs, mask)

def _gen_binary(rnd: Rng, n: int, mask, *, edge: bool) -> List[Any]:
    def one() -> bytes:
        length = rnd.next_int(32)
        return bytes(rnd.next_int(256) for _ in range(length))
    vs = [one() for _ in range(n)]
    if edge:
        if n > 0:
            vs[0] = b""
        if n > 1:
            vs[1] = b"\x00" * 256
    return _apply_mask(vs, mask)

def _gen_fixed_bytes(rnd: Rng, n: int, mask, *, edge: bool, width: int) -> List[Any]:
    vs = [bytes(rnd.next_int(256) for _ in range(width)) for _ in range(n)]
    if edge:
        if n > 0:
            vs[0] = b"\x00" * width
        if n > 1:
            vs[1] = b"\xff" * width
    return _apply_mask(vs, mask)

def _gen_uuid_lo_hi(rnd: Rng, n: int, mask, *, edge: bool) -> List[Any]:
    vs = [(rnd.next_long() & ((1 << 64) - 1), rnd.next_long() & ((1 << 64) - 1))
          for _ in range(n)]
    if edge:
        if n > 0:
            vs[0] = (0, 0)
        if n > 1:
            vs[1] = ((1 << 64) - 1, (1 << 64) - 1)
    return _apply_mask(vs, mask)

def _gen_char_codepoints(rnd: Rng, n: int, mask, *, edge: bool) -> List[Any]:
    vs = [0x41 + rnd.next_int(26) for _ in range(n)]
    if edge:
        if n > 0:
            vs[0] = 0
        if n > 1:
            vs[1] = 0xFFFF
    return _apply_mask(vs, mask)

def _gen_ipv4(rnd: Rng, n: int, mask, *, edge: bool) -> List[Any]:
    vs = [rnd.next_int(0xFFFF_FFFF) for _ in range(n)]
    if edge:
        if n > 0:
            vs[0] = 0
        if n > 1:
            vs[1] = 0x7F00_0001  # loopback
        if n > 2:
            vs[2] = 0xFFFF_FFFF
    return _apply_mask(vs, mask)

def _gen_date_ms(rnd: Rng, n: int, mask, *, edge: bool) -> List[Any]:
    base = 1_700_000_000_000
    vs = [base + rnd.next_int(86_400_000) for _ in range(n)]
    if edge:
        if n > 0:
            vs[0] = 0
        if n > 1:
            vs[1] = base
    return _apply_mask(vs, mask)

def _gen_ts_us(rnd: Rng, n: int, mask, *, edge: bool, base: int) -> List[Any]:
    vs = [base + rnd.next_int(1_000_000) for _ in range(n)]
    return _apply_mask(vs, mask)

def _gen_ts_ns(rnd: Rng, n: int, mask, *, edge: bool, base: int) -> List[Any]:
    vs = [base + rnd.next_int(1_000_000_000) for _ in range(n)]
    return _apply_mask(vs, mask)

def _gen_symbol(rnd: Rng, n: int, mask, *, edge: bool) -> List[Any]:
    palette = ["AAPL", "MSFT", "GOOG", "AMZN", "NVDA"]
    vs = [palette[rnd.next_int(len(palette))] for _ in range(n)]
    if edge:
        if n > 0:
            vs[0] = ""
        if n > 1:
            vs[1] = palette[0]
    return _apply_mask(vs, mask)

def _gen_geohash(rnd: Rng, n: int, mask, *, edge: bool, bits: int) -> List[Any]:
    cap = (1 << bits) - 1
    vs = [rnd.next_int(cap + 1) for _ in range(n)]
    if edge:
        if n > 0:
            vs[0] = 0
        if n > 1:
            vs[1] = cap
    return _apply_mask(vs, mask)

def _gen_decimal_int(rnd: Rng, n: int, mask, *, edge: bool, bound: int) -> List[Any]:
    vs = [rnd.next_int(2 * bound + 1) - bound for _ in range(n)]
    if edge:
        if n > 0:
            vs[0] = 0
        if n > 1:
            vs[1] = bound
        if n > 2:
            vs[2] = -bound
    return _apply_mask(vs, mask)

def _gen_double_array_1d(rnd: Rng, n: int, mask, *, edge: bool) -> List[Any]:
    def one() -> List[float]:
        ln = rnd.next_int(5) + 1
        return [(rnd.next_int(2000) - 1000) / 100.0 for _ in range(ln)]
    vs = [one() for _ in range(n)]
    if edge:
        if n > 0:
            vs[0] = []
        if n > 1:
            vs[1] = [float("nan"), float("inf"), -0.0]
    return _apply_mask(vs, mask)

def _gen_double_array_2d(rnd: Rng, n: int, mask, *, edge: bool) -> List[Any]:
    def one() -> List[List[float]]:
        rows = rnd.next_int(3) + 1
        cols = rnd.next_int(3) + 1
        return [
            [(rnd.next_int(2000) - 1000) / 100.0 for _ in range(cols)]
            for _ in range(rows)
        ]
    vs = [one() for _ in range(n)]
    if edge:
        if n > 0:
            vs[0] = [[1.0]]
    return _apply_mask(vs, mask)

def _gen_double_array_3d(rnd: Rng, n: int, mask, *, edge: bool) -> List[Any]:
    def one():
        a, b, c = (rnd.next_int(2) + 1 for _ in range(3))
        return [
            [
                [(rnd.next_int(1000) - 500) / 100.0 for _ in range(c)]
                for _ in range(b)
            ]
            for _ in range(a)
        ]
    vs = [one() for _ in range(n)]
    return _apply_mask(vs, mask)

def _gen_long_array_1d(rnd: Rng, n: int, mask, *, edge: bool) -> List[Any]:
    def one() -> List[int]:
        ln = rnd.next_int(5) + 1
        return [rnd.next_int(1_000_000) - 500_000 for _ in range(ln)]
    vs = [one() for _ in range(n)]
    if edge:
        if n > 0:
            vs[0] = []
        if n > 1:
            vs[1] = [-(1 << 63), 0, (1 << 63) - 1]
    return _apply_mask(vs, mask)

def _arr_bool(values, *, params) -> pa.Array:
    return pa.array(values, type=pa.bool_())

def _arr_int(values, *, params) -> pa.Array:
    return pa.array(values, type=params["arrow_dtype"])

def _arr_float(values, *, params) -> pa.Array:
    return pa.array(values, type=params["arrow_dtype"])

def _arr_uint16(values, *, params) -> pa.Array:
    return pa.array(values, type=pa.uint16())

def _arr_uint32(values, *, params) -> pa.Array:
    return pa.array(values, type=pa.uint32())

def _arr_string(values, *, params) -> pa.Array:
    return pa.array(values, type=pa.string())

def _arr_binary(values, *, params) -> pa.Array:
    return pa.array(values, type=pa.binary())

def _arr_fsb(values, *, params) -> pa.Array:
    return pa.array(values, type=pa.binary(params["width"]))

def _arr_uuid_lo_hi(values, *, params) -> pa.Array:
    payload: List[Optional[bytes]] = []
    for v in values:
        if v is None:
            payload.append(None)
        else:
            lo, hi = v
            payload.append(lo.to_bytes(8, "little") + hi.to_bytes(8, "little"))
    return pa.array(payload, type=pa.binary(16))

def _arr_timestamp(values, *, params) -> pa.Array:
    return pa.array(values, type=pa.timestamp(params["unit"], tz="UTC"))

def _arr_symbol(values, *, params) -> pa.Array:
    seen: Dict[str, int] = {}
    dict_vals: List[str] = []
    idxs: List[Optional[int]] = []
    for v in values:
        if v is None:
            idxs.append(None)
        else:
            if v not in seen:
                seen[v] = len(dict_vals)
                dict_vals.append(v)
            idxs.append(seen[v])
    idx_arr = pa.array(idxs, type=pa.uint32())
    dict_arr = pa.array(dict_vals, type=pa.string())
    return pa.DictionaryArray.from_arrays(idx_arr, dict_arr)

def _arr_geohash_int(values, *, params) -> pa.Array:
    return pa.array(values, type=params["arrow_dtype"])

def _unscaled_to_decimal(values, scale):
    from decimal import Decimal
    return [None if v is None else Decimal(int(v)).scaleb(-scale) for v in values]

def _arr_decimal64(values, *, params) -> pa.Array:
    scale = params["scale"]
    precision = params.get("precision", 18)
    factory = getattr(pa, "decimal64", None)
    dtype = factory(precision, scale) if factory else pa.decimal128(precision, scale)
    return pa.array(_unscaled_to_decimal(values, scale), type=dtype)

def _arr_decimal128(values, *, params) -> pa.Array:
    scale = params["scale"]
    precision = params.get("precision", 38)
    return pa.array(
        _unscaled_to_decimal(values, scale),
        type=pa.decimal128(precision, scale),
    )

def _arr_decimal256(values, *, params) -> pa.Array:
    scale = params["scale"]
    precision = params.get("precision", 76)
    return pa.array(
        _unscaled_to_decimal(values, scale),
        type=pa.decimal256(precision, scale),
    )

def _arr_double_list(values, *, params) -> pa.Array:
    ndim = params["ndim"]
    leaf = pa.float64()
    if ndim == 1:
        return pa.array(values, type=pa.list_(leaf))
    if ndim == 2:
        inner = pa.list_(leaf)
        return pa.array(values, type=pa.list_(inner))
    if ndim == 3:
        inner = pa.list_(pa.list_(leaf))
        return pa.array(values, type=pa.list_(inner))
    raise ValueError(f"unsupported ndim={ndim}")

def _arr_long_list(values, *, params) -> pa.Array:
    return pa.array(values, type=pa.list_(pa.int64()))

def _set_bool(buf, name, v, *, params):
    buf.column(name, bool(v))

def _set_i8(buf, name, v, *, params):
    buf.column_i8(name, int(v))

def _set_i16(buf, name, v, *, params):
    buf.column_i16(name, int(v))

def _set_i32(buf, name, v, *, params):
    buf.column_i32(name, int(v))

def _set_i64(buf, name, v, *, params):
    buf.column(name, int(v))

def _set_f32(buf, name, v, *, params):
    buf.column_f32(name, float(v))

def _set_f64(buf, name, v, *, params):
    buf.column(name, float(v))

def _set_char(buf, name, v, *, params):
    buf.column_char(name, int(v))

def _set_ipv4(buf, name, v, *, params):
    buf.column_ipv4(name, int(v))

def _set_varchar(buf, name, v, *, params):
    buf.column(name, str(v))

def _set_binary(buf, name, v, *, params):
    buf.column_binary(name, bytes(v))

def _set_symbol(buf, name, v, *, params):
    buf.symbol(name, str(v))

def _set_uuid(buf, name, v, *, params):
    lo, hi = v
    buf.column_uuid(name, int(lo), int(hi))

def _set_long256(buf, name, v, *, params):
    buf.column_long256(name, bytes(v))

def _set_date(buf, name, v, *, params):
    buf.column_date(name, int(v))

def _set_ts_us(buf, name, v, *, params):
    from questdb_line_sender import TimestampMicros
    buf.column(name, TimestampMicros(int(v)))

def _set_ts_ns(buf, name, v, *, params):
    from questdb_line_sender import TimestampNanos
    buf.column(name, TimestampNanos(int(v)))

def _set_geohash(buf, name, v, *, params):
    buf.column_geohash(name, int(v), int(params["bits"]))

def _set_decimal_str(buf, name, v, *, params):
    buf.column_dec_str(name, _format_decimal(int(v), params["scale"]))

def _set_double_array(buf, name, v, *, params):
    import numpy as np
    arr = np.ascontiguousarray(np.asarray(v, dtype=np.float64))
    buf.column_f64_arr(name, arr)

def _format_decimal(unscaled: int, scale: int) -> str:
    if scale == 0:
        return str(unscaled)
    sign = "-" if unscaled < 0 else ""
    digits = str(abs(unscaled)).rjust(scale + 1, "0")
    int_part = digits[:-scale]
    frac_part = digits[-scale:]
    return f"{sign}{int_part}.{frac_part}"

_INT_NULL_SENTINEL = -(1 << 31)
_LONG_NULL_SENTINEL = -(1 << 63)
_IPV4_NULL_SENTINEL = 0


def _is_null_for(value, sentinel):
    if value is None:
        return True
    try:
        return int(value) == sentinel
    except (TypeError, ValueError):
        return False


def _cmp_default(a, e, *, params):
    if a is None or e is None:
        return a is None and e is None
    return a == e


def _cmp_int_sentinel(a, e, *, params):
    if _is_null_for(a, _INT_NULL_SENTINEL) and _is_null_for(e, _INT_NULL_SENTINEL):
        return True
    if a is None or e is None:
        return False
    return int(a) == int(e)


def _cmp_long_sentinel(a, e, *, params):
    if _is_null_for(a, _LONG_NULL_SENTINEL) and _is_null_for(e, _LONG_NULL_SENTINEL):
        return True
    if a is None or e is None:
        return False
    return int(a) == int(e)


def _cmp_ipv4_sentinel(a, e, *, params):
    if _is_null_for(a, _IPV4_NULL_SENTINEL) and _is_null_for(e, _IPV4_NULL_SENTINEL):
        return True
    if a is None or e is None:
        return False
    return int(a) == int(e)


def _cmp_geohash_sentinel(a, e, *, params):
    bits = params["bits"]
    storage_w = 8 if bits <= 7 else 16 if bits <= 15 else 32 if bits <= 32 else 64
    storage_sentinel = (1 << storage_w) - 1
    def _is_null(v):
        if v is None:
            return True
        try:
            return int(v) == storage_sentinel
        except (TypeError, ValueError):
            return False
    if _is_null(a) and _is_null(e):
        return True
    if a is None or e is None:
        return False
    return int(a) == int(e)

def _is_null_or_nan(v):
    if v is None:
        return True
    try:
        f = float(v)
        return math.isnan(f) or math.isinf(f)
    except (TypeError, ValueError):
        return False


def _cmp_float(a, e, *, params):
    if _is_null_or_nan(a) and _is_null_or_nan(e):
        return True
    if a is None or e is None:
        return False
    return float(a) == float(e)


def _cmp_float32(a, e, *, params):
    if _is_null_or_nan(a) and _is_null_or_nan(e):
        return True
    if a is None or e is None:
        return False
    return _f32_round(float(a)) == _f32_round(float(e))

def _cmp_uuid_bytes(a, e, *, params):
    if a is None or e is None:
        return a is None and e is None
    return bytes(a) == bytes(e)


def _cmp_uuid_tuple(a, e, *, params):
    if a is None or e is None:
        return a is None and e is None
    return tuple(a) == tuple(e)

def _cmp_symbol(a, e, *, params):
    if a is None or e is None:
        return a is None and e is None
    return str(a) == str(e)

def _cmp_timestamp(a, e, *, params):
    if a is None or e is None:
        return a is None and e is None
    import datetime as _dt
    if isinstance(a, _dt.datetime) and isinstance(e, _dt.datetime):
        return a == e
    if isinstance(a, _dt.datetime):
        unit = params.get("unit", "us")
        divisor = {"s": 1, "ms": 1_000, "us": 1_000_000, "ns": 1_000_000_000}[unit]
        return int(a.timestamp() * divisor) == int(e)
    return a == e

def _cmp_decimal(a, e, *, params):
    if a is None or e is None:
        return a is None and e is None
    from decimal import Decimal
    if not isinstance(a, Decimal):
        a = Decimal(str(a))
    if not isinstance(e, Decimal):
        e = Decimal(str(e))
    return a.normalize() == e.normalize()

def _cmp_double_array(a, e, *, params):
    if a is None or e is None:
        return a is None and e is None
    return _deep_float_equal(a, e)

def _deep_float_equal(a, e) -> bool:
    if isinstance(a, list) and isinstance(e, list):
        if len(a) != len(e):
            return False
        return all(_deep_float_equal(x, y) for x, y in zip(a, e))
    if isinstance(a, float) and isinstance(e, float):
        if math.isnan(a) and math.isnan(e):
            return True
        return a == e
    return a == e

class KindSpec:
    """Catalog entry for one column type tested via Arrow."""

    def __init__(
        self,
        name: str,
        ddl: str,
        arrow_type_factory: Callable[[Dict[str, Any]], pa.DataType],
        metadata_factory: Callable[[Dict[str, Any]], Optional[Dict[bytes, bytes]]],
        value_generator: Callable[..., List[Any]],
        arrow_array_builder: Callable[..., pa.Array],
        ilp_setter: Optional[Callable[..., None]],
        compare_fn: Callable[..., bool] = _cmp_default,
        *,
        round_trip_capable: bool = True,
        supports_ilp_setter: bool = True,
        supports_arrow_ingest: bool = True,
        supports_arrow_egress: bool = True,
        supports_server_null: bool = True,
        params: Optional[Dict[str, Any]] = None,
    ):
        self.name = name
        self.ddl = ddl
        self._arrow_type_factory = arrow_type_factory
        self._metadata_factory = metadata_factory
        self._value_generator = value_generator
        self._arrow_array_builder = arrow_array_builder
        self._ilp_setter = ilp_setter
        self._compare_fn = compare_fn
        self.round_trip_capable = round_trip_capable
        self.supports_ilp_setter = supports_ilp_setter
        self.supports_arrow_ingest = supports_arrow_ingest
        self.supports_arrow_egress = supports_arrow_egress
        self.supports_server_null = supports_server_null
        self.params: Dict[str, Any] = params or {}

    def arrow_type(self) -> pa.DataType:
        return self._arrow_type_factory(self.params)

    def metadata(self) -> Optional[Dict[bytes, bytes]]:
        return self._metadata_factory(self.params)

    def make_field(self, col_name: str, nullable: bool = True) -> pa.Field:
        return pa.field(
            col_name, self.arrow_type(), nullable=nullable,
            metadata=self.metadata(),
        )

    def generate_values(
        self, rnd: Rng, n: int, mask: List[bool], *, edge: bool = False
    ) -> List[Any]:
        return self._value_generator(rnd, n, mask, edge=edge, **self.params)

    def build_arrow_array(self, values: List[Any]) -> pa.Array:
        return self._arrow_array_builder(values, params=self.params)

    def ilp_set(self, buf, col_name: str, value: Any) -> None:
        if not self.supports_ilp_setter:
            raise NotImplementedError(
                f"kind {self.name!r} has no per-row ILP setter"
            )
        self._ilp_setter(buf, col_name, value, params=self.params)

    def compare(self, actual: Any, expected: Any) -> bool:
        return self._compare_fn(actual, expected, params=self.params)

def _vg_bool(rnd, n, mask, *, edge, **_):
    return _gen_bool(rnd, n, mask, edge=edge)

def _vg_signed(corpus, bound):
    def fn(rnd, n, mask, *, edge, **_):
        return _gen_signed_int(rnd, n, mask, edge=edge, corpus=corpus, bound=bound)
    return fn

def _vg_unsigned(corpus, ubound):
    def fn(rnd, n, mask, *, edge, **_):
        return _gen_unsigned_int(rnd, n, mask, edge=edge, corpus=corpus, ubound=ubound)
    return fn

def _vg_float(dtype: str):
    def fn(rnd, n, mask, *, edge, **_):
        return _gen_float(rnd, n, mask, edge=edge, dtype=dtype)
    return fn

def _vg_string(rnd, n, mask, *, edge, **_):
    return _gen_string(rnd, n, mask, edge=edge)

def _vg_binary(rnd, n, mask, *, edge, **_):
    return _gen_binary(rnd, n, mask, edge=edge)

def _vg_fixed_bytes(width):
    def fn(rnd, n, mask, *, edge, **_):
        return _gen_fixed_bytes(rnd, n, mask, edge=edge, width=width)
    return fn

def _vg_uuid_lo_hi(rnd, n, mask, *, edge, **_):
    return _gen_uuid_lo_hi(rnd, n, mask, edge=edge)

def _vg_char(rnd, n, mask, *, edge, **_):
    return _gen_char_codepoints(rnd, n, mask, edge=edge)

def _vg_ipv4(rnd, n, mask, *, edge, **_):
    return _gen_ipv4(rnd, n, mask, edge=edge)

def _vg_date(rnd, n, mask, *, edge, **_):
    return _gen_date_ms(rnd, n, mask, edge=edge)

def _vg_ts_us(rnd, n, mask, *, edge, base=1_700_000_000_000_000, **_):
    return _gen_ts_us(rnd, n, mask, edge=edge, base=base)

def _vg_ts_ns(rnd, n, mask, *, edge, base=1_700_000_000_000_000_000, **_):
    return _gen_ts_ns(rnd, n, mask, edge=edge, base=base)

def _vg_symbol(rnd, n, mask, *, edge, **_):
    return _gen_symbol(rnd, n, mask, edge=edge)

def _vg_geohash(rnd, n, mask, *, edge, bits, **_):
    return _gen_geohash(rnd, n, mask, edge=edge, bits=bits)

def _vg_decimal(rnd, n, mask, *, edge, bound, **_):
    return _gen_decimal_int(rnd, n, mask, edge=edge, bound=bound)

def _vg_double_array_1d(rnd, n, mask, *, edge, **_):
    return _gen_double_array_1d(rnd, n, mask, edge=edge)

def _vg_double_array_2d(rnd, n, mask, *, edge, **_):
    return _gen_double_array_2d(rnd, n, mask, edge=edge)

def _vg_double_array_3d(rnd, n, mask, *, edge, **_):
    return _gen_double_array_3d(rnd, n, mask, edge=edge)

def _vg_long_array_1d(rnd, n, mask, *, edge, **_):
    return _gen_long_array_1d(rnd, n, mask, edge=edge)

def _ty_bool(p): return pa.bool_()
def _ty_int8(p): return pa.int8()
def _ty_int16(p): return pa.int16()
def _ty_int32(p): return pa.int32()
def _ty_int64(p): return pa.int64()
def _ty_float32(p): return pa.float32()
def _ty_float64(p): return pa.float64()
def _ty_uint16(p): return pa.uint16()
def _ty_uint32(p): return pa.uint32()
def _ty_string(p): return pa.string()
def _ty_binary(p): return pa.binary()
def _ty_fsb(p): return pa.binary(p["width"])
def _ty_fsb16(p): return pa.binary(16)
def _ty_fsb32(p): return pa.binary(32)

def _ty_timestamp(p):
    return pa.timestamp(p["unit"], tz="UTC")

def _ty_symbol(p):
    return pa.dictionary(pa.uint32(), pa.string())

def _ty_geohash_int(p):
    return p["arrow_dtype"]

def _ty_decimal64(p):
    factory = getattr(pa, "decimal64", None)
    if factory is None:
        return pa.decimal128(p.get("precision", 18), p["scale"])
    return factory(p.get("precision", 18), p["scale"])

def _ty_decimal128(p):
    return pa.decimal128(p.get("precision", 38), p["scale"])

def _ty_decimal256(p):
    return pa.decimal256(p.get("precision", 76), p["scale"])

def _ty_double_list(p):
    leaf = pa.float64()
    for _ in range(p["ndim"]):
        leaf = pa.list_(leaf)
    return leaf

def _ty_long_list(p):
    return pa.list_(pa.int64())

def _md_none(p):
    return None

def _md_char(p):
    return {b"questdb.column_type": b"char"}

def _md_ipv4(p):
    return {b"questdb.column_type": b"ipv4"}

def _md_uuid(p):
    return {b"ARROW:extension:name": b"arrow.uuid"}

def _md_symbol(p):
    return {b"questdb.symbol": b"true"}

def _md_geohash(p):
    return {b"questdb.geohash_bits": str(p["bits"]).encode()}

def _geohash_arrow_dtype_for_bits(bits: int) -> pa.DataType:
    if bits <= 7:
        return pa.int8()
    if bits <= 15:
        return pa.int16()
    if bits <= 31:
        return pa.int32()
    return pa.int64()

def _make_geohash_spec(bits: int) -> KindSpec:
    arrow_dtype = _geohash_arrow_dtype_for_bits(bits)
    name = f"geohash{bits}"
    return KindSpec(
        name=name,
        ddl=f"GEOHASH({bits}b)",
        arrow_type_factory=_ty_geohash_int,
        metadata_factory=_md_geohash,
        value_generator=_vg_geohash,
        arrow_array_builder=_arr_geohash_int,
        ilp_setter=_set_geohash,
        compare_fn=_cmp_geohash_sentinel,
        params={"bits": bits, "arrow_dtype": arrow_dtype},
    )

def _build_kind_registry() -> Dict[str, KindSpec]:
    reg: Dict[str, KindSpec] = {}

    reg["boolean"] = KindSpec(
        "boolean", "BOOLEAN",
        _ty_bool, _md_none,
        _vg_bool, _arr_bool, _set_bool,
        supports_server_null=False,
    )
    reg["byte"] = KindSpec(
        "byte", "BYTE",
        _ty_int8, _md_none,
        _vg_signed(EDGE_INTS_I8, 100), _arr_int, _set_i8,
        supports_server_null=False,
        params={"arrow_dtype": pa.int8()},
    )
    reg["short"] = KindSpec(
        "short", "SHORT",
        _ty_int16, _md_none,
        _vg_signed(EDGE_INTS_I16, 10_000), _arr_int, _set_i16,
        supports_server_null=False,
        params={"arrow_dtype": pa.int16()},
    )
    reg["int"] = KindSpec(
        "int", "INT",
        _ty_int32, _md_none,
        _vg_signed(EDGE_INTS_I32, 1_000_000), _arr_int, _set_i32,
        compare_fn=_cmp_int_sentinel,
        params={"arrow_dtype": pa.int32()},
    )
    reg["long"] = KindSpec(
        "long", "LONG",
        _ty_int64, _md_none,
        _vg_signed(EDGE_INTS_I64, 1_000_000_000), _arr_int, _set_i64,
        compare_fn=_cmp_long_sentinel,
        params={"arrow_dtype": pa.int64()},
    )
    reg["float"] = KindSpec(
        "float", "FLOAT",
        _ty_float32, _md_none,
        _vg_float("float"), _arr_float, _set_f32,
        compare_fn=_cmp_float32,
        params={"arrow_dtype": pa.float32()},
    )
    reg["double"] = KindSpec(
        "double", "DOUBLE",
        _ty_float64, _md_none,
        _vg_float("double"), _arr_float, _set_f64,
        compare_fn=_cmp_float,
        params={"arrow_dtype": pa.float64()},
    )
    reg["char"] = KindSpec(
        "char", "CHAR",
        _ty_uint16, _md_char,
        _vg_char, _arr_uint16, _set_char,
        supports_server_null=False,
    )
    reg["ipv4"] = KindSpec(
        "ipv4", "IPV4",
        _ty_uint32, _md_ipv4,
        _vg_ipv4, _arr_uint32, _set_ipv4,
        compare_fn=_cmp_ipv4_sentinel,
    )
    reg["varchar"] = KindSpec(
        "varchar", "VARCHAR",
        _ty_string, _md_none,
        _vg_string, _arr_string, _set_varchar,
    )
    reg["binary"] = KindSpec(
        "binary", "BINARY",
        _ty_binary, _md_none,
        _vg_binary, _arr_binary, _set_binary,
    )
    reg["symbol"] = KindSpec(
        "symbol", "SYMBOL",
        _ty_symbol, _md_symbol,
        _vg_symbol, _arr_symbol, _set_symbol,
        compare_fn=_cmp_symbol,
    )
    reg["uuid"] = KindSpec(
        "uuid", "UUID",
        _ty_fsb16, _md_uuid,
        _vg_uuid_lo_hi, _arr_uuid_lo_hi, _set_uuid,
        compare_fn=_cmp_uuid_tuple,
        params={"width": 16},
    )
    reg["long256"] = KindSpec(
        "long256", "LONG256",
        _ty_fsb32, _md_none,
        _vg_fixed_bytes(32), _arr_fsb, _set_long256,
        compare_fn=_cmp_uuid_bytes,
        params={"width": 32},
    )
    reg["date"] = KindSpec(
        "date", "DATE",
        _ty_timestamp, _md_none,
        _vg_date, _arr_timestamp, _set_date,
        compare_fn=_cmp_timestamp,
        params={"unit": "ms"},
    )
    reg["timestamp"] = KindSpec(
        "timestamp", "TIMESTAMP",
        _ty_timestamp, _md_none,
        _vg_ts_us, _arr_timestamp, _set_ts_us,
        compare_fn=_cmp_timestamp,
        params={"unit": "us"},
        supports_server_null=False,
    )
    reg["timestamp_ns"] = KindSpec(
        "timestamp_ns", "TIMESTAMP_NS",
        _ty_timestamp, _md_none,
        _vg_ts_ns, _arr_timestamp, _set_ts_ns,
        compare_fn=_cmp_timestamp,
        params={"unit": "ns"},
        supports_server_null=False,
    )
    for bits in EDGE_GEOHASH_BITS:
        spec = _make_geohash_spec(bits)
        reg[spec.name] = spec
    reg["decimal64"] = KindSpec(
        "decimal64", "DECIMAL(18,4)",
        _ty_decimal64, _md_none,
        _vg_decimal, _arr_decimal64, _set_decimal_str,
        compare_fn=_cmp_decimal,
        supports_ilp_setter=True,
        params={"scale": 4, "precision": 18, "bound": 10**14},
    )
    reg["decimal128"] = KindSpec(
        "decimal128", "DECIMAL(38,10)",
        _ty_decimal128, _md_none,
        _vg_decimal, _arr_decimal128, _set_decimal_str,
        compare_fn=_cmp_decimal,
        params={"scale": 10, "precision": 38, "bound": 10**28},
    )
    reg["decimal256"] = KindSpec(
        "decimal256", "DECIMAL(76,20)",
        _ty_decimal256, _md_none,
        _vg_decimal, _arr_decimal256, _set_decimal_str,
        compare_fn=_cmp_decimal,
        supports_ilp_setter=False,
        params={"scale": 20, "precision": 76, "bound": 10**40},
    )
    reg["double_array_1d"] = KindSpec(
        "double_array_1d", "DOUBLE[]",
        _ty_double_list, _md_none,
        _vg_double_array_1d, _arr_double_list, _set_double_array,
        compare_fn=_cmp_double_array,
        params={"ndim": 1},
    )
    reg["double_array_2d"] = KindSpec(
        "double_array_2d", "DOUBLE[][]",
        _ty_double_list, _md_none,
        _vg_double_array_2d, _arr_double_list, _set_double_array,
        compare_fn=_cmp_double_array,
        params={"ndim": 2},
        supports_ilp_setter=True,
    )
    reg["double_array_3d"] = KindSpec(
        "double_array_3d", "DOUBLE[][][]",
        _ty_double_list, _md_none,
        _vg_double_array_3d, _arr_double_list, _set_double_array,
        compare_fn=_cmp_double_array,
        params={"ndim": 3},
        supports_ilp_setter=True,
    )
    return reg

KIND_REGISTRY: Dict[str, KindSpec] = _build_kind_registry()

def build_record_batch(
    kinds: List[Tuple[str, KindSpec]],
    rnd: Rng,
    n: int,
    *,
    null_mode: str = "valid",       # "valid" | "partial" | "all_null" | "edge"
    null_p: float = 0.2,
    ts_base_us: int = 1_700_000_000_000_000,
) -> pa.RecordBatch:
    arrays: List[pa.Array] = []
    fields: List[pa.Field] = []
    for col_name, spec in kinds:
        if null_mode == "valid":
            mask = all_valid_mask(n)
            edge = False
        elif null_mode == "partial":
            mask = partial_null_mask(rnd, n, null_p=null_p)
            edge = False
        elif null_mode == "all_null":
            mask = all_null_mask(n)
            edge = False
        elif null_mode == "edge":
            mask = all_valid_mask(n)
            edge = True
        else:
            raise ValueError(f"unknown null_mode {null_mode!r}")
        values = spec.generate_values(rnd, n, mask, edge=edge)
        arr = spec.build_arrow_array(values)
        arrays.append(arr)
        fields.append(spec.make_field(col_name))
    ts_arr = pa.array(
        [ts_base_us + i for i in range(n)],
        type=pa.timestamp("us", tz="UTC"),
    )
    arrays.append(ts_arr)
    fields.append(pa.field("ts", pa.timestamp("us", tz="UTC"), nullable=False))
    return pa.RecordBatch.from_arrays(arrays, schema=pa.schema(fields))

def create_table_from_kinds(
    fixture, table: str, kinds: List[Tuple[str, KindSpec]],
    *, designated_ts: str = "ts",
) -> None:
    col_defs = [f'"{n}" {s.ddl}' for n, s in kinds]
    col_defs.append(f'"{designated_ts}" TIMESTAMP')
    ddl = (
        f"CREATE TABLE '{table}' ({', '.join(col_defs)}) "
        f"TIMESTAMP({designated_ts}) PARTITION BY DAY WAL"
    )
    exec_ddl(fixture, ddl)

class ArrowFuzzBase(unittest.TestCase):
    """Common skeleton: live-fixture skip, seed echo, table cleanup."""

    SUITE_LABEL = "arrow_fuzz"

    def setUp(self) -> None:
        super().setUp()
        try:
            import pyarrow
        except ImportError:
            self.skipTest("pyarrow is required for the Arrow system tests")
        self._fixture = get_live_fixture(self)
        seed = derive_master_seed()
        self._master_rng = Rng(seed)
        self._seed_label = format_seed(seed)
        sys.stderr.write(
            f"[{self.SUITE_LABEL} seed] {self.id()} {self._seed_label}\n"
        )
        sys.stderr.flush()
        self._created_tables: List[str] = []
        self._exit_stack = contextlib.ExitStack()

    def tearDown(self) -> None:
        self._exit_stack.close()
        for table in self._created_tables:
            drop_table_safe(self._fixture, table)
        super().tearDown()

    def track_table(self, table: str) -> None:
        self._created_tables.append(table)

    def fresh_table(self, prefix: str) -> str:
        table = make_table_name(prefix, self._master_rng)
        self.track_table(table)
        return table

    def label(self, extra: str = "") -> str:
        return f"seed={self._seed_label}{(' ' + extra) if extra else ''}"
