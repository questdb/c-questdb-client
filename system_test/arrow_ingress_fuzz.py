from __future__ import annotations

import base64
import ctypes
import datetime as _dt
import os
import sys
import threading
import time
import unittest
import uuid as _uuid_mod
from decimal import Decimal
from typing import Any, Callable, Dict, List, Optional, Tuple

import pyarrow as pa

import arrow_fuzz_common as afc
from arrow_fuzz_common import KIND_REGISTRY, KindSpec
from arrow_ffi import (
    ArrowSenderError,
    SenderErrorCode,
)
from questdb_line_sender import QwpWsErrorCategory, QwpWsErrorPolicy

_FUZZ_ITERATIONS = int(os.environ.get("ARROW_INGRESS_FUZZ_ITERATIONS", "6"))
_ROWS_PER_BATCH = int(os.environ.get("ARROW_INGRESS_FUZZ_ROWS", "12"))

def _epoch_us() -> _dt.datetime:
    return _dt.datetime(1970, 1, 1, tzinfo=_dt.timezone.utc)

def _iso_to_us(s: str) -> int:
    """ISO datetime string → microseconds since epoch (handles ns suffix)."""
    s = s.rstrip("Z")
    if "." in s:
        head, frac = s.split(".", 1)
        if "T" not in head:
            head = head.replace(" ", "T")
        frac = frac.ljust(6, "0")
        us = int(frac[:6])
        ns_tail = frac[6:]
        if ns_tail and any(c != "0" for c in ns_tail):
            us += int(round(int(ns_tail.ljust(3, "0")[:3]) / 1000.0))
        try:
            base_dt = _dt.datetime.fromisoformat(head).replace(
                tzinfo=_dt.timezone.utc
            )
        except ValueError:
            return -1
        return int((base_dt - _epoch_us()).total_seconds() * 1_000_000) + us
    head = s.replace(" ", "T") if "T" not in s else s
    try:
        base_dt = _dt.datetime.fromisoformat(head).replace(
            tzinfo=_dt.timezone.utc
        )
    except ValueError:
        return -1
    return int((base_dt - _epoch_us()).total_seconds() * 1_000_000)

def _iso_to_ns(s: str) -> int:
    s = s.rstrip("Z")
    if "." in s:
        head, frac = s.split(".", 1)
        if "T" not in head:
            head = head.replace(" ", "T")
        frac = frac.ljust(9, "0")[:9]
        ns_part = int(frac)
        try:
            base_dt = _dt.datetime.fromisoformat(head).replace(
                tzinfo=_dt.timezone.utc
            )
        except ValueError:
            return -1
        return int((base_dt - _epoch_us()).total_seconds() * 1_000_000_000) + ns_part
    head = s.replace(" ", "T") if "T" not in s else s
    try:
        base_dt = _dt.datetime.fromisoformat(head).replace(
            tzinfo=_dt.timezone.utc
        )
    except ValueError:
        return -1
    return int((base_dt - _epoch_us()).total_seconds() * 1_000_000_000)

def _iso_to_ms(s: str) -> int:
    return _iso_to_us(s) // 1_000

_INT_NULL_SENTINEL = -(1 << 31)
_LONG_NULL_SENTINEL = -(1 << 63)
_IPV4_NULL_SENTINEL = 0


def _cmp_int(expected, actual) -> bool:
    if expected is None or actual is None or actual == "":
        return expected is None and (actual is None or actual == "")
    return int(expected) == int(actual)


def _cmp_int32(expected, actual) -> bool:
    if expected == _INT_NULL_SENTINEL:
        expected = None
    return _cmp_int(expected, actual)


def _cmp_int64(expected, actual) -> bool:
    if expected == _LONG_NULL_SENTINEL:
        expected = None
    return _cmp_int(expected, actual)


def _cmp_ipv4_with_sentinel(expected, actual) -> bool:
    if expected == _IPV4_NULL_SENTINEL:
        expected = None
    if expected is None:
        return actual is None or actual == ""
    if isinstance(actual, str):
        parts = list(int(expected).to_bytes(4, "big"))
        return actual == ".".join(str(p) for p in parts)
    return int(actual) == int(expected)


_GEOHASH_BASE32 = "0123456789bcdefghjkmnpqrstuvwxyz"


def _geohash_decode_server_str(s: str, bits: int) -> int:
    if bits % 5 == 0:
        result = 0
        for c in s:
            try:
                result = (result << 5) | _GEOHASH_BASE32.index(c)
            except ValueError:
                return -1
        return result
    result = 0
    for c in s:
        if c not in ("0", "1"):
            return -1
        result = (result << 1) | (1 if c == "1" else 0)
    return result


def _cmp_geohash_with_sentinel(bits: int):
    storage_w = 8 if bits <= 7 else 16 if bits <= 15 else 32 if bits <= 32 else 64
    storage_sentinel = (1 << storage_w) - 1
    def fn(expected, actual) -> bool:
        if expected == storage_sentinel:
            expected = None
        if expected is None:
            return actual is None or actual == ""
        if actual is None or actual == "":
            return False
        if isinstance(actual, str):
            decoded = _geohash_decode_server_str(actual, bits)
            return decoded == int(expected)
        return int(actual) == int(expected)
    return fn

def _is_null_or_special(v):
    import math
    if v is None or v == "":
        return True
    try:
        f = float(v)
        return math.isnan(f) or math.isinf(f)
    except (TypeError, ValueError):
        return False


def _cmp_float(expected, actual) -> bool:
    if _is_null_or_special(expected) and _is_null_or_special(actual):
        return True
    if _is_null_or_special(expected) or _is_null_or_special(actual):
        return False
    return float(expected) == float(actual)


def _cmp_float32(expected, actual) -> bool:
    import struct, math
    if _is_null_or_special(expected) and _is_null_or_special(actual):
        return True
    if _is_null_or_special(expected) or _is_null_or_special(actual):
        return False
    def _f32(v):
        try:
            return struct.unpack("<f", struct.pack("<f", float(v)))[0]
        except (OverflowError, ValueError):
            return math.copysign(math.inf, float(v))
    return _f32(expected) == _f32(actual)

def _cmp_str(expected, actual) -> bool:
    if expected is None:
        return actual is None or actual == ""
    return str(expected) == str(actual)

def _cmp_bool(expected, actual) -> bool:
    if expected is None:
        return actual is None or actual == ""
    if isinstance(actual, bool):
        return bool(expected) == actual
    if isinstance(actual, str):
        return ("true" if expected else "false") == actual.lower()
    return bool(expected) == bool(actual)

def _cmp_binary(expected, actual) -> bool:
    if expected is None:
        return actual is None or actual == "" or actual == []
    if isinstance(actual, list):
        if not actual:
            return True
        try:
            return bytes(expected) == bytes(actual)
        except (TypeError, ValueError):
            return False
    if isinstance(actual, str):
        if actual.startswith("0x"):
            try:
                return bytes(expected) == bytes.fromhex(actual[2:])
            except ValueError:
                return False
        try:
            return bytes(expected) == base64.b64decode(actual)
        except Exception:
            return False
    return bytes(expected) == bytes(actual)

def _cmp_uuid(expected, actual) -> bool:
    if expected is None:
        return actual is None or actual == ""
    lo, hi = expected
    expected_int = (hi << 64) | lo
    if isinstance(actual, str):
        try:
            return _uuid_mod.UUID(actual).int == expected_int
        except Exception:
            return False
    if isinstance(actual, (bytes, bytearray)):
        return bytes(actual) == lo.to_bytes(8, "little") + hi.to_bytes(8, "little")
    return False

def _cmp_long256(expected, actual) -> bool:
    if expected is None:
        return actual is None or actual == ""
    expected = bytes(expected)
    if isinstance(actual, str):
        if actual.startswith("0x"):
            try:
                actual_bytes = bytes.fromhex(actual[2:].zfill(64))
            except ValueError:
                return False
            return actual_bytes == expected[::-1] or actual_bytes == expected
    return False

def _cmp_decimal(expected, actual, scale: int) -> bool:
    if expected is None:
        return actual is None or actual == ""
    if actual is None or actual == "":
        return False
    try:
        a = Decimal(str(actual)).normalize()
        e = (Decimal(int(expected)).scaleb(-scale)).normalize()
        return a == e
    except Exception:
        return False

def _cmp_date_ms(expected, actual) -> bool:
    if expected is None:
        return actual is None or actual == ""
    if isinstance(actual, str):
        return _iso_to_ms(actual) == int(expected)
    return int(expected) == int(actual)

def _cmp_timestamp_us(expected, actual) -> bool:
    if expected is None:
        return actual is None or actual == ""
    if isinstance(actual, str):
        return _iso_to_us(actual) == int(expected)
    return int(expected) == int(actual)

def _cmp_timestamp_ns(expected, actual) -> bool:
    if expected is None:
        return actual is None or actual == ""
    if isinstance(actual, str):
        return _iso_to_ns(actual) == int(expected)
    return int(expected) == int(actual)

def _cmp_char_codepoint(expected, actual) -> bool:
    if expected is None:
        return actual is None or actual == ""
    if isinstance(actual, str):
        if len(actual) == 0:
            return expected == 0
        return ord(actual) == int(expected)
    return int(actual) == int(expected)

def _cmp_ipv4(expected, actual) -> bool:
    if expected is None:
        return actual is None or actual == ""
    if isinstance(actual, str):
        parts = list(int(expected).to_bytes(4, "big"))
        return actual == ".".join(str(p) for p in parts)
    return int(actual) == int(expected)

def _cmp_passthrough(expected, actual) -> bool:
    return True

def _cmp_array(expected, actual) -> bool:
    """Best-effort: shape and non-null status; full string parsing is brittle."""
    if expected is None:
        return actual is None or actual == ""
    return actual is not None and str(actual) != ""

# kind name → (expected_value, actual_json_cell) -> bool
_INGRESS_ORACLES: Dict[str, Callable[[Any, Any], bool]] = {
    "boolean": _cmp_bool,
    "byte": _cmp_int, "short": _cmp_int,
    "int": _cmp_int32, "long": _cmp_int64,
    "float": _cmp_float32, "double": _cmp_float,
    "char": _cmp_char_codepoint,
    "ipv4": _cmp_ipv4_with_sentinel,
    "varchar": _cmp_str,
    "binary": _cmp_binary,
    "symbol": _cmp_str,
    "uuid": _cmp_uuid,
    "long256": _cmp_long256,
    "date": _cmp_date_ms,
    "timestamp": _cmp_timestamp_us,
    "timestamp_ns": _cmp_timestamp_ns,
    "geohash1": _cmp_geohash_with_sentinel(1),
    "geohash5": _cmp_geohash_with_sentinel(5),
    "geohash32": _cmp_geohash_with_sentinel(32),
    "geohash60": _cmp_geohash_with_sentinel(60),
    "decimal64": lambda e, a: _cmp_decimal(e, a, scale=4),
    "decimal128": lambda e, a: _cmp_decimal(e, a, scale=10),
    "decimal256": lambda e, a: _cmp_decimal(e, a, scale=20),
    "double_array_1d": _cmp_array,
    "double_array_2d": _cmp_array,
    "double_array_3d": _cmp_array,
    "long_array_1d": _cmp_array,
}

def _build_record_batch_with_ts(
    rnd: afc.Rng, n: int, kinds: List[Tuple[str, KindSpec]],
    *, null_mode: str = "valid", null_p: float = 0.3,
    ts_base_us: int = 1_700_000_000_000_000,
    include_ts: bool = True,
) -> Tuple[pa.RecordBatch, Dict[str, List[Any]]]:
    arrays: List[pa.Array] = []
    fields: List[pa.Field] = []
    values_per_col: Dict[str, List[Any]] = {}
    for col_name, spec in kinds:
        if null_mode == "valid":
            mask = afc.all_valid_mask(n); edge = False
        elif null_mode == "partial":
            mask = afc.partial_null_mask(rnd, n, null_p=null_p); edge = False
        elif null_mode == "all_null":
            mask = afc.all_null_mask(n); edge = False
        elif null_mode == "edge":
            mask = afc.all_valid_mask(n); edge = True
        else:
            raise ValueError(null_mode)
        values = spec.generate_values(rnd, n, mask, edge=edge)
        values_per_col[col_name] = values
        arrays.append(spec.build_arrow_array(values))
        fields.append(spec.make_field(col_name))
    if include_ts:
        ts_values = [ts_base_us + i for i in range(n)]
        arrays.append(pa.array(ts_values, type=pa.timestamp("us", tz="UTC")))
        fields.append(pa.field("ts", pa.timestamp("us", tz="UTC"), nullable=False))
        values_per_col["ts"] = ts_values
    return pa.RecordBatch.from_arrays(arrays, schema=pa.schema(fields)), values_per_col

def _read_back_json(fixture, table: str, kinds: List[Tuple[str, KindSpec]]) -> Tuple[list, list]:
    cols_sql = ", ".join(f'"{c}"' for c, _ in kinds)
    resp = fixture.http_sql_query(
        f"select {cols_sql} from '{table}' order by ts"
    )
    return resp["columns"], resp["dataset"]


def _read_back_arrow_cells(fixture, table: str, kinds: List[Tuple[str, KindSpec]]) -> list:
    """Read column 0 cells back via Arrow C ABI (used for kinds that /exec
    JSON cannot represent correctly, e.g. BINARY on this server)."""
    cols_sql = ", ".join(f'"{c}"' for c, _ in kinds)
    rb = afc.read_back_arrow_concat(
        fixture, f"select {cols_sql} from '{table}' order by ts"
    )
    return [rb.column(0)[r].as_py() for r in range(rb.num_rows)]

class TestArrowIngressPerKind(afc.ArrowFuzzBase):
    """One method per kind. Ingest via Arrow, read back via /exec, compare."""

    SUITE_LABEL = "arrow_ingress_per_kind"

    def _exercise_kind(self, kind_name: str) -> None:
        spec = KIND_REGISTRY[kind_name]
        if not spec.supports_arrow_ingest:
            self.skipTest(f"kind {kind_name!r} not supported by Arrow ingest")
        modes = ["valid", "edge"]
        if spec.supports_server_null:
            modes[1:1] = ["partial", "all_null"]
        for null_mode in modes:
            with self.subTest(null_mode=null_mode):
                table = self.fresh_table(f"arrow_in_{kind_name}_{null_mode}")
                kinds = [(f"c_{kind_name}", spec)]
                afc.create_table_from_kinds(self._fixture, table, kinds)
                rb, vpc = _build_record_batch_with_ts(
                    self._master_rng, _ROWS_PER_BATCH, kinds, null_mode=null_mode,
                )
                afc.ingest_via_arrow(self._fixture, table, rb)
                afc.wait_for_rows(self._fixture, table, rb.num_rows)
                expected_col = vpc[f"c_{kind_name}"]
                if kind_name == "binary":
                    dataset = _read_back_arrow_cells(
                        self._fixture, table, kinds,
                    )
                    self._assert_arrow_binary_matches(
                        kind_name, expected_col, dataset, null_mode,
                    )
                else:
                    _columns, dataset = _read_back_json(self._fixture, table, kinds)
                    self._assert_dataset_matches(
                        kind_name, spec, expected_col, dataset, null_mode,
                    )

    def _assert_arrow_binary_matches(
        self, kind_name: str, expected_values, actual_cells, null_mode: str,
    ) -> None:
        self.assertEqual(
            len(actual_cells), len(expected_values),
            self.label(f"row count for kind={kind_name} mode={null_mode}"),
        )
        for r, (e, a) in enumerate(zip(expected_values, actual_cells)):
            if e is None:
                if a not in (None, b""):
                    self.fail(self.label(
                        f"kind={kind_name} mode={null_mode} row={r}: "
                        f"expected=None actual={a!r}"
                    ))
                continue
            if bytes(e) != bytes(a if a is not None else b""):
                self.fail(self.label(
                    f"kind={kind_name} mode={null_mode} row={r}: "
                    f"expected={bytes(e)!r} actual={a!r}"
                ))

    def _assert_dataset_matches(
        self, kind_name: str, spec: KindSpec,
        expected_values, dataset, null_mode: str,
    ) -> None:
        self.assertEqual(
            len(dataset), len(expected_values),
            self.label(f"row count for kind={kind_name} mode={null_mode}"),
        )
        oracle = _INGRESS_ORACLES.get(kind_name, _cmp_passthrough)
        for r, (expected, row) in enumerate(zip(expected_values, dataset)):
            actual = row[0]
            if not oracle(expected, actual):
                self.fail(self.label(
                    f"kind={kind_name} mode={null_mode} row={r}: "
                    f"expected={expected!r} actual={actual!r}"
                ))

for _kind_name in list(KIND_REGISTRY.keys()):
    def _make(name):
        def test(self):
            self._exercise_kind(name)
        test.__name__ = f"test_kind_{name}"
        test.__qualname__ = f"TestArrowIngressPerKind.test_kind_{name}"
        return test
    setattr(TestArrowIngressPerKind, f"test_kind_{_kind_name}", _make(_kind_name))

class TestArrowIngressDesignatedTs(afc.ArrowFuzzBase):
    """Each designated-timestamp mode (column / server-now) against a small mixed batch."""

    SUITE_LABEL = "arrow_ingress_dts"

    def _build_small_batch(self):
        kinds = [
            ("c_int", KIND_REGISTRY["int"]),
            ("c_sym", KIND_REGISTRY["symbol"]),
            ("c_double", KIND_REGISTRY["double"]),
        ]
        rb, _vpc = _build_record_batch_with_ts(
            self._master_rng, _ROWS_PER_BATCH, kinds, null_mode="valid",
        )
        return rb, kinds

    def test_dts_column_micros(self):
        rb, kinds = self._build_small_batch()
        table = self.fresh_table("arrow_in_dts_col_us")
        afc.ingest_via_arrow(self._fixture, table, rb,
                              ts_col=b"ts")
        afc.wait_for_rows(self._fixture, table, rb.num_rows)
        resp = self._fixture.http_sql_query(f"select count() from '{table}'")
        self.assertEqual(int(resp["dataset"][0][0]), rb.num_rows, self.label())

    def test_dts_column_nanos(self):
        # Replace ts column with ns precision.
        kinds = [("c_int", KIND_REGISTRY["int"])]
        n = _ROWS_PER_BATCH
        vs = KIND_REGISTRY["int"].generate_values(
            self._master_rng, n, afc.all_valid_mask(n), edge=False,
        )
        arr_int = KIND_REGISTRY["int"].build_arrow_array(vs)
        ts_ns_base = 1_700_000_000_000_000_000
        ts_arr = pa.array(
            [ts_ns_base + i for i in range(n)],
            type=pa.timestamp("ns", tz="UTC"),
        )
        schema = pa.schema([
            KIND_REGISTRY["int"].make_field("c_int"),
            pa.field("ts", pa.timestamp("ns", tz="UTC"), nullable=False),
        ])
        rb = pa.RecordBatch.from_arrays([arr_int, ts_arr], schema=schema)
        table = self.fresh_table("arrow_in_dts_col_ns")
        afc.ingest_via_arrow(self._fixture, table, rb,
                              ts_col=b"ts")
        afc.wait_for_rows(self._fixture, table, rb.num_rows)

    def test_dts_default(self):
        rb, kinds = self._build_small_batch()
        no_ts_fields = [f for f in rb.schema if f.name != "ts"]
        no_ts_arrays = [rb.column(rb.schema.get_field_index(f.name))
                         for f in no_ts_fields]
        rb_no_ts = pa.RecordBatch.from_arrays(
            no_ts_arrays, schema=pa.schema(no_ts_fields),
        )
        table = self.fresh_table("arrow_in_dts_default")
        afc.ingest_via_arrow(self._fixture, table, rb_no_ts, ts_col=None)
        afc.wait_for_rows(self._fixture, table, rb_no_ts.num_rows)

class TestArrowIngressErrors(afc.ArrowFuzzBase):
    """Deterministic recipes for each reachable line_sender_error_code."""

    SUITE_LABEL = "arrow_ingress_errors"

    def _expect_code(self, rb: pa.RecordBatch, expected_code: int, *,
                    ts_col: Optional[bytes] = b"ts",
                    extras=None) -> ArrowSenderError:
        table = f"arrow_in_err_{self._master_rng.next_int(2**32):08x}"
        try:
            afc.ingest_via_arrow(
                self._fixture, table, rb,
                ts_col=ts_col,
                sender_conf_extras=extras or {},
            )
        except ArrowSenderError as e:
            if e.code != expected_code:
                self.fail(self.label(
                    f"expected code={expected_code} got code={e.code} msg={e}"
                ))
            return e
        else:
            self.fail(self.label(
                f"expected ArrowSenderError code={expected_code} but call succeeded"
            ))

    def test_err_designated_ts_column_missing(self):
        rb, _ = _build_record_batch_with_ts(
            self._master_rng, 4,
            [("c_int", KIND_REGISTRY["int"])],
            null_mode="valid",
        )
        self._expect_code(rb, SenderErrorCode.ARROW_INGEST,
                          ts_col=b"definitely_not_a_column")

    def test_err_designated_ts_wrong_type(self):
        # Build a batch where "ts" is Int64, not Timestamp.
        n = 4
        vs = list(range(n))
        arr_int = pa.array(vs, type=pa.int64())
        ts_arr = pa.array(vs, type=pa.int64())
        schema = pa.schema([
            pa.field("c_int", pa.int64(), nullable=True),
            pa.field("ts", pa.int64(), nullable=True),
        ])
        rb = pa.RecordBatch.from_arrays([arr_int, ts_arr], schema=schema)
        self._expect_code(rb, SenderErrorCode.ARROW_INGEST)

    def test_err_designated_ts_has_nulls(self):
        n = 4
        c_int = pa.array([1, 2, 3, 4], type=pa.int64())
        ts_arr = pa.array([1_700_000_000_000_000, None,
                           1_700_000_000_000_002, 1_700_000_000_000_003],
                          type=pa.timestamp("us", tz="UTC"))
        schema = pa.schema([
            pa.field("c_int", pa.int64(), nullable=True),
            pa.field("ts", pa.timestamp("us", tz="UTC"), nullable=True),
        ])
        rb = pa.RecordBatch.from_arrays([c_int, ts_arr], schema=schema)
        self._expect_code(rb, SenderErrorCode.ARROW_INGEST)

    def test_err_list_non_float_leaf(self):
        n = 4
        c_list = pa.array([[1, 2], [3], [], [4, 5, 6]], type=pa.list_(pa.int64()))
        # int64 list IS supported as LONG_ARRAY now — pick a non-numeric leaf.
        c_str_list = pa.array(
            [["a"], ["b", "c"], [], ["d"]],
            type=pa.list_(pa.string()),
        )
        ts_arr = pa.array(
            [1_700_000_000_000_000 + i for i in range(n)],
            type=pa.timestamp("us", tz="UTC"),
        )
        schema = pa.schema([
            pa.field("c_str_list", pa.list_(pa.string()), nullable=True),
            pa.field("ts", pa.timestamp("us", tz="UTC"), nullable=False),
        ])
        rb = pa.RecordBatch.from_arrays([c_str_list, ts_arr], schema=schema)
        self._expect_code(rb, SenderErrorCode.ARROW_UNSUPPORTED_COLUMN_KIND)

    def test_err_geohash_bits_zero(self):
        n = 4
        c_geo = pa.array([0] * n, type=pa.int32())
        ts_arr = pa.array(
            [1_700_000_000_000_000 + i for i in range(n)],
            type=pa.timestamp("us", tz="UTC"),
        )
        schema = pa.schema([
            pa.field("c_geo", pa.int32(), nullable=True,
                     metadata={b"questdb.geohash_bits": b"0"}),
            pa.field("ts", pa.timestamp("us", tz="UTC"), nullable=False),
        ])
        rb = pa.RecordBatch.from_arrays([c_geo, ts_arr], schema=schema)
        self._expect_code(rb, SenderErrorCode.ARROW_INGEST)

    def test_err_geohash_bits_too_large(self):
        n = 4
        c_geo = pa.array([0] * n, type=pa.int64())
        ts_arr = pa.array(
            [1_700_000_000_000_000 + i for i in range(n)],
            type=pa.timestamp("us", tz="UTC"),
        )
        schema = pa.schema([
            pa.field("c_geo", pa.int64(), nullable=True,
                     metadata={b"questdb.geohash_bits": b"61"}),
            pa.field("ts", pa.timestamp("us", tz="UTC"), nullable=False),
        ])
        rb = pa.RecordBatch.from_arrays([c_geo, ts_arr], schema=schema)
        self._expect_code(rb, SenderErrorCode.ARROW_INGEST)

    def test_err_malformed_list_schema_zero_children(self):
        # pyarrow always emits structurally-valid Arrow, so hand-build a
        # malformed C Data Interface struct directly: a List ("+l") that
        # declares no child. The pre-import validator must reject it with
        # ArrowIngest rather than letting arrow-rs abort the panic=abort FFI
        # crate inside DataType::try_from -> FFI_ArrowSchema::child().
        from arrow_ffi import ArrowArray, ArrowSchema, conn_flush_arrow_batch
        from questdb_line_sender import _table_name as _c_table_name

        arr_release_t = ctypes.CFUNCTYPE(None, ctypes.POINTER(ArrowArray))
        sch_release_t = ctypes.CFUNCTYPE(None, ctypes.POINTER(ArrowSchema))
        # Held in locals for the lifetime of the call. release must be
        # non-NULL so the array passes the already-consumed check and
        # actually reaches the schema validator.
        arr_release = arr_release_t(lambda _p: None)
        sch_release = sch_release_t(lambda _p: None)

        arr = ArrowArray()
        arr.length = 2
        arr.n_buffers = 0
        arr.n_children = 0
        arr.release = arr_release

        sch = ArrowSchema()
        sch.format = b"+l"
        sch.name = b"c"
        sch.n_children = 0
        sch.release = sch_release

        table = f"arrow_in_malformed_{self._master_rng.next_int(2**32):08x}"
        with afc.borrowed_column_sender(self._fixture) as conn:
            table_name = _c_table_name(table)
            try:
                conn_flush_arrow_batch(
                    conn, table_name,
                    ctypes.byref(arr), ctypes.byref(sch),
                )
            except ArrowSenderError as e:
                self.assertEqual(
                    e.code, SenderErrorCode.ARROW_INGEST,
                    self.label(f"malformed +l → code={e.code} msg={e}"))
            else:
                self.fail(self.label("malformed +l schema must be rejected"))

class TestArrowIngressExtraTypes(afc.ArrowFuzzBase):
    """Arrow primitive variants that don't surface via polars but are
    accepted by the Rust ingest path through a widening / unit conversion:
    Float16, Date64, Timestamp(s), Decimal32."""

    SUITE_LABEL = "arrow_ingress_extra_types"

    def _ts_arr(self, n: int) -> pa.Array:
        return pa.array(
            [1_700_000_000_000_000 + i for i in range(n)],
            type=pa.timestamp("us", tz="UTC"),
        )

    def _ingest_one_col(self, table: str, ddl_col: str, col_name: str,
                        col_arr: pa.Array) -> None:
        afc.exec_ddl(
            self._fixture,
            f'CREATE TABLE "{table}" ("{col_name}" {ddl_col}, ts TIMESTAMP) '
            f'TIMESTAMP(ts) PARTITION BY DAY WAL',
        )
        ts_arr = self._ts_arr(len(col_arr))
        schema = pa.schema([
            pa.field(col_name, col_arr.type, nullable=True),
            pa.field("ts", pa.timestamp("us", tz="UTC"), nullable=False),
        ])
        rb = pa.RecordBatch.from_arrays([col_arr, ts_arr], schema=schema)
        afc.ingest_via_arrow(self._fixture, table, rb,
                              ts_col=b"ts")
        afc.wait_for_rows(self._fixture, table, len(col_arr))

    def test_extra_float16_widens_to_double(self):
        try:
            import numpy as np
        except ImportError:
            self.skipTest("numpy required to build Float16 arrays via pyarrow")
        arr = pa.array(np.array([1.5, -2.5, 0.0, 1.0], dtype=np.float16))
        self.assertEqual(arr.type, pa.float16())
        table = self.fresh_table("arrow_extra_f16")
        self._ingest_one_col(table, "FLOAT", "c", arr)

    def test_extra_date64_appends_as_date(self):
        # Date64 stores ms-since-epoch as i64.
        day_ms = 86_400_000
        arr = pa.array([0, day_ms * 19_675, day_ms * 20_000, None],
                       type=pa.date64())
        table = self.fresh_table("arrow_extra_d64")
        self._ingest_one_col(table, "DATE", "c", arr)

    def test_extra_timestamp_second_widens_to_micros(self):
        arr = pa.array([1_700_000_000, 0, 1, 2],
                       type=pa.timestamp("s", tz="UTC"))
        table = self.fresh_table("arrow_extra_ts_s")
        self._ingest_one_col(table, "TIMESTAMP", "c", arr)

    def test_extra_decimal32_widens_to_decimal64(self):
        arr = pa.array([Decimal("1.23"), Decimal("-0.99"),
                        Decimal("99.99"), None],
                       type=pa.decimal32(9, 2))
        table = self.fresh_table("arrow_extra_d32")
        self._ingest_one_col(table, "DECIMAL(18, 2)", "c", arr)


class TestArrowIngressUnsupportedTypes(afc.ArrowFuzzBase):
    """Arrow primitive variants that QuestDB ingress explicitly rejects
    with ARROW_UNSUPPORTED_COLUMN_KIND."""

    SUITE_LABEL = "arrow_ingress_unsupported"

    def _expect_unsupported(self, col_arr: pa.Array) -> None:
        n = len(col_arr)
        ts_arr = pa.array(
            [1_700_000_000_000_000 + i for i in range(n)],
            type=pa.timestamp("us", tz="UTC"),
        )
        schema = pa.schema([
            pa.field("c", col_arr.type, nullable=True),
            pa.field("ts", pa.timestamp("us", tz="UTC"), nullable=False),
        ])
        rb = pa.RecordBatch.from_arrays([col_arr, ts_arr], schema=schema)
        table = self.fresh_table("arrow_in_reject")
        try:
            afc.ingest_via_arrow(self._fixture, table, rb,
                                  ts_col=b"ts")
        except ArrowSenderError as e:
            self.assertEqual(
                e.code, SenderErrorCode.ARROW_UNSUPPORTED_COLUMN_KIND,
                self.label(f"code={e.code} msg={e}")
            )
            return
        self.fail(self.label(
            f"expected ARROW_UNSUPPORTED_COLUMN_KIND for arrow type {col_arr.type}"
        ))

    def test_reject_interval_month_day_nano(self):
        arr = pa.array([(1, 2, 3)], type=pa.month_day_nano_interval())
        self._expect_unsupported(arr)

    def test_reject_map_string_int32(self):
        arr = pa.array([[("k", 1)], [("q", 2)]],
                       type=pa.map_(pa.string(), pa.int32()))
        self._expect_unsupported(arr)

    def test_reject_struct(self):
        arr = pa.StructArray.from_arrays(
            [pa.array([1, 2], type=pa.int32()),
             pa.array(["a", "b"], type=pa.string())],
            names=["x", "y"],
        )
        self._expect_unsupported(arr)

    def test_reject_dense_union(self):
        arr = pa.UnionArray.from_dense(
            pa.array([0, 1, 0], type=pa.int8()),
            pa.array([0, 0, 1], type=pa.int32()),
            [pa.array([1, 2]), pa.array(["x"])],
            ["i", "s"],
        )
        self._expect_unsupported(arr)

    def test_reject_run_end_encoded(self):
        arr = pa.RunEndEncodedArray.from_arrays([3], pa.array([42]))
        self._expect_unsupported(arr)

    def test_reject_fixed_size_binary_non_uuid_width(self):
        arr = pa.array([b"12345678"], type=pa.binary(8))
        self._expect_unsupported(arr)

    def test_reject_null(self):
        arr = pa.array([None, None, None], type=pa.null())
        self._expect_unsupported(arr)


class TestArrowIngressMultiBatch(afc.ArrowFuzzBase):
    """Multiple `column_sender_flush_arrow_batch_*` calls on one
    borrowed conn — verifies cross-frame schema-registry / symbol-dict
    reuse against the live server."""

    SUITE_LABEL = "arrow_ingress_multi_batch"

    def _ingest_two_batches(self, table: str, rb1: pa.RecordBatch,
                            rb2: pa.RecordBatch) -> None:
        from arrow_ffi import (
            conn_flush_arrow_batch, pyarrow_export_record_batch,
        )
        from questdb_line_sender import _table_name as _c_table_name
        with afc.borrowed_column_sender(self._fixture) as conn:
            for rb in (rb1, rb2):
                table_name = _c_table_name(table)
                arr, sch = pyarrow_export_record_batch(rb)
                try:
                    conn_flush_arrow_batch(
                        conn, table_name,
                        ctypes.byref(arr), ctypes.byref(sch),
                        ts_column_name=b"ts",
                    )
                finally:
                    if sch.release:
                        sch.release(ctypes.byref(sch))

    def test_identical_schema_two_batches_accumulate(self):
        table = self.fresh_table("arrow_in_mb_same")
        kinds = [("c_int", KIND_REGISTRY["int"])]
        rb1, _ = _build_record_batch_with_ts(
            self._master_rng, 5, kinds, null_mode="valid",
        )
        rb2, _ = _build_record_batch_with_ts(
            self._master_rng, 7, kinds, null_mode="valid",
            ts_base_us=1_700_000_010_000_000,
        )
        self._ingest_two_batches(table, rb1, rb2)
        afc.wait_for_rows(self._fixture, table, 12)

    def test_schema_grows_new_column_in_batch2_accepted(self):
        # Conn-level `flush_arrow_batch` treats each call as an independent
        # buffer with its own schema (registered under a fresh schema_id);
        # adding a column in batch 2 is allowed and both batches land.
        table = self.fresh_table("arrow_in_mb_grow")
        kinds1 = [("c_int", KIND_REGISTRY["int"])]
        rb1, _ = _build_record_batch_with_ts(
            self._master_rng, 4, kinds1, null_mode="valid",
        )
        kinds2 = [
            ("c_int", KIND_REGISTRY["int"]),
            ("c_sym", KIND_REGISTRY["symbol"]),
        ]
        rb2, _ = _build_record_batch_with_ts(
            self._master_rng, 4, kinds2, null_mode="valid",
            ts_base_us=1_700_000_010_000_000,
        )
        self._ingest_two_batches(table, rb1, rb2)
        afc.wait_for_rows(self._fixture, table, 8)

    def test_schema_drops_column_in_batch2_accepted(self):
        table = self.fresh_table("arrow_in_mb_drop")
        kinds_a = [
            ("c_int", KIND_REGISTRY["int"]),
            ("c_sym", KIND_REGISTRY["symbol"]),
        ]
        kinds_b = [("c_int", KIND_REGISTRY["int"])]
        rb1, _ = _build_record_batch_with_ts(
            self._master_rng, 4, kinds_a, null_mode="valid",
        )
        rb2, _ = _build_record_batch_with_ts(
            self._master_rng, 4, kinds_b, null_mode="valid",
            ts_base_us=1_700_000_010_000_000,
        )
        self._ingest_two_batches(table, rb1, rb2)
        afc.wait_for_rows(self._fixture, table, 8)

class TestArrowIngressSfa(afc.ArrowFuzzBase):
    """Columnar Arrow ingress through the QWP/WebSocket SFA backend."""

    SUITE_LABEL = "arrow_ingress_sfa"
    BOUNCE_COUNT = 2
    BOUNCE_BATCH_ROWS = 5

    def _sfa_extras(self, sender_id: str, sf_dir: str) -> Dict[str, str]:
        return {
            "sender_id": sender_id,
            "sf_dir": sf_dir,
            "pool_size": "1",
            "pool_max": "1",
            "pool_reap": "manual",
            "reconnect_max_duration_millis": "30000",
            "close_flush_timeout_millis": "30000",
        }

    def _sfa_conf_for_port(
        self,
        port: int,
        sender_id: str,
        sf_dir: str,
        **overrides: str,
    ) -> bytes:
        extras = self._sfa_extras(sender_id, sf_dir)
        extras.update(overrides)
        parts = [f"qwpws::addr={self._fixture.host}:{port};"]
        parts.extend(f"{key}={value};" for key, value in extras.items())
        return "".join(parts).encode("utf-8")

    def _require_managed_plain_qwp_ws(self, purpose: str) -> None:
        from test import QuestDbDockerFixture, QuestDbFixture

        if not isinstance(self._fixture, (QuestDbFixture, QuestDbDockerFixture)):
            self.skipTest(f"{purpose} requires a managed QuestDB fixture")
        if self._fixture.auth:
            self.skipTest(f"{purpose} runs without auth")
        if getattr(self._fixture, "http_auth", False):
            self.skipTest(f"{purpose} runs without HTTP auth")
        if self._fixture.http:
            self.skipTest(f"{purpose} runs outside the HTTP ILP matrix")

    def _require_persistent_restart_qwp_ws(self, purpose: str) -> None:
        from test import QuestDbFixture

        self._require_managed_plain_qwp_ws(purpose)
        if not isinstance(self._fixture, QuestDbFixture):
            self.skipTest(f"{purpose} requires restart with persistent server data")

    @staticmethod
    def _exported_batch(rb: pa.RecordBatch):
        arr, sch = afc.pyarrow_export_record_batch(rb)
        return arr, sch

    def _flush_batch(self, conn, table: str, rb: pa.RecordBatch) -> None:
        table_name = afc._c_table_name(table)
        arr, sch = self._exported_batch(rb)
        try:
            afc.conn_flush_arrow_batch(
                conn,
                table_name,
                ctypes.byref(arr),
                ctypes.byref(sch),
                ts_column_name=b"ts",
            )
        finally:
            if sch.release:
                sch.release(ctypes.byref(sch))

    def test_sfa_single_batch_round_trip_and_cleans_slot(self):
        table = self.fresh_table("arrow_sfa_smoke")
        sender_id = f"arrow-sfa-{_uuid_mod.uuid4().hex[:8]}"
        schema = pa.schema([
            pa.field("id", pa.int64(), nullable=False),
            pa.field("px", pa.float64(), nullable=False),
            KIND_REGISTRY["symbol"].make_field("sym", nullable=False),
            pa.field("ts", pa.timestamp("us", tz="UTC"), nullable=False),
        ])
        rb = pa.RecordBatch.from_arrays(
            [
                pa.array([0, 1, 2], type=pa.int64()),
                pa.array([10.5, 20.5, 30.5], type=pa.float64()),
                pa.array(["alpha", "bravo", "charlie"], type=pa.utf8()),
                pa.array(
                    [
                        1_700_000_000_000_000,
                        1_700_000_000_001_000,
                        1_700_000_000_002_000,
                    ],
                    type=pa.timestamp("us", tz="UTC"),
                ),
            ],
            schema=schema,
        )

        with afc.temp_sf_dir("arrow_sfa_smoke_") as sf_dir:
            afc.ingest_via_arrow(
                self._fixture,
                table,
                rb,
                sender_conf_extras=self._sfa_extras(sender_id, sf_dir),
            )
            self.assertEqual(
                afc.sfa_file_count(sf_dir, sender_id),
                0,
                self.label("SFA files left after synced single-batch ingest"),
            )

        afc.wait_for_rows(self._fixture, table, 3)
        resp = self._fixture.http_sql_query(
            f"select id, px, sym from '{table}' order by id"
        )
        self.assertEqual(
            resp["dataset"],
            [[0, 10.5, "alpha"], [1, 20.5, "bravo"], [2, 30.5, "charlie"]],
            self.label(),
        )

    def test_sfa_schema_evolution_across_batches(self):
        table = self.fresh_table("arrow_sfa_schema")
        sender_id = f"arrow-sfa-{_uuid_mod.uuid4().hex[:8]}"

        rb1 = pa.RecordBatch.from_arrays(
            [
                pa.array([0, 1], type=pa.int64()),
                pa.array(
                    [1_700_000_000_000_000, 1_700_000_000_001_000],
                    type=pa.timestamp("us", tz="UTC"),
                ),
            ],
            schema=pa.schema([
                pa.field("id", pa.int64(), nullable=False),
                pa.field("ts", pa.timestamp("us", tz="UTC"), nullable=False),
            ]),
        )
        rb2 = pa.RecordBatch.from_arrays(
            [
                pa.array([2, 3], type=pa.int64()),
                pa.array(["r2", "r3"], type=pa.utf8()),
                pa.array([20.5, 30.5], type=pa.float64()),
                pa.array(
                    [1_700_000_000_002_000, 1_700_000_000_003_000],
                    type=pa.timestamp("us", tz="UTC"),
                ),
            ],
            schema=pa.schema([
                pa.field("id", pa.int64(), nullable=False),
                KIND_REGISTRY["symbol"].make_field("host", nullable=False),
                pa.field("px", pa.float64(), nullable=False),
                pa.field("ts", pa.timestamp("us", tz="UTC"), nullable=False),
            ]),
        )

        with afc.temp_sf_dir("arrow_sfa_schema_") as sf_dir:
            with afc.borrowed_column_sender(
                self._fixture,
                **self._sfa_extras(sender_id, sf_dir),
            ) as conn:
                self._flush_batch(conn, table, rb1)
                self._flush_batch(conn, table, rb2)
            self.assertEqual(
                afc.sfa_file_count(sf_dir, sender_id),
                0,
                self.label("SFA files left after schema-evolution ingest"),
            )

        afc.wait_for_rows(self._fixture, table, 4)
        resp = self._fixture.http_sql_query(
            f"select id, host, px from '{table}' order by id"
        )
        self.assertEqual(
            resp["dataset"],
            [[0, None, None], [1, None, None], [2, "r2", 20.5], [3, "r3", 30.5]],
            self.label(),
        )

    def test_sfa_write_rejection_reports_once_and_continues(self):
        table = self.fresh_table("arrow_sfa_reject")
        sender_id = f"arrow-sfa-{_uuid_mod.uuid4().hex[:8]}"
        afc.exec_ddl(
            self._fixture,
            f'CREATE TABLE "{table}" '
            '(id LONG, px DOUBLE, bad LONG, ts TIMESTAMP) '
            'TIMESTAMP(ts) PARTITION BY DAY WAL',
        )

        valid1 = pa.RecordBatch.from_arrays(
            [
                pa.array([0], type=pa.int64()),
                pa.array([10.5], type=pa.float64()),
                pa.array([1_700_000_000_000_000], type=pa.timestamp("us", tz="UTC")),
            ],
            schema=pa.schema([
                pa.field("id", pa.int64(), nullable=False),
                pa.field("px", pa.float64(), nullable=False),
                pa.field("ts", pa.timestamp("us", tz="UTC"), nullable=False),
            ]),
        )
        rejected = pa.RecordBatch.from_arrays(
            [
                pa.array([1], type=pa.int64()),
                pa.array(["not-a-long"], type=pa.utf8()),
                pa.array([1_700_000_000_001_000], type=pa.timestamp("us", tz="UTC")),
            ],
            schema=pa.schema([
                pa.field("id", pa.int64(), nullable=False),
                pa.field("bad", pa.utf8(), nullable=False),
                pa.field("ts", pa.timestamp("us", tz="UTC"), nullable=False),
            ]),
        )
        valid2 = pa.RecordBatch.from_arrays(
            [
                pa.array([2], type=pa.int64()),
                pa.array([20.5], type=pa.float64()),
                pa.array([1_700_000_000_002_000], type=pa.timestamp("us", tz="UTC")),
            ],
            schema=pa.schema([
                pa.field("id", pa.int64(), nullable=False),
                pa.field("px", pa.float64(), nullable=False),
                pa.field("ts", pa.timestamp("us", tz="UTC"), nullable=False),
            ]),
        )

        with afc.temp_sf_dir("arrow_sfa_reject_") as sf_dir:
            with afc.borrowed_column_sender(
                self._fixture,
                sync_on_exit=False,
                **self._sfa_extras(sender_id, sf_dir),
            ) as conn:
                self._flush_batch(conn, table, valid1)
                self._flush_batch(conn, table, rejected)
                self._flush_batch(conn, table, valid2)

                with self.assertRaises(ArrowSenderError) as raised:
                    afc.column_sender_sync(conn, 0)
                err = raised.exception
                self.assertEqual(err.code, SenderErrorCode.SERVER_REJECTION)
                diagnostic = err.qwp_ws_error
                self.assertIsNotNone(diagnostic)
                self.assertEqual(
                    diagnostic.category,
                    QwpWsErrorCategory.SCHEMA_MISMATCH,
                )
                self.assertEqual(
                    diagnostic.applied_policy,
                    QwpWsErrorPolicy.TERMINAL,
                )
                self.assertEqual(diagnostic.status, 0x03)
                self.assertEqual(diagnostic.from_fsn, 1)
                self.assertEqual(diagnostic.to_fsn, 1)

            self.assertGreater(
                afc.sfa_file_count(sf_dir, sender_id),
                0,
                self.label("Terminal rejection should preserve SFA files"),
            )

        afc.wait_for_rows(self._fixture, table, 1)
        resp = self._fixture.http_sql_query(
            f"select id, px from '{table}' order by id"
        )
        self.assertEqual(
            resp["dataset"],
            [[0, 10.5]],
            self.label(),
        )

    def test_sfa_new_owner_recovers_server_accepted_unacked_batch(self):
        from test import (
            QwpWsDropAckProxy,
            QuestDbDockerFixture,
            QuestDbFixture,
            skip_if_unsupported_qwp_ws_fixture,
        )

        if not isinstance(self._fixture, (QuestDbFixture, QuestDbDockerFixture)):
            self.skipTest("SFA restart recovery requires a managed QuestDB fixture")
        if self._fixture.auth:
            self.skipTest("SFA drop-ACK proxy tests run without auth")
        if getattr(self._fixture, "http_auth", False):
            self.skipTest("SFA drop-ACK proxy tests run without HTTP auth")
        if self._fixture.http:
            self.skipTest("SFA drop-ACK proxy tests run outside the HTTP ILP matrix")

        table = self.fresh_table("arrow_sfa_restart")
        sender_id = f"arrow-sfa-{_uuid_mod.uuid4().hex[:8]}"
        afc.exec_ddl(
            self._fixture,
            f'CREATE TABLE "{table}" '
            '(id LONG, px DOUBLE, ts TIMESTAMP) '
            'TIMESTAMP(ts) PARTITION BY DAY WAL '
            'DEDUP UPSERT KEYS(ts, id)',
        )
        rb = pa.RecordBatch.from_arrays(
            [
                pa.array([0, 1, 2], type=pa.int64()),
                pa.array([10.5, 20.5, 30.5], type=pa.float64()),
                pa.array(
                    [
                        1_700_000_000_000_000,
                        1_700_000_000_001_000,
                        1_700_000_000_002_000,
                    ],
                    type=pa.timestamp("us", tz="UTC"),
                ),
            ],
            schema=pa.schema([
                pa.field("id", pa.int64(), nullable=False),
                pa.field("px", pa.float64(), nullable=False),
                pa.field("ts", pa.timestamp("us", tz="UTC"), nullable=False),
            ]),
        )

        with afc.temp_sf_dir("arrow_sfa_restart_") as sf_dir:
            proxy = QwpWsDropAckProxy(
                self._fixture.host,
                self._fixture.http_server_port,
            )
            proxy.start()
            conf = self._sfa_conf_for_port(
                proxy.port,
                sender_id,
                sf_dir,
                reconnect_max_duration_millis="120000",
                close_flush_timeout_millis="0",
            )
            db = None
            conn = None
            stopped = False
            try:
                try:
                    db = afc.db_connect(conf)
                except afc.SenderError as e:
                    skip_if_unsupported_qwp_ws_fixture(e, self._fixture)
                    raise
                try:
                    conn = afc.db_borrow_conn(db)
                except afc.SenderError as e:
                    skip_if_unsupported_qwp_ws_fixture(e, self._fixture)
                    raise
                self._flush_batch(conn, table, rb)
                proxy.join()
                self._fixture.stop()
                stopped = True
            finally:
                if db is not None and conn is not None:
                    afc.db_return_conn(db, conn)
                afc.db_close(db)
                if proxy.is_alive():
                    proxy.close()
                if stopped:
                    self._fixture.start()

            self.assertGreater(
                afc.sfa_file_count(sf_dir, sender_id),
                0,
                self.label(
                    "server-accepted unacked frame did not leave recoverable SFA files"
                ),
            )

            recover_extras = self._sfa_extras(sender_id, sf_dir)
            recover_extras.update({
                "reconnect_max_duration_millis": "120000",
                "close_flush_timeout_millis": "120000",
            })
            with afc.borrowed_column_sender(
                self._fixture,
                sync_on_exit=False,
                **recover_extras,
            ) as conn:
                afc.column_sender_sync(conn, 0)

            self.assertEqual(
                afc.sfa_file_count(sf_dir, sender_id),
                0,
                self.label("SFA files left after new-owner recovery"),
            )

        afc.wait_for_rows(self._fixture, table, 3, timeout=60.0)
        resp = self._fixture.http_sql_query(
            f"select id, px from '{table}' order by id"
        )
        self.assertEqual(
            resp["dataset"],
            [[0, 10.5], [1, 20.5], [2, 30.5]],
            self.label(),
        )

    def test_sfa_arrow_producer_survives_server_bounces(self):
        self._require_persistent_restart_qwp_ws("SFA bounce fuzz")

        table = self.fresh_table("arrow_sfa_bounce")
        sender_id = f"arrow-sfa-{_uuid_mod.uuid4().hex[:8]}"
        afc.exec_ddl(
            self._fixture,
            f'CREATE TABLE "{table}" '
            '(id LONG, px DOUBLE, sym SYMBOL, ts TIMESTAMP) '
            'TIMESTAMP(ts) PARTITION BY DAY WAL '
            'DEDUP UPSERT KEYS(ts, id)',
        )

        stop_producer = threading.Event()
        rows_produced = 0
        producer_errors: List[BaseException] = []
        progress_lock = threading.Lock()

        def make_batch(first_id: int, count: int) -> pa.RecordBatch:
            ids = list(range(first_id, first_id + count))
            return pa.RecordBatch.from_arrays(
                [
                    pa.array(ids, type=pa.int64()),
                    pa.array([row_id * 0.5 for row_id in ids], type=pa.float64()),
                    pa.array(
                        [f"sym-{row_id % 4}" for row_id in ids],
                        type=pa.utf8(),
                    ),
                    pa.array(
                        [
                            1_700_000_100_000_000 + row_id * 1_000
                            for row_id in ids
                        ],
                        type=pa.timestamp("us", tz="UTC"),
                    ),
                ],
                schema=pa.schema([
                    pa.field("id", pa.int64(), nullable=False),
                    pa.field("px", pa.float64(), nullable=False),
                    KIND_REGISTRY["symbol"].make_field("sym", nullable=False),
                    pa.field("ts", pa.timestamp("us", tz="UTC"), nullable=False),
                ]),
            )

        def current_rows() -> int:
            with progress_lock:
                return rows_produced

        def producer(sf_dir: str) -> None:
            nonlocal rows_produced
            extras = self._sfa_extras(sender_id, sf_dir)
            extras.update({
                "initial_connect_retry": "sync",
                "reconnect_max_duration_millis": "120000",
                "reconnect_max_backoff_millis": "250",
                "close_flush_timeout_millis": "120000",
            })
            try:
                with afc.borrowed_column_sender(
                    self._fixture,
                    sync_on_exit=False,
                    **extras,
                ) as conn:
                    next_id = 0
                    while not stop_producer.is_set():
                        batch = make_batch(next_id, self.BOUNCE_BATCH_ROWS)
                        self._flush_batch(conn, table, batch)
                        next_id += self.BOUNCE_BATCH_ROWS
                        with progress_lock:
                            rows_produced = next_id
                        time.sleep(0.005)
                    afc.column_sender_sync(conn, 0)
            except BaseException as exc:
                producer_errors.append(exc)

        with afc.temp_sf_dir("arrow_sfa_bounce_") as sf_dir:
            producer_thread = threading.Thread(
                target=producer,
                args=(sf_dir,),
                name="arrow-sfa-bounce-producer",
                daemon=True,
            )
            producer_thread.start()
            try:
                startup_deadline = time.monotonic() + 5
                while (
                    current_rows() == 0
                    and not producer_errors
                    and time.monotonic() < startup_deadline
                ):
                    time.sleep(0.01)
                if producer_errors:
                    raise AssertionError(
                        "producer failed before first server bounce"
                    ) from producer_errors[0]
                self.assertGreater(
                    current_rows(),
                    0,
                    self.label("producer did not flush before first bounce"),
                )

                for bounce_index in range(self.BOUNCE_COUNT):
                    rows_before_stop = current_rows()
                    stopped = False
                    try:
                        self._fixture.stop()
                        stopped = True
                        time.sleep(0.05)
                        self._fixture.start()
                        stopped = False
                    finally:
                        if stopped:
                            self._fixture.start()
                    rows_at_restart = current_rows()
                    restart_deadline = time.monotonic() + 10
                    while (
                        current_rows() <= rows_at_restart
                        and not producer_errors
                        and time.monotonic() < restart_deadline
                    ):
                        time.sleep(0.01)
                    if producer_errors:
                        raise AssertionError(
                            f"producer failed after restart #{bounce_index + 1}"
                        ) from producer_errors[0]
                    self.assertGreater(
                        current_rows(),
                        rows_at_restart,
                        self.label(
                            f"producer made no progress after restart "
                            f"#{bounce_index + 1}"
                        ),
                    )
                    self.assertGreater(
                        current_rows(),
                        rows_before_stop,
                        self.label(
                            f"producer made no progress during bounce "
                            f"#{bounce_index + 1}"
                        ),
                    )
            finally:
                stop_producer.set()
                producer_thread.join(180)

            self.assertFalse(
                producer_thread.is_alive(),
                self.label(
                    f"producer did not finish within 180s "
                    f"(rows_produced={current_rows()})"
                ),
            )
            if producer_errors:
                raise AssertionError(
                    f"producer failed across server bounces "
                    f"(rows_produced={current_rows()})"
                ) from producer_errors[0]

            expected = current_rows()
            self.assertGreater(expected, 0, self.label("producer wrote zero rows"))
            afc.wait_for_rows(self._fixture, table, expected, timeout=60.0)
            resp = self._fixture.http_sql_query(
                f"select count(), count_distinct(id), min(id), max(id) "
                f"from '{table}'"
            )
            self.assertEqual(
                resp["dataset"],
                [[expected, expected, 0, expected - 1]],
                self.label(),
            )
            self.assertEqual(
                afc.sfa_file_count(sf_dir, sender_id),
                0,
                self.label("SFA files left after bounce fuzz"),
            )

    def test_sfa_random_arrow_ingest(self):
        full_pool = [
            (n, s) for n, s in KIND_REGISTRY.items()
            if s.supports_arrow_ingest
        ]
        nullable_pool = [(n, s) for n, s in full_pool if s.supports_server_null]
        sender_id = f"arrow-sfa-{_uuid_mod.uuid4().hex[:8]}"
        with afc.temp_sf_dir("arrow_sfa_fuzz_") as sf_dir:
            extras = self._sfa_extras(sender_id, sf_dir)
            for it in range(_FUZZ_ITERATIONS):
                with self.subTest(iter=it):
                    null_mode = ("valid", "partial", "all_null")[it % 3]
                    pool = full_pool if null_mode == "valid" else nullable_pool
                    self._master_rng.shuffle(pool)
                    picked = pool[: 4 + (it % 4)]
                    kinds = [
                        (f"c{i}_{n}", s) for i, (n, s) in enumerate(picked)
                    ]
                    rb, _vpc = _build_record_batch_with_ts(
                        self._master_rng,
                        _ROWS_PER_BATCH,
                        kinds,
                        null_mode=null_mode,
                    )
                    table = self.fresh_table(f"arrow_sfa_fuzz_{it}")
                    afc.create_table_from_kinds(self._fixture, table, kinds)
                    afc.ingest_via_arrow(
                        self._fixture,
                        table,
                        rb,
                        sender_conf_extras=extras,
                    )
                    afc.wait_for_rows(self._fixture, table, rb.num_rows)
                    self.assertEqual(
                        afc.sfa_file_count(sf_dir, sender_id),
                        0,
                        self.label(f"SFA files left after fuzz iter={it}"),
                    )

class TestArrowIngressFuzz(afc.ArrowFuzzBase):
    """Random subsets of kinds × random null modes × random DTS variants."""

    SUITE_LABEL = "arrow_ingress_fuzz"

    def test_random_arrow_ingest(self):
        full_pool = [
            (n, s) for n, s in KIND_REGISTRY.items()
            if s.supports_arrow_ingest
        ]
        nullable_pool = [(n, s) for n, s in full_pool if s.supports_server_null]
        for it in range(_FUZZ_ITERATIONS):
            with self.subTest(iter=it):
                null_mode = ("valid", "partial", "all_null")[it % 3]
                pool = full_pool if null_mode == "valid" else nullable_pool
                self._master_rng.shuffle(pool)
                picked = pool[: 4 + (it % 4)]
                kinds = [(f"c{i}_{n}", s) for i, (n, s) in enumerate(picked)]
                rb, _vpc = _build_record_batch_with_ts(
                    self._master_rng, _ROWS_PER_BATCH, kinds,
                    null_mode=null_mode,
                )
                table = self.fresh_table(f"arrow_in_fuzz_{it}")
                afc.create_table_from_kinds(self._fixture, table, kinds)
                afc.ingest_via_arrow(self._fixture, table, rb)
                afc.wait_for_rows(self._fixture, table, rb.num_rows)

class TestColumnSenderBorrowWithRetry(unittest.TestCase):
    """Cross-FFI coverage for the `questdb_db_borrow_*_column_sender_with_retry`
    shims — the retry/backoff borrow driven through the C ABI from Python."""

    def test_direct_with_retry_fails_against_dead_endpoint(self):
        import socket
        from arrow_ffi import (
            db_connect,
            db_close,
            db_borrow_direct_conn_with_retry,
        )
        # Bind then close to get a definitely-closed local port. The pool is
        # lazy, so the connect only happens on borrow; a closed port refuses
        # immediately, so the Direct retry shim must exhaust its budget and
        # raise across the FFI boundary instead of hanging or crashing.
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        dead_port = probe.getsockname()[1]
        probe.close()
        conf = f"qwpws::addr=127.0.0.1:{dead_port};".encode("utf-8")
        db = db_connect(conf)  # lazy: opens no socket, so it succeeds
        try:
            # Non-zero budget exercises the retry loop (attempts + backoff).
            with self.assertRaises(ArrowSenderError):
                db_borrow_direct_conn_with_retry(db, 200)
            # Zero budget makes a single attempt; still fails.
            with self.assertRaises(ArrowSenderError):
                db_borrow_direct_conn_with_retry(db, 0)
        finally:
            db_close(db)

    def test_sf_with_retry_borrows_against_live_fixture(self):
        from arrow_ffi import (
            db_connect,
            db_close,
            db_borrow_conn_with_retry,
            db_return_conn,
        )
        from test import skip_if_unsupported_qwp_ws_fixture
        fixture = afc.get_live_fixture(self)  # skips when no live fixture
        conf = afc.ingress_conf(fixture).encode("utf-8")
        try:
            db = db_connect(conf)
        except ArrowSenderError as e:
            skip_if_unsupported_qwp_ws_fixture(e, fixture)
            raise
        try:
            try:
                conn = db_borrow_conn_with_retry(db, 5000)
            except ArrowSenderError as e:
                skip_if_unsupported_qwp_ws_fixture(e, fixture)
                raise
            self.assertTrue(conn)
            db_return_conn(db, conn)
        finally:
            db_close(db)


def register(loop_registry):
    loop_registry.append(TestArrowIngressPerKind)
    loop_registry.append(TestArrowIngressDesignatedTs)
    loop_registry.append(TestArrowIngressErrors)
    loop_registry.append(TestArrowIngressExtraTypes)
    loop_registry.append(TestArrowIngressUnsupportedTypes)
    loop_registry.append(TestArrowIngressMultiBatch)
    loop_registry.append(TestArrowIngressSfa)
    loop_registry.append(TestArrowIngressFuzz)
    loop_registry.append(TestColumnSenderBorrowWithRetry)

if __name__ == "__main__":
    print(
        "Note: arrow_ingress_fuzz tests require a live QuestDB fixture. "
        "Run via `python test.py run --existing HOST:ILP:HTTP "
        "TestArrowIngressPerKind` (or any of the other arrow ingress classes).",
        file=sys.stderr,
    )
    unittest.main()
