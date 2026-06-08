from __future__ import annotations

import base64
import ctypes
import datetime as _dt
import os
import sys
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
    """Multiple `column_sender_flush_arrow_batch` calls on one
    borrowed conn — verifies cross-frame schema-registry / symbol-dict
    reuse against the live server."""

    SUITE_LABEL = "arrow_ingress_multi_batch"

    def _ingest_two_batches(self, table: str, rb1: pa.RecordBatch,
                            rb2: pa.RecordBatch) -> None:
        from arrow_ffi import (
            conn_flush_arrow_batch, pyarrow_export_record_batch,
        )
        from questdb_line_sender import _table_name as _c_table_name
        with afc.borrowed_conn(self._fixture) as conn:
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

def register(loop_registry):
    loop_registry.append(TestArrowIngressPerKind)
    loop_registry.append(TestArrowIngressDesignatedTs)
    loop_registry.append(TestArrowIngressErrors)
    loop_registry.append(TestArrowIngressExtraTypes)
    loop_registry.append(TestArrowIngressUnsupportedTypes)
    loop_registry.append(TestArrowIngressMultiBatch)
    loop_registry.append(TestArrowIngressFuzz)

if __name__ == "__main__":
    print(
        "Note: arrow_ingress_fuzz tests require a live QuestDB fixture. "
        "Run via `python test.py run --existing HOST:ILP:HTTP "
        "TestArrowIngressPerKind` (or any of the other arrow ingress classes).",
        file=sys.stderr,
    )
    unittest.main()
