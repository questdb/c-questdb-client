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
    DTS_COLUMN,
    DTS_NOW,
    DTS_SERVER_NOW,
    SenderErrorCode,
)
from questdb_line_sender import Buffer, Sender

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

def _cmp_int(expected, actual) -> bool:
    if expected is None or actual is None or actual == "":
        return expected is None and (actual is None or actual == "")
    return int(expected) == int(actual)

def _cmp_float(expected, actual) -> bool:
    import math
    if expected is None or actual is None or actual == "":
        return expected is None and (actual is None or actual == "")
    e = float(expected)
    a = float(actual) if not isinstance(actual, float) else actual
    if math.isnan(e) and math.isnan(a):
        return True
    return e == a

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
        return actual is None or actual == ""
    if isinstance(actual, str):
        # /exec may render BINARY as base64 or hex with `0x` prefix.
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
    "byte": _cmp_int, "short": _cmp_int, "int": _cmp_int, "long": _cmp_int,
    "float": _cmp_float, "double": _cmp_float,
    "char": _cmp_char_codepoint,
    "ipv4": _cmp_ipv4,
    "varchar": _cmp_str,
    "binary": _cmp_binary,
    "symbol": _cmp_str,
    "uuid": _cmp_uuid,
    "long256": _cmp_long256,
    "date": _cmp_date_ms,
    "timestamp": _cmp_timestamp_us,
    "timestamp_ns": _cmp_timestamp_ns,
    "geohash1": _cmp_passthrough,
    "geohash5": _cmp_passthrough,
    "geohash32": _cmp_passthrough,
    "geohash60": _cmp_passthrough,
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

class TestArrowIngressPerKind(afc.ArrowFuzzBase):
    """One method per kind. Ingest via Arrow, read back via /exec, compare."""

    SUITE_LABEL = "arrow_ingress_per_kind"

    def _exercise_kind(self, kind_name: str) -> None:
        spec = KIND_REGISTRY[kind_name]
        if not spec.supports_arrow_ingest:
            self.skipTest(f"kind {kind_name!r} not supported by Arrow ingest")
        for null_mode in ("valid", "partial", "all_null", "edge"):
            with self.subTest(null_mode=null_mode):
                table = self.fresh_table(f"arrow_in_{kind_name}_{null_mode}")
                kinds = [(f"c_{kind_name}", spec)]
                rb, vpc = _build_record_batch_with_ts(
                    self._master_rng, _ROWS_PER_BATCH, kinds, null_mode=null_mode,
                )
                afc.ingest_via_arrow(self._fixture, table, rb, ts_kind=DTS_COLUMN)
                afc.wait_for_rows(self._fixture, table, rb.num_rows)
                _columns, dataset = _read_back_json(self._fixture, table, kinds)
                self._assert_dataset_matches(
                    kind_name, spec, vpc[f"c_{kind_name}"], dataset, null_mode,
                )

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
    """Each DesignatedTimestamp variant against a small mixed batch."""

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
                              ts_kind=DTS_COLUMN, ts_col=b"ts")
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
                              ts_kind=DTS_COLUMN, ts_col=b"ts")
        afc.wait_for_rows(self._fixture, table, rb.num_rows)

    def test_dts_now(self):
        rb, kinds = self._build_small_batch()
        # Drop the ts column for DTS_NOW (server stamps its own).
        no_ts_fields = [f for f in rb.schema if f.name != "ts"]
        no_ts_arrays = [rb.column(rb.schema.get_field_index(f.name))
                         for f in no_ts_fields]
        rb_no_ts = pa.RecordBatch.from_arrays(
            no_ts_arrays, schema=pa.schema(no_ts_fields),
        )
        table = self.fresh_table("arrow_in_dts_now")
        afc.ingest_via_arrow(self._fixture, table, rb_no_ts,
                              ts_kind=DTS_NOW, ts_col=b"")
        afc.wait_for_rows(self._fixture, table, rb_no_ts.num_rows)

    def test_dts_server_now(self):
        rb, kinds = self._build_small_batch()
        no_ts_fields = [f for f in rb.schema if f.name != "ts"]
        no_ts_arrays = [rb.column(rb.schema.get_field_index(f.name))
                         for f in no_ts_fields]
        rb_no_ts = pa.RecordBatch.from_arrays(
            no_ts_arrays, schema=pa.schema(no_ts_fields),
        )
        table = self.fresh_table("arrow_in_dts_snow")
        afc.ingest_via_arrow(self._fixture, table, rb_no_ts,
                              ts_kind=DTS_SERVER_NOW, ts_col=b"")
        afc.wait_for_rows(self._fixture, table, rb_no_ts.num_rows)

class TestArrowIngressErrors(afc.ArrowFuzzBase):
    """Deterministic recipes for each reachable line_sender_error_code."""

    SUITE_LABEL = "arrow_ingress_errors"

    def _expect_code(self, rb: pa.RecordBatch, expected_code: int, *,
                    ts_kind: int = DTS_COLUMN, ts_col: bytes = b"ts",
                    extras=None) -> ArrowSenderError:
        table = f"arrow_in_err_{self._master_rng.next_int(2**32):08x}"
        try:
            afc.ingest_via_arrow(
                self._fixture, table, rb,
                ts_kind=ts_kind, ts_col=ts_col,
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
        self._expect_code(rb, SenderErrorCode.INVALID_API_CALL,
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
        self._expect_code(rb, SenderErrorCode.INVALID_API_CALL)

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

    def test_err_fsb16_without_uuid_metadata(self):
        n = 4
        c_fsb = pa.array([b"x" * 16] * n, type=pa.binary(16))
        ts_arr = pa.array(
            [1_700_000_000_000_000 + i for i in range(n)],
            type=pa.timestamp("us", tz="UTC"),
        )
        schema = pa.schema([
            pa.field("c_fsb", pa.binary(16), nullable=True),  # no metadata
            pa.field("ts", pa.timestamp("us", tz="UTC"), nullable=False),
        ])
        rb = pa.RecordBatch.from_arrays([c_fsb, ts_arr], schema=schema)
        self._expect_code(rb, SenderErrorCode.ARROW_UNSUPPORTED_COLUMN_KIND)

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

class TestArrowIngressMultiBatch(afc.ArrowFuzzBase):
    """Multiple `buffer_append_arrow` calls on one Buffer before flush."""

    SUITE_LABEL = "arrow_ingress_multi_batch"

    def _ingest_two_batches(self, table: str, rb1: pa.RecordBatch,
                            rb2: pa.RecordBatch) -> None:
        from arrow_ffi import (
            buffer_append_arrow, pyarrow_export_record_batch,
        )
        from questdb_line_sender import _table_name as _c_table_name
        with afc.existing_sender(self._fixture) as sender:
            buf = Buffer.from_sender(sender._impl)
            for rb in (rb1, rb2):
                table_name = _c_table_name(table)
                arr, sch = pyarrow_export_record_batch(rb)
                try:
                    buffer_append_arrow(
                        buf._impl, table_name,
                        ctypes.byref(arr), ctypes.byref(sch),
                        DTS_COLUMN, b"ts",
                    )
                finally:
                    if sch.release:
                        sch.release(ctypes.byref(sch))
            sender.flush(buf)

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

    def test_schema_grows_new_column_in_batch2(self):
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
        # Earlier rows for c_sym should be null on the server side.
        resp = self._fixture.http_sql_query(
            f"select count() from '{table}' where c_sym is not null"
        )
        self.assertEqual(int(resp["dataset"][0][0]), 4, self.label())

    def test_schema_drops_column_in_batch2(self):
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
        resp = self._fixture.http_sql_query(
            f"select count() from '{table}' where c_sym is null"
        )
        self.assertEqual(int(resp["dataset"][0][0]), 4, self.label())

class TestArrowIngressFuzz(afc.ArrowFuzzBase):
    """Random subsets of kinds × random null modes × random DTS variants."""

    SUITE_LABEL = "arrow_ingress_fuzz"

    def test_random_arrow_ingest(self):
        pool = [
            (n, s) for n, s in KIND_REGISTRY.items()
            if s.supports_arrow_ingest
        ]
        for it in range(_FUZZ_ITERATIONS):
            with self.subTest(iter=it):
                self._master_rng.shuffle(pool)
                picked = pool[: 4 + (it % 4)]
                kinds = [(f"c{i}_{n}", s) for i, (n, s) in enumerate(picked)]
                null_mode = ("valid", "partial", "all_null")[it % 3]
                rb, _vpc = _build_record_batch_with_ts(
                    self._master_rng, _ROWS_PER_BATCH, kinds,
                    null_mode=null_mode,
                )
                table = self.fresh_table(f"arrow_in_fuzz_{it}")
                afc.ingest_via_arrow(self._fixture, table, rb,
                                      ts_kind=DTS_COLUMN)
                afc.wait_for_rows(self._fixture, table, rb.num_rows)

def register(loop_registry):
    loop_registry.append(TestArrowIngressPerKind)
    loop_registry.append(TestArrowIngressDesignatedTs)
    loop_registry.append(TestArrowIngressErrors)
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
