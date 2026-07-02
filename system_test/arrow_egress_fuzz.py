from __future__ import annotations

import os
import sys
import unittest
from typing import List, Tuple

import pyarrow as pa

import arrow_fuzz_common as afc
from arrow_fuzz_common import KIND_REGISTRY, KindSpec

_FUZZ_ITERATIONS = int(os.environ.get("ARROW_EGRESS_FUZZ_ITERATIONS", "6"))
_ROWS_PER_BATCH = int(os.environ.get("ARROW_EGRESS_FUZZ_ROWS", "16"))


def _ilp_capable_kinds() -> List[Tuple[str, KindSpec]]:
    return [(k, s) for k, s in KIND_REGISTRY.items() if s.supports_ilp_setter]


def _populate_table_via_ilp(sender, table: str, kinds, values_per_col, ts_base_us: int) -> None:
    n = len(next(iter(values_per_col.values()))) if values_per_col else 0
    ordered = sorted(kinds, key=lambda kv: 0 if kv[1].name == "symbol" else 1)
    for r in range(n):
        sender.table(table)
        wrote_any = False
        for col_name, spec in ordered:
            v = values_per_col[col_name][r]
            if v is None:
                continue
            spec.ilp_set(sender, col_name, v)
            wrote_any = True
        if not wrote_any:
            sender.column("_keep", True)
        sender.at_micros(ts_base_us + r)
    sender.flush()

def _read_back_arrow(fixture, table: str, kinds) -> pa.RecordBatch:
    cols_sql = ", ".join(f'"{c}"' for c, _ in kinds)
    sql = f"select {cols_sql} from '{table}' order by ts"
    return afc.read_back_arrow_concat(fixture, sql)

def _ingest_and_read_back(testcase, table: str, kinds, *, null_mode: str
                          ) -> Tuple[pa.RecordBatch, dict]:
    afc.create_table_from_kinds(testcase._fixture, table, kinds)
    rnd = testcase._master_rng
    n = _ROWS_PER_BATCH
    values_per_col: dict = {}
    for col_name, spec in kinds:
        if null_mode == "valid":
            mask = afc.all_valid_mask(n)
            edge = False
        elif null_mode == "partial":
            mask = afc.partial_null_mask(rnd, n, null_p=0.3)
            edge = False
        elif null_mode == "all_null":
            mask = afc.all_null_mask(n)
            edge = False
        elif null_mode == "edge":
            mask = afc.all_valid_mask(n)
            edge = True
        else:
            raise ValueError(null_mode)
        values_per_col[col_name] = spec.generate_values(rnd, n, mask, edge=edge)
    ts_base = 1_700_000_000_000_000 + rnd.next_int(1_000_000)
    with afc.existing_sender(testcase._fixture) as sender:
        _populate_table_via_ilp(sender, table, kinds, values_per_col, ts_base)
    afc.wait_for_rows(testcase._fixture, table, n)
    rb = _read_back_arrow(testcase._fixture, table, kinds)
    return rb, values_per_col

def _build_expected_arrow(kinds, values_per_col, num_rows: int) -> pa.RecordBatch:
    arrays = []
    fields = []
    for col_name, spec in kinds:
        arr = spec.build_arrow_array(values_per_col[col_name])
        arrays.append(arr)
        fields.append(spec.make_field(col_name))
    return pa.RecordBatch.from_arrays(arrays, schema=pa.schema(fields))

class TestArrowEgressPerKind(afc.ArrowFuzzBase):
    """One test method per kind covering all four null modes via sub-tests."""

    SUITE_LABEL = "arrow_egress_per_kind"

    def _exercise_kind(self, kind_name: str) -> None:
        spec = KIND_REGISTRY[kind_name]
        if not spec.supports_ilp_setter:
            self.skipTest(f"kind {kind_name!r} has no ILP setter (Arrow-ingest only)")
        modes = ["valid", "edge"]
        if spec.supports_server_null:
            modes[1:1] = ["partial", "all_null"]
        for null_mode in modes:
            with self.subTest(null_mode=null_mode):
                table = self.fresh_table(f"arrow_eg_{kind_name}_{null_mode}")
                kinds = [(f"c_{kind_name}", spec)]
                rb, values_per_col = _ingest_and_read_back(
                    self, table, kinds, null_mode=null_mode,
                )
                self._assert_kind_round_trip(rb, kinds, values_per_col, null_mode)

    def _assert_kind_round_trip(self, rb, kinds, values_per_col, null_mode: str) -> None:
        col_name, spec = kinds[0]
        self.assertEqual(rb.num_columns, 1, self.label(f"kind={spec.name}"))
        self.assertEqual(rb.num_rows, _ROWS_PER_BATCH,
                         self.label(f"row count kind={spec.name}"))
        expected_dtype = spec.arrow_type()
        actual_dtype = _storage_type(rb.column(0).type)
        if not _dtype_compatible(actual_dtype, expected_dtype):
            self.fail(self.label(
                f"DataType mismatch kind={spec.name}: "
                f"want {expected_dtype}, got {actual_dtype}"
            ))
        self._assert_field_metadata(rb.schema.field(0), spec)
        expected_values = values_per_col[col_name]
        for r in range(rb.num_rows):
            expected = expected_values[r]
            actual = _scalar_to_python(rb.column(0)[r], spec)
            expected_canon = _canonicalise_for_compare(expected, spec)
            actual_canon = _canonicalise_for_compare(actual, spec)
            if not spec.compare(actual_canon, expected_canon):
                self.fail(self.label(
                    f"kind={spec.name} mode={null_mode} row={r}: "
                    f"expected {expected_canon!r}, got {actual_canon!r}"
                ))

    def _assert_field_metadata(self, field: pa.Field, spec: KindSpec) -> None:
        expected_md = spec.metadata() or {}
        if not expected_md:
            return
        actual_md = dict(field.metadata or {})
        ext_name = getattr(field.type, "extension_name", None)
        for k, v in expected_md.items():
            key_bytes = k if isinstance(k, bytes) else k.encode()
            val_bytes = v if isinstance(v, bytes) else v.encode()
            if key_bytes == b"ARROW:extension:name" and ext_name is not None:
                if ext_name.encode() == val_bytes:
                    continue
            self.assertEqual(
                actual_md.get(key_bytes), val_bytes,
                self.label(
                    f"kind={spec.name}: field metadata "
                    f"{key_bytes!r} expected={val_bytes!r} "
                    f"actual={actual_md.get(key_bytes)!r}"
                ),
            )

def _storage_type(t: pa.DataType) -> pa.DataType:
    storage = getattr(t, "storage_type", None)
    return storage if storage is not None else t


def _dtype_compatible(actual: pa.DataType, expected: pa.DataType) -> bool:
    if str(actual) == str(expected):
        return True
    a_str = str(actual)
    e_str = str(expected)
    if a_str.startswith("decimal") and e_str.startswith("decimal"):
        a_args = a_str[a_str.index("("):]
        e_args = e_str[e_str.index("("):]
        return a_args == e_args
    if "list" in a_str and "list" in e_str:
        return _leaf_type(actual) == _leaf_type(expected)
    return False


def _leaf_type(t: pa.DataType) -> str:
    while pa.types.is_list(t) or pa.types.is_large_list(t):
        t = t.value_type
    return str(t)


def _scalar_to_python(scalar, spec: KindSpec):
    if scalar is None:
        return None
    if spec.name in ("timestamp", "timestamp_ns", "date") and hasattr(scalar, "value"):
        if not scalar.is_valid:
            return None
        return scalar.value
    try:
        return scalar.as_py()
    except (ValueError, OverflowError):
        return getattr(scalar, "value", None)


def _canonicalise_for_compare(value, spec: KindSpec):
    if value is None:
        return None
    import datetime as _dt
    from decimal import Decimal
    if isinstance(value, _dt.datetime):
        unit = spec.params.get("unit", "us")
        divisor = {"s": 1, "ms": 1_000, "us": 1_000_000, "ns": 1_000_000_000}[unit]
        epoch = _dt.datetime(1970, 1, 1, tzinfo=_dt.timezone.utc)
        if value.tzinfo is None:
            value = value.replace(tzinfo=_dt.timezone.utc)
        delta_s = (value - epoch).total_seconds()
        return int(round(delta_s * divisor))
    if isinstance(value, Decimal):
        scale = spec.params.get("scale", 0)
        return int(value.scaleb(scale))
    if spec.name == "uuid":
        import uuid as _uuid
        if isinstance(value, _uuid.UUID):
            value = value.bytes
        if isinstance(value, (bytes, bytearray)):
            lo = int.from_bytes(value[:8], "little")
            hi = int.from_bytes(value[8:], "little")
            return (lo, hi)
    return value

# Inject one test method per kind so failures pinpoint the offending type.
for _kind_name in list(KIND_REGISTRY.keys()):
    def _make(name):
        def test(self):
            self._exercise_kind(name)
        test.__name__ = f"test_kind_{name}"
        test.__qualname__ = f"TestArrowEgressPerKind.test_kind_{name}"
        return test
    setattr(TestArrowEgressPerKind, f"test_kind_{_kind_name}", _make(_kind_name))

class TestArrowEgressEmpty(afc.ArrowFuzzBase):
    """Zero-row stream → cursor terminates cleanly (no half-filled batch)."""

    SUITE_LABEL = "arrow_egress_empty"

    def _assert_no_rows(self, sql: str) -> None:
        try:
            batches = afc.read_back_arrow_batches(self._fixture, sql)
        except afc.ReaderError as e:
            from arrow_ffi import ReaderErrorCode
            self.assertEqual(
                e.code, ReaderErrorCode.NO_SCHEMA,
                self.label(f"unexpected ReaderError code={e.code} msg={e.message!r}")
            )
            return
        total_rows = sum(rb.num_rows for rb in batches)
        self.assertEqual(
            total_rows, 0,
            self.label(
                f"expected 0 total rows, got {total_rows} across {len(batches)} batch(es)"
            ),
        )

    def test_empty_select_returns_no_batches(self):
        self._assert_no_rows("select 1 from long_sequence(0)")

    def test_filter_yielding_no_rows(self):
        table = self.fresh_table("arrow_eg_filter_empty")
        kinds = [("c_int", KIND_REGISTRY["int"])]
        rb, _ = _ingest_and_read_back(self, table, kinds, null_mode="valid")
        self.assertGreater(rb.num_rows, 0)
        self._assert_no_rows(
            f"select c_int from '{table}' where c_int = -999999999"
        )

class TestArrowEgressFuzz(afc.ArrowFuzzBase):
    """Random subsets of ILP-capable kinds per iteration."""

    SUITE_LABEL = "arrow_egress_fuzz"

    def test_random_schemas(self):
        full_pool = _ilp_capable_kinds()
        nullable_pool = [(n, s) for n, s in full_pool if s.supports_server_null]
        for it in range(_FUZZ_ITERATIONS):
            with self.subTest(iter=it):
                null_mode = ("valid", "partial", "all_null")[it % 3]
                pool = full_pool if null_mode == "valid" else nullable_pool
                self._master_rng.shuffle(pool)
                picked_kinds = pool[:4 + (it % 4)]
                kinds = [(f"c{i}_{n}", s) for i, (n, s) in enumerate(picked_kinds)]
                table = self.fresh_table(f"arrow_eg_fuzz_{it}")
                rb, values_per_col = _ingest_and_read_back(
                    self, table, kinds, null_mode=null_mode,
                )
                self.assertEqual(rb.num_rows, _ROWS_PER_BATCH,
                                 self.label(f"iter={it}"))
                self.assertEqual(rb.num_columns, len(kinds), self.label())
                # Per-cell comparison via each spec's canonicaliser.
                for col_idx, (col_name, spec) in enumerate(kinds):
                    expected = values_per_col[col_name]
                    for r in range(rb.num_rows):
                        a = _canonicalise_for_compare(
                            _scalar_to_python(rb.column(col_idx)[r], spec), spec)
                        e = _canonicalise_for_compare(expected[r], spec)
                        if not spec.compare(a, e):
                            self.fail(self.label(
                                f"iter={it} kind={spec.name} col={col_name} row={r}: "
                                f"expected {e!r}, got {a!r}"
                            ))

def register(loop_registry):
    loop_registry.append(TestArrowEgressPerKind)
    loop_registry.append(TestArrowEgressEmpty)
    loop_registry.append(TestArrowEgressFuzz)

if __name__ == "__main__":
    print(
        "Note: arrow_egress_fuzz tests require a live QuestDB fixture. "
        "Run via `python test.py run --existing HOST:ILP:HTTP "
        "TestArrowEgressPerKind` (or any of the other arrow egress classes).",
        file=sys.stderr,
    )
    unittest.main()
