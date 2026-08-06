from __future__ import annotations

import os
import sys
import unittest
from typing import Dict, List, Tuple

import pyarrow as pa

import arrow_fuzz_common as afc
from arrow_fuzz_common import KIND_REGISTRY, KindSpec

_FUZZ_ITERATIONS = int(os.environ.get("ARROW_ROUND_TRIP_FUZZ_ITERATIONS", "6"))
_ROWS_PER_BATCH = int(os.environ.get("ARROW_ROUND_TRIP_FUZZ_ROWS", "10"))


def _round_trip_capable(spec: KindSpec) -> bool:
    return (
            spec.round_trip_capable
            and spec.supports_arrow_ingest
            and spec.supports_arrow_egress
    )


def _round_trip_capable_kinds() -> List[Tuple[str, KindSpec]]:
    return [(n, s) for n, s in KIND_REGISTRY.items() if _round_trip_capable(s)]


def _build_batch(
        rnd: afc.Rng, n: int, kinds: List[Tuple[str, KindSpec]],
        *, null_mode: str, ts_base_us: int,
) -> Tuple[pa.RecordBatch, Dict[str, list]]:
    arrays: List[pa.Array] = []
    fields: List[pa.Field] = []
    vpc: Dict[str, list] = {}
    for col_name, spec in kinds:
        if null_mode == "valid":
            mask = afc.all_valid_mask(n);
            edge = False
        elif null_mode == "partial":
            mask = afc.partial_null_mask(rnd, n, null_p=0.3);
            edge = False
        elif null_mode == "all_null":
            mask = afc.all_null_mask(n);
            edge = False
        elif null_mode == "edge":
            mask = afc.all_valid_mask(n);
            edge = True
        else:
            raise ValueError(null_mode)
        vs = spec.generate_values(rnd, n, mask, edge=edge)
        vpc[col_name] = vs
        arrays.append(spec.build_arrow_array(vs))
        fields.append(spec.make_field(col_name))
    ts_arr = pa.array(
        [ts_base_us + i for i in range(n)],
        type=pa.timestamp("us", tz="UTC"),
    )
    arrays.append(ts_arr)
    fields.append(pa.field("ts", pa.timestamp("us", tz="UTC"), nullable=False))
    return pa.RecordBatch.from_arrays(arrays, schema=pa.schema(fields)), vpc


def _read_back(fixture, table: str, kinds: List[Tuple[str, KindSpec]]) -> pa.RecordBatch:
    cols_sql = ", ".join(f'"{c}"' for c, _ in kinds)
    sql = f"select {cols_sql} from '{table}' order by ts"
    return afc.read_back_arrow_concat(fixture, sql)


class TestArrowRoundTripPerKind(afc.ArrowFuzzBase):
    """Per-kind round-trip. Failure pinpoints the single offending type."""

    SUITE_LABEL = "arrow_round_trip_per_kind"

    def _exercise_kind(self, kind_name: str) -> None:
        spec = KIND_REGISTRY[kind_name]
        if not _round_trip_capable(spec):
            self.skipTest(f"kind {kind_name!r} not round-trip capable")
        modes = ["valid", "edge"]
        if spec.supports_server_null:
            modes[1:1] = ["partial", "all_null"]
        for null_mode in modes:
            with self.subTest(null_mode=null_mode):
                table = self.fresh_table(f"arrow_rt_{kind_name}_{null_mode}")
                kinds = [(f"c_{kind_name}", spec)]
                afc.create_table_from_kinds(self._fixture, table, kinds)
                ts_base = 1_700_000_000_000_000 + self._master_rng.next_int(1_000_000)
                rb_in, vpc = _build_batch(
                    self._master_rng, _ROWS_PER_BATCH, kinds,
                    null_mode=null_mode, ts_base_us=ts_base,
                )
                afc.ingest_via_arrow(self._fixture, table, rb_in)
                afc.wait_for_rows(self._fixture, table, rb_in.num_rows)
                rb_out = _read_back(self._fixture, table, kinds)
                self._assert_kind_round_trip(rb_in, rb_out, kinds, null_mode)

    def _assert_kind_round_trip(
            self, rb_in: pa.RecordBatch, rb_out: pa.RecordBatch,
            kinds: List[Tuple[str, KindSpec]], null_mode: str,
    ) -> None:
        col_name, spec = kinds[0]
        self.assertEqual(rb_out.num_rows, rb_in.num_rows,
                         self.label(f"row count kind={spec.name} mode={null_mode}"))
        expected_dtype = spec.arrow_type()
        actual_dtype = _storage_type(rb_out.column(0).type)
        if not _dtype_compatible(actual_dtype, expected_dtype):
            self.fail(self.label(f"DataType kind={spec.name}: "
                                 f"want {expected_dtype}, got {actual_dtype}"))
        expected_md = spec.metadata() or {}
        actual_md = dict(rb_out.schema.field(0).metadata or {})
        ext_name = getattr(rb_out.schema.field(0).type, "extension_name", None)
        for k, v in expected_md.items():
            key_bytes = k if isinstance(k, bytes) else k.encode()
            val_bytes = v if isinstance(v, bytes) else v.encode()
            if key_bytes == b"ARROW:extension:name" and ext_name is not None:
                if ext_name.encode() == val_bytes:
                    continue
            self.assertEqual(
                actual_md.get(key_bytes), val_bytes,
                self.label(f"kind={spec.name} field metadata mismatch "
                           f"key={key_bytes!r} expected={val_bytes!r} "
                           f"actual={actual_md.get(key_bytes)!r}"),
            )
        for r in range(rb_in.num_rows):
            ev_canon = _canonicalise_value(
                _scalar_to_python(rb_in.column(0)[r], spec), spec)
            av_canon = _canonicalise_value(
                _scalar_to_python(rb_out.column(0)[r], spec), spec)
            if not spec.compare(av_canon, ev_canon):
                self.fail(self.label(
                    f"kind={spec.name} mode={null_mode} row={r}: "
                    f"in={ev_canon!r} out={av_canon!r}"
                ))


def _storage_type(t: pa.DataType) -> pa.DataType:
    storage = getattr(t, "storage_type", None)
    return storage if storage is not None else t


def _leaf_type(t: pa.DataType) -> str:
    while pa.types.is_list(t) or pa.types.is_large_list(t):
        t = t.value_type
    return str(t)


def _dtype_compatible(actual: pa.DataType, expected: pa.DataType) -> bool:
    if str(actual) == str(expected):
        return True
    a_str = str(actual)
    e_str = str(expected)
    if a_str.startswith("decimal") and e_str.startswith("decimal"):
        return a_str[a_str.index("("):] == e_str[e_str.index("("):]
    if "list" in a_str and "list" in e_str:
        return _leaf_type(actual) == _leaf_type(expected)
    return False


def _scalar_to_python(scalar, spec=None):
    if scalar is None:
        return None
    if spec is not None and spec.name in ("timestamp", "timestamp_ns", "date") \
            and hasattr(scalar, "value"):
        if not scalar.is_valid:
            return None
        return scalar.value
    try:
        return scalar.as_py()
    except (ValueError, OverflowError):
        return getattr(scalar, "value", None)


def _canonicalise_value(value, spec: KindSpec):
    if value is None:
        return None
    import datetime as _dt
    import uuid as _uuid
    from decimal import Decimal
    if isinstance(value, _dt.datetime):
        unit = spec.params.get("unit", "us")
        divisor = {"s": 1, "ms": 1_000, "us": 1_000_000, "ns": 1_000_000_000}[unit]
        if value.tzinfo is None:
            value = value.replace(tzinfo=_dt.timezone.utc)
        epoch = _dt.datetime(1970, 1, 1, tzinfo=_dt.timezone.utc)
        return int(round((value - epoch).total_seconds() * divisor))
    if isinstance(value, Decimal):
        scale = spec.params.get("scale", 0)
        return int(value.scaleb(scale))
    if spec.name == "uuid":
        if isinstance(value, _uuid.UUID):
            value = value.bytes
        if isinstance(value, (bytes, bytearray)):
            lo = int.from_bytes(value[:8], "little")
            hi = int.from_bytes(value[8:], "little")
            return (lo, hi)
    return value


for _kind_name in list(KIND_REGISTRY.keys()):
    spec = KIND_REGISTRY[_kind_name]
    if not _round_trip_capable(spec):
        continue


    def _make(name):
        def test(self):
            self._exercise_kind(name)

        test.__name__ = f"test_rt_{name}"
        test.__qualname__ = f"TestArrowRoundTripPerKind.test_rt_{name}"
        return test


    setattr(TestArrowRoundTripPerKind, f"test_rt_{_kind_name}", _make(_kind_name))


class TestArrowRoundTripFuzz(afc.ArrowFuzzBase):
    """Random subsets of kinds, random null modes."""

    SUITE_LABEL = "arrow_round_trip_fuzz"

    def _run_random_iteration(self, it: int, null_mode: str,
                              *, include_edge: bool = False) -> None:
        full_pool = _round_trip_capable_kinds()
        mode = "edge" if include_edge else null_mode
        if mode in ("partial", "all_null"):
            pool = [(n, s) for n, s in full_pool if s.supports_server_null]
        else:
            pool = full_pool
        self._master_rng.shuffle(pool)
        picked = pool[: 3 + (it % 4)]
        kinds = [(f"c{i}_{n}", s) for i, (n, s) in enumerate(picked)]
        table = self.fresh_table(f"arrow_rt_fuzz_{it}")
        afc.create_table_from_kinds(self._fixture, table, kinds)
        ts_base = 1_700_000_000_000_000 + it * 10_000_000
        rb_in, _vpc = _build_batch(
            self._master_rng, _ROWS_PER_BATCH, kinds,
            null_mode=mode, ts_base_us=ts_base,
        )
        afc.ingest_via_arrow(self._fixture, table, rb_in)
        afc.wait_for_rows(self._fixture, table, rb_in.num_rows)
        rb_out = _read_back(self._fixture, table, kinds)
        self.assertEqual(rb_out.num_rows, rb_in.num_rows, self.label())
        for col_idx, (col_name, spec) in enumerate(kinds):
            for r in range(rb_in.num_rows):
                ev = _canonicalise_value(
                    _scalar_to_python(rb_in.column(col_idx)[r], spec), spec)
                av = _canonicalise_value(
                    _scalar_to_python(rb_out.column(col_idx)[r], spec), spec)
                if not spec.compare(av, ev):
                    self.fail(self.label(
                        f"iter={it} mode={mode} kind={spec.name} "
                        f"col={col_name} row={r}: in={ev!r} out={av!r}"
                    ))

    def _run_sliced_iteration(self, it: int, null_mode: str) -> None:
        """Build a batch padded with rows that must NOT be ingested, then
        send only the inner window via `slice_window`. The sliced arrays
        carry non-zero offsets across the FFI boundary; a regression that
        ignored `array.offset()` would emit the leading pad rows (or wrong
        varlen/bool bytes) and the row-by-row compare below would catch
        it."""
        full_pool = _round_trip_capable_kinds()
        if null_mode in ("partial", "all_null"):
            pool = [(n, s) for n, s in full_pool if s.supports_server_null]
        else:
            pool = full_pool
        self._master_rng.shuffle(pool)
        picked = pool[: 3 + (it % 4)]
        kinds = [(f"c{i}_{n}", s) for i, (n, s) in enumerate(picked)]
        table = self.fresh_table(f"arrow_rt_sliced_{it}")
        afc.create_table_from_kinds(self._fixture, table, kinds)
        n = _ROWS_PER_BATCH
        pad = 2 + (it % 3)
        total = pad + n + pad
        ts_base = 1_700_000_000_000_000 + it * 10_000_000
        rb_full, _vpc = _build_batch(
            self._master_rng, total, kinds,
            null_mode=null_mode, ts_base_us=ts_base,
        )
        # Expected = the inner window only; the encoder must reproduce it
        # despite the surrounding pad rows present in the parent buffers.
        rb_window = rb_full.slice(pad, n)
        afc.ingest_via_arrow(
            self._fixture, table, rb_full, slice_window=(pad, n),
        )
        afc.wait_for_rows(self._fixture, table, n)
        rb_out = _read_back(self._fixture, table, kinds)
        self.assertEqual(rb_out.num_rows, n,
                         self.label(f"sliced iter={it} mode={null_mode}"))
        for col_idx, (col_name, spec) in enumerate(kinds):
            for r in range(n):
                ev = _canonicalise_value(
                    _scalar_to_python(rb_window.column(col_idx)[r], spec), spec)
                av = _canonicalise_value(
                    _scalar_to_python(rb_out.column(col_idx)[r], spec), spec)
                if not spec.compare(av, ev):
                    self.fail(self.label(
                        f"sliced iter={it} mode={null_mode} kind={spec.name} "
                        f"col={col_name} row={r}: in={ev!r} out={av!r}"
                    ))

    def test_random_schemas_all_valid(self):
        for it in range(_FUZZ_ITERATIONS):
            with self.subTest(iter=it):
                self._run_random_iteration(it, "valid")

    def test_random_schemas_sliced_window(self):
        for it in range(_FUZZ_ITERATIONS):
            with self.subTest(iter=it):
                self._run_sliced_iteration(it, "valid")

    def test_random_schemas_sliced_window_partial_null(self):
        for it in range(_FUZZ_ITERATIONS):
            with self.subTest(iter=it):
                self._run_sliced_iteration(it, "partial")

    def test_random_schemas_partial_null(self):
        for it in range(_FUZZ_ITERATIONS):
            with self.subTest(iter=it):
                self._run_random_iteration(it, "partial")

    def test_random_schemas_edge_values(self):
        for it in range(_FUZZ_ITERATIONS):
            with self.subTest(iter=it):
                self._run_random_iteration(it, "edge", include_edge=True)


def register(loop_registry):
    loop_registry.append(TestArrowRoundTripPerKind)
    loop_registry.append(TestArrowRoundTripFuzz)


if __name__ == "__main__":
    print(
        "Note: arrow_round_trip_fuzz tests require a live QuestDB fixture. "
        "Run via `python test.py run --existing HOST:ILP:HTTP "
        "TestArrowRoundTripPerKind` (or TestArrowRoundTripFuzz).",
        file=sys.stderr,
    )
    unittest.main()
