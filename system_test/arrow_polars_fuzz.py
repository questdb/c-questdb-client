from __future__ import annotations

import os
import unittest
from typing import Dict, List, Tuple

import pyarrow as pa

import arrow_fuzz_common as afc
from arrow_fuzz_common import KIND_REGISTRY, KindSpec

_FUZZ_ITERATIONS = int(os.environ.get("ARROW_POLARS_FUZZ_ITERATIONS", "6"))
_ROWS_PER_BATCH = int(os.environ.get("ARROW_POLARS_FUZZ_ROWS", "10"))


def _require_polars(testcase: unittest.TestCase):
    try:
        import polars as pl  # noqa: F401
    except ImportError:
        testcase.skipTest("polars is required for the Arrow-Polars round-trip tests")


def _polars_round_trip_capable(spec: KindSpec) -> bool:
    if not (spec.round_trip_capable
            and spec.supports_arrow_ingest
            and spec.supports_arrow_egress):
        return False
    if spec.metadata():
        return False
    if spec.name == "long256":
        return False
    if spec.name in ("decimal64", "decimal128", "decimal256"):
        return False
    if spec.name.startswith("double_array") or spec.name == "long_array_1d":
        return False
    return True


def _polars_round_trip_kinds() -> List[Tuple[str, KindSpec]]:
    return [(n, s) for n, s in KIND_REGISTRY.items() if _polars_round_trip_capable(s)]


def _build_batch(
        rnd: afc.Rng, n: int, kinds: List[Tuple[str, KindSpec]],
        *, null_mode: str, ts_base_us: int,
) -> Tuple[pa.RecordBatch, Dict[str, list]]:
    arrays: List[pa.Array] = []
    fields: List[pa.Field] = []
    vpc: Dict[str, list] = {}
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


def _rb_to_polars(rb: pa.RecordBatch):
    import polars as pl
    return pl.from_arrow(rb)


def _polars_to_rb(df) -> pa.RecordBatch:
    arrow_obj = df.to_arrow()
    if isinstance(arrow_obj, pa.Table):
        batches = arrow_obj.to_batches()
        if len(batches) != 1:
            raise AssertionError(
                f"polars.to_arrow() produced {len(batches)} batches, expected 1"
            )
        return batches[0]
    return arrow_obj


def _read_back(fixture, table: str, kinds: List[Tuple[str, KindSpec]]) -> pa.RecordBatch:
    cols_sql = ", ".join(f'"{c}"' for c, _ in kinds)
    sql = f"select {cols_sql} from '{table}' order by ts"
    return afc.read_back_arrow_concat(fixture, sql)


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


def _canonicalise_value(value, spec: KindSpec):
    if value is None:
        return None
    import datetime as _dt
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
    return value


class TestArrowPolarsRoundTripPerKind(afc.ArrowFuzzBase):
    SUITE_LABEL = "arrow_polars_round_trip_per_kind"

    def setUp(self) -> None:
        super().setUp()
        _require_polars(self)

    def _exercise_kind(self, kind_name: str) -> None:
        spec = KIND_REGISTRY[kind_name]
        if not _polars_round_trip_capable(spec):
            self.skipTest(
                f"kind {kind_name!r} not currently round-trippable via polars"
            )
        modes = ["valid", "edge"]
        if spec.supports_server_null:
            modes[1:1] = ["partial", "all_null"]
        for null_mode in modes:
            with self.subTest(null_mode=null_mode):
                table = self.fresh_table(f"arrow_pl_{kind_name}_{null_mode}")
                kinds = [(f"c_{kind_name}", spec)]
                afc.create_table_from_kinds(self._fixture, table, kinds)
                ts_base = 1_700_000_000_000_000 + self._master_rng.next_int(1_000_000)
                rb_orig, _vpc = _build_batch(
                    self._master_rng, _ROWS_PER_BATCH, kinds,
                    null_mode=null_mode, ts_base_us=ts_base,
                )
                df_send = _rb_to_polars(rb_orig)
                rb_send = _polars_to_rb(df_send)
                afc.ingest_via_arrow(self._fixture, table, rb_send)
                afc.wait_for_rows(self._fixture, table, rb_send.num_rows)
                rb_recv = _read_back(self._fixture, table, kinds)
                df_recv = _rb_to_polars(rb_recv)
                rb_recv_pl = _polars_to_rb(df_recv)
                self._assert_polars_round_trip(
                    rb_orig, rb_recv_pl, kinds, null_mode,
                )

    def _assert_polars_round_trip(
            self, rb_in: pa.RecordBatch, rb_out: pa.RecordBatch,
            kinds: List[Tuple[str, KindSpec]], null_mode: str,
    ) -> None:
        col_name, spec = kinds[0]
        self.assertEqual(
            rb_out.num_rows, rb_in.num_rows,
            self.label(f"row count kind={spec.name} mode={null_mode}"),
        )
        for r in range(rb_in.num_rows):
            ev = _canonicalise_value(
                _scalar_to_python(rb_in.column(0)[r], spec), spec)
            av = _canonicalise_value(
                _scalar_to_python(rb_out.column(0)[r], spec), spec)
            if not spec.compare(av, ev):
                self.fail(self.label(
                    f"kind={spec.name} mode={null_mode} row={r}: "
                    f"in={ev!r} out={av!r}"
                ))


for _kind_name in list(KIND_REGISTRY.keys()):
    if not _polars_round_trip_capable(KIND_REGISTRY[_kind_name]):
        continue


    def _make(name):
        def test(self):
            self._exercise_kind(name)

        test.__name__ = f"test_pl_{name}"
        test.__qualname__ = f"TestArrowPolarsRoundTripPerKind.test_pl_{name}"
        return test


    setattr(TestArrowPolarsRoundTripPerKind, f"test_pl_{_kind_name}", _make(_kind_name))


class TestArrowPolarsFuzz(afc.ArrowFuzzBase):
    SUITE_LABEL = "arrow_polars_fuzz"

    def setUp(self) -> None:
        super().setUp()
        _require_polars(self)

    def _run_iteration(self, it: int, null_mode: str) -> None:
        full_pool = _polars_round_trip_kinds()
        if null_mode in ("partial", "all_null"):
            pool = [(n, s) for n, s in full_pool if s.supports_server_null]
        else:
            pool = full_pool
        self._master_rng.shuffle(pool)
        picked = pool[: 3 + (it % 3)]
        if not picked:
            return
        kinds = [(f"c{i}_{n}", s) for i, (n, s) in enumerate(picked)]
        table = self.fresh_table(f"arrow_pl_fuzz_{it}")
        afc.create_table_from_kinds(self._fixture, table, kinds)
        ts_base = 1_700_000_000_000_000 + it * 10_000_000
        rb_orig, _vpc = _build_batch(
            self._master_rng, _ROWS_PER_BATCH, kinds,
            null_mode=null_mode, ts_base_us=ts_base,
        )
        df_send = _rb_to_polars(rb_orig)
        rb_send = _polars_to_rb(df_send)
        afc.ingest_via_arrow(self._fixture, table, rb_send)
        afc.wait_for_rows(self._fixture, table, rb_send.num_rows)
        rb_recv = _read_back(self._fixture, table, kinds)
        df_recv = _rb_to_polars(rb_recv)
        rb_recv_pl = _polars_to_rb(df_recv)
        self.assertEqual(
            rb_recv_pl.num_rows, rb_orig.num_rows,
            self.label(f"iter={it} mode={null_mode}"),
        )
        for col_idx, (col_name, spec) in enumerate(kinds):
            for r in range(rb_orig.num_rows):
                ev = _canonicalise_value(
                    _scalar_to_python(rb_orig.column(col_idx)[r], spec), spec)
                av = _canonicalise_value(
                    _scalar_to_python(rb_recv_pl.column(col_idx)[r], spec), spec)
                if not spec.compare(av, ev):
                    self.fail(self.label(
                        f"iter={it} mode={null_mode} kind={spec.name} "
                        f"col={col_name} row={r}: in={ev!r} out={av!r}"
                    ))

    def test_random_valid(self):
        for it in range(_FUZZ_ITERATIONS):
            with self.subTest(iter=it):
                self._run_iteration(it, "valid")

    def test_random_partial_null(self):
        for it in range(_FUZZ_ITERATIONS):
            with self.subTest(iter=it):
                self._run_iteration(it, "partial")


def register(loop_registry):
    loop_registry.append(TestArrowPolarsRoundTripPerKind)
    loop_registry.append(TestArrowPolarsFuzz)


if __name__ == "__main__":
    unittest.main()
